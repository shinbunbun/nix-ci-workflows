#!/usr/bin/env python3
"""PR が新規導入した store path に既知脆弱性が乗っていないか vulnix で検査する diff-gate (#347)。

2 つのサブコマンドで構成する:

  scan <head_closure> <base_closure> <out_json> [--whitelist FILE]
      [producer] flake を eval 済みの **scan ジョブ内** (= derivers 完備、対象プラットフォーム上)
      で 1 target を処理する。head/base の closure-paths から差分 Δ を取り、Δ だけを
      `vulnix -R` で検査して introduced findings を out_json に書く。

  gate <introduced_dir> <pr_number> [--gate]
      [aggregator] 各 target の producer 出力 (introduced-*.json) を集約し、PR コメントを
      upsert する。--gate 時、新規流入 or scan 未完走があれば exit 1 で required check を fail。

## 設計 (#347 の根本修正)

旧 delta-gate は「この run の head スキャン」を「**別 run** の baseline notify.json artifact」と
diff していた。両者は別時刻・別データ snapshot なので、脆弱性 DB のドリフトや vulnix の NVD
フィード 404 が「PR の新規流入」に化け、無関係な no-fix CVE (glibc 等) で誤ブロックしていた。

本 diff-gate はこれを構造的に断つ:

  introduced = (head_closure_paths − base_closure_paths) に乗った vulnix 検出 CVE

- head/base は「**閉包の store path 集合**」= 決定的な事実だけを使う。脆弱性データは head 側の
  vulnix 1 スキャンからのみ読む (base 側の脆弱性データは一切使わない)。base のドリフト/404 は
  gate に影響しない。content-addressed な差分 Δ は「この PR が実際に足した/変えたパッケージ」
  そのもので、未変更の共有ライブラリ (glibc 等) は Δ に出ない → 二度と誤検出しない。
- **producer は scan ジョブ内 (flake を build/eval した後) で走らせる**。これにより Δ パスの
  .drv = derivers が store に揃い、`vulnix -R` が deriver を解決できる。別ジョブで output path を
  substitute するだけだと Attic 由来 (unfree/カスタム: terraform/claude-code 等) の deriver が
  失われ vulnix がクラッシュするため、必ず eval 済みコンテキストで実行すること。
- target ごとに対象プラットフォームの runner で producer を走らせるので、darwin の Δ は macos 上で
  vulnix にかかる (cross-platform substitute 不要)。

## エンジン選択 (#347 実測)

gate は vulnix 一本。C ライブラリ閉包の実測で vulnix は union の ~97% を検出し (glibc/gcc/zlib は
vulnix が拾い grype は取りこぼす)。grype/osv の固有上乗せは僅少で、漏れる分は #283 集約のフル
vulnxscan (vulnix+grype+osv) が backstop する。gate は「速く・単純に・PR の流入を止める」役割。

## fail-closed

vulnix が完走しなかった (出力が JSON list として解釈できない) target は、本物の流入を
すり抜けさせないため gate を block する。

env (gate サブコマンドのみ):
  GITHUB_TOKEN       無い場合は dry-run (body を stdout 出力)
  GITHUB_REPOSITORY  "owner/repo"
  GITHUB_API_URL     省略時 https://api.github.com
"""
import csv
import glob
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

from vulnxscan_common import make_requester, ok, sevf, short_target

MARKER = "<!-- vulnxscan-diff-gate -->"
# vulnix 呼び出し 1 回あたりの最大 path 数 (argv 長制限の安全側チャンク)。
VULNIX_CHUNK = 400


# ============================ closure paths I/O ============================
def read_closure_file(path):
    """closure-paths.txt を (target, set(store_paths)) で読む。

    先頭付近の `# target: <TARGET>` ヘッダから target を、それ以外の非コメント行を
    store path として取る。ファイル不在は (None, None)。
    """
    target = None
    paths = set()
    try:
        with open(path) as f:
            for line in f:
                s = line.strip()
                if s.startswith("# target:"):
                    target = s.split(":", 1)[1].strip()
                elif s and not s.startswith("#"):
                    paths.add(s)
    except OSError:
        return None, None
    return target, paths


# ============================ vulnix 実行 (producer) ============================
def _query_deriver(path):
    """store path の deriver を返す (`nix-store --query --deriver`)。不明/失敗時は空文字。"""
    r = subprocess.run(
        ["nix-store", "--query", "--deriver", path],
        capture_output=True,
        text=True,
        check=False,
    )
    return r.stdout.strip() if r.returncode == 0 else ""


def scannable_paths(paths, *, query=_query_deriver):
    """vulnix -R が扱える (deriver 判明) パスだけに絞る。

    `vulnix -R` は **deriver 不明の path** (home-manager 生成の unit/manpage、builtins.toFile
    産物等の「パッケージでない生成物」) で DeriverLookupError を投げてクラッシュし、その chunk
    全体の結果を失う。これらは pname/version を持たず CVE 照合の対象外なので、
    `nix-store --query --deriver` が `unknown-deriver` を返す path を除外する。
    flake を eval 済みのコンテキスト (scan ジョブ) では本物パッケージの deriver は必ず揃うので、
    除外されるのは生成物のみで検出は減らない。
    """
    return [p for p in paths if (d := query(p)) and d != "unknown-deriver"]


def _default_runner(chunk):
    """実 vulnix を起動する (test 時は runner 差し替えで分離)。

    deriver 不明パス (vulnix -R がクラッシュする非パッケージ生成物) を除外してから
    `vulnix -R --json` を実行する。
    """
    scannable = scannable_paths(chunk)
    if not scannable:
        # 差分が生成物のみ (deriver 無し) = 検査対象パッケージ無し → 脆弱性なし扱い。
        return 0, "[]", ""
    proc = subprocess.run(
        ["vulnix", "-R", "--json", *scannable],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _extract_findings(data):
    """vulnix --json (package list) を {pname,version,vuln_id,severity} に展開。"""
    out = []
    for pkg in data:
        if not isinstance(pkg, dict):
            continue
        pname = pkg.get("pname") or pkg.get("name") or ""
        version = pkg.get("version") or ""
        cvss = pkg.get("cvssv3_basescore") or {}
        for cve in pkg.get("affected_by") or []:
            sev = cvss.get(cve, "") if isinstance(cvss, dict) else ""
            out.append(
                {
                    "pname": pname,
                    "version": version,
                    "vuln_id": cve,
                    "severity": str(sev) if sev not in (None, "") else "",
                }
            )
    return out


def run_vulnix(paths, *, runner=None):
    """Δ の store path 群を vulnix -R --json でスキャンし (findings, error) を返す。

    成否は exit code でなく **stdout が JSON list として解釈できたか**で判定する
    (vulnix は脆弱性ありで非ゼロ終了し、クラッシュ時は stdout が空/非 JSON になる)。
    error が非 None のとき scan 失敗 (fail-closed 対象)。
    """
    runner = runner or _default_runner
    findings = []
    ordered = sorted(paths)
    for i in range(0, len(ordered), VULNIX_CHUNK):
        chunk = ordered[i : i + VULNIX_CHUNK]
        rc, stdout, stderr = runner(chunk)
        try:
            data = json.loads(stdout)
        except (ValueError, TypeError):
            tail = (stderr or "").strip().splitlines()[-3:]
            return [], f"vulnix 出力を JSON として解釈できません (rc={rc}): {' / '.join(tail)}"
        if not isinstance(data, list):
            return [], f"vulnix 出力が list ではありません (rc={rc})"
        findings.extend(_extract_findings(data))
    return findings, None


def load_whitelist(path):
    """gate 用 whitelist を読み、[(vuln_id 正規表現, pname|None), ...] を返す。

    フル vulnxscan (`--whitelist`) と **同一ファイルを共用**できるよう 2 形式を受理する:

      - sbomnix/vulnxscan 3 列 CSV (ヘッダ `vuln_id,comment,package`、リポジトリの
        `.github/vulnxscan-whitelist.csv` で使う本命形式):
        vuln_id 列は**正規表現** (例 `^CVE-2021-4034$`)、package 列は pname (空可)。
      - レガシー簡易形式 (1 列): `CVE-ID` (完全一致) または `pname,CVE-ID` (完全一致)。
        `#` 以降は行コメント。

    package/pname が空のエントリは「全 pname にマッチ」(CVE 単位の受容) とみなす。
    """
    matchers = []
    if not path:
        return matchers
    try:
        with open(path, newline="") as f:
            rows = list(csv.reader(f))
    except OSError:
        return matchers
    for row in rows:
        if not row:
            continue
        first = row[0].strip()
        # ヘッダ行 (vuln_id,...) と # コメント行 / 空行をスキップ。
        if not first or first.startswith("#") or first == "vuln_id":
            continue
        if len(row) >= 3:
            # sbomnix 3 列: vuln_id(正規表現), comment, package。
            pattern, pname = first, (row[2].strip() or None)
        elif len(row) == 2:
            # レガシー `pname,CVE-ID` (完全一致)。
            pname, pattern = (first or None), "^" + re.escape(row[1].strip()) + "$"
        else:
            # レガシー `CVE-ID` 単体 (# 以降コメント、完全一致)。
            cve = first.split("#", 1)[0].strip()
            if not cve:
                continue
            pname, pattern = None, "^" + re.escape(cve) + "$"
        try:
            matchers.append((re.compile(pattern), pname))
        except re.error:
            # 不正な正規表現は無視 (whitelist の typo で gate を壊さない)。
            continue
    return matchers


def apply_whitelist(findings, matchers):
    """matchers (load_whitelist の戻り値) にマッチする finding を除外する。"""
    if not matchers:
        return findings

    def whitelisted(f):
        vid, pname = f.get("vuln_id", ""), f.get("pname", "")
        return any(
            rx.search(vid) and (pn is None or pn == pname) for rx, pn in matchers
        )

    return [f for f in findings if not whitelisted(f)]


def scan_delta(head_closure, base_closure, out_json, *, whitelist=(), runner=None):
    """[producer] 1 target の Δ を vulnix で検査し out_json に結果を書く。

    出力 JSON: {"target", "label", "findings": [...], "scan_failed": str|None,
                "baseline_missing": bool}
    """
    target, head_paths = read_closure_file(head_closure)
    _, base_paths = read_closure_file(base_closure)
    label = short_target(target) if target else "?"
    result = {"target": target, "label": label, "findings": [], "scan_failed": None,
              "baseline_missing": False}
    if base_paths is None:
        # baseline 不在 (初回 / artifact 失効)。delta 計算不可だが block しない (graceful)。
        result["baseline_missing"] = True
    else:
        delta = (head_paths or set()) - base_paths
        if delta:
            findings, error = run_vulnix(delta, runner=runner)
            if error:
                result["scan_failed"] = error
            else:
                result["findings"] = apply_whitelist(findings, whitelist)
    with open(out_json, "w") as f:
        json.dump(result, f)
    return result


# ============================ 集約 (aggregator) ============================
def aggregate(introduced_dir):
    """introduced_dir 配下の *.json (producer 出力) を集約する。

    戻り値: (introduced, baseline_missing, scan_failed)
      introduced = {(vuln_id, pname): {"severity","targets":set}}
      baseline_missing = [label...]、scan_failed = {label: error}
    """
    introduced = {}
    baseline_missing = []
    scan_failed = {}
    for path in sorted(glob.glob(os.path.join(introduced_dir, "**", "*.json"), recursive=True)):
        try:
            with open(path) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        label = data.get("label") or short_target(data.get("target", "?"))
        if data.get("baseline_missing"):
            baseline_missing.append(label)
        if data.get("scan_failed"):
            scan_failed[label] = data["scan_failed"]
        for fdg in data.get("findings", []):
            key = (fdg.get("vuln_id", ""), fdg.get("pname", ""))
            if not key[0]:
                continue
            e = introduced.setdefault(key, {"severity": fdg.get("severity", ""), "targets": set()})
            if sevf(fdg.get("severity")) > sevf(e["severity"]):
                e["severity"] = fdg.get("severity", "")
            e["targets"].add(label)
    return introduced, baseline_missing, scan_failed


def build_body(introduced, baseline_missing, scan_failed, gate_mode):
    """diff-gate コメントの (markdown body, blocked) を返す。"""
    ts = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")
    blocked = bool(introduced) or bool(scan_failed)
    lines = [
        MARKER,
        "",
        "## 🔬 vulnxscan diff-gate — この PR が新規導入する脆弱性"
        + ("（**新規流入で auto-merge ブロック**）" if gate_mode else "（report-only）"),
        "",
        f"自動生成 (最終更新: {ts})。closure の**差分 store path** だけを vulnix で検査します"
        " (base 側の脆弱性データは使わないため、DB ドリフト/404 起因の誤検出は発生しません)。"
        " 既存の CVE 全体は集約 Issue #283 を参照。",
        "",
    ]
    if scan_failed:
        lines += [
            "> ⛔ **スキャン未完走のため fail-closed で block しました。**"
            " vulnix が完走しなかった target があり、新規流入の有無を判定できません。 re-run してください:",
            "",
        ]
        for t, err in sorted(scan_failed.items()):
            lines.append(f"> - `{t}`: {err}")
        lines.append("")
    if introduced:
        items = sorted(introduced.items(), key=lambda kv: -sevf(kv[1]["severity"]))
        lines.append(f"**🆕 新規流入 {len(items)} 件**")
        lines.append("")
        if gate_mode:
            lines += [
                "> ⛔ **この PR は新規の既知脆弱性を持ち込むため auto-merge をブロックしました。**",
                "> 対応: 流入元の更新を見送る / パッケージを置換・削除する / "
                "意図的に受容する場合は理由付きで gate whitelist に追記する (再スキャンで解除)。",
                "",
            ]
        lines += ["| CVE | sev | pkg | 影響ターゲット |", "|---|---|---|---|"]
        for (vid, pname), e in items:
            url = f"https://nvd.nist.gov/vuln/detail/{vid}"
            tgts = ",".join(sorted(e["targets"]))
            lines.append(f"| [{vid}]({url}) | {e['severity'] or '—'} | {pname} | {tgts} |")
        lines.append("")
    elif not scan_failed:
        lines.append("✅ **この PR は新規の既知脆弱性を持ち込みません。**")
        lines.append("")
    if baseline_missing:
        lines += [
            "> 📭 次の target は baseline (main の closure paths) が無く delta 未計算: "
            + ", ".join(f"`{t}`" for t in baseline_missing)
            + " (初回 / artifact 失効。次回 main スキャン後に解消)。",
            "",
        ]
    lines.append(
        "> 確定 FP / リスク受容は gate whitelist に追記すると introduced から外れます。"
        " 網羅的な脆弱性一覧は集約 Issue #283 を参照。"
    )
    return "\n".join(lines), blocked


def upsert_comment(pr_number, body):
    """PR コメントを MARKER で探して upsert (再 push でスパムしない)。"""
    repo = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN")
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    if not token or not repo or not pr_number:
        print("[dry-run] GITHUB_TOKEN / GITHUB_REPOSITORY / PR 番号 未設定。body:\n")
        print(body)
        return
    req = make_requester(token, api)
    st, comments = req("GET", f"/repos/{repo}/issues/{pr_number}/comments?per_page=100")
    if st != 200 or not isinstance(comments, list):
        print(f"::warning::PR #{pr_number} のコメント一覧取得に失敗 (status={st})。コメントをスキップ。")
        return
    existing = next((c for c in comments if MARKER in (c.get("body") or "")), None)
    if existing:
        st, _ = req("PATCH", f"/repos/{repo}/issues/comments/{existing['id']}", {"body": body})
    else:
        st, _ = req("POST", f"/repos/{repo}/issues/{pr_number}/comments", {"body": body})
    if not ok(st):
        print(f"::warning::diff-gate コメント upsert に失敗 (status={st})")


# ============================ CLI ============================
def _main_scan(argv):
    whitelist_path = None
    pos = []
    it = iter(argv)
    for a in it:
        if a == "--whitelist":
            whitelist_path = next(it, None)
        else:
            pos.append(a)
    head_closure = pos[0]
    base_closure = pos[1]
    out_json = pos[2]
    result = scan_delta(
        head_closure, base_closure, out_json, whitelist=load_whitelist(whitelist_path)
    )
    print(
        f"scan {result['label']}: findings {len(result['findings'])} / "
        f"scan_failed {'yes' if result['scan_failed'] else 'no'} / "
        f"baseline_missing {result['baseline_missing']}"
    )
    return 0


def _main_gate(argv):
    gate_mode = "--gate" in argv
    pos = [a for a in argv if a != "--gate"]
    introduced_dir = pos[0] if pos else "introduced"
    pr_number = pos[1] if len(pos) > 1 else os.environ.get("GITHUB_PR_NUMBER", "")
    introduced, baseline_missing, scan_failed = aggregate(introduced_dir)
    body, blocked = build_body(introduced, baseline_missing, scan_failed, gate_mode)
    upsert_comment(pr_number, body)
    print(
        f"introduced {len(introduced)} / scan_failed {len(scan_failed)} / "
        f"baseline_missing {len(baseline_missing)}"
    )
    if gate_mode and blocked:
        if scan_failed:
            print(f"::error::vulnix 未完走の target あり (fail-closed)。re-run してください: {sorted(scan_failed)}")
        if introduced:
            print(f"::error::この PR は新規脆弱性 {len(introduced)} 件を持ち込むため gate を fail させます。")
        return 1
    return 0


def main(argv):
    if len(argv) < 2 or argv[1] not in ("scan", "gate"):
        print("usage: vulnxscan_diff_gate.py {scan|gate} ...", file=sys.stderr)
        return 2
    if argv[1] == "scan":
        return _main_scan(argv[2:])
    return _main_gate(argv[2:])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
