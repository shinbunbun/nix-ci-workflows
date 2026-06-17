#!/usr/bin/env python3
"""PR が新規導入した store path に既知脆弱性が乗っていないか vulnix で検査する diff-gate (#347)。

usage: vulnxscan_diff_gate.py <head_dir> <base_dir> <pr_number> [--gate] [--whitelist FILE]

<head_dir> / <base_dir> はそれぞれ download-artifact が展開した closure-paths.txt 群を含む
ディレクトリ (サブディレクトリ可)。各 closure-paths.txt は先頭に `# target: <TARGET>` ヘッダを
持ち、残り行が runtime closure の store path。target ヘッダで head/base を突き合わせる。

## 設計 (#347 の根本修正)

旧 delta-gate は「この run の head スキャン」を「**別 run** の baseline notify.json artifact」と
diff していた。両者は別時刻・別データ snapshot なので、脆弱性 DB のドリフトや vulnix の NVD
フィード 404 が「PR の新規流入」に化け、無関係な no-fix CVE (glibc 等) で auto-merge を
恒常的に誤ブロックしていた。

本 gate はこれを構造的に断つ:

  introduced = (head_closure_paths − base_closure_paths) に乗った vulnix 検出 CVE

- head/base は「**閉包の store path 集合**」= 決定的な事実だけを使う。脆弱性データは head 側の
  vulnix 1 スキャンからのみ読む (base 側の脆弱性データは一切使わない)。よって base 側の
  ドリフト/404/fail-open は gate に影響しない。
- Nix の store path は content-addressed。差分集合 Δ は「この PR が実際に足した/変えたパッケージ」
  そのもので、未変更の共有ライブラリ (glibc 等) は Δ に出ない → 二度と誤検出しない。
- closure は参照に閉じているため Δ を単一 closure で表現することは不可能 (glibc を引き戻す)。
  Δ は「閉じていない集合」なので、vulnix に store path 列挙 (`-R` = no-requisites) で渡す。

## エンジン選択 (#347 実測)

gate は vulnix 一本。C ライブラリ閉包の実測で vulnix は union の ~97% を検出し (glibc/gcc/zlib は
vulnix が拾い grype は取りこぼす)、grype/osv の固有上乗せは僅少。漏れる分は #283 集約のフル
vulnxscan (vulnix+grype+osv) が backstop する。gate は「速く・単純に・PR の流入を止める」役割。

## fail-closed

vulnix が完走しなかった (出力が JSON list として解釈できない) target は、本物の流入を
すり抜けさせないため gate を block する。

env:
  GITHUB_TOKEN       無い場合は dry-run (body を stdout 出力)
  GITHUB_REPOSITORY  "owner/repo"
  GITHUB_API_URL     省略時 https://api.github.com
"""
import glob
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

from vulnxscan_common import make_requester, ok, sevf, short_target

MARKER = "<!-- vulnxscan-diff-gate -->"
# vulnix 呼び出し 1 回あたりの最大 path 数 (argv 長制限の安全側チャンク)。
VULNIX_CHUNK = 400


def read_closure_file(path):
    """closure-paths.txt を (target, set(store_paths)) で読む。

    先頭付近の `# target: <TARGET>` ヘッダから target を、それ以外の非コメント行を
    store path として取る。
    """
    target = ""
    paths = set()
    with open(path) as f:
        for line in f:
            s = line.strip()
            if s.startswith("# target:"):
                target = s.split(":", 1)[1].strip()
            elif s and not s.startswith("#"):
                paths.add(s)
    return target, paths


def load_closures(directory):
    """directory 配下の **/closure-paths.txt を {target: set(paths)} で読む。"""
    out = {}
    for p in sorted(glob.glob(os.path.join(directory, "**", "closure-paths.txt"), recursive=True)):
        try:
            target, paths = read_closure_file(p)
        except OSError:
            continue
        if target:
            out[target] = paths
    return out


def run_vulnix(paths, *, runner=None):
    """Δ の store path 群を vulnix -R --json でスキャンし findings list を返す。

    戻り値: (findings, error)
      findings = [{"pname","version","vuln_id","severity"}], error = None なら成功
      error が非 None のときは scan 失敗 (fail-closed 対象)。
    vulnix の exit code は「脆弱性ありで非ゼロ」になるため成否判定には使わず、
    **stdout が JSON list として解釈できたか**で成否を判定する (vulnix がクラッシュすると
    stdout は空/非 JSON になり stderr に traceback が出る)。
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


def _default_runner(chunk):
    """実 vulnix を起動する (test 時は runner 差し替えで分離)。

    gate ジョブの store には Δ パスが無いことがあるため、vulnix が参照できるよう先に
    substituter (cache.nixos.org / Attic) から realise する。realise 失敗時はそのまま
    vulnix に進み、読めなければ JSON が返らず fail-closed になる。
    """
    subprocess.run(
        ["nix-store", "--realise", *chunk],
        capture_output=True,
        text=True,
        check=False,
    )
    proc = subprocess.run(
        ["vulnix", "-R", "--json", *chunk],
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


def load_whitelist(path):
    """gate 用 whitelist を読む。1 行 1 エントリ: `CVE-ID` または `pname,CVE-ID`。

    `CVE-ID` 単独はその CVE を全 package で抑制、`pname,CVE-ID` は当該 package のみ抑制。
    空行・`#` コメントは無視。受容理由は行末コメントで残す運用 (機械的には無視)。
    """
    cve_only = set()
    pkg_cve = set()
    if not path:
        return cve_only, pkg_cve
    try:
        with open(path) as f:
            for line in f:
                s = line.split("#", 1)[0].strip()
                if not s:
                    continue
                if "," in s:
                    pkg, cve = (x.strip() for x in s.split(",", 1))
                    pkg_cve.add((pkg, cve))
                else:
                    cve_only.add(s)
    except OSError:
        pass
    return cve_only, pkg_cve


def apply_whitelist(findings, wl):
    cve_only, pkg_cve = wl
    return [
        f
        for f in findings
        if f["vuln_id"] not in cve_only
        and (f["pname"], f["vuln_id"]) not in pkg_cve
    ]


def collect(head_dir, base_dir, whitelist, *, runner=None):
    """target ごとに Δ を取り vulnix で検査。

    戻り値: (introduced, baseline_missing, scan_failed)
      introduced = {(vuln_id, pname): {"severity","targets":set}}
      baseline_missing = [target...]  (base paths 不在で delta 未計算)
      scan_failed = {target: error}    (vulnix 未完走 = fail-closed 対象)
    """
    head = load_closures(head_dir)
    base = load_closures(base_dir)
    introduced = {}
    baseline_missing = []
    scan_failed = {}
    for target, head_paths in sorted(head.items()):
        label = short_target(target)
        if target not in base:
            baseline_missing.append(label)
            continue
        delta = head_paths - base[target]
        if not delta:
            continue
        findings, error = run_vulnix(delta, runner=runner)
        if error:
            scan_failed[label] = error
            continue
        for f in apply_whitelist(findings, whitelist):
            key = (f["vuln_id"], f["pname"])
            e = introduced.setdefault(
                key, {"severity": f["severity"], "targets": set()}
            )
            if sevf(f["severity"]) > sevf(e["severity"]):
                e["severity"] = f["severity"]
            e["targets"].add(label)
    return introduced, baseline_missing, scan_failed


def build_body(introduced, baseline_missing, scan_failed, gate_mode):
    """diff-gate コメントの markdown body を返す。"""
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
            " vulnix が完走しなかった target があり、新規流入の有無を判定できません。"
            " re-run してください:",
            "",
        ]
        for t, err in sorted(scan_failed.items()):
            lines.append(f"> - `{t}`: {err}")
        lines.append("")

    if introduced:
        items = sorted(
            introduced.items(), key=lambda kv: -sevf(kv[1]["severity"])
        )
        lines.append(f"**🆕 新規流入 {len(items)} 件**")
        lines.append("")
        if gate_mode:
            lines += [
                "> ⛔ **この PR は新規の既知脆弱性を持ち込むため auto-merge をブロックしました。**",
                "> 対応: 流入元の更新を見送る / パッケージを置換・削除する / "
                "意図的に受容する場合は理由付きで gate whitelist に追記する (再スキャンで解除)。",
                "",
            ]
        lines += [
            "| CVE | sev | pkg | 影響ターゲット |",
            "|---|---|---|---|",
        ]
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


def main(argv):
    gate_mode = "--gate" in argv[1:]
    whitelist_path = None
    pos = []
    it = iter(argv[1:])
    for a in it:
        if a == "--gate":
            continue
        if a == "--whitelist":
            whitelist_path = next(it, None)
            continue
        pos.append(a)
    head_dir = pos[0] if len(pos) > 0 else "head-paths"
    base_dir = pos[1] if len(pos) > 1 else "base-paths"
    pr_number = pos[2] if len(pos) > 2 else os.environ.get("GITHUB_PR_NUMBER", "")

    whitelist = load_whitelist(whitelist_path)
    introduced, baseline_missing, scan_failed = collect(head_dir, base_dir, whitelist)
    body, blocked = build_body(introduced, baseline_missing, scan_failed, gate_mode)

    upsert_comment(pr_number, body)

    summary = f"introduced {len(introduced)} / scan_failed {len(scan_failed)} / baseline_missing {len(baseline_missing)}"
    print(summary)
    if gate_mode and blocked:
        if scan_failed:
            print(f"::error::vulnix 未完走の target あり (fail-closed)。re-run してください: {sorted(scan_failed)}")
        if introduced:
            print(f"::error::この PR は新規脆弱性 {len(introduced)} 件を持ち込むため gate を fail させます。")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
