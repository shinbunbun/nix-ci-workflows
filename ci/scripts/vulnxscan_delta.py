#!/usr/bin/env python3
"""PR が新規導入/解消した NOTIFY (CVE) を抽出し、PR にコメントを 1 本 upsert する (#284)。

usage: vulnxscan_delta.py <head_signals_dir> <baseline_signals_dir> <pr_number>

差分(delta)スキャン = 「この PR が新たに持ち込んだ / 解消した CVE だけ」を出す report-only 機能。
full-closure の集約 Issue (#283, vulnxscan_aggregate.py) とは別経路 (PR コメント)。

base は **main の最新成功スキャンの artifact** (案B)。head はこの run のスキャン結果。
両者の notify.json の **要対処集合 (NOTIFY findings + judged-affected)** を target ごとに diff する:
  🆕 introduced = head にあって baseline に無い (= この PR/更新が持ち込んだ)
  ✅ resolved    = baseline にあって head に無い (= この PR/更新が解消した)

baseline 不在 (初回スキャン / artifact 失効 / target 増減) は graceful に注記して非 fail。
report-only なので CI を止めることはしない。

env:
  GITHUB_TOKEN       無い場合は dry-run (body を stdout 出力して終了)
  GITHUB_REPOSITORY  "owner/repo"
  GITHUB_API_URL     省略時 https://api.github.com
"""
import glob
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

from vulnxscan_common import sevf, short_target

MARKER = "<!-- vulnxscan-delta -->"


def load_signals(signals_dir):
    """signals_dir 配下の */notify.json を読み、要対処 finding を
    {(target, vuln_id, package): meta} で返す。targets セットも併せて返す
    (delta を計算できない target を baseline 不在として検出するため)。

    要対処集合 = NOTIFY (findings = fixable + no-fix) + judged-affected (NVD で該当確定し昇格)。
    UNKNOWN/spot-check/reclassified/likely-FP は「確定要対処」ではないので delta から除外し、
    PR コメントを actionable な変化だけに絞る。
    """
    keyed = {}
    targets = set()
    for path in sorted(glob.glob(os.path.join(signals_dir, "**", "notify.json"), recursive=True)):
        try:
            with open(path) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        target = short_target(data.get("target", "?"))
        targets.add(target)
        for bucket, kind in (("findings", ""), ("judged", "judged")):
            for fdg in data.get(bucket, []):
                vid = fdg.get("vuln_id", "")
                pkg = fdg.get("package", "")
                if not vid:
                    continue
                # kind: judged は判定確定枠。findings は classify で fixable/no-fix を区別。
                if kind == "judged":
                    k = "judged"
                elif "fix_update_to_version_nixpkgs" in (fdg.get("classify", "") or ""):
                    k = "fixable"
                else:
                    k = "no-fix"
                ent = fdg.get("entry") or fdg.get("bundled_by") or "—"
                keyed[(target, vid, pkg)] = {
                    "severity": fdg.get("severity", ""),
                    "kind": k,
                    "entry": ent,
                }
    return keyed, targets


def group(keys, src):
    """(target, vid, pkg) キー群を (vid, pkg) で畳み込み、影響 target を列挙する。
    meta (sev/kind/entry) は src 側 (introduced=head / resolved=baseline) から取る。"""
    agg = {}
    for (target, vid, pkg) in keys:
        meta = src[(target, vid, pkg)]
        e = agg.setdefault((vid, pkg), {"severity": "", "kind": meta["kind"],
                                        "targets": set(), "entry": set()})
        if sevf(meta["severity"]) > sevf(e["severity"]):
            e["severity"] = meta["severity"]
        e["targets"].add(target)
        if meta["entry"] and meta["entry"] != "—":
            e["entry"].add(meta["entry"])
    return sorted(agg.items(), key=lambda kv: -sevf(kv[1]["severity"]))


KIND_LABEL = {"fixable": "🔧 fixable", "no-fix": "🛑 no-fix", "judged": "✅ judged"}


def entrycol(e):
    return ",".join(sorted(x for x in e["entry"] if x)) or "—"


def render_table(rows):
    out = ["| CVE | sev | pkg | 種別 | 入口 (設定) | 影響ターゲット |",
           "|---|---|---|---|---|---|"]
    for (vid, pkg), e in rows:
        url = f"https://nvd.nist.gov/vuln/detail/{vid}"
        out.append(f"| [{vid}]({url}) | {e['severity']} | {pkg} | "
                   f"{KIND_LABEL.get(e['kind'], e['kind'])} | {entrycol(e)} | "
                   f"{','.join(sorted(e['targets']))} |")
    return out


def compute_delta(head_dir, base_dir):
    """head/baseline の signals から (introduced, resolved, baseline_missing,
    head_missing, have_baseline) を計算する。"""
    head, head_targets = load_signals(head_dir)
    base, base_targets = load_signals(base_dir)

    # baseline に存在しない (= main 最新スキャンに無い) target は delta を計算できない。
    # 新規 config / artifact 失効が原因。これらは「📭 baseline 不在」として注記し、
    # その target の finding は introduced から除外する (baseline が無いだけで
    # 「新規流入」ではないため。誤って 🆕 に出さない)。
    baseline_missing = sorted(head_targets - base_targets)
    # 逆に baseline にあって head に無い target は head 側スキャン失敗 (matrix leg 失敗で
    # artifact 欠落) の可能性。これを resolved に含めると「PR が全部解消した」と誤表示するので、
    # 対称に除外して注記する (config 削除との区別は付かないが、誤った安心を出さない方を優先)。
    head_missing = sorted(base_targets - head_targets)
    have_baseline = bool(base_targets)

    introduced_keys = sorted(k for k in set(head) - set(base) if k[0] in base_targets)
    resolved_keys = sorted(k for k in set(base) - set(head) if k[0] in head_targets)

    introduced = group(introduced_keys, head)
    resolved = group(resolved_keys, base)
    return introduced, resolved, baseline_missing, head_missing, have_baseline


def build_body(head_dir, base_dir, gate_mode):
    """delta コメントの markdown body と (introduced, resolved) を返す。"""
    introduced, resolved, baseline_missing, head_missing, have_baseline = compute_delta(
        head_dir, base_dir)

    # --- body 生成 ---
    ts = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")
    lines = [
        MARKER,
        "",
        "## 🔬 vulnxscan delta — この PR が変える脆弱性"
        + ("（**新規流入で auto-merge ブロック**）" if gate_mode else "（report-only）"),
        "",
        f"自動生成 (最終更新: {ts})。base = **main の最新スキャン**、head = この PR のクロージャ。"
        " 要対処集合 (NOTIFY + judged-affected) の差分のみ。既存の CVE は集約 Issue #283 を参照。",
        "",
    ]

    if not have_baseline:
        lines += [
            "> 📭 **baseline 不在** — main の最新成功スキャン artifact が見つからないため delta を計算できません。",
            "> (初回スキャン / artifact 失効 / ワークフロー名変更などが原因。次回 main スキャン後に解消します。)",
        ]
    elif not introduced and not resolved:
        lines += [
            "✅ **この PR は要対処 CVE 集合を変えません** (新規流入・解消ともになし)。",
        ]
    else:
        lines.append(f"**🆕 新規流入 {len(introduced)} ・ ✅ 解消 {len(resolved)}**")
        lines.append("")
        if gate_mode and introduced:
            lines += [
                "> ⛔ **この PR は新規の脆弱性を持ち込むため auto-merge をブロックしました。**",
                "> 対応: 流入元の更新を見送る / パッケージを置換・削除する / "
                "意図的に受容する場合は理由付きで `whitelist.csv` に追記する (再スキャンで gate 解除)。",
                "",
            ]
        if introduced:
            lines += ["### 🆕 この PR が新規流入させる CVE", ""]
            lines += render_table(introduced)
            lines.append("")
        if resolved:
            lines += ["### ✅ この PR が解消する CVE", ""]
            lines += render_table(resolved)
            lines.append("")

    if baseline_missing:
        lines += [
            "",
            "> 📭 次の target は baseline が無く delta 未計算: "
            + ", ".join(f"`{t}`" for t in baseline_missing),
        ]
    if head_missing:
        lines += [
            "",
            "> ⚠️ 次の target は今回のスキャン結果が無く delta 未計算 "
            "(scan 失敗 or config 削除の可能性): "
            + ", ".join(f"`{t}`" for t in head_missing),
        ]

    lines += [
        "",
        ("> 確定FP/リスク受容は `whitelist.csv` に追記すると introduced から外れ gate が解除されます。"
         if gate_mode else
         "> report-only。確定FP/リスク受容は `whitelist.csv` に追記すると以降抑制されます。")
        + " 詳細分類は各 target の job summary 参照。",
    ]
    return "\n".join(lines), introduced, resolved


def main(argv):
    # --gate: introduced > 0 のとき exit 1 を返し、required status check を fail させて
    # auto-merge をブロックする (#284 blocking モード)。フラグは positional 引数より先に除去する。
    gate_mode = "--gate" in argv[1:]
    _pos = [a for a in argv[1:] if a != "--gate"]
    head_dir = _pos[0] if len(_pos) > 0 else "head-signals"
    base_dir = _pos[1] if len(_pos) > 1 else "baseline-signals"
    pr_number = _pos[2] if len(_pos) > 2 else os.environ.get("GITHUB_PR_NUMBER", "")

    body, introduced, resolved = build_body(head_dir, base_dir, gate_mode)

    # gate モード時は introduced があれば最終的に exit 1 で required check を fail させる
    # (auto-merge ブロック)。コメント投稿の成否とは独立に評価する。
    gate_fail = gate_mode and bool(introduced)

    repo = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN")
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")

    if not token or not repo or not pr_number:
        print("[dry-run] GITHUB_TOKEN / GITHUB_REPOSITORY / PR 番号 のいずれか未設定。body:\n")
        print(body)
        return 1 if gate_fail else 0

    def req(method, path, payload=None):
        url = path if path.startswith("http") else f"{api}{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        r = urllib.request.Request(url, data=data, method=method)
        r.add_header("Authorization", f"Bearer {token}")
        r.add_header("Accept", "application/vnd.github+json")
        r.add_header("X-GitHub-Api-Version", "2022-11-28")
        if data:
            r.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(r) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as ex:
            return ex.code, None

    def ok(status):
        return 200 <= status < 300

    # PR コメント (= issue コメント) を MARKER で探して upsert。再 push でスパムしない。
    # 一覧取得に失敗したらコメントはスキップするが、gate モードで introduced があれば
    # 末尾と同じく exit 1 で block する (コメント投稿の成否と gate 判定は独立)。
    st, comments = req("GET", f"/repos/{repo}/issues/{pr_number}/comments?per_page=100")
    if st != 200 or not isinstance(comments, list):
        print(f"::warning::PR #{pr_number} のコメント一覧取得に失敗 (status={st})。delta コメントをスキップ。")
        return 1 if gate_fail else 0

    existing = next((c for c in comments if MARKER in (c.get("body") or "")), None)
    summary = f"introduced {len(introduced)} / resolved {len(resolved)}"
    if existing:
        st, _ = req("PATCH", f"/repos/{repo}/issues/comments/{existing['id']}", {"body": body})
        if ok(st):
            print(f"updated delta comment on PR #{pr_number} ({summary})")
        else:
            print(f"::warning::delta コメント更新に失敗 (status={st})")
    else:
        st, _ = req("POST", f"/repos/{repo}/issues/{pr_number}/comments", {"body": body})
        if ok(st):
            print(f"created delta comment on PR #{pr_number} ({summary})")
        else:
            print(f"::warning::delta コメント作成に失敗 (status={st})")

    # gate モード: 新規流入があれば exit 1 で required check を fail → auto-merge をブロック。
    if gate_fail:
        print(f"::error::この PR は新規脆弱性 {len(introduced)} 件を持ち込むため gate を fail させます "
              f"(auto-merge ブロック)。whitelist.csv で受容するか流入元を見直してください。")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
