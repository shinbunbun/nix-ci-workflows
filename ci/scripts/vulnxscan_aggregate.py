#!/usr/bin/env python3
"""各ターゲットの NOTIFY (notify.json) を集約し、GitHub Issue を1本 upsert する。

usage: vulnxscan_aggregate.py <signals_dir>

<signals_dir> 配下の */notify.json (download-artifact が artifact ごとに作るサブdir) を読み、
vuln_id で dedup (影響ターゲット列挙) して、🔧 fixable / 🛑 no-fix に分けた本文で
ラベル付き Issue を find-or-create-or-update する。

env:
  GITHUB_TOKEN       無い場合は dry-run (body を stdout 出力して終了)
  GITHUB_REPOSITORY  "owner/repo"
  GITHUB_API_URL     省略時 https://api.github.com
"""
import glob
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

signals_dir = sys.argv[1] if len(sys.argv) > 1 else "signals"
LABEL = "vulnxscan"
TITLE = "🔎 vulnxscan: 脆弱性スキャン結果 (自動)"
MARKER = "<!-- vulnxscan-auto -->"


def sevf(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def short_target(t):
    """'.#nixosConfigurations.nixos-desktop.config...' -> 'nixos-desktop' (表示短縮)。"""
    m = re.search(r"(?:nixos|darwin)Configurations\.([^.]+)", t)
    return m.group(1) if m else t


# --- notify.json 収集 + vuln_id で dedup ---
def _new_entry():
    return {"severity": "", "packages": set(), "classifies": set(), "targets": set(),
            "cur": set(), "patch": set(), "entry": set(), "base_n": 0, "tracker": "",
            "jrange": set(), "fpreason": set(), "nvdcpe": set()}


def _accumulate(agg, target, fdg):
    """1 finding を vuln_id で dedup しながら agg に畳み込む (影響ターゲット列挙)。"""
    vid = fdg.get("vuln_id", "")
    if not vid:
        return
    e = agg.setdefault(vid, _new_entry())
    if sevf(fdg.get("severity")) > sevf(e["severity"]):
        e["severity"] = fdg.get("severity") or ""
    e["packages"].add(fdg.get("package", ""))
    e["classifies"].add(fdg.get("classify", ""))
    e["targets"].add(target)
    # nixpkgs (Tracker) ステータスは CVE 単位なので target 間で同一。非空を 1 つ保持。
    if fdg.get("tracker"):
        e["tracker"] = fdg["tracker"]
    # identity フィールドから verdict 別の補助情報を抽出 (該当しない bucket は空のまま)。
    ident = fdg.get("identity")
    if isinstance(ident, dict):
        v = ident.get("verdict")
        if v == "affected":  # judged の NVD CPE 版範囲
            jr = f"{ident.get('cpe', '')} {ident.get('range', '')}".strip()
            if jr:
                e["jrange"].add(jr)
        elif v == "disputed":  # likely-FP の NVD タグ降格理由 (#289)
            st = ident.get("status", "")
            tail = f" ({st})" if st and st.lower() == "rejected" else ""
            e["fpreason"].add(f"NVD tag: {ident.get('reason', '')}{tail}")
        elif v == "not_in_range":  # likely-FP の CPE 版範囲外降格理由 (#289)
            e["fpreason"].add(f"版範囲外 {ident.get('cpe', '')} {ident.get('range', '')}".strip())
        elif v == "nofix_cpe":  # no-fix 据え置きの NVD CPE 判定注記 (#289 表示拡張)
            kind, detail = ident.get("kind"), ident.get("detail", "")
            label = ({"confirmed": f"該当確定 {detail}", "date": f"日付上限 {detail}",
                      "nobound": "上限なし"}.get(kind) or "").strip()
            if label:
                e["nvdcpe"].add(label)
    if fdg.get("version_local"):
        e["cur"].add(fdg.get("version_local"))
    if fdg.get("version_nixpkgs"):
        e["patch"].add(fdg.get("version_nixpkgs"))
    # entry (入口/設定)。"基盤依存 (N 入口)" は target ごとに N が揺れるので、
    # 個別文字列を set に積まず最大入口数だけ保持して 1 つに集約する。
    ent = fdg.get("entry") or fdg.get("bundled_by")  # bundled_by は旧 artifact 互換
    if ent and ent != "—":
        m = re.fullmatch(r"基盤依存 \((\d+) 入口\)", ent)
        if m:
            e["base_n"] = max(e["base_n"], int(m.group(1)))
        else:
            e["entry"].add(ent)


# NOTIFY / judged / UNKNOWN / spot-check / reclassified / likely-FP を別集合で集約
# (notify.json の各キー、無ければ空)。
agg_notify, agg_judged, agg_unknown, agg_spot, agg_reclass, agg_likely = {}, {}, {}, {}, {}, {}
for path in sorted(glob.glob(os.path.join(signals_dir, "**", "notify.json"), recursive=True)):
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        continue
    target = short_target(data.get("target", "?"))
    for fdg in data.get("findings", []):
        _accumulate(agg_notify, target, fdg)
    for fdg in data.get("judged", []):
        _accumulate(agg_judged, target, fdg)
    for fdg in data.get("unknown", []):
        _accumulate(agg_unknown, target, fdg)
    for fdg in data.get("spotcheck", []):
        _accumulate(agg_spot, target, fdg)
    for fdg in data.get("reclassified", []):
        _accumulate(agg_reclass, target, fdg)
    for fdg in data.get("likely_fp", []):
        _accumulate(agg_likely, target, fdg)


def _sort_items(agg):
    return sorted(agg.items(), key=lambda kv: -sevf(kv[1]["severity"]))


items = _sort_items(agg_notify)
fixable = [(v, e) for v, e in items if "fix_update_to_version_nixpkgs" in e["classifies"]]
nofix = [(v, e) for v, e in items if "fix_update_to_version_nixpkgs" not in e["classifies"]]
judged_items = _sort_items(agg_judged)
unknown_items = _sort_items(agg_unknown)
spot_items = _sort_items(agg_spot)
reclass_items = _sort_items(agg_reclass)
likely_items = _sort_items(agg_likely)
tracker_on = bool(reclass_items) or any(e["tracker"] for _, e in items + unknown_items)
# no-fix の NVD CPE 判定列は注記が 1 件でもある時だけ出す (全部 — なら列を増やさない)。
nofixcpe_on = any(e["nvdcpe"] for _, e in nofix)


def joinset(s):
    return ",".join(sorted(x for x in s if x))


def entrycol(e):
    """入口 (設定) 列。列挙された入口 + (あれば) 集約した基盤依存 (max N 入口)。"""
    parts = sorted(x for x in e["entry"] if x)
    if e["base_n"]:
        parts.append(f"基盤依存 ({e['base_n']} 入口)")
    return ",".join(parts) or "—"


def trkcol(e):
    """nixpkgs (Tracker) 権威ステータス列。未登録は — 。"""
    return e["tracker"] or "—"


def fpreasoncol(e):
    """🟢 likely-FP の降格理由列 (NVD タグ / 版範囲外)。"""
    return ",".join(sorted(x for x in e["fpreason"] if x)) or "—"


def nvdcpecol(e):
    """no-fix の NVD CPE 判定列 (#289)。該当確定=本物 TP / 上限なし・日付上限=要確認 FP 候補。"""
    return ",".join(sorted(x for x in e["nvdcpe"] if x)) or "—"


def _trk_h():
    """tracker 有効時のみ nixpkgs 列ヘッダ片を返す (無効時は空)。"""
    return "nixpkgs | " if tracker_on else ""


def _trk_c(e):
    return f"{trkcol(e)} | " if tracker_on else ""


# --- body 生成 ---
ts = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")
lines = [
    MARKER,
    "",
    f"自動生成 (最終更新: {ts})。vulnxscan の **NOTIFY** (latest nixpkgs でも残る = 要対処) を集約。",
    "",
    "> **凡例**\n>\n"
    "> - 🔧 **fixable**: nixpkgs に修正版あり、pin 解消/更新で直る（パッチ版明記）\n"
    "> - 🛑 **no-fix**: 修正版が存在しない → Remove/Replace/Mitigate/受容(whitelist.csv)/upstream 待ち。"
    "**判定 (NVD CPE)** 列=該当確定(NVD 版範囲内=本物 TP)/上限なし(NVD に修正版データ無し)/"
    "日付上限(修正が git-master commit で release 未反映=要 backport 確認・FP 候補)/—(NVD 未照会・vendor 不一致)\n"
    "> - ✅ **judged-affected**: repology が判定不能/非該当としたが NVD CPE の版範囲で該当確定し "
    "UNKNOWN/spot-check/非該当 DROP から昇格 (vendor 一致 + clean 版のみの保守判定)\n"
    "> - ❓ **UNKNOWN**: repology にデータ無し/版解析失敗で判定不能 (safe ではない、要確認)\n"
    "> - 🔁 **reclassified**: Nixpkgs Security Tracker が notaffected/notforus と判断 "
    "(backport patch/対象外) し no-fix/UNKNOWN から降格した要確認・whitelist 候補\n"
    "> - 🟢 **likely-FP**: no-fix のうち NVD の権威データ (cveTags=disputed 等 / 版範囲外) で"
    "偽陽性疑いと判定し降格した要確認・whitelist 候補 (#289)\n"
    "> - **nixpkgs** 列=Tracker の権威ステータス (affected/wontfix/notaffected/notforus、— は未登録)\n"
    "> - 🔍 **spot-check**: repology は非該当判定だが high-sev のため誤判定保険として併載 (DROP 維持)。"
    "auto-update で直る分(INFO)と誤検知(DROP)は除外済。詳細分類は各 run の job summary 参照\n"
    "> - 入口(設定)=その版を closure に入れた宣言 (systemPackages/home.packages) とソースファイル"
    " (そこを更新/削除/service 無効化で解消)。『基盤依存』=多数参照の基盤ライブラリで config 単独不可、nixpkgs 更新待ち",
    "",
    f"**NOTIFY: {len(items)} CVE** (🔧 fixable {len(fixable)} / 🛑 no-fix {len(nofix)})"
    + (f" ・ ✅ judged-affected {len(judged_items)}" if judged_items else "")
    + f" ・ ❓ UNKNOWN {len(unknown_items)}"
    + (f" ・ 🔁 reclassified {len(reclass_items)}" if reclass_items else "")
    + (f" ・ 🟢 likely-FP {len(likely_items)}" if likely_items else "")
    + (f" ・ 🔍 spot-check {len(spot_items)}" if spot_items else ""),
    "",
]
if fixable:
    lines += ["### 🔧 fixable — pin 解消・更新で直る", "", "| CVE | sev | pkg | 現在版 | → パッチ版 | 入口 (設定) | 影響ターゲット |", "|---|---|---|---|---|---|---|"]
    for vid, e in fixable:
        url = f"https://nvd.nist.gov/vuln/detail/{vid}"
        lines.append(f"| [{vid}]({url}) | {e['severity']} | {joinset(e['packages'])} | {joinset(e['cur'])} | {joinset(e['patch'])} | {entrycol(e)} | {joinset(e['targets'])} |")
    lines.append("")
if judged_items:
    lines += ["### ✅ judged-affected — NVD 版範囲で該当確定 (repology の判定不能/非該当から昇格)", "", "| CVE | sev | pkg | 現在版 | 判定 (NVD CPE) | 入口 (設定) | 影響ターゲット |", "|---|---|---|---|---|---|---|"]
    for vid, e in judged_items:
        url = f"https://nvd.nist.gov/vuln/detail/{vid}"
        lines.append(f"| [{vid}]({url}) | {e['severity']} | {joinset(e['packages'])} | {joinset(e['cur'])} | {joinset(e['jrange'])} | {entrycol(e)} | {joinset(e['targets'])} |")
    lines.append("")
if nofix:
    _nch = "判定 (NVD CPE) | " if nofixcpe_on else ""
    _nch_sep = "---|" if nofixcpe_on else ""
    lines += ["### 🛑 no-fix — 修正版なし (mitigation/受容/待ち)", "", f"| CVE | sev | pkg | 現在版 | {_trk_h()}{_nch}入口 (設定) | 影響ターゲット |", "|---|---|---|---|" + ("---|" if tracker_on else "") + _nch_sep + "---|---|"]
    for vid, e in nofix:
        url = f"https://nvd.nist.gov/vuln/detail/{vid}"
        _nc = f"{nvdcpecol(e)} | " if nofixcpe_on else ""
        lines.append(f"| [{vid}]({url}) | {e['severity']} | {joinset(e['packages'])} | {joinset(e['cur'])} | {_trk_c(e)}{_nc}{entrycol(e)} | {joinset(e['targets'])} |")
    lines.append("")
if unknown_items:
    lines += ["### ❓ UNKNOWN — 判定不能 (要確認・safe ではない)", "", f"| CVE | sev | pkg | 現在版 | 理由 | {_trk_h()}入口 (設定) | 影響ターゲット |", "|---|---|---|---|---|" + ("---|" if tracker_on else "") + "---|---|"]
    for vid, e in unknown_items:
        url = f"https://nvd.nist.gov/vuln/detail/{vid}"
        lines.append(f"| [{vid}]({url}) | {e['severity']} | {joinset(e['packages'])} | {joinset(e['cur'])} | {joinset(e['classifies'])} | {_trk_c(e)}{entrycol(e)} | {joinset(e['targets'])} |")
    lines.append("")
if reclass_items:
    lines += ["### 🔁 reclassified — Nixpkgs Tracker が非該当判断 (要確認・whitelist 候補)", "", "| CVE | sev | pkg | 現在版 | 元分類 | nixpkgs | 入口 (設定) | 影響ターゲット |", "|---|---|---|---|---|---|---|---|"]
    for vid, e in reclass_items:
        url = f"https://nvd.nist.gov/vuln/detail/{vid}"
        lines.append(f"| [{vid}]({url}) | {e['severity']} | {joinset(e['packages'])} | {joinset(e['cur'])} | {joinset(e['classifies'])} | {trkcol(e)} | {entrycol(e)} | {joinset(e['targets'])} |")
    lines.append("")
if likely_items:
    lines += ["### 🟢 likely-FP — no-fix 偽陽性疑い (NVD タグ/版範囲・要確認・whitelist 候補)", "", "| CVE | sev | pkg | 現在版 | 降格理由 (NVD) | 入口 (設定) | 影響ターゲット |", "|---|---|---|---|---|---|---|"]
    for vid, e in likely_items:
        url = f"https://nvd.nist.gov/vuln/detail/{vid}"
        lines.append(f"| [{vid}]({url}) | {e['severity']} | {joinset(e['packages'])} | {joinset(e['cur'])} | {fpreasoncol(e)} | {entrycol(e)} | {joinset(e['targets'])} |")
    lines.append("")
if spot_items:
    lines += ["### 🔍 spot-check — repology 非該当・high-sev (念のため確認・自動 DROP)", "", "| CVE | sev | pkg | 現在版 | 入口 (設定) | 影響ターゲット |", "|---|---|---|---|---|---|"]
    for vid, e in spot_items:
        url = f"https://nvd.nist.gov/vuln/detail/{vid}"
        lines.append(f"| [{vid}]({url}) | {e['severity']} | {joinset(e['packages'])} | {joinset(e['cur'])} | {entrycol(e)} | {joinset(e['targets'])} |")
    lines.append("")
# 要対処/要確認 = NOTIFY / judged / UNKNOWN / reclassified / likely-FP。judged は該当確定の要対処。
# reclassified / likely-FP は「確認して whitelist する」人手 action が残るので open 維持。spot-check は
# DROP 維持の「念のため」枠なので単独では Issue を open し続けない (常時 alarm 化を避ける)。
has_content = bool(items or judged_items or unknown_items or reclass_items or likely_items)
if not has_content:
    lines.append("✅ 現在 NOTIFY / UNKNOWN / reclassified 対象の脆弱性はありません。")
else:
    lines.append("> 確定FP/リスク受容は whitelist.csv に追記すると以降抑制されます。")
body = "\n".join(lines)

repo = os.environ.get("GITHUB_REPOSITORY")
token = os.environ.get("GITHUB_TOKEN")
api = os.environ.get("GITHUB_API_URL", "https://api.github.com")

if not token or not repo:
    print("[dry-run] GITHUB_TOKEN / GITHUB_REPOSITORY 未設定。body:\n")
    print(body)
    sys.exit(0)


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


def must(status, action):
    if not ok(status):
        print(f"::error::{action} に失敗しました (status={status})")
        sys.exit(1)


# ラベルを保証
st, _ = req("GET", f"/repos/{repo}/labels/{LABEL}")
if st == 404:
    req("POST", f"/repos/{repo}/labels", {"name": LABEL, "color": "b60205", "description": "vulnxscan 自動脆弱性レポート"})

# 既存 open issue (PR は除外)。GET 失敗時は重複起票を避けるため中断する。
st, issues = req("GET", f"/repos/{repo}/issues?labels={LABEL}&state=open&per_page=100")
if st != 200 or not isinstance(issues, list):
    print(f"::error::issue 一覧取得に失敗 (status={st})。重複起票回避のため中断します。")
    sys.exit(1)
# 対象は自動生成レポート issue だけ。`vulnxscan` ラベルは他の手動 issue (機能 Issue 等) にも
# 付くため「ラベル先頭一致」では別 issue を誤って上書きしうる (実害例: #294 を上書き)。
# MARKER (本文先頭の隠しコメント) または完全一致タイトルで本レポート issue のみを選ぶ。
existing = next(
    (it for it in issues
     if "pull_request" not in it
     and (MARKER in (it.get("body") or "") or it.get("title") == TITLE)),
    None,
)

cnt = f"NOTIFY {len(items)} / judged {len(judged_items)} / UNKNOWN {len(unknown_items)} / reclassified {len(reclass_items)} / likely-FP {len(likely_items)}"
if has_content:
    if existing:
        st, _ = req("PATCH", f"/repos/{repo}/issues/{existing['number']}", {"body": body, "state": "open"})
        must(st, f"issue #{existing['number']} の更新")
        print(f"updated issue #{existing['number']} ({cnt})")
    else:
        st, _ = req("POST", f"/repos/{repo}/issues", {"title": TITLE, "body": body, "labels": [LABEL]})
        must(st, "issue の作成")
        print(f"created issue ({cnt})")
else:
    if existing:
        st, _ = req("PATCH", f"/repos/{repo}/issues/{existing['number']}", {"body": body, "state": "closed"})
        must(st, f"issue #{existing['number']} の close")
        print(f"closed issue #{existing['number']} (NOTIFY 0 / UNKNOWN 0 / reclassified 0)")
    else:
        print("no NOTIFY/UNKNOWN/reclassified, no existing issue")
