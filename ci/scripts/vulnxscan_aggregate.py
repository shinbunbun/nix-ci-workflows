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
agg = {}
for path in sorted(glob.glob(os.path.join(signals_dir, "**", "notify.json"), recursive=True)):
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        continue
    target = short_target(data.get("target", "?"))
    for fdg in data.get("findings", []):
        vid = fdg.get("vuln_id", "")
        if not vid:
            continue
        e = agg.setdefault(
            vid,
            {"severity": "", "packages": set(), "classifies": set(), "targets": set(),
             "cur": set(), "patch": set(), "bundled": set()},
        )
        if sevf(fdg.get("severity")) > sevf(e["severity"]):
            e["severity"] = fdg.get("severity") or ""
        e["packages"].add(fdg.get("package", ""))
        e["classifies"].add(fdg.get("classify", ""))
        e["targets"].add(target)
        if fdg.get("version_local"):
            e["cur"].add(fdg.get("version_local"))
        if fdg.get("version_nixpkgs"):
            e["patch"].add(fdg.get("version_nixpkgs"))
        b = fdg.get("bundled_by")
        if b and b != "—":
            e["bundled"].add(b)

items = sorted(agg.items(), key=lambda kv: -sevf(kv[1]["severity"]))
fixable = [(v, e) for v, e in items if "fix_update_to_version_nixpkgs" in e["classifies"]]
nofix = [(v, e) for v, e in items if "fix_update_to_version_nixpkgs" not in e["classifies"]]


def joinset(s):
    return ",".join(sorted(x for x in s if x))


# --- body 生成 ---
ts = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")
lines = [
    MARKER,
    "",
    f"自動生成 (最終更新: {ts})。vulnxscan の **NOTIFY** (latest nixpkgs でも残る = 要対処) を集約。",
    "",
    "> **凡例** — 🔧 **fixable**: nixpkgs に修正版あり、pin 解消/更新で直る（パッチ版明記）。"
    " 🛑 **no-fix**: 修正版が存在しない → Remove/Replace/Mitigate/受容(whitelist.csv)/upstream 待ち。"
    " auto-update で直る分(INFO)と誤検知(DROP)は除外済。詳細分類は各 run の job summary 参照。"
    " 由来=その版を closure に入れた親 (— は直接導入、`+N` は他にも N 件)。",
    "",
    f"**NOTIFY: {len(items)} CVE** (🔧 fixable {len(fixable)} / 🛑 no-fix {len(nofix)})",
    "",
]
if fixable:
    lines += ["### 🔧 fixable — pin 解消・更新で直る", "", "| CVE | sev | pkg | 現在版 | → パッチ版 | 由来 | 影響ターゲット |", "|---|---|---|---|---|---|---|"]
    for vid, e in fixable:
        url = f"https://nvd.nist.gov/vuln/detail/{vid}"
        lines.append(f"| [{vid}]({url}) | {e['severity']} | {joinset(e['packages'])} | {joinset(e['cur'])} | {joinset(e['patch'])} | {joinset(e['bundled']) or '—'} | {joinset(e['targets'])} |")
    lines.append("")
if nofix:
    lines += ["### 🛑 no-fix — 修正版なし (mitigation/受容/待ち)", "", "| CVE | sev | pkg | 現在版 | 由来 | 影響ターゲット |", "|---|---|---|---|---|---|"]
    for vid, e in nofix:
        url = f"https://nvd.nist.gov/vuln/detail/{vid}"
        lines.append(f"| [{vid}]({url}) | {e['severity']} | {joinset(e['packages'])} | {joinset(e['cur'])} | {joinset(e['bundled']) or '—'} | {joinset(e['targets'])} |")
    lines.append("")
if not items:
    lines.append("✅ 現在 NOTIFY 対象の脆弱性はありません。")
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
existing = next((it for it in issues if "pull_request" not in it), None)

if items:
    if existing:
        st, _ = req("PATCH", f"/repos/{repo}/issues/{existing['number']}", {"body": body, "state": "open"})
        must(st, f"issue #{existing['number']} の更新")
        print(f"updated issue #{existing['number']} ({len(items)} CVE)")
    else:
        st, _ = req("POST", f"/repos/{repo}/issues", {"title": TITLE, "body": body, "labels": [LABEL]})
        must(st, "issue の作成")
        print(f"created issue ({len(items)} CVE)")
else:
    if existing:
        st, _ = req("PATCH", f"/repos/{repo}/issues/{existing['number']}", {"body": body, "state": "closed"})
        must(st, f"issue #{existing['number']} の close")
        print(f"closed issue #{existing['number']} (NOTIFY 0)")
    else:
        print("no NOTIFY, no existing issue")
