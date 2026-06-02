#!/usr/bin/env python3
"""各ターゲットの NOTIFY (notify.json) を集約し、GitHub Issue を1本 upsert する。

usage: vulnxscan_aggregate.py <signals_dir>

<signals_dir> 配下の */notify.json (download-artifact が artifact ごとに作るサブdir) を読み、
vuln_id で dedup (影響ターゲットを列挙) して、ラベル付き Issue を find-or-create-or-update する。

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

signals_dir = sys.argv[1] if len(sys.argv) > 1 else "signals"
LABEL = "vulnxscan"
TITLE = "🔎 vulnxscan: 脆弱性スキャン結果 (自動)"
MARKER = "<!-- vulnxscan-auto -->"


def sevf(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


# --- notify.json 収集 + vuln_id で dedup ---
agg = {}
for path in sorted(glob.glob(os.path.join(signals_dir, "**", "notify.json"), recursive=True)):
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        continue
    target = data.get("target", "?")
    for fdg in data.get("findings", []):
        vid = fdg.get("vuln_id", "")
        if not vid:
            continue
        e = agg.setdefault(
            vid,
            {"severity": "", "packages": set(), "classifies": set(), "targets": set()},
        )
        if sevf(fdg.get("severity")) > sevf(e["severity"]):
            e["severity"] = fdg.get("severity") or ""
        e["packages"].add(fdg.get("package", ""))
        e["classifies"].add(fdg.get("classify", ""))
        e["targets"].add(target)

items = sorted(agg.items(), key=lambda kv: -sevf(kv[1]["severity"]))

# --- body 生成 ---
ts = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")
lines = [
    MARKER,
    "",
    f"自動生成 (最終更新: {ts})。vulnxscan の **NOTIFY** (latest nixpkgs でも残る = 要対処/mitigation) を集約。",
    "",
]
if items:
    lines += [f"**NOTIFY: {len(items)} CVE**", "", "| CVE | sev | pkg | classify | 影響ターゲット |", "|---|---|---|---|---|"]
    for vid, e in items:
        url = f"https://nvd.nist.gov/vuln/detail/{vid}"
        lines.append(
            f"| [{vid}]({url}) | {e['severity']} | {','.join(sorted(p for p in e['packages'] if p))} "
            f"| {','.join(sorted(c for c in e['classifies'] if c))} | {','.join(sorted(e['targets']))} |"
        )
    lines += ["", "> 確定FP/リスク受容は whitelist.csv に追記すると以降抑制されます。"]
else:
    lines.append("✅ 現在 NOTIFY 対象の脆弱性はありません。")
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


# ラベルを保証
st, _ = req("GET", f"/repos/{repo}/labels/{LABEL}")
if st == 404:
    req("POST", f"/repos/{repo}/labels", {"name": LABEL, "color": "b60205", "description": "vulnxscan 自動脆弱性レポート"})

def ok(status):
    return 200 <= status < 300


def must(status, action):
    # mutating 失敗を握り潰さない (silent green 回避)
    if not ok(status):
        print(f"::error::{action} に失敗しました (status={status})")
        sys.exit(1)


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
