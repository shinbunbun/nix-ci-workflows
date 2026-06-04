#!/usr/bin/env python3
"""Nixpkgs Security Tracker から CVE ごとの nixpkgs 権威ステータスを取得する (#285c/#289)。

usage: vulnxscan_tracker.py <csv_path> <out_json> [base_url]

triage CSV (<csv_path>) の vuln_id から CVE を集め、Tracker の
  GET <base_url>/api/v1/issues?cve=<CVE,CVE,...>
を叩いて {cve: status} を <out_json> に書く。status は human-readable
(affected / notaffected / notforus / wontfix / unknown)。1 CVE が複数 issue を
持つ場合は保守的にマージ (affected/wontfix を優先し downgrade を避ける)。

repology は非権威 proxy。triage が repology 単独で出した分類のうち
  - fix_not_available (no-fix)       → nixpkgs が notaffected なら backport 偽陽性の疑い
  - err_* (判定不能 UNKNOWN)          → nixpkgs の affected/notaffected で確度を補完
を summary 側で再検証するための入力を作る。

ネットワーク/パース失敗時は空 dict を書いて exit 0 (scan 継続・override 無し)。
これは「権威ソースが取れない時は現状維持」= 既存挙動を壊さず FN を増やさない安全側。
"""
import csv
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BASE = "https://tracker.security.nixos.org"
CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")
CHUNK = 50    # 1 リクエストあたりの CVE 数 (URL 長制限回避)
TIMEOUT = 20  # 秒。CI を無限に止めない

# 複数 issue のマージ優先度。affected/wontfix を上位に置き「該当を非該当へ降格
# しない」保守側に倒す。notaffected/notforus が summary 側の downgrade 候補。
_PRIORITY = ["affected", "wontfix", "notaffected", "notforus", "unknown"]


def collect_cves(csv_path):
    """triage CSV から CVE 形式の vuln_id を集める (重複排除・ソート)。"""
    out = set()
    try:
        with open(csv_path) as f:
            for row in csv.DictReader(f):
                vid = (row.get("vuln_id") or "").strip()
                if CVE_RE.match(vid):
                    out.add(vid)
    except FileNotFoundError:
        return []
    return sorted(out)


def merge_status(statuses):
    """1 CVE の複数 status を保守的に 1 つへ。優先度最上位を返す。"""
    s = set(statuses)
    for p in _PRIORITY:
        if p in s:
            return p
    return "unknown"


def _parse_items(data):
    """API レスポンス (bare list か {results, next} dict) から (items, next_url)。"""
    if isinstance(data, dict):
        return data.get("results", []), data.get("next")
    return (data if isinstance(data, list) else []), None


def fetch(cves, base_url=DEFAULT_BASE, opener=None):
    """CVE 群の {cve: merged_status}。失敗は例外送出 (呼び出し側で握る)。
    opener は test 用に差し替え可能 (urlopen 互換: (request, timeout=...) を取る)。
    None なら urllib.request.urlopen を関数内で解決 (default 引数の早期束縛を避ける)。"""
    if opener is None:
        opener = urllib.request.urlopen
    acc = {}  # cve -> [statuses]
    for i in range(0, len(cves), CHUNK):
        chunk = cves[i:i + CHUNK]
        nxt = f"{base_url}/api/v1/issues?" + urllib.parse.urlencode({"cve": ",".join(chunk)})
        while nxt:
            req = urllib.request.Request(nxt, headers={"Accept": "application/json"})
            with opener(req, timeout=TIMEOUT) as resp:
                data = json.loads(resp.read())
            items, nxt = _parse_items(data)
            for it in items:
                cve = it.get("cve")
                stt = it.get("status")
                if cve and stt:
                    acc.setdefault(cve, []).append(stt)
    return {cve: merge_status(sts) for cve, sts in acc.items()}


def main(argv):
    csv_path = argv[1] if len(argv) > 1 else "vulns.triage.csv"
    out_path = argv[2] if len(argv) > 2 else "tracker.json"
    base = argv[3] if len(argv) > 3 else DEFAULT_BASE
    cves = collect_cves(csv_path)
    result = {}
    if cves:
        try:
            result = fetch(cves, base)
        except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError) as ex:
            # 空のまま書く (override 無し = 現状維持)。scan 自体は止めない。
            sys.stderr.write(f"tracker fetch failed: {ex}\n")
    with open(out_path, "w") as f:
        json.dump(result, f, ensure_ascii=False)
    sys.stderr.write(f"tracker: {len(result)}/{len(cves)} CVE にステータス付与\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
