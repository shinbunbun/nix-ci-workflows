#!/usr/bin/env python3
"""vulnxscan の (triage) CSV を GitHub Actions job summary 用 markdown に変換する。

usage: vulnxscan_summary.py <csv_path> <target>

scan-vulnerabilities.yaml (reusable workflow) から呼ばれる。
"""
import csv
import sys
from collections import Counter

path = sys.argv[1] if len(sys.argv) > 1 else "vulns.triage.csv"
target = sys.argv[2] if len(sys.argv) > 2 else "(unknown)"


def sevf(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


try:
    with open(path) as f:
        rows = list(csv.DictReader(f))
except FileNotFoundError:
    print("## 🔎 vulnxscan\n")
    print("⚠️ 出力 CSV が見つかりません（スキャン失敗の可能性）。ジョブログを確認してください。")
    sys.exit(0)

total = len(rows)
pkgs = len({r.get("package", "") for r in rows})
cols = list(rows[0].keys()) if rows else []
has_classify = "classify" in cols

print("## 🔎 vulnxscan 結果\n")
print(f"- **target**: `{target}`")
print(f"- **検出**: {total} CVE / {pkgs} packages\n")

if not rows:
    print("✅ 脆弱性は検出されませんでした。")
    sys.exit(0)

if has_classify:
    c = Counter(r["classify"] for r in rows)
    print("### classify 分布\n")
    print("| classify | 件数 |")
    print("|---|---|")
    for k, v in c.most_common():
        print(f"| {k} | {v} |")

    fp = c.get("err_not_vulnerable_based_on_repology", 0)
    act = [r for r in rows if r["classify"] == "fix_update_to_version_nixpkgs"]
    print()
    print(f"- **即対処可能 (fix_update_to_version_nixpkgs)**: {len(act)}")
    print(f"- **repology 上 非該当 (誤検知候補)**: {fp} ({fp * 100 // total if total else 0}%)\n")

    hi = sorted((r for r in act if sevf(r.get("severity")) >= 7), key=lambda r: -sevf(r.get("severity")))
    if hi:
        print("### 即対処可能 & severity>=7（要 adjudication）\n")
        print("| CVE | sev | pkg | local → nixpkgs |")
        print("|---|---|---|---|")
        for r in hi[:20]:
            print(
                f"| {r.get('vuln_id', '')} | {r.get('severity', '')} | {r.get('package', '')} "
                f"| {r.get('version_local', '')} → {r.get('version_nixpkgs', '')} |"
            )
    print(
        "\n> ⚠️ 自動 triage は一次フィルタ。high-sev は実 closure バージョンや "
        "Nixpkgs Security Tracker で要 adjudication。"
    )
else:
    print("(triage 無効: classify 列なし。`--triage` を有効にすると分類が付きます。)")
