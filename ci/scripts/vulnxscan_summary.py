#!/usr/bin/env python3
"""vulnxscan の (triage) CSV を signal/info/noise に分類して job summary を生成する。

usage: vulnxscan_summary.py <csv_path> <target> [closure_file]

closure_file (任意): `nix path-info -r <target>` の出力 (store path basename 一覧)。
あれば pin 検出を有効化する: 同一 package が複数版で closure に在る場合、古い版の CVE は
auto-update では直らない (意図的 pin) ため NOTIFY 扱いにする。

分類方針 (auto-update-flake.lock 前提, dotfiles-private#276):
  - NOTIFY : latest nixpkgs でも残る = 要対処/要 mitigation
            fix_not_available + pin された fix_update_to_version_nixpkgs
  - INFO   : auto-update が解決見込み (今は残るが nixpkgs 追従/次回更新で消える)
            fix_update_to_version_upstream + unpinned fix_update_to_version_nixpkgs
  - DROP   : ノイズ (repology 上 非該当 / 判定不能)
            err_not_vulnerable_based_on_repology / err_missing_repology_version / err_invalid_version
  - whitelist=True は確定FP/リスク受容として抑制済 (件数のみ表示)
"""
import csv
import re
import sys
from collections import Counter, defaultdict

csv_path = sys.argv[1] if len(sys.argv) > 1 else "vulns.triage.csv"
target = sys.argv[2] if len(sys.argv) > 2 else "(unknown)"
closure_path = sys.argv[3] if len(sys.argv) > 3 else None

NOISE_CLASSIFY = {
    "err_not_vulnerable_based_on_repology",
    "err_missing_repology_version",
    "err_invalid_version",
}


def sevf(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


# --- closure から package -> {versions} を構築 (pin 検出用) ---
closure_versions = defaultdict(set)
if closure_path:
    try:
        with open(closure_path) as f:
            for line in f:
                name = line.strip()
                if not name:
                    continue
                m = re.match(r"^(.+?)-(\d[\w.+]*)", name)
                if m:
                    closure_versions[m.group(1)].add(m.group(2))
    except FileNotFoundError:
        closure_path = None
    # path-info 失敗等で空 closure.txt の場合は pin 検出 OFF として扱う (無言で無効化しない)
    if closure_path and not closure_versions:
        closure_path = None


def is_pinned(pkg, _ver):
    """package が closure に複数版で存在 = 意図的 pin (古い版の CVE は auto-update で直らない)。

    版文字列の rev サフィックス (例 glibc 2.42-61) を厳密照合すると取りこぼすため、
    「複数版が closure に在るか」だけで判定する (NOTIFY 寄り = signal を隠さない安全側)。
    """
    return len(closure_versions.get(pkg, set())) >= 2


try:
    with open(csv_path) as f:
        rows = list(csv.DictReader(f))
except FileNotFoundError:
    print("## 🔎 vulnxscan\n")
    print("⚠️ 出力 CSV が見つかりません（スキャン失敗の可能性）。ジョブログを確認してください。")
    sys.exit(0)

total = len(rows)
pkgs = len({r.get("package", "") for r in rows})

notify, info, drop, whitelisted = [], [], [], []
for r in rows:
    if str(r.get("whitelist", "")).strip().lower() == "true":
        whitelisted.append(r)
        continue
    cl = r.get("classify", "")
    if cl in NOISE_CLASSIFY:
        drop.append(r)
    elif cl == "fix_update_to_version_nixpkgs":
        if closure_path and is_pinned(r.get("package", ""), r.get("version_local", "")):
            notify.append(r)  # pin: auto-update では直らない
        else:
            info.append(r)  # auto-update が次回解決
    else:
        # fix_not_available / fix_update_to_version_upstream / classify 無し
        if cl == "fix_not_available":
            notify.append(r)
        else:
            info.append(r)

# 集約 (Issue 自動起票) 用に NOTIFY を JSON 出力 (argv[4] が与えられた場合)
notify_json_path = sys.argv[4] if len(sys.argv) > 4 else None
if notify_json_path:
    import json

    keys = ["vuln_id", "severity", "package", "classify", "version_local", "version_nixpkgs"]
    payload = {"target": target, "findings": [{k: r.get(k, "") for k in keys} for r in notify]}
    with open(notify_json_path, "w") as jf:
        json.dump(payload, jf, ensure_ascii=False)

print("## 🔎 vulnxscan 結果\n")
print(f"- **target**: `{target}`")
print(f"- **検出**: {total} CVE / {pkgs} packages")
print(
    f"- **NOTIFY**: {len(notify)} ・ INFO: {len(info)} ・ DROP(noise): {len(drop)} "
    f"・ whitelisted: {len(whitelisted)}"
    + ("" if closure_path else "  _(closure 未指定: pin 検出 OFF)_")
)
print()

if not rows:
    print("✅ 脆弱性は検出されませんでした。")
    sys.exit(0)


def table(items, title, note=""):
    if not items:
        return
    items = sorted(items, key=lambda r: -sevf(r.get("severity")))
    print(f"### {title} ({len(items)}件){note}\n")
    print("| CVE | sev | pkg | classify | local→nixpkgs |")
    print("|---|---|---|---|---|")
    for r in items[:30]:
        print(
            f"| {r.get('vuln_id','')} | {r.get('severity','')} "
            f"| {r.get('package','')} | {r.get('classify','')} "
            f"| {r.get('version_local','')}→{r.get('version_nixpkgs','')} |"
        )
    if len(items) > 30:
        print(f"\n_… 他 {len(items) - 30} 件 (CSV 参照)_")
    print()


# NOTIFY = 最優先 (latest でも残る)。sum>=2 / 高 sev を上位表示。
table(notify, "🚨 NOTIFY — latest nixpkgs でも残る (要対処/mitigation)")

# INFO は件数 + classify 内訳のみ (auto-update 解決見込み)
if info:
    ic = Counter(r.get("classify", "") for r in info)
    print("### ℹ️ INFO — auto-update 解決見込み\n")
    for k, v in ic.most_common():
        print(f"- {k}: {v}")
    print()

print("### 内訳 (classify 分布)\n")
print("| classify | 件数 |")
print("|---|---|")
for k, v in Counter(r.get("classify", "") for r in rows).most_common():
    print(f"| {k} | {v} |")

print(
    "\n> NOTIFY は実 closure バージョンや Nixpkgs Security Tracker で要 adjudication。"
    " 確定FP/リスク受容は whitelist.csv に追記すると以降抑制される。"
)
