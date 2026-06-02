#!/usr/bin/env python3
"""vulnxscan の (triage) CSV を分類して job summary を生成する。

usage: vulnxscan_summary.py <csv_path> <target> [closure_file] [notify_json_out]

分類 (auto-update-flake.lock 前提, dotfiles-private#276):
  NOTIFY = latest nixpkgs でも残る = 要対処
    🔧 fixable : fix_update_to_version_nixpkgs かつ pin されている
                 (nixpkgs に修正版あり / auto-update で動かない) → パッチ版を明記
    🛑 no-fix  : fix_not_available (修正がどこにも無い → mitigation/受容/待ち)
  INFO  = auto-update 解決見込み
          fix_update_to_version_upstream + unpinned fix_update_to_version_nixpkgs
  DROP  = noise (err_not_vulnerable_based_on_repology 等)
  whitelist=True は確定FP/リスク受容として抑制 (件数のみ)

closure_file (任意): `nix path-info -r <target>` の出力。pin 検出に使う。
notify_json_out (任意): NOTIFY を JSON 出力 (集約/Issue 起票用)。
"""
import csv
import re
import sys
from collections import Counter, defaultdict

csv_path = sys.argv[1] if len(sys.argv) > 1 else "vulns.triage.csv"
target = sys.argv[2] if len(sys.argv) > 2 else "(unknown)"
closure_path = sys.argv[3] if len(sys.argv) > 3 else None
notify_json_path = sys.argv[4] if len(sys.argv) > 4 else None

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


# closure -> package -> {versions} (pin 検出用)
closure_versions = defaultdict(set)
if closure_path:
    try:
        with open(closure_path) as f:
            for line in f:
                name = line.strip()
                if not name:
                    continue
                # raw な `nix path-info -r` 出力 (/nix/store/<hash>-name-ver) なら
                # store path prefix を除去。strip 済み basename はそのまま。
                if name.startswith("/"):
                    name = re.sub(r"^[a-z0-9]{32}-", "", name.rsplit("/", 1)[-1])
                m = re.match(r"^(.+?)-(\d[\w.+]*)", name)
                if m:
                    closure_versions[m.group(1)].add(m.group(2))
    except FileNotFoundError:
        closure_path = None
    if closure_path and not closure_versions:
        closure_path = None


def is_pinned(pkg):
    """package が closure に複数版で存在 = 意図的 pin (古い版の CVE は auto-update で直らない)。"""
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

fixable, nofix, info, drop, whitelisted = [], [], [], [], []
for r in rows:
    if str(r.get("whitelist", "")).strip().lower() == "true":
        whitelisted.append(r)
        continue
    cl = r.get("classify", "")
    if cl in NOISE_CLASSIFY:
        drop.append(r)
    elif cl == "fix_update_to_version_nixpkgs":
        # nixpkgs に修正版あり。pin されている = auto-update で直らない → fixable。
        # pin されていない = 次の auto-update で直る → info。
        if closure_path and is_pinned(r.get("package", "")):
            fixable.append(r)
        else:
            info.append(r)
    elif cl == "fix_not_available":
        nofix.append(r)
    else:
        info.append(r)

notify = fixable + nofix

# 集約 (Issue 起票) 用に NOTIFY を JSON 出力
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
    f"- **NOTIFY {len(notify)}** (🔧 fixable {len(fixable)} / 🛑 no-fix {len(nofix)}) "
    f"・ INFO {len(info)} ・ DROP {len(drop)} ・ whitelisted {len(whitelisted)}"
    + ("" if closure_path else "  _(closure 未指定: pin 検出 OFF)_")
)
print()
print(
    "> **凡例** — NOTIFY = latest nixpkgs でも残る要対処 CVE。"
    "🔧 **fixable**: nixpkgs に修正版あり、pin 解消/更新で直る（パッチ版を明記）。"
    "🛑 **no-fix**: 修正版が存在しない → Remove/Replace/Mitigate/受容(whitelist)/待ち。"
    " INFO=auto-update で自動解決見込み・DROP=誤検知。\n"
)

if not rows:
    print("✅ 脆弱性は検出されませんでした。")
    sys.exit(0)


def table(items, headers, row_fn, title):
    if not items:
        return
    items = sorted(items, key=lambda r: -sevf(r.get("severity")))
    print(f"### {title} ({len(items)}件)\n")
    print("| " + " | ".join(headers) + " |")
    print("|" + "|".join(["---"] * len(headers)) + "|")
    for r in items[:30]:
        print("| " + " | ".join(row_fn(r)) + " |")
    if len(items) > 30:
        print(f"\n_… 他 {len(items) - 30} 件 (CSV 参照)_")
    print()


# 🔧 fixable: パッチ版 (version_nixpkgs) を明記
table(
    fixable,
    ["CVE", "sev", "pkg", "現在版", "→ パッチ版 (nixpkgs)"],
    lambda r: [
        r.get("vuln_id", ""),
        r.get("severity", ""),
        r.get("package", ""),
        r.get("version_local", ""),
        r.get("version_nixpkgs", ""),
    ],
    "🔧 NOTIFY / fixable — pin 解消・更新で直る",
)
# 🛑 no-fix
table(
    nofix,
    ["CVE", "sev", "pkg", "現在版"],
    lambda r: [r.get("vuln_id", ""), r.get("severity", ""), r.get("package", ""), r.get("version_local", "")],
    "🛑 NOTIFY / no-fix — 修正版なし (mitigation/受容/待ち)",
)

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

print("\n> 確定FP/リスク受容は whitelist.csv に追記すると以降抑制されます。")
