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

closure_file (任意): `nix path-info -r [--json] <target>` の出力。
  - `--json` (参照グラフ) なら pin 検出 + 由来 (bundled by / 依存元の親) を算出。
  - plain text なら pin 検出のみ (由来は "—" 不可)。
notify_json_out (任意): NOTIFY を JSON 出力 (集約/Issue 起票用)。
"""
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from functools import lru_cache

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


# closure 解析: package -> {versions} (pin 検出) と reverse-ref graph (由来 / bundled by)
closure_versions = defaultdict(set)
ref_parents = {}  # store path -> {それを参照する store path}
store_paths = []  # closure 内の全 store path (--json 時のみ)

# 由来抽出で「意味ある親」とみなさない汎用コンテナ (これ自体は何かを bundle していない)
GENERIC_NODES = {
    "system-path", "user-environment", "home-manager-path",
    "home-manager-files", "etc", "set-environment", "profile", "sw",
}


def _base(store_path):
    """store path -> hash prefix を除いた basename (<name>-<ver>[-<output>])。"""
    return re.sub(r"^[a-z0-9]{32}-", "", store_path.rsplit("/", 1)[-1])


def _node_name(store_path):
    """/nix/store/<hash>-<name>-<ver>[-<output>] -> (name, version)。
    version の正規表現は `-` で止まる (出力サフィックス -lib 等と区別するため) ので、
    `2.42-61` のような nixpkgs patch-set suffix 付き版は `2.42` に切り詰められる点に注意。
    脆弱版との照合には _base() の prefix 一致を使う (bundled_by 参照)。"""
    b = _base(store_path)
    m = re.match(r"^(.+?)-(\d[\w.+]*)", b)
    return (m.group(1), m.group(2)) if m else (b, "")


def _is_generic(name):
    if name in GENERIC_NODES:
        return True
    if name.startswith(("nixos-system", "darwin-system", "unit-", "etc-")):
        return True
    return "home-manager" in name or name.endswith("-env")


def _meaningful_parent(parent_path, pkg):
    """parent_path が pkg の『由来』として意味ある親なら name、そうでなければ None。
    glue/config/trigger ノード (X-Restart-Triggers-*, *.conf, 50-*.conf 等) は version を
    持たないという構造的特徴で弾く (純粋な name denylist より漏れが桁違いに少ない)。"""
    n, v = _node_name(parent_path)
    if n == pkg:  # 自身の別 output (ffmpeg-bin が ffmpeg-lib を参照する等)
        return None
    if not v:  # 版なし = 実パッケージでない (glue/config/trigger)
        return None
    if n.endswith(("-wrapped", "-wrapper")):  # ラッパー derivation
        return None
    if _is_generic(n):  # 版は持つが汎用コンテナ (nixos-system-* 等)
        return None
    return n


def _load_closure(path):
    """closure ファイルを読み込む。先頭が [ / { なら `--json` (参照グラフ) として
    パースし逆参照を構築、それ以外は plain text として版のみ抽出する。"""
    try:
        with open(path) as f:
            text = f.read()
    except FileNotFoundError:
        return False
    if text.lstrip()[:1] in "[{":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return False
        # nix のバージョンで dict ({path: {...}}) か list ([{path, ...}]) が変わる
        graph = (
            [(p, (v or {}).get("references", [])) for p, v in data.items()]
            if isinstance(data, dict)
            else [(e.get("path", ""), e.get("references", [])) for e in data]
        )
        for p, refs in graph:
            if not p:
                continue
            store_paths.append(p)
            n, ver = _node_name(p)
            if ver:
                closure_versions[n].add(ver)
            for r in refs:
                ref_parents.setdefault(r, set()).add(p)
        return bool(store_paths)
    # plain text (`nix path-info -r`): 版のみ (由来は算出不可)
    for line in text.splitlines():
        name = line.strip()
        if not name:
            continue
        if name.startswith("/"):
            name = re.sub(r"^[a-z0-9]{32}-", "", name.rsplit("/", 1)[-1])
        m = re.match(r"^(.+?)-(\d[\w.+]*)", name)
        if m:
            closure_versions[m.group(1)].add(m.group(2))
    return bool(closure_versions)


if closure_path and not _load_closure(closure_path):
    closure_path = None


def is_pinned(pkg):
    """package が closure に複数版で存在 = 意図的 pin (古い版の CVE は auto-update で直らない)。"""
    return len(closure_versions.get(pkg, set())) >= 2


@lru_cache(maxsize=None)
def bundled_by(pkg, ver, cap=3):
    """pkg@ver を closure に入れた『意味ある親』(由来)。generic ノードと自身の
    output (同名) を除外し、上位 cap 件 + 残数を返す。参照グラフが無ければ ""。
    直接導入 (generic な親しか居ない) は "—"。"""
    if not ref_parents:
        return ""
    # 脆弱版の store path 特定。version は _node_name だと `2.42-61` 等が `2.42` に
    # 切り詰められ完全一致に失敗するため、basename の prefix (<pkg>-<ver> 直後が
    # `-`<output> か終端) で照合する。ver 未指定なら name 一致のみ。
    prefix = f"{pkg}-{ver}" if ver else ""
    out = set()
    for p in store_paths:
        if ver:
            b = _base(p)
            if b != prefix and not b.startswith(prefix + "-"):
                continue
        elif _node_name(p)[0] != pkg:
            continue
        for parent in ref_parents.get(p, ()):
            pn = _meaningful_parent(parent, pkg)
            if pn:
                out.add(pn)
    if not out:
        return "—"
    s = sorted(out)
    return ",".join(s[:cap]) + (f" +{len(s) - cap}" if len(s) > cap else "")


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

# 集約 (Issue 起票) 用に NOTIFY を JSON 出力 (由来 bundled_by も含める)
if notify_json_path:
    keys = ["vuln_id", "severity", "package", "classify", "version_local", "version_nixpkgs"]
    findings = []
    for r in notify:
        d = {k: r.get(k, "") for k in keys}
        d["bundled_by"] = bundled_by(r.get("package", ""), r.get("version_local", ""))
        findings.append(d)
    payload = {"target": target, "findings": findings}
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
    " INFO=auto-update で自動解決見込み・DROP=誤検知。"
    " 由来=その版を closure に入れた親 (— は直接導入、`+N` は他にも N 件)。\n"
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


# 🔧 fixable: パッチ版 (version_nixpkgs) を明記。由来 = 何にバンドルされたか。
table(
    fixable,
    ["CVE", "sev", "pkg", "現在版", "→ パッチ版 (nixpkgs)", "由来"],
    lambda r: [
        r.get("vuln_id", ""),
        r.get("severity", ""),
        r.get("package", ""),
        r.get("version_local", ""),
        r.get("version_nixpkgs", ""),
        bundled_by(r.get("package", ""), r.get("version_local", "")),
    ],
    "🔧 NOTIFY / fixable — pin 解消・更新で直る",
)
# 🛑 no-fix
table(
    nofix,
    ["CVE", "sev", "pkg", "現在版", "由来"],
    lambda r: [
        r.get("vuln_id", ""),
        r.get("severity", ""),
        r.get("package", ""),
        r.get("version_local", ""),
        bundled_by(r.get("package", ""), r.get("version_local", "")),
    ],
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
