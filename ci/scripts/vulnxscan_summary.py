#!/usr/bin/env python3
"""vulnxscan の (triage) CSV を分類して job summary を生成する。

usage: vulnxscan_summary.py <csv_path> <target> [closure_file] [notify_json_out] [roots_file] [tracker_file] [identity_file]

分類 (auto-update-flake.lock 前提, dotfiles-private#276):
  NOTIFY = latest nixpkgs でも残る = 要対処
    🔧 fixable : fix_update_to_version_nixpkgs かつ pin されている
                 (nixpkgs に修正版あり / auto-update で動かない) → パッチ版を明記
    🛑 no-fix  : fix_not_available (修正がどこにも無い → mitigation/受容/待ち)
  ❓ UNKNOWN = err_missing_repology_version / err_invalid_version (判定不能)。
              repology にデータ無し / 版解析失敗。safe ではないので surface する (#285a)。
  INFO  = auto-update 解決見込み
          fix_update_to_version_upstream + unpinned fix_update_to_version_nixpkgs
  DROP  = noise (err_not_vulnerable_based_on_repology = repology が非該当判定)。
          ただし high-sev (>= HIGH_SEV_SPOTCHECK) は repology 誤判定保険として
          🔍 spot-check に併載する (DROP は維持, #285b)。
  🔁 reclassified = tracker_file ありの時、no-fix/UNKNOWN のうち Nixpkgs Security
          Tracker が notaffected/notforus と判断したもの (backport patch / 対象外)。
          silent DROP せず「要確認・whitelist 候補」として可視化する (#285c/#289)。
  🚫 identity-mismatch = identity_file ありの時、UNKNOWN / spot-check のうち
          名前衝突 (CVE が同名の別ソフトに当たった FP) と確定したもの。durable surface
          から除外し job summary に監査ログとして残す (#285、vulnxscan_identity.py)。
  whitelist=True は確定FP/リスク受容として抑制 (件数のみ)

closure_file (任意): `nix path-info -r [--json] <target>` の出力。
  - `--json` (参照グラフ) なら pin 検出 + 入口/由来の逆引きを算出。
  - plain text なら pin 検出のみ。
notify_json_out (任意): NOTIFY を JSON 出力 (集約/Issue 起票用)。
roots_file (任意): vulnxscan_provenance.nix の出力 (宣言ルート [{o,n,f,src}])。
  これがあると「入口 (設定)」= 脆弱版を closure に入れた宣言 (systemPackages /
  home.packages) とそのソースファイルを逆引きする。無い場合は closure の
  immediate referrer (由来 / bundled by) にフォールバックする。
tracker_file (任意): vulnxscan_tracker.py の出力 ({cve: status})。Nixpkgs Security
  Tracker の権威ステータスで repology 単独分類を再検証する (#285c/#289)。
  notaffected/notforus の no-fix/UNKNOWN を 🔁 reclassified に降格 (silent DROP せず
  可視化)、他は据え置き + nixpkgs 列に status 注記。無い/空なら override 無しで現状維持。
identity_file (任意): vulnxscan_identity.py の出力 ({vuln_id: {verdict, package, ...}})。
  verdict=collision (名前衝突 FP) は 🚫 identity-mismatch に隔離し durable surface から除外、
  verdict=affected (NVD 版範囲で該当確定) は ✅ judged-affected として UNKNOWN/spot-check から
  NOTIFY へ昇格する (#285)。昇格のみで降格はせず、衝突は積極証拠がある時のみ確定するため FN を
  増やさない (vulnxscan_identity.py 参照)。無い/空なら override 無しで現状維持。
"""
import csv
import json
import re
import sys
from collections import Counter, defaultdict, deque
from functools import lru_cache

from vulnxscan_common import UNKNOWN_CLASSIFY, sevf

csv_path = sys.argv[1] if len(sys.argv) > 1 else "vulns.triage.csv"
target = sys.argv[2] if len(sys.argv) > 2 else "(unknown)"
closure_path = sys.argv[3] if len(sys.argv) > 3 else None
notify_json_path = sys.argv[4] if len(sys.argv) > 4 else None
roots_path = sys.argv[5] if len(sys.argv) > 5 else None
tracker_path = sys.argv[6] if len(sys.argv) > 6 else None
identity_path = sys.argv[7] if len(sys.argv) > 7 else None

# 入口 (設定) 表示の調整: 入口が多い基盤ライブラリは個別列挙せず縮退する
ENTRY_FANOUT_LIMIT = 6  # これを超える入口数 = 基盤依存 (config では直せない)
ENTRY_SHOW = 3  # 列挙する入口の最大数 (残りは先頭の入口数 "N 入口" で示す)

# UNKNOWN_CLASSIFY (判定不能 = ❓UNKNOWN として surface) は vulnxscan_common から import (#285a)。
# err_not_vulnerable_based_on_repology は repology が明示的に「非該当」と返したものなので DROP の
# ままだが、high-sev は spot-check で可視化 (#285b)。
HIGH_SEV_SPOTCHECK = 9.0  # repology 非該当でもこの severity 以上は念のため確認リストへ


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


# --- 入口 (設定) 逆引き: 宣言ルート (provenance) を closure グラフで逆到達する ---
# declared_roots: outPath -> (name, file, src)  (vulnxscan_provenance.nix の出力)
declared_roots = {}


def _load_roots(path):
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(data, list):
        return False
    for e in data:
        o = e.get("o")
        if o:
            declared_roots.setdefault(o, (e.get("n", "?"), e.get("f", ""), e.get("src", "")))
    return bool(declared_roots)


if roots_path and not _load_roots(roots_path):
    roots_path = None


def _relfile(f):
    """flake source の store path prefix (/nix/store/<hash>-<name>/) を除去して
    repo 相対パスに縮約する (例 .../<hash>-source/home/x.nix -> home/x.nix)。
    位置不明 (module system が _file を保持しない宣言) は "" に正規化する。"""
    if not f or f == "<unknown-file>":
        return ""
    return re.sub(r"^/nix/store/[a-z0-9]{32}-[^/]*/", "", f)


def _pkgname(n):
    """derivation name から版以降を落として表示名にする (vlc-3.0.23-2 -> vlc)。"""
    return re.sub(r"-\d[\w.+]*.*$", "", n) or n


def _vuln_paths(pkg, ver):
    """脆弱版の store path 群 (basename prefix 一致)。"""
    prefix = f"{pkg}-{ver}" if ver else ""
    res = []
    for p in store_paths:
        if ver:
            b = _base(p)
            if b == prefix or b.startswith(prefix + "-"):
                res.append(p)
        elif _node_name(p)[0] == pkg:
            res.append(p)
    return res


@lru_cache(maxsize=None)
def entry_points(pkg, ver):
    """pkg@ver を closure に入れた『宣言された入口』を逆到達で求める。
    返り値: (name, relfile, src) のタプルのソート済み list。
    provenance / closure が無ければ None (呼び出し側で由来にフォールバック)。"""
    if not declared_roots or not ref_parents:
        return None
    targets = _vuln_paths(pkg, ver)
    seen = set(targets)
    q = deque(targets)
    found = {}
    while q:
        cur = q.popleft()
        if cur in declared_roots:
            n, f, s = declared_roots[cur]
            found[(_pkgname(n), _relfile(f), s)] = 1
        for parent in ref_parents.get(cur, ()):
            if parent not in seen:
                seen.add(parent)
                q.append(parent)
    return sorted(found.keys())


def origin(pkg, ver):
    """表示用の『入口 (設定)』文字列。provenance があれば入口+ファイル、
    多すぎる (基盤依存) なら縮退、無ければ由来 (bundled by) にフォールバック。"""
    eps = entry_points(pkg, ver)
    if eps is None:
        return bundled_by(pkg, ver)  # フォールバック (closure immediate referrer)
    if not eps:
        return "—"
    # 入口数を常に明示する (1 = そこを直せば確実に消える / 多数 = 基盤依存で config 不可)。
    n_ep = len(eps)
    if n_ep > ENTRY_FANOUT_LIMIT:
        return f"基盤依存 ({n_ep} 入口)"

    def render(n, f, s):
        # file があれば file、無ければ src ラベル (home:<user> 等) で補う
        loc = f or (s if s and s != "system" else "")
        return f"{n} ({loc})" if loc else n

    shown = [render(*ep) for ep in eps[:ENTRY_SHOW]]
    # ENTRY_SHOW 件までを列挙。残りは入口数 (N 入口) で示すので "他N" は省く。
    return f"{n_ep} 入口: " + "; ".join(shown)


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
unknown, spotcheck = [], []  # #285: 判定不能 / high-sev の repology 非該当
for r in rows:
    if str(r.get("whitelist", "")).strip().lower() == "true":
        whitelisted.append(r)
        continue
    cl = r.get("classify", "")
    if cl in UNKNOWN_CLASSIFY:
        # repology が判定できなかった = unknown。safe と同一視せず surface する。
        unknown.append(r)
    elif cl == "err_not_vulnerable_based_on_repology":
        # repology が「非該当」と判定 → DROP。ただし repology は非権威なので
        # high-sev は spot-check に併載する (DROP は維持しつつ「念のため確認」)。
        drop.append(r)
        if sevf(r.get("severity")) >= HIGH_SEV_SPOTCHECK:
            spotcheck.append(r)
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

# --- Nixpkgs Security Tracker による権威再検証 (#285c/#289) ---
# tracker.json: {cve: status}。repology 単独で出した no-fix / UNKNOWN を nixpkgs の
# 権威ステータスで見直す。notaffected/notforus (backport patch / 対象外) は silent DROP
# せず 🔁 reclassified に降格して「要確認・whitelist 候補」として可視化 (保守的)。
# affected/wontfix/unknown は据え置き、各 finding に _tracker を付けて nixpkgs 列に注記。
tracker_status = {}
if tracker_path:
    try:
        with open(tracker_path) as tf:
            tracker_status = json.load(tf) or {}
    except (OSError, json.JSONDecodeError):
        tracker_status = {}
tracker_loaded = bool(tracker_status)
RECLASS_STATUS = {"notaffected", "notforus"}
reclassified = []


def _tracker_reverify(bucket):
    """bucket を tracker で再検証。notaffected/notforus は reclassified へ移し、
    残りは _tracker 注記を付けて keep。tracker データが無ければ素通し。"""
    keep = []
    for r in bucket:
        st = tracker_status.get(r.get("vuln_id", ""), "")
        r["_tracker"] = st
        if st in RECLASS_STATUS:
            reclassified.append(r)
        else:
            keep.append(r)
    return keep


if tracker_loaded:
    nofix = _tracker_reverify(nofix)
    unknown = _tracker_reverify(unknown)

# --- identity ガード: 名前衝突 FP を隔離 (#285、vulnxscan_identity.py) ---
# identity.json: {vuln_id: {package, nix_repo, cve_repo}}。UNKNOWN / spot-check のうち
# CVE が同名の別ソフトに当たった衝突 FP を 🚫 collision に移し durable surface から除外する。
# 衝突は積極証拠 (src.url repo ≠ CVE repo, canonical 化後も不一致) がある時のみ確定済なので
# FN を増やさない。データが無ければ素通し (現状維持)。
identity_map = {}
if identity_path:
    try:
        with open(identity_path) as idf:
            identity_map = json.load(idf) or {}
    except (OSError, json.JSONDecodeError):
        identity_map = {}
identity_loaded = bool(identity_map)
collision = []  # verdict=collision: 名前衝突 FP (除外)
judged = []     # verdict=affected: NVD 版範囲で該当確定 (UNKNOWN/spot-check/DROP → NOTIFY 昇格)
likely_fp = []  # verdict=disputed / not_in_range: no-fix 偽陽性疑い (#289、no-fix → 降格)
_seen_verdict = set()  # spotcheck⊂drop で同一 row が二重昇格しないよう vuln_id で抑止


def _identity_filter(bucket):
    """bucket から verdict 付き row を抜き出す。collision は除外、affected は昇格 (judged)、
    disputed / not_in_range は no-fix の偽陽性降格 (likely_fp、#289)。verdict=nofix_cpe は
    分類を動かさず _identity を注記するだけ (no-fix 表の NVD CPE 判定列、#289 表示拡張)。
    同一 vuln_id は 1 度だけ処理し、残り (判定なし/注記のみ) はそのまま返す。"""
    dest_of = {"collision": collision, "affected": judged,
               "disputed": likely_fp, "not_in_range": likely_fp}
    keep = []
    for r in bucket:
        vid = r.get("vuln_id", "")
        info = identity_map.get(vid)
        if info:
            r["_identity"] = info  # 移動有無に関わらず注記 (nofix_cpe は keep 側で表示に使う)
        dest = dest_of.get((info or {}).get("verdict"))
        if dest is not None:
            if vid not in _seen_verdict:
                _seen_verdict.add(vid)
                dest.append(r)
            # 既処理 (別 bucket で昇格/降格/除外済) の重複はこの bucket から取り除くだけ
        else:
            keep.append(r)
    return keep


if identity_loaded:
    # no-fix は #289 の降格 (disputed/not_in_range) と名前衝突を抜く。tracker 降格 (reclassified)
    # の後に通すので、両方該当する CVE は reclassified が優先される (Nixpkgs 権威を上位扱い)。
    nofix = _identity_filter(nofix)
    unknown = _identity_filter(unknown)
    spotcheck = _identity_filter(spotcheck)
    # #1: repology が非該当として DROP した分 (spot-check 未満の sev 含む) も該当判定で救済。
    # spotcheck は drop の部分集合なので _seen_verdict で二重昇格を防ぐ。
    drop = _identity_filter(drop)

notify = fixable + nofix

# 集約 (Issue 起票) 用に NOTIFY / UNKNOWN / spot-check / reclassified を JSON 出力。
# 後方互換: 既存の "findings" (NOTIFY) キーは不変。unknown/spotcheck を追加キーとして
# 並べる (古い aggregate は未知キーを無視するだけ) → 集約 Issue でも surface (#285a/b)。
if notify_json_path:
    keys = ["vuln_id", "severity", "package", "classify", "version_local", "version_nixpkgs"]

    def _to_findings(items):
        out = []
        for r in items:
            d = {k: r.get(k, "") for k in keys}
            d["entry"] = origin(r.get("package", ""), r.get("version_local", ""))
            d["tracker"] = r.get("_tracker", "")  # nixpkgs 権威ステータス注記
            d["identity"] = r.get("_identity", "")  # collision の repo 対 / judged の cpe・range
            out.append(d)
        return out

    payload = {
        "target": target,
        "findings": _to_findings(notify),
        "unknown": _to_findings(unknown),
        "spotcheck": _to_findings(spotcheck),
        "reclassified": _to_findings(reclassified),
        # judged = NVD 版範囲で該当確定し UNKNOWN/spot-check から昇格 (#285)。NOTIFY 級として
        # 集約 Issue に surface する (aggregate が judged キーを描画)。
        "judged": _to_findings(judged),
        # likely_fp = no-fix のうち NVD タグ (disputed 等) / 版範囲外で偽陽性疑いと判定し降格 (#289)。
        # silent DROP せず「要確認・whitelist 候補」として集約 Issue にも surface する。
        "likely_fp": _to_findings(likely_fp),
        # collision は監査用。集約 (aggregate) は未知キーを無視するので Issue には出ない
        # = durable surface から除外される (= FP 除去の目的)。
        "collision": _to_findings(collision),
    }
    with open(notify_json_path, "w") as jf:
        json.dump(payload, jf, ensure_ascii=False)

print("## 🔎 vulnxscan 結果\n")
print(f"- **target**: `{target}`")
print(f"- **検出**: {total} CVE / {pkgs} packages")
print(
    f"- **NOTIFY {len(notify)}** (🔧 fixable {len(fixable)} / 🛑 no-fix {len(nofix)}) "
    + (f"・ ✅ judged-affected {len(judged)} " if judged else "")
    + f"・ ❓ UNKNOWN {len(unknown)}"
    + (f" ・ 🔁 reclassified {len(reclassified)}" if reclassified else "")
    + (f" ・ 🟢 likely-FP {len(likely_fp)}" if likely_fp else "")
    + f" ・ INFO {len(info)} ・ DROP {len(drop)}"
    + (f" (🔍 spot-check {len(spotcheck)})" if spotcheck else "")
    + (f" ・ 🚫 identity-mismatch {len(collision)}" if collision else "")
    + f" ・ whitelisted {len(whitelisted)}"
    + ("" if closure_path else "  _(closure 未指定: pin 検出 OFF)_")
    + ("" if tracker_loaded else "  _(tracker 未指定: 権威再検証 OFF)_")
    + ("" if identity_loaded else "  _(identity 未指定: 名前衝突検出 OFF)_")
)
print()
print(
    "> **凡例**\n>\n"
    "> - **NOTIFY** = latest nixpkgs でも残る要対処 CVE\n"
    "> - 🔧 **fixable**: nixpkgs に修正版あり、pin 解消/更新で直る（パッチ版を明記）\n"
    "> - 🛑 **no-fix**: 修正版が存在しない → Remove/Replace/Mitigate/受容(whitelist)/待ち。"
    "**判定 (NVD CPE)** 列=該当確定 (NVD 版範囲内=本物 TP) / 上限なし (NVD に修正版データ無し) / "
    "日付上限 (修正が git-master commit で release 未反映=要 backport 確認・FP 候補) / —(NVD 未照会・vendor 不一致)\n"
    "> - ✅ **judged-affected** = repology が判定不能/非該当としたが NVD CPE の版範囲で該当確定 "
    "(UNKNOWN/spot-check/repology 非該当 DROP から NOTIFY へ昇格、vendor 一致 + clean 版のみの保守判定)\n"
    "> - ❓ **UNKNOWN** = repology にデータ無し/版解析失敗で判定不能 (safe ではない、要確認)\n"
    "> - 🔁 **reclassified** = Nixpkgs Security Tracker が notaffected/notforus と判断 "
    "(backport patch/対象外)。no-fix/UNKNOWN から降格した要確認・whitelist 候補\n"
    "> - 🟢 **likely-FP** = no-fix のうち NVD の権威データで偽陽性疑いと判定し降格 (#289)。"
    "cveTags が disputed/unsupported-when-assigned/exclusively-hosted-service (or vulnStatus=Rejected)、"
    "または CPE 版範囲が全て範囲外。silent DROP せず要確認・whitelist 候補として残す\n"
    "> - **nixpkgs** 列 = Tracker の権威ステータス (affected/wontfix/notaffected/notforus、— は未登録)\n"
    "> - INFO = auto-update で自動解決見込み・DROP = 誤検知 "
    "(repology 非該当のうち high-sev は 🔍 **spot-check** に併載=誤判定保険、DROP は維持)\n"
    "> - 🚫 **identity-mismatch** = CVE が同名の別ソフトに当たった名前衝突 FP "
    "(nixpkgs の src.url repo ≠ CVE の repo)。UNKNOWN/spot-check から除外し監査用に併記\n"
    "> - 入口(設定) = その版を closure に入れた宣言 (systemPackages/home.packages) とソースファイル。"
    "そこを更新/削除/service 無効化で解消できる。"
    "『基盤依存 (N 入口)』= 多数から参照される基盤ライブラリで config 単独では直せない → nixpkgs 更新待ち\n"
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


# 🔧 fixable: パッチ版 (version_nixpkgs) を明記。入口 = どの設定が原因か。
table(
    fixable,
    ["CVE", "sev", "pkg", "現在版", "→ パッチ版 (nixpkgs)", "入口 (設定)"],
    lambda r: [
        r.get("vuln_id", ""),
        r.get("severity", ""),
        r.get("package", ""),
        r.get("version_local", ""),
        r.get("version_nixpkgs", ""),
        origin(r.get("package", ""), r.get("version_local", "")),
    ],
    "🔧 NOTIFY / fixable — pin 解消・更新で直る",
)
# ✅ judged-affected: NVD 版範囲で該当確定し UNKNOWN/spot-check から昇格 (#285)。
table(
    judged,
    ["CVE", "sev", "pkg", "現在版", "判定 (NVD CPE)", "入口 (設定)"],
    lambda r: [
        r.get("vuln_id", ""),
        r.get("severity", ""),
        r.get("package", ""),
        r.get("version_local", ""),
        f"{(r.get('_identity') or {}).get('cpe', '')} {(r.get('_identity') or {}).get('range', '')}".strip(),
        origin(r.get("package", ""), r.get("version_local", "")),
    ],
    "✅ NOTIFY / judged-affected — NVD 版範囲で該当確定 (repology の判定不能/非該当から昇格)",
)


def _trk(r):
    """nixpkgs (Tracker) 権威ステータス列。未登録は — 。"""
    return r.get("_tracker", "") or "—"


def _nofix_cpe(r):
    """no-fix の NVD CPE 判定列 (#289 表示拡張)。identity の nofix_cpe 注記から、
    NVD で該当確定 (本物 TP) / 上限なし・日付上限 (修正版が semver で無い=要確認・FP 候補) を区別。
    identity 未指定/未照会/vendor 不一致は — 。"""
    info = r.get("_identity") or {}
    if info.get("verdict") != "nofix_cpe":
        return "—"
    kind, detail = info.get("kind"), info.get("detail", "")
    if kind == "confirmed":
        return f"該当確定 {detail}".strip()
    if kind == "date":
        return f"日付上限 {detail}".strip()
    if kind == "nobound":
        return "上限なし"
    return "—"


# 🛑 no-fix。tracker 有効時は nixpkgs 列で権威ステータスを併記。identity 有効時は NVD CPE 判定列で
# 該当確定 TP と repology 頼み (上限なし/日付上限) の FP 候補を区別する (#289)。
table(
    nofix,
    ["CVE", "sev", "pkg", "現在版"] + (["nixpkgs"] if tracker_loaded else [])
    + (["判定 (NVD CPE)"] if identity_loaded else []) + ["入口 (設定)"],
    lambda r: [r.get("vuln_id", ""), r.get("severity", ""), r.get("package", ""), r.get("version_local", "")]
    + ([_trk(r)] if tracker_loaded else [])
    + ([_nofix_cpe(r)] if identity_loaded else [])
    + [origin(r.get("package", ""), r.get("version_local", ""))],
    "🛑 NOTIFY / no-fix — 修正版なし (mitigation/受容/待ち)",
)
# ❓ UNKNOWN: 判定不能 (repology データ無し / 版解析失敗)。safe ではないので要確認 (#285a)。
table(
    unknown,
    ["CVE", "sev", "pkg", "現在版", "理由"] + (["nixpkgs"] if tracker_loaded else []) + ["入口 (設定)"],
    lambda r: [r.get("vuln_id", ""), r.get("severity", ""), r.get("package", ""), r.get("version_local", ""), r.get("classify", "")]
    + ([_trk(r)] if tracker_loaded else [])
    + [origin(r.get("package", ""), r.get("version_local", ""))],
    "❓ UNKNOWN — 判定不能 (要確認・safe ではない)",
)
# 🔁 reclassified: Tracker が notaffected/notforus と判断し no-fix/UNKNOWN から降格 (#285c/#289)。
table(
    reclassified,
    ["CVE", "sev", "pkg", "現在版", "元分類", "nixpkgs", "入口 (設定)"],
    lambda r: [
        r.get("vuln_id", ""),
        r.get("severity", ""),
        r.get("package", ""),
        r.get("version_local", ""),
        r.get("classify", ""),
        _trk(r),
        origin(r.get("package", ""), r.get("version_local", "")),
    ],
    "🔁 reclassified — Nixpkgs Tracker が非該当判断 (要確認・whitelist 候補)",
)


def _fp_reason(r):
    """🟢 likely-FP の降格理由列。disputed は NVD タグ、not_in_range は CPE 版範囲。"""
    info = r.get("_identity") or {}
    v = info.get("verdict")
    if v == "disputed":
        st = info.get("status", "")
        tag = info.get("reason", "")
        return f"NVD tag: {tag}" + (f" ({st})" if st and st.lower() == "rejected" else "")
    if v == "not_in_range":
        return f"版範囲外 {info.get('cpe', '')} {info.get('range', '')}".strip()
    return ""


# 🟢 likely-FP: no-fix のうち NVD タグ/版範囲で偽陽性疑い。降格理由を併記 (#289)。
table(
    likely_fp,
    ["CVE", "sev", "pkg", "現在版", "降格理由 (NVD)", "入口 (設定)"],
    lambda r: [
        r.get("vuln_id", ""),
        r.get("severity", ""),
        r.get("package", ""),
        r.get("version_local", ""),
        _fp_reason(r),
        origin(r.get("package", ""), r.get("version_local", "")),
    ],
    "🟢 likely-FP — no-fix 偽陽性疑い (NVD タグ/版範囲・要確認・whitelist 候補)",
)
# 🔍 spot-check: repology 非該当だが high-sev。誤判定保険の確認リスト (DROP は維持, #285b)。
table(
    spotcheck,
    ["CVE", "sev", "pkg", "現在版", "入口 (設定)"],
    lambda r: [
        r.get("vuln_id", ""),
        r.get("severity", ""),
        r.get("package", ""),
        r.get("version_local", ""),
        origin(r.get("package", ""), r.get("version_local", "")),
    ],
    f"🔍 spot-check — repology 非該当・sev≥{HIGH_SEV_SPOTCHECK:g} (念のため確認・自動 DROP)",
)
# 🚫 identity-mismatch: 名前衝突 FP。監査用に nixpkgs / CVE の repo を併記 (#285)。
table(
    collision,
    ["CVE", "sev", "pkg", "nixpkgs src repo", "CVE repo", "入口 (設定)"],
    lambda r: [
        r.get("vuln_id", ""),
        r.get("severity", ""),
        r.get("package", ""),
        (r.get("_identity") or {}).get("nix_repo", ""),
        (r.get("_identity") or {}).get("cve_repo", ""),
        origin(r.get("package", ""), r.get("version_local", "")),
    ],
    "🚫 identity-mismatch — 名前衝突 FP (別ソフト確定・surface から除外)",
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
