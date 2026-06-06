#!/usr/bin/env python3
"""パッケージ identity 照合 + 版範囲判定で UNKNOWN/spot-check の精度を上げる (#285) +
no-fix の偽陽性を権威ソースで降格する (#289)。

usage: vulnxscan_identity.py <csv_path> <out_json> [pkgs_base]

vulnxscan/grype/osv は CVE を Nix パッケージに **名前 (pname) だけ** で突合せるため、
①同名の別ソフトに当たる「名前衝突 FP」と ②repology が判定できなかった「真の該当」見逃しが出る。
本スクリプトは OSV/NVD の権威データで両方を是正する:

  verdict=collision : 名前衝突 FP。CVE の対象 repo が nixpkgs の src.url repo と別物。
      durable surface から除外する。実例 snappy(google↔KnpLabs PHP)/codex(openai↔jcv8000)/
      jellyfin(server↔jellyfin-ios)/malcontent(GNOME↔chainguard)/zlib(madler↔ruby)。
  verdict=affected  : repology が判定不能/非該当としたが、NVD CPE の版範囲で **該当が確定**。
      UNKNOWN/spot-check から NOTIFY へ昇格する (#285 本丸の「判定」)。実例 taglib(<2.0)/avahi(<0.9)。

#289 (no-fix 偽陽性の降格)。no-fix (fix_not_available) は repology 単独の fallthrough 判定で、
修正版が実在する/そもそも該当しない CVE が「修正版なし=要対処」に居座る偽陽性がある。これを NVD の
権威データで降格する (降格先は silent DROP ではなく可視バケツ 🟢 likely-FP = 要確認・whitelist 候補):

  verdict=disputed     : NVD cveTags が disputed / unsupported-when-assigned /
      exclusively-hosted-service、または vulnStatus=Rejected。ベンダー否認 / 採番時 EOL /
      配布物でなくホスト型サービスの脆弱性 = パッケージ scan では偽陽性寄り。実例 gcc(CVE-2023-4039)/
      openssh(CVE-2023-51767 rowhammer、いずれも disputed)。
  verdict=not_in_range : NVD CPE の vendor 一致・product 一致の版範囲が **全て clean に「範囲外」**
      (True/None が 1 つも無い時のみ)。古い CVE の上限を現在版が超えている偽陽性。affected の対称判定。

判定 anchor は homepage でなく **src.url (= 実際にビルドしている取得元)**。
  - 名前衝突: nix=src.url の owner/repo、CVE=OSV references の GHSA advisory repo (無ければ NVD
    references の GHSA repo)。両者を HTTP redirect で **canonical 化**して比較 (org 移管を吸収)。
  - 版範囲: NVD CPE の clean semver range (versionStart/End*) を使う。ただし **CPE の vendor が
    nix の identity トークン (src.url owner/repo + homepage) に含まれる時のみ適用** する。これで
    intel:openmp(nix=LLVM) や plotly:dash(nix=shell) の版範囲を誤適用しない。

**FN を増やさない設計 (最重要)**:
  - collision は「両 repo 取得 + canonical 化成功 + canonical 不一致」の積極証拠がある時のみ確定。
    曖昧/取得失敗は collision としない (= surface したまま残す)。
  - affected は **昇格のみ** (promote-only)。判定できない/版が不一致なら UNKNOWN 据え置き
    (= 現状維持) で、降格 (DROP) は一切しない。よって FN は構造的に増えない。version 比較は
    clean な dotted-numeric 同士に限定し、vendor ゲートを通った CPE のみ使う (誤昇格=FP を防ぐ)。
  - disputed / not_in_range (#289) は no-fix を **silent DROP しない**。降格先 🟢 likely-FP は
    集約 Issue にも出る「要確認・whitelist 候補」枠なので、誤って降格しても finding は surface に
    残る (= 隠れ FN にならない)。not_in_range は vendor+product 一致の全 range が clean に「範囲外」
    の時だけ確定し、True/None が 1 つでもあれば降格しない (= 不確実は no-fix 据え置きで保守)。

対象は UNKNOWN (err_missing_repology_version / err_invalid_version)、repology 非該当
(err_not_vulnerable_based_on_repology かつ sev >= ADJUDICATE_SEV。既定 0 = 数値 sev 全件)、
および no-fix (fix_not_available、#289)。旧実装は非該当を sev>=9 の spot-check だけ判定していたが、
repology は非権威なので低 sev の silent DROP も FN になりうる。no-fix 以外の NOTIFY (fixable) は触らない。

出力 out_json: {vuln_id: {verdict, package, ...}}。summary 側が collision を 🚫 identity-mismatch、
affected を ✅ judged-affected、disputed / not_in_range を 🟢 likely-FP に振り分ける。

ネットワーク/eval 失敗は全て安全側 (collision/affected を出さない) に倒し exit 0 (scan 継続)。
"""
import csv
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")
TIMEOUT = 20  # 秒
UA = {"User-Agent": "vulnxscan-identity (+https://github.com/shinbunbun/nix-ci-workflows)"}
OSV_VULN = "https://api.osv.dev/v1/vulns/"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
NVD_KEY = os.environ.get("NVD_API_KEY", "").strip()
# NVD は API key 無しで 5 req/30s。429/403 を避けるため呼び出し間隔を空ける (key ありは短縮)。
NVD_DELAY = float(os.environ.get("NVD_DELAY", "1.5" if NVD_KEY else "6.5"))

# summary.py の UNKNOWN_CLASSIFY と一致させること。
UNKNOWN_CLASSIFY = {"err_missing_repology_version", "err_invalid_version"}
SPOTCHECK_CLASSIFY = "err_not_vulnerable_based_on_repology"
# no-fix (修正版なし) の偽陽性を権威ソースで降格する対象 classify (#289)。
NOFIX_CLASSIFY = "fix_not_available"
# NVD cveTags のうち no-fix を 🟢 likely-FP に降格してよいタグ (#289)。disputed=ベンダー否認、
# unsupported-when-assigned=採番時に対象版が EOL、exclusively-hosted-service=配布物でなく
# ホスト型サービスの脆弱性 (パッケージ scan では非該当寄り)。いずれも silent DROP せず可視化。
DEMOTE_TAGS = {"disputed", "unsupported-when-assigned", "exclusively-hosted-service"}
# repology が「非該当」と返した finding を該当判定 (Phase 2) にかける severity 下限。
# 旧実装は sev>=9 の spot-check だけ判定していたが、repology は非権威なので sev<9 を
# 黙って DROP すると FN になる。既定 0.0 = 数値 sev を持つ err_not_vulnerable 全件を判定し、
# NVD CPE が該当と確定したものだけ NOTIFY に昇格する (promote-only)。NVD 呼び出しが増える
# (key 推奨) ので、コスト調整したい場合は ADJUDICATE_SEV を上げて高 sev だけに絞れる。
ADJUDICATE_SEV = float(os.environ.get("ADJUDICATE_SEV", "0"))

# CVE 側 repo 抽出で「上流プロジェクトではない」インフラ系をはじく host / owner。
INFRA_HOSTS = {
    "nvd.nist.gov", "cve.org", "cve.mitre.org", "www.cve.org",
    "lists.debian.org", "lists.fedoraproject.org", "www.openwall.com",
    "access.redhat.com", "bugzilla.redhat.com", "security.netapp.com",
    "security.gentoo.org", "www.cisa.gov", "lists.apache.org",
    "bugs.debian.org", "bugzilla.suse.com", "lists.gnu.org",
}
INFRA_OWNERS = {"cveproject", "advisories", "github"}

# CVE references に出てくるが「上流プロジェクトではない」セキュリティ開示/リサーチ系 repo。
# owner/repo 名がこれに一致するものは collision の証拠に使わない (mandiant/vulnerability-disclosures
# を openprinting/cups の別物と誤判定する false collision を防ぐ)。collision を**減らす**方向なので
# 本物を誤って消す FN は増えない (厳しめ=keep 寄り)。実プロジェクト (KnpLabs/snappy 等) は非該当。
_DISCLOSURE_RE = re.compile(
    r"disclosur|advisor|vulnerabilit|security[-_]?research|\bcve\b|[-_]cve[-_]|"
    r"\bpoc\b|exploit|write[-_]?up|bug[-_]?bount|0day|securitylab", re.I)

# identity トークンから落とす汎用語 (host TLD / ホスティング語 / mirror パス片)。
TOKEN_STOP = {
    "", "www", "com", "org", "net", "io", "dev", "app", "apps", "github",
    "gitlab", "sourceforge", "mirror", "src", "sources", "projects", "api",
    "v4", "archive", "releases", "html", "git", "gnu", "gnupg", "download",
    "pub", "scm", "tag", "tags", "refs", "wiki", "code", "page", "home",
}

_GH_RE = re.compile(r"^https?://(github\.com|gitlab\.[^/]+)/(.+)$", re.I)
_API_PROJ_RE = re.compile(r"^api/v4/projects/([^/]+)/", re.I)
_CLEAN_VER_RE = re.compile(r"^\d+(\.\d+)*$")


def sevf(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


# ----------------------------- repo 抽出・比較 -----------------------------
def parse_repo(url):
    """git ホスティング URL → (host, owner, repo) 小文字。非対応 (mirror://, tarball
    ミラー, sourceforge 等) は None。GitLab API archive 形式にも対応。"""
    if not url or not isinstance(url, str):
        return None
    m = _GH_RE.match(url.strip())
    if not m:
        return None
    host = m.group(1).lower()
    path = m.group(2)
    api = _API_PROJ_RE.match(path)
    if api:
        parts = urllib.parse.unquote(api.group(1)).split("/")
    else:
        parts = path.split("/")
    parts = [p for p in parts if p]
    if len(parts) < 2:
        return None
    owner = parts[0].lower()
    repo = re.sub(r"\.git$", "", parts[1]).lower()
    if not owner or not repo:
        return None
    return (host, owner, repo)


def _is_infra(repo_tuple):
    host, owner, _ = repo_tuple
    return host in INFRA_HOSTS or owner in INFRA_OWNERS


def _is_disclosure(repo_tuple):
    """repo が上流プロジェクトでなくセキュリティ開示/リサーチ系なら True (owner か repo 名で判定)。
    GHSA advisory URL は当該プロジェクト repo を指すのでここには該当しない (= 影響を受けない)。"""
    _, owner, repo = repo_tuple
    return bool(_DISCLOSURE_RE.search(repo) or _DISCLOSURE_RE.search(owner))


def _repo_from_refs(refs):
    """references (url 文字列の列) から上流 repo (host, owner, repo)。GHSA advisory URL
    (/security/advisories/GHSA-) を最優先、無ければ非インフラ repo の多数決。無ければ None。
    インフラ系 (cve.org 等) と開示/リサーチ系 repo (mandiant/vulnerability-disclosures 等) は
    上流プロジェクトでないので除外する (false collision を防ぐ)。"""
    advisory = None
    votes = {}
    for u in refs:
        rt = parse_repo(u)
        if not rt or _is_infra(rt) or _is_disclosure(rt):
            continue
        if "/security/advisories/" in u and advisory is None:
            advisory = rt
        votes[rt] = votes.get(rt, 0) + 1
    if advisory:
        return advisory
    if votes:
        return max(votes, key=lambda k: votes[k])
    return None


def canonicalize(repo_tuple, opener=None):
    """repo を HTTP redirect 追跡して canonical な (host, owner, repo) に正規化する
    (org 移管を吸収)。到達不能/失敗は None (= 衝突判定に使わない安全側)。"""
    if opener is None:
        opener = urllib.request.urlopen
    host, owner, repo = repo_tuple
    url = f"https://{host}/{owner}/{repo}"
    for method in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(url, headers=UA, method=method)
            with opener(req, timeout=TIMEOUT) as resp:
                return parse_repo(resp.geturl())
        except (urllib.error.URLError, OSError, ValueError):
            continue
    return None


def is_collision(nix_rt, cve_rt, opener=None):
    """nix 側 / CVE 側 repo が別プロジェクト (= 名前衝突) なら True。raw 一致 → False、
    raw 不一致 → 両 canonical 化し、両成功かつ不一致の時だけ True (失敗側があれば False)。"""
    if not nix_rt or not cve_rt:
        return False
    if nix_rt == cve_rt:
        return False
    cn = canonicalize(nix_rt, opener)
    cc = canonicalize(cve_rt, opener)
    if cn is None or cc is None:
        return False
    return cn != cc


# ----------------------------- OSV / NVD 取得 -----------------------------
def _http_json(url, headers=None, opener=None):
    if opener is None:
        opener = urllib.request.urlopen
    try:
        req = urllib.request.Request(url, headers={**UA, **(headers or {})})
        with opener(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
        return None


def osv_fetch(cve, opener=None):
    """OSV レコードから {repo: (h,o,r)|None}。404/失敗は repo=None。"""
    rec = _http_json(OSV_VULN + urllib.parse.quote(cve), {"Accept": "application/json"}, opener)
    if not rec:
        return {"repo": None}
    refs = [r.get("url", "") for r in rec.get("references", []) or []]
    return {"repo": _repo_from_refs(refs)}


def nvd_fetch(cve, opener=None):
    """NVD レコードから {repo, cpe:[(vendor, product, bounds)], tags:set, status:str}。失敗は空。
    repo は references の GHSA repo (Phase 1b)、cpe は vulnerable な版範囲付き match (Phase 2)、
    tags/status は cveTags / vulnStatus (#289 の no-fix 降格用、disputed/Rejected 等)。"""
    headers = {"Accept": "application/json"}
    if NVD_KEY:
        headers["apiKey"] = NVD_KEY
    data = _http_json(NVD_API + urllib.parse.quote(cve), headers, opener)
    empty = {"repo": None, "cpe": [], "tags": set(), "status": ""}
    if not data:
        return empty
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return empty
    cve_o = vulns[0].get("cve", {})
    refs = [r.get("url", "") for r in cve_o.get("references", []) or []]
    cpe = []
    for cfg in cve_o.get("configurations", []) or []:
        for node in cfg.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable"):
                    continue
                parts = m.get("criteria", "").split(":")
                if len(parts) < 6:
                    continue
                vendor, product = parts[3].lower(), parts[4].lower()
                bounds = {k: m[k] for k in (
                    "versionStartIncluding", "versionStartExcluding",
                    "versionEndIncluding", "versionEndExcluding") if k in m}
                if bounds:
                    cpe.append((vendor, product, bounds))
    # cveTags は [{sourceIdentifier, tags:[...]}, ...]。全 source の tags を平坦化して集める。
    tags = set()
    for ct in cve_o.get("cveTags", []) or []:
        for t in ct.get("tags", []) or []:
            tags.add(str(t).lower())
    return {"repo": _repo_from_refs(refs), "cpe": cpe,
            "tags": tags, "status": str(cve_o.get("vulnStatus", ""))}


# ----------------------------- nix 側 identity -----------------------------
def _nix_eval_raw(argv):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    return (p.stdout.strip() or None) if p.returncode == 0 else None


def nix_repo(pname, pkgs_base, runner=None):
    """nixpkgs の src から (host, owner, repo)。pkgs_base.<pname>.src.url (単数 URL の
    fetchurl/fetchFromGitHub) を見て、空なら .src.urls (複数 URL の fetchurl。mirror や
    複数ミラー指定) の最初の git URL を採る。eval 失敗 (pname≠attr 等) や非 git ホスティングは None。"""
    if not pkgs_base:
        return None
    runner = runner or _nix_eval_raw
    attr = f"{pkgs_base}.{pname}.src"
    out = runner(["nix", "eval", "--raw", "--no-warn-dirty", f"{attr}.url"])
    rt = parse_repo(out) if out else None
    if rt:
        return rt
    js = runner(["nix", "eval", "--json", "--no-warn-dirty", f"{attr}.urls"])
    if js:
        try:
            for u in json.loads(js):
                rt = parse_repo(u)
                if rt:
                    return rt
        except (ValueError, TypeError):
            pass
    return None


def nix_homepage(pname, pkgs_base, runner=None):
    """nixpkgs の meta.homepage (vendor ゲート用トークン源)。失敗は ""。"""
    if not pkgs_base:
        return ""
    runner = runner or _nix_eval_raw
    return runner(["nix", "eval", "--raw", "--no-warn-dirty", f"{pkgs_base}.{pname}.meta.homepage"]) or ""


def _tokenize(*strs):
    toks = set()
    for s in strs:
        for t in re.split(r"[^a-z0-9]+", (s or "").lower()):
            if t and t not in TOKEN_STOP and not t.isdigit():
                toks.add(t)
    return toks


def nix_tokens(src_repo, homepage):
    """nix の identity トークン集合 (src.url owner/repo + homepage)。CPE vendor ゲート用。"""
    toks = set()
    if src_repo:
        toks |= _tokenize(src_repo[1], src_repo[2])
    if homepage:
        toks |= _tokenize(urllib.parse.urlparse(homepage).netloc, urllib.parse.urlparse(homepage).path)
    return toks


# ----------------------------- 版範囲判定 -----------------------------
def _cv(v):
    """clean な dotted-numeric 版 → int タプル。不純 (beta/rc/英字/-N suffix) は None。"""
    return tuple(int(x) for x in v.split(".")) if v and _CLEAN_VER_RE.match(v) else None


def _ge(a, b):
    return _pad(a, b) >= _pad(b, a)


def _pad(a, b):
    return a + (0,) * (len(b) - len(a))


def in_affected_range(inst_ver, bounds):
    """inst_ver が bounds (NVD CPE の versionStart/End*) の affected 範囲内なら True、
    範囲外 False、clean に比較できなければ None (= 判定不能でスキップ)。"""
    iv = _cv(inst_ver)
    # 単一コンポーネント版 ("1" 等) は store path のパースアーティファクトの可能性が高い
    # (dbus→"1"/polkit→"1")。"1" < 1.12.24 のような誤該当を避けるため判定しない。
    if iv is None or len(iv) < 2:
        return None
    si, se = bounds.get("versionStartIncluding"), bounds.get("versionStartExcluding")
    ei, ee = bounds.get("versionEndIncluding"), bounds.get("versionEndExcluding")
    present = [v for v in (si, se, ei, ee) if v is not None]
    if not present:
        return None
    if any(_cv(v) is None for v in present):
        return None  # 範囲側に不純な版 (0.8-4 等) → 安全に判定不能
    if not (ei or ee):
        return None  # 上限が無い (該当全版) は誤適用しやすいので使わない
    lo_ok = (_ge(iv, _cv(si)) if si else True) and (not se or _pad(iv, _cv(se)) > _pad(_cv(se), iv))
    hi_ok = (not ee or _pad(iv, _cv(ee)) < _pad(_cv(ee), iv)) and (_ge(_cv(ei), iv) if ei else True)
    return bool(lo_ok and hi_ok)


def _norm(s):
    return re.sub(r"[-_]", "", (s or "").lower())


def adjudicate_affected(pname, inst_ver, cpe_list, tokens):
    """NVD CPE 群から「該当確定」を判定。product≈pname かつ vendor∈tokens の range のみ使う。
    in_range True が 1 つでもあれば (range 文字列, 'vendor:product') を返す。無ければ None。"""
    target = _norm(pname)
    for vendor, product, bounds in cpe_list:
        if _norm(product) != target:
            continue
        if vendor not in tokens:  # vendor ゲート: intel:openmp / plotly:dash 等の誤適用を防ぐ
            continue
        if in_affected_range(inst_ver, bounds) is True:
            rng = ",".join(f"{k}={v}" for k, v in bounds.items())
            return (rng, f"{vendor}:{product}")
    return None


def adjudicate_not_affected(pname, inst_ver, cpe_list, tokens):
    """affected の対称 (#289)。product≈pname かつ vendor∈tokens の range だけ見て、それらが
    **全て clean に「範囲外 (False)」** の時だけ (range 文字列, 'vendor:product') を返す。
    True (該当) や None (判定不能・不純な版/上限なし) が 1 つでもあれば None = 降格しない
    (= no-fix 据え置きで保守、隠れ FN を作らない)。一致 CPE が無くても None。"""
    target = _norm(pname)
    matched = []
    for vendor, product, bounds in cpe_list:
        if _norm(product) != target:
            continue
        if vendor not in tokens:  # vendor ゲート: affected と同じ誤適用防止
            continue
        matched.append((vendor, product, bounds, in_affected_range(inst_ver, bounds)))
    if not matched:
        return None
    if any(v is not False for _, _, _, v in matched):  # True/None があれば降格不可
        return None
    rng = ";".join(",".join(f"{k}={x}" for k, x in b.items()) for _, _, b, _ in matched)
    vp = matched[0]
    return (rng, f"{vp[0]}:{vp[1]}")


def classify_nofix_cpe(pname, inst_ver, cpe_list, tokens):
    """no-fix のまま据え置く項目の NVD CPE 判定を表示用に分類 (分類は動かさない、#289 表示拡張)。
    not_in_range (全 range が clean に範囲外) で降格しなかった = 該当確定/上限なし/日付上限 の
    いずれか。vendor+product 一致の range だけ見て (厳格 vendor ゲート):
      ('confirmed', 'vendor:product range')  : in_affected_range True = NVD CPE で該当確定 (本物 TP)
      ('date',      'k=v,...')               : 上限が semver でない (日付等) = git-master 修正で
                                               release 未反映の疑い (要 backport 確認・FP 候補)
      ('nobound',   '')                      : 一致 range はあるが上限なし (versionStart のみ)
    一致 range が無い (vendor 不一致/未照会) は None (表示 '—')。"""
    target = _norm(pname)
    matched = [(v, p, b) for v, p, b in cpe_list if _norm(p) == target and v in tokens]
    if not matched:
        return None
    for v, p, b in matched:
        if in_affected_range(inst_ver, b) is True:
            rng = ",".join(f"{k}={x}" for k, x in b.items())
            return ("confirmed", f"{v}:{p} {rng}")
    _UPPER = ("versionEndIncluding", "versionEndExcluding")
    for v, p, b in matched:
        # 上限キーを持ち、その値が clean semver でない (日付 2025-09-16 等) = date 上限
        if any(k in b for k in _UPPER) and any(_cv(b[k]) is None for k in _UPPER if k in b):
            return ("date", ",".join(f"{k}={x}" for k, x in b.items()))
    return ("nobound", "")


# ----------------------------- 候補収集・統合判定 -----------------------------
def collect_candidates(csv_path):
    """判定対象の {pname: [(vuln_id, version_local, classify), ...]}。
    対象 = UNKNOWN (repology 判定不能) + err_not_vulnerable (repology 非該当) のうち数値 sev が
    ADJUDICATE_SEV 以上のもの + no-fix (fix_not_available、#289)。err_not_vulnerable は旧実装の
    sev>=9 spot-check 限定から全 sev へ拡張し、repology が黙って DROP していた低 sev の見逃し (FN)
    も NVD CPE で再判定する (#285)。no-fix は detect 側で昇格でなく降格 (disputed/not_in_range) に回す。
    classify を 3 要素目に持たせ、detect が昇格 (UNKNOWN/非該当) と降格 (no-fix) を振り分ける。"""
    out = {}
    try:
        with open(csv_path) as f:
            rows = list(csv.DictReader(f))
    except FileNotFoundError:
        return out
    for r in rows:
        if str(r.get("whitelist", "")).strip().lower() == "true":
            continue
        cl = r.get("classify", "")
        vid = (r.get("vuln_id") or "").strip()
        if not CVE_RE.match(vid):
            continue
        is_unknown = cl in UNKNOWN_CLASSIFY
        sev_str = (r.get("severity") or "").strip()
        is_notvuln = cl == SPOTCHECK_CLASSIFY and sev_str != "" and sevf(sev_str) >= ADJUDICATE_SEV
        is_nofix = cl == NOFIX_CLASSIFY
        if not (is_unknown or is_notvuln or is_nofix):
            continue
        pkg = (r.get("package") or "").strip()
        if pkg:
            out.setdefault(pkg, []).append((vid, (r.get("version_local") or "").strip(), cl))
    return out


def detect(csv_path, pkgs_base, osv_fn=None, nvd_fn=None, nixrepo_fn=None,
           nixhome_fn=None, collision_fn=None, sleep_fn=None):
    """{vuln_id: {verdict, package, ...}}。verdict は collision か affected。
    各依存は test 用に差し替え可能。"""
    osv_fn = osv_fn or osv_fetch
    nvd_fn = nvd_fn or nvd_fetch
    nixrepo_fn = nixrepo_fn or nix_repo
    nixhome_fn = nixhome_fn or nix_homepage
    collision_fn = collision_fn or is_collision
    sleep_fn = sleep_fn or time.sleep
    candidates = collect_candidates(csv_path)
    result = {}
    nvd_calls = 0
    for pkg, items in candidates.items():
        src = nixrepo_fn(pkg, pkgs_base)
        tokens = None  # lazy: homepage eval は範囲判定が要る時だけ
        for vid, inst, cls in items:
            if vid in result:  # 同一 CVE が複数 pkg に跨る時の二重判定を避ける (先勝ち)
                continue
            is_nofix = cls == NOFIX_CLASSIFY
            try:
                # ① OSV repo で衝突確定なら NVD を引かずに終了 (NVD rate-limit 節約)。
                #    衝突 (別ソフト確定) は no-fix/UNKNOWN を問わず純粋な FP なので共通。
                osv_repo = osv_fn(vid).get("repo")
                if src and osv_repo and collision_fn(src, osv_repo):
                    result[vid] = {"verdict": "collision", "package": pkg,
                                   "nix_repo": "/".join(src), "cve_repo": "/".join(osv_repo)}
                    continue
                # ② NVD を引く (repo=Phase1b フォールバック + cpe=Phase2 版範囲 + tags/status=#289)
                if nvd_calls:
                    sleep_fn(NVD_DELAY)  # 2 件目以降は間隔を空ける (429/403 回避)
                nvd_calls += 1
                nvd = nvd_fn(vid)
                cve_repo = osv_repo or nvd.get("repo")
                if src and cve_repo and collision_fn(src, cve_repo):
                    result[vid] = {"verdict": "collision", "package": pkg,
                                   "nix_repo": "/".join(src), "cve_repo": "/".join(cve_repo)}
                    continue
                if is_nofix:
                    # #289: no-fix は降格判定のみ (昇格しない。既に NOTIFY のため)。
                    # (a) cveTags / vulnStatus による disputed 降格 (権威・ゼロ FN)
                    tags = nvd.get("tags") or set()
                    bad = tags & DEMOTE_TAGS
                    status = nvd.get("status") or ""
                    if bad or status.lower() == "rejected":
                        result[vid] = {"verdict": "disputed", "package": pkg,
                                       "reason": ",".join(sorted(bad)) or "rejected",
                                       "tags": sorted(tags), "status": status, "source": "nvd"}
                        continue
                    # (b) NVD CPE 版範囲が全て「範囲外」なら not_in_range 降格 (affected の対称)
                    if nvd.get("cpe"):
                        if tokens is None:
                            tokens = nix_tokens(src, nixhome_fn(pkg, pkgs_base))
                        nia = adjudicate_not_affected(pkg, inst, nvd["cpe"], tokens)
                        if nia:
                            result[vid] = {"verdict": "not_in_range", "package": pkg,
                                           "version": inst, "range": nia[0],
                                           "cpe": nia[1], "source": "nvd"}
                            continue
                        # (c) 降格しない (該当確定/上限なし/日付上限) なら NVD CPE 判定を
                        # annotation として記録 (分類は no-fix のまま、表示用。lever 2 で取れない
                        # FP 候補=上限なし/日付上限と、NVD 該当確定 TP を no-fix 表で区別する)。
                        cn = classify_nofix_cpe(pkg, inst, nvd["cpe"], tokens)
                        if cn:
                            result[vid] = {"verdict": "nofix_cpe", "package": pkg,
                                           "kind": cn[0], "detail": cn[1], "source": "nvd"}
                    continue
                if nvd.get("cpe"):
                    if tokens is None:
                        tokens = nix_tokens(src, nixhome_fn(pkg, pkgs_base))
                    # version_local (= vulnxscan が見た脆弱インスタンスの版) で判定する。
                    # closure に複数版がある (pin) 場合この版が脆弱な実体なので .version
                    # (default attr 版) では見逃す。ただしパースアーティファクト ("1" 等) は
                    # in_affected_range が弾く (2 要素以上の dotted 版のみ判定)。
                    judged = adjudicate_affected(pkg, inst, nvd["cpe"], tokens)
                    if judged:
                        result[vid] = {"verdict": "affected", "package": pkg,
                                       "version": inst, "range": judged[0],
                                       "cpe": judged[1], "source": "nvd"}
            except Exception:  # 個別 CVE の失敗で全体を落とさない (安全側=判定なし)
                continue
    return result


def main(argv):
    csv_path = argv[1] if len(argv) > 1 else "vulns.triage.csv"
    out_path = argv[2] if len(argv) > 2 else "identity.json"
    pkgs_base = argv[3] if len(argv) > 3 else ""
    result = {}
    try:
        result = detect(csv_path, pkgs_base)
    except Exception as ex:  # 何があっても scan は止めない (現状維持)
        sys.stderr.write(f"identity detect failed: {ex}\n")
        result = {}
    with open(out_path, "w") as f:
        json.dump(result, f, ensure_ascii=False)
    def _cnt(v):
        return sum(1 for x in result.values() if x.get("verdict") == v)
    sys.stderr.write(
        f"identity: 名前衝突 {_cnt('collision')} 件 / 該当確定 (昇格) {_cnt('affected')} 件 / "
        f"no-fix 降格 disputed {_cnt('disputed')} 件・範囲外 {_cnt('not_in_range')} 件 / "
        f"no-fix NVD CPE 注記 {_cnt('nofix_cpe')} 件\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
