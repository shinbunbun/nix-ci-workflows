#!/usr/bin/env python3
"""パッケージ identity (record linkage) を検証し名前衝突 FP を検出する (#285)。

usage: vulnxscan_identity.py <csv_path> <out_json> [pkgs_base]

vulnxscan/grype/osv は CVE を Nix パッケージに **名前 (pname) だけ** で突合せるため、
同名の別ソフトに当たる「名前衝突」FP が出る。実例:
  - snappy     : Nix=github.com/google/snappy (C++) ↔ CVE=github.com/KnpLabs/snappy (PHP)
  - codex      : Nix=github.com/openai/codex      ↔ CVE=github.com/jcv8000/Codex (ノートアプリ)
  - jellyfin   : Nix=github.com/jellyfin/jellyfin ↔ CVE=github.com/jellyfin/jellyfin-ios (iOS CI)
  - malcontent : Nix=gitlab.../pwithnall/malcontent (GNOME) ↔ CVE=github.com/chainguard-dev/malcontent

判定の anchor は **homepage ではなく src.url (= 実際にビルドしている取得元)**。homepage は
人手設定で不正確/プロジェクトサイト/docs を指すことがあり信用できない。src.url の owner/repo を
Nix 側の identity とし、CVE 側は OSV references の GitHub/GitLab repo (GHSA advisory URL 優先) を取る。

**FN を増やさない設計 (最重要)**: 「不一致の積極証拠がある時だけ衝突と判定」する。
  - 両側の repo が取れない / 曖昧 → 衝突と判定しない (= 現状維持で surface したまま)
  - owner 文字列が違っても同一プロジェクトの可能性 (org 移管: lathiat/avahi → avahi/avahi) があるため、
    **両 repo を HTTP redirect で canonical 化してから比較**する。canonical 化に失敗した側があれば
    衝突と判定しない (安全側)。canonical 同士が一致 → 同一プロジェクト確定で keep。
これにより本物の TP を誤って落とす (= FN) ことを防ぐ。redirect 追跡できない移管 (gitlab→github 等で
旧 URL が生存かつ無 redirect) のみ理論上のすき間だが、nixpkgs の src.url は現行 upstream を指すため稀。

対象は UNKNOWN (err_missing_repology_version / err_invalid_version) と high-sev spot-check
(err_not_vulnerable_based_on_repology かつ sev >= SPOTCHECK_SEV) のみ。NOTIFY 等は触らない (#285 scope)。

出力 out_json: {vuln_id: {"package", "nix_repo", "cve_repo"}} = 衝突確定のみ。
summary 側が unknown/spotcheck からこれらを 🚫 identity-mismatch に隔離し durable surface から除外する。

ネットワーク/eval 失敗は全て「衝突なし」に倒し exit 0 (scan 継続・現状維持)。FN を増やさない安全側。
"""
import csv
import json
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")
TIMEOUT = 20  # 秒
UA = {"User-Agent": "vulnxscan-identity (+https://github.com/shinbunbun/nix-ci-workflows)"}

# summary.py の UNKNOWN_CLASSIFY / HIGH_SEV_SPOTCHECK と一致させること (対象 bucket を揃える)。
UNKNOWN_CLASSIFY = {"err_missing_repology_version", "err_invalid_version"}
SPOTCHECK_CLASSIFY = "err_not_vulnerable_based_on_repology"
SPOTCHECK_SEV = 9.0

# CVE 側 repo 抽出で「上流プロジェクトではない」インフラ系をはじく host / owner。
INFRA_HOSTS = {
    "nvd.nist.gov", "cve.org", "cve.mitre.org", "www.cve.org",
    "lists.debian.org", "lists.fedoraproject.org", "www.openwall.com",
    "access.redhat.com", "bugzilla.redhat.com", "security.netapp.com",
    "security.gentoo.org", "www.cisa.gov", "lists.apache.org",
    "bugs.debian.org", "bugzilla.suse.com", "lists.gnu.org",
}
INFRA_OWNERS = {"cveproject", "advisories", "github"}  # github.com/advisories, CVEProject/cvelistV5 等

# git ホスティングの URL から (host, owner, repo) を取る。GitLab API archive 形式
# (gitlab.host/api/v4/projects/<owner>%2F<repo>/...) と Web 形式の双方に対応。
_GH_RE = re.compile(r"^https?://(github\.com|gitlab\.[^/]+|gitlab\.com)/(.+)$", re.I)
_API_PROJ_RE = re.compile(r"^api/v4/projects/([^/]+)/", re.I)


def sevf(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def parse_repo(url):
    """git ホスティング URL → (host, owner, repo) 小文字。非対応 (mirror://, tarball
    ミラー, sourceforge 等) は None。owner/repo は最初の 2 セグメントを採り、.git や
    アーカイブサフィックスを落とす。"""
    if not url:
        return None
    m = _GH_RE.match(url.strip())
    if not m:
        return None
    host = m.group(1).lower()
    path = m.group(2)
    api = _API_PROJ_RE.match(path)
    if api:  # gitlab API: projects/<owner>%2F<repo>/repository/archive...
        proj = urllib.parse.unquote(api.group(1))
        parts = proj.split("/")
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


def osv_repo(cve, opener=None):
    """OSV の CVE レコードから上流 repo (host, owner, repo) を取る。GHSA advisory URL
    (/security/advisories/GHSA-) を最優先、無ければ非インフラ repo の多数決。無ければ None。
    404/ネットワーク失敗は None (= 衝突判定に使わない)。"""
    if opener is None:
        opener = urllib.request.urlopen
    url = "https://api.osv.dev/v1/vulns/" + urllib.parse.quote(cve)
    try:
        req = urllib.request.Request(url, headers={**UA, "Accept": "application/json"})
        with opener(req, timeout=TIMEOUT) as resp:
            rec = json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
        return None
    advisory = None
    votes = {}
    for ref in rec.get("references", []) or []:
        u = ref.get("url", "")
        rt = parse_repo(u)
        if not rt or _is_infra(rt):
            continue
        if "/security/advisories/" in u and advisory is None:
            advisory = rt  # GHSA advisory の所属 repo = CVE 対象本体 (最も確実)
        votes[rt] = votes.get(rt, 0) + 1
    if advisory:
        return advisory
    if votes:
        return max(votes, key=lambda k: votes[k])
    return None


def nix_repo(pname, pkgs_base, runner=None):
    """nixpkgs の src.url から (host, owner, repo)。pkgs_base.<pname>.src.url を eval する。
    eval 失敗 (attr 不在 / pname≠attr / src 構造的) や非 git ホスティングは None。
    runner は test 用に差し替え可能 (引数 list を取り stdout 文字列か None を返す)。"""
    if not pkgs_base:
        return None
    if runner is None:
        runner = _nix_eval_raw
    attr = f"{pkgs_base}.{pname}.src.url"
    out = runner(["nix", "eval", "--raw", "--no-warn-dirty", attr])
    return parse_repo(out) if out else None


def _nix_eval_raw(argv):
    """nix eval --raw を実行し stdout を返す。失敗 (非 0 / 例外) は None。"""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    out = p.stdout.strip()
    return out or None


def canonicalize(repo_tuple, opener=None):
    """repo を HTTP redirect 追跡して canonical な (host, owner, repo) に正規化する。
    org 移管 (github が 301 で新 owner へ飛ばす) を吸収するため。到達不能/失敗は None
    (= 衝突判定に使わない安全側)。"""
    if opener is None:
        opener = urllib.request.urlopen
    host, owner, repo = repo_tuple
    url = f"https://{host}/{owner}/{repo}"
    try:
        req = urllib.request.Request(url, headers=UA, method="HEAD")
        with opener(req, timeout=TIMEOUT) as resp:
            final = resp.geturl()
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError):
        # HEAD 非対応サーバ等で HTTPError の場合もある。GET で再試行。
        try:
            req = urllib.request.Request(url, headers=UA)
            with opener(req, timeout=TIMEOUT) as resp:
                final = resp.geturl()
        except (urllib.error.URLError, OSError, ValueError):
            return None
    return parse_repo(final)


def is_collision(nix_rt, cve_rt, opener=None):
    """nix 側 / CVE 側 repo が別プロジェクト (= 名前衝突) なら True。
    raw が一致 → 同一で False。raw が違う → 両方 canonical 化し、両成功かつ canonical が
    違う時だけ True。canonical 化に失敗した側があれば False (FN を出さない安全側)。"""
    if nix_rt == cve_rt:
        return False
    cn = canonicalize(nix_rt, opener)
    cc = canonicalize(cve_rt, opener)
    if cn is None or cc is None:
        return False  # 確証が取れない → 衝突と断定しない
    return cn != cc


def collect_candidates(csv_path):
    """対象 bucket (UNKNOWN + high-sev spot-check) の {pname: [(vuln_id, row), ...]}。"""
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
        is_spot = cl == SPOTCHECK_CLASSIFY and sevf(r.get("severity")) >= SPOTCHECK_SEV
        if not (is_unknown or is_spot):
            continue
        pkg = (r.get("package") or "").strip()
        if pkg:
            out.setdefault(pkg, []).append((vid, r))
    return out


def detect(csv_path, pkgs_base, osv_fn=None, nix_fn=None, collision_fn=None):
    """{vuln_id: {package, nix_repo, cve_repo}} = 衝突確定。各依存は test 用に差し替え可能。"""
    osv_fn = osv_fn or osv_repo
    nix_fn = nix_fn or nix_repo
    collision_fn = collision_fn or is_collision
    candidates = collect_candidates(csv_path)
    result = {}
    for pkg, items in candidates.items():
        # まず CVE 側 repo が 1 つでも取れるか確認 (取れないなら nix eval する価値なし)。
        cve_repos = {}
        for vid, _row in items:
            rt = osv_fn(vid)
            if rt:
                cve_repos[vid] = rt
        if not cve_repos:
            continue
        nrepo = nix_fn(pkg, pkgs_base)
        if not nrepo:
            continue
        for vid, crepo in cve_repos.items():
            try:
                if collision_fn(nrepo, crepo):
                    result[vid] = {
                        "package": pkg,
                        "nix_repo": "/".join(nrepo),
                        "cve_repo": "/".join(crepo),
                    }
            except Exception:  # 個別 CVE の判定失敗で全体を落とさない
                continue
    return result


def main(argv):
    csv_path = argv[1] if len(argv) > 1 else "vulns.triage.csv"
    out_path = argv[2] if len(argv) > 2 else "identity.json"
    pkgs_base = argv[3] if len(argv) > 3 else ""
    result = {}
    try:
        result = detect(csv_path, pkgs_base)
    except Exception as ex:  # 何があっても scan は止めない (現状維持 = FN 増やさない)
        sys.stderr.write(f"identity detect failed: {ex}\n")
        result = {}
    with open(out_path, "w") as f:
        json.dump(result, f, ensure_ascii=False)
    sys.stderr.write(f"identity: {len(result)} 件の名前衝突 FP を検出\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
