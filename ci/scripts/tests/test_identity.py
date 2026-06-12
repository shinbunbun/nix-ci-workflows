"""vulnxscan_identity.py のユニットテスト。

純粋関数 (parse_repo / 版範囲判定 / vendor ゲート / 分類) と、依存注入された detect() の
ネットワーク・nix-eval 非依存テスト。production スクリプトは変更しない。
"""
import json

import vulnxscan_identity as ident


# ----------------------------- parse_repo -----------------------------
def test_parse_repo_github_basic():
    assert ident.parse_repo("https://github.com/Madler/zlib") == ("github.com", "madler", "zlib")


def test_parse_repo_strips_git_suffix_and_extra_path():
    assert ident.parse_repo("https://github.com/Foo/Bar.git/archive/refs/tags/v1.0.tar.gz") == (
        "github.com", "foo", "bar")


def test_parse_repo_gitlab_api_projects_form():
    # api/v4/projects/<url-encoded owner%2Frepo>/... 形式
    rt = ident.parse_repo("https://gitlab.com/api/v4/projects/group%2Fsub/repository/archive.tar.gz")
    assert rt == ("gitlab.com", "group", "sub")


def test_parse_repo_rejects_unsupported():
    assert ident.parse_repo("mirror://gnu/foo/foo-1.0.tar.gz") is None
    assert ident.parse_repo("https://sourceforge.net/projects/foo/") is None
    assert ident.parse_repo("") is None
    assert ident.parse_repo(None) is None
    assert ident.parse_repo("https://github.com/onlyowner") is None


# ----------------------------- infra / disclosure フィルタ -----------------------------
def test_is_infra_by_host_and_owner():
    assert ident._is_infra(("nvd.nist.gov", "x", "y")) is True
    assert ident._is_infra(("github.com", "cveproject", "cvelistv5")) is True
    assert ident._is_infra(("github.com", "madler", "zlib")) is False


def test_is_disclosure_matches_research_repos():
    assert ident._is_disclosure(("github.com", "mandiant", "vulnerability-disclosures")) is True
    assert ident._is_disclosure(("github.com", "someone", "CVE-2023-poc")) is True
    assert ident._is_disclosure(("github.com", "madler", "zlib")) is False


# ----------------------------- _repo_from_refs -----------------------------
def test_repo_from_refs_prefers_ghsa_advisory():
    refs = [
        "https://github.com/owner/proj/issues/5",
        "https://github.com/owner/proj/issues/6",
        "https://github.com/realowner/realrepo/security/advisories/GHSA-aaaa-bbbb-cccc",
    ]
    # advisory URL が最優先 (多数決ではなく)。
    assert ident._repo_from_refs(refs) == ("github.com", "realowner", "realrepo")


def test_repo_from_refs_majority_vote_when_no_advisory():
    refs = [
        "https://github.com/a/b/commit/1",
        "https://github.com/a/b/commit/2",
        "https://github.com/c/d/issues/1",
    ]
    assert ident._repo_from_refs(refs) == ("github.com", "a", "b")


def test_repo_from_refs_excludes_infra_and_disclosure():
    refs = [
        "https://nvd.nist.gov/vuln/detail/CVE-2023-0001",
        "https://github.com/mandiant/vulnerability-disclosures/blob/x",
    ]
    assert ident._repo_from_refs(refs) is None


# ----------------------------- is_collision (canonicalize 注入) -----------------------------
def test_is_collision_identical_repos_false():
    rt = ("github.com", "a", "b")
    # 注入 opener が呼ばれないことも兼ねて確認 (raw 一致 → 即 False)。
    assert ident.is_collision(rt, rt, opener=lambda *a, **k: (_ for _ in ()).throw(AssertionError())) is False


def test_is_collision_distinct_canonical_true():
    nix_rt = ("github.com", "google", "snappy")
    cve_rt = ("github.com", "knplabs", "snappy")

    class _Resp:
        def __init__(self, url):
            self._url = url

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def geturl(self):
            return self._url

    def _opener(req, timeout=None):
        # redirect 無し。元の URL をそのまま canonical として返す。
        return _Resp(req.full_url)

    assert ident.is_collision(nix_rt, cve_rt, opener=_opener) is True


def test_is_collision_canonicalize_failure_is_safe_false():
    def _boom(req, timeout=None):
        raise OSError("unreachable")

    # 取得失敗時は collision を出さない (= surface したまま、FN を増やさない安全側)。
    assert ident.is_collision(("github.com", "a", "b"), ("github.com", "c", "d"), opener=_boom) is False


# ----------------------------- 版範囲判定 in_affected_range -----------------------------
def test_in_affected_range_inside():
    assert ident.in_affected_range("1.5.0", {"versionEndExcluding": "2.0"}) is True


def test_in_affected_range_outside_upper():
    assert ident.in_affected_range("2.5.0", {"versionEndExcluding": "2.0"}) is False


def test_in_affected_range_with_lower_bound():
    bounds = {"versionStartIncluding": "1.0", "versionEndExcluding": "2.0"}
    assert ident.in_affected_range("0.9.0", bounds) is False
    assert ident.in_affected_range("1.0.0", bounds) is True
    assert ident.in_affected_range("2.0.0", bounds) is False


def test_in_affected_range_single_component_undecidable():
    # store path アーティファクト ("1") は判定しない。
    assert ident.in_affected_range("1", {"versionEndExcluding": "2.0"}) is None


def test_in_affected_range_impure_version_undecidable():
    assert ident.in_affected_range("1.2-beta", {"versionEndExcluding": "2.0"}) is None


def test_in_affected_range_no_upper_bound_undecidable():
    # 上限が無い (該当全版) は誤適用しやすいので使わない。
    assert ident.in_affected_range("1.5.0", {"versionStartIncluding": "1.0"}) is None


def test_in_affected_range_impure_bound_undecidable():
    assert ident.in_affected_range("1.5.0", {"versionEndExcluding": "2025-09-16"}) is None


# ----------------------------- vendor ゲート -----------------------------
def test_vendor_in_tokens_direct_and_suffix():
    assert ident._vendor_in_tokens("libsndfile", {"libsndfile", "erikd"}) is True
    # `<x>_project` サフィックスを剥がした形でも照合。
    assert ident._vendor_in_tokens("libsndfile_project", {"libsndfile", "erikd"}) is True
    # 無関係 vendor は弾く。
    assert ident._vendor_in_tokens("intel", {"llvm", "clang"}) is False


# ----------------------------- adjudicate_affected / not_affected -----------------------------
def test_adjudicate_affected_promotes_in_range():
    cpe = [("taglib", "taglib", {"versionEndExcluding": "2.0"})]
    res = ident.adjudicate_affected("taglib", "1.12", cpe, {"taglib"})
    assert res is not None
    rng, vp = res
    assert vp == "taglib:taglib"
    assert "versionEndExcluding=2.0" in rng


def test_adjudicate_affected_skips_wrong_vendor():
    # vendor が tokens に無い → 誤昇格しない。
    cpe = [("intel", "taglib", {"versionEndExcluding": "2.0"})]
    assert ident.adjudicate_affected("taglib", "1.12", cpe, {"taglib"}) is None


def test_adjudicate_affected_none_when_out_of_range():
    cpe = [("taglib", "taglib", {"versionEndExcluding": "1.0"})]
    assert ident.adjudicate_affected("taglib", "1.12", cpe, {"taglib"}) is None


def test_adjudicate_not_affected_all_out_of_range():
    cpe = [("taglib", "taglib", {"versionEndExcluding": "1.0"})]
    res = ident.adjudicate_not_affected("taglib", "1.12", cpe, {"taglib"})
    assert res is not None
    assert res[1] == "taglib:taglib"


def test_adjudicate_not_affected_blocked_by_undecidable():
    # 範囲外 (False) と判定不能 (None) が混在 → 降格しない (保守)。
    cpe = [
        ("taglib", "taglib", {"versionEndExcluding": "1.0"}),     # 範囲外
        ("taglib", "taglib", {"versionStartIncluding": "0.1"}),   # 上限なし → None
    ]
    assert ident.adjudicate_not_affected("taglib", "1.12", cpe, {"taglib"}) is None


def test_adjudicate_not_affected_none_without_match():
    assert ident.adjudicate_not_affected("taglib", "1.12", [], {"taglib"}) is None


# ----------------------------- classify_nofix_cpe -----------------------------
def test_classify_nofix_cpe_confirmed():
    cpe = [("taglib", "taglib", {"versionEndExcluding": "2.0"})]
    assert ident.classify_nofix_cpe("taglib", "1.12", cpe, {"taglib"}) == (
        "confirmed", "taglib:taglib versionEndExcluding=2.0")


def test_classify_nofix_cpe_date_upper_bound():
    cpe = [("taglib", "taglib", {"versionEndExcluding": "2025-09-16"})]
    kind, _ = ident.classify_nofix_cpe("taglib", "1.12", cpe, {"taglib"})
    assert kind == "date"


def test_classify_nofix_cpe_nobound():
    cpe = [("taglib", "taglib", {"versionStartIncluding": "1.0"})]
    assert ident.classify_nofix_cpe("taglib", "1.12", cpe, {"taglib"}) == ("nobound", "")


def test_classify_nofix_cpe_none_without_vendor_match():
    cpe = [("intel", "taglib", {"versionEndExcluding": "2.0"})]
    assert ident.classify_nofix_cpe("taglib", "1.12", cpe, {"taglib"}) is None


# ----------------------------- collect_candidates -----------------------------
def test_collect_candidates_selects_target_classifies(tmp_path):
    csv_path = tmp_path / "triage.csv"
    csv_path.write_text(
        "vuln_id,package,classify,severity,version_local,whitelist\n"
        "CVE-2023-0001,taglib,err_invalid_version,5.0,1.12,\n"          # UNKNOWN → 対象
        "CVE-2023-0002,avahi,err_not_vulnerable_based_on_repology,7.5,0.8,\n"  # 非該当 (sev 有) → 対象
        "CVE-2023-0003,gcc,fix_not_available,6.0,13.2,\n"              # no-fix → 対象
        "CVE-2023-0004,foo,fix_update_to_version_nixpkgs,9.0,1.0,\n"   # fixable → 対象外
        "CVE-2023-0005,bar,err_invalid_version,5.0,1.0,true\n"        # whitelist → 除外
        "GHSA-x,baz,err_invalid_version,5.0,1.0,\n"                  # CVE 形式でない → 除外
    )
    cand = ident.collect_candidates(str(csv_path))
    assert set(cand.keys()) == {"taglib", "avahi", "gcc"}
    assert cand["taglib"] == [("CVE-2023-0001", "1.12", "err_invalid_version")]


def test_collect_candidates_missing_file(tmp_path):
    assert ident.collect_candidates(str(tmp_path / "nope.csv")) == {}


# ----------------------------- detect (依存注入・ネットワーク非依存) -----------------------------
def _write_triage(tmp_path, rows):
    csv_path = tmp_path / "triage.csv"
    header = "vuln_id,package,classify,severity,version_local,whitelist\n"
    csv_path.write_text(header + "".join(rows))
    return str(csv_path)


def test_detect_affected_promotion(tmp_path):
    csv_path = _write_triage(tmp_path, [
        "CVE-2023-1000,taglib,err_invalid_version,7.0,1.12,\n",
    ])
    result = ident.detect(
        csv_path, pkgs_base="legacyPackages.x86_64-linux",
        osv_fn=lambda cve, opener=None: {"repo": None},
        nvd_fn=lambda cve, opener=None: {
            "repo": None, "tags": set(), "status": "",
            "cpe": [("taglib", "taglib", {"versionEndExcluding": "2.0"})],
        },
        nixrepo_fn=lambda pkg, base: ("github.com", "taglib", "taglib"),
        nixhome_fn=lambda pkg, base: "https://taglib.org",
        collision_fn=lambda a, b, opener=None: False,
        sleep_fn=lambda *a, **k: None,
    )
    assert result["CVE-2023-1000"]["verdict"] == "affected"
    assert result["CVE-2023-1000"]["package"] == "taglib"


def test_detect_collision_short_circuits_via_osv(tmp_path):
    csv_path = _write_triage(tmp_path, [
        "CVE-2023-2000,snappy,err_invalid_version,5.0,1.1,\n",
    ])

    def _nvd_should_not_be_called(cve, opener=None):
        raise AssertionError("collision は OSV で確定し NVD を引かない")

    result = ident.detect(
        csv_path, pkgs_base="x",
        osv_fn=lambda cve, opener=None: {"repo": ("github.com", "knplabs", "snappy")},
        nvd_fn=_nvd_should_not_be_called,
        nixrepo_fn=lambda pkg, base: ("github.com", "google", "snappy"),
        nixhome_fn=lambda pkg, base: "",
        collision_fn=lambda a, b, opener=None: True,
        sleep_fn=lambda *a, **k: None,
    )
    assert result["CVE-2023-2000"]["verdict"] == "collision"
    assert result["CVE-2023-2000"]["nix_repo"] == "github.com/google/snappy"
    assert result["CVE-2023-2000"]["cve_repo"] == "github.com/knplabs/snappy"


def test_detect_nofix_disputed_demotion(tmp_path):
    csv_path = _write_triage(tmp_path, [
        "CVE-2023-3000,gcc,fix_not_available,6.0,13.2,\n",
    ])
    result = ident.detect(
        csv_path, pkgs_base="x",
        osv_fn=lambda cve, opener=None: {"repo": None},
        nvd_fn=lambda cve, opener=None: {
            "repo": None, "cpe": [], "status": "",
            "tags": {"disputed"},
        },
        nixrepo_fn=lambda pkg, base: ("github.com", "gcc-mirror", "gcc"),
        nixhome_fn=lambda pkg, base: "",
        collision_fn=lambda a, b, opener=None: False,
        sleep_fn=lambda *a, **k: None,
    )
    assert result["CVE-2023-3000"]["verdict"] == "disputed"
    assert result["CVE-2023-3000"]["reason"] == "disputed"


def test_detect_nofix_not_in_range_demotion(tmp_path):
    csv_path = _write_triage(tmp_path, [
        "CVE-2023-4000,taglib,fix_not_available,6.0,1.12,\n",
    ])
    result = ident.detect(
        csv_path, pkgs_base="x",
        osv_fn=lambda cve, opener=None: {"repo": None},
        nvd_fn=lambda cve, opener=None: {
            "repo": None, "status": "", "tags": set(),
            "cpe": [("taglib", "taglib", {"versionEndExcluding": "1.0"})],  # 現行版が上限超
        },
        nixrepo_fn=lambda pkg, base: ("github.com", "taglib", "taglib"),
        nixhome_fn=lambda pkg, base: "https://taglib.org",
        collision_fn=lambda a, b, opener=None: False,
        sleep_fn=lambda *a, **k: None,
    )
    assert result["CVE-2023-4000"]["verdict"] == "not_in_range"


def test_detect_no_verdict_when_inconclusive(tmp_path):
    # NVD CPE が無く collision も無い → 判定なし (promote-only、現状維持)。
    csv_path = _write_triage(tmp_path, [
        "CVE-2023-5000,foo,err_invalid_version,5.0,1.0,\n",
    ])
    result = ident.detect(
        csv_path, pkgs_base="x",
        osv_fn=lambda cve, opener=None: {"repo": None},
        nvd_fn=lambda cve, opener=None: {"repo": None, "cpe": [], "tags": set(), "status": ""},
        nixrepo_fn=lambda pkg, base: ("github.com", "foo", "foo"),
        nixhome_fn=lambda pkg, base: "",
        collision_fn=lambda a, b, opener=None: False,
        sleep_fn=lambda *a, **k: None,
    )
    assert result == {}


def test_main_writes_identity_json(tmp_path):
    csv_path = _write_triage(tmp_path, [
        "GHSA-x,foo,err_invalid_version,5.0,1.0,\n",  # 候補ゼロ (CVE 形式でない)
    ])
    out_path = tmp_path / "identity.json"
    rc = ident.main(["prog", csv_path, str(out_path), ""])
    assert rc == 0
    # pkgs_base="" のため nix_repo 等は呼ばれず候補ゼロ → 空 dict。
    assert json.loads(out_path.read_text()) == {}
