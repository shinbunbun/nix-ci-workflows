"""vulnxscan_diff_gate.py の純粋関数テスト (#347 diff-gate)。

実 vulnix を起動せず、runner 注入 (collect/run_vulnix の runner 引数) で
Δ 計算・パース・whitelist・fail-closed・body 生成を GitHub I/O 非依存に検証する。
vulnix --json の実スキーマ (pname/version/affected_by/cvssv3_basescore) を実測値で固定する。
"""
import json

import vulnxscan_diff_gate as gate


# 実測した vulnix --json の 1 要素 (openssl) を模した payload を作る。
def _pkg(pname, version, cves_scores):
    return {
        "name": f"{pname}-{version}",
        "pname": pname,
        "version": version,
        "derivation": f"/nix/store/xxxx-{pname}-{version}.drv",
        "affected_by": list(cves_scores.keys()),
        "whitelisted": [],
        "cvssv3_basescore": dict(cves_scores),
    }


def _runner_returning(pkgs, rc=2):
    """成功 runner: vulnix が JSON list を返すケース (rc は脆弱性ありで 2 でも成功扱い)。"""

    def runner(chunk):
        return rc, json.dumps(pkgs), ""

    return runner


def _runner_crash(chunk):
    """fail-closed runner: vulnix がクラッシュし stdout が空 (404 等)。"""
    return 1, "", "Traceback ...\nrequests.exceptions.HTTPError: 404"


def _write_closure(directory, target, paths):
    """download-artifact 展開を模し <dir>/<sub>/closure-paths.txt をヘッダ付きで書く。"""
    sub = directory / target.replace("/", "_").replace("#", "_").replace(".", "_")
    sub.mkdir(parents=True, exist_ok=True)
    body = f"# target: {target}\n" + "\n".join(paths) + "\n"
    (sub / "closure-paths.txt").write_text(body)


# ------------------------- _extract_findings -------------------------
def test_extract_findings_real_schema():
    pkgs = [_pkg("openssl", "3.6.2", {"CVE-2026-45447": 8.8, "CVE-2026-9076": 7.5})]
    out = gate._extract_findings(pkgs)
    assert {(f["vuln_id"], f["pname"], f["severity"]) for f in out} == {
        ("CVE-2026-45447", "openssl", "8.8"),
        ("CVE-2026-9076", "openssl", "7.5"),
    }


def test_extract_findings_missing_score_is_blank():
    pkgs = [{"pname": "p", "version": "1", "affected_by": ["CVE-X"], "cvssv3_basescore": {}}]
    out = gate._extract_findings(pkgs)
    assert out == [{"pname": "p", "version": "1", "vuln_id": "CVE-X", "severity": ""}]


# ------------------------- run_vulnix (fail-closed) -------------------------
def test_run_vulnix_success_parses_list():
    findings, err = gate.run_vulnix(
        {"/nix/store/a"}, runner=_runner_returning([_pkg("p", "1", {"CVE-A": 5.0})])
    )
    assert err is None
    assert findings == [{"pname": "p", "version": "1", "vuln_id": "CVE-A", "severity": "5.0"}]


def test_run_vulnix_empty_list_is_success_not_failure():
    findings, err = gate.run_vulnix({"/nix/store/a"}, runner=_runner_returning([], rc=0))
    assert err is None and findings == []


def test_run_vulnix_non_json_is_fail_closed():
    findings, err = gate.run_vulnix({"/nix/store/a"}, runner=_runner_crash)
    assert findings == [] and err is not None and "404" in err


# ------------------------- collect -------------------------
_HOST = ".#nixosConfigurations.host.config.system.build.toplevel"
_NEWHOST = ".#nixosConfigurations.newhost.config.system.build.toplevel"


def test_collect_only_delta_paths_scanned(tmp_path):
    head = tmp_path / "head"
    base = tmp_path / "base"
    # head は glibc(共有・base にもある) と新規 foo。base は glibc のみ。
    _write_closure(head, _HOST, ["/nix/store/glibc", "/nix/store/foo"])
    _write_closure(base, _HOST, ["/nix/store/glibc"])
    seen = {}

    def runner(chunk):
        seen["chunk"] = list(chunk)
        return 2, json.dumps([_pkg("foo", "1", {"CVE-FOO": 9.8})]), ""

    introduced, missing, failed = gate.collect(str(head), str(base), (set(), set()), runner=runner)
    # Δ = {foo} のみ (glibc は base にもあるので渡らない = 誤検出しない)
    assert seen["chunk"] == ["/nix/store/foo"]
    assert ("CVE-FOO", "foo") in introduced
    assert introduced[("CVE-FOO", "foo")]["targets"] == {"host"}
    assert not missing and not failed


def test_collect_baseline_missing(tmp_path):
    head = tmp_path / "head"
    base = tmp_path / "base"
    base.mkdir()
    _write_closure(head, _NEWHOST, ["/nix/store/foo"])
    introduced, missing, failed = gate.collect(
        str(head), str(base), (set(), set()), runner=_runner_returning([_pkg("foo", "1", {"C": 1.0})])
    )
    assert missing == ["newhost"] and not introduced and not failed


def test_collect_scan_failure_is_recorded(tmp_path):
    head = tmp_path / "head"
    base = tmp_path / "base"
    _write_closure(head, _HOST, ["/nix/store/foo"])
    _write_closure(base, _HOST, [])
    introduced, missing, failed = gate.collect(str(head), str(base), (set(), set()), runner=_runner_crash)
    assert "host" in failed and not introduced


def test_collect_whitelist_filters(tmp_path):
    head = tmp_path / "head"
    base = tmp_path / "base"
    _write_closure(head, _HOST, ["/nix/store/foo"])
    _write_closure(base, _HOST, [])
    runner = _runner_returning([_pkg("foo", "1", {"CVE-WL": 9.8, "CVE-KEEP": 5.0})])
    wl = ({"CVE-WL"}, set())
    introduced, _, _ = gate.collect(str(head), str(base), wl, runner=runner)
    assert ("CVE-KEEP", "foo") in introduced
    assert ("CVE-WL", "foo") not in introduced


# ------------------------- build_body (blocked 判定) -------------------------
def test_build_body_introduced_blocks():
    introduced = {("CVE-A", "p"): {"severity": "9.8", "targets": {"host"}}}
    body, blocked = gate.build_body(introduced, [], {}, gate_mode=True)
    assert blocked and "新規流入 1 件" in body and "CVE-A" in body


def test_build_body_clean_does_not_block():
    body, blocked = gate.build_body({}, [], {}, gate_mode=True)
    assert not blocked and "新規の既知脆弱性を持ち込みません" in body


def test_build_body_scan_failed_blocks_fail_closed():
    body, blocked = gate.build_body({}, [], {"host": "vulnix 404"}, gate_mode=True)
    assert blocked and "fail-closed" in body


# ------------------------- load_whitelist -------------------------
def test_load_whitelist_formats(tmp_path):
    wl = tmp_path / "wl.csv"
    wl.write_text("CVE-1  # 受容理由\nopenssl,CVE-2\n\n# comment\n")
    cve_only, pkg_cve = gate.load_whitelist(str(wl))
    assert cve_only == {"CVE-1"} and pkg_cve == {("openssl", "CVE-2")}
