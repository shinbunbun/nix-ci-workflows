"""vulnxscan_diff_gate.py の純粋関数テスト (#347 diff-gate, B 設計)。

実 vulnix を起動せず runner 注入で producer (scan_delta) / aggregator (aggregate) /
パース・deriver フィルタ・whitelist・body 生成を GitHub I/O 非依存に検証する。
vulnix --json の実スキーマ (pname/version/affected_by/cvssv3_basescore) を実測値で固定する。
"""
import json

import vulnxscan_diff_gate as gate

_HOST = ".#nixosConfigurations.host.config.system.build.toplevel"


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
    def runner(chunk):
        return rc, json.dumps(pkgs), ""

    return runner


def _runner_crash(chunk):
    return 1, "", "Traceback ...\nrequests.exceptions.HTTPError: 404"


def _closure(path, target, paths):
    path.write_text(f"# target: {target}\n" + "\n".join(paths) + "\n")


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
    assert gate._extract_findings(pkgs) == [
        {"pname": "p", "version": "1", "vuln_id": "CVE-X", "severity": ""}
    ]


# ------------------------- run_vulnix (fail-closed) -------------------------
def test_run_vulnix_success_parses_list():
    findings, err = gate.run_vulnix(
        {"/nix/store/a"}, runner=_runner_returning([_pkg("p", "1", {"CVE-A": 5.0})])
    )
    assert err is None
    assert findings == [{"pname": "p", "version": "1", "vuln_id": "CVE-A", "severity": "5.0"}]


def test_run_vulnix_empty_list_is_success():
    findings, err = gate.run_vulnix({"/nix/store/a"}, runner=_runner_returning([], rc=0))
    assert err is None and findings == []


def test_run_vulnix_non_json_is_fail_closed():
    findings, err = gate.run_vulnix({"/nix/store/a"}, runner=_runner_crash)
    assert findings == [] and err is not None and "404" in err


# ------------------------- scannable_paths (deriver フィルタ) -------------------------
def test_scannable_paths_drops_unknown_and_missing_deriver():
    derivers = {
        "/nix/store/a-openssl-3.6.2": "/nix/store/x-openssl-3.6.2.drv",
        "/nix/store/b-unit-home-manager.service": "unknown-deriver",
        "/nix/store/c-glibc-2.42": "/nix/store/y-glibc-2.42.drv",
        "/nix/store/d-reference-manpage": "",
    }
    out = gate.scannable_paths(list(derivers), query=lambda p: derivers[p])
    assert out == ["/nix/store/a-openssl-3.6.2", "/nix/store/c-glibc-2.42"]


# ------------------------- scan_delta (producer) -------------------------
def test_scan_delta_only_delta_paths_scanned(tmp_path):
    head = tmp_path / "head.txt"
    base = tmp_path / "base.txt"
    out = tmp_path / "out.json"
    # head は glibc(共有) と新規 foo。base は glibc のみ。
    _closure(head, _HOST, ["/nix/store/glibc", "/nix/store/foo"])
    _closure(base, _HOST, ["/nix/store/glibc"])
    seen = {}

    def runner(chunk):
        seen["chunk"] = list(chunk)
        return 2, json.dumps([_pkg("foo", "1", {"CVE-FOO": 9.8})]), ""

    res = gate.scan_delta(str(head), str(base), str(out), runner=runner)
    assert seen["chunk"] == ["/nix/store/foo"]  # glibc(共有)は渡らない
    assert res["label"] == "host"
    assert res["findings"][0]["vuln_id"] == "CVE-FOO"
    assert res["scan_failed"] is None and not res["baseline_missing"]
    assert json.load(open(out))["findings"]  # out.json に書かれている


def test_scan_delta_baseline_missing(tmp_path):
    head = tmp_path / "head.txt"
    out = tmp_path / "out.json"
    _closure(head, _HOST, ["/nix/store/foo"])
    res = gate.scan_delta(
        str(head), str(tmp_path / "nope.txt"), str(out),
        runner=_runner_returning([_pkg("foo", "1", {"C": 1.0})]),
    )
    assert res["baseline_missing"] and not res["findings"] and res["scan_failed"] is None


def test_scan_delta_scan_failure(tmp_path):
    head = tmp_path / "head.txt"
    base = tmp_path / "base.txt"
    out = tmp_path / "out.json"
    _closure(head, _HOST, ["/nix/store/foo"])
    _closure(base, _HOST, [])
    res = gate.scan_delta(str(head), str(base), str(out), runner=_runner_crash)
    assert res["scan_failed"] and "404" in res["scan_failed"] and not res["findings"]


def test_scan_delta_whitelist(tmp_path):
    head = tmp_path / "head.txt"
    base = tmp_path / "base.txt"
    out = tmp_path / "out.json"
    _closure(head, _HOST, ["/nix/store/foo"])
    _closure(base, _HOST, [])
    wl = tmp_path / "wl.csv"
    wl.write_text('vuln_id,comment,package\n^CVE-WL$,"受容理由",\n')
    runner = _runner_returning([_pkg("foo", "1", {"CVE-WL": 9.8, "CVE-KEEP": 5.0})])
    res = gate.scan_delta(
        str(head), str(base), str(out), whitelist=gate.load_whitelist(str(wl)), runner=runner
    )
    ids = {f["vuln_id"] for f in res["findings"]}
    assert ids == {"CVE-KEEP"}


# ------------------------- aggregate (aggregator) -------------------------
def test_aggregate_collects_findings_and_failures(tmp_path):
    d = tmp_path / "introduced"
    d.mkdir()
    (d / "host.json").write_text(json.dumps({
        "target": _HOST, "label": "host",
        "findings": [{"vuln_id": "CVE-A", "pname": "p", "severity": "9.8"}],
        "scan_failed": None, "baseline_missing": False,
    }))
    (d / "mac.json").write_text(json.dumps({
        "label": "mac", "findings": [], "scan_failed": "vulnix 404", "baseline_missing": False,
    }))
    (d / "new.json").write_text(json.dumps({
        "label": "newhost", "findings": [], "scan_failed": None, "baseline_missing": True,
    }))
    introduced, missing, failed = gate.aggregate(str(d))
    assert ("CVE-A", "p") in introduced
    assert introduced[("CVE-A", "p")]["targets"] == {"host"}
    assert failed == {"mac": "vulnix 404"}
    assert missing == ["newhost"]


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


def test_build_body_baseline_missing_does_not_block():
    body, blocked = gate.build_body({}, ["newhost"], {}, gate_mode=True)
    assert not blocked and "baseline" in body


# ------------------------- load_whitelist / apply_whitelist -------------------------
def test_load_whitelist_formats(tmp_path):
    """sbomnix 3 列 CSV (正規表現+package) とレガシー簡易形式の混在を受理する。"""
    wl = tmp_path / "wl.csv"
    wl.write_text(
        "vuln_id,comment,package\n"
        '^CVE-2021-4034$,"polkit FP",polkit\n'
        "CVE-1  # 受容理由\n"
        "openssl,CVE-2\n"
        "\n# comment\n"
    )
    matchers = gate.load_whitelist(str(wl))
    findings = [
        {"vuln_id": "CVE-2021-4034", "pname": "polkit"},  # sbomnix 正規表現+pkg 一致 → drop
        {"vuln_id": "CVE-2021-4034", "pname": "other"},   # pkg 不一致 → keep
        {"vuln_id": "CVE-1", "pname": "anything"},         # legacy CVE 単体 → drop
        {"vuln_id": "CVE-2", "pname": "openssl"},          # legacy pname,CVE 一致 → drop
        {"vuln_id": "CVE-2", "pname": "curl"},             # pkg 不一致 → keep
        {"vuln_id": "CVE-9", "pname": "x"},                # 無関係 → keep
    ]
    kept = {(f["vuln_id"], f["pname"]) for f in gate.apply_whitelist(findings, matchers)}
    assert kept == {("CVE-2021-4034", "other"), ("CVE-2", "curl"), ("CVE-9", "x")}


def test_load_whitelist_empty_and_missing(tmp_path):
    """空/不在 whitelist は finding をそのまま通す (regression: 旧 (set,set) の真偽判定罠)。"""
    findings = [{"vuln_id": "CVE-X", "pname": "p"}]
    assert gate.apply_whitelist(findings, gate.load_whitelist(None)) == findings
    assert gate.apply_whitelist(findings, gate.load_whitelist(str(tmp_path / "nope.csv"))) == findings
