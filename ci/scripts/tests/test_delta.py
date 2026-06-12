"""vulnxscan_delta.py の純粋関数テスト (#284 PR delta ロジック)。

delta.py は main(argv) ガード化され import 時に副作用を持たないので、純粋関数
(load_signals / group / compute_delta / render_table) と build_body を GitHub I/O 非依存で検証する。
"""
import json

import vulnxscan_delta as delta


def _write(dir_path, target, findings, judged=None):
    leg = dir_path / "leg1"
    leg.mkdir(parents=True, exist_ok=True)
    payload = {"target": target, "findings": findings}
    if judged is not None:
        payload["judged"] = judged
    (leg / "notify.json").write_text(json.dumps(payload))


# ----------------------------- load_signals -----------------------------
def test_load_signals_keys_actionable_findings(tmp_path):
    _write(tmp_path, ".#nixosConfigurations.host-a.config", [
        {"vuln_id": "CVE-1", "package": "p", "severity": "9.0",
         "classify": "fix_not_available", "entry": "systemPackages"},
        {"vuln_id": "CVE-2", "package": "q", "severity": "5.0",
         "classify": "fix_update_to_version_nixpkgs"},
    ])
    keyed, targets = delta.load_signals(str(tmp_path))
    assert targets == {"host-a"}
    assert keyed[("host-a", "CVE-1", "p")]["kind"] == "no-fix"
    assert keyed[("host-a", "CVE-2", "q")]["kind"] == "fixable"


def test_load_signals_marks_judged_kind(tmp_path):
    _write(tmp_path, ".#nixosConfigurations.h.config", [],
           judged=[{"vuln_id": "CVE-J", "package": "j", "severity": "8.0"}])
    keyed, _ = delta.load_signals(str(tmp_path))
    assert keyed[("h", "CVE-J", "j")]["kind"] == "judged"


def test_load_signals_skips_findings_without_vuln_id(tmp_path):
    _write(tmp_path, ".#nixosConfigurations.h.config",
           [{"vuln_id": "", "package": "p", "severity": "9", "classify": "fix_not_available"}])
    keyed, targets = delta.load_signals(str(tmp_path))
    assert keyed == {}
    assert targets == {"h"}


# ----------------------------- group -----------------------------
def test_group_dedups_and_keeps_max_severity():
    src = {
        ("host-a", "CVE-1", "p"): {"severity": "5.0", "kind": "no-fix", "entry": "systemPackages"},
        ("host-b", "CVE-1", "p"): {"severity": "9.1", "kind": "no-fix", "entry": "—"},
    }
    rows = delta.group(list(src), src)
    assert len(rows) == 1
    (vid, pkg), e = rows[0]
    assert (vid, pkg) == ("CVE-1", "p")
    assert e["severity"] == "9.1"
    assert e["targets"] == {"host-a", "host-b"}
    # entry が "—" のものは集約に含めない。
    assert e["entry"] == {"systemPackages"}


# ----------------------------- compute_delta -----------------------------
def test_compute_delta_introduced_and_resolved(tmp_path):
    head = tmp_path / "head"
    base = tmp_path / "base"
    _write(head, ".#nixosConfigurations.host-a.config", [
        {"vuln_id": "CVE-NEW", "package": "n", "severity": "9.0",
         "classify": "fix_not_available"},
    ])
    _write(base, ".#nixosConfigurations.host-a.config", [
        {"vuln_id": "CVE-OLD", "package": "o", "severity": "6.0",
         "classify": "fix_not_available"},
    ])
    introduced, resolved, base_missing, head_missing, have_baseline = delta.compute_delta(
        str(head), str(base))
    assert have_baseline is True
    assert base_missing == [] and head_missing == []
    assert [vid for (vid, _), _ in introduced] == ["CVE-NEW"]
    assert [vid for (vid, _), _ in resolved] == ["CVE-OLD"]


def test_compute_delta_baseline_missing_target_excluded_from_introduced(tmp_path):
    head = tmp_path / "head"
    base = tmp_path / "base"
    _write(head, ".#nixosConfigurations.new-host.config", [
        {"vuln_id": "CVE-X", "package": "x", "severity": "9.0",
         "classify": "fix_not_available"},
    ])
    # base には new-host が無い (baseline 不在) → introduced に出さず注記する。
    base.mkdir()
    introduced, resolved, base_missing, head_missing, have_baseline = delta.compute_delta(
        str(head), str(base))
    assert have_baseline is False
    assert introduced == []
    assert base_missing == ["new-host"]


# ----------------------------- build_body -----------------------------
def test_build_body_reports_no_change(tmp_path):
    head = tmp_path / "head"
    base = tmp_path / "base"
    finding = [{"vuln_id": "CVE-SAME", "package": "s", "severity": "7.0",
                "classify": "fix_not_available"}]
    _write(head, ".#nixosConfigurations.h.config", finding)
    _write(base, ".#nixosConfigurations.h.config", finding)
    body, introduced, resolved = delta.build_body(str(head), str(base), gate_mode=False)
    assert introduced == [] and resolved == []
    assert "要対処 CVE 集合を変えません" in body
    assert "report-only" in body


def test_build_body_gate_mode_blocks_on_introduced(tmp_path):
    head = tmp_path / "head"
    base = tmp_path / "base"
    _write(head, ".#nixosConfigurations.h.config", [
        {"vuln_id": "CVE-NEW", "package": "n", "severity": "9.0",
         "classify": "fix_not_available"},
    ])
    _write(base, ".#nixosConfigurations.h.config", [])
    body, introduced, resolved = delta.build_body(str(head), str(base), gate_mode=True)
    assert [vid for (vid, _), _ in introduced] == ["CVE-NEW"]
    assert "auto-merge をブロック" in body
