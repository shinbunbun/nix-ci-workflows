"""vulnxscan_aggregate.py の純粋関数テスト (#283 集約ロジック)。

aggregate.py は main(argv) ガード化され import 時に副作用を持たないので、純粋関数
(_accumulate / _sort_items / 列フォーマッタ) と build_body を GitHub I/O 非依存で検証する。
build_body は notify.json を読むだけ (GitHub 呼び出しは main 側) なので、tmp の signals dir
に対して markdown body と件数を end-to-end で確認できる。
"""
import json

import vulnxscan_aggregate as agg


# ----------------------------- _accumulate / dedup -----------------------------
def test_accumulate_dedups_by_vuln_id_and_keeps_max_severity():
    out = {}
    agg._accumulate(out, "host-a", {"vuln_id": "CVE-1", "severity": "5.0", "package": "p",
                                    "classify": "fix_not_available", "version_local": "1.0"})
    agg._accumulate(out, "host-b", {"vuln_id": "CVE-1", "severity": "9.8", "package": "p",
                                    "classify": "fix_not_available", "version_local": "1.0"})
    assert set(out) == {"CVE-1"}
    e = out["CVE-1"]
    # 影響 target は両方列挙、severity は最大を保持。
    assert e["targets"] == {"host-a", "host-b"}
    assert e["severity"] == "9.8"


def test_accumulate_skips_entries_without_vuln_id():
    out = {}
    agg._accumulate(out, "host", {"vuln_id": "", "severity": "9.0", "package": "p"})
    assert out == {}


def test_accumulate_collapses_base_dependency_entry():
    out = {}
    agg._accumulate(out, "h", {"vuln_id": "CVE-2", "severity": "1", "package": "p",
                               "entry": "基盤依存 (6 入口)"})
    agg._accumulate(out, "h2", {"vuln_id": "CVE-2", "severity": "1", "package": "p",
                                "entry": "基盤依存 (9 入口)"})
    # 基盤依存は個別 set に積まず最大入口数だけ保持。
    assert out["CVE-2"]["base_n"] == 9
    assert out["CVE-2"]["entry"] == set()


# ----------------------------- 列フォーマッタ -----------------------------
def test_entrycol_lists_entries_then_base_dependency():
    e = {"entry": {"systemPackages", "home.packages"}, "base_n": 4}
    assert agg.entrycol(e) == "home.packages,systemPackages,基盤依存 (4 入口)"


def test_entrycol_dash_when_empty():
    assert agg.entrycol({"entry": set(), "base_n": 0}) == "—"


def test_joinset_sorts_and_drops_empty():
    assert agg.joinset({"b", "", "a"}) == "a,b"


def test_sort_items_descending_by_severity():
    data = {"CVE-lo": {"severity": "3.0"}, "CVE-hi": {"severity": "9.1"}}
    ordered = [vid for vid, _ in agg._sort_items(data)]
    assert ordered == ["CVE-hi", "CVE-lo"]


# ----------------------------- build_body (end-to-end, GitHub 非依存) -----------------------------
def _write_signals(tmp_path, payload):
    leg = tmp_path / "leg1"
    leg.mkdir()
    (leg / "notify.json").write_text(json.dumps(payload))
    return str(tmp_path)


def test_build_body_counts_and_buckets(tmp_path):
    signals = _write_signals(tmp_path, {
        "target": ".#nixosConfigurations.host-a.config",
        "findings": [
            {"vuln_id": "CVE-A", "severity": "9.8", "package": "bar",
             "classify": "fix_not_available", "version_local": "2.0"},
            {"vuln_id": "CVE-B", "severity": "7.0", "package": "foo",
             "classify": "fix_update_to_version_nixpkgs", "version_local": "1.0",
             "version_nixpkgs": "1.1"},
        ],
        "unknown": [
            {"vuln_id": "CVE-C", "severity": "5.0", "package": "baz",
             "classify": "err_invalid_version", "version_local": "3.0"},
        ],
    })
    body, has_content, counts = agg.build_body(signals)
    assert has_content is True
    # NOTIFY = fixable(CVE-B) + no-fix(CVE-A) = 2、UNKNOWN = 1。
    assert counts == {"items": 2, "judged": 0, "unknown": 1, "reclass": 0, "likely": 0}
    assert "**NOTIFY: 2 CVE** (🔧 fixable 1 / 🛑 no-fix 1)" in body
    assert "❓ UNKNOWN 1" in body
    # short_target で config 名に縮退して影響ターゲット列に出る。
    assert "host-a" in body
    assert "CVE-A" in body and "CVE-B" in body and "CVE-C" in body


def test_build_body_empty_when_no_signals(tmp_path):
    body, has_content, counts = agg.build_body(str(tmp_path))
    assert has_content is False
    assert counts == {"items": 0, "judged": 0, "unknown": 0, "reclass": 0, "likely": 0}
    assert "現在 NOTIFY / UNKNOWN / reclassified 対象の脆弱性はありません" in body
