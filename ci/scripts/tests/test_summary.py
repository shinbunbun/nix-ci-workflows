"""vulnxscan_summary.py の直接 import ユニットテスト (#285 分類分岐)。

summary.py は T55 で main(argv) ガード化され import 時副作用を持たなくなったので、
分類ロジック (classify) / closure グラフ (Closure) / notify payload (build_notify_payload) を
GitHub・CLI 非依存で直接検証できる。CLI スモーク (test_summary_cli.py) は後方互換の確認に残す。

ここでは #285 系の分岐を個別にカバーする:
  - pin 検出 (fixable vs INFO)
  - spot-check (high-sev の repology 非該当)
  - reclassified (Nixpkgs Tracker notaffected/notforus による降格)
  - identity-mismatch (collision 除外) / judged 昇格 / likely-FP 降格
"""
import json

import vulnxscan_summary as summary


def _row(vuln_id, classify, severity="5.0", package="p", version_local="1.0", **extra):
    base = {
        "vuln_id": vuln_id,
        "severity": severity,
        "package": package,
        "classify": classify,
        "version_local": version_local,
        "version_nixpkgs": "",
        "whitelist": "",
    }
    base.update(extra)
    return base


def _classify(rows, closure=None, tracker=None, identity=None):
    closure = closure if closure is not None else summary.Closure()
    buckets, tracker_loaded, identity_loaded = summary.classify(
        rows, closure, tracker or {}, identity or {})
    return buckets, tracker_loaded, identity_loaded


def _vids(items):
    return {r["vuln_id"] for r in items}


# ----------------------------- 基本振り分け -----------------------------
def test_classify_basic_buckets():
    rows = [
        _row("CVE-1", "fix_not_available", severity="9.8"),                      # no-fix
        _row("CVE-2", "err_invalid_version"),                                    # UNKNOWN
        _row("CVE-3", "err_not_vulnerable_based_on_repology", severity="3.0"),   # DROP のみ
        _row("CVE-4", "fix_update_to_version_upstream"),                         # INFO
        _row("CVE-5", "fix_not_available", whitelist="true"),                    # whitelisted
    ]
    buckets, _, _ = _classify(rows)
    assert _vids(buckets["nofix"]) == {"CVE-1"}
    assert _vids(buckets["unknown"]) == {"CVE-2"}
    assert _vids(buckets["drop"]) == {"CVE-3"}
    assert _vids(buckets["info"]) == {"CVE-4"}
    assert _vids(buckets["whitelisted"]) == {"CVE-5"}
    assert buckets["spotcheck"] == []


# ----------------------------- spot-check (#285b) -----------------------------
def test_high_sev_repology_nonmatch_goes_to_spotcheck():
    rows = [
        _row("CVE-HI", "err_not_vulnerable_based_on_repology", severity="9.5"),
        _row("CVE-LO", "err_not_vulnerable_based_on_repology", severity="8.9"),
    ]
    buckets, _, _ = _classify(rows)
    # high-sev (>=9.0) は DROP 維持しつつ spot-check に併載。低 sev は spot-check 外。
    assert _vids(buckets["drop"]) == {"CVE-HI", "CVE-LO"}
    assert _vids(buckets["spotcheck"]) == {"CVE-HI"}


# ----------------------------- pin 検出 (fixable vs INFO) -----------------------------
def test_pin_detection_routes_to_fixable_only_when_pinned():
    rows = [_row("CVE-P", "fix_update_to_version_nixpkgs", package="foo", version_local="1.0")]

    # closure 未 load → pin 検出 OFF → INFO 落ち。
    buckets, _, _ = _classify(rows)
    assert _vids(buckets["info"]) == {"CVE-P"}
    assert buckets["fixable"] == []

    # foo が 2 版存在 = pin → fixable。
    pinned = summary.Closure()
    pinned.closure_versions["foo"] = {"1.0", "2.0"}
    buckets, _, _ = _classify(rows, closure=pinned)
    assert _vids(buckets["fixable"]) == {"CVE-P"}
    assert buckets["info"] == []


def test_closure_is_pinned_threshold():
    c = summary.Closure()
    c.closure_versions["one"] = {"1.0"}
    c.closure_versions["two"] = {"1.0", "2.0"}
    assert c.is_pinned("one") is False
    assert c.is_pinned("two") is True
    assert c.is_pinned("absent") is False


# ----------------------------- reclassified (#285c/#289) -----------------------------
def test_tracker_notaffected_demotes_nofix_to_reclassified():
    rows = [
        _row("CVE-NA", "fix_not_available", severity="9.0"),
        _row("CVE-KEEP", "fix_not_available", severity="8.0"),
        _row("CVE-UK", "err_invalid_version"),
    ]
    tracker = {"CVE-NA": "notaffected", "CVE-UK": "notforus", "CVE-KEEP": "affected"}
    buckets, tracker_loaded, _ = _classify(rows, tracker=tracker)
    assert tracker_loaded is True
    # notaffected/notforus は no-fix/UNKNOWN から reclassified へ降格。
    assert _vids(buckets["reclassified"]) == {"CVE-NA", "CVE-UK"}
    # affected は no-fix に残り、_tracker 注記が付く。
    assert _vids(buckets["nofix"]) == {"CVE-KEEP"}
    assert buckets["nofix"][0]["_tracker"] == "affected"
    assert buckets["unknown"] == []


# ----------------------------- identity: collision / judged / likely-FP (#285/#289) -----------------------------
def test_identity_collision_excluded_judged_promoted_likely_fp_demoted():
    rows = [
        _row("CVE-COL", "err_invalid_version"),                              # UNKNOWN → collision 除外
        _row("CVE-AFF", "err_not_vulnerable_based_on_repology", severity="9.9"),  # spot-check → judged 昇格
        _row("CVE-FP", "fix_not_available", severity="7.0"),                 # no-fix → likely_fp 降格
        _row("CVE-PLAIN", "fix_not_available", severity="6.0"),              # no-fix のまま
    ]
    identity = {
        "CVE-COL": {"verdict": "collision", "nix_repo": "a", "cve_repo": "b"},
        "CVE-AFF": {"verdict": "affected", "cpe": "cpe:x", "range": "<2.0"},
        "CVE-FP": {"verdict": "disputed", "reason": "disputed"},
    }
    buckets, _, identity_loaded = _classify(rows, identity=identity)
    assert identity_loaded is True
    assert _vids(buckets["collision"]) == {"CVE-COL"}
    assert buckets["unknown"] == []           # collision は UNKNOWN から抜ける
    assert _vids(buckets["judged"]) == {"CVE-AFF"}
    assert _vids(buckets["likely_fp"]) == {"CVE-FP"}
    assert _vids(buckets["nofix"]) == {"CVE-PLAIN"}
    # _identity 注記が judged 側に伝播。
    assert buckets["judged"][0]["_identity"]["cpe"] == "cpe:x"


def test_identity_drop_rescued_to_judged_without_double_promotion():
    # spotcheck ⊂ drop。affected の high-sev row が judged に 1 度だけ入る (二重昇格しない)。
    rows = [_row("CVE-D", "err_not_vulnerable_based_on_repology", severity="9.9")]
    identity = {"CVE-D": {"verdict": "affected", "cpe": "cpe:y"}}
    buckets, _, _ = _classify(rows, identity=identity)
    assert _vids(buckets["judged"]) == {"CVE-D"}
    assert len(buckets["judged"]) == 1
    assert buckets["spotcheck"] == []
    assert buckets["drop"] == []


# ----------------------------- build_notify_payload (後方互換) -----------------------------
def test_build_notify_payload_keys_and_findings():
    rows = [
        _row("CVE-NF", "fix_not_available", severity="9.0", package="bar"),
        _row("CVE-UK", "err_invalid_version", package="baz"),
    ]
    closure = summary.Closure()
    buckets, _, _ = _classify(rows, closure=closure)
    payload = summary.build_notify_payload(".#nixosConfigurations.h.config", buckets, closure)

    assert payload["target"] == ".#nixosConfigurations.h.config"
    # findings = NOTIFY (fixable + no-fix)。
    assert {f["vuln_id"] for f in payload["findings"]} == {"CVE-NF"}
    assert {f["vuln_id"] for f in payload["unknown"]} == {"CVE-UK"}
    # 後方互換: 追加バケツキーは全て存在する (古い aggregate は未知キーを無視)。
    for k in ("spotcheck", "reclassified", "judged", "likely_fp", "collision"):
        assert k in payload and payload[k] == []
    # entry/tracker/identity 注記列が finding に付く (closure 未 load なら entry は "")。
    f = payload["findings"][0]
    assert set(f) >= {"vuln_id", "severity", "package", "classify", "entry", "tracker", "identity"}


# ----------------------------- main(argv) スモーク (load_csv 経由) -----------------------------
def test_main_writes_notify_json(tmp_path, capsys):
    csv_path = tmp_path / "v.csv"
    csv_path.write_text(
        "vuln_id,severity,package,classify,version_local,version_nixpkgs,whitelist\n"
        "CVE-X,9.8,foo,fix_not_available,1.0,,\n"
    )
    notify = tmp_path / "notify.json"
    rc = summary.main(["prog", str(csv_path), "tgt", "", str(notify)])
    assert rc == 0
    payload = json.loads(notify.read_text())
    assert payload["target"] == "tgt"
    assert {f["vuln_id"] for f in payload["findings"]} == {"CVE-X"}
    out = capsys.readouterr().out
    assert "**NOTIFY 1**" in out


def test_main_missing_csv_graceful(tmp_path, capsys):
    rc = summary.main(["prog", str(tmp_path / "nope.csv"), "t"])
    assert rc == 0
    assert "出力 CSV が見つかりません" in capsys.readouterr().out
