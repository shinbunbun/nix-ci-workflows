"""vulnxscan_tracker.py のユニットテスト。

純粋関数 (collect_cves / merge_status / _parse_items) と、opener 差し替えによる
fetch() / main(argv) のネットワーク非依存テスト。production スクリプトは変更しない。
"""
import io
import json

import vulnxscan_tracker as tracker


class _FakeResp:
    """urlopen 互換のレスポンス (context manager + read())。"""

    def __init__(self, payload):
        self._raw = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._raw


def _opener_returning(*payloads):
    """呼び出しごとに payloads を順に返す opener。timeout kwarg を受け取る。"""
    seq = list(payloads)

    def _open(req, timeout=None):
        return _FakeResp(seq.pop(0))

    return _open


# ----------------------------- merge_status -----------------------------
def test_merge_status_prefers_affected_over_notaffected():
    assert tracker.merge_status(["notaffected", "affected"]) == "affected"


def test_merge_status_wontfix_outranks_notaffected():
    assert tracker.merge_status(["notaffected", "wontfix"]) == "wontfix"


def test_merge_status_full_priority_order():
    # affected > wontfix > notaffected > notforus > unknown
    assert tracker.merge_status(["unknown", "notforus", "notaffected", "wontfix", "affected"]) == "affected"
    assert tracker.merge_status(["unknown", "notforus", "notaffected"]) == "notaffected"
    assert tracker.merge_status(["unknown", "notforus"]) == "notforus"


def test_merge_status_unknown_when_empty_or_unrecognized():
    assert tracker.merge_status([]) == "unknown"
    assert tracker.merge_status(["bogus-status"]) == "unknown"


# ----------------------------- collect_cves -----------------------------
def test_collect_cves_filters_dedups_and_sorts(tmp_path):
    csv_path = tmp_path / "triage.csv"
    csv_path.write_text(
        "vuln_id,package\n"
        "CVE-2023-0002,foo\n"
        "CVE-2023-0001,bar\n"
        "CVE-2023-0001,baz\n"      # 重複 (dedup される)
        "GHSA-xxxx-yyyy,qux\n"     # CVE 形式でない (除外)
        " CVE-2024-1234 ,trim\n"   # 前後空白は strip される
        ",empty\n"
    )
    assert tracker.collect_cves(str(csv_path)) == [
        "CVE-2023-0001",
        "CVE-2023-0002",
        "CVE-2024-1234",
    ]


def test_collect_cves_missing_file_returns_empty(tmp_path):
    assert tracker.collect_cves(str(tmp_path / "nope.csv")) == []


# ----------------------------- _parse_items -----------------------------
def test_parse_items_bare_list():
    items, nxt = tracker._parse_items([{"cve": "CVE-2023-0001"}])
    assert items == [{"cve": "CVE-2023-0001"}]
    assert nxt is None


def test_parse_items_paginated_dict():
    items, nxt = tracker._parse_items({"results": [{"cve": "X"}], "next": "http://n/2"})
    assert items == [{"cve": "X"}]
    assert nxt == "http://n/2"


def test_parse_items_unexpected_shape():
    assert tracker._parse_items("garbage") == ([], None)


# ----------------------------- fetch (opener 差し替え) -----------------------------
def test_fetch_merges_multiple_issues_per_cve():
    payload = [
        {"cve": "CVE-2023-0001", "status": "notaffected"},
        {"cve": "CVE-2023-0001", "status": "affected"},  # 同一 CVE の複数 issue
        {"cve": "CVE-2023-0002", "status": "notforus"},
    ]
    result = tracker.fetch(
        ["CVE-2023-0001", "CVE-2023-0002"],
        base_url="https://tracker.example",
        opener=_opener_returning(payload),
    )
    assert result == {"CVE-2023-0001": "affected", "CVE-2023-0002": "notforus"}


def test_fetch_follows_pagination():
    page1 = {"results": [{"cve": "CVE-2023-0001", "status": "affected"}], "next": "https://tracker.example/next"}
    page2 = {"results": [{"cve": "CVE-2023-0002", "status": "wontfix"}], "next": None}
    result = tracker.fetch(
        ["CVE-2023-0001", "CVE-2023-0002"],
        base_url="https://tracker.example",
        opener=_opener_returning(page1, page2),
    )
    assert result == {"CVE-2023-0001": "affected", "CVE-2023-0002": "wontfix"}


def test_fetch_skips_items_missing_cve_or_status():
    payload = [
        {"cve": "CVE-2023-0001"},                 # status 無し → 無視
        {"status": "affected"},                   # cve 無し → 無視
        {"cve": "CVE-2023-0002", "status": "affected"},
    ]
    result = tracker.fetch(["CVE-2023-0002"], opener=_opener_returning(payload))
    assert result == {"CVE-2023-0002": "affected"}


# ----------------------------- main (argv 経路) -----------------------------
def test_main_writes_status_json(tmp_path, monkeypatch):
    csv_path = tmp_path / "triage.csv"
    csv_path.write_text("vuln_id,package\nCVE-2023-0001,foo\n")
    out_path = tmp_path / "tracker.json"

    payload = [{"cve": "CVE-2023-0001", "status": "affected"}]
    monkeypatch.setattr(tracker.urllib.request, "urlopen", _opener_returning(payload))

    rc = tracker.main(["prog", str(csv_path), str(out_path)])
    assert rc == 0
    assert json.loads(out_path.read_text()) == {"CVE-2023-0001": "affected"}


def test_main_writes_empty_on_fetch_failure(tmp_path, monkeypatch):
    csv_path = tmp_path / "triage.csv"
    csv_path.write_text("vuln_id,package\nCVE-2023-0001,foo\n")
    out_path = tmp_path / "tracker.json"

    def _boom(req, timeout=None):
        raise OSError("network down")

    monkeypatch.setattr(tracker.urllib.request, "urlopen", _boom)

    rc = tracker.main(["prog", str(csv_path), str(out_path)])
    # 失敗時も exit 0 + 空 dict (現状維持 = override 無しの安全側)。
    assert rc == 0
    assert json.loads(out_path.read_text()) == {}


def test_main_no_cves_writes_empty_without_network(tmp_path):
    csv_path = tmp_path / "triage.csv"
    csv_path.write_text("vuln_id,package\nGHSA-xxxx,foo\n")  # CVE 無し
    out_path = tmp_path / "tracker.json"
    # opener を差し替えなくても CVE が無いので fetch は呼ばれない。
    rc = tracker.main(["prog", str(csv_path), str(out_path)])
    assert rc == 0
    assert json.loads(out_path.read_text()) == {}
