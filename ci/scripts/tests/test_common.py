"""vulnxscan_common.py のユニットテスト (共通化した純粋関数・定数)。

sevf / short_target / UNKNOWN_CLASSIFY は summary / identity / aggregate / delta から
重複コピーを排して一元化したもの。ここで一箇所だけ振る舞いを固定する。
make_requester / ok は aggregate (Issue 起票) と delta (PR コメント) で byte-identical だった
GitHub API クロージャを共通化したもの (T55)。
"""
import io
import json
import urllib.error

import vulnxscan_common as common


# ----------------------------- sevf -----------------------------
def test_sevf_parses_numeric_strings():
    assert common.sevf("9.8") == 9.8
    assert common.sevf("0") == 0.0
    assert common.sevf(7.5) == 7.5


def test_sevf_falls_back_to_zero_on_garbage():
    assert common.sevf("") == 0.0
    assert common.sevf(None) == 0.0
    assert common.sevf("n/a") == 0.0


# ----------------------------- short_target -----------------------------
def test_short_target_extracts_nixos_config_name():
    assert common.short_target(".#nixosConfigurations.nixos-desktop.config.system") == "nixos-desktop"


def test_short_target_extracts_darwin_config_name():
    assert common.short_target(".#darwinConfigurations.macbook.system") == "macbook"


def test_short_target_passthrough_when_no_match():
    assert common.short_target("homeMachine") == "homeMachine"
    assert common.short_target("") == ""


# ----------------------------- UNKNOWN_CLASSIFY -----------------------------
def test_unknown_classify_membership():
    assert "err_missing_repology_version" in common.UNKNOWN_CLASSIFY
    assert "err_invalid_version" in common.UNKNOWN_CLASSIFY
    # 非該当 (DROP) / fixable は UNKNOWN ではない。
    assert "err_not_vulnerable_based_on_repology" not in common.UNKNOWN_CLASSIFY
    assert "fix_not_available" not in common.UNKNOWN_CLASSIFY
    assert common.UNKNOWN_CLASSIFY == {"err_missing_repology_version", "err_invalid_version"}


def test_identity_shares_the_same_constant():
    """identity.py が common と同一オブジェクトを import していること
    (旧「summary.py と一致させること」手動同期コメントを廃した代わりの回帰防止)。
    summary.py は module-level で副作用を持つ script なので import せず CLI 経由で検証する
    (test_summary_cli.py 参照)。"""
    import vulnxscan_identity as ident

    assert ident.UNKNOWN_CLASSIFY is common.UNKNOWN_CLASSIFY
    assert ident.sevf is common.sevf


# ----------------------------- ok -----------------------------
def test_ok_accepts_2xx_only():
    assert common.ok(200) is True
    assert common.ok(201) is True
    assert common.ok(299) is True
    assert common.ok(199) is False
    assert common.ok(300) is False
    assert common.ok(404) is False
    assert common.ok(500) is False


# ----------------------------- make_requester -----------------------------
class _FakeResp:
    def __init__(self, status, raw):
        self.status = status
        self._raw = raw

    def read(self):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_make_requester_sets_headers_and_parses_json(monkeypatch):
    captured = {}

    def fake_urlopen(req):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["headers"] = dict(req.header_items())
        captured["data"] = req.data
        return _FakeResp(200, json.dumps({"id": 7}).encode())

    monkeypatch.setattr(common.urllib.request, "urlopen", fake_urlopen)
    req = common.make_requester("tok", "https://api.example.com")

    # 相対 path は api を前置、payload あり時は JSON body + 必須ヘッダ。
    status, body = req("POST", "/repos/o/r/issues", {"title": "x"})
    assert (status, body) == (200, {"id": 7})
    assert captured["url"] == "https://api.example.com/repos/o/r/issues"
    assert captured["method"] == "POST"
    # urllib は header 名を Title-Case で保持する。
    assert captured["headers"]["Authorization"] == "Bearer tok"
    assert captured["headers"]["Accept"] == "application/vnd.github+json"
    assert captured["headers"]["X-github-api-version"] == "2022-11-28"
    assert captured["headers"]["Content-type"] == "application/json"
    assert captured["data"] == json.dumps({"title": "x"}).encode()


def test_make_requester_absolute_url_and_no_payload(monkeypatch):
    captured = {}

    def fake_urlopen(req):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        captured["data"] = req.data
        return _FakeResp(204, b"")

    monkeypatch.setattr(common.urllib.request, "urlopen", fake_urlopen)
    req = common.make_requester("tok", "https://api.example.com")

    # http で始まる path は絶対 URL として尊重。本文空なら parsed は None。
    status, body = req("GET", "https://other.example.com/x")
    assert (status, body) == (204, None)
    assert captured["url"] == "https://other.example.com/x"
    # payload 無しなら Content-Type を付けない。
    assert "Content-type" not in captured["headers"]
    assert captured["data"] is None


def test_make_requester_httperror_returns_code_and_none(monkeypatch):
    def fake_urlopen(req):
        raise urllib.error.HTTPError(req.full_url, 404, "nf", hdrs=None, fp=io.BytesIO(b""))

    monkeypatch.setattr(common.urllib.request, "urlopen", fake_urlopen)
    req = common.make_requester("tok", "https://api.example.com")

    # HTTPError は例外を投げず (code, None) を返す (呼び出し側が status で分岐)。
    assert req("GET", "/repos/o/r/labels/x") == (404, None)
