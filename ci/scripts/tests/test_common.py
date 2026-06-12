"""vulnxscan_common.py のユニットテスト (共通化した純粋関数・定数)。

sevf / short_target / UNKNOWN_CLASSIFY は summary / identity / aggregate / delta から
重複コピーを排して一元化したもの。ここで一箇所だけ振る舞いを固定する。
"""
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
