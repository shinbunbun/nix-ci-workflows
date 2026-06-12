#!/usr/bin/env python3
"""vulnxscan スクリプト群で共有する小さな純粋関数・定数。

summary / identity / aggregate / delta に重複コピーされていた sevf() / short_target() /
UNKNOWN_CLASSIFY を一元化し、分類ロジック変更時の同期ミスを防ぐ。
scan-vulnerabilities.yaml は各スクリプトを ci/scripts/ から実行するため、同一ディレクトリの
このモジュールを `from vulnxscan_common import ...` でそのまま import できる (sys.path 追加不要)。
"""
import re

# 判定不能 (repology にデータ無し / 版解析失敗)。safe ではないので ❓UNKNOWN として
# surface する (#285a)。err_not_vulnerable_based_on_repology は repology が明示的に
# 「非該当」と返したものなので DROP のままだが、high-sev は spot-check で可視化 (#285b)。
UNKNOWN_CLASSIFY = {
    "err_missing_repology_version",
    "err_invalid_version",
}


def sevf(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def short_target(t):
    """'.#nixosConfigurations.nixos-desktop.config...' -> 'nixos-desktop' (表示短縮)。"""
    m = re.search(r"(?:nixos|darwin)Configurations\.([^.]+)", t)
    return m.group(1) if m else t
