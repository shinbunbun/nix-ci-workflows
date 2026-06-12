"""pytest 共通設定。

ci/scripts/ を import パスに追加し、各 vulnxscan モジュールを直接 import できるようにする。
全 5 スクリプト (tracker / identity / common / aggregate / delta / summary) が main(argv) ガード化
され import 時に副作用 (ネットワーク・glob・sys.exit) を持たない。summary.py は T55 で main(argv)
化したので直接 import して分類分岐をユニットテストできる (test_summary.py)。CLI スモーク
(subprocess 実行) も後方互換確認のため残してある (test_summary_cli.py)。
"""
import os
import sys

_SCRIPTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)
