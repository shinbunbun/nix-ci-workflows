"""pytest 共通設定。

ci/scripts/ を import パスに追加し、各 vulnxscan モジュールを直接 import できるようにする。
import 時に副作用 (ネットワーク・glob・sys.exit) を持たないのは tracker / identity / common /
aggregate / delta (いずれも main(argv) ガード or 純粋モジュール)。summary.py のみ module-level で
重い処理を走らせる script のままなので import せず、CLI として subprocess 実行で検証する
(test_summary_cli.py 参照)。
"""
import os
import sys

_SCRIPTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)
