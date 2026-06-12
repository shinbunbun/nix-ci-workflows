"""pytest 共通設定。

ci/scripts/ を import パスに追加し、各 vulnxscan モジュールを直接 import できるようにする。
import 時に副作用 (ネットワーク・glob・sys.exit) を持たないのは tracker.py と identity.py のみ
(両者は main(argv) ガードを持つ)。aggregate/delta/summary は module-level で重い処理を走らせるため
ここでは import せず、純粋関数だけを別途 importlib で隔離ロードする (test_script_modules.py 参照)。
"""
import os
import sys

_SCRIPTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)
