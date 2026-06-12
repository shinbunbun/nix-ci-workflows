"""vulnxscan_summary.py の CLI スモークテスト (#285 分類ロジック)。

summary.py は module-level で重い処理 (CSV 読み込み・分類・markdown 出力) を走らせる
script 型なので、純粋関数を隔離 import できない。代わりに documented な CLI
(`summary.py <csv> <target> ... <notify_json>`) を subprocess で実行し、
小さな CSV fixture に対する分類結果 (markdown サマリ + notify.json の各バケツ) を検証する。

これにより UNKNOWN_CLASSIFY / fix_not_available / fix_update_to_version_nixpkgs /
err_not_vulnerable_based_on_repology / whitelist の振り分けが production スクリプトを
変更せずに end-to-end でカバーされる。
"""
import json
import os
import subprocess
import sys

_SCRIPTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SUMMARY = os.path.join(_SCRIPTS_DIR, "vulnxscan_summary.py")

# 各 classify を 1 件ずつ含む最小 triage CSV。closure/tracker/identity は付けない
# (= pin 検出 OFF、tracker OFF、identity OFF) ので分類は CSV の classify と severity のみで決まる。
_CSV = (
    "vuln_id,severity,package,classify,version_local,version_nixpkgs,whitelist\n"
    "CVE-2023-0001,7.5,foo,fix_update_to_version_nixpkgs,1.0,1.1,\n"   # → INFO (pin 検出 OFF)
    "CVE-2023-0002,9.8,bar,fix_not_available,2.0,,\n"                  # → NOTIFY / no-fix
    "CVE-2023-0003,5.0,baz,err_invalid_version,3.0,,\n"               # → UNKNOWN
    "CVE-2023-0004,9.5,qux,err_not_vulnerable_based_on_repology,4.0,,\n"  # → DROP + spot-check (high-sev)
    "CVE-2023-0005,3.0,quux,err_not_vulnerable_based_on_repology,5.0,,\n" # → DROP (低 sev、spot-check 外)
    "CVE-2023-0006,8.0,wl,fix_not_available,6.0,,true\n"             # → whitelisted (除外)
)


def _run_summary(tmp_path):
    csv_path = tmp_path / "vulns.triage.csv"
    csv_path.write_text(_CSV)
    notify_path = tmp_path / "notify.json"
    # 引数: csv, target, closure(空), notify_json, roots(空), tracker(空), identity(空)
    proc = subprocess.run(
        [sys.executable, _SUMMARY, str(csv_path), "testtarget", "", str(notify_path)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout, json.loads(notify_path.read_text())


def test_summary_counts_line(tmp_path):
    stdout, _ = _run_summary(tmp_path)
    # 検出件数: 6 CVE / 6 packages
    assert "- **検出**: 6 CVE / 6 packages" in stdout
    # NOTIFY = fixable 0 + no-fix 1 (CVE-0002)。fixable 候補 (CVE-0001) は pin 検出 OFF で INFO 落ち。
    assert "**NOTIFY 1**" in stdout
    assert "🛑 no-fix 1" in stdout
    # UNKNOWN 1 (CVE-0003)
    assert "❓ UNKNOWN 1" in stdout
    # whitelisted 1 (CVE-0006)
    assert "whitelisted 1" in stdout


def test_summary_notify_json_buckets(tmp_path):
    _, payload = _run_summary(tmp_path)
    assert payload["target"] == "testtarget"

    def _vids(bucket):
        return {f["vuln_id"] for f in payload[bucket]}

    # NOTIFY (findings) = no-fix の CVE-0002 のみ。
    assert _vids("findings") == {"CVE-2023-0002"}
    # UNKNOWN = err_invalid_version の CVE-0003。
    assert _vids("unknown") == {"CVE-2023-0003"}
    # spotcheck = high-sev (>=9 既定) の repology 非該当 CVE-0004。低 sev CVE-0005 は入らない。
    assert _vids("spotcheck") == {"CVE-2023-0004"}
    # tracker/identity 未指定なので judged/likely_fp/reclassified/collision は空。
    assert payload["judged"] == []
    assert payload["likely_fp"] == []
    assert payload["reclassified"] == []
    assert payload["collision"] == []


def test_summary_missing_csv_is_graceful(tmp_path):
    missing = tmp_path / "nope.csv"
    proc = subprocess.run(
        [sys.executable, _SUMMARY, str(missing), "t"],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "出力 CSV が見つかりません" in proc.stdout
