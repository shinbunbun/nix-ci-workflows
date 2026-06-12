#!/usr/bin/env python3
"""vulnxscan スクリプト群で共有する小さな純粋関数・定数。

summary / identity / aggregate / delta に重複コピーされていた sevf() / short_target() /
UNKNOWN_CLASSIFY を一元化し、分類ロジック変更時の同期ミスを防ぐ。
scan-vulnerabilities.yaml は各スクリプトを ci/scripts/ から実行するため、同一ディレクトリの
このモジュールを `from vulnxscan_common import ...` でそのまま import できる (sys.path 追加不要)。
"""
import json
import re
import urllib.error
import urllib.request

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


def ok(status):
    """GitHub API レスポンスが成功 (2xx) か。"""
    return 200 <= status < 300


def make_requester(token, api):
    """GitHub REST API 呼び出しクロージャ req(method, path, payload=None) を返す。

    aggregate (Issue 起票) と delta (PR コメント) で byte-identical だった req() を一元化する。
    挙動は両者と完全等価:
      - path が http で始まれば絶対 URL、そうでなければ `{api}{path}` に解決
      - Authorization: Bearer / Accept: application/vnd.github+json /
        X-GitHub-Api-Version: 2022-11-28 を付与、payload 有り時のみ Content-Type
      - 戻り値は (status, parsed_json_or_None)。本文が空なら None、HTTPError は
        (ex.code, None) として返す (呼び出し側が status で分岐するため例外を投げない)。
    """

    def req(method, path, payload=None):
        url = path if path.startswith("http") else f"{api}{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        r = urllib.request.Request(url, data=data, method=method)
        r.add_header("Authorization", f"Bearer {token}")
        r.add_header("Accept", "application/vnd.github+json")
        r.add_header("X-GitHub-Api-Version", "2022-11-28")
        if data:
            r.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(r) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as ex:
            return ex.code, None

    return req
