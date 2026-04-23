#!/usr/bin/env bash
# WireGuard VPN ティアダウンスクリプト
#
# WireGuard インターフェースを削除し、peer-issuer API でリースを解放する。
#
# 環境変数:
#   LEASE_ID, PEER_ISSUER_URL, AUTHENTIK_URL, AUTHENTIK_CLIENT_ID
#   ACTIONS_ID_TOKEN_REQUEST_TOKEN, ACTIONS_ID_TOKEN_REQUEST_URL

set -uo pipefail  # -e は意図的に外している（cleanup は best-effort）

# --- WireGuard インターフェース削除 ---
echo "Removing WireGuard interface..."
if [[ "$RUNNER_OS" == "Linux" ]]; then
  if ip link show wg-ci &>/dev/null; then
    sudo ip link del wg-ci
    echo "WireGuard interface removed (Linux)"
  else
    echo "WireGuard interface not found, skipping removal"
  fi
elif [[ "$RUNNER_OS" == "macOS" ]]; then
  if [[ -f /etc/wireguard/wg-ci.conf ]]; then
    sudo wg-quick down wg-ci || true
    sudo rm -f /etc/wireguard/wg-ci.conf
    echo "WireGuard interface removed (macOS)"
  else
    echo "WireGuard config not found, skipping removal"
  fi
fi

# --- リース解放 ---
if [[ -z "${LEASE_ID:-}" ]]; then
  echo "::warning::No lease ID provided, skipping release"
  exit 0
fi

echo "Releasing lease: $LEASE_ID"

# release_failed は /release の最終的な失敗を Job Summary に記録するヘルパ。
# teardown は best-effort のため exit 0 は維持し、reconciler が保険で回収する。
release_failed() {
  local reason="$1"
  echo "::error::Failed to release lease: $reason"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "## WireGuard lease release failed"
      echo ""
      echo "- Lease ID: \`$LEASE_ID\`"
      echo "- Reason: $reason"
      echo "- Impact: Lease will be swept by peer-issuer reconciler within 60s"
    } >> "$GITHUB_STEP_SUMMARY"
  fi
}

# OIDC トークン取得
if [[ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]]; then
  release_failed "OIDC token not available"
  exit 0
fi

OIDC_TOKEN=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=wg-lease" | jq -r '.value')

if [[ -z "$OIDC_TOKEN" || "$OIDC_TOKEN" == "null" ]]; then
  release_failed "OIDC token empty/null"
  exit 0
fi
echo "::add-mask::$OIDC_TOKEN"

# Authentik トークン交換
HTTP_RESPONSE=$(curl -sS -w "\n%{http_code}" -X POST "${AUTHENTIK_URL}/application/o/token/" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode client_id="$AUTHENTIK_CLIENT_ID" \
  --data-urlencode client_assertion_type='urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
  --data-urlencode client_assertion="$OIDC_TOKEN")

HTTP_CODE=$(echo "$HTTP_RESPONSE" | tail -n1)
RESPONSE=$(echo "$HTTP_RESPONSE" | sed '$d')

if [[ "$HTTP_CODE" -lt 200 || "$HTTP_CODE" -ge 300 ]]; then
  release_failed "Authentik token exchange HTTP $HTTP_CODE"
  exit 0
fi

ACCESS_TOKEN=$(echo "$RESPONSE" | jq -r '.access_token')

if [[ -z "$ACCESS_TOKEN" || "$ACCESS_TOKEN" == "null" ]]; then
  release_failed "Authentik access token empty/null"
  exit 0
fi
echo "::add-mask::$ACCESS_TOKEN"

# リース解放を指数バックオフで最大 3 回まで再送
# 一時的なネットワーク障害や peer-issuer の瞬断で /release が失敗しても、
# 再送で成功すれば ghost peer を防げる。
MAX_RETRY=3
HTTP_CODE=0
for ATTEMPT in $(seq 1 "$MAX_RETRY"); do
  RESPONSE=$(curl -sS -w "\n%{http_code}" -X POST "${PEER_ISSUER_URL}/release" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"lease_id\": \"$LEASE_ID\"}")
  HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
  HTTP_CODE="${HTTP_CODE:-000}"  # set -u と算術評価で空文字エラーを防ぐ
  if [[ "$HTTP_CODE" -ge 200 && "$HTTP_CODE" -lt 300 ]]; then
    echo "Lease released successfully: $LEASE_ID (attempt $ATTEMPT)"
    exit 0
  fi
  echo "::warning::Release attempt $ATTEMPT/$MAX_RETRY failed (HTTP $HTTP_CODE)"
  if [[ "$ATTEMPT" -lt "$MAX_RETRY" ]]; then
    sleep $((2 ** ATTEMPT))
  fi
done

release_failed "/release HTTP $HTTP_CODE after $MAX_RETRY attempts"
exit 0
