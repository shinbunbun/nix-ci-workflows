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

# OIDC トークン取得
if [[ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]]; then
  echo "::warning::OIDC token not available for lease release"
  exit 0
fi

OIDC_TOKEN=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=wg-lease" | jq -r '.value')

if [[ -z "$OIDC_TOKEN" || "$OIDC_TOKEN" == "null" ]]; then
  echo "::warning::Failed to get OIDC token for lease release"
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
  echo "::warning::Authentik token exchange failed (HTTP $HTTP_CODE) for lease release"
  exit 0
fi

ACCESS_TOKEN=$(echo "$RESPONSE" | jq -r '.access_token')

if [[ -z "$ACCESS_TOKEN" || "$ACCESS_TOKEN" == "null" ]]; then
  echo "::warning::Failed to get access token for lease release"
  exit 0
fi
echo "::add-mask::$ACCESS_TOKEN"

# リース解放
RESPONSE=$(curl -sS -w "\n%{http_code}" -X POST "${PEER_ISSUER_URL}/release" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"lease_id\": \"$LEASE_ID\"}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [[ "$HTTP_CODE" -ge 200 && "$HTTP_CODE" -lt 300 ]]; then
  echo "Lease released successfully: $LEASE_ID"
else
  echo "::warning::Failed to release lease (HTTP $HTTP_CODE)"
  echo "Lease will expire automatically via TTL"
fi
