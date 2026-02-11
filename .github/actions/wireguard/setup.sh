#!/usr/bin/env bash
# WireGuard VPN セットアップスクリプト
#
# peer-issuer API から動的にリースを取得し、WireGuard VPN 接続を確立する。
# GitHub Actions OIDC トークンで認証を行う。
#
# 環境変数:
#   PEER_ISSUER_URL, TTL_SECONDS, ATTIC_HOST, AUTHENTIK_URL, AUTHENTIK_CLIENT_ID
#   ACTIONS_ID_TOKEN_REQUEST_TOKEN, ACTIONS_ID_TOKEN_REQUEST_URL

set -euo pipefail

# --- WireGuard ツールのインストール ---
echo "Installing WireGuard tools..."
if [[ "$RUNNER_OS" == "Linux" ]]; then
  sudo apt-get update
  sudo apt-get install -y wireguard-tools
elif [[ "$RUNNER_OS" == "macOS" ]]; then
  brew install wireguard-tools wireguard-go
else
  echo "::error::Unsupported OS: $RUNNER_OS"
  exit 1
fi

# --- エフェメラルキーペア生成 ---
echo "Generating ephemeral keypair..."
PRIVATE_KEY=$(wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey)
echo "::add-mask::$PRIVATE_KEY"

# --- GitHub OIDC トークン取得 ---
echo "Getting GitHub OIDC token..."
if [[ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]]; then
  echo "::error::OIDC token not available. Ensure 'permissions: id-token: write' is set."
  exit 1
fi

OIDC_TOKEN=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=wg-lease" | jq -r '.value')

if [[ -z "$OIDC_TOKEN" || "$OIDC_TOKEN" == "null" ]]; then
  echo "::error::Failed to get OIDC token"
  exit 1
fi
echo "::add-mask::$OIDC_TOKEN"

# --- Authentik トークン交換 ---
echo "Exchanging token via Authentik..."
HTTP_RESPONSE=$(curl -sS -w "\n%{http_code}" -X POST "${AUTHENTIK_URL}/application/o/token/" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode client_id="$AUTHENTIK_CLIENT_ID" \
  --data-urlencode client_assertion_type='urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
  --data-urlencode client_assertion="$OIDC_TOKEN")

HTTP_CODE=$(echo "$HTTP_RESPONSE" | tail -n1)
RESPONSE=$(echo "$HTTP_RESPONSE" | sed '$d')

if [[ "$HTTP_CODE" -lt 200 || "$HTTP_CODE" -ge 300 ]]; then
  echo "::error::Authentik token exchange failed (HTTP $HTTP_CODE)"
  echo "Response: $RESPONSE"
  exit 1
fi

ACCESS_TOKEN=$(echo "$RESPONSE" | jq -r '.access_token')

if [[ -z "$ACCESS_TOKEN" || "$ACCESS_TOKEN" == "null" ]]; then
  echo "::error::Failed to get access token from Authentik"
  echo "Response: $RESPONSE"
  exit 1
fi
echo "::add-mask::$ACCESS_TOKEN"
echo "Token exchange successful"

# --- peer-issuer リース取得 ---
echo "Requesting lease from peer-issuer..."
HTTP_RESPONSE=$(curl -sS -w "\n%{http_code}" -X POST "${PEER_ISSUER_URL}/lease" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"client_pubkey\": \"$PUBLIC_KEY\", \"ttl_seconds\": $TTL_SECONDS}")

HTTP_CODE=$(echo "$HTTP_RESPONSE" | tail -n1)
RESPONSE=$(echo "$HTTP_RESPONSE" | sed '$d')

echo "HTTP Status: $HTTP_CODE"

if [[ "$HTTP_CODE" -lt 200 || "$HTTP_CODE" -ge 300 ]]; then
  echo "::error::peer-issuer API returned HTTP $HTTP_CODE"
  exit 1
fi

if ! echo "$RESPONSE" | jq -e . >/dev/null 2>&1; then
  echo "::error::peer-issuer API returned invalid JSON"
  exit 1
fi

LEASE_ID=$(echo "$RESPONSE" | jq -r '.lease_id')
CLIENT_IP=$(echo "$RESPONSE" | jq -r '.client_ip')
SERVER_PUBKEY=$(echo "$RESPONSE" | jq -r '.server_pubkey')
ENDPOINT=$(echo "$RESPONSE" | jq -r '.endpoint')
MTU=$(echo "$RESPONSE" | jq -r '.mtu // 1420')
KEEPALIVE=$(echo "$RESPONSE" | jq -r '.persistent_keepalive // 25')

echo "::add-mask::$SERVER_PUBKEY"
echo "::add-mask::$ENDPOINT"

if [[ -z "$LEASE_ID" || "$LEASE_ID" == "null" ]]; then
  echo "::error::Failed to get lease from peer-issuer"
  exit 1
fi

echo "Lease acquired: $LEASE_ID"
echo "Client IP: $CLIENT_IP"

# --- WireGuard インターフェース設定 ---
echo "Configuring WireGuard interface..."
if [[ "$RUNNER_OS" == "Linux" ]]; then
  sudo ip link add wg-ci type wireguard

  CONF_FILE=$(mktemp)
  cat > "$CONF_FILE" << EOF
[Interface]
PrivateKey = $PRIVATE_KEY

[Peer]
PublicKey = $SERVER_PUBKEY
Endpoint = $ENDPOINT
AllowedIPs = ${ATTIC_HOST}/32
PersistentKeepalive = $KEEPALIVE
EOF

  sudo wg setconf wg-ci "$CONF_FILE"
  rm -f "$CONF_FILE"

  sudo ip addr add "${CLIENT_IP}/32" dev wg-ci
  sudo ip link set wg-ci mtu "$MTU"
  sudo ip link set wg-ci up
  sudo ip route add "${ATTIC_HOST}/32" dev wg-ci

elif [[ "$RUNNER_OS" == "macOS" ]]; then
  sudo mkdir -p /etc/wireguard
  sudo tee /etc/wireguard/wg-ci.conf > /dev/null << EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = ${CLIENT_IP}/32
MTU = $MTU

[Peer]
PublicKey = $SERVER_PUBKEY
Endpoint = $ENDPOINT
AllowedIPs = ${ATTIC_HOST}/32
PersistentKeepalive = $KEEPALIVE
EOF

  sudo chmod 600 /etc/wireguard/wg-ci.conf
  sudo wg-quick up wg-ci
fi

echo "WireGuard interface configured"

# --- 接続確認 ---
echo "Testing connectivity to $ATTIC_HOST..."
if ping -c 3 "$ATTIC_HOST"; then
  echo "Connectivity verified"
else
  echo "::error::Cannot reach $ATTIC_HOST via WireGuard"
  exit 1
fi

echo ""
echo "Testing Attic access (port 8080)..."
if curl -sS --connect-timeout 10 --max-time 15 -o /dev/null -w "HTTP %{http_code} (%{time_total}s)" "http://${ATTIC_HOST}:8080/"; then
  echo ""
  echo "Attic reachable"
else
  echo ""
  echo "::error::Cannot reach Attic at $ATTIC_HOST:8080 via WireGuard"
  exit 1
fi

# --- 結果を出力 ---
echo "LEASE_ID=$LEASE_ID" >> "$GITHUB_OUTPUT_FILE"
echo "CLIENT_IP=$CLIENT_IP" >> "$GITHUB_OUTPUT_FILE"
