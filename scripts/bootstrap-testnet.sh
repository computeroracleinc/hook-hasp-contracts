#!/usr/bin/env bash
set -euo pipefail

# Single-command Stellar Testnet bootstrapping script for Hook-Hasp (Latch) E2E testing.
# - Generates or loads deployer & test signer keypairs
# - Funds accounts via Stellar Testnet Friendbot
# - Builds workspace WASMs and deploys factory-contract + latch-smart-account
# - Outputs deployments/.testnet.env for downstream test scripts

NETWORK="${STELLAR_NETWORK:-testnet}"
RPC_URL="${STELLAR_RPC_URL:-https://soroban-testnet.stellar.org}"
FRIENDBOT_URL="${FRIENDBOT_URL:-https://friendbot.stellar.org}"
ENV_OUT="${ENV_OUT:-deployments/.testnet.env}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Error: '$1' is required but not installed." >&2
    exit 1
  fi
}

require_cmd stellar
require_cmd curl
require_cmd jq

echo "==> Ensuring Stellar Testnet keys exist..."
for alias in latch-deployer latch-signer-a latch-signer-b; do
  if ! stellar keys address "$alias" >/dev/null 2>&1; then
    stellar keys generate "$alias" --network "$NETWORK" >/dev/null
  fi
  PUB=$(stellar keys address "$alias")
  echo "  $alias -> $PUB"
  curl -sf "${FRIENDBOT_URL}?addr=${PUB}" >/dev/null || echo "  (Friendbot already funded or rate-limited for $PUB)"
done

echo "==> Building workspace contracts..."
stellar contract build

DEPLOYER_ADDR=$(stellar keys address latch-deployer)
WASM_DIR="target/wasm32v1-none/release"

echo "==> Uploading LatchSmartAccount WASM..."
ACCOUNT_WASM_HASH=$(stellar contract upload \
  --wasm "${WASM_DIR}/latch_smart_account.wasm" \
  --source latch-deployer \
  --network "$NETWORK")
echo "  ACCOUNT_WASM_HASH=$ACCOUNT_WASM_HASH"

echo "==> Uploading & deploying Ed25519Verifier..."
ED25519_VERIFIER_ID=$(stellar contract deploy \
  --wasm "${WASM_DIR}/ed25519_verifier.wasm" \
  --source latch-deployer \
  --network "$NETWORK")
echo "  ED25519_VERIFIER_ID=$ED25519_VERIFIER_ID"

echo "==> Deploying factory-contract..."
FACTORY_ID=$(stellar contract deploy \
  --wasm "${WASM_DIR}/factory_contract.wasm" \
  --source latch-deployer \
  --network "$NETWORK" \
  -- \
  --account_wasm_hash "$ACCOUNT_WASM_HASH" \
  --ed25519_verifier "$ED25519_VERIFIER_ID")
echo "  FACTORY_ID=$FACTORY_ID"

mkdir -p "$(dirname "$ENV_OUT")"
cat > "$ENV_OUT" <<EOF
STELLAR_NETWORK=$NETWORK
STELLAR_RPC_URL=$RPC_URL
DEPLOYER_ADDRESS=$DEPLOYER_ADDR
SIGNER_A_ADDRESS=$(stellar keys address latch-signer-a)
SIGNER_B_ADDRESS=$(stellar keys address latch-signer-b)
ACCOUNT_WASM_HASH=$ACCOUNT_WASM_HASH
ED25519_VERIFIER_ID=$ED25519_VERIFIER_ID
FACTORY_CONTRACT_ID=$FACTORY_ID
EOF

echo "==> Bootstrap complete. Environment saved to $ENV_OUT"
