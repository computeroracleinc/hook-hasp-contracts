#!/usr/bin/env bash
# verify-artifacts.sh
# Verifies that compiled WASM artifacts (or committed deployment artifacts) match expected SHA256 checksums bit-for-bit.
#
# Usage:
#   ./scripts/verify-artifacts.sh [--target-dir <path>]
#
# Default target dir: target/wasm32v1-none/release (if it exists) or deployments/artifacts

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

TARGET_DIR="${1:-}"

# Canonical SHA256 checksums for published deployment artifacts (16 production contracts)
declare -A EXPECTED_CHECKSUMS=(
  ["ed25519_verifier"]="7ec21a870fd7aa6458fff6105fb67db526b54187424eb7687c778be9c5e97ade"
  ["factory_contract"]="26c48c109685eab95eade21f146003f2003632aff16fd93fc2c14b0dc62c716c"
  ["fee_forwarder"]="d6fd2e3d7d0dab4dfc35275e5d0b07e01b756966b6650f94a876bb557793f776"
  ["multi_token_spending_limit_policy"]="6c481faba9a62bb12521f3fc1617e1d059538eed55ec5461473e426c407a71f2"
  ["p256_verifier"]="9ab31b9466e9c88cfe091e111b7eef17653c884ac6c73afb6744ca525b64abb1"
  ["parameter_scoped_policy"]="315f3b856da197163b7ec8e7d6ed5488f4f9576eba4b120b229b9a810443a03e"
  ["recipient_allowlist_policy"]="c93acfe6b7a250df24d3de7f84d4a15b3c6cf5aaef99b802649e27565cc158fc"
  ["secp256k1_verifier"]="9b65ede149796ec9bcc4669ed7d8e11e8675c734f0026f73b829e3c7ae1d1478"
  ["session_policy"]="a3c840f2e181424abca2153ca61ea48ce35f7ecd162acd88b325e2e5b3dd8132"
  ["smart_account"]="85f4e1d77f4f9efab5e8b3effb6d10719951d2355337ba459bc9593fb36fae18"
  ["spending_limit_policy"]="dfd3d2e85678f5263bb79367c66b619891656cac674fdef6209bacd4efe4b66e"
  ["threshold_policy"]="668a18b9613a01fdb53cf7f56c3613cf9e011eddb43e909a15b21a3155868f24"
  ["timelock_vault"]="07e04c1a0fdd0a1a9f2d99742608df835f4bb7813a3879be5f0168f7ae041f34"
  ["vesting_schedule"]="7c6bda5c5bd3ed11296ab5a39477b6f727c317a85966c2de4476d05bfce55b67"
  ["webauthn_verifier"]="dc4a5393eb111f5d89848fdbc4c79ef914df1a70d819d62d6e1f4168f9f8f6c8"
  ["weighted_threshold_policy"]="7b967b02248534442fb9da2ebbb844310429df1449d4463e288a989ac883a676"
)

echo "============================================================"
echo "Verifying WASM Build Outputs against Canonical Checksums"
echo "============================================================"

PASS_COUNT=0
FAIL_COUNT=0
MISSING_COUNT=0

# Check either target build directory or deployments/artifacts directory
MODE="build"
if [[ -n "$TARGET_DIR" && -d "$TARGET_DIR" ]]; then
  SEARCH_DIR="$TARGET_DIR"
elif [[ -d "${REPO_ROOT}/target/wasm32v1-none/release" ]]; then
  SEARCH_DIR="${REPO_ROOT}/target/wasm32v1-none/release"
else
  MODE="deployment"
  SEARCH_DIR="${REPO_ROOT}/deployments/artifacts"
fi

echo "Mode: $MODE (checking in $SEARCH_DIR)"
echo ""

for contract in "${!EXPECTED_CHECKSUMS[@]}"; do
  expected_hash="${EXPECTED_CHECKSUMS[$contract]}"
  
  wasm_path=""
  if [[ "$MODE" == "deployment" ]]; then
    candidate="${SEARCH_DIR}/${contract}-${expected_hash}/${contract}.wasm"
    if [[ -f "$candidate" ]]; then
      wasm_path="$candidate"
    fi
  else
    candidate="${SEARCH_DIR}/${contract}.wasm"
    if [[ -f "$candidate" ]]; then
      wasm_path="$candidate"
    fi
  fi

  if [[ -z "$wasm_path" || ! -f "$wasm_path" ]]; then
    echo "[-] MISSING: ${contract}.wasm not found in ${SEARCH_DIR}"
    MISSING_COUNT=$((MISSING_COUNT + 1))
    continue
  fi

  actual_hash="$(sha256sum "$wasm_path" | awk '{print $1}')"

  if [[ "$actual_hash" == "$expected_hash" ]]; then
    echo "[+] MATCH:   ${contract}.wasm (${actual_hash})"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "[!] MISMATCH: ${contract}.wasm"
    echo "    Expected: ${expected_hash}"
    echo "    Actual:   ${actual_hash}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
done

echo ""
echo "============================================================"
echo "Verification Summary: ${PASS_COUNT} passed, ${FAIL_COUNT} failed, ${MISSING_COUNT} missing"
echo "============================================================"

if [[ $FAIL_COUNT -gt 0 || $MISSING_COUNT -gt 0 ]]; then
  exit 1
fi

exit 0
