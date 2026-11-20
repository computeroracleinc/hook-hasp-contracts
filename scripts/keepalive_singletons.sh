#!/usr/bin/env bash
set -euo pipefail

: "${STELLAR_SECRET_KEY:?Set the funded testnet signer in the STELLAR_SECRET_KEY Actions secret}"

readonly NETWORK="${STELLAR_NETWORK:-testnet}"
readonly SOURCE_ACCOUNT="${STELLAR_SOURCE_ACCOUNT:-singleton-ttl-keepalive}"
readonly LEDGERS_TO_EXTEND="${STELLAR_LEDGERS_TO_EXTEND:-518400}"
readonly TARGETS_FILE="${STELLAR_TTL_TARGETS_FILE:-deployments/ttl-targets.json}"

if ! command -v stellar >/dev/null 2>&1; then
    echo "stellar CLI is required" >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "jq is required" >&2
    exit 1
fi
if [[ ! "$LEDGERS_TO_EXTEND" =~ ^[1-9][0-9]*$ ]]; then
    echo "STELLAR_LEDGERS_TO_EXTEND must be a positive integer" >&2
    exit 1
fi
if [[ ! -r "$TARGETS_FILE" ]] || ! jq -e '.contract_ids | type == "array" and length > 0' "$TARGETS_FILE" >/dev/null; then
    echo "TTL target file is missing or has no contract_ids: $TARGETS_FILE" >&2
    exit 1
fi
if ! jq -e '.wasm_hashes | type == "array" and length > 0' "$TARGETS_FILE" >/dev/null; then
    echo "TTL target file has no wasm_hashes: $TARGETS_FILE" >&2
    exit 1
fi

stellar keys add "$SOURCE_ACCOUNT" --overwrite

while IFS= read -r contract_id; do
    if [[ ! "$contract_id" =~ ^C[A-Z2-7]{55}$ ]]; then
        echo "Invalid Stellar contract ID in $TARGETS_FILE: $contract_id" >&2
        exit 1
    fi
    echo "Extending contract instance $contract_id"
    stellar contract extend \
        --id "$contract_id" \
        --ledgers-to-extend "$LEDGERS_TO_EXTEND" \
        --source-account "$SOURCE_ACCOUNT" \
        --network "$NETWORK"
done < <(jq -r '.contract_ids[]' "$TARGETS_FILE")

while IFS= read -r wasm_hash; do
    if [[ ! "$wasm_hash" =~ ^[0-9a-f]{64}$ ]]; then
        echo "Invalid WASM hash in $TARGETS_FILE: $wasm_hash" >&2
        exit 1
    fi
    echo "Extending contract code $wasm_hash"
    stellar contract extend \
        --wasm-hash "$wasm_hash" \
        --ledgers-to-extend "$LEDGERS_TO_EXTEND" \
        --source-account "$SOURCE_ACCOUNT" \
        --network "$NETWORK"
done < <(jq -r '.wasm_hashes[]' "$TARGETS_FILE")
