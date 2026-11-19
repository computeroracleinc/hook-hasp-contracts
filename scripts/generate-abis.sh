#!/usr/bin/env bash
set -euo pipefail

# Extracts JSON ABI schemas for all compiled workspace WASM contracts using
# `stellar contract inspect` and saves them into deployments/abi/.

WASM_DIR="${WASM_DIR:-target/wasm32v1-none/release}"
ABI_DIR="${ABI_DIR:-deployments/abi}"

mkdir -p "$ABI_DIR"

if ! command -v stellar >/dev/null 2>&1; then
  echo "Error: stellar CLI is required." >&2
  exit 1
fi

for wasm in "$WASM_DIR"/*.wasm; do
  [ -e "$wasm" ] || continue
  base=$(basename "$wasm" .wasm)
  out="$ABI_DIR/${base}.abi.json"
  echo "Generating ABI schema: $out"
  stellar contract inspect --wasm "$wasm" --output json > "$out"
done

echo "ABI generation complete in $ABI_DIR"
