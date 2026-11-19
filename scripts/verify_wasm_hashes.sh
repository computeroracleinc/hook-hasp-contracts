#!/usr/bin/env bash
# Verify that locally built contract WASM binaries match the archived
# deployment artifacts in deployments/artifacts/ by comparing SHA256 hashes.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACTS_DIR="${REPO_ROOT}/deployments/artifacts"

NO_BUILD=false
TARGET_CONTRACT=""

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Verify that locally built WASM binaries match deployments/artifacts/.

Options:
  --no-build           Skip building contracts; use existing target/ artifacts
  --contract <name>    Verify only the specified contract (e.g. smart_account)
  -h, --help           Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build)
      NO_BUILD=true
      shift
      ;;
    --contract)
      if [[ $# -lt 2 ]]; then
        echo "Error: --contract requires a value" >&2
        exit 1
      fi
      TARGET_CONTRACT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Error: Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    echo "Error: Neither sha256sum nor shasum found" >&2
    exit 1
  fi
}

find_local_wasm() {
  local contract_name="$1"
  local candidates=(
    "${REPO_ROOT}/target/wasm32v1-none/release/${contract_name}.optimized.wasm"
    "${REPO_ROOT}/target/wasm32v1-none/release/${contract_name}.wasm"
    "${REPO_ROOT}/target/wasm32-unknown-unknown/release/${contract_name}.optimized.wasm"
    "${REPO_ROOT}/target/wasm32-unknown-unknown/release/${contract_name}.wasm"
  )
  for candidate in "${candidates[@]}"; do
    if [[ -f "$candidate" ]]; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

if [[ ! -d "$ARTIFACTS_DIR" ]]; then
  echo "Error: Artifacts directory not found: $ARTIFACTS_DIR" >&2
  exit 1
fi

if [[ "$NO_BUILD" == false ]]; then
  echo "Building workspace contracts..."
  if command -v stellar >/dev/null 2>&1; then
    (cd "$REPO_ROOT" && stellar contract build --optimize)
  elif command -v cargo >/dev/null 2>&1; then
    (cd "$REPO_ROOT" && cargo build --target wasm32v1-none --release)
  else
    echo "Error: Neither stellar CLI nor cargo found in PATH" >&2
    exit 1
  fi
fi

passed=0
failed=0
checked=0

for artifact_dir in "${ARTIFACTS_DIR}"/*/; do
  [[ -d "$artifact_dir" ]] || continue

  dir_name="$(basename "$artifact_dir")"
  contract_name="${dir_name%-*}"
  expected_hash="${dir_name##*-}"

  if [[ -n "$TARGET_CONTRACT" && "$contract_name" != "$TARGET_CONTRACT" ]]; then
    continue
  fi

  checked=$((checked + 1))
  artifact_wasm="${artifact_dir}${contract_name}.wasm"

  if [[ ! -f "$artifact_wasm" ]]; then
    echo "[FAIL] ${contract_name}: missing artifact file ${artifact_wasm}"
    failed=$((failed + 1))
    continue
  fi

  artifact_hash="$(sha256_file "$artifact_wasm")"
  if [[ "$artifact_hash" != "$expected_hash" ]]; then
    echo "[FAIL] ${contract_name}: artifact hash mismatch (dir=${expected_hash}, file=${artifact_hash})"
    failed=$((failed + 1))
    continue
  fi

  if ! local_wasm="$(find_local_wasm "$contract_name")"; then
    echo "[FAIL] ${contract_name}: local build not found in target/"
    failed=$((failed + 1))
    continue
  fi

  local_hash="$(sha256_file "$local_wasm")"
  if [[ "$local_hash" == "$expected_hash" ]]; then
    echo "[PASS] ${contract_name}: ${local_hash}"
    passed=$((passed + 1))
  else
    echo "[FAIL] ${contract_name}: hash mismatch"
    echo "       expected: ${expected_hash}"
    echo "       actual:   ${local_hash} (${local_wasm})"
    failed=$((failed + 1))
  fi
done

echo ""
echo "Summary: ${passed}/${checked} passed, ${failed} failed"

if [[ "$checked" -eq 0 ]]; then
  echo "Error: No matching artifacts found to verify" >&2
  exit 1
fi

if [[ "$failed" -gt 0 ]]; then
  exit 1
fi
