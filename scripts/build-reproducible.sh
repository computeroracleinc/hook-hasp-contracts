#!/usr/bin/env bash
# build-reproducible.sh
# Automates deterministic compilation of Soroban smart contracts in an isolated pinned Docker container
# and verifies bit-for-bit equivalence against committed deployment artifacts.
#
# Usage:
#   ./scripts/build-reproducible.sh [--check-only | --extract]

set -euo pipefail

IMAGE_NAME="latch-contracts-reproducible:v27.1.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CHECK_ONLY=false
EXTRACT=true

for arg in "$@"; do
  case "$arg" in
    --check-only)
      CHECK_ONLY=true
      EXTRACT=false
      ;;
    --extract)
      EXTRACT=true
      ;;
  esac
done

if ! command -v docker &>/dev/null; then
  echo "[-] Error: docker is required to execute reproducible builds."
  echo "    Please install Docker or use a machine with docker daemon available."
  exit 1
fi

echo "============================================================"
echo "Building pinned Docker image for reproducible builds..."
echo "Image: ${IMAGE_NAME}"
echo "============================================================"

docker build -f "${REPO_ROOT}/Dockerfile.reproducible" -t "${IMAGE_NAME}" "${REPO_ROOT}"

if [[ "$CHECK_ONLY" == "true" ]]; then
  echo "[+] Docker image built successfully. Reproducible environment ready."
  exit 0
fi

echo "============================================================"
echo "Compiling contracts inside container..."
echo "============================================================"

CONTAINER_ID=$(docker create "${IMAGE_NAME}")

cleanup() {
  docker rm -f "${CONTAINER_ID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Extracting compiled WASM artifacts to target/wasm32v1-none/release/..."
mkdir -p "${REPO_ROOT}/target/wasm32v1-none/release"
docker cp "${CONTAINER_ID}:/workspace/target/wasm32v1-none/release/." "${REPO_ROOT}/target/wasm32v1-none/release/"

echo "============================================================"
echo "Verifying build outputs against canonical deployment hashes..."
echo "============================================================"

"${REPO_ROOT}/scripts/verify-artifacts.sh" "${REPO_ROOT}/target/wasm32v1-none/release"

echo "[+] Success: All compiled WASM binaries match bit-for-bit!"
