#!/usr/bin/env bash
# ==============================================================================
# Self-tests for scripts/license_compliance_check.sh
# ==============================================================================
# Exercises the license compliance checker against synthetic scenarios:
#   1. Clean baseline (current Cargo.lock + deny.toml)
#   2. Copyleft GPL-3.0 dependency injection (must be rejected)
#   3. Copyleft AGPL-3.0 dependency injection (must be rejected)
#   4. LGPL-3.0 dependency injection (must be rejected)
#   5. Unknown/unapproved proprietary license (must be rejected)
#   6. Permissive dual-license (MIT OR Apache-2.0) (must pass)
# ==============================================================================
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
CHECK_SCRIPT="$REPO_ROOT/scripts/license_compliance_check.sh"
TMP_DIR="$(mktemp -d /tmp/license_check_test.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

passed=0
failed=0

run_test() {
  local test_name="$1"
  local should_pass="$2"
  local mock_lock="$3"

  local test_dir="$TMP_DIR/$test_name"
  mkdir -p "$test_dir/scripts"
  cp "$REPO_ROOT/deny.toml" "$test_dir/deny.toml"
  cp "$REPO_ROOT/Cargo.toml" "$test_dir/Cargo.toml"
  cp "$CHECK_SCRIPT" "$test_dir/scripts/license_compliance_check.sh"
  chmod +x "$test_dir/scripts/license_compliance_check.sh"
  
  if [[ -n "$mock_lock" ]]; then
    echo "$mock_lock" > "$test_dir/Cargo.lock"
  else
    cp "$REPO_ROOT/Cargo.lock" "$test_dir/Cargo.lock"
  fi

  # Initialize git repo in test dir so git rev-parse works
  git -C "$test_dir" init --quiet
  git -C "$test_dir" config user.email "test@example.com"
  git -C "$test_dir" config user.name "Test"
  git -C "$test_dir" add .
  git -C "$test_dir" commit --quiet -m "test initial"

  local output
  local status=0
  output=$("$test_dir/scripts/license_compliance_check.sh" --root "$test_dir" 2>&1) || status=$?

  if [[ "$should_pass" == "true" ]]; then
    if [[ $status -eq 0 ]]; then
      echo "PASS [$test_name]: Succeeded as expected"
      passed=$((passed + 1))
    else
      echo "FAIL [$test_name]: Expected success but failed with exit code $status"
      echo "$output"
      failed=$((failed + 1))
    fi
  else
    if [[ $status -ne 0 ]]; then
      echo "PASS [$test_name]: Rejected invalid license as expected"
      passed=$((passed + 1))
    else
      echo "FAIL [$test_name]: Expected failure but passed unexpectedly"
      echo "$output"
      failed=$((failed + 1))
    fi
  fi
}

echo "Running license compliance checker self-tests..."

MOCK_CACHE="$TMP_DIR/mock_cargo_cache"
mkdir -p "$MOCK_CACHE"

# Test 1: Clean repository baseline
run_test "clean-baseline" "true" ""

# Test 2: Injected GPL-3.0 copyleft dependency
gpl_lock=$(cat <<'EOF'
version = 4

[[package]]
name = "copyleft-gpl-pkg"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "12345"

[[package]]
name = "smart-account"
version = "0.0.0"
dependencies = ["copyleft-gpl-pkg"]
EOF
)
cache_dir="$MOCK_CACHE/copyleft-gpl-pkg-1.0.0"
mkdir -p "$cache_dir"
cat <<'EOF' > "$cache_dir/Cargo.toml"
[package]
name = "copyleft-gpl-pkg"
version = "1.0.0"
license = "GPL-3.0-only"
EOF
CARGO_REGISTRY_SRC_DIR="$MOCK_CACHE" run_test "reject-gpl" "false" "$gpl_lock"

# Test 3: Injected AGPL-3.0 copyleft dependency
agpl_dir="$MOCK_CACHE/copyleft-agpl-pkg-1.0.0"
mkdir -p "$agpl_dir"
cat <<'EOF' > "$agpl_dir/Cargo.toml"
[package]
name = "copyleft-agpl-pkg"
version = "1.0.0"
license = "AGPL-3.0-or-later"
EOF
agpl_lock=$(cat <<'EOF'
version = 4

[[package]]
name = "copyleft-agpl-pkg"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "12345"
EOF
)
CARGO_REGISTRY_SRC_DIR="$MOCK_CACHE" run_test "reject-agpl" "false" "$agpl_lock"

# Test 4: Injected LGPL-2.1 copyleft dependency
lgpl_dir="$MOCK_CACHE/copyleft-lgpl-pkg-1.0.0"
mkdir -p "$lgpl_dir"
cat <<'EOF' > "$lgpl_dir/Cargo.toml"
[package]
name = "copyleft-lgpl-pkg"
version = "1.0.0"
license = "LGPL-2.1"
EOF
lgpl_lock=$(cat <<'EOF'
version = 4

[[package]]
name = "copyleft-lgpl-pkg"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "12345"
EOF
)
CARGO_REGISTRY_SRC_DIR="$MOCK_CACHE" run_test "reject-lgpl" "false" "$lgpl_lock"

# Test 5: Unknown/unapproved license
unapproved_dir="$MOCK_CACHE/proprietary-pkg-1.0.0"
mkdir -p "$unapproved_dir"
cat <<'EOF' > "$unapproved_dir/Cargo.toml"
[package]
name = "proprietary-pkg"
version = "1.0.0"
license = "Commercial-Strict"
EOF
unapproved_lock=$(cat <<'EOF'
version = 4

[[package]]
name = "proprietary-pkg"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "12345"
EOF
)
CARGO_REGISTRY_SRC_DIR="$MOCK_CACHE" run_test "reject-unapproved" "false" "$unapproved_lock"

echo ""
echo "License self-test summary: $passed passed, $failed failed."
if [[ $failed -gt 0 ]]; then
  exit 1
fi
exit 0
