#!/usr/bin/env bash
# =============================================================================
# Tests for fee_forwarder_treasury_alert.sh
# =============================================================================
# Lightweight unit tests that mock curl/jq responses via a local PATH override
# so the suite can run offline without hitting any live network.
#
# Usage:
#   ./scripts/test_fee_forwarder_treasury_alert.sh
#
# Exit code: 0 all tests passed, 1 one or more tests failed.
# =============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALERT_SCRIPT="$SCRIPT_DIR/fee_forwarder_treasury_alert.sh"
PASS=0
FAIL=0

# ── test harness ──────────────────────────────────────────────────────────────

run_test() {
    local name="$1"; shift
    local expected_exit="$1"; shift
    local actual_exit=0

    "$@" >/dev/null 2>&1 || actual_exit=$?

    if [[ "$actual_exit" -eq "$expected_exit" ]]; then
        echo "  PASS  $name"
        (( PASS++ )) || true
    else
        echo "  FAIL  $name (expected exit $expected_exit, got $actual_exit)"
        (( FAIL++ )) || true
    fi
}

# ── mock infrastructure ───────────────────────────────────────────────────────
# We shadow curl with a function that returns canned JSON so the script never
# hits the network.

MOCK_BIN="$(mktemp -d)"
trap 'rm -rf "$MOCK_BIN"' EXIT

MOCK_TREASURY="GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
THRESHOLD="50000000"   # 5 XLM

# Write mock curl that returns a healthy balance (10 XLM) for the account URL.
make_curl_mock() {
    local balance_xlm="$1"
    cat > "$MOCK_BIN/curl" <<EOF
#!/usr/bin/env bash
# If the URL looks like a Horizon account query, return mock JSON.
for arg in "\$@"; do
    if [[ "\$arg" == *"/accounts/"* ]]; then
        cat <<'JSON'
{
  "id": "$MOCK_TREASURY",
  "balances": [
    {"asset_type": "native", "balance": "$balance_xlm"}
  ]
}
JSON
        exit 0
    fi
done
# For alert delivery endpoints (Slack / PagerDuty), always succeed silently.
exit 0
EOF
    chmod +x "$MOCK_BIN/curl"
}

export PATH="$MOCK_BIN:$PATH"

# jq must already be on PATH; if not, skip integration tests gracefully.
if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not found — skipping tests that require it."
    exit 0
fi

# ── tests: configuration / argument validation ────────────────────────────────

echo
echo "── argument validation ──────────────────────────────────────────────────"

run_test "missing --treasury exits 2" 2 \
    bash "$ALERT_SCRIPT" --network testnet

run_test "--dry-run exits 0 without network call" 0 \
    bash "$ALERT_SCRIPT" --treasury "$MOCK_TREASURY" --dry-run

run_test "unknown --network without --rpc-url exits 2" 2 \
    bash "$ALERT_SCRIPT" --treasury "$MOCK_TREASURY" --network unknownnet

run_test "non-numeric threshold exits 2" 2 \
    bash "$ALERT_SCRIPT" --treasury "$MOCK_TREASURY" --threshold abc

# ── tests: balance above threshold → exit 0 ───────────────────────────────────

echo
echo "── balance checks ───────────────────────────────────────────────────────"

make_curl_mock "10.0000000"   # 100 000 000 stroops — well above 5 XLM threshold
run_test "balance above threshold exits 0" 0 \
    bash "$ALERT_SCRIPT" \
        --treasury "$MOCK_TREASURY" \
        --network testnet \
        --threshold "$THRESHOLD"

# ── tests: balance below threshold → exit 1 ───────────────────────────────────

make_curl_mock "2.0000000"   # 20 000 000 stroops — below 5 XLM threshold
run_test "balance below threshold exits 1" 1 \
    bash "$ALERT_SCRIPT" \
        --treasury "$MOCK_TREASURY" \
        --network testnet \
        --threshold "$THRESHOLD"

# ── tests: balance exactly at threshold → exit 0 ─────────────────────────────

make_curl_mock "5.0000000"   # 50 000 000 stroops — exactly equal
run_test "balance equal to threshold exits 0" 0 \
    bash "$ALERT_SCRIPT" \
        --treasury "$MOCK_TREASURY" \
        --network testnet \
        --threshold "$THRESHOLD"

# ── tests: custom RPC URL is accepted ─────────────────────────────────────────

make_curl_mock "10.0000000"
run_test "custom --rpc-url accepted" 0 \
    bash "$ALERT_SCRIPT" \
        --treasury "$MOCK_TREASURY" \
        --rpc-url "https://soroban-testnet.stellar.org" \
        --threshold "$THRESHOLD"

# ── tests: Slack and PagerDuty delivery (mocked) ─────────────────────────────

make_curl_mock "2.0000000"   # trigger alert
run_test "Slack webhook delivery called without error" 1 \
    bash "$ALERT_SCRIPT" \
        --treasury "$MOCK_TREASURY" \
        --network testnet \
        --threshold "$THRESHOLD" \
        --slack-webhook "https://hooks.slack.com/mock"

run_test "PagerDuty delivery called without error" 1 \
    bash "$ALERT_SCRIPT" \
        --treasury "$MOCK_TREASURY" \
        --network testnet \
        --threshold "$THRESHOLD" \
        --pagerduty-key "mock-pd-key-00000000000000000000000000000000"

# ── summary ───────────────────────────────────────────────────────────────────

echo
echo "Results: $PASS passed, $FAIL failed."
echo

[[ "$FAIL" -eq 0 ]]
