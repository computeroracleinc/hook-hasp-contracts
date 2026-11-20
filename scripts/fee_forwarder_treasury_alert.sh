#!/usr/bin/env bash
# =============================================================================
# fee-forwarder treasury replenishment alert
# =============================================================================
#
# Monitors the XLM balance of a deployed fee-forwarder treasury address on a
# Stellar/Soroban network and emits a structured alert when the balance drops
# below a configured safety threshold.
#
# Usage:
#   ./scripts/fee_forwarder_treasury_alert.sh [OPTIONS]
#
# Options:
#   --network <name>       Stellar network: testnet | mainnet | futurenet
#                          (default: testnet)
#   --rpc-url <url>        Custom Soroban RPC endpoint (overrides --network)
#   --treasury <address>   Treasury / fee-forwarder contract address (required)
#   --threshold <stroops>  Alert threshold in stroops (default: 50000000 = 5 XLM)
#   --slack-webhook <url>  Optional Slack incoming-webhook URL for alert delivery
#   --pagerduty-key <key>  Optional PagerDuty Events API v2 routing key
#   --dry-run              Print what would be checked; do not emit alerts
#   -h, --help             Show this help text
#
# Exit codes:
#   0  Balance is at or above threshold (healthy)
#   1  Balance is below threshold (alert fired)
#   2  Configuration or dependency error
#   3  Network / RPC error
#
# Dependencies:
#   curl, jq  — both must be on PATH.
#
# Examples:
#   # Basic check against testnet
#   ./scripts/fee_forwarder_treasury_alert.sh \
#       --treasury GABC1234... \
#       --threshold 100000000
#
#   # Testnet with Slack notification
#   SLACK_WEBHOOK=https://hooks.slack.com/... \
#   ./scripts/fee_forwarder_treasury_alert.sh \
#       --treasury GABC1234... \
#       --threshold 50000000
#
# =============================================================================
set -euo pipefail

# ── defaults ──────────────────────────────────────────────────────────────────
NETWORK="testnet"
RPC_URL=""
TREASURY_ADDRESS=""
THRESHOLD_STROOPS="50000000"   # 5 XLM
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"
PAGERDUTY_KEY="${PAGERDUTY_KEY:-}"
DRY_RUN="false"
SCRIPT_NAME="$(basename "$0")"

# ── well-known RPC endpoints ──────────────────────────────────────────────────
declare -A NETWORK_RPC_URLS=(
    ["testnet"]="https://soroban-testnet.stellar.org"
    ["mainnet"]="https://soroban-mainnet.stellar.org"
    ["futurenet"]="https://rpc-futurenet.stellar.org"
)

# ── helpers ───────────────────────────────────────────────────────────────────

usage() {
    sed -n '/^# Usage:/,/^# ==/p' "$0" | sed 's/^# \{0,2\}//'
    exit 0
}

log() {
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] [$SCRIPT_NAME] $*" >&2
}

die() {
    log "ERROR: $*"
    exit "${2:-2}"
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found on PATH."
}

stroops_to_xlm() {
    # 1 XLM = 10 000 000 stroops.
    awk "BEGIN { printf \"%.7f\", $1 / 10000000 }"
}

# ── argument parsing ──────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
    case "$1" in
        --network)
            NETWORK="$2"; shift 2 ;;
        --rpc-url)
            RPC_URL="$2"; shift 2 ;;
        --treasury)
            TREASURY_ADDRESS="$2"; shift 2 ;;
        --threshold)
            THRESHOLD_STROOPS="$2"; shift 2 ;;
        --slack-webhook)
            SLACK_WEBHOOK="$2"; shift 2 ;;
        --pagerduty-key)
            PAGERDUTY_KEY="$2"; shift 2 ;;
        --dry-run)
            DRY_RUN="true"; shift ;;
        -h|--help)
            usage ;;
        *)
            die "Unknown option: $1" ;;
    esac
done

# ── validation ────────────────────────────────────────────────────────────────

require_cmd curl
require_cmd jq
require_cmd awk

[[ -n "$TREASURY_ADDRESS" ]] || die "--treasury address is required."

# Resolve RPC URL.
if [[ -z "$RPC_URL" ]]; then
    RPC_URL="${NETWORK_RPC_URLS[$NETWORK]:-}"
    [[ -n "$RPC_URL" ]] || die "Unknown network '$NETWORK'. Use --rpc-url to specify a custom endpoint."
fi

# Validate threshold is a positive integer.
[[ "$THRESHOLD_STROOPS" =~ ^[0-9]+$ ]] || die "--threshold must be a non-negative integer (stroops)."

THRESHOLD_XLM="$(stroops_to_xlm "$THRESHOLD_STROOPS")"

log "Treasury : $TREASURY_ADDRESS"
log "Network  : $NETWORK  ($RPC_URL)"
log "Threshold: $THRESHOLD_STROOPS stroops ($THRESHOLD_XLM XLM)"

if [[ "$DRY_RUN" == "true" ]]; then
    log "DRY-RUN: skipping live balance check and alert delivery."
    exit 0
fi

# ── fetch balance via Horizon ─────────────────────────────────────────────────
# Horizon REST API is more universally available for account balance queries
# than the Soroban JSON-RPC, which targets smart-contract state. We derive the
# Horizon base URL from the network name.

declare -A HORIZON_URLS=(
    ["testnet"]="https://horizon-testnet.stellar.org"
    ["mainnet"]="https://horizon.stellar.org"
    ["futurenet"]="https://horizon-futurenet.stellar.org"
)

HORIZON_URL="${HORIZON_URLS[$NETWORK]:-}"

if [[ -z "$HORIZON_URL" ]]; then
    # Custom RPC was given; derive a best-effort Horizon URL by replacing
    # "soroban-" prefix if present, otherwise fall back to the RPC endpoint
    # itself and attempt to parse account data from the JSON-RPC getLedgerEntries.
    HORIZON_URL="${RPC_URL/soroban-/horizon-}"
fi

ACCOUNT_URL="$HORIZON_URL/accounts/$TREASURY_ADDRESS"

log "Querying Horizon: $ACCOUNT_URL"

HTTP_RESPONSE="$(curl --silent --fail --max-time 15 \
    --header "Accept: application/json" \
    "$ACCOUNT_URL" 2>&1)" || {
    EXIT=$?
    # 404 = account does not exist yet (unfunded).
    if echo "$HTTP_RESPONSE" | grep -q '"status":404'; then
        log "WARNING: Account $TREASURY_ADDRESS not found on $NETWORK (unfunded?). Treating balance as 0."
        BALANCE_STROOPS=0
    else
        log "ERROR: Failed to reach Horizon at $ACCOUNT_URL (curl exit $EXIT)."
        exit 3
    fi
}

if [[ -z "${BALANCE_STROOPS+x}" ]]; then
    # Parse the native XLM balance from the balances array.
    BALANCE_XLM="$(echo "$HTTP_RESPONSE" \
        | jq -r '[.balances[] | select(.asset_type=="native")] | first | .balance // "0"')"

    if [[ -z "$BALANCE_XLM" || "$BALANCE_XLM" == "null" ]]; then
        log "WARNING: Could not parse native balance from Horizon response. Treating as 0."
        BALANCE_XLM="0"
    fi

    # Convert XLM string (e.g. "9.9999900") to stroops (integer).
    BALANCE_STROOPS="$(awk "BEGIN { printf \"%d\", $BALANCE_XLM * 10000000 }")"
fi

BALANCE_XLM_DISPLAY="$(stroops_to_xlm "$BALANCE_STROOPS")"
log "Balance  : $BALANCE_STROOPS stroops ($BALANCE_XLM_DISPLAY XLM)"

# ── threshold check ───────────────────────────────────────────────────────────

if (( BALANCE_STROOPS >= THRESHOLD_STROOPS )); then
    log "OK: Treasury balance ($BALANCE_XLM_DISPLAY XLM) is above threshold ($THRESHOLD_XLM XLM)."
    exit 0
fi

# ── alert ─────────────────────────────────────────────────────────────────────

ALERT_TITLE="[fee-forwarder] Treasury balance below threshold"
ALERT_BODY="Treasury $TREASURY_ADDRESS on $NETWORK has only ${BALANCE_XLM_DISPLAY} XLM \
(threshold: ${THRESHOLD_XLM} XLM). Replenish immediately to avoid failed sponsored transactions."

log "ALERT: $ALERT_BODY"

# Slack notification.
if [[ -n "$SLACK_WEBHOOK" ]]; then
    SLACK_PAYLOAD="$(jq -nc \
        --arg title "$ALERT_TITLE" \
        --arg body "$ALERT_BODY" \
        --arg network "$NETWORK" \
        --arg address "$TREASURY_ADDRESS" \
        --arg balance "$BALANCE_XLM_DISPLAY" \
        --arg threshold "$THRESHOLD_XLM" \
        '{
            text: $title,
            attachments: [{
                color: "danger",
                fields: [
                    {title: "Network",   value: $network,   short: true},
                    {title: "Address",   value: $address,   short: false},
                    {title: "Balance",   value: ($balance + " XLM"),   short: true},
                    {title: "Threshold", value: ($threshold + " XLM"), short: true}
                ]
            }]
        }')"
    curl --silent --max-time 10 \
        --request POST \
        --header "Content-Type: application/json" \
        --data "$SLACK_PAYLOAD" \
        "$SLACK_WEBHOOK" >/dev/null \
        && log "Slack alert delivered." \
        || log "WARNING: Slack delivery failed (non-fatal)."
fi

# PagerDuty Events API v2 notification.
if [[ -n "$PAGERDUTY_KEY" ]]; then
    PD_PAYLOAD="$(jq -nc \
        --arg routing_key "$PAGERDUTY_KEY" \
        --arg summary "$ALERT_TITLE" \
        --arg source "$TREASURY_ADDRESS" \
        --arg network "$NETWORK" \
        --arg balance "$BALANCE_XLM_DISPLAY" \
        --arg threshold "$THRESHOLD_XLM" \
        '{
            routing_key: $routing_key,
            event_action: "trigger",
            payload: {
                summary: $summary,
                severity: "critical",
                source: $source,
                custom_details: {
                    network:   $network,
                    balance:   ($balance + " XLM"),
                    threshold: ($threshold + " XLM")
                }
            }
        }')"
    curl --silent --max-time 10 \
        --request POST \
        --header "Content-Type: application/json" \
        --data "$PD_PAYLOAD" \
        "https://events.pagerduty.com/v2/enqueue" >/dev/null \
        && log "PagerDuty alert delivered." \
        || log "WARNING: PagerDuty delivery failed (non-fatal)."
fi

exit 1
