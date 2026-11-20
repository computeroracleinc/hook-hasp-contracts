//! Core logic for the rate-limit policy.
use soroban_sdk::{
    auth::{Context, ContractContext},
    contracterror, contractevent, contracttype, panic_with_error, Address, Env, Symbol, Vec,
};
use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

// ################## ERRORS ##################

/// Error codes for rate-limit policy operations.
///
/// Numbering starts fresh at `1` — this is a standalone contract, not part of
/// the upstream `stellar-accounts` error-numbering convention.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RateLimitError {
    /// The policy is not installed for this smart account and context rule.
    NotInstalled = 1,
    /// Only `CallContract` context rule types are accepted.
    InvalidContextRule = 2,
    /// `max_calls_per_window` or `period_ledgers` was zero.
    InvalidParams = 3,
    /// The function has been called `max_calls_per_window` times in the
    /// current rolling window.
    RateLimitExceeded = 4,
    /// The policy was already installed for this smart account and context
    /// rule.
    AlreadyInstalled = 5,
    /// The call history reached `MAX_HISTORY_ENTRIES`.
    HistoryCapacityExceeded = 6,
}

// ################## TYPES ##################

/// A single call recorded in the rolling-window history.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CallEntry {
    /// The function name that was called.
    pub fn_name: Symbol,
    /// The ledger sequence at which the call occurred.
    pub ledger: u32,
}

/// Installation parameters for the rate-limit policy.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RateLimitAccountParams {
    /// Maximum number of calls to any single function name within
    /// `period_ledgers`.
    pub max_calls_per_window: u32,
    /// Rolling window size in ledgers.
    pub period_ledgers: u32,
}

/// Internal storage structure for a single `(smart_account, context_rule)`
/// installation.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RateLimitData {
    pub max_calls_per_window: u32,
    pub period_ledgers: u32,
    /// Call history ordered by ascending ledger sequence. Oldest entries are
    /// at the front and are evicted first during `enforce`.
    pub call_history: Vec<CallEntry>,
}

/// Storage keys for rate-limit policy data.
#[contracttype]
pub enum RateLimitStorageKey {
    AccountContext(Address, u32),
}

// ################## EVENTS ##################

/// Emitted when the policy is installed.
#[contractevent]
#[derive(Clone, Debug)]
pub struct RateLimitInstalled {
    #[topic]
    pub smart_account: Address,
    pub context_rule_id: u32,
    pub max_calls_per_window: u32,
    pub period_ledgers: u32,
}

/// Emitted on every successful (non-rate-limited) enforce call.
#[contractevent]
#[derive(Clone)]
pub struct RateLimitEnforced {
    #[topic]
    pub smart_account: Address,
    pub context_rule_id: u32,
    pub fn_name: Symbol,
    pub calls_in_window: u32,
}

/// Emitted when the policy is uninstalled.
#[contractevent]
#[derive(Clone, Debug)]
pub struct RateLimitUninstalled {
    #[topic]
    pub smart_account: Address,
    pub context_rule_id: u32,
}

// ################## CONSTANTS ##################

const DAY_IN_LEDGERS: u32 = 17280;
const EXTEND_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
const TTL_THRESHOLD: u32 = EXTEND_AMOUNT - DAY_IN_LEDGERS;

/// Maximum entries stored in `call_history`. Bounds storage size and the
/// linear eviction scan on every `enforce`.
const MAX_HISTORY_ENTRIES: u32 = 1000;

// ################## INTERNAL HELPERS ##################

pub fn get_rate_limit_data(e: &Env, context_rule_id: u32, smart_account: &Address) -> RateLimitData {
    let key = RateLimitStorageKey::AccountContext(smart_account.clone(), context_rule_id);
    e.storage()
        .persistent()
        .get(&key)
        .inspect(|_| {
            e.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, EXTEND_AMOUNT);
        })
        .unwrap_or_else(|| panic_with_error!(e, RateLimitError::NotInstalled))
}

/// Evicts entries older than the rolling window from the front of the history
/// vec (entries are appended in ascending ledger order).
fn evict_old_entries(call_history: &mut Vec<CallEntry>, current_ledger: u32, period_ledgers: u32) {
    let cutoff = current_ledger.saturating_sub(period_ledgers);
    while let Some(entry) = call_history.get(0) {
        if entry.ledger <= cutoff {
            call_history.pop_front();
        } else {
            break;
        }
    }
}

/// Counts in-window entries whose `fn_name` matches `target`.
fn count_calls_for_fn(call_history: &Vec<CallEntry>, target: &Symbol) -> u32 {
    let mut count: u32 = 0;
    for entry in call_history.iter() {
        if &entry.fn_name == target {
            count += 1;
        }
    }
    count
}

fn emit_rate_limit_installed(
    e: &Env,
    smart_account: &Address,
    context_rule_id: u32,
    max_calls_per_window: u32,
    period_ledgers: u32,
) {
    RateLimitInstalled {
        smart_account: smart_account.clone(),
        context_rule_id,
        max_calls_per_window,
        period_ledgers,
    }
    .publish(e);
}

fn emit_rate_limit_enforced(
    e: &Env,
    smart_account: &Address,
    context_rule_id: u32,
    fn_name: &Symbol,
    calls_in_window: u32,
) {
    RateLimitEnforced {
        smart_account: smart_account.clone(),
        context_rule_id,
        fn_name: fn_name.clone(),
        calls_in_window,
    }
    .publish(e);
}

fn emit_rate_limit_uninstalled(e: &Env, smart_account: &Address, context_rule_id: u32) {
    RateLimitUninstalled { smart_account: smart_account.clone(), context_rule_id }.publish(e);
}

// ################## PUBLIC FREE FUNCTIONS ##################

/// Installs the rate-limit policy on a smart account.
///
/// # Errors
///
/// * [`RateLimitError::InvalidContextRule`] — context rule is not
///   `CallContract`.
/// * [`RateLimitError::InvalidParams`] — `max_calls_per_window` or
///   `period_ledgers` is zero.
/// * [`RateLimitError::AlreadyInstalled`] — already installed for this
///   account and context rule.
pub fn install(
    e: &Env,
    params: &RateLimitAccountParams,
    context_rule: &ContextRule,
    smart_account: &Address,
) {
    smart_account.require_auth();

    if !matches!(context_rule.context_type, ContextRuleType::CallContract(_)) {
        panic_with_error!(e, RateLimitError::InvalidContextRule)
    }

    if params.max_calls_per_window == 0 || params.period_ledgers == 0 {
        panic_with_error!(e, RateLimitError::InvalidParams)
    }

    let key = RateLimitStorageKey::AccountContext(smart_account.clone(), context_rule.id);

    if e.storage().persistent().has(&key) {
        panic_with_error!(e, RateLimitError::AlreadyInstalled)
    }

    let data = RateLimitData {
        max_calls_per_window: params.max_calls_per_window,
        period_ledgers: params.period_ledgers,
        call_history: Vec::new(e),
    };

    e.storage().persistent().set(&key, &data);
    e.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, EXTEND_AMOUNT);

    emit_rate_limit_installed(
        e,
        smart_account,
        context_rule.id,
        params.max_calls_per_window,
        params.period_ledgers,
    );
}

/// Removes all stored rate-limit data for this account and context rule.
///
/// # Errors
///
/// * [`RateLimitError::NotInstalled`] — not installed.
pub fn uninstall(e: &Env, context_rule: &ContextRule, smart_account: &Address) {
    smart_account.require_auth();

    let key = RateLimitStorageKey::AccountContext(smart_account.clone(), context_rule.id);

    if !e.storage().persistent().has(&key) {
        panic_with_error!(e, RateLimitError::NotInstalled)
    }

    e.storage().persistent().remove(&key);

    emit_rate_limit_uninstalled(e, smart_account, context_rule.id);
}

/// Enforces the rate limit for the current call.
///
/// Evicts history entries outside the rolling window, counts how many
/// in-window calls share this `fn_name`, and panics if the count equals
/// `max_calls_per_window`. Otherwise records the call.
///
/// # Errors
///
/// * [`RateLimitError::RateLimitExceeded`] — the per-function call cap has
///   been reached for this window, the context is not a contract call, or no
///   authenticated signers were provided.
/// * [`RateLimitError::HistoryCapacityExceeded`] — history is full.
/// * [`RateLimitError::NotInstalled`] — not installed.
pub fn enforce(
    e: &Env,
    context: &Context,
    authenticated_signers: &Vec<Signer>,
    context_rule: &ContextRule,
    smart_account: &Address,
) {
    smart_account.require_auth();

    if authenticated_signers.is_empty() {
        panic_with_error!(e, RateLimitError::RateLimitExceeded)
    }

    let Context::Contract(ContractContext { fn_name, .. }) = context else {
        panic_with_error!(e, RateLimitError::RateLimitExceeded)
    };

    let mut data = get_rate_limit_data(e, context_rule.id, smart_account);

    let current_ledger = e.ledger().sequence();
    evict_old_entries(&mut data.call_history, current_ledger, data.period_ledgers);

    let calls_so_far = count_calls_for_fn(&data.call_history, fn_name);

    if calls_so_far >= data.max_calls_per_window {
        panic_with_error!(e, RateLimitError::RateLimitExceeded)
    }

    if data.call_history.len() >= MAX_HISTORY_ENTRIES {
        panic_with_error!(e, RateLimitError::HistoryCapacityExceeded)
    }

    data.call_history.push_back(CallEntry { fn_name: fn_name.clone(), ledger: current_ledger });

    let key = RateLimitStorageKey::AccountContext(smart_account.clone(), context_rule.id);
    e.storage().persistent().set(&key, &data);

    emit_rate_limit_enforced(e, smart_account, context_rule.id, fn_name, calls_so_far + 1);
}

/// Simulates whether the next call to `fn_name` would pass the rate limit
/// without mutating any state.
///
/// Returns `(would_pass, calls_remaining)`.
/// Panics with [`RateLimitError::NotInstalled`] when not installed.
pub fn check_policy(
    e: &Env,
    context_rule_id: u32,
    smart_account: &Address,
    fn_name: &Symbol,
) -> (bool, u32) {
    let data = get_rate_limit_data(e, context_rule_id, smart_account);
    let current_ledger = e.ledger().sequence();

    // Work on a local copy so the read is non-mutating.
    let mut local_history = data.call_history.clone();
    evict_old_entries(&mut local_history, current_ledger, data.period_ledgers);

    let calls_so_far = count_calls_for_fn(&local_history, fn_name);
    let remaining = data.max_calls_per_window.saturating_sub(calls_so_far);
    (remaining > 0, remaining)
}
