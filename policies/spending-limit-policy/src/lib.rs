//! Rolling-window spending limit policy for Latch smart accounts.
//!
//! Retains the upstream `SpendingLimitPolicy` interface while:
//! - Storing each non-negative spending amount as unsigned LEB128 for compact
//!   on-chain storage, lazily migrating legacy entries on authenticated writes.
//! - Checking rolling-window arithmetic with checked operations AFTER evicting
//!   expired entries so stale entries can never cause a permanent overflow DoS.
//! - Extending persistent storage TTL on install, read, save, and migration.
#![no_std]

use soroban_sdk::{
    auth::{Context, ContractContext},
    contract, contracterror, contractimpl, contracttype, panic_with_error, symbol_short, Address,
    Bytes, Env, TryFromVal, Vec,
};
use stellar_accounts::{
    policies::{
        spending_limit,
        spending_limit::{
            SpendingLimitAccountParams, SpendingLimitData, SpendingLimitError,
            SpendingLimitStorageKey,
        },
        Policy,
    },
    smart_account::{ContextRule, ContextRuleType, Signer},
};

/// Error codes for this policy shell.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SpendingLimitPolicyError {
    /// A rolling-window calculation is not representable: either the window's
    /// end timestamp would overflow `u64`, or the live (post-eviction) window
    /// total plus this transfer would overflow `i128`.
    WindowArithmeticOverflow = 1,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
struct CompactSpendingEntry {
    amount: Bytes,
    ledger_sequence: u32,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
struct CompactSpendingLimitData {
    spending_limit: i128,
    period_ledgers: u32,
    spending_history: Vec<CompactSpendingEntry>,
    cached_total_spent: i128,
}

#[contracttype]
enum CompactStorageKey {
    CompactAccountContext(Address, u32),
}

const DAY_IN_LEDGERS: u32 = 17280;
const POLICY_EXTEND_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
const POLICY_TTL_THRESHOLD: u32 = POLICY_EXTEND_AMOUNT - DAY_IN_LEDGERS;

/// Approximate ledger close time, in seconds, used to convert `period_ledgers`
/// into seconds for timestamp overflow bounds.
const LEDGER_CLOSE_TIME_SECS: u64 = 5;

fn window_seconds(period_ledgers: u32) -> Option<u64> {
    u64::from(period_ledgers).checked_mul(LEDGER_CLOSE_TIME_SECS)
}

fn encode_amount(e: &Env, amount: i128) -> Bytes {
    let mut remaining = amount as u128;
    let mut encoded = Bytes::new(e);
    loop {
        let mut byte = (remaining & 0x7f) as u8;
        remaining >>= 7;
        if remaining != 0 {
            byte |= 0x80;
        }
        encoded.push_back(byte);
        if remaining == 0 {
            return encoded;
        }
    }
}

fn decode_amount(e: &Env, encoded: &Bytes) -> i128 {
    let mut amount = 0u128;
    let mut shift = 0u32;
    let mut index = 0u32;

    for byte in encoded.iter() {
        if shift > 126 {
            panic_with_error!(e, SpendingLimitError::NotAllowed)
        }
        let part = (byte & 0x7f) as u128;
        if part > (i128::MAX as u128 >> shift) {
            panic_with_error!(e, SpendingLimitError::NotAllowed)
        }
        amount |= part << shift;
        index += 1;

        if byte & 0x80 == 0 {
            if index != encoded.len() || (index > 1 && part == 0) {
                panic_with_error!(e, SpendingLimitError::NotAllowed)
            }
            return amount as i128;
        }
        shift += 7;
    }

    panic_with_error!(e, SpendingLimitError::NotAllowed)
}

fn compress_data(e: &Env, data: SpendingLimitData) -> CompactSpendingLimitData {
    let mut spending_history = Vec::new(e);
    for entry in data.spending_history.iter() {
        if entry.amount < 0 {
            panic_with_error!(e, SpendingLimitError::NotAllowed)
        }
        spending_history.push_back(CompactSpendingEntry {
            amount: encode_amount(e, entry.amount),
            ledger_sequence: entry.ledger_sequence,
        });
    }

    CompactSpendingLimitData {
        spending_limit: data.spending_limit,
        period_ledgers: data.period_ledgers,
        spending_history,
        cached_total_spent: data.cached_total_spent,
    }
}

fn expand_data(e: &Env, data: CompactSpendingLimitData) -> SpendingLimitData {
    let mut spending_history = Vec::new(e);
    for entry in data.spending_history.iter() {
        spending_history.push_back(spending_limit::SpendingEntry {
            amount: decode_amount(e, &entry.amount),
            ledger_sequence: entry.ledger_sequence,
        });
    }

    SpendingLimitData {
        spending_limit: data.spending_limit,
        period_ledgers: data.period_ledgers,
        spending_history,
        cached_total_spent: data.cached_total_spent,
    }
}

/// Pure read helper used by unauthenticated view functions (`get_spending_limit_data`,
/// `check_policy`). Never mutates or migrates storage keys — only refreshes TTL.
fn read_data(e: &Env, context_rule_id: u32, smart_account: &Address) -> SpendingLimitData {
    let key = CompactStorageKey::CompactAccountContext(smart_account.clone(), context_rule_id);
    if let Some(data) = e.storage().persistent().get::<_, CompactSpendingLimitData>(&key) {
        e.storage().persistent().extend_ttl(&key, POLICY_TTL_THRESHOLD, POLICY_EXTEND_AMOUNT);
        return expand_data(e, data);
    }

    let legacy_key =
        SpendingLimitStorageKey::AccountContext(smart_account.clone(), context_rule_id);
    if let Some(data) = e.storage().persistent().get::<_, SpendingLimitData>(&legacy_key) {
        e.storage().persistent().extend_ttl(
            &legacy_key,
            POLICY_TTL_THRESHOLD,
            POLICY_EXTEND_AMOUNT,
        );
        return data;
    }

    panic_with_error!(e, SpendingLimitError::SmartAccountNotInstalled)
}

/// Authenticated load helper used on write paths (`enforce`, `set_spending_limit`).
/// Lazily migrates any legacy `SpendingLimitStorageKey` entry to the compact key
/// and extends its TTL.
fn load_data(e: &Env, context_rule_id: u32, smart_account: &Address) -> SpendingLimitData {
    let key = CompactStorageKey::CompactAccountContext(smart_account.clone(), context_rule_id);
    if let Some(data) = e.storage().persistent().get::<_, CompactSpendingLimitData>(&key) {
        e.storage().persistent().extend_ttl(&key, POLICY_TTL_THRESHOLD, POLICY_EXTEND_AMOUNT);
        return expand_data(e, data);
    }

    let legacy_key =
        SpendingLimitStorageKey::AccountContext(smart_account.clone(), context_rule_id);
    if let Some(data) = e.storage().persistent().get::<_, SpendingLimitData>(&legacy_key) {
        e.storage().persistent().set(&key, &compress_data(e, data.clone()));
        e.storage().persistent().extend_ttl(&key, POLICY_TTL_THRESHOLD, POLICY_EXTEND_AMOUNT);
        e.storage().persistent().remove(&legacy_key);
        return data;
    }

    panic_with_error!(e, SpendingLimitError::SmartAccountNotInstalled)
}

fn save_data(
    e: &Env,
    context_rule_id: u32,
    smart_account: &Address,
    data: SpendingLimitData,
) {
    let key = CompactStorageKey::CompactAccountContext(smart_account.clone(), context_rule_id);
    e.storage().persistent().set(&key, &compress_data(e, data));
    e.storage().persistent().extend_ttl(&key, POLICY_TTL_THRESHOLD, POLICY_EXTEND_AMOUNT);
}

fn cleanup_old_entries(
    e: &Env,
    spending_history: &mut Vec<spending_limit::SpendingEntry>,
    current_ledger: u32,
    period_ledgers: u32,
) -> i128 {
    let cutoff_ledger = current_ledger.saturating_sub(period_ledgers);
    let mut removed_total = 0i128;

    while let Some(entry) = spending_history.get(0) {
        if entry.ledger_sequence <= cutoff_ledger {
            removed_total = removed_total
                .checked_add(entry.amount)
                .unwrap_or_else(|| {
                    panic_with_error!(e, SpendingLimitPolicyError::WindowArithmeticOverflow)
                });
            spending_history.pop_front();
        } else {
            break;
        }
    }

    removed_total
}

#[contract]
pub struct SpendingLimitPolicy;

#[contractimpl]
impl Policy for SpendingLimitPolicy {
    type AccountParams = SpendingLimitAccountParams;

    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();
        if authenticated_signers.is_empty() {
            panic_with_error!(e, SpendingLimitError::NotAllowed)
        }

        let event_context = context.clone();
        let Context::Contract(ContractContext { fn_name, args, .. }) = context else {
            panic_with_error!(e, SpendingLimitError::NotAllowed)
        };
        if fn_name != symbol_short!("transfer") {
            panic_with_error!(e, SpendingLimitError::NotAllowed)
        }
        let amount_val =
            args.get(2).unwrap_or_else(|| panic_with_error!(e, SpendingLimitError::NotAllowed));
        let Ok(amount) = i128::try_from_val(e, &amount_val) else {
            panic_with_error!(e, SpendingLimitError::NotAllowed)
        };
        if amount < 0 {
            panic_with_error!(e, SpendingLimitError::LessThanZero)
        }

        let mut data = load_data(e, context_rule.id, &smart_account);

        // Checked timestamp window bound.
        let Some(window_secs) = window_seconds(data.period_ledgers) else {
            panic_with_error!(e, SpendingLimitPolicyError::WindowArithmeticOverflow)
        };
        if e.ledger().timestamp().checked_add(window_secs).is_none() {
            panic_with_error!(e, SpendingLimitPolicyError::WindowArithmeticOverflow)
        }

        // Evict expired entries FIRST so stale entries near `i128::MAX` cannot
        // cause a permanent overflow DoS once their window has elapsed.
        let current_ledger = e.ledger().sequence();
        let removed_amount = cleanup_old_entries(
            e,
            &mut data.spending_history,
            current_ledger,
            data.period_ledgers,
        );
        data.cached_total_spent = data
            .cached_total_spent
            .checked_sub(removed_amount)
            .unwrap_or_else(|| panic_with_error!(e, SpendingLimitError::NotAllowed));

        // Checked addition against the live (post-eviction) running total.
        let total_spent = data
            .cached_total_spent
            .checked_add(amount)
            .unwrap_or_else(|| {
                panic_with_error!(e, SpendingLimitPolicyError::WindowArithmeticOverflow)
            });
        if total_spent > data.spending_limit {
            panic_with_error!(e, SpendingLimitError::SpendingLimitExceeded)
        }
        if data.spending_history.len() >= spending_limit::MAX_HISTORY_ENTRIES {
            panic_with_error!(e, SpendingLimitError::HistoryCapacityExceeded)
        }

        data.spending_history
            .push_back(spending_limit::SpendingEntry { amount, ledger_sequence: current_ledger });
        data.cached_total_spent = total_spent;
        save_data(e, context_rule.id, &smart_account, data);

        spending_limit::SpendingLimitEnforced {
            smart_account,
            context: event_context,
            context_rule_id: context_rule.id,
            amount,
            total_spent_in_period: total_spent,
        }
        .publish(e);
    }

    fn install(
        e: &Env,
        install_params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();
        if !matches!(context_rule.context_type, ContextRuleType::CallContract(_)) {
            panic_with_error!(e, SpendingLimitError::OnlyCallContractAllowed)
        }
        if install_params.spending_limit <= 0 || install_params.period_ledgers == 0 {
            panic_with_error!(e, SpendingLimitError::InvalidLimitOrPeriod)
        }

        let key = CompactStorageKey::CompactAccountContext(smart_account.clone(), context_rule.id);
        let legacy_key =
            SpendingLimitStorageKey::AccountContext(smart_account.clone(), context_rule.id);
        if e.storage().persistent().has(&key) || e.storage().persistent().has(&legacy_key) {
            panic_with_error!(e, SpendingLimitError::AlreadyInstalled)
        }

        let data = SpendingLimitData {
            spending_limit: install_params.spending_limit,
            period_ledgers: install_params.period_ledgers,
            spending_history: Vec::new(e),
            cached_total_spent: 0,
        };
        e.storage().persistent().set(&key, &compress_data(e, data));
        e.storage().persistent().extend_ttl(&key, POLICY_TTL_THRESHOLD, POLICY_EXTEND_AMOUNT);

        spending_limit::SpendingLimitInstalled {
            smart_account,
            context_rule_id: context_rule.id,
            spending_limit: install_params.spending_limit,
            period_ledgers: install_params.period_ledgers,
        }
        .publish(e);
    }

    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();
        let key = CompactStorageKey::CompactAccountContext(smart_account.clone(), context_rule.id);
        let legacy_key =
            SpendingLimitStorageKey::AccountContext(smart_account.clone(), context_rule.id);
        if !e.storage().persistent().has(&key) && !e.storage().persistent().has(&legacy_key) {
            panic_with_error!(e, SpendingLimitError::SmartAccountNotInstalled)
        }
        e.storage().persistent().remove(&key);
        e.storage().persistent().remove(&legacy_key);

        spending_limit::SpendingLimitUninstalled {
            smart_account,
            context_rule_id: context_rule.id,
        }
        .publish(e);
    }
}

#[contractimpl]
impl SpendingLimitPolicy {
    pub fn get_spending_limit_data(
        e: &Env,
        context_rule_id: u32,
        smart_account: Address,
    ) -> SpendingLimitData {
        read_data(e, context_rule_id, &smart_account)
    }

    pub fn set_spending_limit(
        e: Env,
        spending_limit: i128,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();
        if spending_limit <= 0 {
            panic_with_error!(&e, SpendingLimitError::InvalidLimitOrPeriod)
        }

        let mut data = load_data(&e, context_rule.id, &smart_account);
        data.spending_limit = spending_limit;
        save_data(&e, context_rule.id, &smart_account, data);

        spending_limit::SpendingLimitChanged {
            smart_account,
            context_rule_id: context_rule.id,
            spending_limit,
        }
        .publish(&e);
    }

    /// Simulates whether a transfer of `amount` (in stroops) would pass the
    /// rolling-window spending limit without mutating any state.
    pub fn check_policy(
        e: &Env,
        context_rule_id: u32,
        smart_account: Address,
        amount: i128,
    ) -> (bool, i128) {
        let data = read_data(e, context_rule_id, &smart_account);
        let remaining = data.spending_limit.saturating_sub(data.cached_total_spent).max(0);
        (amount >= 0 && amount <= remaining, remaining)
    }
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod boundary_test;
