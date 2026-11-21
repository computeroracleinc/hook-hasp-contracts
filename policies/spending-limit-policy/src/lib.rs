//! Rolling-window spending limit policy for Latch smart accounts.
//!
//! Attach this policy to a `CallContract` context rule to cap how much can
//! be transferred through that contract within a rolling ledger window —
//! e.g. "at most 10 XLM per rolling day" out of a specific token contract.
//! Once the limit is hit, further transfers in that window are rejected
//! until old entries age out.
//!
//! This is a thin `#[contract]` wrapper around OZ's `spending_limit` policy
//! (`stellar_accounts::policies::spending_limit`) — all real logic lives
//! upstream, this crate only supplies the deployable contract shell the
//! factory and smart accounts can actually install and call.
//!
//! # How it works
//!
//! - `install` — called once per `(smart_account, context_rule)` pair, with a
//!   `spending_limit` (max total, in stroops) and `period_ledgers` (the rolling
//!   window size). Rejects a non-`CallContract` context rule, or a non-positive
//!   limit/period.
//! - `enforce` — called on every authorized call against the rule; evicts
//!   spending entries older than `period_ledgers`, sums what remains, and
//!   panics if adding this call's amount would exceed `spending_limit`.
//!   Otherwise records the entry and updates the running total.
//! - `set_spending_limit` / `get_spending_limit_data` — read or change the
//!   stored limit (and inspect spend history) after installation.
//! - `uninstall` — removes all stored spending history and the limit.
//!
//! # Important Constraints
//!
//! - **Only intercepts calls literally named `transfer`**, with the amount read
//!   as the *third* positional argument — the standard SEP-41 token
//!   `transfer(from, to, amount)` shape. Any other function call on the rule is
//!   unconditionally rejected, not silently allowed through.
//! - **One contract per installation.** Requiring a `CallContract` context rule
//!   pins each installed policy to a single target contract, so all tracked
//!   transfers share one denomination. Limiting spend across several different
//!   token contracts needs a separate context rule (and policy install) per
//!   contract.
//! - **Spend history is capped** at `MAX_HISTORY_ENTRIES` (1000) entries per
//!   `(smart_account, context_rule)`; exceeding it panics with
//!   `HistoryCapacityExceeded` rather than silently dropping old data.
//!
//! # Overflow safety
//!
//! The rolling window's arithmetic is checked by this shell before the
//! upstream policy runs, so an extreme value can never wrap around into a
//! wrong answer:
//!
//! - The window's end — the current ledger timestamp plus the window length in
//!   seconds — must be representable in `u64`. An environment whose clock sits
//!   that close to `u64::MAX` is rejected with
//!   [`SpendingLimitPolicyError::WindowArithmeticOverflow`] instead of silently
//!   computing a wrapped (and therefore useless) window bound.
//! - The window's running total plus the incoming transfer amount must be
//!   representable in `i128`. A transfer large enough to overflow the running
//!   total is rejected with the same error rather than trapping on an
//!   arithmetic overflow inside the upstream policy.
#![no_std]

use soroban_sdk::{
    auth::{Context, ContractContext},
    contract, contracterror, contractimpl, panic_with_error, symbol_short, Address, Env,
    TryFromVal, Vec,
};
use stellar_accounts::{
    policies::{spending_limit, spending_limit::SpendingLimitAccountParams, Policy},
    smart_account::{ContextRule, Signer},
};

/// Error codes for this policy shell.
///
/// This is a standalone, independently-deployed contract, not a module of the
/// upstream `stellar-accounts` crate, so it is not part of that crate's shared
/// error-numbering convention (its own codes start at 3220). Numbering here
/// starts fresh at `1`.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum SpendingLimitPolicyError {
    /// A rolling-window calculation is not representable: either the window's
    /// end timestamp would overflow `u64`, or the window's running total plus
    /// this transfer would overflow `i128`. Fails closed instead of wrapping.
    WindowArithmeticOverflow = 1,
}

/// Approximate ledger close time, in seconds, used to turn `period_ledgers`
/// into the window's length in seconds for timestamp-based checks.
const LEDGER_CLOSE_TIME_SECS: u64 = 5;

/// Returns the window length in seconds for `period_ledgers`, or `None` if
/// the multiplication would overflow (it cannot for a `u32` ledger count, but
/// the conversion stays checked so no window bound is ever computed from a
/// wrapped value).
fn window_seconds(period_ledgers: u32) -> Option<u64> {
    u64::from(period_ledgers).checked_mul(LEDGER_CLOSE_TIME_SECS)
}

/// Verifies, with checked arithmetic only, that this transfer cannot make the
/// upstream rolling-window bookkeeping overflow.
///
/// Only runs for calls the upstream policy would actually process (a
/// `transfer` with a parseable, non-negative amount); everything else is left
/// to the upstream policy, which rejects it with its own error. When the
/// policy is not installed this surfaces the upstream
/// `SmartAccountNotInstalled` error early, exactly as the delegated `enforce`
/// would.
///
/// It reads only the policy's own (publicly readable) storage and never
/// writes, so running it before the upstream `require_auth` cannot authorize,
/// mutate, or bypass anything.
fn precheck_window_arithmetic(
    e: &Env,
    context: &Context,
    context_rule: &ContextRule,
    smart_account: &Address,
) {
    let Context::Contract(ContractContext { fn_name, args, .. }) = context else {
        return;
    };
    if fn_name != &symbol_short!("transfer") {
        return;
    }
    let Some(amount_val) = args.get(2) else {
        return;
    };
    let Ok(amount) = i128::try_from_val(e, &amount_val) else {
        return;
    };
    if amount < 0 {
        return;
    }

    let data = spending_limit::get_spending_limit_data(e, context_rule.id, smart_account);

    // The window's end timestamp — current timestamp plus the window length
    // in seconds — must be representable, so a clock at an extreme value can
    // never produce a wrapped window bound.
    let Some(window_secs) = window_seconds(data.period_ledgers) else {
        panic_with_error!(e, SpendingLimitPolicyError::WindowArithmeticOverflow)
    };
    if e.ledger().timestamp().checked_add(window_secs).is_none() {
        panic_with_error!(e, SpendingLimitPolicyError::WindowArithmeticOverflow)
    }

    // The window's running total plus this transfer must be representable;
    // otherwise the upstream `cached_total_spent + amount` comparison would
    // trap on an arithmetic overflow instead of returning a contract error.
    if data.cached_total_spent.checked_add(amount).is_none() {
        panic_with_error!(e, SpendingLimitPolicyError::WindowArithmeticOverflow)
    }
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
        // Checked window arithmetic first: extreme ledger timestamps and
        // window totals that would overflow are rejected with a contract
        // error instead of trapping inside the upstream policy.
        precheck_window_arithmetic(e, &context, &context_rule, &smart_account);

        spending_limit::enforce(e, &context, &authenticated_signers, &context_rule, &smart_account)
    }

    fn install(
        e: &Env,
        install_params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        spending_limit::install(e, &install_params, &context_rule, &smart_account)
    }

    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        spending_limit::uninstall(e, &context_rule, &smart_account)
    }
}

#[contractimpl]
impl SpendingLimitPolicy {
    pub fn get_spending_limit_data(
        e: &Env,
        context_rule_id: u32,
        smart_account: Address,
    ) -> spending_limit::SpendingLimitData {
        spending_limit::get_spending_limit_data(e, context_rule_id, &smart_account)
    }

    pub fn set_spending_limit(
        e: Env,
        spending_limit: i128,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        spending_limit::set_spending_limit(&e, spending_limit, &context_rule, &smart_account)
    }
}

#[cfg(test)]
mod test;
