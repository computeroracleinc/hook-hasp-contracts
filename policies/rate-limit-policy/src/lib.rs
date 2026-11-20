//! # Rate-Limit Policy
//!
//! Attach this policy to a `CallContract` context rule to cap how many times
//! any given function may be called within a rolling ledger window — e.g.
//! "at most 5 calls to `swap` per 1 000 ledgers". This is useful for
//! protecting automated bot accounts and relayers from runaway call loops or
//! griefing by rate-capping per-function call frequency.
//!
//! # How it works
//!
//! - `install` — called once per `(smart_account, context_rule)` pair with
//!   `max_calls_per_window` (the cap) and `period_ledgers` (the rolling window
//!   size in ledgers). Rejects a non-`CallContract` context rule or a zero
//!   limit/period.
//! - `enforce` — called on every authorized call against the rule; evicts call
//!   history entries older than `period_ledgers`, counts how many in-window
//!   entries share the same `fn_name`, and panics if that count has reached
//!   `max_calls_per_window`. Otherwise appends a new entry.
//! - `check_policy` — read-only preflight that returns `(would_pass,
//!   calls_remaining)` without touching state. Clients can call this to
//!   preview whether the next call would succeed.
//! - `get_rate_limit_data` — inspect the full stored state.
//! - `uninstall` — removes all stored history.
//!
//! # Constraints
//!
//! - Only `CallContract` context rules are accepted.
//! - Call history is capped at `MAX_HISTORY_ENTRIES` (1 000) entries; exceeding
//!   it panics with `HistoryCapacityExceeded` rather than silently dropping
//!   older entries.
#![no_std]

mod rate_limit;

pub use rate_limit::{
    CallEntry, RateLimitAccountParams, RateLimitData, RateLimitError, RateLimitStorageKey,
};

use soroban_sdk::{auth::Context, contract, contractimpl, Address, Env, Symbol, Vec};
use stellar_accounts::{
    policies::Policy,
    smart_account::{ContextRule, Signer},
};

#[contract]
pub struct RateLimitPolicy;

#[contractimpl]
impl Policy for RateLimitPolicy {
    type AccountParams = RateLimitAccountParams;

    fn install(
        e: &Env,
        install_params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        rate_limit::install(e, &install_params, &context_rule, &smart_account)
    }

    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        rate_limit::uninstall(e, &context_rule, &smart_account)
    }

    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        rate_limit::enforce(e, &context, &authenticated_signers, &context_rule, &smart_account)
    }
}

#[contractimpl]
impl RateLimitPolicy {
    /// Returns the full stored rate-limit data for this account and context
    /// rule.
    ///
    /// # Errors
    ///
    /// * [`RateLimitError::NotInstalled`] — not installed.
    pub fn get_rate_limit_data(
        e: &Env,
        context_rule_id: u32,
        smart_account: Address,
    ) -> RateLimitData {
        rate_limit::get_rate_limit_data(e, context_rule_id, &smart_account)
    }

    /// Simulates whether the next call to `fn_name` would pass the rate limit
    /// without mutating any state.
    ///
    /// Returns `(would_pass, calls_remaining)`:
    /// - `would_pass` is `true` when at least one more call to `fn_name` is
    ///   allowed in the current window.
    /// - `calls_remaining` is `max_calls_per_window - in_window_count`.
    ///
    /// Panics with [`RateLimitError::NotInstalled`] when not installed.
    pub fn check_policy(
        e: &Env,
        context_rule_id: u32,
        smart_account: Address,
        fn_name: Symbol,
    ) -> (bool, u32) {
        rate_limit::check_policy(e, context_rule_id, &smart_account, &fn_name)
    }
}

#[cfg(test)]
mod test;
