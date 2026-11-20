//! Permissioned fee forwarder — lets `latch-relayer` sponsor gasless
//! transactions for Latch accounts that hold no XLM.
//!
//! Singleton, permissioned contract shared across every Latch account, same
//! pattern as `ed25519-verifier`/`threshold-policy` (not deployed per
//! account). Permissioned because Latch controls both sides of the flow —
//! the wallet and the relayer — so the executor role is reserved for
//! `latch-relayer`'s own operating address(es), not an open relayer market.
//!
//! This is a thin `#[contract]` wrapper around OZ's `stellar-fee-abstraction`
//! helpers (`stellar_fee_abstraction::collect_fee_and_invoke` and friends) —
//! all real fee-collection logic lives upstream, this crate only supplies the
//! deployable contract shell plus the role-gating that makes the flow
//! permissioned. Follows OZ's `examples/fee-forwarder-permissioned` reference
//! contract.
//!
//! # How it works
//!
//! - `__constructor(admin, manager, executors)` — sets `admin`, grants
//!   `manager` the `manager` role, and grants each address in `executors` the
//!   `executor` role. `AccessControl` (below) exposes `grant_role`/
//!   `revoke_role` for admin/manager-authorized follow-up changes to either
//!   role after deployment.
//! - `forward` — the sponsored-transaction entrypoint. The account signs one
//!   authorization tree covering `forward()`, with sub-invocations for
//!   `fee_token.approve(fee_forwarder, max_fee_amount, expiration_ledger)` (if
//!   needed) and the actual target call. The relayer, gated to the `executor`
//!   role by `#[only_role]`, fills in the real `fee_amount` (must be `<=
//!   max_fee_amount`) and submits, paying the network's XLM fee itself.
//!   Requires **both** the user's and the executor's authorization — collects
//!   the fee and forwards the target call atomically: if either step fails, the
//!   whole transaction (including the fee collection) reverts.
//!   Before executing, `forward` checks whether the circuit breaker has been
//!   tripped for `fee_token`. After a successful fee collection it updates the
//!   rolling 1-hour outflow window; if the new total exceeds the emergency
//!   budget the circuit breaker trips and the transaction is reverted.
//! - `enable_fee_token` / `disable_fee_token` — manager-gated allowlist
//!   management for which tokens `forward` accepts as a fee. The allowlist is
//!   disabled (all tokens accepted) until the first token is enabled — see
//!   `stellar_fee_abstraction::is_allowed_fee_token`.
//! - `sweep_tokens` — manager-gated withdrawal of fees this contract has
//!   collected.
//! - `set_emergency_budget` — manager-gated per-token hourly outflow cap. When
//!   aggregate fees for a token exceed this within a rolling 1-hour window, the
//!   circuit breaker trips and all further `forward` calls for that token are
//!   rejected until the manager calls `reset_circuit_breaker`.
//! - `reset_circuit_breaker` — manager-gated manual reset of the tripped state
//!   for a given token.
//!
//! # Security Warning
//!
//! `collect_fee_and_invoke` only authorizes the user's *input* — it does not
//! vet whether the forwarded call is safe for the user to make. Simulating
//! the outcome of `target_contract.target_fn(target_args)` before signing is
//! the invoker's (the account's own signer's) responsibility, same as any
//! other authorization the account signs.
#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracterror, contractevent, contracttype, panic_with_error,
    symbol_short, Address, Env, Symbol, Val, Vec,
};
use stellar_access::access_control::{grant_role_no_auth, set_admin, AccessControl};
use stellar_fee_abstraction::{
    collect_fee_and_invoke, set_allowed_fee_token, sweep_token, FeeAbstractionApproval,
};
use stellar_macros::only_role;

const MANAGER_ROLE: Symbol = symbol_short!("manager");
const EXECUTOR_ROLE: Symbol = symbol_short!("executor");

/// One hour in seconds. The rolling window over which outflow is summed.
const HOUR_IN_SECS: u64 = 3_600;

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum FeeForwarderStorageKey {
    /// Per-token emergency budget (i128). No entry means no budget enforced.
    EmergencyBudget(Address),
    /// Per-token circuit-breaker tripped flag (bool).
    CircuitBreakerPaused(Address),
    /// Per-token rolling-window outflow data.
    HourlyOutflow(Address),
}

// ── Types ─────────────────────────────────────────────────────────────────────

/// Rolling 1-hour outflow window for a single fee token.
#[contracttype]
#[derive(Clone, Debug)]
pub struct HourlyOutflowData {
    /// Cumulative fee amount forwarded within the current window.
    pub total_amount: i128,
    /// Ledger timestamp (seconds) when the current window opened.
    pub window_start: u64,
}

// ── Errors ────────────────────────────────────────────────────────────────────

/// Error codes specific to the fee-forwarder contract.
#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum FeeForwarderError {
    /// The circuit breaker is tripped for this fee token; sponsorships are
    /// paused until the manager calls `reset_circuit_breaker`.
    CircuitBreakerTripped = 1,
    /// `budget` passed to `set_emergency_budget` must be strictly positive.
    InvalidBudget = 2,
}

// ── Events ────────────────────────────────────────────────────────────────────

/// Emitted when the rolling 1-hour outflow for a token exceeds the emergency
/// budget and the circuit breaker trips.
#[contractevent]
#[derive(Clone, Debug)]
pub struct CircuitBreakerTripped {
    #[topic]
    pub token: Address,
    pub total_amount: i128,
    pub emergency_budget: i128,
}

/// Emitted when the manager manually resets the circuit breaker for a token.
#[contractevent]
#[derive(Clone, Debug)]
pub struct CircuitBreakerReset {
    #[topic]
    pub token: Address,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct FeeForwarder;

#[contractimpl]
impl FeeForwarder {
    /// Sets `admin`, grants `manager` the `manager` role, and grants each
    /// address in `executors` the `executor` role.
    pub fn __constructor(env: Env, admin: Address, manager: Address, executors: Vec<Address>) {
        set_admin(&env, &admin);
        grant_role_no_auth(&env, &manager, &MANAGER_ROLE, &admin);

        for executor in executors.iter() {
            grant_role_no_auth(&env, &executor, &EXECUTOR_ROLE, &admin);
        }
    }

    // ── Circuit-breaker management ────────────────────────────────────────

    /// Sets the per-token emergency budget (maximum aggregate outflow within
    /// any rolling 1-hour window). Manager-gated.
    ///
    /// Once set, every successful `forward` for `token` accumulates toward
    /// this cap. When the running total exceeds `budget` the circuit breaker
    /// trips, all further `forward` calls for that token revert with
    /// [`FeeForwarderError::CircuitBreakerTripped`], and the manager must
    /// call [`reset_circuit_breaker`] to resume.
    ///
    /// # Errors
    ///
    /// * [`FeeForwarderError::InvalidBudget`] - If `budget` is not strictly
    ///   positive.
    #[only_role(operator, "manager")]
    pub fn set_emergency_budget(e: &Env, token: Address, budget: i128, operator: Address) {
        if budget <= 0 {
            panic_with_error!(e, FeeForwarderError::InvalidBudget);
        }
        e.storage()
            .instance()
            .set(&FeeForwarderStorageKey::EmergencyBudget(token), &budget);
    }

    /// Clears the tripped state for `token`, re-enabling `forward` calls and
    /// resetting the outflow window. Manager-gated.
    #[only_role(operator, "manager")]
    pub fn reset_circuit_breaker(e: &Env, token: Address, operator: Address) {
        e.storage()
            .instance()
            .remove(&FeeForwarderStorageKey::CircuitBreakerPaused(token.clone()));
        e.storage()
            .instance()
            .remove(&FeeForwarderStorageKey::HourlyOutflow(token.clone()));
        CircuitBreakerReset { token }.publish(e);
    }

    /// Returns `true` if the circuit breaker is currently tripped for `token`.
    pub fn get_circuit_breaker_paused(e: &Env, token: Address) -> bool {
        e.storage()
            .instance()
            .get::<_, bool>(&FeeForwarderStorageKey::CircuitBreakerPaused(token))
            .unwrap_or(false)
    }

    /// Returns the current rolling-window outflow data for `token`, or `None`
    /// if no outflow has been recorded yet.
    pub fn get_hourly_outflow(e: &Env, token: Address) -> Option<HourlyOutflowData> {
        e.storage()
            .instance()
            .get(&FeeForwarderStorageKey::HourlyOutflow(token))
    }

    // ── Core forwarding ───────────────────────────────────────────────────

    /// Collects `fee_amount` of `fee_token` from `user` and forwards the
    /// call to `target_contract.target_fn(target_args)`, atomically.
    ///
    /// Requires authorization from both `user` (covering `fee_token`,
    /// `max_fee_amount`, `expiration_ledger`, and the target call — not
    /// `fee_amount` or `relayer`, which are only known once the executor
    /// picks up the request) and `relayer` (who must hold the `executor`
    /// role).
    ///
    /// # Errors
    ///
    /// * [`FeeForwarderError::CircuitBreakerTripped`] - If the circuit breaker
    ///   has been tripped for `fee_token` (checked before the fee is collected,
    ///   and can also trip on this very call when the new total exceeds the
    ///   budget).
    /// * [`stellar_fee_abstraction::FeeAbstractionError::FeeTokenNotAllowed`]
    ///   - If `fee_token` is not on the allowlist (once the allowlist is
    ///     enabled).
    /// * [`stellar_fee_abstraction::FeeAbstractionError::InvalidFeeBounds`] -
    ///   If `fee_amount` is `<= 0` or exceeds `max_fee_amount`.
    /// * [`stellar_access::access_control::AccessControlError::Unauthorized`]
    ///   - If `relayer` does not hold the `executor` role.
    // 10 args is inherent to this entrypoint's shape: it mirrors OZ's audited
    // `collect_fee_and_invoke` parameter list plus `relayer` for
    // `#[only_role]`'s role check. Splitting into a struct would diverge from
    // the audited reference and from the ABI the companion latch-relayer
    // issue builds its off-chain signing/submission against.
    #[allow(clippy::too_many_arguments)]
    #[only_role(relayer, "executor")]
    pub fn forward(
        e: &Env,
        fee_token: Address,
        fee_amount: i128,
        max_fee_amount: i128,
        expiration_ledger: u32,
        target_contract: Address,
        target_fn: Symbol,
        target_args: Vec<Val>,
        user: Address,
        relayer: Address,
    ) -> Val {
        // Reject immediately if the circuit breaker is already tripped.
        let paused_key = FeeForwarderStorageKey::CircuitBreakerPaused(fee_token.clone());
        if e.storage().instance().get::<_, bool>(&paused_key).unwrap_or(false) {
            panic_with_error!(e, FeeForwarderError::CircuitBreakerTripped);
        }

        let result = collect_fee_and_invoke(
            e,
            &fee_token,
            fee_amount,
            max_fee_amount,
            expiration_ledger,
            &target_contract,
            &target_fn,
            &target_args,
            &user,
            &e.current_contract_address(),
            FeeAbstractionApproval::Lazy,
        );

        // Update rolling outflow window and check the emergency budget (if
        // one is configured for this token). The budget check runs after a
        // successful fee collection so that the tripping transaction itself
        // is still reverted — once the event fires and the panic runs, the
        // whole invocation unwinds.
        let budget_key = FeeForwarderStorageKey::EmergencyBudget(fee_token.clone());
        if let Some(budget) = e.storage().instance().get::<_, i128>(&budget_key) {
            let now = e.ledger().timestamp();
            let outflow_key = FeeForwarderStorageKey::HourlyOutflow(fee_token.clone());

            let mut outflow: HourlyOutflowData = e
                .storage()
                .instance()
                .get(&outflow_key)
                .unwrap_or(HourlyOutflowData { total_amount: 0, window_start: now });

            // Roll the window forward if more than an hour has elapsed.
            if now.saturating_sub(outflow.window_start) >= HOUR_IN_SECS {
                outflow.total_amount = 0;
                outflow.window_start = now;
            }

            outflow.total_amount = outflow.total_amount.saturating_add(fee_amount);
            e.storage().instance().set(&outflow_key, &outflow);

            if outflow.total_amount > budget {
                // Trip the breaker so subsequent calls are rejected immediately.
                e.storage().instance().set(&paused_key, &true);
                CircuitBreakerTripped {
                    token: fee_token,
                    total_amount: outflow.total_amount,
                    emergency_budget: budget,
                }
                .publish(e);
                panic_with_error!(e, FeeForwarderError::CircuitBreakerTripped);
            }
        }

        result
    }

    /// Adds `token` to the fee-token allowlist. Manager-gated.
    #[only_role(operator, "manager")]
    pub fn enable_fee_token(e: &Env, token: Address, operator: Address) {
        set_allowed_fee_token(e, &token, true);
    }

    /// Removes `token` from the fee-token allowlist. Manager-gated.
    #[only_role(operator, "manager")]
    pub fn disable_fee_token(e: &Env, token: Address, operator: Address) {
        set_allowed_fee_token(e, &token, false);
    }

    /// Transfers this contract's entire balance of `token` to `recipient`.
    /// Manager-gated. Returns the amount swept.
    #[only_role(operator, "manager")]
    pub fn sweep_tokens(e: &Env, token: Address, recipient: Address, operator: Address) -> i128 {
        sweep_token(e, &token, &recipient)
    }
}

#[contractimpl(contracttrait)]
impl AccessControl for FeeForwarder {}

#[cfg(test)]
mod test;
