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
//!   `fee_amount` is additionally capped at `MAX_FEE_CAP` stroops; any
//!   transaction whose fee exceeds the global cap is rejected before the fee
//!   is collected, preventing relayer griefing of the fee sponsor treasury.
//! - `enable_fee_token` / `disable_fee_token` — manager-gated allowlist
//!   management for which tokens `forward` accepts as a fee. The allowlist is
//!   disabled (all tokens accepted) until the first token is enabled — see
//!   `stellar_fee_abstraction::is_allowed_fee_token`.
//! - `sweep_tokens` — manager-gated withdrawal of fees this contract has
//!   collected.
//! - `set_fee_cap` — manager-gated override of `MAX_FEE_CAP`. The cap
//!   defaults to [`DEFAULT_FEE_CAP`] at construction and can be tightened or
//!   relaxed by the manager at any time.
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
    contract, contractimpl, contracterror, contracttype, panic_with_error, symbol_short, Address,
    Env, Symbol, Val, Vec,
};
use stellar_access::access_control::{grant_role_no_auth, set_admin, AccessControl};
use stellar_fee_abstraction::{
    collect_fee_and_invoke, set_allowed_fee_token, sweep_token, FeeAbstractionApproval,
};
use stellar_macros::only_role;

const MANAGER_ROLE: Symbol = symbol_short!("manager");
const EXECUTOR_ROLE: Symbol = symbol_short!("executor");

/// Default maximum fee per sponsored transaction, in stroops (0.1 XLM).
/// Prevents a rogue relayer from draining the sponsor treasury through a
/// single oversized transaction before the manager can react.
pub const DEFAULT_FEE_CAP: i128 = 1_000_000;

/// Storage key for the configurable fee cap.
#[contracttype]
pub enum FeeForwarderStorageKey {
    FeeCap,
}

/// Error codes specific to the fee-forwarder contract.
#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum FeeForwarderError {
    /// `fee_amount` exceeds the per-transaction `MAX_FEE_CAP`. The relayer
    /// must resubmit with a fee at or below the cap.
    FeeCapExceeded = 1,
    /// `fee_cap` passed to `set_fee_cap` must be strictly positive.
    InvalidFeeCap = 2,
}

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

        env.storage().instance().set(&FeeForwarderStorageKey::FeeCap, &DEFAULT_FEE_CAP);
    }

    /// Returns the current per-transaction fee cap in stroops.
    pub fn get_fee_cap(e: &Env) -> i128 {
        e.storage()
            .instance()
            .get(&FeeForwarderStorageKey::FeeCap)
            .unwrap_or(DEFAULT_FEE_CAP)
    }

    /// Updates the per-transaction fee cap. Manager-gated.
    ///
    /// # Errors
    ///
    /// * [`FeeForwarderError::InvalidFeeCap`] - If `fee_cap` is not strictly
    ///   positive.
    #[only_role(operator, "manager")]
    pub fn set_fee_cap(e: &Env, fee_cap: i128, operator: Address) {
        if fee_cap <= 0 {
            panic_with_error!(e, FeeForwarderError::InvalidFeeCap);
        }
        e.storage().instance().set(&FeeForwarderStorageKey::FeeCap, &fee_cap);
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
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `fee_token` - The address of the token used to pay the forwarding fee.
    /// * `fee_amount` - The fee charged to the user.
    /// * `max_fee_amount` - The maximum allowable fee authorized by the user.
    /// * `expiration_ledger` - The ledger sequence after which the authorization expires.
    /// * `target_contract` - The address of the destination contract to invoke.
    /// * `target_fn` - The name of the destination function to call.
    /// * `target_args` - Arguments passed to the destination function.
    /// * `user` - The user authorizing the fee payment and destination call.
    /// * `relayer` - The relayer submitting the call (must have `executor` role).
    ///
    /// # Returns
    ///
    /// Returns the result of invoking `target_contract.target_fn(target_args)`.
    ///
    /// # Errors
    ///
    /// * [`FeeForwarderError::FeeCapExceeded`] - If `fee_amount` exceeds the
    ///   configured per-transaction fee cap.
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
        let fee_cap = e
            .storage()
            .instance()
            .get(&FeeForwarderStorageKey::FeeCap)
            .unwrap_or(DEFAULT_FEE_CAP);

        if fee_amount > fee_cap {
            panic_with_error!(e, FeeForwarderError::FeeCapExceeded);
        }

        collect_fee_and_invoke(
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
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `token` - The address of the fee token to allow.
    /// * `operator` - The address performing the action (must hold the `manager` role).
    ///
    /// # Errors
    ///
    /// * [`stellar_access::access_control::AccessControlError::Unauthorized`] - If `operator` lacks `manager` role.
    #[only_role(operator, "manager")]
    pub fn enable_fee_token(e: &Env, token: Address, operator: Address) {
        set_allowed_fee_token(e, &token, true);
    }

    /// Removes `token` from the fee-token allowlist. Manager-gated.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `token` - The address of the fee token to disallow.
    /// * `operator` - The address performing the action (must hold the `manager` role).
    ///
    /// # Errors
    ///
    /// * [`stellar_access::access_control::AccessControlError::Unauthorized`] - If `operator` lacks `manager` role.
    #[only_role(operator, "manager")]
    pub fn disable_fee_token(e: &Env, token: Address, operator: Address) {
        set_allowed_fee_token(e, &token, false);
    }

    /// Transfers this contract's entire balance of `token` to `recipient`.
    /// Manager-gated. Returns the amount swept.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `token` - The token to sweep.
    /// * `recipient` - The destination address for swept tokens.
    /// * `operator` - The address performing the action (must hold the `manager` role).
    ///
    /// # Returns
    ///
    /// The total amount of `token` swept to `recipient`.
    ///
    /// # Errors
    ///
    /// * [`stellar_access::access_control::AccessControlError::Unauthorized`] - If `operator` lacks `manager` role.
    #[only_role(operator, "manager")]
    pub fn sweep_tokens(e: &Env, token: Address, recipient: Address, operator: Address) -> i128 {
        sweep_token(e, &token, &recipient)
    }
}

#[contractimpl(contracttrait)]
impl AccessControl for FeeForwarder {}

#[cfg(test)]
mod test;

#[cfg(test)]
mod fuzz_test;
