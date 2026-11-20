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
        )
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
