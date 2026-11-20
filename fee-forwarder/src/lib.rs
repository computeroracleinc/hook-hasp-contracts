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
//! - `enable_fee_token` / `disable_fee_token` — manager-gated allowlist
//!   management for which tokens `forward` accepts as a fee. The allowlist is
//!   disabled (all tokens accepted) until the first token is enabled — see
//!   `stellar_fee_abstraction::is_allowed_fee_token`.
//! - `sweep_tokens` — manager-gated withdrawal of fees this contract has
//!   collected to the configured treasury address. The treasury address is
//!   governed by a two-step timelock: `propose_treasury` starts the clock,
//!   and `execute_treasury_change` completes the redirect only after
//!   `TREASURY_TIMELOCK_LEDGERS` have elapsed. The current treasury may be
//!   queried via `get_treasury`. See the treasury-timelock section below.
//!
//! # Treasury Timelock
//!
//! Redirecting swept fees to a new address is a high-impact operation. A
//! compromised manager key must not be able to instantly drain the contract.
//! The two-step timelock enforces a mandatory delay:
//!
//! 1. Manager calls `propose_treasury(new_treasury)` — stores the proposal
//!    with `eligible_ledger = current_ledger + TREASURY_TIMELOCK_LEDGERS`.
//! 2. After `TREASURY_TIMELOCK_LEDGERS` ledgers pass, manager calls
//!    `execute_treasury_change()` — activates the new treasury.
//! 3. Manager may call `cancel_treasury_change()` at any time before execution
//!    to discard a pending proposal (e.g. if it was submitted in error).
//!
//! `sweep_tokens` sends fees to the current active treasury. If no treasury
//! has been set yet, `sweep_tokens` requires the caller to pass `recipient`
//! directly (legacy behaviour, unchanged). Once a treasury is set via the
//! timelock, `recipient` is ignored — fees always go to the active treasury.
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
    contract, contractimpl, contracttype, symbol_short, Address, Env, Symbol, Val, Vec,
};
use stellar_access::access_control::{grant_role_no_auth, set_admin, AccessControl};
use stellar_fee_abstraction::{
    collect_fee_and_invoke, set_allowed_fee_token, sweep_token, FeeAbstractionApproval,
};
use stellar_macros::only_role;

const MANAGER_ROLE: Symbol = symbol_short!("manager");
const EXECUTOR_ROLE: Symbol = symbol_short!("executor");

/// Mandatory delay, in ledgers, between proposing a new treasury address
/// and being able to execute the change. At ~5 s per ledger this is roughly
/// 24 hours, giving operators time to detect and cancel a rogue proposal.
const TREASURY_TIMELOCK_LEDGERS: u32 = 17_280;

/// Storage keys for treasury-timelock state.
#[contracttype]
enum DataKey {
    /// The active treasury address. Absent until the first successful
    /// `execute_treasury_change`.
    Treasury,
    /// A pending proposal: `(new_treasury, eligible_ledger)`.
    PendingTreasury,
}

/// A pending treasury-change proposal.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct TreasuryProposal {
    /// The proposed new treasury address.
    pub new_treasury: Address,
    /// The earliest ledger sequence at which `execute_treasury_change` may
    /// be called.
    pub eligible_ledger: u32,
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

    /// Transfers this contract's entire balance of `token` to the active
    /// treasury address (if one has been set via the timelock) or to
    /// `recipient` if no treasury is configured. Manager-gated.
    /// Returns the amount swept.
    #[only_role(operator, "manager")]
    pub fn sweep_tokens(e: &Env, token: Address, recipient: Address, operator: Address) -> i128 {
        let destination = e
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::Treasury)
            .unwrap_or(recipient);
        sweep_token(e, &token, &destination)
    }

    // ── Treasury timelock ────────────────────────────────────────────────────

    /// Proposes a new treasury address. The change becomes eligible for
    /// execution after `TREASURY_TIMELOCK_LEDGERS` ledgers. Manager-gated.
    ///
    /// Any previously pending (unexecuted) proposal is overwritten.
    #[only_role(operator, "manager")]
    pub fn propose_treasury(e: &Env, new_treasury: Address, operator: Address) {
        let eligible_ledger = e.ledger().sequence() + TREASURY_TIMELOCK_LEDGERS;
        e.storage().instance().set(
            &DataKey::PendingTreasury,
            &TreasuryProposal { new_treasury, eligible_ledger },
        );
    }

    /// Executes a pending treasury proposal, activating the new treasury
    /// address. Reverts if no proposal exists or the timelock delay has not
    /// yet elapsed. Manager-gated.
    #[only_role(operator, "manager")]
    pub fn execute_treasury_change(e: &Env, operator: Address) {
        let proposal = e
            .storage()
            .instance()
            .get::<DataKey, TreasuryProposal>(&DataKey::PendingTreasury)
            .unwrap_or_else(|| panic!("no pending treasury proposal"));

        if e.ledger().sequence() < proposal.eligible_ledger {
            panic!("treasury timelock has not elapsed");
        }

        e.storage().instance().set(&DataKey::Treasury, &proposal.new_treasury);
        e.storage().instance().remove(&DataKey::PendingTreasury);
    }

    /// Cancels a pending treasury proposal without executing it. Manager-gated.
    /// Reverts if no proposal exists.
    #[only_role(operator, "manager")]
    pub fn cancel_treasury_change(e: &Env, operator: Address) {
        if !e.storage().instance().has(&DataKey::PendingTreasury) {
            panic!("no pending treasury proposal");
        }
        e.storage().instance().remove(&DataKey::PendingTreasury);
    }

    /// Returns the pending treasury proposal, if any.
    pub fn get_pending_treasury(e: &Env) -> Option<TreasuryProposal> {
        e.storage().instance().get(&DataKey::PendingTreasury)
    }

    /// Returns the active treasury address, if one has been set.
    pub fn get_treasury(e: &Env) -> Option<Address> {
        e.storage().instance().get(&DataKey::Treasury)
    }
}

#[contractimpl(contracttrait)]
impl AccessControl for FeeForwarder {}

#[cfg(test)]
mod test;
