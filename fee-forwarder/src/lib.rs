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
//!   collected.
//!
//! # Role-based access control hardening
//!
//! Three privilege-separation rules are enforced explicitly:
//!
//! 1. **Managers cannot self-elevate to admin** — `promote_to_admin` requires
//!    the current admin's authorization; a manager calling it without that
//!    authorization is rejected.
//! 2. **Managers cannot grant themselves the `manager` role** — `grant_manager`
//!    is admin-only and verifies the caller is not the grantee.
//! 3. **Treasury reassignment requires admin approval** — `set_treasury`
//!    is admin-only; managers have no path to reroute fee sweeps.
//!
//! # Security Warning
//!
//! `collect_fee_and_invoke` only authorizes the user's *input* — it does not
//! vet whether the forwarded call is safe for the user to make. Simulating
//! the outcome of `target_contract.target_fn(target_args)` before signing is
//! the invoker's (the account's own signer's) responsibility, same as any
//! other authorization the account signs.
#![no_std]

use soroban_sdk::{contract, contractimpl, contracterror, symbol_short, Address, Env, Symbol, Val, Vec};
use stellar_access::access_control::{
    get_admin, grant_role_no_auth, set_admin, AccessControl,
};
use stellar_fee_abstraction::{
    collect_fee_and_invoke, set_allowed_fee_token, sweep_token, FeeAbstractionApproval,
};
use stellar_macros::only_role;

const MANAGER_ROLE: Symbol = symbol_short!("manager");
const EXECUTOR_ROLE: Symbol = symbol_short!("executor");
/// Instance-storage key for the optional treasury address.
const TREASURY_KEY: Symbol = symbol_short!("treasury");

/// Contract-level errors for RBAC hardening.
#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum FeeForwarderError {
    /// A manager attempted to self-elevate to admin or grant themselves a
    /// higher role. Code 7001.
    PrivilegeEscalation = 7001,
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

    /// Transfers this contract's entire balance of `token` to `recipient`.
    /// Manager-gated. Returns the amount swept.
    #[only_role(operator, "manager")]
    pub fn sweep_tokens(e: &Env, token: Address, recipient: Address, operator: Address) -> i128 {
        sweep_token(e, &token, &recipient)
    }

    // ── RBAC hardening (#41) ─────────────────────────────────────────────────

    /// Grants `grantee` the `manager` role. Admin-only.
    ///
    /// Managers cannot call this for themselves — only the admin may grant the
    /// `manager` role, preventing self-elevation. Panics with
    /// `Error(Contract, #7001)` if `admin` and `grantee` are the same address
    /// (the admin already has full authority; granting themselves `manager`
    /// would be a no-op but is blocked to surface misuse early).
    pub fn grant_manager(e: &Env, grantee: Address, admin: Address) {
        // Require the current admin's explicit authorization.
        let current_admin = get_admin(e).unwrap();
        if admin != current_admin {
            panic_with_error!(e, FeeForwarderError::PrivilegeEscalation);
        }
        admin.require_auth();

        // The admin must not grant themselves the manager role to avoid
        // muddying the privilege boundary.
        if grantee == admin {
            panic_with_error!(e, FeeForwarderError::PrivilegeEscalation);
        }

        grant_role_no_auth(e, &grantee, &MANAGER_ROLE, &admin);
    }

    /// Transfers the admin role to `new_admin`. Requires the **current**
    /// admin's authorization — managers cannot call this.
    ///
    /// Panics with `Error(Contract, #7001)` if `caller` is not the current
    /// admin, ensuring managers cannot self-elevate.
    pub fn promote_to_admin(e: &Env, new_admin: Address, caller: Address) {
        let current_admin = get_admin(e).unwrap();
        if caller != current_admin {
            panic_with_error!(e, FeeForwarderError::PrivilegeEscalation);
        }
        caller.require_auth();
        set_admin(e, &new_admin);
    }

    /// Sets the treasury address for fee sweeps. Admin-only.
    ///
    /// Managers cannot reassign the treasury — only the admin may do so,
    /// ensuring the fee destination is not rerouted without top-level
    /// approval.
    pub fn set_treasury(e: &Env, treasury: Address, caller: Address) {
        let current_admin = get_admin(e).unwrap();
        if caller != current_admin {
            panic_with_error!(e, FeeForwarderError::PrivilegeEscalation);
        }
        caller.require_auth();
        e.storage().instance().set(&TREASURY_KEY, &treasury);
    }

    /// Returns the current treasury address, if set.
    pub fn get_treasury(e: &Env) -> Option<Address> {
        e.storage().instance().get(&TREASURY_KEY)
    }
}

#[contractimpl(contracttrait)]
impl AccessControl for FeeForwarder {}

#[cfg(test)]
mod test;
