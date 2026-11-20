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
//! # Security Warning
//!
//! `collect_fee_and_invoke` only authorizes the user's *input* — it does not
//! vet whether the forwarded call is safe for the user to make. Simulating
//! the outcome of `target_contract.target_fn(target_args)` before signing is
//! the invoker's (the account's own signer's) responsibility, same as any
//! other authorization the account signs.
#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Symbol, Val, Vec};
use stellar_access::access_control::{grant_role_no_auth, set_admin, AccessControl};
use stellar_fee_abstraction::{
    collect_fee_and_invoke, set_allowed_fee_token, sweep_token, FeeAbstractionApproval,
};
use stellar_macros::only_role;

const MANAGER_ROLE: Symbol = symbol_short!("manager");
const EXECUTOR_ROLE: Symbol = symbol_short!("executor");
const GAS_TIER_KEY: Symbol = symbol_short!("gastier");

/// Configuration for tiered relayer refund rates.
///
/// The refund for a given `gas_used` is:
///   `base_fee + gas_used * multiplier / 1_000`
///
/// where `multiplier` is the per-mille value from `tier_multipliers` whose
/// corresponding threshold in `tier_thresholds` is the highest one still
/// `<= gas_used`. Both vecs must have the same length; thresholds must be
/// provided in ascending order.
#[contracttype]
#[derive(Clone)]
pub struct GasTierConfig {
    /// Flat base component added to every refund regardless of gas consumed.
    pub base_fee: i128,
    /// Gas-unit thresholds (CPU instructions) at which each tier begins,
    /// in ascending order. Must be the same length as `tier_multipliers`.
    pub tier_thresholds: Vec<u64>,
    /// Per-mille multipliers (divide by 1_000) applied to `gas_used` within
    /// the matching tier. Must be the same length as `tier_thresholds`.
    pub tier_multipliers: Vec<u32>,
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

    // ── tiered relayer refund rates ──────────────────────────────────────────

    /// Stores the gas-tier configuration used by `compute_tiered_refund`.
    /// Manager-gated.
    ///
    /// `tier_thresholds` and `tier_multipliers` must have the same length and
    /// thresholds must be in ascending order. The multipliers are per-mille
    /// values (divide by 1_000); e.g. `5` means ×0.005 per gas unit.
    #[only_role(operator, "manager")]
    pub fn set_gas_tier_config(
        e: &Env,
        base_fee: i128,
        tier_thresholds: Vec<u64>,
        tier_multipliers: Vec<u32>,
        operator: Address,
    ) {
        let config = GasTierConfig { base_fee, tier_thresholds, tier_multipliers };
        e.storage().instance().set(&GAS_TIER_KEY, &config);
    }

    /// Returns the current gas-tier configuration, or `None` if not yet set.
    pub fn get_gas_tier_config(e: &Env) -> Option<GasTierConfig> {
        e.storage().instance().get(&GAS_TIER_KEY)
    }

    /// Computes the tiered refund amount for `gas_used` CPU instructions.
    ///
    /// Formula: `base_fee + gas_used * multiplier / 1_000`, where
    /// `multiplier` is taken from the highest tier whose threshold is
    /// `<= gas_used`. Returns `0` when no configuration has been stored.
    pub fn compute_tiered_refund(e: &Env, gas_used: u64) -> i128 {
        let config: GasTierConfig = match e.storage().instance().get(&GAS_TIER_KEY) {
            Some(c) => c,
            None => return 0,
        };

        // Walk the tiers in order; keep updating the multiplier for every
        // threshold that gas_used has crossed.
        let mut multiplier: u32 = config.tier_multipliers.get(0).unwrap_or(0);
        let len = config.tier_thresholds.len();
        for i in 0..len {
            let threshold: u64 = config.tier_thresholds.get(i).unwrap_or(u64::MAX);
            if gas_used >= threshold {
                multiplier = config.tier_multipliers.get(i).unwrap_or(multiplier);
            }
        }

        config.base_fee + (gas_used as i128) * (multiplier as i128) / 1_000
    }
}

#[contractimpl(contracttrait)]
impl AccessControl for FeeForwarder {}

#[cfg(test)]
mod test;
