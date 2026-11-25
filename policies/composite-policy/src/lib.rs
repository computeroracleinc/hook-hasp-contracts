//! Composite (AND) policy pipeline for Latch smart accounts.
//!
//! Chains multiple independently-deployed policy contracts together so that
//! **all** of them must approve a call before it is authorized. Install this
//! policy on a context rule alongside (or instead of) individual policies
//! when you want a logical AND across several policy contracts — for example,
//! "SessionPolicy AND SpendingLimitPolicy must both pass".
//!
//! # How it works
//!
//! - `install(params, context_rule, smart_account)` — stores an ordered list
//!   of policy contract addresses for the `(smart_account, context_rule)`
//!   pair. Each address must be a deployed policy contract that implements
//!   the `Policy` trait interface.
//! - `enforce(context, signers, context_rule, smart_account)` — calls
//!   `policy.enforce(context, signers, context_rule, smart_account)` on
//!   every registered policy contract in order. The evaluation short-circuits
//!   on the first panic; if all policies pass, the call is authorized.
//! - `uninstall(context_rule, smart_account)` — removes the stored policy
//!   list; individual member policies are **not** uninstalled automatically.
//! - `get_policies(context_rule_id, smart_account)` — returns the ordered
//!   list of policy contract addresses for a given installation.
//!
//! # Design constraints
//!
//! - **AND semantics only.** Every policy in the pipeline must approve; there
//!   is no OR path. For OR semantics, install separate context rules.
//! - **No circular references.** A composite policy must not list itself or
//!   another composite policy that transitively references it; doing so would
//!   cause infinite recursion. The contract does not detect cycles — it is the
//!   installer's responsibility to avoid them.
//! - **Member policies must share the same `smart_account`.** Each cross-
//!   contract `enforce` call passes the same `smart_account` and
//!   `context_rule`, so member policies must have been installed for that
//!   exact pair.
//! - **Bounded pipeline length.** At most [`MAX_POLICIES`] policy contracts
//!   may be chained; `install` rejects a longer list.
#![no_std]

use soroban_sdk::{
    auth::Context, contract, contracterror, contractevent, contractimpl, contracttype,
    panic_with_error, Address, Env, Symbol, Vec,
};
use stellar_accounts::{
    policies::Policy,
    smart_account::{ContextRule, Signer},
};

// ── Constants ─────────────────────────────────────────────────────────────────

const DAY_IN_LEDGERS: u32 = 17280;
const COMPOSITE_EXTEND_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
const COMPOSITE_TTL_THRESHOLD: u32 = COMPOSITE_EXTEND_AMOUNT - DAY_IN_LEDGERS;

/// Maximum number of policy contracts that may be chained in a single
/// composite pipeline. Bounds the cross-contract call fan-out on each
/// `enforce` invocation and the storage size of the policy list.
pub const MAX_POLICIES: u32 = 10;

// ── Errors ────────────────────────────────────────────────────────────────────

/// Error codes for composite policy operations.
///
/// This is a standalone, independently-deployed contract, not a module of
/// the upstream `stellar-accounts` crate, so it is not part of that crate's
/// shared error-numbering convention. Numbering starts fresh at `1`.
#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum CompositeError {
    /// The smart account does not have a composite policy installed for this
    /// context rule.
    NotInstalled = 1,
    /// `policies` was empty or exceeded [`MAX_POLICIES`].
    InvalidPolicies = 2,
    /// The composite policy was already installed for this smart account and
    /// context rule.
    AlreadyInstalled = 3,
}

// ── Storage ───────────────────────────────────────────────────────────────────

#[contracttype]
pub enum CompositeStorageKey {
    /// Stores the ordered list of member policy addresses for a
    /// `(smart_account, context_rule_id)` pair.
    AccountContext(Address, u32),
}

// ── Types ─────────────────────────────────────────────────────────────────────

/// Installation parameters for the composite policy.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CompositeAccountParams {
    /// Ordered list of policy contract addresses. All must approve for the
    /// composite policy to pass.
    pub policies: Vec<Address>,
}

// ── Events ────────────────────────────────────────────────────────────────────

/// Emitted when a composite policy pipeline is installed.
#[contractevent]
#[derive(Clone, Debug)]
pub struct CompositeInstalled {
    #[topic]
    pub smart_account: Address,
    pub context_rule_id: u32,
    pub policies: Vec<Address>,
}

/// Emitted when a composite policy pipeline is uninstalled.
#[contractevent]
#[derive(Clone, Debug)]
pub struct CompositeUninstalled {
    #[topic]
    pub smart_account: Address,
    pub context_rule_id: u32,
}

/// Emitted after all member policies have been successfully enforced.
#[contractevent]
#[derive(Clone)]
pub struct CompositeEnforced {
    #[topic]
    pub smart_account: Address,
    pub context_rule_id: u32,
    pub policy_count: u32,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn load_policies(e: &Env, context_rule_id: u32, smart_account: &Address) -> Vec<Address> {
    let key = CompositeStorageKey::AccountContext(smart_account.clone(), context_rule_id);
    e.storage()
        .persistent()
        .get(&key)
        .inspect(|_| {
            e.storage()
                .persistent()
                .extend_ttl(&key, COMPOSITE_TTL_THRESHOLD, COMPOSITE_EXTEND_AMOUNT);
        })
        .unwrap_or_else(|| panic_with_error!(e, CompositeError::NotInstalled))
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct CompositePolicy;

#[contractimpl]
impl Policy for CompositePolicy {
    type AccountParams = CompositeAccountParams;

    /// Stores the ordered list of member policy addresses for
    /// `(smart_account, context_rule)`. Requires authorization from the
    /// smart account.
    ///
    /// # Errors
    ///
    /// * [`CompositeError::InvalidPolicies`] — `policies` is empty or longer
    ///   than [`MAX_POLICIES`].
    /// * [`CompositeError::AlreadyInstalled`] — already installed for this
    ///   pair.
    ///
    /// # Events
    ///
    /// * topics — `["composite_installed", smart_account: Address]`
    /// * data — `[context_rule_id: u32, policies: Vec<Address>]`
    fn install(
        e: &Env,
        params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();

        if params.policies.is_empty() || params.policies.len() > MAX_POLICIES {
            panic_with_error!(e, CompositeError::InvalidPolicies);
        }

        let key =
            CompositeStorageKey::AccountContext(smart_account.clone(), context_rule.id);

        if e.storage().persistent().has(&key) {
            panic_with_error!(e, CompositeError::AlreadyInstalled);
        }

        e.storage().persistent().set(&key, &params.policies);

        CompositeInstalled {
            smart_account,
            context_rule_id: context_rule.id,
            policies: params.policies,
        }
        .publish(e);
    }

    /// Removes the stored policy list for `(smart_account, context_rule)`.
    /// Member policies are not uninstalled. Requires authorization from the
    /// smart account.
    ///
    /// # Errors
    ///
    /// * [`CompositeError::NotInstalled`] — not installed for this pair.
    ///
    /// # Events
    ///
    /// * topics — `["composite_uninstalled", smart_account: Address]`
    /// * data — `[context_rule_id: u32]`
    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();

        let key =
            CompositeStorageKey::AccountContext(smart_account.clone(), context_rule.id);

        if !e.storage().persistent().has(&key) {
            panic_with_error!(e, CompositeError::NotInstalled);
        }

        e.storage().persistent().remove(&key);

        CompositeUninstalled { smart_account, context_rule_id: context_rule.id }.publish(e);
    }

    /// Calls `enforce` on every member policy in order. The first policy that
    /// panics stops evaluation and the whole call is rejected. If all pass,
    /// emits [`CompositeEnforced`]. Requires authorization from the smart
    /// account.
    ///
    /// # Errors
    ///
    /// * [`CompositeError::NotInstalled`] — not installed for this pair.
    /// * Any error from a member policy — propagated as-is.
    ///
    /// # Events
    ///
    /// * topics — `["composite_enforced", smart_account: Address]`
    /// * data — `[context_rule_id: u32, policy_count: u32]`
    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();

        let policies = load_policies(e, context_rule.id, &smart_account);
        let policy_count = policies.len();

        for policy_address in policies.iter() {
            let client = PolicyClient::new(e, &policy_address);
            client.enforce(
                &context,
                &authenticated_signers,
                &context_rule,
                &smart_account,
            );
        }

        CompositeEnforced {
            smart_account,
            context_rule_id: context_rule.id,
            policy_count,
        }
        .publish(e);
    }
}

#[contractimpl]
impl CompositePolicy {
    /// Returns the ordered list of member policy addresses for a given
    /// `(smart_account, context_rule_id)` installation.
    ///
    /// # Errors
    ///
    /// * [`CompositeError::NotInstalled`] — not installed for this pair.
    pub fn get_policies(
        e: &Env,
        context_rule_id: u32,
        smart_account: Address,
    ) -> Vec<Address> {
        load_policies(e, context_rule_id, &smart_account)
    }
}

// ── Cross-contract client ─────────────────────────────────────────────────────

/// Minimal cross-contract client for calling `enforce` on any deployed
/// policy contract that implements the `Policy` trait interface.
#[soroban_sdk::contractclient(name = "PolicyClient")]
pub trait PolicyInterface {
    fn enforce(
        e: &Env,
        context: &Context,
        authenticated_signers: &Vec<Signer>,
        context_rule: &ContextRule,
        smart_account: &Address,
    );
}

#[cfg(test)]
mod test;
