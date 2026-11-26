//! Composite (AND) policy pipeline for Latch smart accounts.
//!
//! Chains multiple independently-deployed policy contracts together so that
//! **all** of them must approve a call before it is authorized.
//!
//! # Hardening
//!
//! - Rejects empty pipelines, pipelines exceeding [`MAX_POLICIES`], duplicate
//!   policy addresses, and direct self-references (`policy == current_contract`)
//!   at `install` time.
//! - Extends persistent storage TTL immediately upon `install` and on every
//!   read.
#![no_std]

use soroban_sdk::{
    auth::Context, contract, contracterror, contractevent, contractimpl, contracttype,
    panic_with_error, Address, Env, Vec,
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
/// composite pipeline.
pub const MAX_POLICIES: u32 = 10;

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum CompositeError {
    /// The smart account does not have a composite policy installed for this
    /// context rule.
    NotInstalled = 1,
    /// `policies` was empty, exceeded [`MAX_POLICIES`], contained duplicates,
    /// or referenced this composite policy contract itself.
    InvalidPolicies = 2,
    /// The composite policy was already installed for this smart account and
    /// context rule.
    AlreadyInstalled = 3,
}

// ── Storage ───────────────────────────────────────────────────────────────────

#[contracttype]
pub enum CompositeStorageKey {
    AccountContext(Address, u32),
}

// ── Types ─────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct CompositeAccountParams {
    pub policies: Vec<Address>,
}

// ── Events ────────────────────────────────────────────────────────────────────

#[contractevent]
#[derive(Clone, Debug)]
pub struct CompositeInstalled {
    #[topic]
    pub smart_account: Address,
    pub context_rule_id: u32,
    pub policies: Vec<Address>,
}

#[contractevent]
#[derive(Clone, Debug)]
pub struct CompositeUninstalled {
    #[topic]
    pub smart_account: Address,
    pub context_rule_id: u32,
}

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

    fn install(
        e: &Env,
        params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();

        let len = params.policies.len();
        if len == 0 || len > MAX_POLICIES {
            panic_with_error!(e, CompositeError::InvalidPolicies);
        }

        // Reject direct self-references and duplicate policy addresses.
        let self_addr = e.current_contract_address();
        for i in 0..len {
            let Some(addr) = params.policies.get(i) else {
                panic_with_error!(e, CompositeError::InvalidPolicies);
            };
            if addr == self_addr {
                panic_with_error!(e, CompositeError::InvalidPolicies);
            }
            for j in (i + 1)..len {
                if params.policies.get(j).as_ref() == Some(&addr) {
                    panic_with_error!(e, CompositeError::InvalidPolicies);
                }
            }
        }

        let key = CompositeStorageKey::AccountContext(smart_account.clone(), context_rule.id);

        if e.storage().persistent().has(&key) {
            panic_with_error!(e, CompositeError::AlreadyInstalled);
        }

        e.storage().persistent().set(&key, &params.policies);
        e.storage()
            .persistent()
            .extend_ttl(&key, COMPOSITE_TTL_THRESHOLD, COMPOSITE_EXTEND_AMOUNT);

        CompositeInstalled {
            smart_account,
            context_rule_id: context_rule.id,
            policies: params.policies,
        }
        .publish(e);
    }

    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();

        let key = CompositeStorageKey::AccountContext(smart_account.clone(), context_rule.id);

        if !e.storage().persistent().has(&key) {
            panic_with_error!(e, CompositeError::NotInstalled);
        }

        e.storage().persistent().remove(&key);

        CompositeUninstalled { smart_account, context_rule_id: context_rule.id }.publish(e);
    }

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
            client.enforce(&context, &authenticated_signers, &context_rule, &smart_account);
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
    pub fn get_policies(
        e: &Env,
        context_rule_id: u32,
        smart_account: Address,
    ) -> Vec<Address> {
        load_policies(e, context_rule_id, &smart_account)
    }
}

// ── Cross-contract client ─────────────────────────────────────────────────────

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
