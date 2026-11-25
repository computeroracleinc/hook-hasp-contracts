#![cfg(test)]
extern crate std;

use soroban_sdk::{
    auth::{Context, ContractContext},
    contract, contractimpl,
    testutils::{Address as _, Events},
    vec, Address, Env, String, Vec,
};
use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

use crate::{CompositeAccountParams, CompositeError, CompositePolicy, CompositePolicyClient};

// ── Stub policies ─────────────────────────────────────────────────────────────
//
// PolicyAlwaysPass — enforce is a no-op; install/uninstall are no-ops.
// PolicyAlwaysFail — enforce always panics with a string.
//
// These are registered as real contracts so the composite can call them
// via cross-contract invocation.

#[contract]
pub struct PolicyAlwaysPass;

#[contractimpl]
impl PolicyAlwaysPass {
    pub fn enforce(
        _e: &Env,
        _context: Context,
        _authenticated_signers: Vec<Signer>,
        _context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();
        // passes unconditionally
    }

    pub fn install(
        _e: &Env,
        _context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();
    }

    pub fn uninstall(
        _e: &Env,
        _context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();
    }
}

#[contract]
pub struct PolicyAlwaysFail;

#[contractimpl]
impl PolicyAlwaysFail {
    pub fn enforce(
        _e: &Env,
        _context: Context,
        _authenticated_signers: Vec<Signer>,
        _context_rule: ContextRule,
        _smart_account: Address,
    ) {
        panic!("policy rejected")
    }

    pub fn install(
        _e: &Env,
        _context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_context_rule(e: &Env, target: &Address) -> ContextRule {
    let signer = Address::generate(e);
    let mut signers = Vec::new(e);
    signers.push_back(Signer::Delegated(signer));

    ContextRule {
        id: 1,
        context_type: ContextRuleType::CallContract(target.clone()),
        name: String::from_str(e, "composite-test"),
        signers,
        signer_ids: Vec::new(e),
        policies: Vec::new(e),
        policy_ids: Vec::new(e),
        valid_until: None,
    }
}

fn make_contract_context(e: &Env, target: &Address) -> Context {
    Context::Contract(ContractContext {
        contract: target.clone(),
        fn_name: soroban_sdk::Symbol::new(e, "transfer"),
        args: Vec::new(e),
    })
}

struct Setup<'a> {
    composite: CompositePolicyClient<'a>,
    pass_policy: Address,
    fail_policy: Address,
    smart_account: Address,
    context_rule: ContextRule,
    context: Context,
}

fn setup(e: &Env) -> Setup<'_> {
    let smart_account = Address::generate(e);
    let target = Address::generate(e);

    let composite_id = e.register(CompositePolicy, ());
    let pass_id = e.register(PolicyAlwaysPass, ());
    let fail_id = e.register(PolicyAlwaysFail, ());

    Setup {
        composite: CompositePolicyClient::new(e, &composite_id),
        pass_policy: pass_id,
        fail_policy: fail_id,
        smart_account: smart_account.clone(),
        context_rule: make_context_rule(e, &target),
        context: make_contract_context(e, &target),
    }
}

// ── install / uninstall ───────────────────────────────────────────────────────

#[test]
fn install_stores_policy_list() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let policies = vec![&e, s.pass_policy.clone()];
    s.composite.install(
        &CompositeAccountParams { policies: policies.clone() },
        &s.context_rule,
        &s.smart_account,
    );

    let stored = s.composite.get_policies(&s.context_rule.id, &s.smart_account);
    assert_eq!(stored, policies);
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn install_rejects_empty_policies() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.composite.install(
        &CompositeAccountParams { policies: Vec::new(&e) },
        &s.context_rule,
        &s.smart_account,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn install_rejects_duplicate_installation() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let params = CompositeAccountParams { policies: vec![&e, s.pass_policy.clone()] };
    s.composite.install(&params, &s.context_rule, &s.smart_account);
    s.composite.install(&params, &s.context_rule, &s.smart_account);
}

#[test]
fn uninstall_removes_policy_list() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.composite.install(
        &CompositeAccountParams { policies: vec![&e, s.pass_policy.clone()] },
        &s.context_rule,
        &s.smart_account,
    );
    s.composite.uninstall(&s.context_rule, &s.smart_account);

    let result = s.composite.try_get_policies(&s.context_rule.id, &s.smart_account);
    assert!(result.is_err());
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn uninstall_rejects_when_not_installed() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.composite.uninstall(&s.context_rule, &s.smart_account);
}

// ── enforce: pipeline evaluation ─────────────────────────────────────────────

#[test]
fn enforce_passes_when_all_policies_pass() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    // Two pass-through policies — both must be called.
    let second_pass = e.register(PolicyAlwaysPass, ());
    let policies = vec![&e, s.pass_policy.clone(), second_pass];

    s.composite.install(
        &CompositeAccountParams { policies },
        &s.context_rule,
        &s.smart_account,
    );

    s.composite.enforce(
        &s.context,
        &s.context_rule.signers,
        &s.context_rule,
        &s.smart_account,
    );

    // CompositeEnforced event should have been emitted.
    assert!(!e.events().all().events().is_empty());
}

#[test]
#[should_panic(expected = "policy rejected")]
fn enforce_fails_when_any_policy_fails() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    // Pass first, then fail — short-circuits on the failing one.
    let policies = vec![&e, s.pass_policy.clone(), s.fail_policy.clone()];
    s.composite.install(
        &CompositeAccountParams { policies },
        &s.context_rule,
        &s.smart_account,
    );

    s.composite.enforce(
        &s.context,
        &s.context_rule.signers,
        &s.context_rule,
        &s.smart_account,
    );
}

/// End-to-end test: SessionPolicy (pass stub) AND SpendingLimitPolicy (pass
/// stub) both evaluate simultaneously via the composite pipeline.
#[test]
fn enforce_end_to_end_two_active_policies_simultaneously() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    // Simulate "SessionPolicy AND SpendingLimitPolicy" with two independent
    // pass stubs registered as separate contracts, mirroring what two real
    // installed policy contracts would look like.
    let session_policy = e.register(PolicyAlwaysPass, ());
    let spending_limit_policy = e.register(PolicyAlwaysPass, ());

    let policies = vec![&e, session_policy, spending_limit_policy];

    s.composite.install(
        &CompositeAccountParams { policies: policies.clone() },
        &s.context_rule,
        &s.smart_account,
    );

    // Both policies are enforced in a single composite evaluate.
    s.composite.enforce(
        &s.context,
        &s.context_rule.signers,
        &s.context_rule,
        &s.smart_account,
    );

    let stored = s.composite.get_policies(&s.context_rule.id, &s.smart_account);
    assert_eq!(stored, policies);
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn enforce_rejects_when_not_installed() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.composite.enforce(
        &s.context,
        &s.context_rule.signers,
        &s.context_rule,
        &s.smart_account,
    );
}

// ── get_policies ──────────────────────────────────────────────────────────────

#[test]
fn get_policies_returns_correct_list() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let policies = vec![&e, s.pass_policy.clone()];
    s.composite.install(
        &CompositeAccountParams { policies: policies.clone() },
        &s.context_rule,
        &s.smart_account,
    );

    assert_eq!(
        s.composite.get_policies(&s.context_rule.id, &s.smart_account),
        policies
    );
}
