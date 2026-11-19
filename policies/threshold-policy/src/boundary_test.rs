#![cfg(test)]
extern crate std;

use soroban_sdk::{
    auth::Context,
    testutils::Address as _,
    Address, Env, IntoVal, String, Vec,
};
use stellar_accounts::{
    policies::{simple_threshold::SimpleThresholdAccountParams, Policy},
    smart_account::{ContextRule, ContextRuleType, Signer},
};

use crate::{ThresholdPolicy, ThresholdPolicyClient};

fn setup() -> (Env, Address, ThresholdPolicyClient<'static>) {
    let e = Env::default();
    e.mock_all_auths();
    let smart_account = Address::generate(&e);
    let policy_id = e.register(ThresholdPolicy, ());
    let client = ThresholdPolicyClient::new(&e, &policy_id);
    (e, smart_account, client)
}

fn create_context_rule_with_signers(e: &Env, count: usize) -> (ContextRule, Vec<Signer>) {
    let mut signers = Vec::new(e);
    for _ in 0..count {
        signers.push_back(Signer::Delegated(Address::generate(e)));
    }

    let rule = ContextRule {
        id: 1,
        context_type: ContextRuleType::CallContract(Address::generate(e)),
        name: String::from_str(e, "threshold_rule"),
        signers: signers.clone(),
        signer_ids: Vec::new(e),
        policies: Vec::new(e),
        policy_ids: Vec::new(e),
        valid_until: None,
    };
    (rule, signers)
}

// =========================================================================
// BOUNDARY TEST SUITE: Threshold boundaries (0, max, exact, overflow)
// =========================================================================

#[test]
fn test_threshold_boundary_exact_match() {
    let (e, smart_account, client) = setup();
    let (rule, signers) = create_context_rule_with_signers(&e, 3);

    client.install(
        &SimpleThresholdAccountParams { threshold: 3 },
        &rule,
        &smart_account,
    );

    assert_eq!(client.get_threshold(&rule.id, &smart_account), 3);

    // Enforce with exact 3 signers
    let dummy_context = Context::Contract(soroban_sdk::auth::ContractContext {
        contract: Address::generate(&e),
        fn_name: soroban_sdk::Symbol::new(&e, "test"),
        args: Vec::new(&e),
    });

    client.enforce(&dummy_context, &signers, &rule, &smart_account);
}

#[test]
#[should_panic]
fn test_threshold_boundary_zero_install_panics() {
    let (e, smart_account, client) = setup();
    let (rule, _) = create_context_rule_with_signers(&e, 3);

    // Threshold = 0 must panic (strictly positive required)
    client.install(
        &SimpleThresholdAccountParams { threshold: 0 },
        &rule,
        &smart_account,
    );
}

#[test]
#[should_panic]
fn test_threshold_boundary_exceeds_signer_count_panics() {
    let (e, smart_account, client) = setup();
    let (rule, _) = create_context_rule_with_signers(&e, 3);

    // Threshold = 4 with 3 signers must panic
    client.install(
        &SimpleThresholdAccountParams { threshold: 4 },
        &rule,
        &smart_account,
    );
}

#[test]
#[should_panic]
fn test_threshold_boundary_u32_max_install_panics() {
    let (e, smart_account, client) = setup();
    let (rule, _) = create_context_rule_with_signers(&e, 3);

    // u32::MAX threshold exceeds signer count and must panic
    client.install(
        &SimpleThresholdAccountParams { threshold: u32::MAX },
        &rule,
        &smart_account,
    );
}

#[test]
#[should_panic]
fn test_threshold_boundary_authenticated_below_threshold_panics() {
    let (e, smart_account, client) = setup();
    let (rule, signers) = create_context_rule_with_signers(&e, 3);

    client.install(
        &SimpleThresholdAccountParams { threshold: 2 },
        &rule,
        &smart_account,
    );

    // Only 1 authenticated signer when threshold is 2
    let mut partial_signers = Vec::new(&e);
    partial_signers.push_back(signers.get(0).unwrap());

    let dummy_context = Context::Contract(soroban_sdk::auth::ContractContext {
        contract: Address::generate(&e),
        fn_name: soroban_sdk::Symbol::new(&e, "test"),
        args: Vec::new(&e),
    });

    client.enforce(&dummy_context, &partial_signers, &rule, &smart_account);
}
