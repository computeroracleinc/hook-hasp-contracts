#![cfg(test)]
extern crate std;

use soroban_sdk::{
    auth::Context,
    testutils::Address as _,
    Address, Env, IntoVal, Map, String, Vec,
};
use stellar_accounts::{
    policies::{weighted_threshold::WeightedThresholdAccountParams, Policy},
    smart_account::{ContextRule, ContextRuleType, Signer},
};

use crate::{WeightedThresholdPolicy, WeightedThresholdPolicyClient};

fn setup() -> (Env, Address, WeightedThresholdPolicyClient<'static>) {
    let e = Env::default();
    e.mock_all_auths();
    let smart_account = Address::generate(&e);
    let policy_id = e.register(WeightedThresholdPolicy, ());
    let client = WeightedThresholdPolicyClient::new(&e, &policy_id);
    (e, smart_account, client)
}

fn create_context_rule(e: &Env, signers: &Vec<Signer>) -> ContextRule {
    ContextRule {
        id: 1,
        context_type: ContextRuleType::CallContract(Address::generate(e)),
        name: String::from_str(e, "weighted_threshold"),
        signers: signers.clone(),
        signer_ids: Vec::new(e),
        policies: Vec::new(e),
        policy_ids: Vec::new(e),
        valid_until: None,
    }
}

// =========================================================================
// BOUNDARY TEST SUITE: Weighted Threshold boundaries
// =========================================================================

#[test]
fn test_weighted_threshold_boundary_exact_match() {
    let (e, smart_account, client) = setup();

    let signer1 = Signer::Delegated(Address::generate(&e));
    let signer2 = Signer::Delegated(Address::generate(&e));
    let mut signers = Vec::new(&e);
    signers.push_back(signer1.clone());
    signers.push_back(signer2.clone());

    let rule = create_context_rule(&e, &signers);

    let mut signer_weights = Map::new(&e);
    signer_weights.set(signer1.clone(), 100);
    signer_weights.set(signer2.clone(), 200);

    // Threshold = 300 (sum of all weights)
    client.install(
        &WeightedThresholdAccountParams {
            signer_weights,
            threshold: 300,
        },
        &rule,
        &smart_account,
    );

    assert_eq!(client.get_threshold(&rule.id, &smart_account), 300);

    let dummy_context = Context::Contract(soroban_sdk::auth::ContractContext {
        contract: Address::generate(&e),
        fn_name: soroban_sdk::Symbol::new(&e, "test"),
        args: Vec::new(&e),
    });

    // Enforce with both signers (100 + 200 = 300 >= 300)
    client.enforce(&dummy_context, &signers, &rule, &smart_account);
}

#[test]
#[should_panic]
fn test_weighted_threshold_boundary_zero_install_panics() {
    let (e, smart_account, client) = setup();
    let signer = Signer::Delegated(Address::generate(&e));
    let mut signers = Vec::new(&e);
    signers.push_back(signer.clone());
    let rule = create_context_rule(&e, &signers);

    let mut signer_weights = Map::new(&e);
    signer_weights.set(signer, 100);

    // Threshold = 0 must panic
    client.install(
        &WeightedThresholdAccountParams {
            signer_weights,
            threshold: 0,
        },
        &rule,
        &smart_account,
    );
}

#[test]
#[should_panic]
fn test_weighted_threshold_boundary_threshold_exceeds_total_weight_panics() {
    let (e, smart_account, client) = setup();
    let signer = Signer::Delegated(Address::generate(&e));
    let mut signers = Vec::new(&e);
    signers.push_back(signer.clone());
    let rule = create_context_rule(&e, &signers);

    let mut signer_weights = Map::new(&e);
    signer_weights.set(signer, 100);

    // Threshold 101 > total 100 must panic
    client.install(
        &WeightedThresholdAccountParams {
            signer_weights,
            threshold: 101,
        },
        &rule,
        &smart_account,
    );
}

#[test]
#[should_panic]
fn test_weighted_threshold_boundary_u32_max_install_panics() {
    let (e, smart_account, client) = setup();
    let signer = Signer::Delegated(Address::generate(&e));
    let mut signers = Vec::new(&e);
    signers.push_back(signer.clone());
    let rule = create_context_rule(&e, &signers);

    let mut signer_weights = Map::new(&e);
    signer_weights.set(signer, 100);

    // Threshold u32::MAX > total 100 must panic
    client.install(
        &WeightedThresholdAccountParams {
            signer_weights,
            threshold: u32::MAX,
        },
        &rule,
        &smart_account,
    );
}

#[test]
#[should_panic]
fn test_weighted_threshold_boundary_enforce_below_threshold_panics() {
    let (e, smart_account, client) = setup();

    let signer1 = Signer::Delegated(Address::generate(&e));
    let signer2 = Signer::Delegated(Address::generate(&e));
    let mut signers = Vec::new(&e);
    signers.push_back(signer1.clone());
    signers.push_back(signer2.clone());

    let rule = create_context_rule(&e, &signers);

    let mut signer_weights = Map::new(&e);
    signer_weights.set(signer1.clone(), 100);
    signer_weights.set(signer2.clone(), 200);

    client.install(
        &WeightedThresholdAccountParams {
            signer_weights,
            threshold: 250,
        },
        &rule,
        &smart_account,
    );

    let dummy_context = Context::Contract(soroban_sdk::auth::ContractContext {
        contract: Address::generate(&e),
        fn_name: soroban_sdk::Symbol::new(&e, "test"),
        args: Vec::new(&e),
    });

    // Authenticate only signer1 (weight 100 < 250), must panic
    let mut partial = Vec::new(&e);
    partial.push_back(signer1);
    client.enforce(&dummy_context, &partial, &rule, &smart_account);
}
