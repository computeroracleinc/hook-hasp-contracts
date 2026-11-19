extern crate std;

use soroban_sdk::{testutils::Address as _, vec, Address, Env, Map, String, Vec};
use stellar_accounts::{
    policies::weighted_threshold::WeightedThresholdAccountParams,
    smart_account::{ContextRule, ContextRuleType, Signer},
};

use crate::{WeightedThresholdPolicy, WeightedThresholdPolicyClient};

fn setup<'a>(e: &'a Env) -> (WeightedThresholdPolicyClient<'a>, Address) {
    let address = e.register(WeightedThresholdPolicy, ());
    (WeightedThresholdPolicyClient::new(e, &address), address)
}

fn participants(e: &Env) -> (Signer, Signer) {
    (Signer::Delegated(Address::generate(e)), Signer::Delegated(Address::generate(e)))
}

fn signer_weights(e: &Env, signer1: &Signer, signer2: &Signer) -> Map<Signer, u32> {
    let mut weights = Map::new(e);
    weights.set(signer1.clone(), 100);
    weights.set(signer2.clone(), 50);
    weights
}

fn context_rule(e: &Env, signer1: &Signer, signer2: &Signer) -> ContextRule {
    ContextRule {
        id: 1,
        context_type: ContextRuleType::Default,
        name: String::from_str(e, "weighted"),
        signers: vec![e, signer1.clone(), signer2.clone()],
        signer_ids: Vec::new(e),
        policies: Vec::new(e),
        policy_ids: Vec::new(e),
        valid_until: None,
    }
}

#[test]
fn install_accepts_threshold_equal_to_total_weight() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, smart_account) = setup(&e);
    let (signer1, signer2) = participants(&e);
    let context_rule = context_rule(&e, &signer1, &signer2);
    let params = WeightedThresholdAccountParams {
        signer_weights: signer_weights(&e, &signer1, &signer2),
        threshold: 150,
    };

    client.install(&params, &context_rule, &smart_account);

    assert_eq!(client.get_threshold(&context_rule.id, &smart_account), 150);
}

#[test]
#[should_panic(expected = "Error(Contract, #3211)")]
fn install_rejects_threshold_above_total_weight() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, smart_account) = setup(&e);
    let (signer1, signer2) = participants(&e);
    let context_rule = context_rule(&e, &signer1, &signer2);
    let params = WeightedThresholdAccountParams {
        signer_weights: signer_weights(&e, &signer1, &signer2),
        threshold: 151,
    };

    client.install(&params, &context_rule, &smart_account);
}

#[test]
#[should_panic(expected = "Error(Contract, #3212)")]
fn install_rejects_weight_sum_overflow() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, smart_account) = setup(&e);
    let (signer1, signer2) = participants(&e);
    let context_rule = context_rule(&e, &signer1, &signer2);
    let mut weights = Map::new(&e);
    weights.set(signer1.clone(), u32::MAX);
    weights.set(signer2.clone(), 1);
    let params = WeightedThresholdAccountParams { signer_weights: weights, threshold: 1 };

    client.install(&params, &context_rule, &smart_account);
}

#[test]
#[should_panic(expected = "Error(Contract, #3211)")]
fn set_threshold_rejects_threshold_above_total_weight() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, smart_account) = setup(&e);
    let (signer1, signer2) = participants(&e);
    let context_rule = context_rule(&e, &signer1, &signer2);
    let params = WeightedThresholdAccountParams {
        signer_weights: signer_weights(&e, &signer1, &signer2),
        threshold: 75,
    };
    client.install(&params, &context_rule, &smart_account);

    client.set_threshold(&151, &context_rule, &smart_account);
}

#[test]
fn set_threshold_accepts_threshold_within_total_weight() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, smart_account) = setup(&e);
    let (signer1, signer2) = participants(&e);
    let context_rule = context_rule(&e, &signer1, &signer2);
    let params = WeightedThresholdAccountParams {
        signer_weights: signer_weights(&e, &signer1, &signer2),
        threshold: 75,
    };
    client.install(&params, &context_rule, &smart_account);

    client.set_threshold(&150, &context_rule, &smart_account);

    assert_eq!(client.get_threshold(&context_rule.id, &smart_account), 150);
}

#[test]
#[should_panic(expected = "Error(Contract, #3211)")]
fn set_signer_weight_rejects_reduction_below_threshold() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, smart_account) = setup(&e);
    let (signer1, signer2) = participants(&e);
    let context_rule = context_rule(&e, &signer1, &signer2);
    let params = WeightedThresholdAccountParams {
        signer_weights: signer_weights(&e, &signer1, &signer2),
        threshold: 120,
    };
    client.install(&params, &context_rule, &smart_account);

    client.set_signer_weight(&signer1, &10, &context_rule, &smart_account);
}

#[test]
fn set_signer_weight_accepts_increase_above_threshold() {
    let e = Env::default();
    e.mock_all_auths();
    let (client, smart_account) = setup(&e);
    let (signer1, signer2) = participants(&e);
    let context_rule = context_rule(&e, &signer1, &signer2);
    let params = WeightedThresholdAccountParams {
        signer_weights: signer_weights(&e, &signer1, &signer2),
        threshold: 120,
    };
    client.install(&params, &context_rule, &smart_account);

    client.set_signer_weight(&signer1, &200, &context_rule, &smart_account);

    let weights = client.get_signer_weights(&context_rule, &smart_account);
    assert_eq!(weights.get(signer1).unwrap(), 200);
    assert_eq!(weights.get(signer2).unwrap(), 50);
}
