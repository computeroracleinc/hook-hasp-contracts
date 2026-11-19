#![cfg(test)]
extern crate std;

use soroban_sdk::{
    auth::{Context, ContractContext},
    contract, contractimpl, symbol_short,
    testutils::Address as _,
    vec, Address, Env, IntoVal, String, Val, Vec,
};
use stellar_accounts::{
    policies::{spending_limit::SpendingLimitAccountParams, Policy},
    smart_account::{ContextRule, ContextRuleType, Signer},
};

use crate::SpendingLimitPolicy;

fn setup() -> (Env, Address, Address, SpendingLimitPolicyClient<'static>) {
    let e = Env::default();
    e.mock_all_auths();
    let smart_account = Address::generate(&e);
    let target = Address::generate(&e);
    let policy_id = e.register(SpendingLimitPolicy, ());
    let client = SpendingLimitPolicyClient::new(&e, &policy_id);
    (e, smart_account, target, client)
}

fn create_context_rule(e: &Env, target: &Address) -> ContextRule {
    let signer = Address::generate(e);
    let mut signers = Vec::new(e);
    signers.push_back(Signer::Delegated(signer));

    ContextRule {
        id: 1,
        context_type: ContextRuleType::CallContract(target.clone()),
        name: String::from_str(e, "spending_limit"),
        signers,
        signer_ids: Vec::new(e),
        policies: Vec::new(e),
        policy_ids: Vec::new(e),
        valid_until: None,
    }
}

fn transfer_context(e: &Env, target: &Address, amount: i128) -> Context {
    let from = Address::generate(e);
    let to = Address::generate(e);
    let args: Vec<Val> = vec![e, from.into_val(e), to.into_val(e), amount.into_val(e)];
    Context::Contract(ContractContext {
        contract: target.clone(),
        fn_name: symbol_short!("transfer"),
        args,
    })
}

// =========================================================================
// BOUNDARY TEST SUITE: uint128, int128, uint64 boundaries, 0
// =========================================================================

#[test]
fn test_spending_boundary_install_u64_max() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    // Test install with u64::MAX boundary
    let u64_max = u64::MAX as i128;
    client.install(
        &SpendingLimitAccountParams {
            spending_limit: u64_max,
            period_ledgers: 100,
        },
        &rule,
        &smart_account,
    );

    let data = client.get_spending_limit_data(&rule.id, &smart_account);
    assert_eq!(data.spending_limit, u64_max);
    assert_eq!(data.current_spent, 0);
}

#[test]
fn test_spending_boundary_install_i128_max() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    // Test install with i128::MAX boundary
    client.install(
        &SpendingLimitAccountParams {
            spending_limit: i128::MAX,
            period_ledgers: 100,
        },
        &rule,
        &smart_account,
    );

    let data = client.get_spending_limit_data(&rule.id, &smart_account);
    assert_eq!(data.spending_limit, i128::MAX);
    assert_eq!(data.current_spent, 0);
}

#[test]
fn test_spending_boundary_enforce_zero_amount() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    client.install(
        &SpendingLimitAccountParams {
            spending_limit: 1000,
            period_ledgers: 100,
        },
        &rule,
        &smart_account,
    );

    let context = transfer_context(&e, &target, 0);
    client.enforce(&context, &Vec::new(&e), &rule, &smart_account);

    let data = client.get_spending_limit_data(&rule.id, &smart_account);
    assert_eq!(data.current_spent, 0);
}

#[test]
fn test_spending_boundary_enforce_crossing_64bit_boundary() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    let u64_max = u64::MAX as i128;
    client.install(
        &SpendingLimitAccountParams {
            spending_limit: i128::MAX,
            period_ledgers: 100,
        },
        &rule,
        &smart_account,
    );

    // Spend u64::MAX - 1
    let context1 = transfer_context(&e, &target, u64_max - 1);
    client.enforce(&context1, &Vec::new(&e), &rule, &smart_account);

    // Spend 2 to cross 64-bit boundary to u64::MAX + 1
    let context2 = transfer_context(&e, &target, 2);
    client.enforce(&context2, &Vec::new(&e), &rule, &smart_account);

    let data = client.get_spending_limit_data(&rule.id, &smart_account);
    assert_eq!(data.current_spent, u64_max + 1);
}

#[test]
fn test_spending_boundary_exact_limit() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    let limit = (u64::MAX as i128) + 500;
    client.install(
        &SpendingLimitAccountParams {
            spending_limit: limit,
            period_ledgers: 100,
        },
        &rule,
        &smart_account,
    );

    // Exactly spend the limit
    let context = transfer_context(&e, &target, limit);
    client.enforce(&context, &Vec::new(&e), &rule, &smart_account);

    let data = client.get_spending_limit_data(&rule.id, &smart_account);
    assert_eq!(data.current_spent, limit);
}

#[test]
#[should_panic]
fn test_spending_boundary_exceed_by_one_panics() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    let limit = (u64::MAX as i128) + 500;
    client.install(
        &SpendingLimitAccountParams {
            spending_limit: limit,
            period_ledgers: 100,
        },
        &rule,
        &smart_account,
    );

    // Spend limit + 1
    let context = transfer_context(&e, &target, limit + 1);
    client.enforce(&context, &Vec::new(&e), &rule, &smart_account);
}

#[test]
#[should_panic]
fn test_spending_boundary_install_zero_or_negative_panics() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    // 0 is not positive, must panic
    client.install(
        &SpendingLimitAccountParams {
            spending_limit: 0,
            period_ledgers: 100,
        },
        &rule,
        &smart_account,
    );
}

#[test]
#[should_panic]
fn test_spending_boundary_install_negative_panics() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    // Negative limit must panic
    client.install(
        &SpendingLimitAccountParams {
            spending_limit: -1,
            period_ledgers: 100,
        },
        &rule,
        &smart_account,
    );
}
