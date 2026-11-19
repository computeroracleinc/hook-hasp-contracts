#![cfg(test)]
extern crate std;

use soroban_sdk::{
    auth::Context,
    testutils::Address as _,
    Address, Env, IntoVal, Map, String, Symbol, Vec,
};
use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

use super::*;

fn setup() -> (Env, Address, u32, Address, Address) {
    let e = Env::default();
    e.mock_all_auths();
    let smart_account = Address::generate(&e);
    let target_contract = Address::generate(&e);
    let context_rule_id = 1;
    let policy_id = e.register(ParameterScopedPolicy, ());
    (e, smart_account, context_rule_id, target_contract, policy_id)
}

fn create_context_rule(e: &Env, target: &Address) -> ContextRule {
    let signer = Address::generate(e);
    let mut signers = Vec::new(e);
    signers.push_back(Signer::Delegated(signer));

    ContextRule {
        id: 1,
        context_type: ContextRuleType::CallContract(target.clone()),
        name: String::from_str(e, "parameter_scoped"),
        signers,
        signer_ids: Vec::new(e),
        policies: Vec::new(e),
        policy_ids: Vec::new(e),
        valid_until: None,
    }
}

fn create_contract_context(
    e: &Env,
    target: &Address,
    fn_name: &str,
    args: Vec<soroban_sdk::Val>,
) -> Context {
    Context::Contract(soroban_sdk::auth::ContractContext {
        contract: target.clone(),
        fn_name: Symbol::new(e, fn_name),
        args,
    })
}

// =========================================================================
// BOUNDARY TEST SUITE: uint128, int128, uint64 boundaries, 0
// =========================================================================

#[test]
fn test_boundary_u128_max_eq_and_gte() {
    let (e, smart_account, _, target, policy_id) = setup();
    let rule = create_context_rule(&e, &target);
    let mut conditions = Map::new(&e);
    conditions.set(
        Symbol::new(&e, "swap"),
        Vec::from_array(
            &e,
            [
                Condition {
                    arg_index: 0,
                    operator: Operator::Eq,
                    expected_value: ExpectedValue::U128(u128::MAX),
                },
                Condition {
                    arg_index: 0,
                    operator: Operator::Gte,
                    expected_value: ExpectedValue::U128(u128::MAX),
                },
            ],
        ),
    );
    e.as_contract(&policy_id, || {
        conditions::install(
            &e,
            &ParameterScopedAccountParams { conditions },
            &rule,
            &smart_account,
        );
    });

    let context = create_contract_context(
        &e,
        &target,
        "swap",
        Vec::from_array(&e, [u128::MAX.into_val(&e)]),
    );
    let signers = Vec::from_array(&e, [Signer::Delegated(Address::generate(&e))]);
    e.as_contract(&policy_id, || {
        conditions::enforce(&e, &context, &signers, &rule, &smart_account);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")] // ConditionFailed
fn test_boundary_u128_max_gt_fails() {
    let (e, smart_account, _, target, policy_id) = setup();
    let rule = create_context_rule(&e, &target);
    let mut conditions = Map::new(&e);
    conditions.set(
        Symbol::new(&e, "swap"),
        Vec::from_array(
            &e,
            [Condition {
                arg_index: 0,
                operator: Operator::Gt,
                expected_value: ExpectedValue::U128(u128::MAX),
            }],
        ),
    );
    e.as_contract(&policy_id, || {
        conditions::install(
            &e,
            &ParameterScopedAccountParams { conditions },
            &rule,
            &smart_account,
        );
    });

    let context = create_contract_context(
        &e,
        &target,
        "swap",
        Vec::from_array(&e, [u128::MAX.into_val(&e)]),
    );
    let signers = Vec::from_array(&e, [Signer::Delegated(Address::generate(&e))]);
    e.as_contract(&policy_id, || {
        conditions::enforce(&e, &context, &signers, &rule, &smart_account);
    });
}

#[test]
fn test_boundary_u128_zero() {
    let (e, smart_account, _, target, policy_id) = setup();
    let rule = create_context_rule(&e, &target);
    let mut conditions = Map::new(&e);
    conditions.set(
        Symbol::new(&e, "swap"),
        Vec::from_array(
            &e,
            [
                Condition {
                    arg_index: 0,
                    operator: Operator::Eq,
                    expected_value: ExpectedValue::U128(0),
                },
                Condition {
                    arg_index: 0,
                    operator: Operator::Lte,
                    expected_value: ExpectedValue::U128(0),
                },
            ],
        ),
    );
    e.as_contract(&policy_id, || {
        conditions::install(
            &e,
            &ParameterScopedAccountParams { conditions },
            &rule,
            &smart_account,
        );
    });

    let context = create_contract_context(
        &e,
        &target,
        "swap",
        Vec::from_array(&e, [0u128.into_val(&e)]),
    );
    let signers = Vec::from_array(&e, [Signer::Delegated(Address::generate(&e))]);
    e.as_contract(&policy_id, || {
        conditions::enforce(&e, &context, &signers, &rule, &smart_account);
    });
}

#[test]
fn test_boundary_u128_crossing_64bit_boundary() {
    let (e, smart_account, _, target, policy_id) = setup();
    let rule = create_context_rule(&e, &target);
    let mut conditions = Map::new(&e);

    let boundary_64 = (u64::MAX as u128) + 1; // 2^64
    conditions.set(
        Symbol::new(&e, "swap"),
        Vec::from_array(
            &e,
            [
                Condition {
                    arg_index: 0,
                    operator: Operator::Gt,
                    expected_value: ExpectedValue::U128(u64::MAX as u128),
                },
                Condition {
                    arg_index: 0,
                    operator: Operator::Eq,
                    expected_value: ExpectedValue::U128(boundary_64),
                },
            ],
        ),
    );
    e.as_contract(&policy_id, || {
        conditions::install(
            &e,
            &ParameterScopedAccountParams { conditions },
            &rule,
            &smart_account,
        );
    });

    let context = create_contract_context(
        &e,
        &target,
        "swap",
        Vec::from_array(&e, [boundary_64.into_val(&e)]),
    );
    let signers = Vec::from_array(&e, [Signer::Delegated(Address::generate(&e))]);
    e.as_contract(&policy_id, || {
        conditions::enforce(&e, &context, &signers, &rule, &smart_account);
    });
}

#[test]
fn test_boundary_i128_max() {
    let (e, smart_account, _, target, policy_id) = setup();
    let rule = create_context_rule(&e, &target);
    let mut conditions = Map::new(&e);
    conditions.set(
        Symbol::new(&e, "swap"),
        Vec::from_array(
            &e,
            [
                Condition {
                    arg_index: 0,
                    operator: Operator::Eq,
                    expected_value: ExpectedValue::I128(i128::MAX),
                },
                Condition {
                    arg_index: 0,
                    operator: Operator::Gte,
                    expected_value: ExpectedValue::I128(i128::MAX),
                },
            ],
        ),
    );
    e.as_contract(&policy_id, || {
        conditions::install(
            &e,
            &ParameterScopedAccountParams { conditions },
            &rule,
            &smart_account,
        );
    });

    let context = create_contract_context(
        &e,
        &target,
        "swap",
        Vec::from_array(&e, [i128::MAX.into_val(&e)]),
    );
    let signers = Vec::from_array(&e, [Signer::Delegated(Address::generate(&e))]);
    e.as_contract(&policy_id, || {
        conditions::enforce(&e, &context, &signers, &rule, &smart_account);
    });
}

#[test]
fn test_boundary_i128_min() {
    let (e, smart_account, _, target, policy_id) = setup();
    let rule = create_context_rule(&e, &target);
    let mut conditions = Map::new(&e);
    conditions.set(
        Symbol::new(&e, "swap"),
        Vec::from_array(
            &e,
            [
                Condition {
                    arg_index: 0,
                    operator: Operator::Eq,
                    expected_value: ExpectedValue::I128(i128::MIN),
                },
                Condition {
                    arg_index: 0,
                    operator: Operator::Lte,
                    expected_value: ExpectedValue::I128(i128::MIN),
                },
            ],
        ),
    );
    e.as_contract(&policy_id, || {
        conditions::install(
            &e,
            &ParameterScopedAccountParams { conditions },
            &rule,
            &smart_account,
        );
    });

    let context = create_contract_context(
        &e,
        &target,
        "swap",
        Vec::from_array(&e, [i128::MIN.into_val(&e)]),
    );
    let signers = Vec::from_array(&e, [Signer::Delegated(Address::generate(&e))]);
    e.as_contract(&policy_id, || {
        conditions::enforce(&e, &context, &signers, &rule, &smart_account);
    });
}

#[test]
fn test_boundary_i128_zero() {
    let (e, smart_account, _, target, policy_id) = setup();
    let rule = create_context_rule(&e, &target);
    let mut conditions = Map::new(&e);
    conditions.set(
        Symbol::new(&e, "swap"),
        Vec::from_array(
            &e,
            [
                Condition {
                    arg_index: 0,
                    operator: Operator::Eq,
                    expected_value: ExpectedValue::I128(0),
                },
            ],
        ),
    );
    e.as_contract(&policy_id, || {
        conditions::install(
            &e,
            &ParameterScopedAccountParams { conditions },
            &rule,
            &smart_account,
        );
    });

    let context = create_contract_context(
        &e,
        &target,
        "swap",
        Vec::from_array(&e, [0i128.into_val(&e)]),
    );
    let signers = Vec::from_array(&e, [Signer::Delegated(Address::generate(&e))]);
    e.as_contract(&policy_id, || {
        conditions::enforce(&e, &context, &signers, &rule, &smart_account);
    });
}

#[test]
fn test_boundary_i128_crossing_64bit_boundary() {
    let (e, smart_account, _, target, policy_id) = setup();
    let rule = create_context_rule(&e, &target);
    let mut conditions = Map::new(&e);

    let boundary_64 = (i64::MAX as i128) + 1; // 2^63
    conditions.set(
        Symbol::new(&e, "swap"),
        Vec::from_array(
            &e,
            [
                Condition {
                    arg_index: 0,
                    operator: Operator::Gt,
                    expected_value: ExpectedValue::I128(i64::MAX as i128),
                },
                Condition {
                    arg_index: 0,
                    operator: Operator::Eq,
                    expected_value: ExpectedValue::I128(boundary_64),
                },
            ],
        ),
    );
    e.as_contract(&policy_id, || {
        conditions::install(
            &e,
            &ParameterScopedAccountParams { conditions },
            &rule,
            &smart_account,
        );
    });

    let context = create_contract_context(
        &e,
        &target,
        "swap",
        Vec::from_array(&e, [boundary_64.into_val(&e)]),
    );
    let signers = Vec::from_array(&e, [Signer::Delegated(Address::generate(&e))]);
    e.as_contract(&policy_id, || {
        conditions::enforce(&e, &context, &signers, &rule, &smart_account);
    });
}

#[test]
fn test_boundary_u64_max_crossing_32bit_boundary() {
    let (e, smart_account, _, target, policy_id) = setup();
    let rule = create_context_rule(&e, &target);
    let mut conditions = Map::new(&e);

    let boundary_32 = (u32::MAX as u64) + 1;
    conditions.set(
        Symbol::new(&e, "swap"),
        Vec::from_array(
            &e,
            [
                Condition {
                    arg_index: 0,
                    operator: Operator::Eq,
                    expected_value: ExpectedValue::U64(boundary_32),
                },
                Condition {
                    arg_index: 0,
                    operator: Operator::Gt,
                    expected_value: ExpectedValue::U64(u32::MAX as u64),
                },
            ],
        ),
    );
    e.as_contract(&policy_id, || {
        conditions::install(
            &e,
            &ParameterScopedAccountParams { conditions },
            &rule,
            &smart_account,
        );
    });

    let context = create_contract_context(
        &e,
        &target,
        "swap",
        Vec::from_array(&e, [boundary_32.into_val(&e)]),
    );
    let signers = Vec::from_array(&e, [Signer::Delegated(Address::generate(&e))]);
    e.as_contract(&policy_id, || {
        conditions::enforce(&e, &context, &signers, &rule, &smart_account);
    });
}
