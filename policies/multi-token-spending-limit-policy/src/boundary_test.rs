#![cfg(test)]
extern crate std;

use soroban_sdk::{
    auth::{Context, ContractContext},
    contract, contractimpl, symbol_short,
    testutils::{Address as _, Ledger},
    vec, Address, Env, IntoVal, String, Symbol, Val, Vec,
};
use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

use crate::{
    oracle::{Asset, PriceData},
    MultiTokenSpendingLimitAccountParams, MultiTokenSpendingLimitPolicy,
    MultiTokenSpendingLimitPolicyClient, Error,
};

const ONE_USD: i128 = 100_000_000;

#[contract]
struct MockOracle;

#[contractimpl]
impl MockOracle {
    pub fn set_price(e: Env, price: Option<PriceData>) {
        e.storage().instance().set(&symbol_short!("price"), &price);
    }

    pub fn set_decimals(e: Env, decimals: u32) {
        e.storage().instance().set(&symbol_short!("decimals"), &decimals);
    }

    pub fn lastprice(e: Env, _asset: Asset) -> Option<PriceData> {
        e.storage().instance().get(&symbol_short!("price")).unwrap()
    }

    pub fn decimals(e: Env) -> u32 {
        e.storage().instance().get(&symbol_short!("decimals")).unwrap_or(8)
    }
}

#[contract]
struct MockToken;

#[contractimpl]
impl MockToken {
    pub fn __constructor(e: Env, decimals: u32) {
        e.storage().instance().set(&symbol_short!("decimals"), &decimals);
    }

    pub fn decimals(e: Env) -> u32 {
        e.storage().instance().get(&symbol_short!("decimals")).unwrap()
    }
}

fn setup_token(e: &Env, decimals: u32) -> Address {
    e.register(MockToken, (decimals,))
}

fn setup_oracle(e: &Env, price: i128) -> Address {
    let oracle = e.register(MockOracle, ());
    let client = MockOracleClient::new(e, &oracle);
    client.set_price(&Some(PriceData {
        price,
        timestamp: e.ledger().timestamp(),
    }));
    oracle
}

fn create_context_rule(e: &Env, call_target: Address) -> ContextRule {
    let signer = Address::generate(e);
    let mut signers = Vec::new(e);
    signers.push_back(Signer::Delegated(signer));

    ContextRule {
        id: 1,
        context_type: ContextRuleType::CallContract(call_target),
        name: String::from_str(e, "multi-token-spending-limit"),
        signers,
        signer_ids: Vec::new(e),
        policies: Vec::new(e),
        policy_ids: Vec::new(e),
        valid_until: None,
    }
}

fn setup_env<'a>() -> (Env, Address, MultiTokenSpendingLimitPolicyClient<'a>) {
    let e = Env::default();
    e.mock_all_auths();
    e.ledger().set_sequence_number(1_000);
    e.ledger().set_timestamp(10_000);

    let smart_account = Address::generate(&e);
    let policy_id = e.register(MultiTokenSpendingLimitPolicy, ());
    let client = MultiTokenSpendingLimitPolicyClient::new(&e, &policy_id);

    (e, smart_account, client)
}

fn install_policy(
    e: &Env,
    client: &MultiTokenSpendingLimitPolicyClient,
    smart_account: &Address,
    oracle: &Address,
    allowed_tokens: Vec<Address>,
    spending_limit_usd: i128,
    period_ledgers: u32,
) -> ContextRule {
    let target = allowed_tokens.get(0).unwrap();
    let rule = create_context_rule(e, target);
    let params = MultiTokenSpendingLimitAccountParams {
        spending_limit_usd,
        period_ledgers,
        oracle_address: oracle.clone(),
        allowed_tokens,
    };
    client.install(&params, &rule, smart_account);
    rule
}

fn transfer_context(e: &Env, token: &Address, amount: i128) -> Context {
    let from = Address::generate(e);
    let to = Address::generate(e);
    let args: Vec<Val> = vec![e, from.into_val(e), to.into_val(e), amount.into_val(e)];
    Context::Contract(ContractContext {
        contract: token.clone(),
        fn_name: symbol_short!("transfer"),
        args,
    })
}

// =========================================================================
// BOUNDARY TEST SUITE: uint128, int128, uint64, 0 boundaries
// =========================================================================

#[test]
fn test_spending_boundary_amount_zero() {
    let (e, smart_account, client) = setup_env();
    let oracle = setup_oracle(&e, ONE_USD);
    let token = setup_token(&e, 0);

    let rule = install_policy(
        &e,
        &client,
        &smart_account,
        &oracle,
        vec![&e, token.clone()],
        1_000,
        100,
    );

    // 0 amount should be allowed and consume 0 USD
    let context = transfer_context(&e, &token, 0);
    client.enforce(&context, &Vec::new(&e), &rule, &smart_account);

    let data = client.get_policy_data(&rule.id, &smart_account);
    assert_eq!(data.cached_total_spent_usd, 0);
}

#[test]
fn test_spending_boundary_u64_max_conversion() {
    let (e, smart_account, client) = setup_env();
    // 1 token = 1 USD (with 8 decimal oracle, 0 decimal token)
    let oracle = setup_oracle(&e, ONE_USD);
    let token = setup_token(&e, 0);

    let limit = (u64::MAX as i128) + 100;
    let rule = install_policy(
        &e,
        &client,
        &smart_account,
        &oracle,
        vec![&e, token.clone()],
        limit,
        100,
    );

    // u64::MAX token amount should convert without overflow
    let u64_max = u64::MAX as i128;
    let context = transfer_context(&e, &token, u64_max);
    client.enforce(&context, &Vec::new(&e), &rule, &smart_account);

    let data = client.get_policy_data(&rule.id, &smart_account);
    assert_eq!(data.cached_total_spent_usd, u64_max);
}

#[test]
fn test_spending_boundary_u64_boundary_crossings() {
    let (e, smart_account, client) = setup_env();
    let oracle = setup_oracle(&e, ONE_USD);
    let token = setup_token(&e, 0);

    let limit = i128::MAX;
    let rule = install_policy(
        &e,
        &client,
        &smart_account,
        &oracle,
        vec![&e, token.clone()],
        limit,
        100,
    );

    // u64::MAX - 1
    let context1 = transfer_context(&e, &token, (u64::MAX - 1) as i128);
    client.enforce(&context1, &Vec::new(&e), &rule, &smart_account);

    // crossing to (u64::MAX - 1) + 2 = u64::MAX + 1
    let context2 = transfer_context(&e, &token, 2);
    client.enforce(&context2, &Vec::new(&e), &rule, &smart_account);

    let data = client.get_policy_data(&rule.id, &smart_account);
    assert_eq!(data.cached_total_spent_usd, (u64::MAX as i128) + 1);
}

#[test]
fn test_spending_boundary_i64_boundary_crossings() {
    let (e, smart_account, client) = setup_env();
    let oracle = setup_oracle(&e, ONE_USD);
    let token = setup_token(&e, 0);

    let limit = i128::MAX;
    let rule = install_policy(
        &e,
        &client,
        &smart_account,
        &oracle,
        vec![&e, token.clone()],
        limit,
        100,
    );

    let i64_max = i64::MAX as i128;
    let context = transfer_context(&e, &token, i64_max);
    client.enforce(&context, &Vec::new(&e), &rule, &smart_account);

    let context2 = transfer_context(&e, &token, 1);
    client.enforce(&context2, &Vec::new(&e), &rule, &smart_account);

    let data = client.get_policy_data(&rule.id, &smart_account);
    assert_eq!(data.cached_total_spent_usd, i64_max + 1);
}

#[test]
#[should_panic(expected = "Error(Contract, #12)")] // AmountConversionOverflow
fn test_spending_boundary_i128_max_overflow_fails_closed() {
    let (e, smart_account, client) = setup_env();
    let oracle = setup_oracle(&e, ONE_USD);
    let token = setup_token(&e, 0);

    let rule = install_policy(
        &e,
        &client,
        &smart_account,
        &oracle,
        vec![&e, token.clone()],
        i128::MAX,
        100,
    );

    // i128::MAX * ONE_USD overflows i128; must panic with AmountConversionOverflow without wrapping
    let context = transfer_context(&e, &token, i128::MAX);
    client.enforce(&context, &Vec::new(&e), &rule, &smart_account);
}

#[test]
#[should_panic(expected = "Error(Contract, #6)")] // InvalidTransferArgs (negative amount)
fn test_spending_boundary_negative_amount_fails_closed() {
    let (e, smart_account, client) = setup_env();
    let oracle = setup_oracle(&e, ONE_USD);
    let token = setup_token(&e, 0);

    let rule = install_policy(
        &e,
        &client,
        &smart_account,
        &oracle,
        vec![&e, token.clone()],
        1_000,
        100,
    );

    let context = transfer_context(&e, &token, -1);
    client.enforce(&context, &Vec::new(&e), &rule, &smart_account);
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")] // SpendingLimitExceeded
fn test_spending_boundary_saturating_add_exceeded_check() {
    let (e, smart_account, client) = setup_env();
    // 1 token = 1 USD (with price = 10^8, oracle decimals = 8, token decimals = 0)
    let oracle = setup_oracle(&e, ONE_USD);
    let token = setup_token(&e, 0);

    // Limit is 100 USD
    let rule = install_policy(
        &e,
        &client,
        &smart_account,
        &oracle,
        vec![&e, token.clone()],
        100,
        100,
    );

    // Spend 100 USD (exact boundary)
    let context = transfer_context(&e, &token, 100);
    client.enforce(&context, &Vec::new(&e), &rule, &smart_account);

    // Next 1 USD exceeds limit (100 + 1 > 100)
    let context2 = transfer_context(&e, &token, 1);
    client.enforce(&context2, &Vec::new(&e), &rule, &smart_account);
}

#[test]
fn test_spending_boundary_exact_limit_allowed() {
    let (e, smart_account, client) = setup_env();
    let oracle = setup_oracle(&e, ONE_USD);
    let token = setup_token(&e, 0);

    let limit = 5_000_000_000i128; // > u32::MAX
    let rule = install_policy(
        &e,
        &client,
        &smart_account,
        &oracle,
        vec![&e, token.clone()],
        limit,
        100,
    );

    // Spend exact limit: 5_000_000_000
    let context = transfer_context(&e, &token, limit);
    client.enforce(&context, &Vec::new(&e), &rule, &smart_account);

    let data = client.get_policy_data(&rule.id, &smart_account);
    assert_eq!(data.cached_total_spent_usd, limit);
}
