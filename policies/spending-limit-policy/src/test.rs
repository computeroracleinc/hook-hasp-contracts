#![cfg(test)]
extern crate std;

use soroban_sdk::{
    auth::{Context, ContractContext},
    contract, symbol_short,
    testutils::{Address as _, Ledger as _},
    vec,
    xdr::ToXdr,
    Address, Env, IntoVal, Val, Vec,
};
use stellar_accounts::{
    policies::{
        spending_limit,
        spending_limit::{SpendingLimitAccountParams, SpendingLimitData, SpendingLimitStorageKey},
    },
    smart_account::{ContextRule, ContextRuleType, Signer},
};

use crate::{
    decode_amount, encode_amount, load_data, read_data, window_seconds, CompactSpendingEntry,
    CompactSpendingLimitData, CompactStorageKey, SpendingLimitPolicy, SpendingLimitPolicyClient,
};

#[contract]
struct MockContract;

const DAY_IN_LEDGERS: u32 = 17_280;
const WEEK_IN_LEDGERS: u32 = 7 * DAY_IN_LEDGERS;

fn create_context_rule(e: &Env, target: &Address) -> ContextRule {
    let signer = Address::generate(e);
    let mut signers = Vec::new(e);
    signers.push_back(Signer::Delegated(signer));

    ContextRule {
        id: 1,
        context_type: ContextRuleType::CallContract(target.clone()),
        name: soroban_sdk::String::from_str(e, "session"),
        signers,
        signer_ids: Vec::new(e),
        policies: Vec::new(e),
        policy_ids: Vec::new(e),
        valid_until: None,
    }
}

fn setup<'a>() -> (Env, Address, Address, SpendingLimitPolicyClient<'a>) {
    let e = Env::default();
    e.mock_all_auths();
    e.ledger().set_sequence_number(1_000);
    e.ledger().set_timestamp(1_000_000);

    let smart_account = Address::generate(&e);
    let target = Address::generate(&e);
    let contract_id = e.register(SpendingLimitPolicy, ());
    let client = SpendingLimitPolicyClient::new(&e, &contract_id);

    (e, smart_account, target, client)
}

fn install(
    client: &SpendingLimitPolicyClient,
    rule: &ContextRule,
    smart_account: &Address,
    spending_limit: i128,
    period_ledgers: u32,
) {
    client.install(
        &SpendingLimitAccountParams { spending_limit, period_ledgers },
        rule,
        smart_account,
    );
}

fn transfer_context(e: &Env, target: &Address, amount: i128) -> Context {
    let args: Vec<Val> = vec![
        e,
        Address::generate(e).into_val(e),
        Address::generate(e).into_val(e),
        amount.into_val(e),
    ];
    Context::Contract(ContractContext {
        contract: target.clone(),
        fn_name: symbol_short!("transfer"),
        args,
    })
}

fn signers(e: &Env) -> Vec<Signer> {
    Vec::from_array(e, [Signer::Delegated(Address::generate(e))])
}

// ==========================================
// COMPACT ENCODING & MIGRATION (#185)
// ==========================================

#[test]
fn compact_spending_entry_uses_fewer_bytes_and_preserves_large_amounts() {
    let e = Env::default();
    let amount = 123_456_789i128;

    let compact =
        CompactSpendingEntry { amount: encode_amount(&e, amount), ledger_sequence: 123_456 };
    let upstream = spending_limit::SpendingEntry { amount, ledger_sequence: 123_456 };

    assert!(compact.to_xdr(&e).len() < upstream.to_xdr(&e).len());
    assert_eq!(decode_amount(&e, &encode_amount(&e, i128::MAX)), i128::MAX);
}

#[test]
fn legacy_spending_state_is_not_mutated_on_read_and_migrated_on_write() {
    let e = Env::default();
    let contract = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let legacy_key = SpendingLimitStorageKey::AccountContext(smart_account.clone(), 7);
    let compact_key = CompactStorageKey::CompactAccountContext(smart_account.clone(), 7);
    let legacy_data = SpendingLimitData {
        spending_limit: 100,
        period_ledgers: 50,
        spending_history: vec![
            &e,
            spending_limit::SpendingEntry { amount: 42, ledger_sequence: 123 },
        ],
        cached_total_spent: 42,
    };

    e.as_contract(&contract, || {
        e.storage().persistent().set(&legacy_key, &legacy_data);

        // Read-only getter does not mutate storage.
        assert_eq!(read_data(&e, 7, &smart_account), legacy_data);
        assert!(e.storage().persistent().has(&legacy_key));
        assert!(!e.storage().persistent().has(&compact_key));

        // Authenticated write-path load migrates legacy -> compact.
        assert_eq!(load_data(&e, 7, &smart_account), legacy_data);
        assert!(!e.storage().persistent().has(&legacy_key));
        assert!(e.storage().persistent().has(&compact_key));

        let compact =
            e.storage().persistent().get::<_, CompactSpendingLimitData>(&compact_key).unwrap();
        assert_eq!(decode_amount(&e, &compact.spending_history.get(0).unwrap().amount), 42);
    });
}

// ==========================================
// WINDOW LENGTH ARITHMETIC & OVERFLOW SAFETY (#189)
// ==========================================

#[test]
fn test_window_seconds_covers_daily_and_weekly_windows() {
    assert_eq!(window_seconds(DAY_IN_LEDGERS), Some(86_400));
    assert_eq!(window_seconds(WEEK_IN_LEDGERS), Some(604_800));
    assert_eq!(window_seconds(u32::MAX), Some(21_474_836_475));
}

#[test]
fn test_enforce_accepts_spend_within_limit() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    install(&client, &rule, &smart_account, 100, DAY_IN_LEDGERS);
    client.enforce(&transfer_context(&e, &target, 60), &signers(&e), &rule, &smart_account);

    let data = client.get_spending_limit_data(&rule.id, &smart_account);
    assert_eq!(data.cached_total_spent, 60);
}

#[test]
#[should_panic(expected = "Error(Contract, #3221)")]
fn test_enforce_rejects_spend_over_limit() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    install(&client, &rule, &smart_account, 100, DAY_IN_LEDGERS);
    client.enforce(&transfer_context(&e, &target, 60), &signers(&e), &rule, &smart_account);
    client.enforce(&transfer_context(&e, &target, 60), &signers(&e), &rule, &smart_account);
}

#[test]
#[should_panic(expected = "Error(Contract, #3220)")]
fn test_enforce_rejects_when_not_installed() {
    let (e, _smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);
    let smart_account = Address::generate(&e);

    client.enforce(&transfer_context(&e, &target, 1), &signers(&e), &rule, &smart_account);
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn test_enforce_rejects_timestamp_where_window_would_overflow() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    install(&client, &rule, &smart_account, 100, DAY_IN_LEDGERS);
    e.ledger().set_timestamp(u64::MAX - 86_400 + 1);

    client.enforce(&transfer_context(&e, &target, 1), &signers(&e), &rule, &smart_account);
}

#[test]
fn test_enforce_accepts_timestamp_at_exact_window_boundary() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    install(&client, &rule, &smart_account, 100, DAY_IN_LEDGERS);
    e.ledger().set_timestamp(u64::MAX - 86_400);

    client.enforce(&transfer_context(&e, &target, 60), &signers(&e), &rule, &smart_account);

    let data = client.get_spending_limit_data(&rule.id, &smart_account);
    assert_eq!(data.cached_total_spent, 60);
}

#[test]
#[should_panic(expected = "Error(Contract, #3221)")]
fn test_enforce_at_extreme_timestamp_still_applies_limit() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    install(&client, &rule, &smart_account, 100, DAY_IN_LEDGERS);
    e.ledger().set_timestamp(u64::MAX - 86_400);

    client.enforce(&transfer_context(&e, &target, 60), &signers(&e), &rule, &smart_account);
    client.enforce(&transfer_context(&e, &target, 60), &signers(&e), &rule, &smart_account);
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn test_enforce_rejects_extreme_timestamp_with_weekly_window() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    install(&client, &rule, &smart_account, 100, WEEK_IN_LEDGERS);
    e.ledger().set_timestamp(u64::MAX);

    client.enforce(&transfer_context(&e, &target, 1), &signers(&e), &rule, &smart_account);
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn test_enforce_rejects_window_total_that_would_overflow() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    install(&client, &rule, &smart_account, i128::MAX, DAY_IN_LEDGERS);
    client.enforce(&transfer_context(&e, &target, 1), &signers(&e), &rule, &smart_account);
    client.enforce(&transfer_context(&e, &target, i128::MAX), &signers(&e), &rule, &smart_account);
}

#[test]
fn test_enforce_evicts_expired_entries_before_overflow_check() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    install(&client, &rule, &smart_account, i128::MAX, 100);
    client.enforce(&transfer_context(&e, &target, i128::MAX), &signers(&e), &rule, &smart_account);

    // Advance past window expiry: the expired i128::MAX entry must be evicted
    // BEFORE checking `cached_total_spent + amount`, preventing a permanent DoS.
    e.ledger().set_sequence_number(e.ledger().sequence() + 101);
    client.enforce(&transfer_context(&e, &target, i128::MAX), &signers(&e), &rule, &smart_account);

    let data = client.get_spending_limit_data(&rule.id, &smart_account);
    assert_eq!(data.cached_total_spent, i128::MAX);
}

#[test]
#[should_panic(expected = "Error(Contract, #3221)")]
fn test_enforce_rejects_huge_amount_without_prior_spend() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    install(&client, &rule, &smart_account, 100, DAY_IN_LEDGERS);
    client.enforce(&transfer_context(&e, &target, i128::MAX), &signers(&e), &rule, &smart_account);
}

#[test]
fn test_enforce_at_high_ledger_sequence_keeps_window_intact() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    e.ledger().set_sequence_number(u32::MAX - 10_000_000);
    install(&client, &rule, &smart_account, 100, DAY_IN_LEDGERS);

    client.enforce(&transfer_context(&e, &target, 60), &signers(&e), &rule, &smart_account);
    let res =
        client.try_enforce(&transfer_context(&e, &target, 60), &signers(&e), &rule, &smart_account);
    assert!(res.is_err());
}

#[test]
fn test_enforce_at_ledger_sequence_below_window_keeps_window_intact() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    e.ledger().set_sequence_number(100);
    install(&client, &rule, &smart_account, 100, DAY_IN_LEDGERS);

    client.enforce(&transfer_context(&e, &target, 60), &signers(&e), &rule, &smart_account);
    let res =
        client.try_enforce(&transfer_context(&e, &target, 60), &signers(&e), &rule, &smart_account);
    assert!(res.is_err());
}
