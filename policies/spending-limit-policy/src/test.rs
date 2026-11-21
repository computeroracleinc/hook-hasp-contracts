#![cfg(test)]
extern crate std;

use soroban_sdk::{
    auth::{Context, ContractContext},
    symbol_short,
    testutils::{Address as _, Ledger as _},
    vec, Address, Env, IntoVal, Val, Vec,
};
use stellar_accounts::{
    policies::spending_limit::SpendingLimitAccountParams,
    smart_account::{ContextRule, ContextRuleType, Signer},
};

use crate::{window_seconds, SpendingLimitPolicy, SpendingLimitPolicyClient};

/// One rolling day at an average ledger close time of 5 seconds.
const DAY_IN_LEDGERS: u32 = 17_280;

/// One rolling week in ledgers.
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
// WINDOW LENGTH ARITHMETIC
// ==========================================

#[test]
fn test_window_seconds_covers_daily_and_weekly_windows() {
    assert_eq!(window_seconds(DAY_IN_LEDGERS), Some(86_400)); // 24 hours
    assert_eq!(window_seconds(WEEK_IN_LEDGERS), Some(604_800)); // 7 days
                                                                // The largest window that can be configured stays representable.
    assert_eq!(window_seconds(u32::MAX), Some(21_474_836_475));
}

// ==========================================
// BASELINE ENFORCEMENT
// ==========================================

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
#[should_panic(expected = "Error(Contract, #3221)")] // SpendingLimitExceeded
fn test_enforce_rejects_spend_over_limit() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    install(&client, &rule, &smart_account, 100, DAY_IN_LEDGERS);

    client.enforce(&transfer_context(&e, &target, 60), &signers(&e), &rule, &smart_account);
    client.enforce(&transfer_context(&e, &target, 60), &signers(&e), &rule, &smart_account);
}

#[test]
#[should_panic(expected = "Error(Contract, #3220)")] // SmartAccountNotInstalled
fn test_enforce_rejects_when_not_installed() {
    let (e, _smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);
    let smart_account = Address::generate(&e);

    client.enforce(&transfer_context(&e, &target, 1), &signers(&e), &rule, &smart_account);
}

// ==========================================
// EXTREME TIMESTAMP VALUES
// ==========================================

#[test]
#[should_panic(expected = "Error(Contract, #1)")] // WindowArithmeticOverflow
fn test_enforce_rejects_timestamp_where_window_would_overflow() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    install(&client, &rule, &smart_account, 100, DAY_IN_LEDGERS);

    // The window is 86_400 seconds long, so a clock one second past
    // `u64::MAX - 86_400` has no representable window end: reject instead of
    // wrapping around to a small timestamp.
    e.ledger().set_timestamp(u64::MAX - 86_400 + 1);

    client.enforce(&transfer_context(&e, &target, 1), &signers(&e), &rule, &smart_account);
}

#[test]
fn test_enforce_accepts_timestamp_at_exact_window_boundary() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    install(&client, &rule, &smart_account, 100, DAY_IN_LEDGERS);

    // `u64::MAX - 86_400 + 86_400 == u64::MAX` still fits, so the transfer
    // goes through and the limit keeps working.
    e.ledger().set_timestamp(u64::MAX - 86_400);

    client.enforce(&transfer_context(&e, &target, 60), &signers(&e), &rule, &smart_account);

    let data = client.get_spending_limit_data(&rule.id, &smart_account);
    assert_eq!(data.cached_total_spent, 60);
}

#[test]
#[should_panic(expected = "Error(Contract, #3221)")] // SpendingLimitExceeded
fn test_enforce_at_extreme_timestamp_still_applies_limit() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    install(&client, &rule, &smart_account, 100, DAY_IN_LEDGERS);
    e.ledger().set_timestamp(u64::MAX - 86_400);

    client.enforce(&transfer_context(&e, &target, 60), &signers(&e), &rule, &smart_account);
    client.enforce(&transfer_context(&e, &target, 60), &signers(&e), &rule, &smart_account);
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")] // WindowArithmeticOverflow
fn test_enforce_rejects_extreme_timestamp_with_weekly_window() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    // A seven-day window against a clock at `u64::MAX`: even the longest
    // supported window has no representable end.
    install(&client, &rule, &smart_account, 100, WEEK_IN_LEDGERS);
    e.ledger().set_timestamp(u64::MAX);

    client.enforce(&transfer_context(&e, &target, 1), &signers(&e), &rule, &smart_account);
}

// ==========================================
// EXTREME AMOUNTS / WINDOW TOTALS
// ==========================================

#[test]
#[should_panic(expected = "Error(Contract, #1)")] // WindowArithmeticOverflow
fn test_enforce_rejects_window_total_that_would_overflow() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    install(&client, &rule, &smart_account, i128::MAX, DAY_IN_LEDGERS);

    // One stroop is recorded, so `cached_total_spent + amount` for the next
    // transfer cannot be represented: reject with a contract error instead of
    // trapping on an i128 overflow inside the upstream window comparison.
    client.enforce(&transfer_context(&e, &target, 1), &signers(&e), &rule, &smart_account);
    client.enforce(&transfer_context(&e, &target, i128::MAX), &signers(&e), &rule, &smart_account);
}

#[test]
#[should_panic(expected = "Error(Contract, #3221)")] // SpendingLimitExceeded
fn test_enforce_rejects_huge_amount_without_prior_spend() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    install(&client, &rule, &smart_account, 100, DAY_IN_LEDGERS);

    // With an empty window `0 + amount` cannot overflow, so the transfer is
    // rejected by the limit itself rather than by the overflow guard.
    client.enforce(&transfer_context(&e, &target, i128::MAX), &signers(&e), &rule, &smart_account);
}

#[test]
fn test_enforce_at_high_ledger_sequence_keeps_window_intact() {
    let (e, smart_account, target, client) = setup();
    let rule = create_context_rule(&e, &target);

    // A sequence high enough that `current_ledger - period_ledgers` would
    // underflow a naive subtraction (the upstream eviction saturates instead).
    // The policy is installed at that sequence so its TTL lands alongside it,
    // with headroom left for the entry's maximum TTL.
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

    // `current_ledger - period_ledgers` underflows here, so the cutoff has to
    // saturate at zero instead of wrapping up to a huge sequence that would
    // evict every entry and silently grant a fresh limit.
    e.ledger().set_sequence_number(100);

    install(&client, &rule, &smart_account, 100, DAY_IN_LEDGERS);

    client.enforce(&transfer_context(&e, &target, 60), &signers(&e), &rule, &smart_account);
    let res =
        client.try_enforce(&transfer_context(&e, &target, 60), &signers(&e), &rule, &smart_account);
    assert!(res.is_err());
}
