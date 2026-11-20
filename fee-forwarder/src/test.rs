#![cfg(test)]
extern crate std;

// The "missing authorization" tests below need to mock only one party's
// signature and leave the other unmocked — `mock_all_auths()` approves every
// `require_auth`/`require_auth_for_args` call regardless of identity, so it
// can't express "the user signed but the relayer didn't" (or vice versa).
// Those tests build the authorization tree by hand with `mock_auths`,
// mirroring OZ's own `examples/fee-forwarder-permissioned` test suite.
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, MockAuth, MockAuthInvoke},
    vec, Address, Env, IntoVal, MuxedAddress, String, Symbol, TryIntoVal, Val, Vec,
};
use stellar_tokens::fungible::{Base, FungibleToken};

use super::{FeeForwarder, FeeForwarderClient};

#[contract]
pub struct MockToken;

#[contractimpl]
impl MockToken {
    pub fn __constructor(e: &Env, to: Address) {
        Base::set_metadata(e, 7, String::from_str(e, "Mock Token"), String::from_str(e, "MOCK"));
        Base::mint(e, &to, 1_000_000_000);
    }
}

#[contractimpl(contracttrait)]
impl FungibleToken for MockToken {
    type ContractType = Base;
}

#[contract]
pub struct MockTarget;

#[contractimpl]
impl MockTarget {
    pub fn greet(e: Env) -> String {
        String::from_str(&e, "hello")
    }

    pub fn fail(_e: Env) -> String {
        panic!("target intentionally fails")
    }

    /// Requires `caller`'s own authorization, independent of whoever signed
    /// the enclosing `forward()` call. Mirrors a real Latch smart-account
    /// operation forwarded through this contract, which needs the account's
    /// own signer authorization as a sub-invocation, not just a no-auth call
    /// like `greet()`.
    pub fn act_as(e: Env, caller: Address) -> String {
        caller.require_auth();
        String::from_str(&e, "authorized")
    }
}

struct Setup<'a> {
    fee_forwarder: FeeForwarderClient<'a>,
    token: MockTokenClient<'a>,
    target: MockTargetClient<'a>,
    admin: Address,
    manager: Address,
    user: Address,
    relayer: Address,
    fee_amount: i128,
    max_fee_amount: i128,
}

fn setup(e: &Env) -> Setup<'_> {
    let admin = Address::generate(e);
    let manager = Address::generate(e);
    let user = Address::generate(e);
    let relayer = Address::generate(e);

    let fee_forwarder_id =
        e.register(FeeForwarder, (admin.clone(), manager.clone(), vec![e, relayer.clone()]));
    let token_id = e.register(MockToken, (user.clone(),));
    let target_id = e.register(MockTarget, ());

    Setup {
        fee_forwarder: FeeForwarderClient::new(e, &fee_forwarder_id),
        token: MockTokenClient::new(e, &token_id),
        target: MockTargetClient::new(e, &target_id),
        admin,
        manager,
        user,
        relayer,
        fee_amount: 100_000,
        max_fee_amount: 150_000,
    }
}

/// Builds the (user, relayer) `forward` invocations `mock_auths` expects.
/// Returned by value — a `MockAuth` borrowing these must be constructed by
/// the caller, since a `MockAuthInvoke` built and borrowed inside this
/// function would dangle once it returns.
fn forward_invokes<'a>(
    s: &'a Setup<'a>,
    e: &'a Env,
    fee_amount: i128,
    fn_name: &'a Symbol,
    fn_args: &'a Vec<Val>,
) -> (MockAuthInvoke<'a>, MockAuthInvoke<'a>) {
    let current_ledger = e.ledger().sequence();
    let user_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            s.max_fee_amount,
            current_ledger,
            s.target.address.clone(),
            fn_name.clone(),
            fn_args.clone(),
        )
            .into_val(e),
        sub_invokes: &[],
    };
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            fee_amount,
            s.max_fee_amount,
            current_ledger,
            s.target.address.clone(),
            fn_name.clone(),
            fn_args.clone(),
            s.user.clone(),
            s.relayer.clone(),
        )
            .into_val(e),
        sub_invokes: &[],
    };
    (user_invoke, relayer_invoke)
}

/// Pre-approves `max_fee_amount` directly on the token (authorized by
/// `user`), so `forward`'s Lazy approval strategy sees a sufficient
/// allowance and doesn't need an `approve` sub-invocation folded into the
/// `forward` authorization tree.
fn pre_approve(s: &Setup, e: &Env) {
    let current_ledger = e.ledger().sequence();
    s.token
        .mock_auths(&[MockAuth {
            address: &s.user,
            invoke: &MockAuthInvoke {
                contract: &s.token.address,
                fn_name: "approve",
                args: (
                    s.user.clone(),
                    s.fee_forwarder.address.clone(),
                    s.max_fee_amount,
                    current_ledger,
                )
                    .into_val(e),
                sub_invokes: &[],
            },
        }])
        .approve(&s.user, &s.fee_forwarder.address, &s.max_fee_amount, &current_ledger);
}

// ── forward: happy path ─────────────────────────────────────────────────────

#[test]
fn forward_collects_fee_and_invokes_target() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];

    let initial_user_balance = s.token.balance(&s.user);
    let current_ledger = e.ledger().sequence();

    let (user_invoke, relayer_invoke) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);
    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke },
    ];

    let res: String = s
        .fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &s.fee_amount,
            &s.max_fee_amount,
            &current_ledger,
            &s.target.address,
            &fn_name,
            &fn_args,
            &s.user,
            &s.relayer,
        )
        .try_into_val(&e)
        .unwrap();

    assert_eq!(res, String::from_str(&e, "hello"));
    assert_eq!(s.token.balance(&s.user), initial_user_balance - s.fee_amount);
    assert_eq!(s.token.balance(&s.fee_forwarder.address), s.fee_amount);
}

// ── forward: dual-authorization requirement ─────────────────────────────────

#[test]
#[should_panic]
fn forward_rejects_missing_user_auth() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    let (_user_invoke, relayer_invoke) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);
    let relayer_auth = MockAuth { address: &s.relayer, invoke: &relayer_invoke };

    s.fee_forwarder.mock_auths(&[relayer_auth]).forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );
}

#[test]
#[should_panic]
fn forward_rejects_missing_relayer_auth() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    let (user_invoke, _relayer_invoke) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);
    let user_auth = MockAuth { address: &s.user, invoke: &user_invoke };

    s.fee_forwarder.mock_auths(&[user_auth]).forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );
}

// ── forward: business-rule rejections ───────────────────────────────────────

#[test]
#[should_panic(expected = "Error(Contract, #5003)")]
fn forward_rejects_fee_exceeding_max() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();
    let excessive_fee = s.max_fee_amount + 1;

    s.fee_forwarder.forward(
        &s.token.address,
        &excessive_fee,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #5000)")]
fn forward_rejects_non_allowlisted_fee_token() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    // Enabling any token turns the allowlist on; `s.token` was never added.
    let other_token = Address::generate(&e);
    s.fee_forwarder.enable_fee_token(&other_token, &s.manager);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    s.fee_forwarder.forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #2000)")]
fn forward_rejects_non_executor_caller() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let not_executor = Address::generate(&e);
    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    s.fee_forwarder.forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &not_executor,
    );
}

// ── forward: atomicity ──────────────────────────────────────────────────────

#[test]
fn forward_reverts_fee_collection_when_target_call_fails() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let fn_name = Symbol::new(&e, "fail");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    let initial_user_balance = s.token.balance(&s.user);
    let initial_contract_balance = s.token.balance(&s.fee_forwarder.address);

    let result = s.fee_forwarder.try_forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );

    assert!(result.is_err());
    assert_eq!(s.token.balance(&s.user), initial_user_balance);
    assert_eq!(s.token.balance(&s.fee_forwarder.address), initial_contract_balance);
    assert_eq!(s.token.allowance(&s.user, &s.fee_forwarder.address), 0);
}

// ── forward: nested target authorization ────────────────────────────────────
//
// Covers the realistic case OZ's own reference suite exercises as
// `forward_two_subinvokes`: the target call itself requires its own
// `require_auth()`, folded as a sub-invocation of the same authorization
// tree `user` signs for `forward()` — not a separate top-level entry.

#[test]
fn forward_authorizes_target_call_requiring_nested_auth() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "act_as");
    let fn_args: Vec<Val> = vec![&e, s.user.clone().into_val(&e)];
    let current_ledger = e.ledger().sequence();

    let target_invoke = MockAuthInvoke {
        contract: &s.target.address,
        fn_name: "act_as",
        args: (s.user.clone(),).into_val(&e),
        sub_invokes: &[],
    };
    let user_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            s.max_fee_amount,
            current_ledger,
            s.target.address.clone(),
            fn_name.clone(),
            fn_args.clone(),
        )
            .into_val(&e),
        sub_invokes: &[target_invoke],
    };
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            s.fee_amount,
            s.max_fee_amount,
            current_ledger,
            s.target.address.clone(),
            fn_name.clone(),
            fn_args.clone(),
            s.user.clone(),
            s.relayer.clone(),
        )
            .into_val(&e),
        sub_invokes: &[],
    };
    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke },
    ];

    let res: String = s
        .fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &s.fee_amount,
            &s.max_fee_amount,
            &current_ledger,
            &s.target.address,
            &fn_name,
            &fn_args,
            &s.user,
            &s.relayer,
        )
        .try_into_val(&e)
        .unwrap();

    assert_eq!(res, String::from_str(&e, "authorized"));
}

#[test]
#[should_panic]
fn forward_rejects_target_call_missing_nested_auth() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "act_as");
    let fn_args: Vec<Val> = vec![&e, s.user.clone().into_val(&e)];
    let current_ledger = e.ledger().sequence();

    // Same signed tree as `forward_collects_fee_and_invokes_target`, but
    // without the target's sub-invocation: `user` authorizes `forward()`
    // itself, yet the nested `caller.require_auth()` inside `act_as` has
    // nothing to match, so it must fail even though the outer call is
    // authorized.
    let (user_invoke, relayer_invoke) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);
    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke },
    ];

    s.fee_forwarder.mock_auths(&auths).forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );
}

// ── fee token allowlist: manager-gated ──────────────────────────────────────

#[test]
fn enable_and_disable_fee_token_by_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.fee_forwarder.enable_fee_token(&s.token.address, &s.manager);
    // A second allowlisted token, so disabling `s.token` below leaves the
    // allowlist enabled (it only turns itself off once *no* token remains
    // allowed) rather than falling back open to "all tokens allowed".
    s.fee_forwarder.enable_fee_token(&Address::generate(&e), &s.manager);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // Allowed while enabled.
    s.fee_forwarder.forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );

    s.fee_forwarder.disable_fee_token(&s.token.address, &s.manager);

    let result = s.fee_forwarder.try_forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );
    assert!(result.is_err());
}

#[test]
#[should_panic(expected = "Error(Contract, #2000)")]
fn enable_fee_token_rejects_non_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let not_manager = Address::generate(&e);
    s.fee_forwarder.enable_fee_token(&s.token.address, &not_manager);
}

#[test]
#[should_panic(expected = "Error(Contract, #2000)")]
fn disable_fee_token_rejects_non_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.fee_forwarder.enable_fee_token(&s.token.address, &s.manager);

    let not_manager = Address::generate(&e);
    s.fee_forwarder.disable_fee_token(&s.token.address, &not_manager);
}

// ── sweep_tokens: manager-gated ─────────────────────────────────────────────

#[test]
fn sweep_tokens_by_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    s.fee_forwarder.forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );

    let recipient = Address::generate(&e);
    let swept = s.fee_forwarder.sweep_tokens(&s.token.address, &recipient, &s.manager);

    assert_eq!(swept, s.fee_amount);
    assert_eq!(s.token.balance(&recipient), s.fee_amount);
    assert_eq!(s.token.balance(&s.fee_forwarder.address), 0);
}

#[test]
#[should_panic(expected = "Error(Contract, #2000)")]
fn sweep_tokens_rejects_non_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let not_manager = Address::generate(&e);
    let recipient = Address::generate(&e);
    s.fee_forwarder.sweep_tokens(&s.token.address, &recipient, &not_manager);
}

// ── constructor role wiring ──────────────────────────────────────────────────

#[test]
fn constructor_grants_admin_manager_and_executor_roles() {
    let e = Env::default();
    let s = setup(&e);

    assert!(s.fee_forwarder.has_role(&s.manager, &Symbol::new(&e, "manager")).is_some());
    assert!(s.fee_forwarder.has_role(&s.relayer, &Symbol::new(&e, "executor")).is_some());
    assert_eq!(s.fee_forwarder.get_admin(), Some(s.admin.clone()));
}

// ── Treasury timelock ────────────────────────────────────────────────────────

use crate::TREASURY_TIMELOCK_LEDGERS;

#[test]
fn propose_treasury_stores_pending_proposal() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let new_treasury = Address::generate(&e);
    s.fee_forwarder.propose_treasury(&new_treasury, &s.manager);

    let proposal = s.fee_forwarder.get_pending_treasury().expect("proposal must exist");
    assert_eq!(proposal.new_treasury, new_treasury);
    assert_eq!(proposal.eligible_ledger, e.ledger().sequence() + TREASURY_TIMELOCK_LEDGERS);
}

#[test]
#[should_panic]
fn execute_treasury_change_reverts_before_timelock_elapses() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let new_treasury = Address::generate(&e);
    s.fee_forwarder.propose_treasury(&new_treasury, &s.manager);

    // Try to execute immediately — timelock has not elapsed.
    s.fee_forwarder.execute_treasury_change(&s.manager);
}

#[test]
fn execute_treasury_change_succeeds_after_timelock_elapses() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let new_treasury = Address::generate(&e);
    s.fee_forwarder.propose_treasury(&new_treasury, &s.manager);

    // Advance ledger past the timelock delay.
    e.ledger().set_sequence_number(e.ledger().sequence() + TREASURY_TIMELOCK_LEDGERS);

    s.fee_forwarder.execute_treasury_change(&s.manager);

    // Active treasury is now set; pending proposal is cleared.
    assert_eq!(s.fee_forwarder.get_treasury(), Some(new_treasury.clone()));
    assert!(s.fee_forwarder.get_pending_treasury().is_none());
}

#[test]
fn sweep_tokens_uses_active_treasury_once_set() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    // Forward a call to collect some fees.
    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();
    s.fee_forwarder.forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );

    // Propose, wait, execute the treasury change.
    let treasury = Address::generate(&e);
    s.fee_forwarder.propose_treasury(&treasury, &s.manager);
    e.ledger().set_sequence_number(e.ledger().sequence() + TREASURY_TIMELOCK_LEDGERS);
    s.fee_forwarder.execute_treasury_change(&s.manager);

    // Sweep: recipient arg is ignored once a treasury is active.
    let other_recipient = Address::generate(&e);
    let swept = s.fee_forwarder.sweep_tokens(&s.token.address, &other_recipient, &s.manager);

    assert_eq!(swept, s.fee_amount);
    // Fees went to the treasury, not to other_recipient.
    assert_eq!(s.token.balance(&treasury), s.fee_amount);
    assert_eq!(s.token.balance(&other_recipient), 0);
}

#[test]
fn cancel_treasury_change_removes_pending_proposal() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let new_treasury = Address::generate(&e);
    s.fee_forwarder.propose_treasury(&new_treasury, &s.manager);
    assert!(s.fee_forwarder.get_pending_treasury().is_some());

    s.fee_forwarder.cancel_treasury_change(&s.manager);

    assert!(s.fee_forwarder.get_pending_treasury().is_none());
    assert!(s.fee_forwarder.get_treasury().is_none());
}

#[test]
#[should_panic]
fn execute_treasury_change_reverts_with_no_proposal() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.fee_forwarder.execute_treasury_change(&s.manager);
}

#[test]
#[should_panic]
fn cancel_treasury_change_reverts_with_no_proposal() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.fee_forwarder.cancel_treasury_change(&s.manager);
}

#[test]
fn propose_treasury_overwrites_existing_pending_proposal() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let treasury_a = Address::generate(&e);
    let treasury_b = Address::generate(&e);

    s.fee_forwarder.propose_treasury(&treasury_a, &s.manager);
    // Advance slightly (not past the full timelock) then re-propose.
    e.ledger().set_sequence_number(e.ledger().sequence() + 100);
    s.fee_forwarder.propose_treasury(&treasury_b, &s.manager);

    let proposal = s.fee_forwarder.get_pending_treasury().expect("proposal must exist");
    // The latest proposal wins; eligible_ledger is re-anchored to now.
    assert_eq!(proposal.new_treasury, treasury_b);
    assert_eq!(proposal.eligible_ledger, e.ledger().sequence() + TREASURY_TIMELOCK_LEDGERS);
}

#[test]
#[should_panic(expected = "Error(Contract, #2000)")]
fn propose_treasury_rejects_non_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let not_manager = Address::generate(&e);
    s.fee_forwarder.propose_treasury(&Address::generate(&e), &not_manager);
}

#[test]
#[should_panic(expected = "Error(Contract, #2000)")]
fn execute_treasury_change_rejects_non_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let new_treasury = Address::generate(&e);
    s.fee_forwarder.propose_treasury(&new_treasury, &s.manager);
    e.ledger().set_sequence_number(e.ledger().sequence() + TREASURY_TIMELOCK_LEDGERS);

    let not_manager = Address::generate(&e);
    s.fee_forwarder.execute_treasury_change(&not_manager);
}

#[test]
#[should_panic(expected = "Error(Contract, #2000)")]
fn cancel_treasury_change_rejects_non_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.fee_forwarder.propose_treasury(&Address::generate(&e), &s.manager);

    let not_manager = Address::generate(&e);
    s.fee_forwarder.cancel_treasury_change(&not_manager);
}
