#![cfg(test)]
extern crate std;

// The "missing authorization" tests below need to mock only one party's
// signature and leave the other unmocked — `mock_all_auths()` approves every
// `require_auth`/`require_auth_for_args` call regardless of identity, so it
// can't express "the user signed but the relayer didn't" (or vice versa).
// Those tests build the authorization tree by hand with `mock_auths`,
// mirroring OZ's own `examples/fee-forwarder-permissioned` test suite.
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, Events as _, Ledger as _, MockAuth, MockAuthInvoke},
    vec, xdr, Address, BytesN, Env, IntoVal, MuxedAddress, String, Symbol, TryFromVal, TryIntoVal,
    Val, Vec,
};
use stellar_tokens::fungible::{Base, FungibleToken};

use super::{FeeForwarder, FeeForwarderClient, TREASURY_TIMELOCK_LEDGERS};

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

// ── call stack depth & cross-contract invocation chain validation ────────────

/// Mock verifier contract that validates an authentication proof/payload.
#[contract]
pub struct MockVerifier;

#[contractimpl]
impl MockVerifier {
    pub fn verify(_e: Env, payload: Val, proof: Val) -> bool {
        let _ = (payload, proof);
        // Validates successfully without exceeding host resource limits
        true
    }
}

/// Mock policy contract that invokes an external verifier to validate policy conditions.
#[contract]
pub struct MockPolicy;

#[contractimpl]
impl MockPolicy {
    pub fn enforce_with_verifier(e: Env, verifier: Address, payload: Val, proof: Val) -> bool {
        let verifier_client = MockVerifierClient::new(&e, &verifier);
        verifier_client.verify(&payload, &proof)
    }
}

/// Mock smart account contract that intercepts forwarded calls and evaluates
/// an attached policy before dispatching.
#[contract]
pub struct MockAccount;

#[contractimpl]
impl MockAccount {
    pub fn execute_with_policy(
        e: Env,
        policy: Address,
        verifier: Address,
        payload: Val,
        proof: Val,
    ) -> bool {
        let policy_client = MockPolicyClient::new(&e, &policy);
        policy_client.enforce_with_verifier(&verifier, &payload, &proof)
    }
}

/// Proxy contract to simulate deep non-reentrant cross-contract call chains.
#[contract]
pub struct RecursiveProxy;

#[contractimpl]
impl RecursiveProxy {
    pub fn recurse_and_call(
        e: Env,
        chain: Vec<Address>,
        target_account: Address,
        policy: Address,
        verifier: Address,
        payload: Val,
        proof: Val,
    ) -> bool {
        if let Some(next_proxy) = chain.get(0) {
            let mut rest = Vec::new(&e);
            for i in 1..chain.len() {
                rest.push_back(chain.get(i).unwrap());
            }
            let proxy_client = RecursiveProxyClient::new(&e, &next_proxy);
            proxy_client.recurse_and_call(
                &rest,
                &target_account,
                &policy,
                &verifier,
                &payload,
                &proof,
            )
        } else {
            let account_client = MockAccountClient::new(&e, &target_account);
            account_client.execute_with_policy(&policy, &verifier, &payload, &proof)
        }
    }
}

#[test]
fn test_account_forwarder_policy_verifier_invocation_chain() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    // Deploy verifier, policy, and account contracts
    let verifier_id = e.register(MockVerifier, ());
    let policy_id = e.register(MockPolicy, ());
    let account_id = e.register(MockAccount, ());

    let dummy_payload = 42u32.into_val(&e);
    let dummy_proof = 99u32.into_val(&e);

    let target_args: Vec<Val> = vec![
        &e,
        policy_id.to_val(),
        verifier_id.to_val(),
        dummy_payload,
        dummy_proof,
    ];

    let current_ledger = e.ledger().sequence();

    // Call stack depth of the chain:
    // Test runner -> FeeForwarder.forward -> MockAccount.execute_with_policy -> MockPolicy.enforce_with_verifier -> MockVerifier.verify
    let result = s.fee_forwarder.forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &account_id,
        &Symbol::new(&e, "execute_with_policy"),
        &target_args,
        &s.user,
        &s.relayer,
    );

    let bool_res: bool = bool::try_from_val(&e, &result).unwrap();
    assert!(bool_res);
    assert_eq!(s.token.balance(&s.fee_forwarder.address), s.fee_amount);
}

#[test]
fn test_invocation_chain_under_maximum_call_stack_depth() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let verifier_id = e.register(MockVerifier, ());
    let policy_id = e.register(MockPolicy, ());
    let account_id = e.register(MockAccount, ());
    let proxy_id = e.register(RecursiveProxy, ());

    let dummy_payload = 123u32.into_val(&e);
    let dummy_proof = 456u32.into_val(&e);

    // Build a chain of distinct proxy contracts (Soroban disallows same-contract
    // re-entrancy) safely within Soroban's maximum host call stack depth limit.
    let mut chain = Vec::new(&e);
    for _ in 0..10 {
        chain.push_back(e.register(RecursiveProxy, ()));
    }

    let target_args: Vec<Val> = vec![
        &e,
        chain.into_val(&e),
        account_id.to_val(),
        policy_id.to_val(),
        verifier_id.to_val(),
        dummy_payload,
        dummy_proof,
    ];

    let current_ledger = e.ledger().sequence();

    let result = s.fee_forwarder.forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &proxy_id,
        &Symbol::new(&e, "recurse_and_call"),
        &target_args,
        &s.user,
        &s.relayer,
    );

    let bool_res: bool = bool::try_from_val(&e, &result).unwrap();
    assert!(bool_res);
    assert_eq!(s.token.balance(&s.fee_forwarder.address), s.fee_amount);
}

#[test]
#[should_panic]
fn test_invocation_chain_exceeding_maximum_call_stack_depth_fails_safely() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let verifier_id = e.register(MockVerifier, ());
    let policy_id = e.register(MockPolicy, ());
    let account_id = e.register(MockAccount, ());
    let proxy_id = e.register(RecursiveProxy, ());

    let dummy_payload = 123u32.into_val(&e);
    let dummy_proof = 456u32.into_val(&e);

    // Passing proxy_id inside its own chain triggers Soroban's re-entrancy/depth failure.
    let chain = vec![&e, proxy_id.clone()];

    let target_args: Vec<Val> = vec![
        &e,
        chain.into_val(&e),
        account_id.to_val(),
        policy_id.to_val(),
        verifier_id.to_val(),
        dummy_payload,
        dummy_proof,
    ];

    let current_ledger = e.ledger().sequence();

    s.fee_forwarder.forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &proxy_id,
        &Symbol::new(&e, "recurse_and_call"),
        &target_args,
        &s.user,
        &s.relayer,
    );
}

// ── fee cap: MAX_FEE_CAP enforcement ────────────────────────────────────────

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn forward_rejects_fee_exceeding_cap() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    // Lower the cap to below the default fee_amount used in setup.
    s.fee_forwarder.set_fee_cap(&(s.fee_amount - 1), &s.manager);

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
fn forward_accepts_fee_exactly_at_cap() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    // Set cap exactly equal to fee_amount — boundary should be accepted.
    s.fee_forwarder.set_fee_cap(&s.fee_amount, &s.manager);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // Should not panic.
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
fn set_fee_cap_by_manager_updates_cap() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let new_cap: i128 = 500_000;
    s.fee_forwarder.set_fee_cap(&new_cap, &s.manager);
    assert_eq!(s.fee_forwarder.get_fee_cap(), new_cap);
}

#[test]
#[should_panic(expected = "Error(Contract, #2000)")]
fn set_fee_cap_rejects_non_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let not_manager = Address::generate(&e);
    s.fee_forwarder.set_fee_cap(&500_000, &not_manager);
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn set_fee_cap_rejects_zero() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.fee_forwarder.set_fee_cap(&0, &s.manager);
}

#[test]
fn constructor_sets_default_fee_cap() {
    let e = Env::default();
    let s = setup(&e);

    use super::DEFAULT_FEE_CAP;
    assert_eq!(s.fee_forwarder.get_fee_cap(), DEFAULT_FEE_CAP);
}

// ── adversarial test suite: compromised relayer simulation ───────────────────
//
// Simulates malicious modifications to parameters in `forward` (sponsored execution)
// by an adversarial / compromised relayer attempting to:
//   - Steal user funds (excessive fee, negative/zero fee, redirecting fees, changing fee token)
//   - Modify calldata (target contract, target function, target arguments)
//   - Bypass authorization (substituting user, executing expired authorization,
//     unauthorized caller posing as relayer, replay/mismatched auth tree)
//
// Acceptance Criteria: All compromised requests strictly rejected.

#[test]
#[should_panic]
fn adversarial_relayer_tamper_target_contract() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // User signs authorization for legitimate target contract
    let (user_invoke, _) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);

    // Adversarial relayer attempts to redirect invocation to a malicious target
    let malicious_target = Address::generate(&e);
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            s.fee_amount,
            s.max_fee_amount,
            current_ledger,
            malicious_target.clone(),
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

    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &s.fee_amount,
            &s.max_fee_amount,
            &current_ledger,
            &malicious_target,
            &fn_name,
            &fn_args,
            &s.user,
            &s.relayer,
        );
}

#[test]
#[should_panic]
fn adversarial_relayer_tamper_target_function() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let legitimate_fn = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // User signs for legitimate function "greet"
    let (user_invoke, _) = forward_invokes(&s, &e, s.fee_amount, &legitimate_fn, &fn_args);

    // Adversarial relayer modifies target function to "drain" or unexpected function
    let malicious_fn = Symbol::new(&e, "drain");
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            s.fee_amount,
            s.max_fee_amount,
            current_ledger,
            s.target.address.clone(),
            malicious_fn.clone(),
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

    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &s.fee_amount,
            &s.max_fee_amount,
            &current_ledger,
            &s.target.address,
            &malicious_fn,
            &fn_args,
            &s.user,
            &s.relayer,
        );
}

#[test]
#[should_panic]
fn adversarial_relayer_tamper_target_arguments() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "act_as");
    let legitimate_args: Vec<Val> = vec![&e, s.user.clone().into_val(&e)];
    let current_ledger = e.ledger().sequence();

    // User signs invocation with legitimate arguments
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
            legitimate_args.clone(),
        )
            .into_val(&e),
        sub_invokes: &[target_invoke],
    };

    // Adversarial relayer modifies arguments (e.g. replacing caller with attacker)
    let attacker = Address::generate(&e);
    let tampered_args: Vec<Val> = vec![&e, attacker.clone().into_val(&e)];
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
            tampered_args.clone(),
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

    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &s.fee_amount,
            &s.max_fee_amount,
            &current_ledger,
            &s.target.address,
            &fn_name,
            &tampered_args,
            &s.user,
            &s.relayer,
        );
}

#[test]
#[should_panic]
fn adversarial_relayer_tamper_fee_token() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // User signed auth for s.token
    let (user_invoke, _) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);

    // Relayer attempts to substitute a different, more expensive token or victim token
    let malicious_token = Address::generate(&e);
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            malicious_token.clone(),
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

    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &malicious_token,
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
fn adversarial_relayer_tamper_user_address() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    let (user_invoke, _) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);

    // Relayer attempts to charge another innocent user who did not authorize this call
    let victim_user = Address::generate(&e);
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
            victim_user.clone(),
            s.relayer.clone(),
        )
            .into_val(&e),
        sub_invokes: &[],
    };

    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke },
    ];

    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &s.fee_amount,
            &s.max_fee_amount,
            &current_ledger,
            &s.target.address,
            &fn_name,
            &fn_args,
            &victim_user,
            &s.relayer,
        );
}

#[test]
#[should_panic]
fn adversarial_relayer_tamper_max_fee_amount() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // User signed auth with max_fee_amount = 150_000
    let (user_invoke, _) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);

    // Relayer attempts to pass a forged higher max_fee_amount to collect exorbitant fee
    let inflated_max_fee = s.max_fee_amount * 10;
    let inflated_fee = inflated_max_fee;
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            inflated_fee,
            inflated_max_fee,
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

    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &inflated_fee,
            &inflated_max_fee,
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
fn adversarial_relayer_tamper_expiration_ledger() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let signed_ledger = e.ledger().sequence();

    // User signed auth with signed_ledger
    let (user_invoke, _) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);

    // Relayer modifies expiration_ledger parameter
    let modified_ledger = signed_ledger + 500;
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            s.fee_amount,
            s.max_fee_amount,
            modified_ledger,
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

    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &s.fee_amount,
            &s.max_fee_amount,
            &modified_ledger,
            &s.target.address,
            &fn_name,
            &fn_args,
            &s.user,
            &s.relayer,
        );
}

#[test]
#[should_panic(expected = "Error(Contract, #5003)")]
fn adversarial_relayer_excessive_fee_beyond_max() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // Compromised relayer attempts to extract fee > max_fee_amount
    let stolen_fee = s.max_fee_amount + 10_000;
    let (user_invoke, _) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            stolen_fee,
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

    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &stolen_fee,
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
#[should_panic(expected = "Error(Contract, #5003)")]
fn adversarial_relayer_zero_or_negative_fee() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    let invalid_fee = 0i128;
    let (user_invoke, _) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward",
        args: (
            s.token.address.clone(),
            invalid_fee,
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

    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &invalid_fee,
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
fn adversarial_compromised_caller_not_holding_executor_role() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // Attacker without executor role tries to execute sponsored request
    let attacker = Address::generate(&e);
    let (user_invoke, _) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);
    let attacker_invoke = MockAuthInvoke {
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
            attacker.clone(),
        )
            .into_val(&e),
        sub_invokes: &[],
    };

    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &attacker, invoke: &attacker_invoke },
    ];

    s.fee_forwarder
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
            &attacker,
        );
}

#[test]
#[should_panic]
fn adversarial_relayer_expired_ledger() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let past_ledger = 100u32;

    // Fast-forward current ledger past the authorization expiration ledger
    e.ledger().set_sequence_number(200u32);

    let (user_invoke, relayer_invoke) = forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);
    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke },
    ];

    // Relayer attempts to submit an expired request
    s.fee_forwarder
        .mock_auths(&auths)
        .forward(
            &s.token.address,
            &s.fee_amount,
            &s.max_fee_amount,
            &past_ledger,
            &s.target.address,
            &fn_name,
            &fn_args,
            &s.user,
            &s.relayer,
        );
}


// ── circuit breaker (#155) ───────────────────────────────────────────────────

#[test]
fn circuit_breaker_trips_when_budget_exhausted() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    // Set budget to exactly one fee_amount — consuming the full budget trips
    // the breaker and persists the paused state on-chain.
    s.fee_forwarder.set_emergency_budget(&s.token.address, &s.fee_amount, &s.manager);

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

    assert!(s.fee_forwarder.get_circuit_breaker_paused(&s.token.address));
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn forward_rejects_when_circuit_breaker_tripped_after_budget_exhaustion() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    // First call exhausts the exact budget, persisting CircuitBreakerPaused = true.
    s.fee_forwarder.set_emergency_budget(&s.token.address, &s.fee_amount, &s.manager);

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
    assert!(s.fee_forwarder.get_circuit_breaker_paused(&s.token.address));

    // Second call must be rejected immediately with CircuitBreakerTripped (#3).
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
#[should_panic(expected = "Error(Contract, #3)")]
fn forward_rejects_single_call_exceeding_emergency_budget() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.fee_forwarder.set_emergency_budget(&s.token.address, &(s.fee_amount - 1), &s.manager);

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
fn manual_trip_and_reset_circuit_breaker() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    // Manager explicitly trips the circuit breaker; state persists on-chain.
    s.fee_forwarder.trip_circuit_breaker(&s.token.address, &s.manager);
    assert!(s.fee_forwarder.get_circuit_breaker_paused(&s.token.address));

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    let blocked = s.fee_forwarder.try_forward(
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
    assert!(blocked.is_err());

    // Manager resets it.
    s.fee_forwarder.reset_circuit_breaker(&s.token.address, &s.manager);
    assert!(!s.fee_forwarder.get_circuit_breaker_paused(&s.token.address));

    // Forwarding resumes cleanly.
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
fn reset_circuit_breaker_resumes_forwarding_after_budget_trip() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.fee_forwarder.set_emergency_budget(&s.token.address, &s.fee_amount, &s.manager);

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
    assert!(s.fee_forwarder.get_circuit_breaker_paused(&s.token.address));

    s.fee_forwarder.reset_circuit_breaker(&s.token.address, &s.manager);
    assert!(!s.fee_forwarder.get_circuit_breaker_paused(&s.token.address));

    s.fee_forwarder.set_emergency_budget(&s.token.address, &s.max_fee_amount, &s.manager);

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
fn set_emergency_budget_rejects_non_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let not_manager = Address::generate(&e);
    s.fee_forwarder.set_emergency_budget(&s.token.address, &s.fee_amount, &not_manager);
}

#[test]
#[should_panic(expected = "Error(Contract, #2000)")]
fn trip_circuit_breaker_rejects_non_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let not_manager = Address::generate(&e);
    s.fee_forwarder.trip_circuit_breaker(&s.token.address, &not_manager);
}

#[test]
#[should_panic(expected = "Error(Contract, #2000)")]
fn reset_circuit_breaker_rejects_non_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let not_manager = Address::generate(&e);
    s.fee_forwarder.reset_circuit_breaker(&s.token.address, &not_manager);
}

#[test]
fn forward_without_budget_configured_ignores_circuit_breaker() {
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

    assert!(!s.fee_forwarder.get_circuit_breaker_paused(&s.token.address));
}

// ── tiered relayer refund rates (#157) ───────────────────────────────────────

fn configure_tiers(s: &Setup, e: &Env) {
    let base_fee: i128 = 100;
    let thresholds = vec![e, 0_u64, 1_000_u64, 10_000_u64];
    let multipliers = vec![e, 2_u32, 5_u32, 10_u32];
    s.fee_forwarder.set_gas_tier_config(&base_fee, &thresholds, &multipliers, &s.manager);
}

#[test]
fn tiered_refund_low_gas_uses_first_tier() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);
    configure_tiers(&s, &e);

    // 500 gas -> tier 0 (multiplier 2): 100 + 500 * 2 / 1_000 = 101
    assert_eq!(s.fee_forwarder.compute_tiered_refund(&500_u64), 101);
}

#[test]
fn tiered_refund_mid_gas_uses_second_tier() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);
    configure_tiers(&s, &e);

    // 5_000 gas -> tier 1 (multiplier 5): 100 + 5_000 * 5 / 1_000 = 125
    assert_eq!(s.fee_forwarder.compute_tiered_refund(&5_000_u64), 125);
}

#[test]
fn tiered_refund_high_gas_uses_third_tier() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);
    configure_tiers(&s, &e);

    // 20_000 gas -> tier 2 (multiplier 10): 100 + 20_000 * 10 / 1_000 = 300
    assert_eq!(s.fee_forwarder.compute_tiered_refund(&20_000_u64), 300);
}

#[test]
fn tiered_refund_returns_zero_when_no_config() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    assert_eq!(s.fee_forwarder.compute_tiered_refund(&5_000_u64), 0);
}

#[test]
#[should_panic(expected = "Error(Contract, #2000)")]
fn set_gas_tier_config_rejects_non_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let not_manager = Address::generate(&e);
    let base_fee: i128 = 100;
    let thresholds = vec![&e, 0_u64, 1_000_u64];
    let multipliers = vec![&e, 2_u32, 5_u32];
    s.fee_forwarder.set_gas_tier_config(&base_fee, &thresholds, &multipliers, &not_manager);
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn set_gas_tier_config_rejects_mismatched_lengths() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let thresholds = vec![&e, 0_u64, 1_000_u64];
    let multipliers = vec![&e, 2_u32];
    s.fee_forwarder.set_gas_tier_config(&100_i128, &thresholds, &multipliers, &s.manager);
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn set_gas_tier_config_rejects_non_ascending_thresholds() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let thresholds = vec![&e, 1_000_u64, 1_000_u64];
    let multipliers = vec![&e, 2_u32, 5_u32];
    s.fee_forwarder.set_gas_tier_config(&100_i128, &thresholds, &multipliers, &s.manager);
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn set_gas_tier_config_rejects_negative_base_fee() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let thresholds = vec![&e, 0_u64];
    let multipliers = vec![&e, 2_u32];
    s.fee_forwarder.set_gas_tier_config(&-1_i128, &thresholds, &multipliers, &s.manager);
}

// ── re-entrancy guard (#158) ─────────────────────────────────────────────────

#[test]
fn forward_clears_reentrancy_lock_after_successful_call() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

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

    pre_approve(&s, &e);
    let current_ledger2 = e.ledger().sequence();
    let (user_invoke2, relayer_invoke2) =
        forward_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);
    let auths2 = [
        MockAuth { address: &s.user, invoke: &user_invoke2 },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke2 },
    ];
    s.fee_forwarder.mock_auths(&auths2).forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger2,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #9001)")]
fn forward_rejects_reentrant_call_when_lock_is_set() {
    use soroban_sdk::symbol_short;

    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    e.as_contract(&s.fee_forwarder.address, || {
        e.storage().instance().set(&symbol_short!("reentrant"), &true);
    });

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

// ── front-running mitigation (#159) ──────────────────────────────────────────

fn restricted_invokes<'a>(
    s: &'a Setup<'a>,
    e: &'a Env,
    fee_amount: i128,
    fn_name: &'a Symbol,
    fn_args: &'a Vec<Val>,
) -> (MockAuthInvoke<'a>, MockAuthInvoke<'a>) {
    let current_ledger = e.ledger().sequence();
    let user_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward_restricted",
        args: (
            s.token.address.clone(),
            s.max_fee_amount,
            current_ledger,
            s.target.address.clone(),
            fn_name.clone(),
            fn_args.clone(),
            s.relayer.clone(),
        )
            .into_val(e),
        sub_invokes: &[],
    };
    let relayer_invoke = MockAuthInvoke {
        contract: &s.fee_forwarder.address,
        fn_name: "forward_restricted",
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
            s.relayer.clone(),
        )
            .into_val(e),
        sub_invokes: &[],
    };
    (user_invoke, relayer_invoke)
}

#[test]
fn forward_restricted_succeeds_for_authorized_executor_and_charges_user() {
    let e = Env::default();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    let (user_invoke, relayer_invoke) =
        restricted_invokes(&s, &e, s.fee_amount, &fn_name, &fn_args);
    let auths = [
        MockAuth { address: &s.user, invoke: &user_invoke },
        MockAuth { address: &s.relayer, invoke: &relayer_invoke },
    ];

    let initial_user_balance = s.token.balance(&s.user);

    s.fee_forwarder.mock_auths(&auths).forward_restricted(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.relayer,
        &s.relayer,
    );

    assert_eq!(s.token.balance(&s.user), initial_user_balance - s.fee_amount);
    assert_eq!(s.token.balance(&s.fee_forwarder.address), s.fee_amount);
}

#[test]
#[should_panic(expected = "Error(Contract, #8001)")]
fn forward_restricted_rejects_third_party_relayer_frontrun() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);
    pre_approve(&s, &e);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    let other_executor = Address::generate(&e);
    s.fee_forwarder.grant_role(&other_executor, &Symbol::new(&e, "executor"), &s.admin);

    s.fee_forwarder.forward_restricted(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &other_executor,
        &s.relayer,
    );
}

// ── RBAC hardening (#160) ────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "Error(Contract, #7001)")]
fn manager_cannot_self_elevate_to_admin() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.fee_forwarder.promote_to_admin(&s.manager, &s.manager);
}

#[test]
fn admin_can_promote_to_admin() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let new_admin = Address::generate(&e);
    s.fee_forwarder.promote_to_admin(&new_admin, &s.admin);
    // Two-step transfer: admin remains unchanged until new_admin accepts.
    assert_eq!(s.fee_forwarder.get_admin(), Some(s.admin.clone()));
    s.fee_forwarder.accept_admin_transfer();
    assert_eq!(s.fee_forwarder.get_admin(), Some(new_admin));
}

#[test]
#[should_panic(expected = "Error(Contract, #7001)")]
fn manager_cannot_grant_manager_role_to_self() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.fee_forwarder.grant_manager(&s.manager, &s.manager);
}

#[test]
#[should_panic(expected = "Error(Contract, #7001)")]
fn non_admin_cannot_grant_manager_role() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let new_manager = Address::generate(&e);
    s.fee_forwarder.grant_manager(&new_manager, &s.manager);
}

#[test]
fn admin_can_grant_manager_role() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let new_manager = Address::generate(&e);
    s.fee_forwarder.grant_manager(&new_manager, &s.admin);
    assert!(s.fee_forwarder.has_role(&new_manager, &Symbol::new(&e, "manager")).is_some());
}

#[test]
#[should_panic(expected = "Error(Contract, #7001)")]
fn manager_cannot_reassign_treasury() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let new_treasury = Address::generate(&e);
    s.fee_forwarder.set_treasury(&new_treasury, &s.manager);
}

#[test]
fn admin_can_set_treasury_and_sweep_enforces_it() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let treasury = Address::generate(&e);
    s.fee_forwarder.set_treasury(&treasury, &s.admin);
    assert_eq!(s.fee_forwarder.get_treasury(), Some(treasury.clone()));

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

    let attacker_recipient = Address::generate(&e);
    let swept = s.fee_forwarder.sweep_tokens(&s.token.address, &attacker_recipient, &s.manager);
    assert_eq!(swept, s.fee_amount);
    assert_eq!(s.token.balance(&treasury), s.fee_amount);
    assert_eq!(s.token.balance(&attacker_recipient), 0);
}

// ── max payload size (#161) ──────────────────────────────────────────────────

#[test]
fn max_payload_size_is_unset_by_default() {
    let e = Env::default();
    let s = setup(&e);
    assert_eq!(s.fee_forwarder.max_payload_size(), None);
}

#[test]
fn set_and_get_max_payload_size() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.fee_forwarder.set_max_payload_size(&1024_u32, &s.manager);
    assert_eq!(s.fee_forwarder.max_payload_size(), Some(1024));
}

#[test]
fn set_max_payload_size_zero_removes_limit() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.fee_forwarder.set_max_payload_size(&1024_u32, &s.manager);
    s.fee_forwarder.set_max_payload_size(&0_u32, &s.manager);
    assert_eq!(s.fee_forwarder.max_payload_size(), None);
}

#[test]
#[should_panic(expected = "Error(Contract, #2000)")]
fn set_max_payload_size_rejects_non_manager() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let not_manager = Address::generate(&e);
    s.fee_forwarder.set_max_payload_size(&1024_u32, &not_manager);
}

#[test]
fn forward_accepts_payload_within_limit() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.fee_forwarder.set_max_payload_size(&8192_u32, &s.manager);

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
#[should_panic(expected = "Error(Contract, #7)")]
fn forward_rejects_oversized_payload() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.fee_forwarder.set_max_payload_size(&1_u32, &s.manager);

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
fn forward_skips_payload_check_when_no_limit_set() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    assert_eq!(s.fee_forwarder.max_payload_size(), None);

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

// ── executor permit signature verification (#162) ────────────────────────────

fn test_signing_key() -> SigningKey {
    let secret: [u8; 32] = [
        157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73, 197,
        105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
    ];
    SigningKey::from_bytes(&secret)
}

#[allow(clippy::too_many_arguments)]
fn build_permit(
    e: &Env,
    s: &Setup,
    signing_key: &SigningKey,
    executor: Address,
    nonce: u64,
    permit_expiration_ledger: u32,
    fee_amount: i128,
    max_fee_amount: i128,
    expiration_ledger: u32,
    target_contract: &Address,
    target_fn: &Symbol,
    target_args: &Vec<Val>,
) -> super::ExecutorPermit {
    use sha2::{Digest, Sha256};
    use soroban_sdk::xdr::ToXdr;

    let domain_tag = b"FeeForwarder:ExecutorPermit:v1\x00\x00";
    let mut payload = std::vec![];
    payload.extend_from_slice(domain_tag);
    payload.extend_from_slice(&e.ledger().network_id().to_array());

    let push_bytes = |dst: &mut std::vec::Vec<u8>, b: soroban_sdk::Bytes| {
        for i in 0..b.len() {
            dst.push(b.get(i).unwrap());
        }
    };

    push_bytes(&mut payload, s.fee_forwarder.address.clone().to_xdr(e));
    push_bytes(&mut payload, executor.clone().to_xdr(e));
    payload.extend_from_slice(&nonce.to_be_bytes());
    payload.extend_from_slice(&permit_expiration_ledger.to_be_bytes());
    push_bytes(&mut payload, s.token.address.clone().to_xdr(e));
    payload.extend_from_slice(&fee_amount.to_be_bytes());
    payload.extend_from_slice(&max_fee_amount.to_be_bytes());
    payload.extend_from_slice(&expiration_ledger.to_be_bytes());
    push_bytes(&mut payload, target_contract.clone().to_xdr(e));
    push_bytes(&mut payload, target_fn.clone().to_xdr(e));
    push_bytes(&mut payload, target_args.clone().to_xdr(e));
    push_bytes(&mut payload, s.user.clone().to_xdr(e));

    let hash = Sha256::digest(&payload);
    let sig_bytes = signing_key.sign(&hash).to_bytes();
    let pubkey_bytes = *signing_key.verifying_key().as_bytes();

    super::ExecutorPermit {
        signer_pubkey: BytesN::from_array(e, &pubkey_bytes),
        signature: BytesN::from_array(e, &sig_bytes),
        executor,
        nonce,
        expiration_ledger: permit_expiration_ledger,
    }
}

fn register_test_permit_signer(e: &Env, s: &Setup, signing_key: &SigningKey) {
    let pubkey = BytesN::from_array(e, signing_key.verifying_key().as_bytes());
    s.fee_forwarder.register_permit_signer(&pubkey, &s.admin);
}

#[test]
fn forward_with_permit_valid_permit_accepted() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);
    pre_approve(&s, &e);

    let signing_key = test_signing_key();
    register_test_permit_signer(&e, &s, &signing_key);

    let current_ledger = e.ledger().sequence();
    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let permit = build_permit(
        &e,
        &s,
        &signing_key,
        s.relayer.clone(),
        1,
        current_ledger + 100,
        s.fee_amount,
        s.max_fee_amount,
        current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
    );

    let res: String = s
        .fee_forwarder
        .forward_with_permit(
            &permit,
            &s.token.address,
            &s.fee_amount,
            &s.max_fee_amount,
            &current_ledger,
            &s.target.address,
            &fn_name,
            &fn_args,
            &s.user,
        )
        .try_into_val(&e)
        .unwrap();

    assert_eq!(res, String::from_str(&e, "hello"));
}

#[test]
#[should_panic(expected = "Error(Contract, #10)")]
fn forward_with_permit_rejects_unregistered_signer_pubkey() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);
    pre_approve(&s, &e);

    // Signer is NOT registered by admin — must be rejected with UnauthorizedPermitSigner (#10).
    let signing_key = test_signing_key();
    let current_ledger = e.ledger().sequence();
    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let permit = build_permit(
        &e,
        &s,
        &signing_key,
        s.relayer.clone(),
        1,
        current_ledger + 100,
        s.fee_amount,
        s.max_fee_amount,
        current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
    );

    s.fee_forwarder.forward_with_permit(
        &permit,
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #8001)")]
fn forward_with_permit_rejects_non_executor_in_permit() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);
    pre_approve(&s, &e);

    let signing_key = test_signing_key();
    register_test_permit_signer(&e, &s, &signing_key);

    let not_executor = Address::generate(&e);
    let current_ledger = e.ledger().sequence();
    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let permit = build_permit(
        &e,
        &s,
        &signing_key,
        not_executor,
        1,
        current_ledger + 100,
        s.fee_amount,
        s.max_fee_amount,
        current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
    );

    s.fee_forwarder.forward_with_permit(
        &permit,
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
    );
}

#[test]
#[should_panic]
fn forward_with_permit_rejects_tampered_fee_amount() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);
    pre_approve(&s, &e);

    let signing_key = test_signing_key();
    register_test_permit_signer(&e, &s, &signing_key);

    let current_ledger = e.ledger().sequence();
    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let permit = build_permit(
        &e,
        &s,
        &signing_key,
        s.relayer.clone(),
        1,
        current_ledger + 100,
        s.fee_amount,
        s.max_fee_amount,
        current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
    );

    // Submit with tampered fee_amount — signature must fail verification.
    s.fee_forwarder.forward_with_permit(
        &permit,
        &s.token.address,
        &(s.fee_amount + 1),
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
    );
}

#[test]
fn is_nonce_used_false_before_use() {
    let e = Env::default();
    let s = setup(&e);
    let signing_key = test_signing_key();
    let pubkey = BytesN::from_array(&e, signing_key.verifying_key().as_bytes());
    assert!(!s.fee_forwarder.is_nonce_used(&pubkey, &1_u64));
}

#[test]
fn is_nonce_used_true_after_use() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);
    pre_approve(&s, &e);

    let signing_key = test_signing_key();
    register_test_permit_signer(&e, &s, &signing_key);

    let current_ledger = e.ledger().sequence();
    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let permit = build_permit(
        &e,
        &s,
        &signing_key,
        s.relayer.clone(),
        42,
        current_ledger + 100,
        s.fee_amount,
        s.max_fee_amount,
        current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
    );
    let pubkey = permit.signer_pubkey.clone();

    s.fee_forwarder.forward_with_permit(
        &permit,
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
    );

    assert!(s.fee_forwarder.is_nonce_used(&pubkey, &42_u64));
}

#[test]
#[should_panic(expected = "Error(Contract, #9)")]
fn forward_with_permit_rejects_replayed_nonce() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);
    pre_approve(&s, &e);

    let signing_key = test_signing_key();
    register_test_permit_signer(&e, &s, &signing_key);

    let current_ledger = e.ledger().sequence();
    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let permit = build_permit(
        &e,
        &s,
        &signing_key,
        s.relayer.clone(),
        7,
        current_ledger + 100,
        s.fee_amount,
        s.max_fee_amount,
        current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
    );

    s.fee_forwarder.forward_with_permit(
        &permit,
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
    );

    s.fee_forwarder.forward_with_permit(
        &permit,
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")]
fn forward_with_permit_rejects_expired_permit() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let signing_key = test_signing_key();
    register_test_permit_signer(&e, &s, &signing_key);

    let current_ledger = e.ledger().sequence();
    e.ledger().set_sequence_number(current_ledger + 10);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];
    let permit = build_permit(
        &e,
        &s,
        &signing_key,
        s.relayer.clone(),
        99,
        current_ledger + 5,
        s.fee_amount,
        s.max_fee_amount,
        current_ledger + 10,
        &s.target.address,
        &fn_name,
        &fn_args,
    );

    s.fee_forwarder.forward_with_permit(
        &permit,
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &(current_ledger + 10),
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
    );
}

// ── analytics events (#164) ──────────────────────────────────────────────────

#[test]
fn forward_emits_sponsored_call_executed_event() {
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

    let contract_events =
        e.events().all().filter_by_contract(&s.fee_forwarder.address);
    assert!(
        !contract_events.events().is_empty(),
        "expected SponsoredCallExecuted event after forward"
    );
}

#[test]
fn forward_event_not_emitted_when_target_fails() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let fn_name = Symbol::new(&e, "fail");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    let _ = s.fee_forwarder.try_forward(
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

    let contract_events =
        e.events().all().filter_by_contract(&s.fee_forwarder.address);
    assert!(
        contract_events.events().is_empty(),
        "no event should be emitted when the forwarded call fails"
    );
}

#[test]
fn forward_emits_correct_event_fields() {
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

    let events = e.events().all().filter_by_contract(&s.fee_forwarder.address);
    let raw_events = events.events();
    assert!(!raw_events.is_empty(), "expected at least one event");

    // The last contract event emitted by `forward` is `SponsoredCallExecuted`.
    let last_event = raw_events.last().unwrap();
    let xdr::ContractEventBody::V0(v0) = &last_event.body;

    // Topics: [event_name, sponsor, relayer].
    assert_eq!(v0.topics.len(), 3);
    let event_name: Symbol =
        Symbol::try_from_val(&e, &Val::try_from_val(&e, &v0.topics[0]).unwrap()).unwrap();
    let sponsor: Address =
        Address::try_from_val(&e, &Val::try_from_val(&e, &v0.topics[1]).unwrap()).unwrap();
    let relayer: Address =
        Address::try_from_val(&e, &Val::try_from_val(&e, &v0.topics[2]).unwrap()).unwrap();

    assert_eq!(event_name, Symbol::new(&e, "sponsored_call_executed"));
    assert_eq!(sponsor, s.user);
    assert_eq!(relayer, s.relayer);

    let data_val: Val = Val::try_from_val(&e, &v0.data).unwrap();
    let data_map: soroban_sdk::Map<Symbol, Val> =
        soroban_sdk::Map::try_from_val(&e, &data_val).unwrap();
    let target_contract: Address = data_map
        .get(Symbol::new(&e, "target_contract"))
        .unwrap()
        .try_into_val(&e)
        .unwrap();
    let fee_token: Address = data_map
        .get(Symbol::new(&e, "fee_token"))
        .unwrap()
        .try_into_val(&e)
        .unwrap();
    let fee_amount: i128 = data_map
        .get(Symbol::new(&e, "fee_amount"))
        .unwrap()
        .try_into_val(&e)
        .unwrap();
    let max_fee_amount: i128 = data_map
        .get(Symbol::new(&e, "max_fee_amount"))
        .unwrap()
        .try_into_val(&e)
        .unwrap();

    assert_eq!(target_contract, s.target.address);
    assert_eq!(fee_token, s.token.address);
    assert_eq!(fee_amount, s.fee_amount);
    assert_eq!(max_fee_amount, s.max_fee_amount);
}

// ── Treasury timelock (#168) ─────────────────────────────────────────────────

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
#[should_panic(expected = "Error(Contract, #12)")]
fn execute_treasury_change_reverts_before_timelock_elapses() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let new_treasury = Address::generate(&e);
    s.fee_forwarder.propose_treasury(&new_treasury, &s.manager);

    s.fee_forwarder.execute_treasury_change(&s.manager);
}

#[test]
fn execute_treasury_change_succeeds_after_timelock_elapses() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let new_treasury = Address::generate(&e);
    s.fee_forwarder.propose_treasury(&new_treasury, &s.manager);

    e.ledger().set_sequence_number(e.ledger().sequence() + TREASURY_TIMELOCK_LEDGERS);

    s.fee_forwarder.execute_treasury_change(&s.manager);

    assert_eq!(s.fee_forwarder.get_treasury(), Some(new_treasury));
    assert!(s.fee_forwarder.get_pending_treasury().is_none());
}

#[test]
fn sweep_tokens_uses_active_treasury_once_set() {
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

    let treasury = Address::generate(&e);
    s.fee_forwarder.propose_treasury(&treasury, &s.manager);
    e.ledger().set_sequence_number(e.ledger().sequence() + TREASURY_TIMELOCK_LEDGERS);
    s.fee_forwarder.execute_treasury_change(&s.manager);

    let other_recipient = Address::generate(&e);
    let swept = s.fee_forwarder.sweep_tokens(&s.token.address, &other_recipient, &s.manager);

    assert_eq!(swept, s.fee_amount);
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
#[should_panic(expected = "Error(Contract, #11)")]
fn execute_treasury_change_reverts_with_no_proposal() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    s.fee_forwarder.execute_treasury_change(&s.manager);
}

#[test]
#[should_panic(expected = "Error(Contract, #11)")]
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
    e.ledger().set_sequence_number(e.ledger().sequence() + 100);
    s.fee_forwarder.propose_treasury(&treasury_b, &s.manager);

    let proposal = s.fee_forwarder.get_pending_treasury().expect("proposal must exist");
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

#[test]
fn test_gas_calibration_and_resource_bounds_v22() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let target_args: Vec<Val> = Vec::new(&e);
    let expiration_ledger = e.ledger().sequence() + 100;

    // Reset budget before benchmarking forward invocation
    e.cost_estimate().budget().reset_default();

    s.fee_forwarder.forward(
        &s.token.address,
        &s.fee_amount,
        &s.max_fee_amount,
        &expiration_ledger,
        &s.target.address,
        &Symbol::new(&e, "greet"),
        &target_args,
        &s.user,
        &s.relayer,
    );

    let cpu_cost = e.cost_estimate().budget().cpu_instruction_cost();
    let mem_cost = e.cost_estimate().budget().memory_bytes_cost();

    const TX_MAX_CPU_INSTRUCTIONS: u64 = 100_000_000;
    const TX_MAX_MEMORY_BYTES: u64 = 41_943_040; // 40 MiB

    assert!(cpu_cost > 0, "CPU cost must be metered");
    assert!(mem_cost > 0, "Memory cost must be metered");
    assert!(
        cpu_cost < TX_MAX_CPU_INSTRUCTIONS,
        "CPU cost {} exceeds transaction limit {}",
        cpu_cost,
        TX_MAX_CPU_INSTRUCTIONS
    );
    assert!(
        mem_cost < TX_MAX_MEMORY_BYTES,
        "Memory cost {} exceeds transaction limit {}",
        mem_cost,
        TX_MAX_MEMORY_BYTES
    );
}
