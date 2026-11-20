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
    testutils::{Address as _, MockAuth, MockAuthInvoke},
    vec, Address, Bytes, BytesN, Env, IntoVal, MuxedAddress, String, Symbol, TryIntoVal, Val, Vec,
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

// ── executor permit signature verification ───────────────────────────────────

/// Deterministic test keypair (seed from ed25519-verifier test suite).
fn test_signing_key() -> SigningKey {
    let secret: [u8; 32] = [
        157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73, 197,
        105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
    ];
    SigningKey::from_bytes(&secret)
}

/// Builds a valid [`ExecutorPermit`] signed by `signing_key` for `executor`
/// with the given `nonce` and `expiration_ledger`, matching the on-chain
/// payload construction in `FeeForwarder::permit_payload`.
fn build_permit(
    e: &Env,
    signing_key: &SigningKey,
    executor: Address,
    nonce: u64,
    expiration_ledger: u32,
) -> super::ExecutorPermit {
    use soroban_sdk::xdr::ToXdr;

    // Replicate the on-chain payload: domain_tag ‖ executor_xdr ‖ nonce_be8 ‖ expiry_be4.
    let domain_tag = b"FeeForwarder:ExecutorPermit:v1\x00\x00";
    let executor_xdr = executor.clone().to_xdr(e);

    let mut payload = std::vec![];
    payload.extend_from_slice(domain_tag);
    for i in 0..executor_xdr.len() {
        payload.push(executor_xdr.get(i).unwrap());
    }
    payload.extend_from_slice(&nonce.to_be_bytes());
    payload.extend_from_slice(&expiration_ledger.to_be_bytes());

    // sha256 of the payload (matches on-chain `e.crypto().sha256(&payload)`).
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(&payload);

    let sig_bytes = signing_key.sign(&hash).to_bytes();
    let pubkey_bytes = *signing_key.verifying_key().as_bytes();

    super::ExecutorPermit {
        signer_pubkey: BytesN::from_array(e, &pubkey_bytes),
        signature: BytesN::from_array(e, &sig_bytes),
        executor,
        nonce,
        expiration_ledger,
    }
}

#[test]
fn forward_with_permit_valid_permit_accepted() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);
    pre_approve(&s, &e);

    let signing_key = test_signing_key();
    let current_ledger = e.ledger().sequence();
    let permit = build_permit(&e, &signing_key, s.relayer.clone(), 1, current_ledger + 100);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];

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
    let current_ledger = e.ledger().sequence();
    let permit = build_permit(&e, &signing_key, s.relayer.clone(), 42, current_ledger + 100);
    let pubkey = permit.signer_pubkey.clone();

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];

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
#[should_panic(expected = "Error(Contract, #2)")]
fn forward_with_permit_rejects_replayed_nonce() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);
    pre_approve(&s, &e);

    let signing_key = test_signing_key();
    let current_ledger = e.ledger().sequence();
    let permit = build_permit(&e, &signing_key, s.relayer.clone(), 7, current_ledger + 100);

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];

    // First use succeeds.
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

    // Rebuild the same permit (same nonce) — replay must be rejected.
    let permit2 = build_permit(&e, &signing_key, s.relayer.clone(), 7, current_ledger + 100);
    s.fee_forwarder.forward_with_permit(
        &permit2,
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
#[should_panic(expected = "Error(Contract, #1)")]
fn forward_with_permit_rejects_expired_permit() {
    let e = Env::default();
    e.mock_all_auths();
    let s = setup(&e);

    let signing_key = test_signing_key();
    // Expiry is in the past relative to the current ledger (sequence starts at 0).
    let current_ledger = e.ledger().sequence();
    // Advance ledger beyond the expiry.
    e.ledger().set_sequence_number(current_ledger + 10);

    let permit = build_permit(
        &e,
        &signing_key,
        s.relayer.clone(),
        99,
        current_ledger + 5, // expiry < current after advance
    );

    let fn_name = Symbol::new(&e, "greet");
    let fn_args: Vec<Val> = vec![&e];

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
