//! Fuzz-style concurrency tests for fee-forwarder multi-executor state tracking.
//!
//! Soroban contracts execute single-threaded inside the WASM VM, so true
//! OS-thread races cannot occur at the contract level. What *can* go wrong is
//! sequential state corruption when multiple executors each submit a `forward`
//! call in the same ledger or across ledgers: balances must never underflow,
//! fee amounts must always match what each individual executor declared, and
//! the contract's own token balance must equal the running sum of collected
//! fees across all forwarded calls.
//!
//! These tests exercise a table-driven, property-style suite that covers:
//! - Many distinct executors forwarding independently (no shared mutable state).
//! - Varied fee amounts across a wide range to detect arithmetic anomalies.
//! - Interleaved enable/disable of the fee-token allowlist between sponsorships.
//! - Atomicity: a failing target call must revert fee collection for that
//!   specific executor without affecting any other executor's already-collected
//!   fees.
//! - Sweep after mixed sponsorships: total swept must equal total collected.

#![cfg(test)]
extern crate std;

use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, MockAuth, MockAuthInvoke},
    vec, Address, Env, IntoVal, String, Symbol, TryIntoVal, Val, Vec,
};
use stellar_tokens::fungible::{Base, FungibleToken};

use super::{FeeForwarder, FeeForwarderClient};

// ── Shared mock contracts (mirrors test.rs without re-exporting) ─────────────

#[contract]
pub struct FuzzMockToken;

#[contractimpl]
impl FuzzMockToken {
    pub fn __constructor(e: &Env, to: Address, amount: i128) {
        Base::set_metadata(
            e,
            7,
            String::from_str(e, "Fuzz Token"),
            String::from_str(e, "FUZZ"),
        );
        Base::mint(e, &to, amount);
    }
}

#[contractimpl(contracttrait)]
impl FungibleToken for FuzzMockToken {
    type ContractType = Base;
}

#[contract]
pub struct FuzzMockTarget;

#[contractimpl]
impl FuzzMockTarget {
    pub fn ok(_e: Env) -> bool {
        true
    }

    pub fn fail(_e: Env) -> bool {
        panic!("intentional target failure")
    }
}

// ── Setup helpers ────────────────────────────────────────────────────────────

struct FuzzSetup<'a> {
    env: Env,
    forwarder: FeeForwarderClient<'a>,
    token: FuzzMockTokenClient<'a>,
    target: FuzzMockTargetClient<'a>,
    admin: Address,
    manager: Address,
    /// All registered executor addresses (each holds the `executor` role).
    executors: std::vec::Vec<Address>,
    /// Single user whose balance is being sponsored.
    user: Address,
    max_fee_amount: i128,
}

fn setup_fuzz(e: &Env, num_executors: usize, user_balance: i128) -> FuzzSetup<'_> {
    let admin = Address::generate(e);
    let manager = Address::generate(e);
    let user = Address::generate(e);

    let executors: std::vec::Vec<Address> =
        (0..num_executors).map(|_| Address::generate(e)).collect();

    let mut sdk_executors = Vec::new(e);
    for ex in &executors {
        sdk_executors.push_back(ex.clone());
    }

    let forwarder_id =
        e.register(FeeForwarder, (admin.clone(), manager.clone(), sdk_executors));
    let token_id = e.register(FuzzMockToken, (user.clone(), user_balance));
    let target_id = e.register(FuzzMockTarget, ());

    FuzzSetup {
        env: e.clone(),
        forwarder: FeeForwarderClient::new(e, &forwarder_id),
        token: FuzzMockTokenClient::new(e, &token_id),
        target: FuzzMockTargetClient::new(e, &target_id),
        admin,
        manager,
        executors,
        user,
        max_fee_amount: user_balance / num_executors as i128,
    }
}

/// Builds and submits a `forward` call for one (executor, fee_amount) pair
/// via `mock_all_auths`.
fn forward_once(s: &FuzzSetup, executor: &Address, fee_amount: i128) -> bool {
    let e = &s.env;
    let fn_name = Symbol::new(e, "ok");
    let fn_args: Vec<Val> = vec![e];
    let current_ledger = e.ledger().sequence();

    let result = s.forwarder.mock_all_auths_allowing_non_root_auth().try_forward(
        &s.token.address,
        &fee_amount,
        &s.max_fee_amount,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        executor,
    );
    result.is_ok()
}

// ── Fuzz-style test cases ────────────────────────────────────────────────────

/// Many distinct executors each forward once; the contract's collected
/// balance must equal the sum of all individual fee amounts.
#[test]
fn fuzz_multiple_executors_balance_never_underflows() {
    let e = Env::default();
    // 8 distinct executors, varied fee amounts
    let fee_schedule: &[(i128, i128)] = &[
        (10_000, 10_000),
        (25_000, 25_000),
        (1, 1),
        (50_000, 50_000),
        (99_999, 99_999),
        (7_777, 7_777),
        (33_333, 33_333),
        (12_345, 12_345),
    ];
    let num_executors = fee_schedule.len();
    let total_fees: i128 = fee_schedule.iter().map(|(_, f)| f).sum();
    let user_balance = 1_000_000_000i128;

    let s = setup_fuzz(&e, num_executors, user_balance);

    // Override max_fee_amount so every fee fits.
    let max_fee = fee_schedule.iter().map(|(m, _)| *m).max().unwrap();

    // Re-register with per-executor knowledge isn't needed: mock_all_auths
    // bypasses auth checks, so each executor call is accepted as long as it
    // holds the executor role (which all do from setup_fuzz).

    let mut running_total: i128 = 0;
    for (i, (_, fee)) in fee_schedule.iter().enumerate() {
        let executor = &s.executors[i];
        let fn_name = Symbol::new(&e, "ok");
        let fn_args: Vec<Val> = vec![&e];
        let current_ledger = e.ledger().sequence();

        s.forwarder
            .mock_all_auths_allowing_non_root_auth()
            .forward(
                &s.token.address,
                fee,
                &max_fee,
                &current_ledger,
                &s.target.address,
                &fn_name,
                &fn_args,
                &s.user,
                executor,
            );

        running_total += fee;

        // After each call: contract balance must equal running total.
        let contract_bal = s.token.balance(&s.forwarder.address);
        assert_eq!(
            contract_bal,
            running_total,
            "balance mismatch after executor {} forward (fee={})",
            i,
            fee
        );
        // User balance must have decreased by exactly the fee.
        let user_bal = s.token.balance(&s.user);
        assert_eq!(
            user_bal,
            user_balance - running_total,
            "user balance mismatch after executor {} forward (fee={})",
            i,
            fee
        );
    }

    // Final invariant: no value created or destroyed.
    assert_eq!(s.token.balance(&s.forwarder.address) + s.token.balance(&s.user), user_balance);
}

/// A failing target call must revert fee collection for that executor;
/// other executors' already-collected fees must be unaffected.
#[test]
fn fuzz_failed_target_reverts_only_its_own_fee() {
    let e = Env::default();
    let num_executors = 4;
    let user_balance = 1_000_000_000i128;
    let fee = 100_000i128;
    let max_fee = 150_000i128;

    let s = setup_fuzz(&e, num_executors, user_balance);

    let fn_ok = Symbol::new(&e, "ok");
    let fn_fail = Symbol::new(&e, "fail");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // Executor 0 succeeds.
    s.forwarder.mock_all_auths_allowing_non_root_auth().forward(
        &s.token.address,
        &fee,
        &max_fee,
        &current_ledger,
        &s.target.address,
        &fn_ok,
        &fn_args,
        &s.user,
        &s.executors[0],
    );
    let after_first = s.token.balance(&s.forwarder.address);
    assert_eq!(after_first, fee);

    // Executor 1 targets the failing function — entire tx must revert,
    // leaving fee-forwarder balance unchanged.
    let result = s.forwarder.mock_all_auths_allowing_non_root_auth().try_forward(
        &s.token.address,
        &fee,
        &max_fee,
        &current_ledger,
        &s.target.address,
        &fn_fail,
        &fn_args,
        &s.user,
        &s.executors[1],
    );
    assert!(result.is_err(), "forward to failing target should have reverted");
    assert_eq!(
        s.token.balance(&s.forwarder.address),
        after_first,
        "failed forward must not change contract balance"
    );
    assert_eq!(
        s.token.balance(&s.user),
        user_balance - fee,
        "failed forward must not deduct fee from user"
    );

    // Executor 2 succeeds normally — proves state is still consistent.
    s.forwarder.mock_all_auths_allowing_non_root_auth().forward(
        &s.token.address,
        &fee,
        &max_fee,
        &current_ledger,
        &s.target.address,
        &fn_ok,
        &fn_args,
        &s.user,
        &s.executors[2],
    );
    assert_eq!(s.token.balance(&s.forwarder.address), 2 * fee);
}

/// Sweep after N sponsorships must collect exactly the sum of all fees;
/// no value is left behind or double-counted.
#[test]
fn fuzz_sweep_after_multiple_sponsorships_matches_total_collected() {
    let e = Env::default();
    let fee_amounts = [5_000i128, 20_000, 1_500, 75_000, 3_333, 9_999];
    let num_executors = fee_amounts.len();
    let user_balance = 1_000_000_000i128;
    let max_fee = 100_000i128;

    let s = setup_fuzz(&e, num_executors, user_balance);
    let fn_name = Symbol::new(&e, "ok");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    let mut total_collected: i128 = 0;
    for (i, &fee) in fee_amounts.iter().enumerate() {
        s.forwarder.mock_all_auths_allowing_non_root_auth().forward(
            &s.token.address,
            &fee,
            &max_fee,
            &current_ledger,
            &s.target.address,
            &fn_name,
            &fn_args,
            &s.user,
            &s.executors[i],
        );
        total_collected += fee;
    }

    let recipient = Address::generate(&e);
    let swept = s
        .forwarder
        .mock_all_auths()
        .sweep_tokens(&s.token.address, &recipient, &s.manager);

    assert_eq!(swept, total_collected, "swept amount must equal total collected");
    assert_eq!(s.token.balance(&recipient), total_collected);
    assert_eq!(s.token.balance(&s.forwarder.address), 0, "contract balance must be zero after sweep");
}

/// Interleaved allowlist toggling between sponsorships must not corrupt the
/// fee-token balance; a rejected forward (token not allowed) reverts cleanly.
#[test]
fn fuzz_allowlist_interleaving_preserves_balance_integrity() {
    let e = Env::default();
    let num_executors = 3;
    let user_balance = 1_000_000_000i128;
    let fee = 50_000i128;
    let max_fee = 100_000i128;

    let s = setup_fuzz(&e, num_executors, user_balance);
    let fn_name = Symbol::new(&e, "ok");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // Enable the allowlist so only s.token is accepted.
    s.forwarder
        .mock_all_auths()
        .enable_fee_token(&s.token.address, &s.manager);

    // Executor 0 succeeds (token allowed).
    s.forwarder.mock_all_auths_allowing_non_root_auth().forward(
        &s.token.address,
        &fee,
        &max_fee,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.executors[0],
    );
    assert_eq!(s.token.balance(&s.forwarder.address), fee);

    // Manager disables the token.
    s.forwarder
        .mock_all_auths()
        .disable_fee_token(&s.token.address, &s.manager);

    // Executor 1 is rejected (token no longer on allowlist).
    let result = s.forwarder.mock_all_auths_allowing_non_root_auth().try_forward(
        &s.token.address,
        &fee,
        &max_fee,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.executors[1],
    );
    assert!(result.is_err(), "forward must fail when fee token is disabled");
    assert_eq!(
        s.token.balance(&s.forwarder.address),
        fee,
        "rejected forward must not change collected balance"
    );

    // Re-enable; executor 2 succeeds.
    s.forwarder
        .mock_all_auths()
        .enable_fee_token(&s.token.address, &s.manager);
    s.forwarder.mock_all_auths_allowing_non_root_auth().forward(
        &s.token.address,
        &fee,
        &max_fee,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.executors[2],
    );
    assert_eq!(s.token.balance(&s.forwarder.address), 2 * fee);
}

/// Minimum and maximum fee-amount boundary conditions: fee = 1 (smallest
/// positive) and fee = max_fee_amount (exact ceiling). Both must succeed;
/// fee = 0 and fee = max + 1 must be rejected.
#[test]
fn fuzz_fee_amount_boundary_conditions() {
    let e = Env::default();
    let num_executors = 4;
    let user_balance = 1_000_000_000i128;
    let max_fee = 100_000i128;

    let s = setup_fuzz(&e, num_executors, user_balance);
    let fn_name = Symbol::new(&e, "ok");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // fee = 1 (minimum valid).
    s.forwarder.mock_all_auths_allowing_non_root_auth().forward(
        &s.token.address,
        &1i128,
        &max_fee,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.executors[0],
    );
    assert_eq!(s.token.balance(&s.forwarder.address), 1);

    // fee = max_fee (exact ceiling).
    s.forwarder.mock_all_auths_allowing_non_root_auth().forward(
        &s.token.address,
        &max_fee,
        &max_fee,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.executors[1],
    );
    assert_eq!(s.token.balance(&s.forwarder.address), 1 + max_fee);

    // fee = 0 must be rejected (invalid fee bounds).
    let r0 = s.forwarder.mock_all_auths_allowing_non_root_auth().try_forward(
        &s.token.address,
        &0i128,
        &max_fee,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.executors[2],
    );
    assert!(r0.is_err(), "fee = 0 must be rejected");

    // fee = max + 1 must be rejected.
    let r1 = s.forwarder.mock_all_auths_allowing_non_root_auth().try_forward(
        &s.token.address,
        &(max_fee + 1),
        &max_fee,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.executors[3],
    );
    assert!(r1.is_err(), "fee exceeding max must be rejected");

    // Balance unchanged by both rejected calls.
    assert_eq!(s.token.balance(&s.forwarder.address), 1 + max_fee);
}

/// A non-executor address attempting to forward must be rejected regardless
/// of how many legitimate executors are active; existing state must be
/// unaffected.
#[test]
fn fuzz_non_executor_cannot_piggyback_on_active_executors() {
    let e = Env::default();
    let num_executors = 3;
    let user_balance = 1_000_000_000i128;
    let fee = 10_000i128;
    let max_fee = 50_000i128;

    let s = setup_fuzz(&e, num_executors, user_balance);
    let fn_name = Symbol::new(&e, "ok");
    let fn_args: Vec<Val> = vec![&e];
    let current_ledger = e.ledger().sequence();

    // Legitimate executor 0 collects a fee.
    s.forwarder.mock_all_auths_allowing_non_root_auth().forward(
        &s.token.address,
        &fee,
        &max_fee,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &s.executors[0],
    );

    // A stranger (not in the executor list) tries to forward.
    let stranger = Address::generate(&e);
    let result = s.forwarder.mock_all_auths_allowing_non_root_auth().try_forward(
        &s.token.address,
        &fee,
        &max_fee,
        &current_ledger,
        &s.target.address,
        &fn_name,
        &fn_args,
        &s.user,
        &stranger,
    );
    assert!(result.is_err(), "non-executor must be rejected");

    // State unchanged from the legitimate call.
    assert_eq!(s.token.balance(&s.forwarder.address), fee);
    assert_eq!(s.token.balance(&s.user), user_balance - fee);
}

/// Stress: a single executor submits many sequential sponsorships. The
/// contract balance must grow monotonically and equal the cumulative fee sum
/// at every step.
#[test]
fn fuzz_single_executor_many_sequential_sponsorships() {
    let e = Env::default();
    let s = setup_fuzz(&e, 1, 1_000_000_000i128);

    // 20 sequential forward calls with varying fees.
    let fees: &[i128] = &[
        1, 2, 3, 100, 500, 1_000, 5_000, 10_000, 25_000, 50_000,
        1, 7, 13, 999, 3_333, 7_777, 12_345, 20_000, 40_000, 80_000,
    ];
    let max_fee = 100_000i128;
    let fn_name = Symbol::new(&e, "ok");
    let fn_args: Vec<Val> = vec![&e];

    let mut cumulative: i128 = 0;
    for &fee in fees {
        let current_ledger = e.ledger().sequence();
        s.forwarder.mock_all_auths_allowing_non_root_auth().forward(
            &s.token.address,
            &fee,
            &max_fee,
            &current_ledger,
            &s.target.address,
            &fn_name,
            &fn_args,
            &s.user,
            &s.executors[0],
        );
        cumulative += fee;
        assert_eq!(
            s.token.balance(&s.forwarder.address),
            cumulative,
            "contract balance must equal cumulative fees after fee={}",
            fee
        );
    }

    // Global invariant: tokens are conserved.
    assert_eq!(
        s.token.balance(&s.forwarder.address) + s.token.balance(&s.user),
        1_000_000_000i128
    );
}
