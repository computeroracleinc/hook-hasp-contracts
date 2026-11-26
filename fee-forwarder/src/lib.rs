//! Permissioned fee forwarder — lets `latch-relayer` sponsor gasless
//! transactions for Latch accounts that hold no XLM.
//!
//! Singleton, permissioned contract shared across every Latch account, same
//! pattern as `ed25519-verifier`/`threshold-policy` (not deployed per
//! account). Permissioned because Latch controls both sides of the flow —
//! the wallet and the relayer — so the executor role is reserved for
//! `latch-relayer`'s own operating address(es), not an open relayer market.
//!
//! This is a thin `#[contract]` wrapper around OZ's `stellar-fee-abstraction`
//! helpers (`stellar_fee_abstraction::collect_fee_and_invoke` and friends) —
//! all real fee-collection logic lives upstream, this crate only supplies the
//! deployable contract shell plus the role-gating that makes the flow
//! permissioned. Follows OZ's `examples/fee-forwarder-permissioned` reference
//! contract.
//!
//! # How it works
//!
//! - `__constructor(admin, manager, executors)` — sets `admin`, grants
//!   `manager` the `manager` role, and grants each address in `executors` the
//!   `executor` role. `AccessControl` (below) exposes `grant_role`/
//!   `revoke_role` for admin/manager-authorized follow-up changes to either
//!   role after deployment.
//! - `forward` — the sponsored-transaction entrypoint. The account signs one
//!   authorization tree covering `forward()`, with sub-invocations for
//!   `fee_token.approve(fee_forwarder, max_fee_amount, expiration_ledger)` (if
//!   needed) and the actual target call. The relayer, gated to the `executor`
//!   role by `#[only_role]`, fills in the real `fee_amount` (must be `<=
//!   max_fee_amount`) and submits, paying the network's XLM fee itself.
//!   Requires **both** the user's and the executor's authorization — collects
//!   the fee and forwards the target call atomically: if either step fails, the
//!   whole transaction (including the fee collection) reverts.
//!   `fee_amount` is additionally capped at `MAX_FEE_CAP` stroops; any
//!   transaction whose fee exceeds the global cap is rejected before the fee
//!   is collected, preventing relayer griefing of the fee sponsor treasury.
//! - `forward_restricted` — like `forward`, but binds the user's authorization
//!   to a specific `authorized_executor` to prevent relayer front-running.
//! - `forward_with_permit` — accepts an off-chain Ed25519 permit signed by an
//!   admin-registered permit signer authorizing a specific enrolled executor
//!   and exact call parameters, with contract/network domain separation and
//!   one-time nonce replay protection.
//! - `set_emergency_budget` / `trip_circuit_breaker` / `reset_circuit_breaker`
//!   — per-token rolling 1-hour outflow cap and emergency circuit breaker.
//! - `set_gas_tier_config` / `compute_tiered_refund` — tiered relayer refund
//!   rate calculation based on gas consumption.
//! - `set_max_payload_size` / `max_payload_size` — manager-gated cap on
//!   XDR-serialized `target_args` byte length.
//! - `enable_fee_token` / `disable_fee_token` — manager-gated allowlist
//!   management for which tokens `forward` accepts as a fee. The allowlist is
//!   disabled (all tokens accepted) until the first token is enabled — see
//!   `stellar_fee_abstraction::is_allowed_fee_token`.
//! - `sweep_tokens` — manager-gated withdrawal of fees this contract has
//!   collected to the configured active treasury (or `recipient` if no
//!   treasury has been configured yet).
//! - `propose_treasury` / `execute_treasury_change` / `cancel_treasury_change`
//!   — two-step timelock for treasury address changes; `set_treasury`,
//!   `grant_manager`, `promote_to_admin`, and permit signer registration are
//!   strictly admin-only.
//! - `set_fee_cap` — manager-gated override of `MAX_FEE_CAP`. The cap
//!   defaults to [`DEFAULT_FEE_CAP`] at construction and can be tightened or
//!   relaxed by the manager at any time.
//!
//! # Security Warning
//!
//! `collect_fee_and_invoke` only authorizes the user's *input* — it does not
//! vet whether the forwarded call is safe for the user to make. Simulating
//! the outcome of `target_contract.target_fn(target_args)` before signing is
//! the invoker's (the account's own signer's) responsibility, same as any
//! other authorization the account signs.
#![no_std]

use soroban_sdk::{
    bytes, contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error,
    symbol_short, xdr::ToXdr, Address, Bytes, BytesN, Env, IntoVal, Symbol, Val, Vec,
};
use stellar_access::access_control::{
    get_admin, grant_role_no_auth, has_role, set_admin, transfer_admin_role, AccessControl,
};
use stellar_fee_abstraction::{
    collect_fee, collect_fee_and_invoke, emit_forward_executed, set_allowed_fee_token, sweep_token,
    FeeAbstractionApproval,
};
use stellar_macros::only_role;

const MANAGER_ROLE: Symbol = symbol_short!("manager");
const EXECUTOR_ROLE: Symbol = symbol_short!("executor");
/// Instance-storage key for the re-entrancy lock.
const REENTRANT_KEY: Symbol = symbol_short!("reentrant");

/// Default maximum fee per sponsored transaction, in stroops (0.1 XLM).
/// Prevents a rogue relayer from draining the sponsor treasury through a
/// single oversized transaction before the manager can react.
pub const DEFAULT_FEE_CAP: i128 = 1_000_000;

/// One hour in seconds. The rolling window over which outflow is summed.
const HOUR_IN_SECS: u64 = 3_600;

/// Mandatory delay, in ledgers, between proposing a new treasury address
/// and being able to execute the change (~24 hours at ~5 s per ledger).
pub const TREASURY_TIMELOCK_LEDGERS: u32 = 17_280;

/// Domain tag for permit hashing — prevents cross-purpose signature reuse.
const PERMIT_DOMAIN_TAG: &[u8] = b"FeeForwarder:ExecutorPermit:v1\x00\x00";

// ── Storage keys ─────────────────────────────────────────────────────────────

/// Unified storage keys for the fee-forwarder contract.
#[contracttype]
pub enum FeeForwarderStorageKey {
    /// Configurable per-transaction fee cap (`i128`).
    FeeCap,
    /// Per-token emergency hourly outflow budget (`i128`).
    EmergencyBudget(Address),
    /// Per-token circuit-breaker tripped flag (`bool`).
    CircuitBreakerPaused(Address),
    /// Per-token rolling-window outflow data (`HourlyOutflowData`).
    HourlyOutflow(Address),
    /// Tiered relayer gas-refund configuration (`GasTierConfig`).
    GasTierConfig,
    /// Maximum permitted XDR byte length of `target_args` (`u32`).
    MaxPayloadSize,
    /// Marks a permit nonce as consumed (`bool`). Key: `(signer_pubkey, nonce)`.
    PermitNonce(BytesN<32>, u64),
    /// Marks an Ed25519 public key as an admin-authorized permit signer (`bool`).
    AuthorizedPermitSigner(BytesN<32>),
    /// Active treasury destination for `sweep_tokens` (`Address`).
    Treasury,
    /// Pending treasury-change proposal (`TreasuryProposal`).
    PendingTreasury,
}

// ── Types ────────────────────────────────────────────────────────────────────

/// Rolling 1-hour outflow window for a single fee token.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HourlyOutflowData {
    /// Cumulative fee amount forwarded within the current window.
    pub total_amount: i128,
    /// Ledger timestamp (seconds) when the current window opened.
    pub window_start: u64,
}

/// Configuration for tiered relayer refund rates.
///
/// The refund for a given `gas_used` is:
///   `base_fee + gas_used * multiplier / 1_000`
///
/// where `multiplier` is the per-mille value from `tier_multipliers` whose
/// corresponding threshold in `tier_thresholds` is the highest one still
/// `<= gas_used`. Both vecs must be non-empty, have the same length, and
/// `tier_thresholds` must be in strictly ascending order.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GasTierConfig {
    /// Flat base component added to every refund regardless of gas consumed.
    pub base_fee: i128,
    /// Gas-unit thresholds (CPU instructions) at which each tier begins,
    /// in strictly ascending order. Same length as `tier_multipliers`.
    pub tier_thresholds: Vec<u64>,
    /// Per-mille multipliers (divide by 1_000) applied to `gas_used` within
    /// the matching tier. Same length as `tier_thresholds`.
    pub tier_multipliers: Vec<u32>,
}

/// Off-chain signed permit that authorises a specific enrolled executor address
/// to execute `forward_with_permit` once before `expiration_ledger`.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorPermit {
    /// Admin-authorized Ed25519 public key whose corresponding private key
    /// signed this permit.
    pub signer_pubkey: BytesN<32>,
    /// Ed25519 signature over `sha256(canonical_permit_payload)`.
    pub signature: BytesN<64>,
    /// Enrolled executor address being authorized.
    pub executor: Address,
    /// One-time use value — consumed on first successful verification.
    pub nonce: u64,
    /// Last ledger sequence at which this permit is valid (inclusive).
    pub expiration_ledger: u32,
}

/// A pending treasury-change proposal.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreasuryProposal {
    /// The proposed new treasury address.
    pub new_treasury: Address,
    /// The earliest ledger sequence at which `execute_treasury_change` may
    /// be called.
    pub eligible_ledger: u32,
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Error codes specific to the fee-forwarder contract.
#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum FeeForwarderError {
    /// `fee_amount` exceeds the per-transaction `MAX_FEE_CAP`.
    FeeCapExceeded = 1,
    /// `fee_cap` passed to `set_fee_cap` must be strictly positive.
    InvalidFeeCap = 2,
    /// The circuit breaker is tripped or the hourly emergency budget would be
    /// exceeded for this fee token.
    CircuitBreakerTripped = 3,
    /// `budget` passed to `set_emergency_budget` must be strictly positive.
    InvalidBudget = 4,
    /// Gas-tier configuration is invalid (negative base fee, empty tiers,
    /// mismatched lengths, or non-ascending thresholds).
    InvalidGasTierConfig = 5,
    /// Overflow while computing a tiered gas refund.
    GasTierOverflow = 6,
    /// `target_args` XDR-serialised byte length exceeds the configured maximum.
    PayloadTooLarge = 7,
    /// The permit's `expiration_ledger` has passed.
    PermitExpired = 8,
    /// The permit nonce has already been consumed (replay attempt).
    PermitNonceUsed = 9,
    /// `permit.signer_pubkey` is not registered as an authorized permit signer.
    UnauthorizedPermitSigner = 10,
    /// No pending treasury-change proposal exists.
    NoPendingTreasury = 11,
    /// The treasury timelock delay has not yet elapsed.
    TreasuryTimelockNotElapsed = 12,
    /// Caller attempted an admin-only operation or self-elevation.
    PrivilegeEscalation = 7001,
    /// Submitting relayer is not the authorized/enrolled executor.
    UnauthorizedExecutor = 8001,
    /// `forward` was invoked re-entrantly while a call is already active.
    ReentrantCall = 9001,
}

// ── Events ───────────────────────────────────────────────────────────────────

/// Emitted when the circuit breaker trips (either automatically on exhausting
/// the hourly emergency budget or manually via `trip_circuit_breaker`).
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitBreakerTripped {
    #[topic]
    pub token: Address,
    pub total_amount: i128,
    pub emergency_budget: i128,
}

/// Emitted when the manager manually resets the circuit breaker for a token.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitBreakerReset {
    #[topic]
    pub token: Address,
}

/// Emitted after every successful sponsored forwarding call.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SponsoredCallExecuted {
    /// The user who paid the fee (sponsor of the gasless call).
    #[topic]
    pub sponsor: Address,
    /// The executor address that submitted the forwarded transaction.
    #[topic]
    pub relayer: Address,
    /// The contract the call was forwarded to.
    pub target_contract: Address,
    /// SEP-41 token address used as the fee currency.
    pub fee_token: Address,
    /// Actual fee amount collected from the sponsor.
    pub fee_amount: i128,
    /// Maximum fee amount the sponsor authorised.
    pub max_fee_amount: i128,
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct FeeForwarder;

#[contractimpl]
impl FeeForwarder {
    /// Sets `admin`, grants `manager` the `manager` role, and grants each
    /// address in `executors` the `executor` role.
    pub fn __constructor(env: Env, admin: Address, manager: Address, executors: Vec<Address>) {
        set_admin(&env, &admin);
        grant_role_no_auth(&env, &manager, &MANAGER_ROLE, &admin);

        for executor in executors.iter() {
            grant_role_no_auth(&env, &executor, &EXECUTOR_ROLE, &admin);
        }

        env.storage().instance().set(&FeeForwarderStorageKey::FeeCap, &DEFAULT_FEE_CAP);
    }

    // ── Fee cap ──────────────────────────────────────────────────────────────

    /// Returns the current per-transaction fee cap in stroops.
    pub fn get_fee_cap(e: &Env) -> i128 {
        e.storage()
            .instance()
            .get(&FeeForwarderStorageKey::FeeCap)
            .unwrap_or(DEFAULT_FEE_CAP)
    }

    /// Updates the per-transaction fee cap. Manager-gated.
    #[only_role(operator, "manager")]
    pub fn set_fee_cap(e: &Env, fee_cap: i128, operator: Address) {
        if fee_cap <= 0 {
            panic_with_error!(e, FeeForwarderError::InvalidFeeCap);
        }
        e.storage().instance().set(&FeeForwarderStorageKey::FeeCap, &fee_cap);
    }

    // ── Circuit-breaker management ───────────────────────────────────────────

    /// Sets the per-token emergency budget (maximum aggregate outflow within
    /// any rolling 1-hour window). Manager-gated.
    #[only_role(operator, "manager")]
    pub fn set_emergency_budget(e: &Env, token: Address, budget: i128, operator: Address) {
        if budget <= 0 {
            panic_with_error!(e, FeeForwarderError::InvalidBudget);
        }
        e.storage()
            .instance()
            .set(&FeeForwarderStorageKey::EmergencyBudget(token), &budget);
    }

    /// Manually trips (pauses) the circuit breaker for `token`, persisting the
    /// paused flag on-chain so all subsequent forwarding calls for `token` are
    /// rejected until [`reset_circuit_breaker`] is called. Manager-gated.
    #[only_role(operator, "manager")]
    pub fn trip_circuit_breaker(e: &Env, token: Address, operator: Address) {
        e.storage()
            .instance()
            .set(&FeeForwarderStorageKey::CircuitBreakerPaused(token.clone()), &true);
        let total_amount = e
            .storage()
            .instance()
            .get::<_, HourlyOutflowData>(&FeeForwarderStorageKey::HourlyOutflow(token.clone()))
            .map(|o| o.total_amount)
            .unwrap_or(0);
        let emergency_budget = e
            .storage()
            .instance()
            .get::<_, i128>(&FeeForwarderStorageKey::EmergencyBudget(token.clone()))
            .unwrap_or(0);
        CircuitBreakerTripped { token, total_amount, emergency_budget }.publish(e);
    }

    /// Clears the tripped state for `token`, re-enabling forwarding calls and
    /// resetting the outflow window. Manager-gated.
    #[only_role(operator, "manager")]
    pub fn reset_circuit_breaker(e: &Env, token: Address, operator: Address) {
        e.storage()
            .instance()
            .remove(&FeeForwarderStorageKey::CircuitBreakerPaused(token.clone()));
        e.storage()
            .instance()
            .remove(&FeeForwarderStorageKey::HourlyOutflow(token.clone()));
        CircuitBreakerReset { token }.publish(e);
    }

    /// Returns `true` if the circuit breaker is currently tripped for `token`.
    pub fn get_circuit_breaker_paused(e: &Env, token: Address) -> bool {
        e.storage()
            .instance()
            .get::<_, bool>(&FeeForwarderStorageKey::CircuitBreakerPaused(token))
            .unwrap_or(false)
    }

    /// Returns the current rolling-window outflow data for `token`, or `None`
    /// if no outflow has been recorded yet.
    pub fn get_hourly_outflow(e: &Env, token: Address) -> Option<HourlyOutflowData> {
        e.storage()
            .instance()
            .get(&FeeForwarderStorageKey::HourlyOutflow(token))
    }

    // ── Max payload size ─────────────────────────────────────────────────────

    /// Sets the maximum permitted `target_args` XDR-serialised byte length.
    /// Passing `0` removes the limit. Manager-gated.
    #[only_role(operator, "manager")]
    pub fn set_max_payload_size(e: &Env, max_bytes: u32, operator: Address) {
        if max_bytes == 0 {
            e.storage().instance().remove(&FeeForwarderStorageKey::MaxPayloadSize);
        } else {
            e.storage()
                .instance()
                .set(&FeeForwarderStorageKey::MaxPayloadSize, &max_bytes);
        }
    }

    /// Returns the current maximum `target_args` byte length, or `None` if
    /// no limit is configured.
    pub fn max_payload_size(e: &Env) -> Option<u32> {
        e.storage().instance().get(&FeeForwarderStorageKey::MaxPayloadSize)
    }

    // ── Core forwarding ──────────────────────────────────────────────────────

    /// Collects `fee_amount` of `fee_token` from `user` and forwards the
    /// call to `target_contract.target_fn(target_args)`, atomically.
    ///
    /// Open dispatch — any enrolled executor may relay this payload. For
    /// front-running protection use `forward_restricted` instead.
    #[allow(clippy::too_many_arguments)]
    #[only_role(relayer, "executor")]
    pub fn forward(
        e: &Env,
        fee_token: Address,
        fee_amount: i128,
        max_fee_amount: i128,
        expiration_ledger: u32,
        target_contract: Address,
        target_fn: Symbol,
        target_args: Vec<Val>,
        user: Address,
        relayer: Address,
    ) -> Val {
        Self::pre_forward_checks(e, &fee_token, fee_amount, &target_args);

        let result = collect_fee_and_invoke(
            e,
            &fee_token,
            fee_amount,
            max_fee_amount,
            expiration_ledger,
            &target_contract,
            &target_fn,
            &target_args,
            &user,
            &e.current_contract_address(),
            FeeAbstractionApproval::Lazy,
        );

        Self::post_forward_accounting(
            e,
            fee_token,
            fee_amount,
            max_fee_amount,
            target_contract,
            user,
            relayer,
        );

        result
    }

    /// Restricted dispatch — like `forward`, but binds the user's signed
    /// authorization to `authorized_executor` to prevent front-running.
    #[allow(clippy::too_many_arguments)]
    #[only_role(relayer, "executor")]
    pub fn forward_restricted(
        e: &Env,
        fee_token: Address,
        fee_amount: i128,
        max_fee_amount: i128,
        expiration_ledger: u32,
        target_contract: Address,
        target_fn: Symbol,
        target_args: Vec<Val>,
        user: Address,
        relayer: Address,
        authorized_executor: Address,
    ) -> Val {
        // Enforce that the actual submitting relayer matches what the user bound.
        if relayer != authorized_executor {
            panic_with_error!(e, FeeForwarderError::UnauthorizedExecutor);
        }

        // Bind the user's authorization to the exact call parameters AND
        // `authorized_executor` so substituting a different relayer fails auth.
        user.require_auth_for_args(
            (
                fee_token.clone(),
                max_fee_amount,
                expiration_ledger,
                target_contract.clone(),
                target_fn.clone(),
                target_args.clone(),
                authorized_executor.clone(),
            )
                .into_val(e),
        );

        Self::pre_forward_checks(e, &fee_token, fee_amount, &target_args);

        // Collect the fee directly from `user` (already authenticated above
        // with the executor-bound argument tuple) and invoke the target.
        collect_fee(
            e,
            &fee_token,
            fee_amount,
            max_fee_amount,
            expiration_ledger,
            &user,
            &e.current_contract_address(),
            FeeAbstractionApproval::Lazy,
        );

        let result = e.invoke_contract::<Val>(&target_contract, &target_fn, target_args.clone());
        emit_forward_executed(e, &user, &target_contract, &target_fn, &target_args);

        Self::post_forward_accounting(
            e,
            fee_token,
            fee_amount,
            max_fee_amount,
            target_contract,
            user,
            relayer,
        );

        result
    }

    /// Permit-based variant of `forward` — accepts an off-chain signed
    /// [`ExecutorPermit`] in lieu of a live `require_auth` from the executor.
    ///
    /// Security invariants enforced:
    /// 1. `permit.signer_pubkey` MUST be registered by the contract admin via
    ///    [`register_permit_signer`].
    /// 2. `permit.executor` MUST hold the `executor` role.
    /// 3. The permit digest binds `network_id`, this contract's address,
    ///    `permit.executor`, `permit.nonce`, `permit.expiration_ledger`, AND
    ///    all forwarded call parameters (`fee_token`, `fee_amount`,
    ///    `max_fee_amount`, `expiration_ledger`, `target_contract`,
    ///    `target_fn`, `target_args`, `user`).
    /// 4. Nonces are consumed in persistent storage to prevent replay.
    /// 5. `user` authorization is checked by `collect_fee_and_invoke` via
    ///    `require_auth_for_args`.
    #[allow(clippy::too_many_arguments)]
    pub fn forward_with_permit(
        e: &Env,
        permit: ExecutorPermit,
        fee_token: Address,
        fee_amount: i128,
        max_fee_amount: i128,
        expiration_ledger: u32,
        target_contract: Address,
        target_fn: Symbol,
        target_args: Vec<Val>,
        user: Address,
    ) -> Val {
        // 1. Verify the permit signer public key is admin-authorized.
        if !Self::is_permit_signer_authorized(e, permit.signer_pubkey.clone()) {
            panic_with_error!(e, FeeForwarderError::UnauthorizedPermitSigner);
        }

        // 2. Verify the authorized executor in the permit holds the executor role.
        if has_role(e, &permit.executor, &EXECUTOR_ROLE).is_none() {
            panic_with_error!(e, FeeForwarderError::UnauthorizedExecutor);
        }

        // 3. Check permit expiry.
        if e.ledger().sequence() > permit.expiration_ledger {
            panic_with_error!(e, FeeForwarderError::PermitExpired);
        }

        // 4. Check and consume nonce (prevents replay).
        let nonce_key =
            FeeForwarderStorageKey::PermitNonce(permit.signer_pubkey.clone(), permit.nonce);
        if e.storage().persistent().has(&nonce_key) {
            panic_with_error!(e, FeeForwarderError::PermitNonceUsed);
        }
        e.storage().persistent().set(&nonce_key, &true);

        // 5. Verify Ed25519 signature over the domain-separated, call-bound payload.
        let payload = Self::permit_payload(
            e,
            &permit,
            &fee_token,
            fee_amount,
            max_fee_amount,
            expiration_ledger,
            &target_contract,
            &target_fn,
            &target_args,
            &user,
        );
        let payload_hash_bytes: Bytes = e.crypto().sha256(&payload).into();
        e.crypto().ed25519_verify(&permit.signer_pubkey, &payload_hash_bytes, &permit.signature);

        Self::pre_forward_checks(e, &fee_token, fee_amount, &target_args);

        // 6. Delegate user auth + fee collection + target invocation atomically.
        let result = collect_fee_and_invoke(
            e,
            &fee_token,
            fee_amount,
            max_fee_amount,
            expiration_ledger,
            &target_contract,
            &target_fn,
            &target_args,
            &user,
            &e.current_contract_address(),
            FeeAbstractionApproval::Lazy,
        );

        Self::post_forward_accounting(
            e,
            fee_token,
            fee_amount,
            max_fee_amount,
            target_contract,
            user,
            permit.executor,
        );

        result
    }

    /// Registers an Ed25519 public key as an authorized off-chain permit
    /// signer. Admin-only.
    pub fn register_permit_signer(e: &Env, signer_pubkey: BytesN<32>, caller: Address) {
        Self::require_admin(e, &caller);
        e.storage()
            .instance()
            .set(&FeeForwarderStorageKey::AuthorizedPermitSigner(signer_pubkey), &true);
    }

    /// Revokes a previously authorized Ed25519 permit signer public key.
    /// Admin-only.
    pub fn revoke_permit_signer(e: &Env, signer_pubkey: BytesN<32>, caller: Address) {
        Self::require_admin(e, &caller);
        e.storage()
            .instance()
            .remove(&FeeForwarderStorageKey::AuthorizedPermitSigner(signer_pubkey));
    }

    /// Returns `true` if `signer_pubkey` is registered as an authorized permit signer.
    pub fn is_permit_signer_authorized(e: &Env, signer_pubkey: BytesN<32>) -> bool {
        e.storage()
            .instance()
            .get(&FeeForwarderStorageKey::AuthorizedPermitSigner(signer_pubkey))
            .unwrap_or(false)
    }

    /// Returns `true` if `nonce` has already been consumed for `signer_pubkey`.
    pub fn is_nonce_used(e: &Env, signer_pubkey: BytesN<32>, nonce: u64) -> bool {
        e.storage()
            .persistent()
            .has(&FeeForwarderStorageKey::PermitNonce(signer_pubkey, nonce))
    }

    // ── Fee token allowlist ──────────────────────────────────────────────────

    /// Adds `token` to the fee-token allowlist. Manager-gated.
    #[only_role(operator, "manager")]
    pub fn enable_fee_token(e: &Env, token: Address, operator: Address) {
        set_allowed_fee_token(e, &token, true);
    }

    /// Removes `token` from the fee-token allowlist. Manager-gated.
    #[only_role(operator, "manager")]
    pub fn disable_fee_token(e: &Env, token: Address, operator: Address) {
        set_allowed_fee_token(e, &token, false);
    }

    // ── Treasury sweeping & timelock ─────────────────────────────────────────

    /// Transfers this contract's entire balance of `token` to the configured
    /// active treasury address (if set via `set_treasury` or the treasury
    /// timelock), or to `recipient` when no treasury has been configured yet.
    /// Manager-gated. Returns the amount swept.
    #[only_role(operator, "manager")]
    pub fn sweep_tokens(e: &Env, token: Address, recipient: Address, operator: Address) -> i128 {
        let destination = e
            .storage()
            .instance()
            .get::<FeeForwarderStorageKey, Address>(&FeeForwarderStorageKey::Treasury)
            .unwrap_or(recipient);
        sweep_token(e, &token, &destination)
    }

    /// Proposes a new treasury address. The change becomes eligible for
    /// execution after `TREASURY_TIMELOCK_LEDGERS` ledgers. Manager-gated.
    #[only_role(operator, "manager")]
    pub fn propose_treasury(e: &Env, new_treasury: Address, operator: Address) {
        let eligible_ledger = e
            .ledger()
            .sequence()
            .checked_add(TREASURY_TIMELOCK_LEDGERS)
            .unwrap_or_else(|| panic_with_error!(e, FeeForwarderError::TreasuryTimelockNotElapsed));
        e.storage().instance().set(
            &FeeForwarderStorageKey::PendingTreasury,
            &TreasuryProposal { new_treasury, eligible_ledger },
        );
    }

    /// Executes a pending treasury proposal after `TREASURY_TIMELOCK_LEDGERS`
    /// have elapsed, activating the new treasury address. Manager-gated.
    #[only_role(operator, "manager")]
    pub fn execute_treasury_change(e: &Env, operator: Address) {
        let proposal = e
            .storage()
            .instance()
            .get::<FeeForwarderStorageKey, TreasuryProposal>(
                &FeeForwarderStorageKey::PendingTreasury,
            )
            .unwrap_or_else(|| panic_with_error!(e, FeeForwarderError::NoPendingTreasury));

        if e.ledger().sequence() < proposal.eligible_ledger {
            panic_with_error!(e, FeeForwarderError::TreasuryTimelockNotElapsed);
        }

        e.storage()
            .instance()
            .set(&FeeForwarderStorageKey::Treasury, &proposal.new_treasury);
        e.storage().instance().remove(&FeeForwarderStorageKey::PendingTreasury);
    }

    /// Cancels a pending treasury proposal without executing it. Manager-gated.
    #[only_role(operator, "manager")]
    pub fn cancel_treasury_change(e: &Env, operator: Address) {
        if !e.storage().instance().has(&FeeForwarderStorageKey::PendingTreasury) {
            panic_with_error!(e, FeeForwarderError::NoPendingTreasury);
        }
        e.storage().instance().remove(&FeeForwarderStorageKey::PendingTreasury);
    }

    /// Returns the pending treasury proposal, if any.
    pub fn get_pending_treasury(e: &Env) -> Option<TreasuryProposal> {
        e.storage().instance().get(&FeeForwarderStorageKey::PendingTreasury)
    }

    /// Returns the active treasury address, if one has been set.
    pub fn get_treasury(e: &Env) -> Option<Address> {
        e.storage().instance().get(&FeeForwarderStorageKey::Treasury)
    }

    // ── Tiered relayer refund rates ──────────────────────────────────────────

    /// Stores the gas-tier configuration used by `compute_tiered_refund`.
    /// Manager-gated.
    ///
    /// Validates:
    /// - `base_fee >= 0`
    /// - `!tier_thresholds.is_empty()`
    /// - `tier_thresholds.len() == tier_multipliers.len()`
    /// - `tier_thresholds` is strictly ascending
    #[only_role(operator, "manager")]
    pub fn set_gas_tier_config(
        e: &Env,
        base_fee: i128,
        tier_thresholds: Vec<u64>,
        tier_multipliers: Vec<u32>,
        operator: Address,
    ) {
        if base_fee < 0
            || tier_thresholds.is_empty()
            || tier_thresholds.len() != tier_multipliers.len()
        {
            panic_with_error!(e, FeeForwarderError::InvalidGasTierConfig);
        }

        let len = tier_thresholds.len();
        let mut prev = tier_thresholds
            .get(0)
            .unwrap_or_else(|| panic_with_error!(e, FeeForwarderError::InvalidGasTierConfig));
        for i in 1..len {
            let curr = tier_thresholds
                .get(i)
                .unwrap_or_else(|| panic_with_error!(e, FeeForwarderError::InvalidGasTierConfig));
            if curr <= prev {
                panic_with_error!(e, FeeForwarderError::InvalidGasTierConfig);
            }
            prev = curr;
        }

        let config = GasTierConfig { base_fee, tier_thresholds, tier_multipliers };
        e.storage().instance().set(&FeeForwarderStorageKey::GasTierConfig, &config);
    }

    /// Returns the current gas-tier configuration, or `None` if not yet set.
    pub fn get_gas_tier_config(e: &Env) -> Option<GasTierConfig> {
        e.storage().instance().get(&FeeForwarderStorageKey::GasTierConfig)
    }

    /// Computes the tiered refund amount for `gas_used` CPU instructions using
    /// checked arithmetic.
    ///
    /// Formula: `base_fee + gas_used * multiplier / 1_000`, where `multiplier`
    /// is taken from the highest tier whose threshold is `<= gas_used`.
    /// Returns `0` when no configuration has been stored.
    pub fn compute_tiered_refund(e: &Env, gas_used: u64) -> i128 {
        let config: GasTierConfig = match e.storage().instance().get(&FeeForwarderStorageKey::GasTierConfig) {
            Some(c) => c,
            None => return 0,
        };

        let mut multiplier: u32 = config.tier_multipliers.get(0).unwrap_or(0);
        let len = config.tier_thresholds.len();
        for i in 0..len {
            let threshold: u64 = config.tier_thresholds.get(i).unwrap_or(u64::MAX);
            if gas_used >= threshold {
                multiplier = config.tier_multipliers.get(i).unwrap_or(multiplier);
            }
        }

        let variable_fee = (gas_used as i128)
            .checked_mul(multiplier as i128)
            .unwrap_or_else(|| panic_with_error!(e, FeeForwarderError::GasTierOverflow))
            / 1_000;

        config
            .base_fee
            .checked_add(variable_fee)
            .unwrap_or_else(|| panic_with_error!(e, FeeForwarderError::GasTierOverflow))
    }

    // ── RBAC hardening ───────────────────────────────────────────────────────

    /// Grants `grantee` the `manager` role. Admin-only; blocks self-grant.
    pub fn grant_manager(e: &Env, grantee: Address, admin: Address) {
        Self::require_admin(e, &admin);
        if grantee == admin {
            panic_with_error!(e, FeeForwarderError::PrivilegeEscalation);
        }
        grant_role_no_auth(e, &grantee, &MANAGER_ROLE, &admin);
    }

    /// Initiates a two-step admin transfer to `new_admin` via OpenZeppelin's
    /// `transfer_admin_role`. Strictly admin-only — `new_admin` must finalize
    /// the transfer by calling `accept_admin_transfer`.
    pub fn promote_to_admin(e: &Env, new_admin: Address, caller: Address) {
        Self::require_admin(e, &caller);
        let live_until_ledger = e.ledger().sequence().saturating_add(TREASURY_TIMELOCK_LEDGERS);
        transfer_admin_role(e, &new_admin, live_until_ledger);
    }

    /// Sets the active treasury address directly. Admin-only; clears any
    /// pending manager proposal so it cannot overwrite the admin's decision.
    pub fn set_treasury(e: &Env, treasury: Address, caller: Address) {
        Self::require_admin(e, &caller);
        e.storage().instance().set(&FeeForwarderStorageKey::Treasury, &treasury);
        e.storage().instance().remove(&FeeForwarderStorageKey::PendingTreasury);
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fn require_admin(e: &Env, caller: &Address) {
        let current_admin = get_admin(e)
            .unwrap_or_else(|| panic_with_error!(e, FeeForwarderError::PrivilegeEscalation));
        if *caller != current_admin {
            panic_with_error!(e, FeeForwarderError::PrivilegeEscalation);
        }
        caller.require_auth();
    }

    fn pre_forward_checks(
        e: &Env,
        fee_token: &Address,
        fee_amount: i128,
        target_args: &Vec<Val>,
    ) {
        // 1. Re-entrancy guard: acquire.
        if e.storage().instance().get::<_, bool>(&REENTRANT_KEY).unwrap_or(false) {
            panic_with_error!(e, FeeForwarderError::ReentrantCall);
        }
        e.storage().instance().set(&REENTRANT_KEY, &true);

        // 2. Circuit breaker tripped check.
        let paused_key = FeeForwarderStorageKey::CircuitBreakerPaused(fee_token.clone());
        if e.storage().instance().get::<_, bool>(&paused_key).unwrap_or(false) {
            panic_with_error!(e, FeeForwarderError::CircuitBreakerTripped);
        }

        // 3. Per-transaction fee cap check.
        let fee_cap = e
            .storage()
            .instance()
            .get(&FeeForwarderStorageKey::FeeCap)
            .unwrap_or(DEFAULT_FEE_CAP);
        if fee_amount > fee_cap {
            panic_with_error!(e, FeeForwarderError::FeeCapExceeded);
        }

        // 4. Max payload size check (when configured).
        if let Some(max_bytes) = Self::max_payload_size(e) {
            let serialised_len = target_args.to_xdr(e).len();
            if serialised_len > max_bytes {
                panic_with_error!(e, FeeForwarderError::PayloadTooLarge);
            }
        }

        // 5. Pre-check hourly emergency budget before executing so an
        //    over-budget transaction reverts cleanly.
        let budget_key = FeeForwarderStorageKey::EmergencyBudget(fee_token.clone());
        if let Some(budget) = e.storage().instance().get::<_, i128>(&budget_key) {
            if fee_amount > 0 {
                let outflow = Self::current_window_outflow(e, fee_token);
                let projected = outflow
                    .total_amount
                    .checked_add(fee_amount)
                    .unwrap_or_else(|| panic_with_error!(e, FeeForwarderError::CircuitBreakerTripped));
                if projected > budget {
                    panic_with_error!(e, FeeForwarderError::CircuitBreakerTripped);
                }
            }
        }
    }

    fn post_forward_accounting(
        e: &Env,
        fee_token: Address,
        fee_amount: i128,
        max_fee_amount: i128,
        target_contract: Address,
        user: Address,
        relayer: Address,
    ) {
        // Update rolling 1-hour outflow window. If this transaction exhausts
        // the configured emergency budget (total_amount >= budget), trip the
        // circuit breaker WITHOUT panicking so the paused state and event
        // commit on-chain and block all subsequent calls until reset.
        let budget_key = FeeForwarderStorageKey::EmergencyBudget(fee_token.clone());
        if let Some(budget) = e.storage().instance().get::<_, i128>(&budget_key) {
            let outflow_key = FeeForwarderStorageKey::HourlyOutflow(fee_token.clone());
            let mut outflow = Self::current_window_outflow(e, &fee_token);
            outflow.total_amount = outflow
                .total_amount
                .checked_add(fee_amount)
                .unwrap_or_else(|| panic_with_error!(e, FeeForwarderError::CircuitBreakerTripped));
            e.storage().instance().set(&outflow_key, &outflow);

            if outflow.total_amount >= budget {
                let paused_key = FeeForwarderStorageKey::CircuitBreakerPaused(fee_token.clone());
                e.storage().instance().set(&paused_key, &true);
                CircuitBreakerTripped {
                    token: fee_token.clone(),
                    total_amount: outflow.total_amount,
                    emergency_budget: budget,
                }
                .publish(e);
            }
        }

        // Release re-entrancy lock.
        e.storage().instance().set(&REENTRANT_KEY, &false);

        // Emit analytics event.
        SponsoredCallExecuted {
            sponsor: user,
            relayer,
            target_contract,
            fee_token,
            fee_amount,
            max_fee_amount,
        }
        .publish(e);
    }

    fn current_window_outflow(e: &Env, fee_token: &Address) -> HourlyOutflowData {
        let now = e.ledger().timestamp();
        let outflow_key = FeeForwarderStorageKey::HourlyOutflow(fee_token.clone());
        let mut outflow: HourlyOutflowData = e
            .storage()
            .instance()
            .get(&outflow_key)
            .unwrap_or(HourlyOutflowData { total_amount: 0, window_start: now });

        if now.saturating_sub(outflow.window_start) >= HOUR_IN_SECS {
            outflow.total_amount = 0;
            outflow.window_start = now;
        }
        outflow
    }

    /// Builds the canonical domain-separated byte payload that the permit
    /// signer must sign.
    ///
    /// Layout:
    /// `PERMIT_DOMAIN_TAG (32 B) ‖ network_id (32 B) ‖ contract_address.to_xdr() ‖
    ///  executor.to_xdr() ‖ nonce BE-8 ‖ permit_expiration_ledger BE-4 ‖
    ///  fee_token.to_xdr() ‖ fee_amount BE-16 ‖ max_fee_amount BE-16 ‖
    ///  expiration_ledger BE-4 ‖ target_contract.to_xdr() ‖ target_fn.to_xdr() ‖
    ///  target_args.to_xdr() ‖ user.to_xdr()`
    #[allow(clippy::too_many_arguments)]
    fn permit_payload(
        e: &Env,
        permit: &ExecutorPermit,
        fee_token: &Address,
        fee_amount: i128,
        max_fee_amount: i128,
        expiration_ledger: u32,
        target_contract: &Address,
        target_fn: &Symbol,
        target_args: &Vec<Val>,
        user: &Address,
    ) -> Bytes {
        let mut payload = bytes!(e);
        payload.extend_from_slice(PERMIT_DOMAIN_TAG);
        payload.extend_from_slice(&e.ledger().network_id().to_array());
        payload.append(&e.current_contract_address().to_xdr(e));
        payload.append(&(&permit.executor).to_xdr(e));
        payload.extend_from_slice(&permit.nonce.to_be_bytes());
        payload.extend_from_slice(&permit.expiration_ledger.to_be_bytes());
        payload.append(&fee_token.to_xdr(e));
        payload.extend_from_slice(&fee_amount.to_be_bytes());
        payload.extend_from_slice(&max_fee_amount.to_be_bytes());
        payload.extend_from_slice(&expiration_ledger.to_be_bytes());
        payload.append(&target_contract.to_xdr(e));
        payload.append(&target_fn.to_xdr(e));
        payload.append(&target_args.to_xdr(e));
        payload.append(&user.to_xdr(e));
        payload
    }
}

#[contractimpl(contracttrait)]
impl AccessControl for FeeForwarder {}

#[cfg(test)]
mod test;

#[cfg(test)]
mod fuzz_test;
