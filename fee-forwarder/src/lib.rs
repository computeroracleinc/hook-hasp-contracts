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
//! - `forward_with_permit` — alternative entrypoint that accepts an off-chain
//!   signed Ed25519 permit in lieu of a live `executor` `require_auth`. The
//!   permit binds a specific executor address and expires at a given ledger
//!   sequence, and its nonce is consumed on first use to prevent replay.
//! - `enable_fee_token` / `disable_fee_token` — manager-gated allowlist
//!   management for which tokens `forward` accepts as a fee. The allowlist is
//!   disabled (all tokens accepted) until the first token is enabled — see
//!   `stellar_fee_abstraction::is_allowed_fee_token`.
//! - `sweep_tokens` — manager-gated withdrawal of fees this contract has
//!   collected.
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
    bytes, contract, contractimpl, contracttype, symbol_short, Address, Bytes, BytesN, Env,
    Symbol, Val, Vec,
};
use stellar_access::access_control::{grant_role_no_auth, set_admin, AccessControl};
use stellar_fee_abstraction::{
    collect_fee_and_invoke, set_allowed_fee_token, sweep_token, FeeAbstractionApproval,
};
use stellar_macros::only_role;

const MANAGER_ROLE: Symbol = symbol_short!("manager");
const EXECUTOR_ROLE: Symbol = symbol_short!("executor");

/// Domain tag for permit hashing — prevents cross-purpose signature reuse.
///
/// Hashed from the string `"FeeForwarder:ExecutorPermit:v1"` to fit in 32
/// bytes and distinguish this permit type from any other Soroban auth hash.
const PERMIT_DOMAIN_TAG: &[u8] = b"FeeForwarder:ExecutorPermit:v1\x00\x00";

/// Storage keys used by this contract.
#[contracttype]
enum DataKey {
    /// Marks a permit nonce as consumed. Key: `(signer_pubkey, nonce)`.
    PermitNonce(BytesN<32>, u64),
}

/// Errors specific to this contract.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum FeeForwarderError {
    /// The permit's `expiration_ledger` has passed.
    PermitExpired = 1,
    /// The permit nonce has already been used (replay attempt).
    PermitNonceUsed = 2,
}

/// Off-chain signed permit that authorises a specific executor address to call
/// `forward_with_permit` once before `expiration_ledger`.
///
/// Signed payload (XDR-encoded):
/// ```text
/// PERMIT_DOMAIN_TAG (32 bytes) ‖ executor (address) ‖ nonce (u64) ‖ expiration_ledger (u32)
/// ```
#[contracttype]
pub struct ExecutorPermit {
    /// Ed25519 public key whose corresponding private key signed this permit.
    pub signer_pubkey: BytesN<32>,
    /// Ed25519 signature over the canonical permit payload hash.
    pub signature: BytesN<64>,
    /// Executor address being authorized.
    pub executor: Address,
    /// One-time use value — consumed on first successful verification.
    pub nonce: u64,
    /// Last ledger sequence at which this permit is valid (inclusive).
    pub expiration_ledger: u32,
}

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
    }

    /// Collects `fee_amount` of `fee_token` from `user` and forwards the
    /// call to `target_contract.target_fn(target_args)`, atomically.
    ///
    /// Requires authorization from both `user` (covering `fee_token`,
    /// `max_fee_amount`, `expiration_ledger`, and the target call — not
    /// `fee_amount` or `relayer`, which are only known once the executor
    /// picks up the request) and `relayer` (who must hold the `executor`
    /// role).
    ///
    /// # Errors
    ///
    /// * [`stellar_fee_abstraction::FeeAbstractionError::FeeTokenNotAllowed`]
    ///   - If `fee_token` is not on the allowlist (once the allowlist is
    ///     enabled).
    /// * [`stellar_fee_abstraction::FeeAbstractionError::InvalidFeeBounds`] -
    ///   If `fee_amount` is `<= 0` or exceeds `max_fee_amount`.
    /// * [`stellar_access::access_control::AccessControlError::Unauthorized`]
    ///   - If `relayer` does not hold the `executor` role.
    // 10 args is inherent to this entrypoint's shape: it mirrors OZ's audited
    // `collect_fee_and_invoke` parameter list plus `relayer` for
    // `#[only_role]`'s role check. Splitting into a struct would diverge from
    // the audited reference and from the ABI the companion latch-relayer
    // issue builds its off-chain signing/submission against.
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
        collect_fee_and_invoke(
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
        )
    }

    /// Permit-based variant of `forward` — accepts an off-chain signed
    /// [`ExecutorPermit`] in lieu of a live `require_auth` from the executor.
    ///
    /// The permit's Ed25519 signature is verified against `signer_pubkey`.
    /// Only `user` authorization is required on-chain; the executor's
    /// authority is proven by the permit. The permit nonce is consumed on
    /// first use; replays and expired permits are rejected.
    ///
    /// # Errors
    ///
    /// * [`FeeForwarderError::PermitExpired`] — `permit.expiration_ledger` is
    ///   before the current ledger sequence.
    /// * [`FeeForwarderError::PermitNonceUsed`] — `permit.nonce` has already
    ///   been consumed for `permit.signer_pubkey`.
    /// * The transaction panics if the Ed25519 signature does not verify
    ///   (Soroban host aborts on `ed25519_verify` failure).
    /// * Same fee-abstraction and access-control errors as `forward`.
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
        // 1. Check permit expiry.
        if e.ledger().sequence() > permit.expiration_ledger {
            panic_with_error!(e, FeeForwarderError::PermitExpired);
        }

        // 2. Check and consume nonce (prevents replay).
        let nonce_key = DataKey::PermitNonce(permit.signer_pubkey.clone(), permit.nonce);
        if e.storage().persistent().has(&nonce_key) {
            panic_with_error!(e, FeeForwarderError::PermitNonceUsed);
        }
        e.storage().persistent().set(&nonce_key, &true);

        // 3. Verify Ed25519 signature over the canonical permit payload.
        //    Payload: domain_tag ‖ executor_address_xdr ‖ nonce_be8 ‖ expiry_be4
        //    `ed25519_verify` panics (aborting the transaction) if the
        //    signature does not verify — no explicit error branch is needed.
        let payload = Self::permit_payload(e, &permit);
        let payload_hash_bytes: Bytes = e.crypto().sha256(&payload).into();
        e.crypto().ed25519_verify(&permit.signer_pubkey, &payload_hash_bytes, &permit.signature);

        // 4. User still needs to authorize the forward call on-chain.
        user.require_auth();

        collect_fee_and_invoke(
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
        )
    }

    /// Returns `true` if `nonce` has already been consumed for `signer_pubkey`.
    pub fn is_nonce_used(e: &Env, signer_pubkey: BytesN<32>, nonce: u64) -> bool {
        e.storage().persistent().has(&DataKey::PermitNonce(signer_pubkey, nonce))
    }

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

    /// Transfers this contract's entire balance of `token` to `recipient`.
    /// Manager-gated. Returns the amount swept.
    #[only_role(operator, "manager")]
    pub fn sweep_tokens(e: &Env, token: Address, recipient: Address, operator: Address) -> i128 {
        sweep_token(e, &token, &recipient)
    }

    // ── internal helpers ────────────────────────────────────────────────────

    /// Builds the canonical byte payload that the signer must sign.
    ///
    /// Layout: `PERMIT_DOMAIN_TAG (32 B) ‖ executor.to_xdr() ‖ nonce BE-8 ‖ expiration_ledger BE-4`
    fn permit_payload(e: &Env, permit: &ExecutorPermit) -> Bytes {
        let mut payload = bytes!(e);

        // Domain tag (32 bytes).
        for b in PERMIT_DOMAIN_TAG.iter() {
            payload.push_back(*b);
        }

        // Executor address (XDR-encoded).
        let executor_xdr = permit.executor.to_xdr(e);
        for i in 0..executor_xdr.len() {
            payload.push_back(executor_xdr.get(i).unwrap());
        }

        // Nonce as big-endian u64.
        let nonce_bytes = permit.nonce.to_be_bytes();
        for b in nonce_bytes.iter() {
            payload.push_back(*b);
        }

        // Expiration ledger as big-endian u32.
        let expiry_bytes = permit.expiration_ledger.to_be_bytes();
        for b in expiry_bytes.iter() {
            payload.push_back(*b);
        }

        payload
    }
}

#[contractimpl(contracttrait)]
impl AccessControl for FeeForwarder {}

#[cfg(test)]
mod test;
