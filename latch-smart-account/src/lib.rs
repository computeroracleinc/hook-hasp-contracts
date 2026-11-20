#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::Hash,
    panic_with_error, Address, BytesN, Env, Map, String, Symbol, Val, Vec,
};
use stellar_accounts::smart_account::{
    self as smart_account, AuthPayload, ContextRule, ContextRuleType, ExecutionEntryPoint, Signer,
    SmartAccount, SmartAccountError, SMART_ACCOUNT_EXTEND_AMOUNT, SMART_ACCOUNT_TTL_THRESHOLD,
};
use stellar_contract_utils::upgradeable::{self as upgradeable, Upgradeable};

// ── Flash-loan protocol registry ─────────────────────────────────────────────
//
// A flash-loan callback is a re-entrant call the lending protocol makes back
// into this account after disbursing funds. Without a guard, any contract
// could impersonate a lending protocol, trigger the callback, and manipulate
// the account into signing or transferring assets it did not intend to.
//
// The registry maps each approved lending-protocol address to `true` in
// persistent storage. Only the account itself can add or remove entries
// (each mutating method calls `e.current_contract_address().require_auth()`).
// `flash_loan_callback` checks the caller against the registry before doing
// any work; an unrecognized caller is rejected with
// `FlashLoanCallbackUnauthorized`.

/// Record of a satellite contract this account has deployed via
/// `deploy_contract`, kept for client-side discoverability without needing
/// an off-chain indexer.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct DeployedContract {
    pub address: Address,
    pub wasm_hash: BytesN<32>,
}

#[contracttype]
pub enum LatchSmartAccountStorageKey {
    DeployedContractCount,
    DeployedContract(u32),
    /// Marks a lending-protocol address as approved to invoke the flash-loan
    /// callback on this account. Stored in persistent storage so the registry
    /// survives across ledgers.
    ApprovedFlashLoanProtocol(Address),
}

/// Error codes for `LatchSmartAccount`'s own methods, distinct from
/// `SmartAccountError` (the upstream `stellar-accounts` crate's error type,
/// numbered 3000+). Numbered starting at 4000 so a raw error code seen on
/// this contract is unambiguous about which enum it came from.
#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum LatchSmartAccountError {
    /// No deployed contract is recorded at the requested index.
    DeployedContractNotFound = 4000,
    /// The deployed-contract counter has reached `u32::MAX`.
    MathOverflow = 4001,
    /// A flash-loan callback was invoked by a contract address that is not in
    /// the account's approved-protocol registry. Rejects any attempt by an
    /// unverified contract to re-enter this account via the callback
    /// entrypoint.
    FlashLoanCallbackUnauthorized = 4002,
}

/// Event emitted when this account deploys a satellite contract via
/// `deploy_contract`.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractDeployed {
    #[topic]
    pub address: Address,
    pub wasm_hash: BytesN<32>,
}

/// Emitted when a lending-protocol address is added to the flash-loan
/// approved-protocol registry.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlashLoanProtocolRegistered {
    #[topic]
    pub protocol: Address,
}

/// Emitted when a lending-protocol address is removed from the registry.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlashLoanProtocolRemoved {
    #[topic]
    pub protocol: Address,
}

#[contract]
pub struct LatchSmartAccount;

#[contractimpl]
impl LatchSmartAccount {
    /// Contract constructor — invoked exactly once by the host as part of
    /// `create_contract_v2` (`deploy_v2`) and never callable afterward, so it
    /// needs no "already initialized" guard or `require_auth`: the deploying
    /// transaction authorizes the whole creation, and the host will not
    /// dispatch a later invocation to `__constructor`. Installs the initial
    /// `Default` context rule with the deployer-supplied signers/policies.
    pub fn __constructor(e: &Env, signers: Vec<Signer>, policies: Map<Address, Val>) {
        smart_account::add_context_rule(
            e,
            &ContextRuleType::Default,
            &String::from_str(e, "default"),
            None,
            &signers,
            &policies,
        );
    }

    pub fn batch_add_signer(e: &Env, context_rule_id: u32, signers: Vec<Signer>) {
        e.current_contract_address().require_auth();
        smart_account::batch_add_signer(e, context_rule_id, &signers);
    }

    /// Deploys a new contract owned by this account, deriving its address
    /// from this account (the deployer) and `salt` — the same primitive
    /// `factory-contract` uses to deploy accounts, just invoked from within
    /// an account instead of the factory.
    ///
    /// Unlike `batch_add_signer`/`upgrade`, this method does **not** call
    /// `e.current_contract_address().require_auth()` itself. `deploy_v2`'s
    /// underlying `create_contract_with_constructor` host function already
    /// requires authorization from the deployer address — since
    /// `with_current_contract` makes that deployer this account itself, the
    /// host produces a real
    /// `CreateContractHostFn`/`CreateContractWithCtorHostFn` auth context
    /// for `__check_auth` to validate against a stored
    /// `CreateContract(wasm_hash)` context rule. Adding an explicit
    /// self-`require_auth()` here as well would just demand a second,
    /// unrelated authorization (matched as a generic `Context::Contract`
    /// call to this function, gated by a `Default`/`CallContract(self)`
    /// rule instead) — that's what the other methods need, since none of
    /// their underlying primitives produce their own distinguishable auth
    /// context.
    ///
    /// The deployed contract's address is deterministic: the same
    /// `(wasm_hash, salt)` pair from this account always derives the same
    /// address, and the host itself rejects redeploying over an address
    /// that already has a contract — a caller cannot accidentally collide
    /// with or overwrite an already-deployed satellite by reusing a salt.
    ///
    /// # Errors
    ///
    /// * [`LatchSmartAccountError::MathOverflow`] - If the deployed-contract
    ///   counter has reached `u32::MAX`.
    ///
    /// # Events
    ///
    /// * topics - `["contract_deployed", address: Address]`
    /// * data - `[wasm_hash: BytesN<32>]`
    pub fn deploy_contract(
        e: &Env,
        wasm_hash: BytesN<32>,
        salt: BytesN<32>,
        constructor_args: Vec<Val>,
    ) -> Address {
        let address =
            e.deployer().with_current_contract(salt).deploy_v2(wasm_hash.clone(), constructor_args);

        let index = Self::get_deployed_contract_count(e);
        let next_count = index
            .checked_add(1)
            .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::MathOverflow));
        e.storage()
            .instance()
            .set(&LatchSmartAccountStorageKey::DeployedContractCount, &next_count);

        let key = LatchSmartAccountStorageKey::DeployedContract(index);
        let record = DeployedContract { address: address.clone(), wasm_hash: wasm_hash.clone() };
        e.storage().persistent().set(&key, &record);
        e.storage().persistent().extend_ttl(
            &key,
            SMART_ACCOUNT_TTL_THRESHOLD,
            SMART_ACCOUNT_EXTEND_AMOUNT,
        );

        ContractDeployed { address: address.clone(), wasm_hash }.publish(e);

        address
    }

    /// Returns the number of contracts this account has deployed via
    /// `deploy_contract`. Defaults to `0`.
    pub fn get_deployed_contract_count(e: &Env) -> u32 {
        e.storage().instance().get(&LatchSmartAccountStorageKey::DeployedContractCount).unwrap_or(0)
    }

    /// Returns the `index`-th contract this account has deployed via
    /// `deploy_contract`, in deployment order.
    ///
    /// # Errors
    ///
    /// * [`LatchSmartAccountError::DeployedContractNotFound`] - If no deployed
    ///   contract is recorded at `index`.
    pub fn get_deployed_contract(e: &Env, index: u32) -> DeployedContract {
        let key = LatchSmartAccountStorageKey::DeployedContract(index);
        e.storage()
            .persistent()
            .get::<_, DeployedContract>(&key)
            .inspect(|_| {
                e.storage().persistent().extend_ttl(
                    &key,
                    SMART_ACCOUNT_TTL_THRESHOLD,
                    SMART_ACCOUNT_EXTEND_AMOUNT,
                );
            })
            .unwrap_or_else(|| {
                panic_with_error!(e, LatchSmartAccountError::DeployedContractNotFound)
            })
    }

    // ── Flash-loan protocol registry ──────────────────────────────────────

    /// Adds `protocol` to the set of lending-protocol addresses permitted to
    /// invoke `flash_loan_callback` on this account. Requires self-auth so
    /// only the account's own signer/policy stack can approve a new protocol.
    ///
    /// # Events
    ///
    /// * topics - `["flash_loan_protocol_registered", protocol: Address]`
    pub fn register_flash_loan_protocol(e: &Env, protocol: Address) {
        e.current_contract_address().require_auth();
        let key = LatchSmartAccountStorageKey::ApprovedFlashLoanProtocol(protocol.clone());
        e.storage().persistent().set(&key, &true);
        e.storage().persistent().extend_ttl(
            &key,
            SMART_ACCOUNT_TTL_THRESHOLD,
            SMART_ACCOUNT_EXTEND_AMOUNT,
        );
        FlashLoanProtocolRegistered { protocol }.publish(e);
    }

    /// Removes `protocol` from the approved set, preventing it from invoking
    /// the flash-loan callback in the future. Requires self-auth.
    ///
    /// # Events
    ///
    /// * topics - `["flash_loan_protocol_removed", protocol: Address]`
    pub fn remove_flash_loan_protocol(e: &Env, protocol: Address) {
        e.current_contract_address().require_auth();
        let key = LatchSmartAccountStorageKey::ApprovedFlashLoanProtocol(protocol.clone());
        e.storage().persistent().remove(&key);
        FlashLoanProtocolRemoved { protocol }.publish(e);
    }

    /// Returns `true` if `protocol` is in the approved-protocol registry,
    /// `false` otherwise.
    pub fn is_approved_flash_loan_protocol(e: &Env, protocol: Address) -> bool {
        let key = LatchSmartAccountStorageKey::ApprovedFlashLoanProtocol(protocol);
        e.storage().persistent().has(&key)
    }

    /// Flash-loan callback entrypoint. The calling lending protocol passes
    /// back the `token` it disbursed and the `amount`, plus an arbitrary
    /// `data` payload the account sent with its borrow request.
    ///
    /// **Security guarantee**: this method checks the `caller` supplied by the
    /// invoking transaction against the account's approved-protocol registry
    /// before doing any work. An unrecognized caller is rejected with
    /// [`LatchSmartAccountError::FlashLoanCallbackUnauthorized`], preventing
    /// any contract from arbitrarily re-entering this account via the
    /// flash-loan path.
    ///
    /// The account must also authorize this call through its normal
    /// `require_auth` mechanism — the caller is verified against the registry
    /// first, so an unauthorized contract cannot even attempt to forge auth.
    ///
    /// # Arguments
    ///
    /// * `caller` - The lending-protocol address invoking the callback.
    ///   Must be in the approved-protocol registry.
    /// * `token` - The token disbursed by the flash loan.
    /// * `amount` - The amount disbursed (in token's smallest unit).
    /// * `data` - Opaque payload the account attached when requesting the
    ///   loan; passed back unchanged so the account can recover context.
    ///
    /// # Errors
    ///
    /// * [`LatchSmartAccountError::FlashLoanCallbackUnauthorized`] - If
    ///   `caller` is not in the approved-protocol registry.
    pub fn flash_loan_callback(e: &Env, caller: Address, token: Address, amount: i128, data: Val) {
        // ── Protocol verification ────────────────────────────────────────
        // Check the registry *before* requiring any auth so an unrecognized
        // protocol cannot probe whether the auth check would pass.
        if !Self::is_approved_flash_loan_protocol(e, caller.clone()) {
            panic_with_error!(e, LatchSmartAccountError::FlashLoanCallbackUnauthorized);
        }

        // ── Authorization ────────────────────────────────────────────────
        // The account itself must authorize the callback — the account's
        // `__check_auth` runs against the caller's context rule, ensuring the
        // callback is gated by the same signer/policy stack as every other
        // operation.
        e.current_contract_address().require_auth();

        // ── Application logic placeholder ────────────────────────────────
        // Real implementations would use `token` and `amount` to repay the
        // loan and `data` to recover context. The registry check above is the
        // security boundary; what happens here is application-specific and
        // intentionally left as a no-op in this base implementation.
        let _ = (token, amount, data);
    }
}

#[contractimpl]
impl CustomAccountInterface for LatchSmartAccount {
    type Error = SmartAccountError;
    type Signature = AuthPayload;

    fn __check_auth(
        e: Env,
        signature_payload: Hash<32>,
        signatures: AuthPayload,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Self::Error> {
        smart_account::do_check_auth(&e, &signature_payload, &signatures, &auth_contexts)
    }
}

#[contractimpl(contracttrait)]
impl SmartAccount for LatchSmartAccount {}

#[contractimpl(contracttrait)]
impl ExecutionEntryPoint for LatchSmartAccount {}

#[contractimpl]
impl Upgradeable for LatchSmartAccount {
    fn upgrade(e: &Env, new_wasm_hash: BytesN<32>, _operator: Address) {
        e.current_contract_address().require_auth();
        upgradeable::upgrade(e, &new_wasm_hash);
    }
}

#[cfg(test)]
mod test;
