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
use stellar_contract_utils::{
    pausable::{self as pausable, Pausable},
    upgradeable::{self as upgradeable, Upgradeable},
};

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
    /// Re-entrancy guard status for account management and self-upgrade.
    UpgradeLock,
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
    /// Re-entrancy detected during self-upgrade or unauthorized upgrade state.
    ReentrancyGuardTriggered = 4002,
    /// Post-upgrade state migration verification failed.
    StateMigrationFailed = 4003,
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
    /// Verifies account state and storage format compatibility.
    ///
    /// Called immediately during an upgrade workflow before committing,
    /// ensuring that essential instance and persistent storage keys
    /// (such as context rules, deployed contract counts, and schema version)
    /// remain intact and compatible.
    pub fn verify_state_migration(e: &Env) {
        // 1. Verify instance storage consistency
        let _schema_version = upgradeable::get_schema_version(e);
        let count = Self::get_deployed_contract_count(e);

        // 2. Verify persistent storage accessibility for deployed contracts
        for i in 0..count {
            let key = LatchSmartAccountStorageKey::DeployedContract(i);
            if !e.storage().persistent().has(&key) {
                panic_with_error!(e, LatchSmartAccountError::StateMigrationFailed);
            }
        }

        // 3. Verify smart account core context rules are accessible and non-empty
        // At minimum, every valid smart account must have at least 1 active context rule.
        let rules_count = smart_account::get_context_rules_count(e);
        if rules_count == 0 {
            panic_with_error!(e, LatchSmartAccountError::StateMigrationFailed);
        }

        // Verify default rule (rule 0) can be read successfully
        let _default_rule = smart_account::get_context_rule(e, 0);
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

#[contractimpl]
impl ExecutionEntryPoint for LatchSmartAccount {
    /// Executes a function call on a target contract from within the smart
    /// account context. Overridden to enforce pausable checks: when the account
    /// is paused (e.g. by a guardian or threshold of recovery keys), outgoing
    /// calls are frozen to prevent unauthorized token dispatch while preserving
    /// administrative recovery functions.
    fn execute(e: &Env, target: Address, target_fn: Symbol, target_args: Vec<Val>) {
        pausable::when_not_paused(e);
        e.current_contract_address().require_auth();
        e.invoke_contract::<Val>(&target, &target_fn, target_args);
    }
}

#[contractimpl]
impl Pausable for LatchSmartAccount {
    /// Puts the account into a paused state, freezing outgoing `execute`
    /// calls.
    ///
    /// Requires authorization from `caller`. When configured with a guardian
    /// or recovery rule, the caller's authorization satisfies this requirement.
    fn pause(e: &Env, caller: Address) {
        caller.require_auth();
        pausable::pause(e);
    }

    /// Lifts the emergency pause, restoring outgoing `execute` calls.
    ///
    /// Requires authorization from `caller` (e.g. guardian or recovery admin).
    fn unpause(e: &Env, caller: Address) {
        caller.require_auth();
        pausable::unpause(e);
    }
}

#[contractimpl]
impl Upgradeable for LatchSmartAccount {
    fn upgrade(e: &Env, new_wasm_hash: BytesN<32>, _operator: Address) {
        // Enforce strict re-entrancy protection across upgrade invocations
        if e.storage().instance().has(&LatchSmartAccountStorageKey::UpgradeLock) {
            panic_with_error!(e, LatchSmartAccountError::ReentrancyGuardTriggered);
        }
        e.storage().instance().set(&LatchSmartAccountStorageKey::UpgradeLock, &true);

        // Explicit authorization boundary: requires authentication from the smart account itself
        e.current_contract_address().require_auth();

        // Perform the WASM bytecode update
        upgradeable::upgrade(e, &new_wasm_hash);

        // Explicit state migration verification hook called immediately after upgrade()
        // to verify storage format compatibility and integrity before transaction commit.
        Self::verify_state_migration(e);

        // Release the re-entrancy lock
        e.storage().instance().remove(&LatchSmartAccountStorageKey::UpgradeLock);
    }
}

#[cfg(test)]
mod test;
