#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::Hash,
    panic_with_error, token, Address, BytesN, Env, Map, String, Symbol, Val, Vec,
};
use stellar_accounts::smart_account::{
    self as smart_account, AuthPayload, ContextRule, ContextRuleType, ExecutionEntryPoint, Signer,
    SmartAccount, SmartAccountError, SMART_ACCOUNT_EXTEND_AMOUNT, SMART_ACCOUNT_TTL_THRESHOLD,
};
use stellar_contract_utils::upgradeable::{self as upgradeable, Upgradeable};

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
    /// The post-transfer token balance does not equal `balance_before -
    /// expected_delta`. Execution is halted to prevent silent fund leakage.
    BalanceInvariantViolated = 4002,
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

/// A single token transfer to be executed as part of a `batch_transfer` call.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct TransferOp {
    /// The SEP-41 token contract to call `transfer` on.
    pub token: Address,
    /// Recipient of the transfer.
    pub to: Address,
    /// Amount to transfer, in the token's smallest unit (must be positive).
    pub amount: i128,
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

    /// Executes a batch of token transfers and verifies that the net change in
    /// each token's balance matches the sum of amounts sent from this account.
    ///
    /// For every distinct token in `ops`, the method reads the account's
    /// balance before execution, runs all transfers for that token, then reads
    /// the balance again and asserts:
    ///
    /// ```text
    /// balance_after == balance_before - expected_delta
    /// ```
    ///
    /// where `expected_delta` is the sum of `amount` for all ops on that
    /// token. If the invariant fails (funds leaked or an unexpected credit
    /// occurred), execution panics with [`LatchSmartAccountError::BalanceInvariantViolated`]
    /// before any further state changes can take effect.
    ///
    /// Requires self-authorization, so a valid context rule covering this
    /// function must exist on the account before it can be called.
    ///
    /// # Errors
    ///
    /// * [`LatchSmartAccountError::BalanceInvariantViolated`] - If
    ///   `balance_after != balance_before - expected_delta` for any token.
    pub fn batch_transfer(e: &Env, ops: Vec<TransferOp>) {
        e.current_contract_address().require_auth();

        // Group operations by token so we can snapshot and verify per token.
        // We iterate ops twice: once to read pre-balances, once to execute
        // and read post-balances. Using a Map keeps the grouping inside the
        // no_std / no-alloc constraint.
        let mut tokens: Map<Address, i128> = Map::new(e);

        // Accumulate expected_delta per token.
        for op in ops.iter() {
            let current = tokens.get(op.token.clone()).unwrap_or(0i128);
            tokens.set(op.token.clone(), current.saturating_add(op.amount));
        }

        // For each token, record pre-balance, execute transfers, then verify.
        for (token_addr, expected_delta) in tokens.iter() {
            let token_client = token::TokenClient::new(e, &token_addr);
            let this = e.current_contract_address();

            let balance_before = token_client.balance(&this);

            // Execute all transfers belonging to this token.
            for op in ops.iter() {
                if op.token == token_addr {
                    token_client.transfer(&this, &op.to, &op.amount);
                }
            }

            let balance_after = token_client.balance(&this);

            // Invariant: balance_after == balance_before - expected_delta
            let expected_after = balance_before.saturating_sub(expected_delta);
            if balance_after != expected_after {
                panic_with_error!(e, LatchSmartAccountError::BalanceInvariantViolated);
            }
        }
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
