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
    SignerTimelockDelay,
    SignerProposalCount,
    SignerProposal(u32),
}

/// The state of a pending signer rotation proposal.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ProposalStatus {
    Pending = 0,
    Executed = 1,
    Cancelled = 2,
}

/// The action type for a pending signer rotation proposal.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignerAction {
    Add(Signer),
    Remove(u32),
}

/// A proposal in the timelocked signer rotation queue.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct SignerProposal {
    pub id: u32,
    pub context_rule_id: u32,
    pub action: SignerAction,
    pub eta: u64,
    pub status: ProposalStatus,
    pub proposer: Address,
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
    /// The signer proposal was not found.
    ProposalNotFound = 4002,
    /// The signer proposal is not in pending state.
    ProposalNotPending = 4003,
    /// The timelock delay has not expired yet.
    TimelockNotExpired = 4004,
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

/// Event emitted when signer rotation timelock delay is updated.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerTimelockDelaySet {
    pub delay: u64,
}

/// Event emitted when a signer modification is proposed.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerProposed {
    #[topic]
    pub proposal_id: u32,
    #[topic]
    pub context_rule_id: u32,
    pub eta: u64,
    pub proposer: Address,
}

/// Event emitted when a pending signer proposal is accepted and executed.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerAccepted {
    #[topic]
    pub proposal_id: u32,
    #[topic]
    pub context_rule_id: u32,
}

/// Event emitted when a pending signer proposal is cancelled.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerProposalCancelled {
    #[topic]
    pub proposal_id: u32,
    #[topic]
    pub context_rule_id: u32,
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

    /// Sets the timelock delay (in seconds) required between proposing and accepting
    /// a signer change. Requires self-authorization from the account.
    pub fn set_signer_timelock_delay(e: &Env, delay: u64) {
        e.current_contract_address().require_auth();
        e.storage()
            .instance()
            .set(&LatchSmartAccountStorageKey::SignerTimelockDelay, &delay);
        SignerTimelockDelaySet { delay }.publish(e);
    }

    /// Returns the current timelock delay for signer changes in seconds. Defaults to 0.
    pub fn get_signer_timelock_delay(e: &Env) -> u64 {
        e.storage()
            .instance()
            .get(&LatchSmartAccountStorageKey::SignerTimelockDelay)
            .unwrap_or(0)
    }

    /// Returns the total number of signer rotation proposals created so far.
    pub fn get_signer_proposal_count(e: &Env) -> u32 {
        e.storage()
            .instance()
            .get(&LatchSmartAccountStorageKey::SignerProposalCount)
            .unwrap_or(0)
    }

    /// Returns the proposal at `proposal_id`.
    ///
    /// # Errors
    ///
    /// * [`LatchSmartAccountError::ProposalNotFound`] - If no proposal exists at `proposal_id`.
    pub fn get_signer_proposal(e: &Env, proposal_id: u32) -> SignerProposal {
        let key = LatchSmartAccountStorageKey::SignerProposal(proposal_id);
        e.storage()
            .persistent()
            .get::<_, SignerProposal>(&key)
            .inspect(|_| {
                e.storage().persistent().extend_ttl(
                    &key,
                    SMART_ACCOUNT_TTL_THRESHOLD,
                    SMART_ACCOUNT_EXTEND_AMOUNT,
                );
            })
            .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::ProposalNotFound))
    }

    /// Proposes a signer addition or removal subject to the timelock delay.
    /// Requires self-authorization from the account.
    ///
    /// Returns the unique `proposal_id`.
    pub fn propose_signer(
        e: &Env,
        context_rule_id: u32,
        action: SignerAction,
    ) -> u32 {
        let account = e.current_contract_address();
        account.require_auth();

        let proposal_id = Self::get_signer_proposal_count(e);
        let next_count = proposal_id
            .checked_add(1)
            .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::MathOverflow));
        e.storage()
            .instance()
            .set(&LatchSmartAccountStorageKey::SignerProposalCount, &next_count);

        let delay = Self::get_signer_timelock_delay(e);
        let eta = e.ledger().timestamp() + delay;

        let proposal = SignerProposal {
            id: proposal_id,
            context_rule_id,
            action,
            eta,
            status: ProposalStatus::Pending,
            proposer: account.clone(),
        };

        let key = LatchSmartAccountStorageKey::SignerProposal(proposal_id);
        e.storage().persistent().set(&key, &proposal);
        e.storage().persistent().extend_ttl(
            &key,
            SMART_ACCOUNT_TTL_THRESHOLD,
            SMART_ACCOUNT_EXTEND_AMOUNT,
        );

        SignerProposed {
            proposal_id,
            context_rule_id,
            eta,
            proposer: account,
        }
        .publish(e);

        proposal_id
    }

    /// Accepts and executes a pending signer proposal whose timelock delay has elapsed.
    /// Requires self-authorization from the account.
    pub fn accept_signer(e: &Env, proposal_id: u32) {
        e.current_contract_address().require_auth();

        let key = LatchSmartAccountStorageKey::SignerProposal(proposal_id);
        let mut proposal = e
            .storage()
            .persistent()
            .get::<_, SignerProposal>(&key)
            .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::ProposalNotFound));

        if proposal.status != ProposalStatus::Pending {
            panic_with_error!(e, LatchSmartAccountError::ProposalNotPending);
        }

        if e.ledger().timestamp() < proposal.eta {
            panic_with_error!(e, LatchSmartAccountError::TimelockNotExpired);
        }

        proposal.status = ProposalStatus::Executed;
        e.storage().persistent().set(&key, &proposal);
        e.storage().persistent().extend_ttl(
            &key,
            SMART_ACCOUNT_TTL_THRESHOLD,
            SMART_ACCOUNT_EXTEND_AMOUNT,
        );

        match &proposal.action {
            SignerAction::Add(signer) => {
                smart_account::add_signer(e, proposal.context_rule_id, signer);
            }
            SignerAction::Remove(signer_id) => {
                smart_account::remove_signer(e, proposal.context_rule_id, *signer_id);
            }
        }

        SignerAccepted {
            proposal_id,
            context_rule_id: proposal.context_rule_id,
        }
        .publish(e);
    }

    /// Cancels a disputed or unwanted pending signer proposal.
    /// Requires self-authorization from the account.
    pub fn cancel_signer_proposal(e: &Env, proposal_id: u32) {
        e.current_contract_address().require_auth();

        let key = LatchSmartAccountStorageKey::SignerProposal(proposal_id);
        let mut proposal = e
            .storage()
            .persistent()
            .get::<_, SignerProposal>(&key)
            .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::ProposalNotFound));

        if proposal.status != ProposalStatus::Pending {
            panic_with_error!(e, LatchSmartAccountError::ProposalNotPending);
        }

        proposal.status = ProposalStatus::Cancelled;
        e.storage().persistent().set(&key, &proposal);
        e.storage().persistent().extend_ttl(
            &key,
            SMART_ACCOUNT_TTL_THRESHOLD,
            SMART_ACCOUNT_EXTEND_AMOUNT,
        );

        SignerProposalCancelled {
            proposal_id,
            context_rule_id: proposal.context_rule_id,
        }
        .publish(e);
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
