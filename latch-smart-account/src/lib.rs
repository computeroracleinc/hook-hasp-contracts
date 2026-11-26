#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractevent, contractimpl, contracttype,
    crypto::Hash,
    panic_with_error, token,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, Map, String, Symbol, Val, Vec,
};
use stellar_accounts::smart_account::{
    self as smart_account, AuthPayload, ContextRule, ContextRuleType, ExecutionEntryPoint, Signer,
    SmartAccount, SmartAccountError, MAX_SIGNERS, SMART_ACCOUNT_EXTEND_AMOUNT,
    SMART_ACCOUNT_TTL_THRESHOLD,
};
use stellar_contract_utils::{
    pausable::{self as pausable, Pausable},
    upgradeable::{self as upgradeable, Upgradeable},
};

// ################## CONSTANTS ##################

/// Number of ledgers in one day on Stellar (approx. 5 seconds per ledger).
pub const DAY_IN_LEDGERS: u32 = 17280;

/// Default extended inactivity delay required before fallback recovery can be
/// executed: 14 days of inactivity (241,920 ledgers).
pub const DEFAULT_RECOVERY_INACTIVITY_DELAY_LEDGERS: u32 = 14 * DAY_IN_LEDGERS;

/// Maximum number of secondary recovery signers permitted in a recovery
/// configuration.
pub const MAX_RECOVERY_SIGNERS: u32 = 20;

/// Approximate ledger close time in seconds used to size proposal TTL beyond
/// configured timelock delays.
const LEDGER_CLOSE_TIME_SECS: u64 = 5;

// ################## TYPES ##################

/// Record of a satellite contract this account has deployed via
/// `deploy_contract`, kept for client-side discoverability without needing
/// an off-chain indexer.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct DeployedContract {
    pub wasm_hash: BytesN<32>,
    pub address: Address,
}

/// A single token transfer executed as part of `batch_transfer`.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct TransferOp {
    /// The SEP-41 token contract to call `transfer` on.
    pub token: Address,
    /// Recipient of the transfer.
    pub to: Address,
    /// Amount to transfer, in the token's smallest unit (must be strictly positive).
    pub amount: i128,
}

/// Configuration for the secondary threshold fallback recovery mechanism.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RecoveryConfig {
    /// Secondary recovery signers (e.g. social recovery guardians or backup hardware keys).
    pub recovery_signers: Vec<Signer>,
    /// Minimum number of recovery signers required to authorize recovery.
    pub threshold: u32,
    /// Extended inactivity delay (in host ledgers) required before recovery can be triggered.
    pub inactivity_delay_ledgers: u32,
}

/// State of a pending signer rotation proposal.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ProposalStatus {
    Pending = 0,
    Executed = 1,
    Cancelled = 2,
}

/// Action type for a pending signer rotation proposal.
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

/// Pending timelock delay reduction proposal.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingTimelockDelay {
    pub new_delay: u64,
    pub eta: u64,
}

// ################## STORAGE KEYS ##################

#[contracttype]
pub enum LatchSmartAccountStorageKey {
    DeployedContractCount,
    DeployedContract(u32),
    /// Approved lending-protocol address for `flash_loan_callback`.
    ApprovedFlashLoanProtocol(Address),
    /// Re-entrancy guard for `upgrade`.
    UpgradeLock,
    /// Re-entrancy guard for `execute`, `deploy_contract`, and `batch_transfer`.
    ReentrancyLock,
    /// Host ledger sequence number when the primary account signers were last active.
    LastActiveLedger,
    /// Configuration for secondary threshold fallback recovery.
    RecoveryConfig,
    /// Anti-replay nonce for recovery operations.
    RecoveryNonce,
    /// Timelock delay (seconds) for signer rotation proposals.
    SignerTimelockDelay,
    /// Pending timelock delay reduction proposal.
    PendingSignerTimelockDelay,
    /// Monotonic counter of signer rotation proposals.
    SignerProposalCount,
    /// Signer rotation proposal by ID.
    SignerProposal(u32),
}

// ################## ERRORS ##################

/// Error codes for `LatchSmartAccount`'s own methods, distinct from
/// `SmartAccountError` (3000+) and `PausableError` (1000+).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum LatchSmartAccountError {
    /// No deployed contract is recorded at the requested index.
    DeployedContractNotFound = 4000,
    /// Arithmetic or counter overflow/underflow.
    MathOverflow = 4001,
    /// Flash-loan callback caller is not in the approved-protocol registry.
    FlashLoanCallbackUnauthorized = 4002,
    /// Post-transfer token balance violated `balance_before - expected_delta`.
    BalanceInvariantViolated = 4003,
    /// `TransferOp::amount` must be strictly positive (`> 0`).
    InvalidTransferAmount = 4004,
    /// Re-entrancy detected during `upgrade`.
    ReentrancyGuardTriggered = 4005,
    /// Post-upgrade state migration verification failed.
    StateMigrationFailed = 4006,
    /// `pause`/`unpause` caller must be this smart account contract itself.
    UnauthorizedPauseCaller = 4007,
    /// Re-entrancy detected during `execute`, `deploy_contract`, or `batch_transfer`.
    ReentrantCall = 4008,
    /// No fallback recovery configuration is installed on this account.
    RecoveryNotConfigured = 4009,
    /// Fallback recovery configuration or replacement signer set is invalid.
    InvalidRecoveryConfig = 4010,
    /// Required inactivity delay has not yet elapsed.
    InactivityDelayNotMet = 4011,
    /// Fewer than `threshold` authorized recovery signers signed the digest.
    RecoveryThresholdNotMet = 4012,
    /// Provided signer is not in the configured recovery signer set.
    UnauthorizedRecoverySigner = 4013,
    /// Duplicate recovery signer signature provided.
    DuplicateRecoverySigner = 4014,
    /// Replacement signer list for recovery cannot be empty.
    EmptyNewSigners = 4015,
    /// Signer proposal was not found.
    ProposalNotFound = 4016,
    /// Signer proposal is not in the pending state.
    ProposalNotPending = 4017,
    /// Timelock delay has not yet elapsed.
    TimelockNotExpired = 4018,
    /// Direct delay reduction is forbidden; use `propose_timelock_delay_change`.
    DelayReductionNotAllowed = 4019,
}

// ################## EVENTS ##################

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractDeployed {
    #[topic]
    pub address: Address,
    pub wasm_hash: BytesN<32>,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlashLoanProtocolRegistered {
    #[topic]
    pub protocol: Address,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlashLoanProtocolRemoved {
    #[topic]
    pub protocol: Address,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryConfigured {
    #[topic]
    pub smart_account: Address,
    pub threshold: u32,
    pub inactivity_delay_ledgers: u32,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRemoved {
    #[topic]
    pub smart_account: Address,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityRecorded {
    #[topic]
    pub smart_account: Address,
    pub ledger_sequence: u32,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountRecovered {
    #[topic]
    pub smart_account: Address,
    pub context_rule_id: u32,
    pub recovered_at_ledger: u32,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerTimelockDelaySet {
    pub delay: u64,
}

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

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerAccepted {
    #[topic]
    pub proposal_id: u32,
    #[topic]
    pub context_rule_id: u32,
}

#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerProposalCancelled {
    #[topic]
    pub proposal_id: u32,
    #[topic]
    pub context_rule_id: u32,
}

// ################## HELPERS ##################

fn acquire_reentrancy_lock(e: &Env) {
    let key = LatchSmartAccountStorageKey::ReentrancyLock;
    if e.storage().temporary().get::<_, bool>(&key).unwrap_or(false) {
        panic_with_error!(e, LatchSmartAccountError::ReentrantCall);
    }
    e.storage().temporary().set(&key, &true);
}

fn release_reentrancy_lock(e: &Env) {
    e.storage().temporary().remove(&LatchSmartAccountStorageKey::ReentrancyLock);
}

/// Computes a domain-separated recovery digest bound to `network_id`,
/// `account`, `context_rule_id`, `new_signers`, and `nonce`.
fn compute_recovery_digest(
    e: &Env,
    account: &Address,
    context_rule_id: u32,
    new_signers: &Vec<Signer>,
    nonce: u64,
) -> Hash<32> {
    let mut payload = Bytes::new(e);
    payload.append(&String::from_str(e, "recover_signers").to_bytes());
    payload.extend_from_slice(&e.ledger().network_id().to_array());
    payload.append(&account.to_xdr(e));
    payload.append(&context_rule_id.to_xdr(e));
    payload.append(&new_signers.to_xdr(e));
    payload.append(&nonce.to_xdr(e));
    e.crypto().sha256(&payload)
}

/// Computes a safe TTL extension target covering at least `delay` seconds plus
/// a full safety buffer, clamped to the ledger's configured `max_ttl`.
fn proposal_ttl_extend_amount(e: &Env, delay_secs: u64) -> u32 {
    let delay_ledgers = u32::try_from(delay_secs / LEDGER_CLOSE_TIME_SECS).unwrap_or(u32::MAX);
    let desired = SMART_ACCOUNT_EXTEND_AMOUNT.max(delay_ledgers.saturating_add(DAY_IN_LEDGERS));
    desired.min(e.storage().max_ttl())
}

// ################## CONTRACT ##################

#[contract]
pub struct LatchSmartAccount;

#[contractimpl]
impl LatchSmartAccount {
    /// Contract constructor — installs the initial `Default` context rule with
    /// the deployer-supplied signers/policies and records the creation ledger
    /// as `LastActiveLedger`.
    pub fn __constructor(e: &Env, signers: Vec<Signer>, policies: Map<Address, Val>) {
        smart_account::add_context_rule(
            e,
            &ContextRuleType::Default,
            &String::from_str(e, "default"),
            None,
            &signers,
            &policies,
        );
        let current_ledger = e.ledger().sequence();
        e.storage()
            .instance()
            .set(&LatchSmartAccountStorageKey::LastActiveLedger, &current_ledger);
    }

    /// Adds a batch of signers to an existing context rule on this smart account.
    pub fn batch_add_signer(e: &Env, context_rule_id: u32, signers: Vec<Signer>) {
        e.current_contract_address().require_auth();
        smart_account::batch_add_signer(e, context_rule_id, &signers);
    }

    /// Deploys a new contract owned by this account with re-entrancy protection.
    pub fn deploy_contract(
        e: &Env,
        wasm_hash: BytesN<32>,
        salt: BytesN<32>,
        constructor_args: Vec<Val>,
    ) -> Address {
        acquire_reentrancy_lock(e);

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
        let record = DeployedContract { wasm_hash: wasm_hash.clone(), address: address.clone() };
        e.storage().persistent().set(&key, &record);
        e.storage().persistent().extend_ttl(
            &key,
            SMART_ACCOUNT_TTL_THRESHOLD,
            SMART_ACCOUNT_EXTEND_AMOUNT,
        );

        ContractDeployed { address: address.clone(), wasm_hash }.publish(e);

        release_reentrancy_lock(e);

        address
    }

    /// Returns the number of contracts this account has deployed via `deploy_contract`.
    pub fn get_deployed_contract_count(e: &Env) -> u32 {
        e.storage()
            .instance()
            .get(&LatchSmartAccountStorageKey::DeployedContractCount)
            .unwrap_or(0)
    }

    /// Returns the `index`-th contract deployed via `deploy_contract`.
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

    // ── State migration verification (#190) ──────────────────────────────────

    /// Verifies core account state integrity after an upgrade without bricking
    /// accounts whose initial rule `0` was replaced or whose historical
    /// persistent deployment records have expired.
    pub fn verify_state_migration(e: &Env) {
        let _schema_version = upgradeable::get_schema_version(e);

        // Verify at least one active context rule remains registered.
        let rules_count = smart_account::get_context_rules_count(e);
        if rules_count == 0 {
            panic_with_error!(e, LatchSmartAccountError::StateMigrationFailed);
        }

        // Verify DeployedContractCount is readable and any still-live
        // persistent deployment records deserialize cleanly.
        let count = Self::get_deployed_contract_count(e);
        for i in 0..count {
            let key = LatchSmartAccountStorageKey::DeployedContract(i);
            if e.storage().persistent().has(&key) {
                let _record: DeployedContract = e
                    .storage()
                    .persistent()
                    .get(&key)
                    .unwrap_or_else(|| {
                        panic_with_error!(e, LatchSmartAccountError::StateMigrationFailed)
                    });
            }
        }
    }

    // ── Flash-loan protocol registry (#170) ──────────────────────────────────

    /// Adds `protocol` to the set of lending-protocol addresses permitted to
    /// invoke `flash_loan_callback`. Requires self-auth.
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

    /// Removes `protocol` from the approved flash-loan protocol set. Requires self-auth.
    pub fn remove_flash_loan_protocol(e: &Env, protocol: Address) {
        e.current_contract_address().require_auth();
        let key = LatchSmartAccountStorageKey::ApprovedFlashLoanProtocol(protocol.clone());
        e.storage().persistent().remove(&key);
        FlashLoanProtocolRemoved { protocol }.publish(e);
    }

    /// Returns `true` if `protocol` is in the approved-protocol registry.
    pub fn is_approved_flash_loan_protocol(e: &Env, protocol: Address) -> bool {
        let key = LatchSmartAccountStorageKey::ApprovedFlashLoanProtocol(protocol);
        e.storage().persistent().has(&key)
    }

    /// Flash-loan callback entrypoint.
    ///
    /// Enforces:
    /// 1. `caller` is in the approved-protocol registry.
    /// 2. `caller.require_auth()` — prevents an untrusted contract from
    ///    spoofing an approved protocol's address.
    /// 3. `e.current_contract_address().require_auth()` — gates execution
    ///    through this account's own signer/policy stack.
    pub fn flash_loan_callback(e: &Env, caller: Address, token: Address, amount: i128, data: Val) {
        if !Self::is_approved_flash_loan_protocol(e, caller.clone()) {
            panic_with_error!(e, LatchSmartAccountError::FlashLoanCallbackUnauthorized);
        }

        // Authenticate the calling lending protocol so untrusted contracts
        // cannot spoof an approved protocol address.
        caller.require_auth();
        e.current_contract_address().require_auth();

        let _ = (token, amount, data);
    }

    // ── Batch transfer with balance-invariant verification (#175) ────────────

    /// Executes a batch of SEP-41 token transfers and verifies per-token that
    /// `balance_after == balance_before - expected_delta` (accounting for
    /// self-transfers and using checked arithmetic).
    pub fn batch_transfer(e: &Env, ops: Vec<TransferOp>) {
        pausable::when_not_paused(e);
        let this = e.current_contract_address();
        this.require_auth();
        acquire_reentrancy_lock(e);

        let mut tokens: Map<Address, i128> = Map::new(e);

        for op in ops.iter() {
            if op.amount <= 0 {
                panic_with_error!(e, LatchSmartAccountError::InvalidTransferAmount);
            }
            let current = tokens.get(op.token.clone()).unwrap_or(0i128);
            // Self-transfers do not reduce this account's net token balance.
            let delta = if op.to == this { 0i128 } else { op.amount };
            let next = current
                .checked_add(delta)
                .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::MathOverflow));
            tokens.set(op.token.clone(), next);
        }

        for (token_addr, expected_delta) in tokens.iter() {
            let token_client = token::TokenClient::new(e, &token_addr);
            let balance_before = token_client.balance(&this);

            for op in ops.iter() {
                if op.token == token_addr {
                    token_client.transfer(&this, &op.to, &op.amount);
                }
            }

            let balance_after = token_client.balance(&this);
            let expected_after = balance_before
                .checked_sub(expected_delta)
                .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::MathOverflow));
            if balance_after != expected_after {
                panic_with_error!(e, LatchSmartAccountError::BalanceInvariantViolated);
            }
        }

        release_reentrancy_lock(e);
    }

    // ── Fallback recovery mechanism (#191) ───────────────────────────────────

    /// Configures secondary threshold fallback recovery. Requires self-auth.
    /// Initializes `LastActiveLedger` to the current ledger if unset (preventing
    /// zero-delay takeover on upgraded accounts).
    pub fn set_recovery_config(
        e: &Env,
        recovery_signers: Vec<Signer>,
        threshold: u32,
        inactivity_delay_ledgers: u32,
    ) {
        let account = e.current_contract_address();
        account.require_auth();

        let len = recovery_signers.len();
        if len == 0 || len > MAX_RECOVERY_SIGNERS || threshold == 0 || threshold > len {
            panic_with_error!(e, LatchSmartAccountError::InvalidRecoveryConfig);
        }

        for i in 0..len {
            let s_i = recovery_signers
                .get(i)
                .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::InvalidRecoveryConfig));
            for j in (i + 1)..len {
                let s_j = recovery_signers.get(j).unwrap_or_else(|| {
                    panic_with_error!(e, LatchSmartAccountError::InvalidRecoveryConfig)
                });
                if s_i == s_j {
                    panic_with_error!(e, LatchSmartAccountError::InvalidRecoveryConfig);
                }
            }
        }

        let delay = if inactivity_delay_ledgers == 0 {
            DEFAULT_RECOVERY_INACTIVITY_DELAY_LEDGERS
        } else {
            inactivity_delay_ledgers
        };

        // Ensure upgraded accounts that never ran the new constructor initialize
        // LastActiveLedger to now rather than defaulting to 0.
        if !e.storage().instance().has(&LatchSmartAccountStorageKey::LastActiveLedger) {
            let now = e.ledger().sequence();
            e.storage().instance().set(&LatchSmartAccountStorageKey::LastActiveLedger, &now);
        }

        let config = RecoveryConfig {
            recovery_signers,
            threshold,
            inactivity_delay_ledgers: delay,
        };
        e.storage().instance().set(&LatchSmartAccountStorageKey::RecoveryConfig, &config);

        RecoveryConfigured { smart_account: account, threshold, inactivity_delay_ledgers: delay }
            .publish(e);
    }

    /// Returns the active recovery configuration.
    pub fn get_recovery_config(e: &Env) -> RecoveryConfig {
        e.storage()
            .instance()
            .get(&LatchSmartAccountStorageKey::RecoveryConfig)
            .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::RecoveryNotConfigured))
    }

    /// Removes the recovery configuration. Requires self-auth.
    pub fn remove_recovery_config(e: &Env) {
        let account = e.current_contract_address();
        account.require_auth();
        if !e.storage().instance().has(&LatchSmartAccountStorageKey::RecoveryConfig) {
            panic_with_error!(e, LatchSmartAccountError::RecoveryNotConfigured);
        }
        e.storage().instance().remove(&LatchSmartAccountStorageKey::RecoveryConfig);
        RecoveryRemoved { smart_account: account }.publish(e);
    }

    /// Returns the host ledger sequence when the account was last active.
    pub fn get_last_active_ledger(e: &Env) -> u32 {
        e.storage()
            .instance()
            .get(&LatchSmartAccountStorageKey::LastActiveLedger)
            .unwrap_or(0)
    }

    /// Explicitly refreshes `LastActiveLedger` to the current host ledger.
    pub fn touch_activity(e: &Env) {
        let account = e.current_contract_address();
        account.require_auth();
        let current_ledger = e.ledger().sequence();
        e.storage()
            .instance()
            .set(&LatchSmartAccountStorageKey::LastActiveLedger, &current_ledger);
        ActivityRecorded { smart_account: account, ledger_sequence: current_ledger }.publish(e);
    }

    /// Returns `true` if recovery is configured and inactivity delay has elapsed.
    pub fn is_recovery_eligible(e: &Env) -> bool {
        let Some(config) = e
            .storage()
            .instance()
            .get::<_, RecoveryConfig>(&LatchSmartAccountStorageKey::RecoveryConfig)
        else {
            return false;
        };
        let current_ledger = e.ledger().sequence();
        let last_active = Self::get_last_active_ledger(e);
        current_ledger.saturating_sub(last_active) >= config.inactivity_delay_ledgers
    }

    /// Returns the current recovery anti-replay nonce.
    pub fn get_recovery_nonce(e: &Env) -> u64 {
        e.storage()
            .instance()
            .get(&LatchSmartAccountStorageKey::RecoveryNonce)
            .unwrap_or(0)
    }

    /// Computes the network- and contract-bound recovery digest for the current nonce.
    pub fn get_recovery_digest(
        e: &Env,
        context_rule_id: u32,
        new_signers: Vec<Signer>,
    ) -> BytesN<32> {
        let nonce = Self::get_recovery_nonce(e);
        compute_recovery_digest(
            e,
            &e.current_contract_address(),
            context_rule_id,
            &new_signers,
            nonce,
        )
        .to_bytes()
    }

    /// Recovers the smart account by replacing signers on `context_rule_id`
    /// safely within `MAX_SIGNERS`.
    pub fn recover_signers(
        e: &Env,
        context_rule_id: u32,
        new_signers: Vec<Signer>,
        signatures: Map<Signer, Bytes>,
    ) {
        let config = Self::get_recovery_config(e);

        let new_len = new_signers.len();
        if new_len == 0 {
            panic_with_error!(e, LatchSmartAccountError::EmptyNewSigners);
        }
        if new_len > MAX_SIGNERS {
            panic_with_error!(e, LatchSmartAccountError::InvalidRecoveryConfig);
        }

        // Validate no duplicates in new_signers without `.unwrap()`.
        for i in 0..new_len {
            let s_i = new_signers
                .get(i)
                .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::InvalidRecoveryConfig));
            for j in (i + 1)..new_len {
                let s_j = new_signers.get(j).unwrap_or_else(|| {
                    panic_with_error!(e, LatchSmartAccountError::InvalidRecoveryConfig)
                });
                if s_i == s_j {
                    panic_with_error!(e, LatchSmartAccountError::InvalidRecoveryConfig);
                }
            }
        }

        // 1. Inactivity delay check.
        let current_ledger = e.ledger().sequence();
        let last_active = Self::get_last_active_ledger(e);
        if current_ledger.saturating_sub(last_active) < config.inactivity_delay_ledgers {
            panic_with_error!(e, LatchSmartAccountError::InactivityDelayNotMet);
        }

        // 2. Network- and contract-bound digest with anti-replay nonce.
        let account = e.current_contract_address();
        let nonce = Self::get_recovery_nonce(e);
        let auth_digest =
            compute_recovery_digest(e, &account, context_rule_id, &new_signers, nonce);

        // 3. Enforce threshold recovery signatures.
        let mut authenticated_count: u32 = 0;
        let mut seen_signers: Vec<Signer> = Vec::new(e);

        for (signer, sig_data) in signatures.iter() {
            if !config.recovery_signers.contains(&signer) {
                panic_with_error!(e, LatchSmartAccountError::UnauthorizedRecoverySigner);
            }
            if seen_signers.contains(&signer) {
                panic_with_error!(e, LatchSmartAccountError::DuplicateRecoverySigner);
            }
            seen_signers.push_back(signer.clone());

            smart_account::authenticate(e, &auth_digest, &signer, &sig_data);
            authenticated_count = authenticated_count
                .checked_add(1)
                .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::MathOverflow));
        }

        if authenticated_count < config.threshold {
            panic_with_error!(e, LatchSmartAccountError::RecoveryThresholdNotMet);
        }

        // 4. Rotate signers safely within `1..=MAX_SIGNERS`:
        //    - Collect signers to add and old signers to remove.
        //    - If the rule is already full (`>= MAX_SIGNERS`) and we need to
        //      add at least one new signer, remove one obsolete signer first
        //      (leaving >= 1 signer) so adding the first new signer fits.
        //    - Add the first new signer so the rule stays non-empty while
        //      removing all remaining obsolete signers.
        //    - Add all remaining new signers.
        let old_rule = smart_account::get_context_rule(e, context_rule_id);
        let mut to_add = Vec::new(e);
        for signer in new_signers.iter() {
            if !old_rule.signers.contains(&signer) {
                to_add.push_back(signer);
            }
        }
        let mut to_remove = Vec::new(e);
        for old_signer in old_rule.signers.iter() {
            if !new_signers.contains(&old_signer) {
                to_remove.push_back(old_signer);
            }
        }

        let mut remove_idx: u32 = 0;
        let mut add_idx: u32 = 0;

        if !to_add.is_empty() {
            if old_rule.signers.len() >= MAX_SIGNERS {
                if let Some(first_old) = to_remove.get(0) {
                    let signer_id = <Self as SmartAccount>::get_signer_id(e, first_old);
                    smart_account::remove_signer(e, context_rule_id, signer_id);
                    remove_idx = 1;
                }
            }
            if let Some(first_new) = to_add.get(0) {
                smart_account::add_signer(e, context_rule_id, &first_new);
                add_idx = 1;
            }
        }

        for i in remove_idx..to_remove.len() {
            if let Some(old_signer) = to_remove.get(i) {
                let signer_id = <Self as SmartAccount>::get_signer_id(e, old_signer);
                smart_account::remove_signer(e, context_rule_id, signer_id);
            }
        }

        if add_idx < to_add.len() {
            let mut rest = Vec::new(e);
            for i in add_idx..to_add.len() {
                if let Some(s) = to_add.get(i) {
                    rest.push_back(s);
                }
            }
            smart_account::batch_add_signer(e, context_rule_id, &rest);
        }

        // 5. Advance nonce and refresh LastActiveLedger.
        let next_nonce = nonce
            .checked_add(1)
            .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::MathOverflow));
        e.storage().instance().set(&LatchSmartAccountStorageKey::RecoveryNonce, &next_nonce);
        e.storage()
            .instance()
            .set(&LatchSmartAccountStorageKey::LastActiveLedger, &current_ledger);

        AccountRecovered {
            smart_account: account,
            context_rule_id,
            recovered_at_ledger: current_ledger,
        }
        .publish(e);
    }

    // ── Timelocked signer rotation queue (#193) ──────────────────────────────

    /// Sets or increases the timelock delay (in seconds) for signer proposals.
    /// Reducing an active delay directly is rejected with
    /// [`LatchSmartAccountError::DelayReductionNotAllowed`] to prevent instant
    /// same-ledger bypass; use [`propose_timelock_delay_change`] instead.
    pub fn set_signer_timelock_delay(e: &Env, delay: u64) {
        e.current_contract_address().require_auth();
        let current_delay = Self::get_signer_timelock_delay(e);
        if delay < current_delay {
            panic_with_error!(e, LatchSmartAccountError::DelayReductionNotAllowed);
        }
        e.storage()
            .instance()
            .set(&LatchSmartAccountStorageKey::SignerTimelockDelay, &delay);
        e.storage()
            .instance()
            .remove(&LatchSmartAccountStorageKey::PendingSignerTimelockDelay);
        SignerTimelockDelaySet { delay }.publish(e);
    }

    /// Proposes a timelock delay change (including reductions) subject to the
    /// currently configured delay before it can be activated.
    pub fn propose_timelock_delay_change(e: &Env, new_delay: u64) -> PendingTimelockDelay {
        e.current_contract_address().require_auth();
        let current_delay = Self::get_signer_timelock_delay(e);
        let eta = e
            .ledger()
            .timestamp()
            .checked_add(current_delay)
            .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::MathOverflow));
        let pending = PendingTimelockDelay { new_delay, eta };
        e.storage()
            .instance()
            .set(&LatchSmartAccountStorageKey::PendingSignerTimelockDelay, &pending);
        pending
    }

    /// Executes a pending timelock delay change once its `eta` has elapsed.
    pub fn accept_timelock_delay_change(e: &Env) {
        e.current_contract_address().require_auth();
        let pending: PendingTimelockDelay = e
            .storage()
            .instance()
            .get(&LatchSmartAccountStorageKey::PendingSignerTimelockDelay)
            .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::ProposalNotFound));
        if e.ledger().timestamp() < pending.eta {
            panic_with_error!(e, LatchSmartAccountError::TimelockNotExpired);
        }
        e.storage()
            .instance()
            .set(&LatchSmartAccountStorageKey::SignerTimelockDelay, &pending.new_delay);
        e.storage()
            .instance()
            .remove(&LatchSmartAccountStorageKey::PendingSignerTimelockDelay);
        SignerTimelockDelaySet { delay: pending.new_delay }.publish(e);
    }

    /// Cancels a pending timelock delay change.
    pub fn cancel_timelock_delay_change(e: &Env) {
        e.current_contract_address().require_auth();
        if !e
            .storage()
            .instance()
            .has(&LatchSmartAccountStorageKey::PendingSignerTimelockDelay)
        {
            panic_with_error!(e, LatchSmartAccountError::ProposalNotFound);
        }
        e.storage()
            .instance()
            .remove(&LatchSmartAccountStorageKey::PendingSignerTimelockDelay);
    }

    /// Returns the pending timelock delay change, if any.
    pub fn get_pending_timelock_delay(e: &Env) -> Option<PendingTimelockDelay> {
        e.storage()
            .instance()
            .get(&LatchSmartAccountStorageKey::PendingSignerTimelockDelay)
    }

    /// Returns the current timelock delay for signer changes in seconds.
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

    /// Returns the signer proposal at `proposal_id`.
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
    /// Validates `context_rule_id` exists, computes `eta` via checked addition,
    /// and extends proposal persistent TTL beyond the timelock delay.
    pub fn propose_signer(e: &Env, context_rule_id: u32, action: SignerAction) -> u32 {
        let account = e.current_contract_address();
        account.require_auth();

        // Validate the target context rule exists before queueing a proposal.
        let _ = smart_account::get_context_rule(e, context_rule_id);

        let proposal_id = Self::get_signer_proposal_count(e);
        let next_count = proposal_id
            .checked_add(1)
            .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::MathOverflow));
        e.storage()
            .instance()
            .set(&LatchSmartAccountStorageKey::SignerProposalCount, &next_count);

        let delay = Self::get_signer_timelock_delay(e);
        let eta = e
            .ledger()
            .timestamp()
            .checked_add(delay)
            .unwrap_or_else(|| panic_with_error!(e, LatchSmartAccountError::MathOverflow));

        let proposal = SignerProposal {
            id: proposal_id,
            context_rule_id,
            action,
            eta,
            status: ProposalStatus::Pending,
            proposer: account.clone(),
        };

        let key = LatchSmartAccountStorageKey::SignerProposal(proposal_id);
        let extend_to = proposal_ttl_extend_amount(e, delay);
        let threshold = extend_to.saturating_sub(DAY_IN_LEDGERS);
        e.storage().persistent().set(&key, &proposal);
        e.storage().persistent().extend_ttl(&key, threshold, extend_to);

        SignerProposed { proposal_id, context_rule_id, eta, proposer: account }.publish(e);

        proposal_id
    }

    /// Executes a pending signer proposal whose timelock delay has elapsed.
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

        SignerAccepted { proposal_id, context_rule_id: proposal.context_rule_id }.publish(e);
    }

    /// Cancels a pending signer proposal.
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

        SignerProposalCancelled { proposal_id, context_rule_id: proposal.context_rule_id }
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
        e.storage().instance().extend_ttl(
            SMART_ACCOUNT_TTL_THRESHOLD,
            SMART_ACCOUNT_EXTEND_AMOUNT,
        );
        smart_account::do_check_auth(&e, &signature_payload, &signatures, &auth_contexts)?;
        let current_ledger = e.ledger().sequence();
        e.storage()
            .instance()
            .set(&LatchSmartAccountStorageKey::LastActiveLedger, &current_ledger);
        Ok(())
    }
}

#[contractimpl(contracttrait)]
impl SmartAccount for LatchSmartAccount {}

#[contractimpl]
impl ExecutionEntryPoint for LatchSmartAccount {
    fn execute(e: &Env, target: Address, target_fn: Symbol, target_args: Vec<Val>) {
        pausable::when_not_paused(e);
        e.current_contract_address().require_auth();
        acquire_reentrancy_lock(e);
        e.invoke_contract::<Val>(&target, &target_fn, target_args);
        release_reentrancy_lock(e);
    }
}

#[contractimpl(contracttrait)]
impl Pausable for LatchSmartAccount {
    /// Emergency pause — strictly restricted to self-authorization by this
    /// smart account (`caller == e.current_contract_address()`).
    fn pause(e: &Env, caller: Address) {
        let account = e.current_contract_address();
        if caller != account {
            panic_with_error!(e, LatchSmartAccountError::UnauthorizedPauseCaller);
        }
        account.require_auth();
        pausable::pause(e);
    }

    /// Lifts emergency pause — strictly restricted to self-authorization by
    /// this smart account (`caller == e.current_contract_address()`).
    fn unpause(e: &Env, caller: Address) {
        let account = e.current_contract_address();
        if caller != account {
            panic_with_error!(e, LatchSmartAccountError::UnauthorizedPauseCaller);
        }
        account.require_auth();
        pausable::unpause(e);
    }
}

#[contractimpl]
impl Upgradeable for LatchSmartAccount {
    fn upgrade(e: &Env, new_wasm_hash: BytesN<32>, _operator: Address) {
        if e.storage().instance().has(&LatchSmartAccountStorageKey::UpgradeLock) {
            panic_with_error!(e, LatchSmartAccountError::ReentrancyGuardTriggered);
        }
        e.storage().instance().set(&LatchSmartAccountStorageKey::UpgradeLock, &true);

        e.current_contract_address().require_auth();
        upgradeable::upgrade(e, &new_wasm_hash);
        Self::verify_state_migration(e);

        e.storage().instance().remove(&LatchSmartAccountStorageKey::UpgradeLock);
    }
}

#[cfg(all(test, feature = "bench"))]
mod bench;

#[cfg(test)]
mod test;
