//! # Recipient Allowlist Policy Module
//!
//! This policy restricts a context rule's signers to a fixed set of
//! recipient addresses. It is designed to be attached to a `CallContract`
//! context rule, where it intercepts `transfer(from, to, amount)` calls
//! and ensures the `to` address (the recipient) is in the allowlist.
//!
//! # Address sanitization
//!
//! Allowlists are configured through [`RecipientAllowlistPolicy::install`] and
//! [`RecipientAllowlistPolicy::set_allowed_recipients`], both of which sanitize
//! every address *before* it is written to storage: each entry is rendered back
//! to its Stellar strkey form and must be a canonical, checksummed 56-character
//! account (`G...`) or contract (`C...`) identifier. Anything else — a
//! truncated or padded strkey, a non-base32 character, a muxed (`M...`),
//! claimable-balance (`B...`) or liquidity-pool (`L...`) identifier, or a
//! strkey whose CRC16 checksum does not verify — is rejected at configuration
//! time with [`RecipientError::InvalidRecipientAddress`], so a malformed
//! recipient can never end up in the stored allowlist.
#![no_std]

use soroban_sdk::{
    auth::{Context, ContractContext},
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, Address,
    Env, Symbol, TryFromVal, Vec,
};
use stellar_accounts::{
    policies::Policy,
    smart_account::{ContextRule, ContextRuleType, Signer},
};

/// Event emitted when a recipient policy is enforced.
#[contractevent]
#[derive(Clone)]
pub struct RecipientEnforced {
    #[topic]
    pub smart_account: Address,
    pub context_rule_id: u32,
    pub recipient: Address,
}

/// Event emitted when a recipient policy is installed.
#[contractevent]
#[derive(Clone, Debug)]
pub struct RecipientInstalled {
    #[topic]
    pub smart_account: Address,
    pub context_rule_id: u32,
    pub allowed_recipients: Vec<Address>,
}

/// Event emitted when a recipient policy is uninstalled.
#[contractevent]
#[derive(Clone, Debug)]
pub struct RecipientUninstalled {
    #[topic]
    pub smart_account: Address,
    pub context_rule_id: u32,
}

/// Installation parameters for the recipient allowlist policy.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RecipientAccountParams {
    /// The recipient addresses that this policy is permitted to transfer to.
    pub allowed_recipients: Vec<Address>,
}

/// Internal storage structure for the recipient allowlist.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct RecipientData {
    /// The recipient addresses that this policy is permitted to transfer to.
    pub allowed_recipients: Vec<Address>,
}

/// Error codes for recipient allowlist policy operations.
///
/// This is a standalone, independently-deployed contract, not a module of
/// the upstream `stellar-accounts` crate, so it is not part of that crate's
/// shared error-numbering convention (see its `CLAUDE.md`). Numbering starts
/// fresh at `1`.
#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum RecipientError {
    /// The smart account does not have a recipient policy installed for this
    /// context rule.
    SmartAccountNotInstalled = 1,
    /// Only the `CallContract` context rule type is allowed.
    OnlyCallContractAllowed = 2,
    /// `allowed_recipients` was empty or exceeded `MAX_ALLOWED_RECIPIENTS`.
    InvalidAllowedRecipients = 3,
    /// The context is not a `Context::Contract` invocation for `transfer`,
    /// or the recipient address is not in the allowlist.
    RecipientNotAllowed = 4,
    /// The policy was already installed for this smart account and context
    /// rule.
    AlreadyInstalled = 5,
    /// The call arguments could not be parsed to extract a recipient.
    InvalidTransferArgs = 6,
    /// An allowlist entry is not a canonical, checksummed account (`G...`)
    /// or contract (`C...`) strkey, so it cannot be used as a recipient.
    InvalidRecipientAddress = 7,
}

/// Storage keys for recipient policy data.
#[contracttype]
pub enum RecipientStorageKey {
    /// Storage key for the allowlist of a smart account context rule.
    AccountContext(Address, u32),
}

// ################## CONSTANTS ##################

const DAY_IN_LEDGERS: u32 = 17280;
pub const RECIPIENT_EXTEND_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
pub const RECIPIENT_TTL_THRESHOLD: u32 = RECIPIENT_EXTEND_AMOUNT - DAY_IN_LEDGERS;

/// Maximum number of allowed recipients per policy.
/// Bounds the linear scan performed in `enforce` and the storage size.
pub const MAX_ALLOWED_RECIPIENTS: u32 = 10;

// ################## ADDRESS VALIDATION ##################

/// Encoded length, in base32 characters, of an account (`G...`) or contract
/// (`C...`) strkey: 1 version byte + 32 payload bytes + 2 checksum bytes =
/// 35 raw bytes, which base32-encodes (unpadded) to exactly 56 characters.
const STRKEY_ENCODED_LEN: usize = 56;

/// Raw length of a decoded strkey: version byte, 32-byte payload and the
/// 2-byte checksum.
const STRKEY_DECODED_LEN: usize = 35;

/// Number of leading bytes covered by the strkey checksum (version byte plus
/// the 32-byte payload).
const STRKEY_CHECKSUMMED_LEN: usize = 33;

/// RFC 4648 base32 alphabet used by Stellar strkeys.
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// CRC16-XModem (polynomial `0x1021`, initial value `0x0000`) — the checksum
/// Stellar appends to every strkey.
fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// Decodes RFC 4648 base32 into `out`. Returns `false` when `encoded`
/// contains a character outside the alphabet, or when it does not decode to
/// exactly `out.len()` bytes with no leftover bits.
fn decode_base32(encoded: &[u8], out: &mut [u8]) -> bool {
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut written: usize = 0;

    for &ch in encoded {
        let Some(value) = BASE32_ALPHABET.iter().position(|&c| c == ch) else {
            return false;
        };
        buffer = (buffer << 5) | value as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if written >= out.len() {
                return false;
            }
            out[written] = ((buffer >> bits) & 0xff) as u8;
            written += 1;
            buffer &= (1 << bits) - 1;
        }
    }

    written == out.len() && bits == 0 && buffer == 0
}

/// Returns `true` when `encoded` is a canonical, checksummed account
/// (`G...`) or contract (`C...`) strkey.
fn is_valid_address_strkey(encoded: &[u8]) -> bool {
    if encoded.len() != STRKEY_ENCODED_LEN {
        return false;
    }

    // Only account (`G`, version byte `0x30`) and contract (`C`, version byte
    // `0x10`) identifiers are valid recipients; muxed (`M`), claimable
    // balance (`B`), liquidity pool (`L`) and every other identifier are not
    // plain account/contract ids and are rejected up front.
    if encoded[0] != b'G' && encoded[0] != b'C' {
        return false;
    }

    let mut decoded = [0u8; STRKEY_DECODED_LEN];
    if !decode_base32(encoded, &mut decoded) {
        return false;
    }

    // The version byte must be the canonical zero-padded form of the `G`/`C`
    // prefix: the low three bits come from the second base32 character and
    // have to be zero for a well-formed strkey.
    if decoded[0] & 0x07 != 0 {
        return false;
    }

    let checksum = crc16_xmodem(&decoded[..STRKEY_CHECKSUMMED_LEN]);
    // Stellar stores the checksum little-endian, low byte first.
    decoded[STRKEY_CHECKSUMMED_LEN] == (checksum & 0xff) as u8
        && decoded[STRKEY_CHECKSUMMED_LEN + 1] == (checksum >> 8) as u8
}

/// Sanitizes a single allowlist entry by rendering it back to its strkey
/// form and requiring a canonical, checksummed account or contract
/// identifier. Runs at configuration time, so a malformed address never
/// reaches storage.
fn validate_recipient_address(address: &Address) -> Result<(), RecipientError> {
    let encoded = address.to_string().to_bytes();
    if encoded.len() as usize != STRKEY_ENCODED_LEN {
        return Err(RecipientError::InvalidRecipientAddress);
    }

    let mut buf = [0u8; STRKEY_ENCODED_LEN];
    encoded.copy_into_slice(&mut buf);

    if is_valid_address_strkey(&buf) {
        Ok(())
    } else {
        Err(RecipientError::InvalidRecipientAddress)
    }
}

/// Sanitizes a whole allowlist, failing with
/// [`RecipientError::InvalidRecipientAddress`] on the first malformed entry.
fn validate_allowed_recipients(e: &Env, recipients: &Vec<Address>) {
    for recipient in recipients.iter() {
        validate_recipient_address(&recipient)
            .unwrap_or_else(|_| panic_with_error!(e, RecipientError::InvalidRecipientAddress));
    }
}

// ################## HELPER ##################
fn emit_recipient_enforced(
    e: &Env,
    smart_account: &Address,
    context_rule_id: u32,
    recipient: &Address,
) {
    RecipientEnforced {
        smart_account: smart_account.clone(),
        context_rule_id,
        recipient: recipient.clone(),
    }
    .publish(e);
}

fn emit_recipient_installed(
    e: &Env,
    smart_account: &Address,
    context_rule_id: u32,
    allowed_recipients: &Vec<Address>,
) {
    RecipientInstalled {
        smart_account: smart_account.clone(),
        context_rule_id,
        allowed_recipients: allowed_recipients.clone(),
    }
    .publish(e);
}

fn emit_recipient_uninstalled(e: &Env, smart_account: &Address, context_rule_id: u32) {
    RecipientUninstalled { smart_account: smart_account.clone(), context_rule_id }.publish(e);
}

#[contract]
pub struct RecipientAllowlistPolicy;

#[contractimpl]
impl Policy for RecipientAllowlistPolicy {
    type AccountParams = RecipientAccountParams;

    /// Enforces the recipient policy: the context must be a `Context::Contract`
    /// invocation of a function named "transfer", and the recipient (2nd
    /// argument) must be in the installed allowlist. Requires authorization
    /// from the smart account.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `context` - The authorization context.
    /// * `authenticated_signers` - The list of authenticated signers.
    /// * `context_rule` - The context rule for this policy.
    /// * `smart_account` - The address of the smart account.
    ///
    /// # Errors
    ///
    /// * [`RecipientError::RecipientNotAllowed`] - When there are no
    ///   authenticated signers, the context is not a `Context::Contract`
    ///   invocation for `transfer`, or the recipient is not in the allowlist.
    /// * [`RecipientError::InvalidTransferArgs`] - When the arguments are
    ///   malformed.
    /// * refer to [`get_allowed_recipients`] errors.
    ///
    /// # Events
    ///
    /// * topics - `["recipient_enforced", smart_account: Address]`
    /// * data - `[context_rule_id: u32, recipient: Address]`
    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        // Require authorization from the smart_account
        smart_account.require_auth();

        if authenticated_signers.is_empty() {
            panic_with_error!(e, RecipientError::RecipientNotAllowed)
        }

        let allowed_recipients =
            Self::get_allowed_recipients(e, context_rule.id, smart_account.clone());

        match context {
            Context::Contract(ContractContext { fn_name, args, .. }) => {
                if fn_name != Symbol::new(e, "transfer") {
                    panic_with_error!(e, RecipientError::RecipientNotAllowed)
                }

                // A standard SEP-41 `transfer` is `transfer(from, to, amount)`.
                // The recipient is the second argument (index 1).
                let to_val = args
                    .get(1)
                    .unwrap_or_else(|| panic_with_error!(e, RecipientError::InvalidTransferArgs));
                let Ok(recipient) = Address::try_from_val(e, &to_val) else {
                    panic_with_error!(e, RecipientError::InvalidTransferArgs)
                };

                if !allowed_recipients.contains(recipient.clone()) {
                    panic_with_error!(e, RecipientError::RecipientNotAllowed)
                }

                emit_recipient_enforced(e, &smart_account, context_rule.id, &recipient);
            }
            _ => panic_with_error!(e, RecipientError::RecipientNotAllowed),
        }
    }

    /// Installs the recipient policy on a smart account. Only `CallContract`
    /// context type is allowed, since the allowlisted recipients are only
    /// meaningful when pinned to one target contract. Requires authorization
    /// from the smart account.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `params` - Installation parameters containing the allowed recipients.
    /// * `context_rule` - The context rule for this policy.
    /// * `smart_account` - The address of the smart account.
    ///
    /// # Errors
    ///
    /// * [`RecipientError::OnlyCallContractAllowed`] - When the context rule
    ///   type is not `CallContract`.
    /// * [`RecipientError::InvalidAllowedRecipients`] - When
    ///   `allowed_recipients` is empty or exceeds `MAX_ALLOWED_RECIPIENTS`.
    /// * [`RecipientError::InvalidRecipientAddress`] - When an entry is not a
    ///   canonical, checksummed account or contract strkey.
    /// * [`RecipientError::AlreadyInstalled`] - When the policy was already
    ///   installed for this smart account and context rule.
    ///
    /// # Events
    ///
    /// * topics - `["recipient_installed", smart_account: Address]`
    /// * data - `[context_rule_id: u32, allowed_recipients: Vec<Address>]`
    fn install(
        e: &Env,
        params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        // Require authorization from the smart_account
        smart_account.require_auth();

        if !matches!(context_rule.context_type, ContextRuleType::CallContract(_)) {
            panic_with_error!(e, RecipientError::OnlyCallContractAllowed)
        }

        if params.allowed_recipients.is_empty()
            || params.allowed_recipients.len() > MAX_ALLOWED_RECIPIENTS
        {
            panic_with_error!(e, RecipientError::InvalidAllowedRecipients)
        }

        // Sanitize every entry before it is written to storage, so a
        // malformed address is rejected at configuration time.
        validate_allowed_recipients(e, &params.allowed_recipients);

        let key = RecipientStorageKey::AccountContext(smart_account.clone(), context_rule.id);

        if e.storage().persistent().has(&key) {
            panic_with_error!(e, RecipientError::AlreadyInstalled)
        }

        let data = RecipientData { allowed_recipients: params.allowed_recipients.clone() };

        e.storage().persistent().set(&key, &data);

        emit_recipient_installed(e, &smart_account, context_rule.id, &params.allowed_recipients);
    }

    /// Uninstalls the recipient policy from a smart account, removing all
    /// stored allowlist data for the account and context rule. Requires
    /// authorization from the smart account.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `context_rule` - The context rule for this policy.
    /// * `smart_account` - The address of the smart account.
    ///
    /// # Errors
    ///
    /// * [`RecipientError::SmartAccountNotInstalled`] - When the policy is not
    ///   installed for the given smart account and context rule.
    ///
    /// # Events
    ///
    /// * topics - `["recipient_uninstalled", smart_account: Address]`
    /// * data - `[context_rule_id: u32]`
    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        // Require authorization from the smart_account
        smart_account.require_auth();

        let key = RecipientStorageKey::AccountContext(smart_account.clone(), context_rule.id);

        if !e.storage().persistent().has(&key) {
            panic_with_error!(e, RecipientError::SmartAccountNotInstalled)
        }

        e.storage().persistent().remove(&key);

        emit_recipient_uninstalled(e, &smart_account, context_rule.id);
    }
}

// ################## QUERY & MUTATION ##################

#[contractimpl]
impl RecipientAllowlistPolicy {
    /// Retrieves the allowlist for a smart account's recipient policy.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `context_rule_id` - The context rule ID for this policy.
    /// * `smart_account` - The address of the smart account.
    ///
    /// # Errors
    ///
    /// * [`RecipientError::SmartAccountNotInstalled`] - When the smart account
    ///   does not have a recipient policy installed.
    pub fn get_allowed_recipients(
        e: &Env,
        context_rule_id: u32,
        smart_account: Address,
    ) -> Vec<Address> {
        let key = RecipientStorageKey::AccountContext(smart_account, context_rule_id);
        e.storage()
            .persistent()
            .get::<_, RecipientData>(&key)
            .inspect(|_| {
                e.storage().persistent().extend_ttl(
                    &key,
                    RECIPIENT_TTL_THRESHOLD,
                    RECIPIENT_EXTEND_AMOUNT,
                );
            })
            .map(|data| data.allowed_recipients)
            .unwrap_or_else(|| panic_with_error!(e, RecipientError::SmartAccountNotInstalled))
    }

    /// Updates the allowlist for a smart account's recipient policy.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `allowed_recipients` - The new list of allowed recipients.
    /// * `context_rule_id` - The context rule ID for this policy.
    /// * `smart_account` - The address of the smart account.
    ///
    /// # Errors
    ///
    /// * [`RecipientError::SmartAccountNotInstalled`] - When the policy is not
    ///   installed for the given smart account and context rule.
    /// * [`RecipientError::InvalidAllowedRecipients`] - When
    ///   `allowed_recipients` is empty or exceeds `MAX_ALLOWED_RECIPIENTS`.
    /// * [`RecipientError::InvalidRecipientAddress`] - When an entry is not a
    ///   canonical, checksummed account or contract strkey.
    pub fn set_allowed_recipients(
        e: Env,
        allowed_recipients: Vec<Address>,
        context_rule_id: u32,
        smart_account: Address,
    ) {
        smart_account.require_auth();

        if allowed_recipients.is_empty() || allowed_recipients.len() > MAX_ALLOWED_RECIPIENTS {
            panic_with_error!(&e, RecipientError::InvalidAllowedRecipients)
        }

        // Same sanitization as `install`: a malformed address is rejected
        // before anything is written to storage.
        validate_allowed_recipients(&e, &allowed_recipients);

        let key = RecipientStorageKey::AccountContext(smart_account.clone(), context_rule_id);

        if !e.storage().persistent().has(&key) {
            panic_with_error!(&e, RecipientError::SmartAccountNotInstalled)
        }

        let data = RecipientData { allowed_recipients: allowed_recipients.clone() };

        e.storage().persistent().set(&key, &data);
    }
}

#[cfg(test)]
mod test;
