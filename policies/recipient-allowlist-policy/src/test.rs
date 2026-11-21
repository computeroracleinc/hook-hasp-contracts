#![cfg(test)]
extern crate std;

use soroban_sdk::{
    auth::{Context, ContractContext},
    testutils::Address as _,
    vec, Address, Env, IntoVal, Symbol, Val, Vec,
};
use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

use crate::{
    is_valid_address_strkey, RecipientAccountParams, RecipientAllowlistPolicy,
    RecipientAllowlistPolicyClient, MAX_ALLOWED_RECIPIENTS,
};

/// A real contract identifier recorded in `deployments/`; its checksum is
/// exactly what the strkey decoder has to verify.
const CONTRACT_STRKEY: &[u8; 56] = b"CABX7KCI2S6QH3SG6TBFG3XUKNBWIBPDVRXSECJSRRZQQUYXNVVKO44L";

/// A real account identifier recorded in `deployments/`.
const ACCOUNT_STRKEY: &[u8; 56] = b"GCOWPY2RHD6Y764NAEIB2SMJITDJLAJ7X4WVAQWQQKQTPRNRQKMT2W5K";

fn strkey_bytes(address: &Address) -> [u8; 56] {
    let encoded = address.to_string().to_bytes();
    assert_eq!(encoded.len(), 56);
    let mut buf = [0u8; 56];
    encoded.copy_into_slice(&mut buf);
    buf
}

fn create_context_rule(e: &Env) -> ContextRule {
    let signer = Address::generate(e);
    let mut signers = Vec::new(e);
    signers.push_back(Signer::Delegated(signer));

    ContextRule {
        id: 1,
        context_type: ContextRuleType::CallContract(Address::generate(e)),
        name: soroban_sdk::String::from_str(e, "session"),
        signers,
        signer_ids: Vec::new(e),
        policies: Vec::new(e),
        policy_ids: Vec::new(e),
        valid_until: None,
    }
}

fn setup_env<'a>() -> (Env, Address, RecipientAllowlistPolicyClient<'a>) {
    let e = Env::default();
    e.mock_all_auths();

    let smart_account = Address::generate(&e);
    let contract_id = e.register(RecipientAllowlistPolicy, ());
    let client = RecipientAllowlistPolicyClient::new(&e, &contract_id);

    (e, smart_account, client)
}

#[test]
fn test_install_and_get() {
    let (e, smart_account, client) = setup_env();

    let rule = create_context_rule(&e);

    let recipient1 = Address::generate(&e);
    let recipient2 = Address::generate(&e);
    let allowed_recipients = vec![&e, recipient1.clone(), recipient2.clone()];

    client.install(
        &RecipientAccountParams { allowed_recipients: allowed_recipients.clone() },
        &rule,
        &smart_account,
    );

    assert_eq!(client.get_allowed_recipients(&rule.id, &smart_account), allowed_recipients);
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")] // OnlyCallContractAllowed
fn test_install_rejects_non_call_contract() {
    let (e, smart_account, client) = setup_env();

    let mut rule = create_context_rule(&e);
    rule.context_type = ContextRuleType::Default;

    let allowed_recipients = vec![&e, Address::generate(&e)];

    client.install(&RecipientAccountParams { allowed_recipients }, &rule, &smart_account);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")] // InvalidAllowedRecipients
fn test_install_rejects_empty_allowlist() {
    let (e, smart_account, client) = setup_env();

    let rule = create_context_rule(&e);

    client.install(&RecipientAccountParams { allowed_recipients: vec![&e] }, &rule, &smart_account);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")] // InvalidAllowedRecipients
fn test_install_rejects_too_large_allowlist() {
    let (e, smart_account, client) = setup_env();

    let rule = create_context_rule(&e);

    let mut allowed_recipients = vec![&e];
    for _ in 0..(MAX_ALLOWED_RECIPIENTS + 1) {
        allowed_recipients.push_back(Address::generate(&e));
    }

    client.install(&RecipientAccountParams { allowed_recipients }, &rule, &smart_account);
}

#[test]
fn test_enforce_accepts_allowlisted() {
    let (e, smart_account, client) = setup_env();

    let contract_target = Address::generate(&e);
    let mut rule = create_context_rule(&e);
    rule.context_type = ContextRuleType::CallContract(contract_target.clone());

    let recipient = Address::generate(&e);
    let allowed_recipients = vec![&e, recipient.clone()];

    client.install(&RecipientAccountParams { allowed_recipients }, &rule, &smart_account);

    let args: Vec<Val> =
        vec![&e, smart_account.into_val(&e), recipient.into_val(&e), 100i128.into_val(&e)];
    let context = Context::Contract(ContractContext {
        contract: contract_target,
        fn_name: Symbol::new(&e, "transfer"),
        args,
    });

    client.enforce(&context, &rule.signers, &rule, &smart_account);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")] // RecipientNotAllowed
fn test_enforce_rejects_non_allowlisted() {
    let (e, smart_account, client) = setup_env();

    let contract_target = Address::generate(&e);
    let mut rule = create_context_rule(&e);
    rule.context_type = ContextRuleType::CallContract(contract_target.clone());

    let allowed_recipients = vec![&e, Address::generate(&e)];
    client.install(&RecipientAccountParams { allowed_recipients }, &rule, &smart_account);

    let unapproved_recipient = Address::generate(&e);
    let args: Vec<Val> = vec![
        &e,
        smart_account.into_val(&e),
        unapproved_recipient.into_val(&e),
        100i128.into_val(&e),
    ];
    let context = Context::Contract(ContractContext {
        contract: contract_target,
        fn_name: Symbol::new(&e, "transfer"),
        args,
    });

    client.enforce(&context, &rule.signers, &rule, &smart_account);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")] // RecipientNotAllowed
fn test_enforce_rejects_non_transfer() {
    let (e, smart_account, client) = setup_env();

    let contract_target = Address::generate(&e);
    let mut rule = create_context_rule(&e);
    rule.context_type = ContextRuleType::CallContract(contract_target.clone());

    let recipient = Address::generate(&e);
    let allowed_recipients = vec![&e, recipient.clone()];
    client.install(&RecipientAccountParams { allowed_recipients }, &rule, &smart_account);

    let args: Vec<Val> =
        vec![&e, smart_account.into_val(&e), recipient.into_val(&e), 100i128.into_val(&e)];
    let context = Context::Contract(ContractContext {
        contract: contract_target,
        fn_name: Symbol::new(&e, "mint"),
        args,
    });

    client.enforce(&context, &rule.signers, &rule, &smart_account);
}

#[test]
fn test_uninstall_clears_state() {
    let (e, smart_account, client) = setup_env();

    let rule = create_context_rule(&e);

    let allowed_recipients = vec![&e, Address::generate(&e)];
    client.install(&RecipientAccountParams { allowed_recipients }, &rule, &smart_account);

    client.uninstall(&rule, &smart_account);

    let res = client.try_get_allowed_recipients(&rule.id, &smart_account);
    assert!(res.is_err());
}

// ==========================================
// ADDRESS SANITIZATION / CHECKSUMS
// ==========================================

#[test]
fn test_strkey_validation_accepts_contract_and_account_ids() {
    assert!(is_valid_address_strkey(CONTRACT_STRKEY));
    assert!(is_valid_address_strkey(ACCOUNT_STRKEY));
}

#[test]
fn test_strkey_validation_accepts_live_addresses() {
    let e = Env::default();

    for _ in 0..4 {
        assert!(is_valid_address_strkey(&strkey_bytes(&Address::generate(&e))));
    }

    let account = Address::from_str(&e, std::str::from_utf8(ACCOUNT_STRKEY).unwrap());
    assert!(is_valid_address_strkey(&strkey_bytes(&account)));
}

#[test]
fn test_strkey_validation_rejects_bad_checksum() {
    let mut corrupted = *CONTRACT_STRKEY;
    corrupted[55] = if corrupted[55] == b'A' { b'B' } else { b'A' };
    assert!(!is_valid_address_strkey(&corrupted));
}

#[test]
fn test_strkey_validation_rejects_tampered_payload() {
    let mut tampered = *ACCOUNT_STRKEY;
    tampered[20] = if tampered[20] == b'Q' { b'R' } else { b'Q' };
    assert!(!is_valid_address_strkey(&tampered));
}

#[test]
fn test_strkey_validation_rejects_wrong_prefix() {
    // `M...` (muxed account) is not a plain account or contract identifier.
    let mut muxed = *ACCOUNT_STRKEY;
    muxed[0] = b'M';
    assert!(!is_valid_address_strkey(&muxed));

    let mut contract = *CONTRACT_STRKEY;
    contract[0] = b'A';
    assert!(!is_valid_address_strkey(&contract));
}

#[test]
fn test_strkey_validation_rejects_bad_length() {
    let mut short: std::vec::Vec<u8> = CONTRACT_STRKEY.to_vec();
    short.pop();
    assert!(!is_valid_address_strkey(&short));

    let mut long: std::vec::Vec<u8> = CONTRACT_STRKEY.to_vec();
    long.push(b'A');
    assert!(!is_valid_address_strkey(&long));

    assert!(!is_valid_address_strkey(b""));
}

#[test]
fn test_strkey_validation_rejects_non_base32_character() {
    let mut bad = *CONTRACT_STRKEY;
    bad[10] = b'1'; // `1` is not part of the RFC 4648 base32 alphabet
    assert!(!is_valid_address_strkey(&bad));
}

#[test]
fn test_strkey_validation_rejects_non_canonical_version_byte() {
    // The leading `C` survives, but the second character makes the decoded
    // version byte's low three bits non-zero, which no well-formed strkey
    // ever has.
    let mut bad = *CONTRACT_STRKEY;
    bad[1] = b'I';
    assert!(!is_valid_address_strkey(&bad));
}

#[test]
fn test_install_accepts_account_and_contract_recipients() {
    let (e, smart_account, client) = setup_env();

    let rule = create_context_rule(&e);
    let account_recipient = Address::from_str(&e, std::str::from_utf8(ACCOUNT_STRKEY).unwrap());
    let contract_recipient = Address::generate(&e);

    let allowed_recipients = vec![&e, account_recipient, contract_recipient];

    client.install(
        &RecipientAccountParams { allowed_recipients: allowed_recipients.clone() },
        &rule,
        &smart_account,
    );

    assert_eq!(client.get_allowed_recipients(&rule.id, &smart_account), allowed_recipients);
}
