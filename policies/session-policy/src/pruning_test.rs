extern crate std;

use soroban_sdk::{
    contract,
    testutils::{Address as _, Ledger as _},
    vec, Address, Env, String, Vec,
};
use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

use crate::{pruning::prune_expired_sessions, SessionData, SessionStorageKey};

#[contract]
struct MockContract;

fn context_rule(e: &Env, id: u32, valid_until: Option<u32>) -> ContextRule {
    ContextRule {
        id,
        context_type: ContextRuleType::CallContract(Address::generate(e)),
        name: String::from_str(e, "session"),
        signers: vec![e, Signer::Delegated(Address::generate(e))],
        signer_ids: Vec::new(e),
        policies: Vec::new(e),
        policy_ids: Vec::new(e),
        valid_until,
    }
}

#[test]
fn prune_removes_only_expired_entries_from_either_storage_tier() {
    let e = Env::default();
    e.mock_all_auths();
    let contract = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    e.ledger().with_mut(|li| li.sequence_number = 10);
    let expired = context_rule(&e, 1, Some(9));
    let active = context_rule(&e, 2, Some(11));
    let no_expiry = context_rule(&e, 3, None);

    e.as_contract(&contract, || {
        let expired_key =
            SessionStorageKey::AccountContext(smart_account.clone(), expired.id);
        let active_key = SessionStorageKey::AccountContext(smart_account.clone(), active.id);
        let no_expiry_key =
            SessionStorageKey::AccountContext(smart_account.clone(), no_expiry.id);
        let data = SessionData { allowed_fns: vec![&e, soroban_sdk::symbol_short!("set")] };

        e.storage().persistent().set(&expired_key, &data);
        e.storage().temporary().set(&active_key, &data);
        e.storage().temporary().set(&no_expiry_key, &data);

        let context_rules = vec![&e, expired, active.clone(), no_expiry.clone()];
        assert_eq!(prune_expired_sessions(&e, &context_rules, &smart_account), 1);
        assert!(!e.storage().persistent().has(&expired_key));
        assert!(e.storage().temporary().has(&active_key));
        assert!(e.storage().temporary().has(&no_expiry_key));
    });
}
