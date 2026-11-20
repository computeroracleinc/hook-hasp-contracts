extern crate std;

use soroban_sdk::{contract, testutils::Address as _, vec, Address, Env};
use stellar_accounts::policies::{
    spending_limit,
    spending_limit::{SpendingLimitData, SpendingLimitStorageKey},
};

use crate::{
    decode_amount, encode_amount, load_data, CompactSpendingEntry, CompactStorageKey,
    CompactSpendingLimitData,
};

#[contract]
struct MockContract;

#[test]
fn compact_spending_entry_uses_fewer_bytes_and_preserves_large_amounts() {
    let e = Env::default();
    let amount = 123_456_789i128;

    let compact = CompactSpendingEntry {
        amount: encode_amount(&e, amount),
        ledger_sequence: 123_456,
    };
    let upstream = spending_limit::SpendingEntry {
        amount,
        ledger_sequence: 123_456,
    };

    assert!(compact.to_xdr(&e).len() < upstream.to_xdr(&e).len());
    assert_eq!(decode_amount(&e, &encode_amount(&e, i128::MAX)), i128::MAX);
}

#[test]
fn legacy_spending_state_is_migrated_to_the_compact_key() {
    let e = Env::default();
    let contract = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let legacy_key = SpendingLimitStorageKey::AccountContext(smart_account.clone(), 7);
    let compact_key = CompactStorageKey::AccountContext(smart_account.clone(), 7);
    let legacy_data = SpendingLimitData {
        spending_limit: 100,
        period_ledgers: 50,
        spending_history: vec![
            &e,
            spending_limit::SpendingEntry { amount: 42, ledger_sequence: 123 },
        ],
        cached_total_spent: 42,
    };

    e.as_contract(&contract, || {
        e.storage().persistent().set(&legacy_key, &legacy_data);
        assert_eq!(load_data(&e, 7, &smart_account), legacy_data);
        assert!(!e.storage().persistent().has(&legacy_key));
        assert!(e.storage().persistent().has(&compact_key));

        let compact =
            e.storage().persistent().get::<_, CompactSpendingLimitData>(&compact_key).unwrap();
        assert_eq!(decode_amount(&e, &compact.spending_history.get(0).unwrap().amount), 42);
    });
}
