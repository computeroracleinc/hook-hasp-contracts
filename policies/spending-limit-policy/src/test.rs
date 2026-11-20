extern crate std;

use soroban_sdk::{xdr::ToXdr, Env};
use stellar_accounts::policies::spending_limit;

use crate::{decode_amount, encode_amount, CompactSpendingEntry};

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
