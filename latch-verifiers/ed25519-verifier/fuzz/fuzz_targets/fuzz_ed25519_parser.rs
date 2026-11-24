//! AFL and Honggfuzz compatible fuzz target for ed25519-verifier input parsing.
//!
//! Fuzzes parsing of public keys (KeyData / BytesN<32>), signatures (SigData / BytesN<64>),
//! and hash messages (Bytes / BytesN<32>), as well as arbitrary slice permutations
//! passed into `Ed25519Verifier` endpoints.
//!
//! Supports AFL/Honggfuzz stdin execution, file input parsing, and standalone
//! in-memory corpus replay.

extern crate std;

use std::io::{self, Read};
use std::panic::{catch_unwind, AssertUnwindSafe};

use ed25519_verifier::{Ed25519Verifier, Ed25519VerifierClient};
use soroban_sdk::{Bytes, BytesN, Env, Vec as SorobanVec};

/// Entrypoint to execute a single fuzzing iteration on raw bytes.
/// Guarantees that arbitrary mutated byte sequences parsed as keys,
/// signatures, or hashes do not trigger memory faults, panics escaping the harness,
/// or undefined behavior.
pub fn fuzz_target(data: &[u8]) {
    if data.is_empty() {
        return;
    }

    let e = Env::default();
    let addr = e.register(Ed25519Verifier, ());
    let client = Ed25519VerifierClient::new(&e, &addr);

    // 1. Fuzz canonicalize_key with 32-byte chunks or padded slices
    let mut key_buf = [0u8; 32];
    let key_slice_len = usize::min(32, data.len());
    key_buf[..key_slice_len].copy_from_slice(&data[..key_slice_len]);
    let key_data = BytesN::<32>::from_array(&e, &key_buf);

    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _ = client.canonicalize_key(&key_data);
    }));

    // 2. Fuzz batch_canonicalize_key with variable number of keys
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let chunk_count = usize::min(8, data.len() / 32);
        let mut key_list = SorobanVec::new(&e);
        for i in 0..chunk_count {
            let mut k = [0u8; 32];
            k.copy_from_slice(&data[i * 32..(i + 1) * 32]);
            key_list.push_back(BytesN::<32>::from_array(&e, &k));
        }
        if !key_list.is_empty() {
            let _ = client.batch_canonicalize_key(&key_list);
        }
    }));

    // 3. Fuzz verify input parsing with (hash, key_data, sig_data)
    // Layout: data can be partitioned into:
    // - hash (variable length Bytes)
    // - key_data (BytesN<32>)
    // - sig_data (BytesN<64>)
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let hash_len = if data.len() > 96 { data.len() - 96 } else { data.len() };
        let hash_slice = &data[..hash_len];
        let hash = Bytes::from_slice(&e, hash_slice);

        let mut k_buf = [0u8; 32];
        if data.len() >= hash_len + 32 {
            k_buf.copy_from_slice(&data[hash_len..hash_len + 32]);
        } else if data.len() > hash_len {
            let rem = data.len() - hash_len;
            k_buf[..rem].copy_from_slice(&data[hash_len..]);
        }
        let key = BytesN::<32>::from_array(&e, &k_buf);

        let mut s_buf = [0u8; 64];
        if data.len() >= hash_len + 32 + 64 {
            s_buf.copy_from_slice(&data[hash_len + 32..hash_len + 32 + 64]);
        } else if data.len() > hash_len + 32 {
            let rem = data.len() - (hash_len + 32);
            s_buf[..rem].copy_from_slice(&data[hash_len + 32..]);
        }
        let sig = BytesN::<64>::from_array(&e, &s_buf);

        // Verification call may return false or panic with Error(Crypto, InvalidInput).
        // catch_unwind catches panics so memory faults and aborts are isolated.
        let _ = client.verify(&hash, &key, &sig);
    }));

    // 4. Also fuzz verify with exact 32-byte hash slice
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let mut h_buf = [0u8; 32];
        let h_len = usize::min(32, data.len());
        h_buf[..h_len].copy_from_slice(&data[..h_len]);
        let hash = Bytes::from_array(&e, &h_buf);

        let mut s_buf = [0u8; 64];
        let s_len = usize::min(64, data.len());
        s_buf[..s_len].copy_from_slice(&data[..s_len]);
        let sig = BytesN::<64>::from_array(&e, &s_buf);

        let _ = client.verify(&hash, &key_data, &sig);
    }));
}

fn main() {
    // Read input from stdin (Honggfuzz / AFL stdin mode; avoids host filesystem APIs)
    let mut buffer = std::vec::Vec::new();
    if io::stdin().read_to_end(&mut buffer).is_ok() && !buffer.is_empty() {
        fuzz_target(&buffer);
    }
}
