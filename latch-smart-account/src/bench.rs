//! Instruction-count benchmarks for `__check_auth` scaling with signer count.
//!
//! Gated behind `#[cfg(feature = "bench")]` so normal `cargo test` runs are
//! unaffected. Run with:
//!
//! ```bash
//! cd latch-smart-account
//! cargo test --features bench bench_ -- --nocapture
//! ```
//!
//! Each benchmark sets up a smart account with N `Signer::Delegated` signers
//! on the `Default` context rule, then calls `do_check_auth` with all N
//! signers present and samples `env.budget().cpu_insns_consumed()` and
//! `env.budget().mem_bytes_consumed()` after the call. The results are
//! printed as a formatted table so you can copy them directly into
//! `docs/BENCHMARKS.md`.

extern crate std;

use soroban_sdk::{
    testutils::Budget,
    Bytes, Env, Map, String, Val, Vec,
};
use stellar_accounts::smart_account::{
    self as smart_account, AuthPayload, ContextRuleType, Signer,
};

use crate::{LatchSmartAccount};

fn register_account_with_n_signers(env: &Env, n: usize) -> (soroban_sdk::Address, Vec<Signer>) {
    let mut signers: Vec<Signer> = Vec::new(env);
    for _ in 0..n {
        signers.push_back(Signer::Delegated(soroban_sdk::Address::generate(env)));
    }
    let policies: Map<soroban_sdk::Address, Val> = Map::new(env);
    let account_id = env.register(LatchSmartAccount, (signers.clone(), policies));
    (account_id, signers)
}

fn create_auth_payload(env: &Env, signers: &Vec<Signer>) -> AuthPayload {
    let mut sig_map: Map<Signer, Bytes> = Map::new(env);
    for s in signers.iter() {
        sig_map.set(s, Bytes::new(env));
    }
    AuthPayload { signers: sig_map, context_rule_ids: Vec::from_array(env, [0u32]) }
}

fn bench_n_signers(env: &Env, n: usize) -> (u64, u64) {
    let (account_id, signers) = register_account_with_n_signers(env, n);
    let signatures = create_auth_payload(env, &signers);
    let auth_contexts: Vec<soroban_sdk::auth::Context> = Vec::new(env);
    let payload_hash = env.crypto().sha256(&Bytes::from_array(env, &[1u8; 32]));

    env.budget().reset_default();
    env.as_contract(&account_id, || {
        let _ = smart_account::do_check_auth(env, &payload_hash, &signatures, &auth_contexts);
    });

    (env.budget().cpu_insns_consumed(), env.budget().mem_bytes_consumed())
}

#[test]
fn bench_signer_scaling_1_to_20() {
    let env = Env::default();
    env.mock_all_auths();

    std::println!(
        "\n{:<12} {:>18} {:>16} {:>18}",
        "Signers (N)", "CPU Instructions", "Memory (bytes)", "CPU Δ per signer"
    );
    std::println!("{}", "-".repeat(68));

    let counts: &[usize] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 15, 20];
    let mut prev_cpu: u64 = 0;

    for &n in counts {
        let (cpu, mem) = bench_n_signers(&env, n);
        let delta = if n == 1 {
            "—               ".to_string()
        } else {
            std::format!("{:>+16}", cpu as i64 - prev_cpu as i64)
        };
        std::println!("{:<12} {:>18} {:>16} {:>18}", n, cpu, mem, delta);
        prev_cpu = cpu;
    }
}
