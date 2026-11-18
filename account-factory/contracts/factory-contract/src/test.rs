#![cfg(test)]

extern crate std;

use soroban_sdk::{
    testutils::{Address as _, Events as _},
    Address, Bytes, BytesN, Env,
};

use super::*;

// ---------------------------------------------------------------------------
// Embed compiled dummy wasm so deploy_v2 can instantiate real contracts.
// To regenerate after changing dummy contracts:
//   stellar contract build --package dummy-account
//   stellar contract build --package dummy-singleton
//   cp target/wasm32v1-none/release/dummy_{account,singleton}.wasm \
//      contracts/factory-contract/testdata/
// ---------------------------------------------------------------------------
mod dummy_account {
    soroban_sdk::contractimport!(file = "testdata/dummy_account.wasm");
}

mod dummy_singleton {
    soroban_sdk::contractimport!(file = "testdata/dummy_singleton.wasm");
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Full factory setup with real wasm for create_account tests.
/// Returns the client and the pre-deployed singleton addresses so tests
/// can assert against them directly.
struct FactorySetup<'a> {
    client: ContractClient<'a>,
    ed25519_verifier: Address,
    webauthn_verifier: Address,
    threshold_policy: Address,
}

fn install_factory(env: &Env) -> FactorySetup<'_> {
    let account_hash = env.deployer().upload_contract_wasm(dummy_account::WASM);

    let ed25519_verifier = env.register(dummy_singleton::WASM, ());
    let webauthn_verifier = env.register(dummy_singleton::WASM, ());
    let threshold_policy = env.register(dummy_singleton::WASM, ());

    let contract_id = env.register(
        Contract,
        (
            account_hash,
            ed25519_verifier.clone(),
            webauthn_verifier.clone(),
            threshold_policy.clone(),
        ),
    );

    FactorySetup {
        client: ContractClient::new(env, &contract_id),
        ed25519_verifier,
        webauthn_verifier,
        threshold_policy,
    }
}

/// Stub factory with fake addresses — for validation-only tests that never
/// call create_account and don't need real deployed singletons.
fn install_factory_stub(env: &Env) -> ContractClient<'_> {
    let zero_hash = BytesN::from_array(env, &[0; 32]);
    let singleton = env.register(dummy_singleton::WASM, ());

    let contract_id =
        env.register(Contract, (zero_hash, singleton.clone(), singleton.clone(), singleton));

    ContractClient::new(env, &contract_id)
}

fn ed25519_signer(env: &Env, byte: u8) -> ExternalSignerInit {
    ExternalSignerInit {
        signer_kind: SignerKind::Ed25519,
        key_data: Bytes::from_array(env, &[byte; 32]),
    }
}

fn webauthn_signer(env: &Env, byte: u8) -> ExternalSignerInit {
    let mut raw = [byte; 100]; // >65 bytes, 0x04 prefix
    raw[0] = 0x04;
    ExternalSignerInit { signer_kind: SignerKind::WebAuthn, key_data: Bytes::from_array(env, &raw) }
}

fn delegated_signer(env: &Env) -> AccountSignerInit {
    AccountSignerInit::Delegated(Address::generate(env))
}

fn ext_ed25519_signer(env: &Env, byte: u8) -> AccountSignerInit {
    AccountSignerInit::External(ed25519_signer(env, byte))
}

fn ext_webauthn_signer(env: &Env, byte: u8) -> AccountSignerInit {
    AccountSignerInit::External(webauthn_signer(env, byte))
}

// ---------------------------------------------------------------------------
// Address derivation — get_account_address
// ---------------------------------------------------------------------------

#[test]
fn same_params_same_address() {
    let env = Env::default();
    let client = install_factory_stub(&env);

    let params = AccountInitParams {
        signers: soroban_sdk::vec![&env, ext_ed25519_signer(&env, 7)],
        threshold: None,
        account_salt: BytesN::from_array(&env, &[9; 32]),
    };

    assert_eq!(client.get_account_address(&params), client.get_account_address(&params));
}

#[test]
fn constructor_rejects_undeployed_singletons() {
    let env = Env::default();
    let zero_hash = BytesN::from_array(&env, &[0; 32]);
    let fake = Address::generate(&env);

    // env.register() runs the constructor synchronously and panics if it
    // panics — there is no try_register() in Soroban test utils. This is
    // the only case in the test suite where catch_unwind is unavoidable:
    // constructor-level failures cannot be caught with try_* client methods
    // because no client exists until registration succeeds.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.register(Contract, (zero_hash, fake.clone(), fake.clone(), fake.clone()));
    }));

    assert!(result.is_err());
}

#[test]
fn signer_order_does_not_change_address() {
    let env = Env::default();
    let client = install_factory_stub(&env);

    let signer_a = ext_ed25519_signer(&env, 1);
    let signer_b = ext_webauthn_signer(&env, 2);
    let salt = BytesN::from_array(&env, &[3; 32]);

    let addr_1 = client.get_account_address(&AccountInitParams {
        signers: soroban_sdk::vec![&env, signer_a.clone(), signer_b.clone()],
        threshold: Some(2),
        account_salt: salt.clone(),
    });
    let addr_2 = client.get_account_address(&AccountInitParams {
        signers: soroban_sdk::vec![&env, signer_b, signer_a],
        threshold: Some(2),
        account_salt: salt,
    });

    assert_eq!(addr_1, addr_2);
}

#[test]
fn account_salt_changes_address() {
    let env = Env::default();
    let client = install_factory_stub(&env);

    let signers = soroban_sdk::vec![&env, ext_ed25519_signer(&env, 5)];

    let addr_1 = client.get_account_address(&AccountInitParams {
        signers: signers.clone(),
        threshold: None,
        account_salt: BytesN::from_array(&env, &[1; 32]),
    });
    let addr_2 = client.get_account_address(&AccountInitParams {
        signers,
        threshold: None,
        account_salt: BytesN::from_array(&env, &[2; 32]),
    });

    assert_ne!(addr_1, addr_2);
}

#[test]
fn different_key_data_changes_address() {
    let env = Env::default();
    let client = install_factory_stub(&env);

    let salt = BytesN::from_array(&env, &[5; 32]);

    let addr_1 = client.get_account_address(&AccountInitParams {
        signers: soroban_sdk::vec![&env, ext_ed25519_signer(&env, 1)],
        threshold: None,
        account_salt: salt.clone(),
    });
    let addr_2 = client.get_account_address(&AccountInitParams {
        signers: soroban_sdk::vec![&env, ext_ed25519_signer(&env, 2)],
        threshold: None,
        account_salt: salt,
    });

    assert_ne!(addr_1, addr_2);
}

// ---------------------------------------------------------------------------
// Validation — all rejection cases
// ---------------------------------------------------------------------------

#[test]
fn duplicate_signers_are_rejected() {
    let env = Env::default();
    let client = install_factory_stub(&env);
    let signer = ext_ed25519_signer(&env, 9);

    assert!(client
        .try_get_account_address(&AccountInitParams {
            signers: soroban_sdk::vec![&env, signer.clone(), signer],
            threshold: Some(2),
            account_salt: BytesN::from_array(&env, &[7; 32]),
        })
        .is_err());
}

#[test]
fn multisig_requires_explicit_threshold() {
    let env = Env::default();
    let client = install_factory_stub(&env);

    assert!(client
        .try_get_account_address(&AccountInitParams {
            signers: soroban_sdk::vec![
                &env,
                ext_ed25519_signer(&env, 1),
                ext_ed25519_signer(&env, 2)
            ],
            threshold: None,
            account_salt: BytesN::from_array(&env, &[8; 32]),
        })
        .is_err());
}

#[test]
fn threshold_zero_is_rejected() {
    let env = Env::default();
    let client = install_factory_stub(&env);

    assert!(client
        .try_get_account_address(&AccountInitParams {
            signers: soroban_sdk::vec![
                &env,
                ext_ed25519_signer(&env, 1),
                ext_ed25519_signer(&env, 2)
            ],
            threshold: Some(0),
            account_salt: BytesN::from_array(&env, &[1; 32]),
        })
        .is_err());
}

#[test]
fn threshold_above_signer_count_is_rejected() {
    let env = Env::default();
    let client = install_factory_stub(&env);

    assert!(client
        .try_get_account_address(&AccountInitParams {
            signers: soroban_sdk::vec![
                &env,
                ext_ed25519_signer(&env, 1),
                ext_ed25519_signer(&env, 2)
            ],
            threshold: Some(3),
            account_salt: BytesN::from_array(&env, &[2; 32]),
        })
        .is_err());
}

#[test]
fn invalid_ed25519_key_is_rejected() {
    let env = Env::default();
    let client = install_factory_stub(&env);

    assert!(client
        .try_get_account_address(&AccountInitParams {
            signers: soroban_sdk::vec![
                &env,
                AccountSignerInit::External(ExternalSignerInit {
                    signer_kind: SignerKind::Ed25519,
                    key_data: Bytes::from_array(&env, &[1u8; 31]),
                })
            ],
            threshold: None,
            account_salt: BytesN::from_array(&env, &[6; 32]),
        })
        .is_err());
}

#[test]
fn invalid_webauthn_key_is_rejected() {
    let env = Env::default();
    let client = install_factory_stub(&env);

    let mut raw = [1u8; 65];
    raw[0] = 0x04;

    assert!(client
        .try_get_account_address(&AccountInitParams {
            signers: soroban_sdk::vec![
                &env,
                AccountSignerInit::External(ExternalSignerInit {
                    signer_kind: SignerKind::WebAuthn,
                    key_data: Bytes::from_array(&env, &raw),
                })
            ],
            threshold: None,
            account_salt: BytesN::from_array(&env, &[8; 32]),
        })
        .is_err());
}

// ---------------------------------------------------------------------------
// Config queries — get_verifier, get_threshold_policy
// ---------------------------------------------------------------------------

#[test]
fn get_verifier_returns_stored_addresses() {
    let env = Env::default();
    let setup = install_factory(&env);

    assert_eq!(setup.client.get_verifier(&SignerKind::Ed25519), setup.ed25519_verifier);
    assert_eq!(setup.client.get_verifier(&SignerKind::WebAuthn), setup.webauthn_verifier);
}

#[test]
fn get_threshold_policy_returns_stored_address() {
    let env = Env::default();
    let setup = install_factory(&env);

    assert_eq!(setup.client.get_threshold_policy(), setup.threshold_policy);
}

#[test]
fn each_verifier_address_is_distinct() {
    let env = Env::default();
    let setup = install_factory(&env);

    assert_ne!(setup.ed25519_verifier, setup.webauthn_verifier);
}

// ---------------------------------------------------------------------------
// create_account — full deployment path
// ---------------------------------------------------------------------------

#[test]
fn create_account_deploys_at_precomputed_address() {
    let env = Env::default();
    let setup = install_factory(&env);

    let params = AccountInitParams {
        signers: soroban_sdk::vec![&env, ext_ed25519_signer(&env, 1)],
        threshold: None,
        account_salt: BytesN::from_array(&env, &[10; 32]),
    };

    let expected = setup.client.get_account_address(&params);
    let actual = setup.client.create_account(&params);

    assert_eq!(expected, actual);
}

#[test]
fn create_account_deploys_contract_at_address() {
    let env = Env::default();
    let setup = install_factory(&env);

    let params = AccountInitParams {
        signers: soroban_sdk::vec![&env, ext_ed25519_signer(&env, 2)],
        threshold: None,
        account_salt: BytesN::from_array(&env, &[11; 32]),
    };

    let account = setup.client.create_account(&params);

    assert!(account.executable().is_some());
}

#[test]
fn create_account_emits_account_created_event() {
    let env = Env::default();
    let setup = install_factory(&env);

    let params = AccountInitParams {
        signers: soroban_sdk::vec![&env, ext_ed25519_signer(&env, 3)],
        threshold: None,
        account_salt: BytesN::from_array(&env, &[12; 32]),
    };

    setup.client.create_account(&params);

    assert_eq!(env.events().all().events().len(), 1);
}

#[test]
fn create_account_is_idempotent() {
    let env = Env::default();
    let setup = install_factory(&env);

    let params = AccountInitParams {
        signers: soroban_sdk::vec![&env, ext_ed25519_signer(&env, 4)],
        threshold: None,
        account_salt: BytesN::from_array(&env, &[13; 32]),
    };

    let addr_1 = setup.client.create_account(&params);
    // first call: account is new, event emitted
    assert_eq!(env.events().all().events().len(), 1);

    let addr_2 = setup.client.create_account(&params);
    // second call: account already exists, returns early — no event
    assert_eq!(addr_1, addr_2);
    assert_eq!(env.events().all().events().len(), 0);
}

#[test]
fn create_account_with_webauthn_signer() {
    let env = Env::default();
    let setup = install_factory(&env);

    let params = AccountInitParams {
        signers: soroban_sdk::vec![&env, ext_webauthn_signer(&env, 6)],
        threshold: None,
        account_salt: BytesN::from_array(&env, &[31; 32]),
    };

    let expected = setup.client.get_account_address(&params);
    let actual = setup.client.create_account(&params);

    assert_eq!(expected, actual);
    assert!(actual.executable().is_some());
}

#[test]
fn create_account_multisig_deploys_at_precomputed_address() {
    let env = Env::default();
    let setup = install_factory(&env);

    let params = AccountInitParams {
        signers: soroban_sdk::vec![&env, ext_ed25519_signer(&env, 1), ext_ed25519_signer(&env, 2)],
        threshold: Some(2),
        account_salt: BytesN::from_array(&env, &[15; 32]),
    };

    let expected = setup.client.get_account_address(&params);
    let actual = setup.client.create_account(&params);

    assert_eq!(expected, actual);
    assert!(actual.executable().is_some());
}

#[test]
fn create_account_mixed_signers_multisig() {
    let env = Env::default();
    let setup = install_factory(&env);

    let params = AccountInitParams {
        signers: soroban_sdk::vec![&env, ext_ed25519_signer(&env, 1), ext_webauthn_signer(&env, 3)],
        threshold: Some(2),
        account_salt: BytesN::from_array(&env, &[32; 32]),
    };

    let expected = setup.client.get_account_address(&params);
    let actual = setup.client.create_account(&params);

    assert_eq!(expected, actual);
    assert!(actual.executable().is_some());
}

#[test]
fn delegated_signer_changes_address() {
    let env = Env::default();
    let client = install_factory_stub(&env);

    let addr_1 = client.get_account_address(&AccountInitParams {
        signers: soroban_sdk::vec![&env, delegated_signer(&env)],
        threshold: None,
        account_salt: BytesN::from_array(&env, &[40; 32]),
    });
    let addr_2 = client.get_account_address(&AccountInitParams {
        signers: soroban_sdk::vec![&env, delegated_signer(&env)],
        threshold: None,
        account_salt: BytesN::from_array(&env, &[40; 32]),
    });

    assert_ne!(addr_1, addr_2);
}

#[test]
fn create_account_with_delegated_signer() {
    let env = Env::default();
    let setup = install_factory(&env);
    let delegated = delegated_signer(&env);

    let params = AccountInitParams {
        signers: soroban_sdk::vec![&env, delegated],
        threshold: None,
        account_salt: BytesN::from_array(&env, &[41; 32]),
    };

    let expected = setup.client.get_account_address(&params);
    let actual = setup.client.create_account(&params);

    assert_eq!(expected, actual);
    assert!(actual.executable().is_some());
}

#[test]
fn create_account_with_delegated_and_external_multisig() {
    let env = Env::default();
    let setup = install_factory(&env);

    let params = AccountInitParams {
        signers: soroban_sdk::vec![&env, delegated_signer(&env), ext_webauthn_signer(&env, 9)],
        threshold: Some(2),
        account_salt: BytesN::from_array(&env, &[42; 32]),
    };

    let expected = setup.client.get_account_address(&params);
    let actual = setup.client.create_account(&params);

    assert_eq!(expected, actual);
    assert!(actual.executable().is_some());
}

// ---------------------------------------------------------------------------
// Adversarial tests — Salt collision and front-running
// ---------------------------------------------------------------------------

#[test]
fn salt_collision_with_different_signers_produces_isolated_distinct_addresses() {
    let env = Env::default();
    let setup = install_factory(&env);

    // Two users/parties submit the exact same account_salt, but with different signers.
    let shared_salt = BytesN::from_array(&env, &[0x42; 32]);

    let user_a_params = AccountInitParams {
        signers: soroban_sdk::vec![&env, ext_ed25519_signer(&env, 10)],
        threshold: None,
        account_salt: shared_salt.clone(),
    };

    let user_b_params = AccountInitParams {
        signers: soroban_sdk::vec![&env, ext_ed25519_signer(&env, 20)],
        threshold: None,
        account_salt: shared_salt.clone(),
    };

    // Derived addresses must be strictly isolated and distinct despite identical salt
    let addr_a = setup.client.get_account_address(&user_a_params);
    let addr_b = setup.client.get_account_address(&user_b_params);
    assert_ne!(addr_a, addr_b);

    // Deploy User A's account first
    let deployed_a = setup.client.create_account(&user_a_params);
    assert_eq!(deployed_a, addr_a);
    assert!(deployed_a.executable().is_some());

    // Deploy User B's account afterwards — both succeed independently and do not collide
    let deployed_b = setup.client.create_account(&user_b_params);
    assert_eq!(deployed_b, addr_b);
    assert!(deployed_b.executable().is_some());
    assert_ne!(deployed_a, deployed_b);
}

#[test]
fn salt_collision_with_different_thresholds_produces_isolated_distinct_addresses() {
    let env = Env::default();
    let setup = install_factory(&env);

    let shared_salt = BytesN::from_array(&env, &[0x77; 32]);
    let signers = soroban_sdk::vec![
        &env,
        ext_ed25519_signer(&env, 11),
        ext_ed25519_signer(&env, 12),
    ];

    let params_thresh_1 = AccountInitParams {
        signers: signers.clone(),
        threshold: Some(1),
        account_salt: shared_salt.clone(),
    };

    let params_thresh_2 = AccountInitParams {
        signers,
        threshold: Some(2),
        account_salt: shared_salt,
    };

    let addr_thresh_1 = setup.client.get_account_address(&params_thresh_1);
    let addr_thresh_2 = setup.client.get_account_address(&params_thresh_2);
    assert_ne!(addr_thresh_1, addr_thresh_2);

    let deployed_1 = setup.client.create_account(&params_thresh_1);
    let deployed_2 = setup.client.create_account(&params_thresh_2);

    assert_eq!(deployed_1, addr_thresh_1);
    assert_eq!(deployed_2, addr_thresh_2);
    assert_ne!(deployed_1, deployed_2);
}

#[test]
fn front_running_deployment_is_idempotent_and_safe() {
    let env = Env::default();
    let setup = install_factory(&env);

    // An honest user constructs account parameters
    let params = AccountInitParams {
        signers: soroban_sdk::vec![&env, ext_ed25519_signer(&env, 55)],
        threshold: None,
        account_salt: BytesN::from_array(&env, &[0x99; 32]),
    };

    let target_account_address = setup.client.get_account_address(&params);

    // Adversary observes transaction in mempool and front-runs by calling create_account
    // with the identical parameters first
    let front_run_deployed = setup.client.create_account(&params);
    assert_eq!(front_run_deployed, target_account_address);
    assert!(front_run_deployed.executable().is_some());

    // Exactly 1 AccountCreated event emitted for the front-runner's deployment
    assert_eq!(env.events().all().events().len(), 1);

    // Honest user's subsequent create_account call executes
    // Because deployment is idempotent, it succeeds safely, returning the expected account address
    // without deploying duplicate state or emitting a duplicate creation event
    let honest_deployed = setup.client.create_account(&params);
    assert_eq!(honest_deployed, target_account_address);
    assert_eq!(honest_deployed, front_run_deployed);

    // No duplicate event was published on the second call
    assert_eq!(env.events().all().events().len(), 0);
}

#[test]
fn front_running_attempt_with_malicious_signers_does_not_hijack_victim_address() {
    let env = Env::default();
    let setup = install_factory(&env);

    let salt = BytesN::from_array(&env, &[0xAA; 32]);

    // Honest user's target parameters
    let victim_params = AccountInitParams {
        signers: soroban_sdk::vec![&env, ext_ed25519_signer(&env, 88)],
        threshold: None,
        account_salt: salt.clone(),
    };
    let victim_address = setup.client.get_account_address(&victim_params);

    // Adversary attempts to hijack victim's deployment by front-running with the same salt
    // but replacing victim's signer with attacker's signer
    let attacker_params = AccountInitParams {
        signers: soroban_sdk::vec![&env, ext_ed25519_signer(&env, 99)],
        threshold: None,
        account_salt: salt,
    };
    let attacker_address = setup.client.get_account_address(&attacker_params);

    // Attacker's address cannot collide with victim's address
    assert_ne!(attacker_address, victim_address);

    // Attacker deploys first
    let attacker_deployed = setup.client.create_account(&attacker_params);
    assert_eq!(attacker_deployed, attacker_address);
    assert_ne!(attacker_deployed, victim_address);

    // Victim deploys afterwards; victim's deployment succeeds unhindered at victim_address
    let victim_deployed = setup.client.create_account(&victim_params);
    assert_eq!(victim_deployed, victim_address);
    assert_ne!(victim_deployed, attacker_deployed);
    assert!(victim_deployed.executable().is_some());
}

#[test]
fn front_running_attempt_with_delegated_signer_cannot_collide() {
    let env = Env::default();
    let setup = install_factory(&env);

    let salt = BytesN::from_array(&env, &[0xBB; 32]);
    let victim_delegated = delegated_signer(&env);
    let attacker_delegated = delegated_signer(&env);

    let victim_params = AccountInitParams {
        signers: soroban_sdk::vec![&env, AccountSignerInit::Delegated(victim_delegated)],
        threshold: None,
        account_salt: salt.clone(),
    };
    let attacker_params = AccountInitParams {
        signers: soroban_sdk::vec![&env, AccountSignerInit::Delegated(attacker_delegated)],
        threshold: None,
        account_salt: salt,
    };

    let victim_addr = setup.client.get_account_address(&victim_params);
    let attacker_addr = setup.client.get_account_address(&attacker_params);
    assert_ne!(victim_addr, attacker_addr);

    let attacker_deployed = setup.client.create_account(&attacker_params);
    assert_eq!(attacker_deployed, attacker_addr);

    let victim_deployed = setup.client.create_account(&victim_params);
    assert_eq!(victim_deployed, victim_addr);
    assert_ne!(victim_deployed, attacker_deployed);
}
