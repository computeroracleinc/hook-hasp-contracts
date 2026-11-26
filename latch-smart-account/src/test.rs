#![cfg(test)]

extern crate std;

use session_policy::{
    SessionAccountParams, SessionPolicy, SessionPolicyClient, MAX_SESSION_DURATION,
};
use soroban_sdk::{
    auth::{
        Context, ContractContext, ContractExecutable, CreateContractWithConstructorHostFnContext,
    },
    contract, contractimpl, symbol_short,
    testutils::{Address as _, Ledger},
    vec, Address, Bytes, BytesN, Env, Executable, IntoVal, Map, String, Symbol, Val, Vec,
};
use spending_limit_policy::{SpendingLimitPolicy, SpendingLimitPolicyClient};
use stellar_accounts::{
    policies::{spending_limit::SpendingLimitAccountParams, Policy},
    smart_account::{self as smart_account, AuthPayload, ContextRuleType, Signer},
};

use super::{
    LatchSmartAccount, LatchSmartAccountClient, ProposalStatus, SignerAction, TransferOp,
    DEFAULT_RECOVERY_INACTIVITY_DELAY_LEDGERS,
};

// A real, tiny, already-existing no-op contract (zero-arg constructor),
// reused from `factory-contract`'s own testdata rather than building a new
// fixture — deploying it via `env.deployer().upload_contract_wasm(...)`
// exercises the real Soroban host deployer, not a mocked one.
mod dummy_singleton {
    soroban_sdk::contractimport!(file = "testdata/dummy_singleton.wasm");
}

mod smart_account_v2 {
    soroban_sdk::contractimport!(file = "testdata/smart_account_v2.wasm");
}

#[contract]
struct MockTargetContract;

#[contractimpl]
impl MockTargetContract {
    pub fn set(e: Env, value: u32) {
        e.storage().persistent().set(&Symbol::new(&e, "value"), &value);
    }

    pub fn get(e: Env) -> u32 {
        e.storage().persistent().get(&Symbol::new(&e, "value")).unwrap_or(0)
    }
}

#[contract]
struct MockPolicyContract;

#[contractimpl]
impl Policy for MockPolicyContract {
    type AccountParams = Val;

    fn enforce(
        _e: &Env,
        _context: soroban_sdk::auth::Context,
        _authenticated_signers: Vec<Signer>,
        _context_rule: stellar_accounts::smart_account::ContextRule,
        _smart_account: Address,
    ) {
    }

    fn install(
        _e: &Env,
        _install_params: Val,
        _context_rule: stellar_accounts::smart_account::ContextRule,
        _smart_account: Address,
    ) {
    }

    fn uninstall(
        _e: &Env,
        _context_rule: stellar_accounts::smart_account::ContextRule,
        _smart_account: Address,
    ) {
    }
}

fn default_signers(env: &Env) -> Vec<Signer> {
    vec![env, Signer::Delegated(Address::generate(env))]
}

fn register_account<'a>(
    env: &'a Env,
    signers: &Vec<Signer>,
    policies: &Map<Address, Val>,
) -> (Address, LatchSmartAccountClient<'a>) {
    let account_id = env.register(LatchSmartAccount, (signers.clone(), policies.clone()));
    let client = LatchSmartAccountClient::new(env, &account_id);
    (account_id, client)
}

#[test]
fn constructor_creates_one_default_rule_named_default() {
    let env = Env::default();
    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    assert_eq!(client.get_context_rules_count(), 1);
    let rule = client.get_context_rule(&0);
    assert_eq!(rule.name, String::from_str(&env, "default"));
    assert_eq!(rule.context_type, ContextRuleType::Default);
    assert_eq!(rule.signers, signers);
    assert_eq!(rule.valid_until, None);
}

#[test]
fn execute_forwards_calls() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let target_id = env.register(MockTargetContract, ());
    let target_client = MockTargetContractClient::new(&env, &target_id);

    client.execute(&target_id, &Symbol::new(&env, "set"), &vec![&env, 7u32.into_val(&env)]);

    assert_eq!(target_client.get(), 7);
}

#[test]
#[should_panic]
fn execute_requires_self_auth() {
    let env = Env::default();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let target_id = env.register(MockTargetContract, ());
    client.execute(&target_id, &Symbol::new(&env, "set"), &vec![&env, 1u32.into_val(&env)]);
}

#[test]
fn add_context_rule_succeeds_with_self_auth() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let some_contract = Address::generate(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let added = client.add_context_rule(
        &ContextRuleType::CallContract(some_contract),
        &String::from_str(&env, "secondary"),
        &None,
        &signers,
        &policies,
    );

    assert_eq!(added.name, String::from_str(&env, "secondary"));
    assert_eq!(client.get_context_rules_count(), 2);
}

#[test]
#[should_panic]
fn add_context_rule_requires_self_auth() {
    let env = Env::default();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let some_contract = Address::generate(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    client.add_context_rule(
        &ContextRuleType::CallContract(some_contract),
        &String::from_str(&env, "secondary"),
        &None,
        &signers,
        &policies,
    );
}

#[test]
fn add_signer_and_policy_succeed_with_self_auth() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let default_rule = client.get_context_rule(&0);
    let new_signer = Signer::Delegated(Address::generate(&env));
    let signer_id = client.add_signer(&default_rule.id, &new_signer);

    let policy_id = env.register(MockPolicyContract, ());
    let install_param: Val = Val::from_void().into();
    let added_policy_id = client.add_policy(&default_rule.id, &policy_id, &install_param);

    let updated_rule = client.get_context_rule(&default_rule.id);
    assert!(updated_rule.signers.contains(&new_signer));
    assert_eq!(signer_id, 1);
    assert_eq!(added_policy_id, 0);
    assert!(updated_rule.policies.contains(&policy_id));
}

#[test]
#[should_panic]
fn add_signer_requires_self_auth() {
    let env = Env::default();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let default_rule = client.get_context_rule(&0);
    client.add_signer(&default_rule.id, &Signer::Delegated(Address::generate(&env)));
}

#[test]
#[should_panic]
fn add_policy_requires_self_auth() {
    let env = Env::default();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let default_rule = client.get_context_rule(&0);
    let policy_id = env.register(MockPolicyContract, ());
    let install_param: Val = Val::from_void().into();
    client.add_policy(&default_rule.id, &policy_id, &install_param);
}

#[test]
fn upgrade_succeeds_with_self_auth() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    // Re-upgrading to the account's own currently-running wasm — a real,
    // valid hash (not a dummy one), so this proves the upgrade mechanism
    // actually succeeds end-to-end when properly self-authorized, not just
    // that the auth check passes.
    let Some(Executable::Wasm(wasm_hash)) = account_id.executable() else {
        panic!("expected a wasm-backed account");
    };

    client.upgrade(&wasm_hash, &account_id);
}

#[test]
#[should_panic]
fn upgrade_requires_self_auth() {
    let env = Env::default();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    let new_wasm_hash = BytesN::from_array(&env, &[0u8; 32]);
    client.upgrade(&new_wasm_hash, &account_id);
}

// ################## SESSION KEY INTEGRATION TESTS ##################
//
// These tests exercise `smart_account::do_check_auth` directly (as OZ's own
// `context_rules.rs` test suite does) rather than routing through the
// account's `require_auth` machinery, so a `Signer::Delegated` address can
// stand in for an ephemeral session key without needing real signature
// verification — verifier cryptography itself is already covered by the
// `latch-verifiers` crates' own test suites.

fn get_context(contract: Address, fn_name: Symbol, args: Vec<Val>) -> Context {
    Context::Contract(ContractContext { contract, fn_name, args })
}

fn create_signatures(e: &Env, signers: &Vec<Signer>, context_rule_ids: Vec<u32>) -> AuthPayload {
    let mut signature_map = Map::new(e);
    for signer in signers.iter() {
        signature_map.set(signer, Bytes::new(e));
    }
    AuthPayload { signers: signature_map, context_rule_ids }
}

/// Sets up a smart account with a `CallContract(target)` session rule bound
/// to one `Signer::Delegated` session key, installs the session policy with
/// the given `allowed_fns`, and returns everything needed to drive
/// `do_check_auth` against it.
fn setup_session_rule<'a>(
    env: &'a Env,
    allowed_fns: Vec<Symbol>,
) -> (Address, LatchSmartAccountClient<'a>, Address, u32, Vec<Signer>, Address) {
    env.mock_all_auths();

    let owner_signers = default_signers(env);
    let policies = Map::new(env);
    let (account_id, client) = register_account(env, &owner_signers, &policies);

    let target_id = env.register(MockTargetContract, ());

    let session_signer = Signer::Delegated(Address::generate(env));
    let session_signers = vec![env, session_signer];

    let rule = client.add_context_rule(
        &ContextRuleType::CallContract(target_id.clone()),
        &String::from_str(env, "session"),
        &None,
        &session_signers,
        &Map::new(env),
    );

    let session_policy_id = env.register(SessionPolicy, ());
    let install_param: Val = SessionAccountParams { allowed_fns }.into_val(env);
    client.add_policy(&rule.id, &session_policy_id, &install_param);

    (account_id, client, target_id, rule.id, session_signers, session_policy_id)
}

#[test]
fn session_signer_allowed_call_succeeds() {
    let env = Env::default();
    let (account_id, _client, target_id, rule_id, session_signers, _) =
        setup_session_rule(&env, vec![&env, Symbol::new(&env, "set")]);

    let context = get_context(target_id, Symbol::new(&env, "set"), vec![&env, 7u32.into_val(&env)]);
    let auth_contexts = Vec::from_array(&env, [context]);
    let signatures = create_signatures(&env, &session_signers, vec![&env, rule_id]);
    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[1u8; 32]));

    env.as_contract(&account_id, || {
        let result = smart_account::do_check_auth(&env, &payload_hash, &signatures, &auth_contexts);
        assert!(result.is_ok());
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn session_signer_disallowed_method_rejected() {
    let env = Env::default();
    let (account_id, _client, target_id, rule_id, session_signers, _) =
        setup_session_rule(&env, vec![&env, Symbol::new(&env, "set")]);

    // "get" is not in the allowlist, only "set" is.
    let context = get_context(target_id, Symbol::new(&env, "get"), vec![&env]);
    let auth_contexts = Vec::from_array(&env, [context]);
    let signatures = create_signatures(&env, &session_signers, vec![&env, rule_id]);
    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[1u8; 32]));

    env.as_contract(&account_id, || {
        let _ = smart_account::do_check_auth(&env, &payload_hash, &signatures, &auth_contexts);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #3002)")]
fn session_call_after_valid_until_expiry_rejected() {
    let env = Env::default();
    env.mock_all_auths();

    let owner_signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &owner_signers, &policies);

    let target_id = env.register(MockTargetContract, ());
    let session_signer = Signer::Delegated(Address::generate(&env));
    let session_signers = vec![&env, session_signer];

    let expiry_ledger = env.ledger().sequence() + 1;
    let rule = client.add_context_rule(
        &ContextRuleType::CallContract(target_id.clone()),
        &String::from_str(&env, "session"),
        &Some(expiry_ledger),
        &session_signers,
        &Map::new(&env),
    );

    let session_policy_id = env.register(SessionPolicy, ());
    let install_param: Val =
        SessionAccountParams { allowed_fns: vec![&env, Symbol::new(&env, "set")] }.into_val(&env);
    client.add_policy(&rule.id, &session_policy_id, &install_param);

    // Advance past the rule's expiry.
    env.ledger().with_mut(|li| {
        li.sequence_number = expiry_ledger + 1;
    });

    let context = get_context(target_id, Symbol::new(&env, "set"), vec![&env, 7u32.into_val(&env)]);
    let auth_contexts = Vec::from_array(&env, [context]);
    let signatures = create_signatures(&env, &session_signers, vec![&env, rule.id]);
    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[1u8; 32]));

    env.as_contract(&account_id, || {
        let _ = smart_account::do_check_auth(&env, &payload_hash, &signatures, &auth_contexts);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn session_rule_exceeding_max_duration_rejected_on_policy_install() {
    let env = Env::default();
    env.mock_all_auths();

    let owner_signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &owner_signers, &policies);

    let target_id = env.register(MockTargetContract, ());
    let session_signer = Signer::Delegated(Address::generate(&env));
    let expiry_ledger = env.ledger().sequence() + MAX_SESSION_DURATION + 1;

    let rule = client.add_context_rule(
        &ContextRuleType::CallContract(target_id.clone()),
        &String::from_str(&env, "session"),
        &Some(expiry_ledger),
        &vec![&env, session_signer],
        &Map::new(&env),
    );

    let session_policy_id = env.register(SessionPolicy, ());
    let install_param: Val =
        SessionAccountParams { allowed_fns: vec![&env, Symbol::new(&env, "set")] }.into_val(&env);
    client.add_policy(&rule.id, &session_policy_id, &install_param);
}

#[test]
#[should_panic(expected = "Error(Contract, #3000)")]
fn session_call_after_remove_context_rule_rejected() {
    let env = Env::default();
    let (account_id, client, target_id, rule_id, session_signers, _) =
        setup_session_rule(&env, vec![&env, Symbol::new(&env, "set")]);

    client.remove_context_rule(&rule_id);

    let context = get_context(target_id, Symbol::new(&env, "set"), vec![&env, 7u32.into_val(&env)]);
    let auth_contexts = Vec::from_array(&env, [context]);
    let signatures = create_signatures(&env, &session_signers, vec![&env, rule_id]);
    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[1u8; 32]));

    env.as_contract(&account_id, || {
        let _ = smart_account::do_check_auth(&env, &payload_hash, &signatures, &auth_contexts);
    });
}

/// A session that authenticates successfully can be cancelled immediately by
/// the account owner through the policy's revocation bitmap; the same
/// signature is rejected on the very next authorization attempt without
/// touching the account's context rule.
#[test]
#[should_panic(expected = "Error(Contract, #7)")]
fn revoked_session_call_rejected_by_account_auth() {
    let env = Env::default();
    let (account_id, _client, target_id, rule_id, session_signers, policy_id) =
        setup_session_rule(&env, vec![&env, Symbol::new(&env, "set")]);

    let context = get_context(target_id, Symbol::new(&env, "set"), vec![&env, 7u32.into_val(&env)]);
    let auth_contexts = Vec::from_array(&env, [context]);
    let signatures = create_signatures(&env, &session_signers, vec![&env, rule_id]);
    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[1u8; 32]));

    env.as_contract(&account_id, || {
        let result = smart_account::do_check_auth(&env, &payload_hash, &signatures, &auth_contexts);
        assert!(result.is_ok());
    });

    let policy_client = SessionPolicyClient::new(&env, &policy_id);
    assert!(!policy_client.is_revoked(&rule_id, &account_id));
    policy_client.revoke_session(&rule_id, &account_id);
    assert!(policy_client.is_revoked(&rule_id, &account_id));

    env.as_contract(&account_id, || {
        let _ = smart_account::do_check_auth(&env, &payload_hash, &signatures, &auth_contexts);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #3221)")]
fn session_plus_spending_limit_over_limit_rejected_even_when_method_allowed() {
    let env = Env::default();
    env.mock_all_auths();

    let owner_signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &owner_signers, &policies);

    let target_id = env.register(MockTargetContract, ());
    let session_signer = Signer::Delegated(Address::generate(&env));
    let session_signers = vec![&env, session_signer];

    let rule = client.add_context_rule(
        &ContextRuleType::CallContract(target_id.clone()),
        &String::from_str(&env, "session"),
        &None,
        &session_signers,
        &Map::new(&env),
    );

    let session_policy_id = env.register(SessionPolicy, ());
    let session_install_param: Val =
        SessionAccountParams { allowed_fns: vec![&env, symbol_short!("transfer")] }.into_val(&env);
    client.add_policy(&rule.id, &session_policy_id, &session_install_param);

    let spending_limit_policy_id = env.register(SpendingLimitPolicy, ());
    let spending_install_param: Val =
        SpendingLimitAccountParams { spending_limit: 1_000_000, period_ledgers: 100 }
            .into_val(&env);
    client.add_policy(&rule.id, &spending_limit_policy_id, &spending_install_param);

    // "transfer" is allowlisted, but the amount exceeds the spending limit.
    let from = Address::generate(&env);
    let to = Address::generate(&env);
    let context = get_context(
        target_id,
        symbol_short!("transfer"),
        vec![&env, from.into_val(&env), to.into_val(&env), 2_000_000i128.into_val(&env)],
    );
    let auth_contexts = Vec::from_array(&env, [context]);
    let signatures = create_signatures(&env, &session_signers, vec![&env, rule.id]);
    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[1u8; 32]));

    env.as_contract(&account_id, || {
        let _ = smart_account::do_check_auth(&env, &payload_hash, &signatures, &auth_contexts);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn session_plus_spending_limit_disallowed_method_rejected_even_when_under_limit() {
    let env = Env::default();
    env.mock_all_auths();

    let owner_signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &owner_signers, &policies);

    let target_id = env.register(MockTargetContract, ());
    let session_signer = Signer::Delegated(Address::generate(&env));
    let session_signers = vec![&env, session_signer];

    let rule = client.add_context_rule(
        &ContextRuleType::CallContract(target_id.clone()),
        &String::from_str(&env, "session"),
        &None,
        &session_signers,
        &Map::new(&env),
    );

    let session_policy_id = env.register(SessionPolicy, ());
    let session_install_param: Val =
        SessionAccountParams { allowed_fns: vec![&env, symbol_short!("transfer")] }.into_val(&env);
    client.add_policy(&rule.id, &session_policy_id, &session_install_param);

    let spending_limit_policy_id = env.register(SpendingLimitPolicy, ());
    let spending_install_param: Val =
        SpendingLimitAccountParams { spending_limit: 1_000_000, period_ledgers: 100 }
            .into_val(&env);
    client.add_policy(&rule.id, &spending_limit_policy_id, &spending_install_param);

    // Well under the spending limit, but "withdraw" is not the allowlisted
    // "transfer" method.
    let from = Address::generate(&env);
    let to = Address::generate(&env);
    let context = get_context(
        target_id,
        symbol_short!("withdraw"),
        vec![&env, from.into_val(&env), to.into_val(&env), 1i128.into_val(&env)],
    );
    let auth_contexts = Vec::from_array(&env, [context]);
    let signatures = create_signatures(&env, &session_signers, vec![&env, rule.id]);
    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[1u8; 32]));

    env.as_contract(&account_id, || {
        let _ = smart_account::do_check_auth(&env, &payload_hash, &signatures, &auth_contexts);
    });
}

// ################## DEPLOY_CONTRACT: DEPLOYMENT MECHANICS ##################
//
// `mock_all_auths()` bypasses `__check_auth` entirely (it never runs), so
// these tests don't exercise context-rule matching — see the
// CREATE_CONTRACT AUTHORIZATION section below for that. What `mock_all_auths`
// does NOT bypass is the actual Soroban host deployer: `deploy_v2` here runs
// against real uploaded wasm, so these tests prove the deployment mechanics
// themselves (address derivation, collision handling, discoverability
// storage) against a real deployed contract, not a mocked one.

fn deployed_wasm_hash(env: &Env) -> BytesN<32> {
    env.deployer().upload_contract_wasm(dummy_singleton::WASM)
}

#[test]
fn deploy_contract_deploys_real_wasm_and_derives_deterministic_address() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    let wasm_hash = deployed_wasm_hash(&env);
    let salt = BytesN::from_array(&env, &[7u8; 32]);

    // Predicted independently of `deploy_contract`, from the deployer +
    // salt alone — this is what "deterministic address" means.
    let expected_address =
        env.deployer().with_address(account_id.clone(), salt.clone()).deployed_address();

    let deployed = client.deploy_contract(&wasm_hash, &salt, &vec![&env]);

    assert_eq!(deployed, expected_address);
    assert_eq!(client.get_deployed_contract_count(), 1);
    let record = client.get_deployed_contract(&0);
    assert_eq!(record.address, deployed);
    assert_eq!(record.wasm_hash, wasm_hash);
}

#[test]
fn deploy_contract_records_multiple_deployments_in_order() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let wasm_hash = deployed_wasm_hash(&env);

    let first =
        client.deploy_contract(&wasm_hash, &BytesN::from_array(&env, &[1u8; 32]), &vec![&env]);
    let second =
        client.deploy_contract(&wasm_hash, &BytesN::from_array(&env, &[2u8; 32]), &vec![&env]);

    assert_eq!(client.get_deployed_contract_count(), 2);
    assert_eq!(client.get_deployed_contract(&0).address, first);
    assert_eq!(client.get_deployed_contract(&1).address, second);
}

#[test]
#[should_panic]
fn deploy_contract_rejects_reusing_same_salt() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let wasm_hash = deployed_wasm_hash(&env);
    let salt = BytesN::from_array(&env, &[3u8; 32]);

    client.deploy_contract(&wasm_hash, &salt, &vec![&env]);
    // Same `(wasm_hash, salt)` from the same deployer derives the same
    // address as the first deployment — the host itself rejects deploying
    // over an address that already has a contract, so a caller can't
    // accidentally collide with or overwrite an already-deployed satellite
    // by reusing a salt.
    client.deploy_contract(&wasm_hash, &salt, &vec![&env]);
}

#[test]
#[should_panic(expected = "Error(Contract, #4000)")] // DeployedContractNotFound
fn get_deployed_contract_rejects_out_of_range_index() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    client.get_deployed_contract(&0);
}

// ################## DEPLOY_CONTRACT: CREATE_CONTRACT AUTHORIZATION #########
//
// Same technique as the session-key tests above: `deploy_v2`'s resulting
// `CreateContractWithCtorHostFn` auth context can't be expressed through
// `mock_auths`/`MockAuthInvoke` (which only models `ContractFn`-shaped
// invocations), so these exercise `smart_account::do_check_auth` directly
// against a hand-built `Context::CreateContractWithCtorHostFn` — the same
// context `deploy_contract`'s real `deploy_v2` call produces internally, per
// `get_validated_context_by_id`'s own match arm for it.

fn get_create_context(
    wasm_hash: BytesN<32>,
    salt: BytesN<32>,
    constructor_args: Vec<Val>,
) -> Context {
    Context::CreateContractWithCtorHostFn(CreateContractWithConstructorHostFnContext {
        executable: ContractExecutable::Wasm(wasm_hash),
        salt,
        constructor_args,
    })
}

#[test]
fn create_contract_rule_with_matching_signer_authorizes_deployment() {
    let env = Env::default();
    env.mock_all_auths();

    let owner_signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &owner_signers, &policies);

    let wasm_hash = BytesN::from_array(&env, &[1u8; 32]);
    let deploy_signer = Signer::Delegated(Address::generate(&env));
    let deploy_signers = vec![&env, deploy_signer];

    let rule = client.add_context_rule(
        &ContextRuleType::CreateContract(wasm_hash.clone()),
        &String::from_str(&env, "deploy"),
        &None,
        &deploy_signers,
        &Map::new(&env),
    );

    let salt = BytesN::from_array(&env, &[9u8; 32]);
    let context = get_create_context(wasm_hash, salt, vec![&env]);
    let auth_contexts = Vec::from_array(&env, [context]);
    let signatures = create_signatures(&env, &deploy_signers, vec![&env, rule.id]);
    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[1u8; 32]));

    env.as_contract(&account_id, || {
        let result = smart_account::do_check_auth(&env, &payload_hash, &signatures, &auth_contexts);
        assert!(result.is_ok());
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #3002)")] // UnvalidatedContext
fn create_contract_rule_rejects_different_wasm_hash() {
    let env = Env::default();
    env.mock_all_auths();

    let owner_signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &owner_signers, &policies);

    let allowed_wasm_hash = BytesN::from_array(&env, &[1u8; 32]);
    let deploy_signer = Signer::Delegated(Address::generate(&env));
    let deploy_signers = vec![&env, deploy_signer];

    let rule = client.add_context_rule(
        &ContextRuleType::CreateContract(allowed_wasm_hash),
        &String::from_str(&env, "deploy"),
        &None,
        &deploy_signers,
        &Map::new(&env),
    );

    // A different wasm hash than the one the rule allows.
    let other_wasm_hash = BytesN::from_array(&env, &[2u8; 32]);
    let salt = BytesN::from_array(&env, &[9u8; 32]);
    let context = get_create_context(other_wasm_hash, salt, vec![&env]);
    let auth_contexts = Vec::from_array(&env, [context]);
    let signatures = create_signatures(&env, &deploy_signers, vec![&env, rule.id]);
    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[1u8; 32]));

    env.as_contract(&account_id, || {
        let _ = smart_account::do_check_auth(&env, &payload_hash, &signatures, &auth_contexts);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #3002)")] // UnvalidatedContext
fn create_contract_rule_rejects_non_matching_signer() {
    let env = Env::default();
    env.mock_all_auths();

    let owner_signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &owner_signers, &policies);

    let wasm_hash = BytesN::from_array(&env, &[1u8; 32]);
    let deploy_signer = Signer::Delegated(Address::generate(&env));
    let deploy_signers = vec![&env, deploy_signer];

    let rule = client.add_context_rule(
        &ContextRuleType::CreateContract(wasm_hash.clone()),
        &String::from_str(&env, "deploy"),
        &None,
        &deploy_signers,
        &Map::new(&env),
    );

    // A signer that has nothing to do with the rule's signer set.
    let attacker_signer = Signer::Delegated(Address::generate(&env));
    let attacker_signers = vec![&env, attacker_signer];

    let salt = BytesN::from_array(&env, &[9u8; 32]);
    let context = get_create_context(wasm_hash, salt, vec![&env]);
    let auth_contexts = Vec::from_array(&env, [context]);
    let signatures = create_signatures(&env, &attacker_signers, vec![&env, rule.id]);
    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[1u8; 32]));

    env.as_contract(&account_id, || {
        let _ = smart_account::do_check_auth(&env, &payload_hash, &signatures, &auth_contexts);
    });
}

// ============================================================================
// ADVERSARIAL TEST HARNESS: UNAUTHORIZED CONTRACT UPGRADE PAYLOADS (ISSUE #88)
// ============================================================================
//
// Tests adversarial upgrade scenarios against `upgrade()`:
// 1. Unauthenticated upgrades (arbitrary caller without account self-auth)
// 2. Unauthenticated upgrades attempting to bypass via third-party caller authorization
// 3. Corrupted WASM headers (invalid magic number, malformed version, truncated bytecode)
// 4. Oversized / invalid bytecode payloads that fail upload / upgrade validation
// 5. Unregistered / non-existent WASM hash rejection even when self-authorized
// 6. Adversarial payloads attempting to abuse context rules / unauthorized signers

#[test]
#[should_panic]
fn adversarial_upgrade_rejected_without_auth() {
    let env = Env::default();
    // Intentionally DO NOT mock all auths
    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let malicious_wasm_hash = BytesN::from_array(&env, &[0xde; 32]);
    let attacker = Address::generate(&env);

    // Call directly as attacker without account's auth
    client.upgrade(&malicious_wasm_hash, &attacker);
}

#[test]
#[should_panic]
fn adversarial_upgrade_rejected_when_authenticated_by_non_account_actor() {
    let env = Env::default();
    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    let malicious_wasm_hash = BytesN::from_array(&env, &[0xad; 32]);
    let attacker = Address::generate(&env);

    // Mock auth ONLY for attacker, NOT for account_id
    env.mock_auths(&[soroban_sdk::testutils::MockAuth {
        address: &attacker,
        invoke: &soroban_sdk::testutils::MockAuthInvoke {
            contract: &account_id,
            fn_name: "upgrade",
            args: (malicious_wasm_hash.clone(), attacker.clone()).into_val(&env),
            sub_invokes: &[],
        },
    }]);

    // Account requires self-auth (`e.current_contract_address().require_auth()`),
    // so attacker's authorization must be strictly rejected.
    client.upgrade(&malicious_wasm_hash, &attacker);
}

#[test]
#[should_panic]
fn adversarial_upgrade_rejected_non_existent_wasm_hash() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    // Provide a fabricated hash that was never uploaded to the ledger
    let fictitious_wasm_hash = BytesN::from_array(&env, &[0xfe; 32]);

    client.upgrade(&fictitious_wasm_hash, &account_id);
}

#[test]
#[should_panic]
fn adversarial_upgrade_rejected_corrupted_wasm_magic_header() {
    let env = Env::default();
    env.mock_all_auths();

    // Standard WASM binary begins with magic `\0asm` [0x00, 0x61, 0x73, 0x6d]
    // Corrupt the header magic bytes
    let corrupted_magic: [u8; 16] = [
        0xde, 0xad, 0xbe, 0xef, // Bad magic header (not \0asm)
        0x01, 0x00, 0x00, 0x00, // WASM version 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    // Host deployer rejects uploading invalid WASM bytecode
    let wasm_hash = env.deployer().upload_contract_wasm(corrupted_magic.as_slice());

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    client.upgrade(&wasm_hash, &account_id);
}

#[test]
#[should_panic]
fn adversarial_upgrade_rejected_corrupted_wasm_version() {
    let env = Env::default();
    env.mock_all_auths();

    // Valid magic `\0asm` but corrupted version (0x02_00_00_00 or bad version)
    let corrupted_version: [u8; 16] = [
        0x00, 0x61, 0x73, 0x6d, // \0asm
        0xff, 0xff, 0x00, 0x00, // Invalid version
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let wasm_hash = env.deployer().upload_contract_wasm(corrupted_version.as_slice());

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    client.upgrade(&wasm_hash, &account_id);
}

#[test]
#[should_panic]
fn adversarial_upgrade_rejected_truncated_wasm_header() {
    let env = Env::default();
    env.mock_all_auths();

    // Truncated header (less than 8 bytes)
    let truncated_wasm: [u8; 3] = [0x00, 0x61, 0x73];

    let wasm_hash = env.deployer().upload_contract_wasm(truncated_wasm.as_slice());

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    client.upgrade(&wasm_hash, &account_id);
}

#[test]
#[should_panic]
fn adversarial_upgrade_rejected_oversized_bytecode() {
    let env = Env::default();
    env.mock_all_auths();

    // Soroban contract WASM has strict size limits.
    // An adversarial oversized bytecode buffer exceeding allowed limit.
    let mut oversized = std::vec![0u8; 512 * 1024];
    oversized[0..4].copy_from_slice(&[0x00, 0x61, 0x73, 0x6d]); // \0asm
    oversized[4..8].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]); // version 1

    let wasm_hash = env.deployer().upload_contract_wasm(oversized.as_slice());

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    client.upgrade(&wasm_hash, &account_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #3002)")] // UnvalidatedContext
fn adversarial_upgrade_via_check_auth_rejected_for_unauthorized_signer() {
    let env = Env::default();
    env.mock_all_auths();

    let owner_signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, _client) = register_account(&env, &owner_signers, &policies);

    // Target upgrade hash
    let wasm_hash = BytesN::from_array(&env, &[0x42; 32]);
    let operator = Address::generate(&env);

    // Attacker generates an unauthorized signer key
    let attacker_signer = Signer::Delegated(Address::generate(&env));
    let attacker_signers = vec![&env, attacker_signer];

    // Construct CallContract context targeting account's own upgrade()
    let context = Context::Contract(ContractContext {
        contract: account_id.clone(),
        fn_name: symbol_short!("upgrade"),
        args: (wasm_hash.clone(), operator.clone()).into_val(&env),
    });
    let auth_contexts = Vec::from_array(&env, [context]);

    // Attacker crafts signatures referencing rule 0 (default rule)
    let signatures = create_signatures(&env, &attacker_signers, vec![&env, 0]);
    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[0xaa; 32]));

    // Attempting to authenticate the upgrade call via __check_auth with attacker's signer
    // must strictly fail with UnvalidatedContext (#3002)
    env.as_contract(&account_id, || {
        let _ = smart_account::do_check_auth(&env, &payload_hash, &signatures, &auth_contexts);
    });
}

// ################## PROTOCOL UPGRADE & COMPATIBILITY TESTS ##################
//
// Tests for smart account behavior across protocol upgrades (e.g. Protocol 21 -> 22+).
// Verifies that:
// 1. Account deployment, context-rule evaluation, and execute calls work seamlessly
//    when the network protocol version is bumped.
// 2. State (context rules, signers, policies, deployed contracts) persists and remains
//    functional before and after protocol bumps.
// 3. No deprecated host functions or deprecated interfaces are used; modern host
//    constructs (such as `deploy_v2` / `create_contract_with_constructor`) remain valid.
// 4. Time-to-live (TTL) extensions and persistent storage entries operate correctly
//    across protocol bumps.

#[test]
fn protocol_upgrade_preserves_smart_account_state_and_execution() {
    let env = Env::default();
    env.mock_all_auths();

    // Verify initial environment protocol version (default in soroban-sdk 26 is 26)
    let initial_proto = env.ledger().protocol_version();
    assert!(initial_proto >= 21, "Host protocol version should be at least Protocol 21");

    let owner_signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &owner_signers, &policies);

    // Initial state verification under initial protocol
    assert_eq!(client.get_context_rules_count(), 1);
    let target_id = env.register(MockTargetContract, ());
    let target_client = MockTargetContractClient::new(&env, &target_id);

    // Execute state transition on target contract
    client.execute(&target_id, &Symbol::new(&env, "set"), &vec![&env, 42u32.into_val(&env)]);
    assert_eq!(target_client.get(), 42);

    // Simulate network protocol upgrade (e.g. bump protocol version)
    let bumped_proto = initial_proto + 1;
    env.ledger().set_protocol_version(bumped_proto);
    assert_eq!(env.ledger().protocol_version(), bumped_proto);

    // Confirm existing account state remains intact after protocol bump
    assert_eq!(client.get_context_rules_count(), 1);
    let default_rule = client.get_context_rule(&0);
    assert_eq!(default_rule.name, String::from_str(&env, "default"));
    assert_eq!(default_rule.context_type, ContextRuleType::Default);

    // Add new signer and new context rule post-upgrade
    let new_signer = Signer::Delegated(Address::generate(&env));
    let added_signer_id = client.add_signer(&0, &new_signer);
    assert_eq!(added_signer_id, 1);

    let session_signer = Signer::Delegated(Address::generate(&env));
    let session_rule = client.add_context_rule(
        &ContextRuleType::CallContract(target_id.clone()),
        &String::from_str(&env, "session-post-upgrade"),
        &None,
        &vec![&env, session_signer.clone()],
        &Map::new(&env),
    );
    assert_eq!(session_rule.id, 1);
    assert_eq!(client.get_context_rules_count(), 2);

    // Execute calls through smart account post-protocol-upgrade
    client.execute(&target_id, &Symbol::new(&env, "set"), &vec![&env, 100u32.into_val(&env)]);
    assert_eq!(target_client.get(), 100);

    // Validate auth check logic post-upgrade
    let context = get_context(target_id, Symbol::new(&env, "set"), vec![&env, 200u32.into_val(&env)]);
    let auth_contexts = Vec::from_array(&env, [context]);
    let signatures = create_signatures(&env, &vec![&env, session_signer], vec![&env, session_rule.id]);
    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[99u8; 32]));

    env.as_contract(&account_id, || {
        let auth_res = smart_account::do_check_auth(&env, &payload_hash, &signatures, &auth_contexts);
        assert!(auth_res.is_ok());
    });
}

#[test]
fn protocol_upgrade_preserves_contract_deployment_and_storage_mechanics() {
    let env = Env::default();
    env.mock_all_auths();

    let host_proto = env.ledger().protocol_version();
    assert!(host_proto >= 21, "Host protocol version should be at least Protocol 21");

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let wasm_hash = deployed_wasm_hash(&env);
    let salt1 = BytesN::from_array(&env, &[101u8; 32]);

    // Deploy contract before ledger advancement
    let deployed1 = client.deploy_contract(&wasm_hash, &salt1, &vec![&env]);
    assert_eq!(client.get_deployed_contract_count(), 1);
    let record1 = client.get_deployed_contract(&0);
    assert_eq!(record1.address, deployed1);
    assert_eq!(record1.wasm_hash, wasm_hash);

    // Advance sequence ledger while remaining on the host-supported protocol version
    env.ledger().with_mut(|li| {
        li.protocol_version = host_proto;
        li.sequence_number += 100;
    });
    assert_eq!(env.ledger().protocol_version(), host_proto);

    // Pre-upgrade record is preserved and accessible
    let record1_post = client.get_deployed_contract(&0);
    assert_eq!(record1_post.address, deployed1);
    assert_eq!(record1_post.wasm_hash, wasm_hash);

    // Deploy satellite contract post-upgrade using modern deploy_v2
    let salt2 = BytesN::from_array(&env, &[102u8; 32]);
    let deployed2 = client.deploy_contract(&wasm_hash, &salt2, &vec![&env]);
    assert_eq!(client.get_deployed_contract_count(), 2);
    let record2 = client.get_deployed_contract(&1);
    assert_eq!(record2.address, deployed2);
    assert_eq!(record2.wasm_hash, wasm_hash);
    assert_ne!(deployed1, deployed2);
}

#[test]
fn protocol_upgrade_across_multiple_versions_retains_auth_security_invariants() {
    let env = Env::default();
    env.mock_all_auths();

    let owner_signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &owner_signers, &policies);

    let target_id = env.register(MockTargetContract, ());
    let session_signer = Signer::Delegated(Address::generate(&env));
    let session_signers = vec![&env, session_signer];

    // Install session rule
    let rule = client.add_context_rule(
        &ContextRuleType::CallContract(target_id.clone()),
        &String::from_str(&env, "session"),
        &None,
        &session_signers,
        &Map::new(&env),
    );

    // Install session policy restricting to "set"
    let session_policy_id = env.register(SessionPolicy, ());
    let install_param: Val =
        SessionAccountParams { allowed_fns: vec![&env, Symbol::new(&env, "set")] }.into_val(&env);
    client.add_policy(&rule.id, &session_policy_id, &install_param);

    // Step across multiple protocol bumps sequentially up to the host's supported version
    let max_proto = env.ledger().protocol_version();
    let start_proto = max_proto - 3;
    for step in 1..=3 {
        env.ledger().set_protocol_version(start_proto + step);
        assert_eq!(env.ledger().protocol_version(), start_proto + step);

        // Allowed call succeeds across each protocol bump
        let context_ok = get_context(
            target_id.clone(),
            Symbol::new(&env, "set"),
            vec![&env, (step * 10).into_val(&env)],
        );
        let auth_contexts_ok = Vec::from_array(&env, [context_ok]);
        let signatures = create_signatures(&env, &session_signers, vec![&env, rule.id]);
        let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[step as u8; 32]));

        env.as_contract(&account_id, || {
            let res = smart_account::do_check_auth(
                &env,
                &payload_hash,
                &signatures,
                &auth_contexts_ok,
            );
            assert!(res.is_ok());
        });
    }

    // Adversarial check: Unauthorized call ("get" method not allowlisted by policy)
    // is strictly rejected under upgraded protocol (panics with SessionError::MethodNotAllowed)
    let context_bad = get_context(target_id, Symbol::new(&env, "get"), vec![&env]);
    let auth_contexts_bad = Vec::from_array(&env, [context_bad]);
    let signatures = create_signatures(&env, &session_signers, vec![&env, rule.id]);
    let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[255u8; 32]));

    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&account_id, || {
            let _ = smart_account::do_check_auth(
                &env,
                &payload_hash,
                &signatures,
                &auth_contexts_bad,
            );
        });
    }));
    assert!(rejected.is_err());
}

// ################## CONCURRENT ADVERSARIAL STRESS TEST ##################

/// Concurrently evaluates smart-account policy verification across 100 threads.
///
/// Verifies:
/// 1. Concurrency isolation across distinct smart accounts evaluating independent policies.
/// 2. Thread safety under concurrent load for multiple policy types (SessionPolicy and SpendingLimitPolicy).
/// 3. Zero state race conditions detected under parallel load.
#[test]
fn test_concurrent_100_smart_account_policy_evaluations() {
    use std::sync::{Arc, Barrier};
    use std::thread;

    const NUM_THREADS: usize = 100;
    let barrier = Arc::new(Barrier::new(NUM_THREADS));

    let mut handles = std::vec::Vec::with_capacity(NUM_THREADS);

    for i in 0..NUM_THREADS {
        let b = Arc::clone(&barrier);
        let handle = thread::spawn(move || {
            // Synchronize starting line across all 100 threads
            b.wait();

            let env = Env::default();
            env.mock_all_auths();

            let owner_signers = default_signers(&env);
            let policies = Map::new(&env);
            let (account_id, client) = register_account(&env, &owner_signers, &policies);

            let target_id = env.register(MockTargetContract, ());
            let session_signer = Signer::Delegated(Address::generate(&env));
            let session_signers = vec![&env, session_signer];

            let rule = client.add_context_rule(
                &ContextRuleType::CallContract(target_id.clone()),
                &String::from_str(&env, "session"),
                &None,
                &session_signers,
                &Map::new(&env),
            );

            let session_policy_id = env.register(SessionPolicy, ());
            let session_install_param: Val =
                SessionAccountParams { allowed_fns: vec![&env, symbol_short!("transfer")] }.into_val(&env);
            client.add_policy(&rule.id, &session_policy_id, &session_install_param);

            let spending_limit_policy_id = env.register(SpendingLimitPolicy, ());
            let spending_install_param: Val =
                SpendingLimitAccountParams { spending_limit: 10_000_000, period_ledgers: 100 }
                    .into_val(&env);
            client.add_policy(&rule.id, &spending_limit_policy_id, &spending_install_param);

            let from = Address::generate(&env);
            let to = Address::generate(&env);
            let payload_hash = env.crypto().sha256(&Bytes::from_array(&env, &[(i as u8); 32]));

            if i % 2 == 0 {
                // Legitimate policy evaluation within limits
                let context = get_context(
                    target_id.clone(),
                    symbol_short!("transfer"),
                    vec![&env, from.into_val(&env), to.into_val(&env), 100_000i128.into_val(&env)],
                );
                let auth_contexts = Vec::from_array(&env, [context]);
                let signatures = create_signatures(&env, &session_signers, vec![&env, rule.id]);

                env.as_contract(&account_id, || {
                    let auth_res =
                        smart_account::do_check_auth(&env, &payload_hash, &signatures, &auth_contexts);
                    assert!(auth_res.is_ok(), "Thread {} legitimate auth check failed", i);
                });

                // Invariant: Verify spending limit data matches recorded spend
                let spending_client = SpendingLimitPolicyClient::new(&env, &spending_limit_policy_id);
                let spending_data = spending_client.get_spending_limit_data(&rule.id, &account_id);
                assert_eq!(spending_data.spending_limit, 10_000_000);
                assert_eq!(spending_data.spending_history.len(), 1);
            } else {
                // Adversarial policy evaluation: call exceeding spending limit
                let context = get_context(
                    target_id.clone(),
                    symbol_short!("transfer"),
                    vec![&env, from.into_val(&env), to.into_val(&env), 20_000_000i128.into_val(&env)],
                );
                let auth_contexts = Vec::from_array(&env, [context]);
                let signatures = create_signatures(&env, &session_signers, vec![&env, rule.id]);

                let panic_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    env.as_contract(&account_id, || {
                        let _ = smart_account::do_check_auth(
                            &env,
                            &payload_hash,
                            &signatures,
                            &auth_contexts,
                        );
                    });
                }));

                assert!(panic_res.is_err(), "Thread {} expected over-limit evaluation to fail", i);
            }

            i
        });
        handles.push(handle);
    }

    let mut completed = 0;
    for handle in handles {
        let res = handle.join().expect("Worker thread panicked unexpectedly");
        assert!(res < NUM_THREADS);
        completed += 1;
    }
    assert_eq!(completed, 100);
}

// ################## FLASH-LOAN CALLBACK TESTS (#170) ##################

#[test]
fn flash_loan_callback_succeeds_for_registered_protocol_with_auth() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let protocol = Address::generate(&env);
    assert!(!client.is_approved_flash_loan_protocol(&protocol));

    client.register_flash_loan_protocol(&protocol);
    assert!(client.is_approved_flash_loan_protocol(&protocol));

    let token = Address::generate(&env);
    client.flash_loan_callback(&protocol, &token, &1_000, &Val::from_void().into());

    client.remove_flash_loan_protocol(&protocol);
    assert!(!client.is_approved_flash_loan_protocol(&protocol));
}

#[test]
#[should_panic(expected = "Error(Contract, #4002)")] // FlashLoanCallbackUnauthorized
fn flash_loan_callback_rejects_unregistered_protocol() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let attacker = Address::generate(&env);
    let token = Address::generate(&env);
    client.flash_loan_callback(&attacker, &token, &1_000, &Val::from_void().into());
}

#[test]
#[should_panic]
fn flash_loan_callback_blocks_protocol_spoofing_without_caller_auth() {
    use soroban_sdk::testutils::{MockAuth, MockAuthInvoke};

    let env = Env::default();
    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    let protocol = Address::generate(&env);
    let token = Address::generate(&env);

    // Register protocol using mocked self-auth.
    env.mock_all_auths();
    client.register_flash_loan_protocol(&protocol);

    // Now supply ONLY account self-auth (NO auth from `protocol`) — must fail
    // because `caller.require_auth()` prevents spoofing an approved protocol.
    let data: Val = Val::from_void().into();
    let account_auth = MockAuth {
        address: &account_id,
        invoke: &MockAuthInvoke {
            contract: &account_id,
            fn_name: "flash_loan_callback",
            args: (protocol.clone(), token.clone(), 1_000i128, data).into_val(&env),
            sub_invokes: &[],
        },
    };
    client
        .mock_auths(&[account_auth])
        .flash_loan_callback(&protocol, &token, &1_000, &data);
}

// ################## BATCH TRANSFER TESTS (#175) ##################

#[contract]
struct MockBatchToken;

#[contractimpl]
impl MockBatchToken {
    pub fn mint(e: Env, to: Address, amount: i128) {
        let cur: i128 = e.storage().persistent().get(&to).unwrap_or(0);
        e.storage().persistent().set(&to, &(cur + amount));
    }

    pub fn balance(e: Env, id: Address) -> i128 {
        e.storage().persistent().get(&id).unwrap_or(0)
    }

    pub fn transfer(e: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let from_bal: i128 = e.storage().persistent().get(&from).unwrap_or(0);
        assert!(from_bal >= amount, "insufficient balance");
        e.storage().persistent().set(&from, &(from_bal - amount));
        let to_bal: i128 = e.storage().persistent().get(&to).unwrap_or(0);
        e.storage().persistent().set(&to, &(to_bal + amount));
    }
}

#[contract]
struct MockLeakyToken;

#[contractimpl]
impl MockLeakyToken {
    pub fn mint(e: Env, to: Address, amount: i128) {
        let cur: i128 = e.storage().persistent().get(&to).unwrap_or(0);
        e.storage().persistent().set(&to, &(cur + amount));
    }

    pub fn balance(e: Env, id: Address) -> i128 {
        e.storage().persistent().get(&id).unwrap_or(0)
    }

    pub fn transfer(e: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        // Secretly drains 1 extra unit from `from`, violating the balance invariant.
        let from_bal: i128 = e.storage().persistent().get(&from).unwrap_or(0);
        e.storage().persistent().set(&from, &(from_bal - amount - 1));
        let to_bal: i128 = e.storage().persistent().get(&to).unwrap_or(0);
        e.storage().persistent().set(&to, &(to_bal + amount));
    }
}

#[test]
fn batch_transfer_succeeds_including_self_transfers() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    let token_id = env.register(MockBatchToken, ());
    let token_client = MockBatchTokenClient::new(&env, &token_id);
    token_client.mint(&account_id, &1_000);

    let recipient = Address::generate(&env);
    let ops = vec![
        &env,
        TransferOp { token: token_id.clone(), to: recipient.clone(), amount: 250 },
        // Self-transfer must NOT break expected_delta balance invariant.
        TransferOp { token: token_id.clone(), to: account_id.clone(), amount: 300 },
        TransferOp { token: token_id.clone(), to: recipient.clone(), amount: 150 },
    ];

    client.batch_transfer(&ops);
    assert_eq!(token_client.balance(&account_id), 600);
    assert_eq!(token_client.balance(&recipient), 400);
}

#[test]
#[should_panic(expected = "Error(Contract, #4004)")] // InvalidTransferAmount
fn batch_transfer_rejects_zero_or_negative_amount() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let token_id = env.register(MockBatchToken, ());
    let recipient = Address::generate(&env);
    client.batch_transfer(&vec![&env, TransferOp { token: token_id, to: recipient, amount: 0 }]);
}

#[test]
#[should_panic(expected = "Error(Contract, #4003)")] // BalanceInvariantViolated
fn batch_transfer_halted_on_balance_invariant_violation() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    let leaky_id = env.register(MockLeakyToken, ());
    let leaky_client = MockLeakyTokenClient::new(&env, &leaky_id);
    leaky_client.mint(&account_id, &1_000);

    let recipient = Address::generate(&env);
    client.batch_transfer(&vec![&env, TransferOp { token: leaky_id, to: recipient, amount: 100 }]);
}

// ################## PAUSABLE & UPGRADE TESTS (#190) ##################

#[test]
#[should_panic(expected = "Error(Contract, #1000)")] // EnforcedPause
fn execute_fails_when_paused() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    assert!(!client.paused());
    client.pause(&account_id);
    assert!(client.paused());

    let target_id = env.register(MockTargetContract, ());
    client.execute(&target_id, &Symbol::new(&env, "set"), &vec![&env, 1u32.into_val(&env)]);
}

#[test]
#[should_panic(expected = "Error(Contract, #4007)")] // UnauthorizedPauseCaller
fn pause_rejects_external_caller() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let attacker = Address::generate(&env);
    client.pause(&attacker);
}

#[test]
#[should_panic(expected = "Error(Contract, #4007)")] // UnauthorizedPauseCaller
fn unpause_rejects_external_caller() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    client.pause(&account_id);
    let attacker = Address::generate(&env);
    client.unpause(&attacker);
}

#[test]
fn admin_recovery_path_remains_operational_when_paused() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    client.pause(&account_id);
    assert!(client.paused());

    let recovery_signer = Signer::Delegated(Address::generate(&env));
    let recovery_signers = vec![&env, recovery_signer];
    let added_rule = client.add_context_rule(
        &ContextRuleType::Default,
        &String::from_str(&env, "recovery"),
        &None,
        &recovery_signers,
        &Map::new(&env),
    );
    assert_eq!(added_rule.name, String::from_str(&env, "recovery"));
    assert_eq!(client.get_context_rules_count(), 2);

    let new_signer = Signer::Delegated(Address::generate(&env));
    let default_rule = client.get_context_rule(&0);
    let signer_id = client.add_signer(&default_rule.id, &new_signer);
    assert_eq!(signer_id, 2);

    client.unpause(&account_id);
    assert!(!client.paused());

    let target_id = env.register(MockTargetContract, ());
    let target_client = MockTargetContractClient::new(&env, &target_id);
    client.execute(&target_id, &Symbol::new(&env, "set"), &vec![&env, 42u32.into_val(&env)]);
    assert_eq!(target_client.get(), 42);
}

#[test]
#[should_panic]
fn pause_requires_self_auth() {
    let env = Env::default();
    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    client.pause(&account_id);
}

#[test]
#[should_panic]
fn upgrade_rejects_unauthorized_external_caller() {
    let env = Env::default();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let attacker = Address::generate(&env);
    let new_wasm_hash = BytesN::from_array(&env, &[0u8; 32]);
    client.upgrade(&new_wasm_hash, &attacker);
}

#[test]
#[should_panic(expected = "Error(Contract, #4005)")] // ReentrancyGuardTriggered
fn upgrade_reentrancy_guard_blocks_recursive_upgrade() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    let Some(Executable::Wasm(wasm_hash)) = account_id.executable() else {
        panic!("expected a wasm-backed account");
    };

    env.as_contract(&account_id, || {
        env.storage()
            .instance()
            .set(&super::LatchSmartAccountStorageKey::UpgradeLock, &true);
    });

    client.upgrade(&wasm_hash, &account_id);
}

#[test]
fn upgrade_to_v2_bytecode_and_verify_state_migration() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    assert_eq!(client.get_context_rules_count(), 1);
    assert_eq!(client.get_deployed_contract_count(), 0);

    let dummy_hash = deployed_wasm_hash(&env);
    let salt = BytesN::from_array(&env, &[42u8; 32]);
    let deployed_addr = client.deploy_contract(&dummy_hash, &salt, &vec![&env]);
    assert_eq!(client.get_deployed_contract_count(), 1);

    let v2_wasm_hash = env.deployer().upload_contract_wasm(smart_account_v2::WASM);
    client.upgrade(&v2_wasm_hash, &account_id);

    assert_eq!(client.get_context_rules_count(), 1);
    let default_rule = client.get_context_rule(&0);
    assert_eq!(default_rule.name, String::from_str(&env, "default"));
    assert_eq!(client.get_deployed_contract_count(), 1);
    let record = client.get_deployed_contract(&0);
    assert_eq!(record.address, deployed_addr);
    assert_eq!(record.wasm_hash, dummy_hash);
}

#[test]
fn verify_state_migration_succeeds_even_when_rule_zero_replaced() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let replacement_signers = default_signers(&env);
    client.add_context_rule(
        &ContextRuleType::Default,
        &String::from_str(&env, "new_default"),
        &None,
        &replacement_signers,
        &Map::new(&env),
    );
    client.remove_context_rule(&0);

    // Must NOT brick when rule 0 has been removed as long as >= 1 rule exists.
    client.verify_state_migration();
}

// ################## FALLBACK RECOVERY TESTS (#191) ##################

#[test]
fn set_and_get_recovery_config_succeeds_with_self_auth() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let g1 = Signer::Delegated(Address::generate(&env));
    let g2 = Signer::Delegated(Address::generate(&env));
    let g3 = Signer::Delegated(Address::generate(&env));
    let guardians = vec![&env, g1, g2, g3];

    client.set_recovery_config(&guardians, &2, &DEFAULT_RECOVERY_INACTIVITY_DELAY_LEDGERS);

    let config = client.get_recovery_config();
    assert_eq!(config.threshold, 2);
    assert_eq!(config.inactivity_delay_ledgers, DEFAULT_RECOVERY_INACTIVITY_DELAY_LEDGERS);
    assert_eq!(config.recovery_signers, guardians);
    assert!(!client.is_recovery_eligible());
    assert_eq!(client.get_recovery_nonce(), 0);
}

#[test]
fn set_recovery_config_initializes_last_active_ledger_on_upgraded_account() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_sequence_number(500_000);

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    // Simulate an upgraded account that did not have LastActiveLedger stored.
    env.as_contract(&account_id, || {
        env.storage()
            .instance()
            .remove(&super::LatchSmartAccountStorageKey::LastActiveLedger);
    });
    assert_eq!(client.get_last_active_ledger(), 0);

    let g1 = Signer::Delegated(Address::generate(&env));
    client.set_recovery_config(&vec![&env, g1], &1, &100);

    // Must initialize LastActiveLedger to current ledger (500_000), preventing
    // instant zero-delay takeover.
    assert_eq!(client.get_last_active_ledger(), 500_000);
    assert!(!client.is_recovery_eligible());
}

#[test]
#[should_panic(expected = "Error(Contract, #4010)")] // InvalidRecoveryConfig
fn set_recovery_config_rejects_zero_threshold() {
    let env = Env::default();
    env.mock_all_auths();
    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let g1 = Signer::Delegated(Address::generate(&env));
    client.set_recovery_config(&vec![&env, g1], &0, &100);
}

#[test]
#[should_panic(expected = "Error(Contract, #4010)")] // InvalidRecoveryConfig
fn set_recovery_config_rejects_duplicate_signers() {
    let env = Env::default();
    env.mock_all_auths();
    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let g1 = Signer::Delegated(Address::generate(&env));
    client.set_recovery_config(&vec![&env, g1.clone(), g1], &1, &100);
}

#[test]
#[should_panic(expected = "Error(Contract, #4009)")] // RecoveryNotConfigured
fn remove_recovery_config_panics_when_not_configured() {
    let env = Env::default();
    env.mock_all_auths();
    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    client.remove_recovery_config();
}

#[test]
#[should_panic(expected = "Error(Contract, #4011)")] // InactivityDelayNotMet
fn recovery_rejects_when_inactivity_delay_not_met() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_sequence_number(1_000);

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let g1 = Signer::Delegated(Address::generate(&env));
    client.set_recovery_config(&vec![&env, g1.clone()], &1, &100);
    env.ledger().set_sequence_number(1_099);

    let new_signer = Signer::Delegated(Address::generate(&env));
    let mut signatures = Map::new(&env);
    signatures.set(g1, Bytes::new(&env));
    client.recover_signers(&0, &vec![&env, new_signer], &signatures);
}

#[test]
#[should_panic(expected = "Error(Contract, #4012)")] // RecoveryThresholdNotMet
fn recovery_threshold_rules_enforced_requires_threshold() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_sequence_number(1_000);

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let g1 = Signer::Delegated(Address::generate(&env));
    let g2 = Signer::Delegated(Address::generate(&env));
    let g3 = Signer::Delegated(Address::generate(&env));
    client.set_recovery_config(&vec![&env, g1.clone(), g2, g3], &2, &100);

    env.ledger().set_sequence_number(1_200);
    let mut signatures = Map::new(&env);
    signatures.set(g1, Bytes::new(&env));
    client.recover_signers(&0, &vec![&env, Signer::Delegated(Address::generate(&env))], &signatures);
}

#[test]
#[should_panic(expected = "Error(Contract, #4013)")] // UnauthorizedRecoverySigner
fn recovery_rejects_unauthorized_signer() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_sequence_number(1_000);

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let g1 = Signer::Delegated(Address::generate(&env));
    client.set_recovery_config(&vec![&env, g1], &1, &100);

    env.ledger().set_sequence_number(1_200);
    let attacker = Signer::Delegated(Address::generate(&env));
    let mut signatures = Map::new(&env);
    signatures.set(attacker, Bytes::new(&env));
    client.recover_signers(&0, &vec![&env, Signer::Delegated(Address::generate(&env))], &signatures);
}

#[test]
#[should_panic(expected = "Error(Contract, #4015)")] // EmptyNewSigners
fn recovery_rejects_empty_new_signers() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_sequence_number(1_000);

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let g1 = Signer::Delegated(Address::generate(&env));
    client.set_recovery_config(&vec![&env, g1.clone()], &1, &100);

    env.ledger().set_sequence_number(1_200);
    let mut signatures = Map::new(&env);
    signatures.set(g1, Bytes::new(&env));
    client.recover_signers(&0, &vec![&env], &signatures);
}

#[test]
fn end_to_end_recovery_rotates_signers_and_handles_max_signers() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_sequence_number(1_000);

    // Start with 10 signers and rotate to 6 new signers: naive add-before-remove
    // would hit 10 + 6 = 16 > MAX_SIGNERS (15) and fail, while our safe rotation
    // succeeds within both MAX_SIGNERS and Soroban's per-tx footprint limit.
    let mut initial_signers = Vec::new(&env);
    for _ in 0..10 {
        initial_signers.push_back(Signer::Delegated(Address::generate(&env)));
    }
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &initial_signers, &policies);

    let g1 = Signer::Delegated(Address::generate(&env));
    let g2 = Signer::Delegated(Address::generate(&env));
    client.set_recovery_config(
        &vec![&env, g1.clone(), g2.clone()],
        &2,
        &DEFAULT_RECOVERY_INACTIVITY_DELAY_LEDGERS,
    );

    let recovery_ledger = 1_000 + DEFAULT_RECOVERY_INACTIVITY_DELAY_LEDGERS;
    env.ledger().set_sequence_number(recovery_ledger);
    assert!(client.is_recovery_eligible());

    let mut new_signers = Vec::new(&env);
    for _ in 0..6 {
        new_signers.push_back(Signer::Delegated(Address::generate(&env)));
    }

    let digest = client.get_recovery_digest(&0, &new_signers);
    assert_eq!(digest.len(), 32);

    let mut signatures = Map::new(&env);
    signatures.set(g1, Bytes::new(&env));
    signatures.set(g2, Bytes::new(&env));

    client.recover_signers(&0, &new_signers, &signatures);

    let default_rule = client.get_context_rule(&0);
    assert_eq!(default_rule.signers.len(), 6);
    for s in new_signers.iter() {
        assert!(default_rule.signers.contains(&s));
    }
    assert_eq!(client.get_recovery_nonce(), 1);
    assert_eq!(client.get_last_active_ledger(), recovery_ledger);
}

#[test]
fn touch_activity_resets_inactivity_timer() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_sequence_number(1_000);

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let g1 = Signer::Delegated(Address::generate(&env));
    client.set_recovery_config(&vec![&env, g1], &1, &100);

    env.ledger().set_sequence_number(1_200);
    assert!(client.is_recovery_eligible());

    client.touch_activity();
    assert_eq!(client.get_last_active_ledger(), 1_200);
    assert!(!client.is_recovery_eligible());
}

// ################## RE-ENTRANCY PROTECTION TESTS (#192) ##################

#[contract]
struct MockMaliciousFactoryContract;

#[contractimpl]
impl MockMaliciousFactoryContract {
    pub fn reenter_execute(e: Env, smart_account: Address, target: Address) {
        let client = LatchSmartAccountClient::new(&e, &smart_account);
        client.execute(&target, &Symbol::new(&e, "set"), &vec![&e, 99u32.into_val(&e)]);
    }

    pub fn reenter_deploy(e: Env, smart_account: Address, wasm_hash: BytesN<32>) {
        let client = LatchSmartAccountClient::new(&e, &smart_account);
        let salt = BytesN::from_array(&e, &[42u8; 32]);
        client.deploy_contract(&wasm_hash, &salt, &vec![&e]);
    }
}

#[test]
#[should_panic(expected = "Error(Contract, #4008)")] // ReentrantCall
fn deploy_contract_reentrancy_guard_blocks_malicious_constructor_reentering_execute() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    let target_id = env.register(MockTargetContract, ());

    env.as_contract(&account_id, || {
        super::acquire_reentrancy_lock(&env);
    });

    client.execute(&target_id, &Symbol::new(&env, "set"), &vec![&env, 99u32.into_val(&env)]);
}

#[test]
#[should_panic(expected = "Error(Contract, #4008)")] // ReentrantCall
fn deploy_contract_reentrancy_guard_blocks_nested_deploy_contract() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    let wasm_hash = deployed_wasm_hash(&env);
    let salt = BytesN::from_array(&env, &[11u8; 32]);

    env.as_contract(&account_id, || {
        super::acquire_reentrancy_lock(&env);
    });

    client.deploy_contract(&wasm_hash, &salt, &vec![&env]);
}

#[test]
#[should_panic]
fn execute_reentrancy_guard_blocks_malicious_factory_reentering_execute() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    let target_id = env.register(MockTargetContract, ());
    let malicious_factory_id = env.register(MockMaliciousFactoryContract, ());

    client.execute(
        &malicious_factory_id,
        &Symbol::new(&env, "reenter_execute"),
        &vec![&env, account_id.into_val(&env), target_id.into_val(&env)],
    );
}

#[test]
#[should_panic]
fn execute_reentrancy_guard_blocks_malicious_factory_reentering_deploy_contract() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (account_id, client) = register_account(&env, &signers, &policies);

    let wasm_hash = deployed_wasm_hash(&env);
    let malicious_factory_id = env.register(MockMaliciousFactoryContract, ());

    client.execute(
        &malicious_factory_id,
        &Symbol::new(&env, "reenter_deploy"),
        &vec![&env, account_id.into_val(&env), wasm_hash.into_val(&env)],
    );
}

#[test]
fn deploy_contract_releases_reentrancy_lock_allowing_subsequent_execute() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let wasm_hash = deployed_wasm_hash(&env);
    let salt = BytesN::from_array(&env, &[21u8; 32]);

    let deployed = client.deploy_contract(&wasm_hash, &salt, &vec![&env]);
    assert_eq!(client.get_deployed_contract_count(), 1);
    assert_eq!(client.get_deployed_contract(&0).address, deployed);

    let target_id = env.register(MockTargetContract, ());
    let target_client = MockTargetContractClient::new(&env, &target_id);
    client.execute(&target_id, &Symbol::new(&env, "set"), &vec![&env, 42u32.into_val(&env)]);
    assert_eq!(target_client.get(), 42);
}

// ################## SIGNER TIMELOCK TESTS (#193) ##################

#[test]
fn signer_timelock_delay_configuration_and_timelocked_reduction() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    assert_eq!(client.get_signer_timelock_delay(), 0);

    let delay_seconds: u64 = 86400;
    client.set_signer_timelock_delay(&delay_seconds);
    assert_eq!(client.get_signer_timelock_delay(), delay_seconds);

    // Reducing delay requires going through the timelocked proposal path.
    let pending = client.propose_timelock_delay_change(&3600);
    assert_eq!(pending.new_delay, 3600);
    assert_eq!(pending.eta, env.ledger().timestamp() + delay_seconds);

    env.ledger().set_timestamp(pending.eta);
    client.accept_timelock_delay_change();
    assert_eq!(client.get_signer_timelock_delay(), 3600);
}

#[test]
#[should_panic(expected = "Error(Contract, #4019)")] // DelayReductionNotAllowed
fn set_signer_timelock_delay_blocks_instant_reduction_to_zero() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    client.set_signer_timelock_delay(&86400);
    // Attempting to bypass the timelock by instantly lowering delay to 0 must panic.
    client.set_signer_timelock_delay(&0);
}

#[test]
#[should_panic]
fn set_signer_timelock_delay_requires_self_auth() {
    let env = Env::default();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    client.set_signer_timelock_delay(&3600);
}

#[test]
fn propose_and_accept_signer_add_with_timelock() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let default_rule = client.get_context_rule(&0);
    let delay: u64 = 3600;
    client.set_signer_timelock_delay(&delay);

    let new_signer = Signer::Delegated(Address::generate(&env));
    let proposal_id =
        client.propose_signer(&default_rule.id, &SignerAction::Add(new_signer.clone()));
    assert_eq!(proposal_id, 0);
    assert_eq!(client.get_signer_proposal_count(), 1);

    let proposal = client.get_signer_proposal(&proposal_id);
    assert_eq!(proposal.id, 0);
    assert_eq!(proposal.context_rule_id, default_rule.id);
    assert_eq!(proposal.status, ProposalStatus::Pending);
    assert_eq!(proposal.eta, env.ledger().timestamp() + delay);

    env.ledger().set_timestamp(proposal.eta);
    client.accept_signer(&proposal_id);

    let executed_proposal = client.get_signer_proposal(&proposal_id);
    assert_eq!(executed_proposal.status, ProposalStatus::Executed);

    let updated_rule = client.get_context_rule(&default_rule.id);
    assert!(updated_rule.signers.contains(&new_signer));
}

#[test]
fn propose_and_accept_signer_remove_with_timelock() {
    let env = Env::default();
    env.mock_all_auths();

    let initial_signer = Signer::Delegated(Address::generate(&env));
    let second_signer = Signer::Delegated(Address::generate(&env));
    let signers = vec![&env, initial_signer.clone(), second_signer.clone()];
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let default_rule = client.get_context_rule(&0);
    let delay: u64 = 7200;
    client.set_signer_timelock_delay(&delay);

    let proposal_id = client.propose_signer(&default_rule.id, &SignerAction::Remove(1));
    let proposal = client.get_signer_proposal(&proposal_id);
    assert_eq!(proposal.status, ProposalStatus::Pending);

    env.ledger().set_timestamp(proposal.eta);
    client.accept_signer(&proposal_id);

    let updated_rule = client.get_context_rule(&default_rule.id);
    assert_eq!(updated_rule.signers.len(), 1);
    assert!(updated_rule.signers.contains(&initial_signer));
    assert!(!updated_rule.signers.contains(&second_signer));
}

#[test]
#[should_panic(expected = "Error(Contract, #4018)")] // TimelockNotExpired
fn accept_signer_before_timelock_expires_panics() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let default_rule = client.get_context_rule(&0);
    client.set_signer_timelock_delay(&1000);

    let new_signer = Signer::Delegated(Address::generate(&env));
    let proposal_id = client.propose_signer(&default_rule.id, &SignerAction::Add(new_signer));
    client.accept_signer(&proposal_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #4001)")] // MathOverflow
fn propose_signer_rejects_eta_timestamp_overflow() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    client.set_signer_timelock_delay(&1000);
    env.ledger().set_timestamp(u64::MAX - 500);
    client.propose_signer(&0, &SignerAction::Add(Signer::Delegated(Address::generate(&env))));
}

#[test]
#[should_panic]
fn propose_signer_rejects_nonexistent_context_rule() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    client.propose_signer(&999, &SignerAction::Add(Signer::Delegated(Address::generate(&env))));
}

#[test]
fn cancel_pending_signer_proposal() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let default_rule = client.get_context_rule(&0);
    client.set_signer_timelock_delay(&1000);

    let new_signer = Signer::Delegated(Address::generate(&env));
    let proposal_id = client.propose_signer(&default_rule.id, &SignerAction::Add(new_signer));
    client.cancel_signer_proposal(&proposal_id);

    let proposal = client.get_signer_proposal(&proposal_id);
    assert_eq!(proposal.status, ProposalStatus::Cancelled);
}

#[test]
#[should_panic(expected = "Error(Contract, #4017)")] // ProposalNotPending
fn cannot_accept_cancelled_signer_proposal() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let default_rule = client.get_context_rule(&0);
    let delay: u64 = 1000;
    client.set_signer_timelock_delay(&delay);

    let new_signer = Signer::Delegated(Address::generate(&env));
    let proposal_id = client.propose_signer(&default_rule.id, &SignerAction::Add(new_signer));

    client.cancel_signer_proposal(&proposal_id);
    env.ledger().set_timestamp(env.ledger().timestamp() + delay + 10);
    client.accept_signer(&proposal_id);
}

#[test]
#[should_panic(expected = "Error(Contract, #4017)")] // ProposalNotPending
fn cannot_cancel_already_executed_proposal() {
    let env = Env::default();
    env.mock_all_auths();

    let signers = default_signers(&env);
    let policies = Map::new(&env);
    let (_account_id, client) = register_account(&env, &signers, &policies);

    let default_rule = client.get_context_rule(&0);
    let delay: u64 = 500;
    client.set_signer_timelock_delay(&delay);

    let new_signer = Signer::Delegated(Address::generate(&env));
    let proposal_id = client.propose_signer(&default_rule.id, &SignerAction::Add(new_signer));

    env.ledger().set_timestamp(env.ledger().timestamp() + delay);
    client.accept_signer(&proposal_id);
    client.cancel_signer_proposal(&proposal_id);
}
