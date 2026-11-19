extern crate std;

use soroban_sdk::{
    auth::{Context, ContractContext, ContractExecutable, CreateContractHostFnContext},
    contract, symbol_short,
    testutils::{Address as _, Events},
    vec, Address, BytesN, Env, String, Vec,
};
use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

use crate::{allowlist::*, SessionPolicy, SessionPolicyClient};

#[contract]
struct MockContract;

fn create_context_rule(e: &Env) -> ContextRule {
    create_context_rule_with_id(e, 1)
}

fn create_context_rule_with_id(e: &Env, id: u32) -> ContextRule {
    let signer = Address::generate(e);
    let mut signers = Vec::new(e);
    signers.push_back(Signer::Delegated(signer));

    ContextRule {
        id,
        context_type: ContextRuleType::CallContract(Address::generate(e)),
        name: String::from_str(e, "session"),
        signers,
        signer_ids: Vec::new(e),
        policies: Vec::new(e),
        policy_ids: Vec::new(e),
        valid_until: None,
    }
}

fn create_contract_context(e: &Env, fn_name: soroban_sdk::Symbol) -> Context {
    Context::Contract(ContractContext {
        contract: Address::generate(e),
        fn_name,
        args: Vec::new(e),
    })
}

#[test]
fn install_success() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let context_rule = create_context_rule(&e);
        let params = SessionAccountParams {
            allowed_fns: vec![&e, symbol_short!("set"), symbol_short!("get")],
        };

        install(&e, &params, &context_rule, &smart_account);

        let allowed_fns = get_allowed_fns(&e, context_rule.id, &smart_account);
        assert_eq!(allowed_fns.len(), 2);
        assert!(allowed_fns.contains(&symbol_short!("set")));

        // Verify install event was emitted
        assert_eq!(e.events().all().events().len(), 1);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn install_rejects_default_rule() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let mut context_rule = create_context_rule(&e);
        context_rule.context_type = ContextRuleType::Default;
        let params = SessionAccountParams { allowed_fns: vec![&e, symbol_short!("set")] };

        install(&e, &params, &context_rule, &smart_account);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn install_rejects_create_contract_rule() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let mut context_rule = create_context_rule(&e);
        context_rule.context_type =
            ContextRuleType::CreateContract(BytesN::from_array(&e, &[0u8; 32]));
        let params = SessionAccountParams { allowed_fns: vec![&e, symbol_short!("set")] };

        install(&e, &params, &context_rule, &smart_account);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn install_rejects_empty_allowed_fns() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let context_rule = create_context_rule(&e);
        let params = SessionAccountParams { allowed_fns: Vec::new(&e) };

        install(&e, &params, &context_rule, &smart_account);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn install_rejects_too_many_allowed_fns() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let context_rule = create_context_rule(&e);
        let mut allowed_fns = Vec::new(&e);
        for i in 0..(MAX_ALLOWED_FNS + 1) {
            allowed_fns.push_back(soroban_sdk::Symbol::new(&e, &std::format!("fn{}", i)));
        }
        let params = SessionAccountParams { allowed_fns };

        install(&e, &params, &context_rule, &smart_account);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn install_rejects_already_installed() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);

    e.mock_all_auths();

    let context_rule = create_context_rule(&e);
    let params = SessionAccountParams { allowed_fns: vec![&e, symbol_short!("set")] };

    e.as_contract(&address, || {
        install(&e, &params, &context_rule, &smart_account);
    });

    e.as_contract(&address, || {
        install(&e, &params, &context_rule, &smart_account);
    });
}

#[test]
fn enforce_allows_whitelisted_fn() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let params = SessionAccountParams { allowed_fns: vec![&e, symbol_short!("set")] };
        install(&e, &params, &context_rule, &smart_account);
    });

    e.as_contract(&address, || {
        let context = create_contract_context(&e, symbol_short!("set"));
        enforce(&e, &context, &context_rule.signers, &context_rule, &smart_account);

        assert!(!e.events().all().events().is_empty());
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn enforce_rejects_non_whitelisted_fn() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let params = SessionAccountParams { allowed_fns: vec![&e, symbol_short!("set")] };
        install(&e, &params, &context_rule, &smart_account);
    });

    e.as_contract(&address, || {
        let context = create_contract_context(&e, symbol_short!("delete"));
        enforce(&e, &context, &context_rule.signers, &context_rule, &smart_account);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn enforce_rejects_create_contract_context() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let params = SessionAccountParams { allowed_fns: vec![&e, symbol_short!("set")] };
        install(&e, &params, &context_rule, &smart_account);
    });

    e.as_contract(&address, || {
        let context = Context::CreateContractHostFn(CreateContractHostFnContext {
            salt: BytesN::from_array(&e, &[1u8; 32]),
            executable: ContractExecutable::Wasm(BytesN::from_array(&e, &[1u8; 32])),
        });

        enforce(&e, &context, &context_rule.signers, &context_rule, &smart_account);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn enforce_rejects_when_not_installed() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let context = create_contract_context(&e, symbol_short!("set"));
        enforce(&e, &context, &context_rule.signers, &context_rule, &smart_account);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn enforce_rejects_empty_authenticated_signers() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let params = SessionAccountParams { allowed_fns: vec![&e, symbol_short!("set")] };
        install(&e, &params, &context_rule, &smart_account);
    });

    e.as_contract(&address, || {
        let context = create_contract_context(&e, symbol_short!("set"));
        enforce(&e, &context, &Vec::new(&e), &context_rule, &smart_account);
    });
}

#[test]
fn uninstall_success() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let params = SessionAccountParams { allowed_fns: vec![&e, symbol_short!("set")] };
        install(&e, &params, &context_rule, &smart_account);
    });

    e.as_contract(&address, || {
        uninstall(&e, &context_rule, &smart_account);

        assert_eq!(e.events().all().events().len(), 1);
    });

    e.as_contract(&address, || {
        let key = SessionStorageKey::AccountContext(smart_account.clone(), context_rule.id);
        assert!(!e.storage().persistent().has(&key));
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn uninstall_rejects_when_not_installed() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        uninstall(&e, &context_rule, &smart_account);
    });
}

#[test]
fn get_allowed_fns_returns_installed_value() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let params = SessionAccountParams {
            allowed_fns: vec![&e, symbol_short!("set"), symbol_short!("get")],
        };
        install(&e, &params, &context_rule, &smart_account);
    });

    e.as_contract(&address, || {
        let allowed_fns = get_allowed_fns(&e, context_rule.id, &smart_account);
        assert_eq!(allowed_fns, vec![&e, symbol_short!("set"), symbol_short!("get")]);
    });
}

// ################## SESSION REVOCATION TESTS ##################
//
// Each authorization-requiring operation gets its own `as_contract` frame:
// `mock_all_auths` authorizes one frame at a time, so chaining two
// `require_auth` calls in a single frame fails with `Auth, ExistingValue`.

fn install_session(e: &Env, policy: &Address, smart_account: &Address, rule: &ContextRule) {
    let params = SessionAccountParams { allowed_fns: vec![e, symbol_short!("set")] };
    e.as_contract(policy, || install(e, &params, rule, smart_account));
}

fn revoke_id(e: &Env, policy: &Address, smart_account: &Address, session_id: u32) {
    e.as_contract(policy, || revoke_session(e, session_id, smart_account));
}

#[test]
fn revoke_session_marks_session_as_revoked() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    install_session(&e, &address, &smart_account, &context_rule);
    e.as_contract(&address, || {
        assert!(!is_revoked(&e, context_rule.id, &smart_account));
    });

    e.as_contract(&address, || {
        revoke_session(&e, context_rule.id, &smart_account);

        assert!(is_revoked(&e, context_rule.id, &smart_account));
        assert_eq!(e.events().all().events().len(), 1);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn revoked_session_enforcement_fails_immediately() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);
    let context = create_contract_context(&e, symbol_short!("set"));

    e.mock_all_auths();

    install_session(&e, &address, &smart_account, &context_rule);
    e.as_contract(&address, || {
        enforce(&e, &context, &context_rule.signers, &context_rule, &smart_account);
    });

    revoke_id(&e, &address, &smart_account, context_rule.id);

    e.as_contract(&address, || {
        enforce(&e, &context, &context_rule.signers, &context_rule, &smart_account);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn revoke_session_rejects_unknown_session() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);

    e.mock_all_auths();

    revoke_id(&e, &address, &smart_account, 42);
}

#[test]
#[should_panic(expected = "Error(Contract, #7)")]
fn revoke_session_rejects_duplicate_revocation() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    install_session(&e, &address, &smart_account, &context_rule);
    revoke_id(&e, &address, &smart_account, context_rule.id);
    revoke_id(&e, &address, &smart_account, context_rule.id);
}

#[test]
fn revocation_bitmap_isolates_sessions_and_accounts() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let other_account = Address::generate(&e);
    let first = create_context_rule_with_id(&e, 1);
    let same_word = create_context_rule_with_id(&e, 2);
    let next_word = create_context_rule_with_id(&e, REVOCATION_BITS_PER_WORD);

    e.mock_all_auths();

    for rule in [&first, &same_word, &next_word] {
        install_session(&e, &address, &smart_account, rule);
    }
    install_session(&e, &address, &other_account, &first);
    revoke_id(&e, &address, &smart_account, first.id);
    revoke_id(&e, &address, &smart_account, next_word.id);

    e.as_contract(&address, || {
        assert!(is_revoked(&e, first.id, &smart_account));
        assert!(is_revoked(&e, next_word.id, &smart_account));
        assert!(!is_revoked(&e, same_word.id, &smart_account));
        assert!(!is_revoked(&e, first.id, &other_account));

        let context = create_contract_context(&e, symbol_short!("set"));
        enforce(&e, &context, &same_word.signers, &same_word, &smart_account);
    });
}

#[test]
fn revoke_session_requires_smart_account_auth() {
    let e = Env::default();
    let address = e.register(SessionPolicy, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);
    let client = SessionPolicyClient::new(&e, &address);

    e.mock_all_auths();
    install_session(&e, &address, &smart_account, &context_rule);

    e.set_auths(&[]);
    assert!(client.try_revoke_session(&context_rule.id, &smart_account).is_err());
    e.as_contract(&address, || {
        assert!(!is_revoked(&e, context_rule.id, &smart_account));
    });
}
