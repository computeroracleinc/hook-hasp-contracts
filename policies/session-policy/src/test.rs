extern crate std;

use soroban_sdk::{
    auth::{Context, ContractContext, ContractExecutable, CreateContractHostFnContext},
    contract, symbol_short,
    testutils::{Address as _, Events, Ledger as _},
    vec, Address, BytesN, Env, String, Vec,
};
use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

use crate::allowlist::*;

#[contract]
struct MockContract;

fn create_context_rule(e: &Env) -> ContextRule {
    let signer = Address::generate(e);
    let mut signers = Vec::new(e);
    signers.push_back(Signer::Delegated(signer));

    ContextRule {
        id: 1,
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

#[test]
fn create_session_accepts_expiry_at_max_duration() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let current_ledger = e.ledger().sequence();
    let mut context_rule = create_context_rule(&e);
    context_rule.valid_until = Some(current_ledger + MAX_SESSION_DURATION);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let params = SessionAccountParams { allowed_fns: vec![&e, symbol_short!("set")] };
        create_session(&e, &params, &context_rule, &smart_account);

        assert!(!get_allowed_fns(&e, context_rule.id, &smart_account).is_empty());
    });
}

#[test]
fn create_session_accepts_rule_without_expiry() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let params = SessionAccountParams { allowed_fns: vec![&e, symbol_short!("set")] };
        create_session(&e, &params, &context_rule, &smart_account);

        assert_eq!(context_rule.valid_until, None);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn create_session_rejects_expiry_beyond_max_duration() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let current_ledger = e.ledger().sequence();
    let mut context_rule = create_context_rule(&e);
    context_rule.valid_until = Some(current_ledger + MAX_SESSION_DURATION + 1);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let params = SessionAccountParams { allowed_fns: vec![&e, symbol_short!("set")] };
        create_session(&e, &params, &context_rule, &smart_account);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn install_rejects_expiry_beyond_max_duration() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let current_ledger = e.ledger().sequence();
    let mut context_rule = create_context_rule(&e);
    context_rule.valid_until = Some(current_ledger + MAX_SESSION_DURATION * 2);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let params = SessionAccountParams { allowed_fns: vec![&e, symbol_short!("set")] };
        install(&e, &params, &context_rule, &smart_account);
    });
}

#[test]
fn expiry_within_max_duration_is_measured_against_current_ledger() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let mut context_rule = create_context_rule(&e);
    let expiry = e.ledger().sequence() + MAX_SESSION_DURATION;
    context_rule.valid_until = Some(expiry);

    e.ledger().with_mut(|li| {
        li.sequence_number = expiry - MAX_SESSION_DURATION / 2;
    });
    e.mock_all_auths();

    e.as_contract(&address, || {
        let params = SessionAccountParams { allowed_fns: vec![&e, symbol_short!("set")] };
        install(&e, &params, &context_rule, &smart_account);
    });
}
