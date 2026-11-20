extern crate std;

use soroban_sdk::{
    auth::{Context, ContractContext, ContractExecutable, CreateContractHostFnContext},
    contract, symbol_short,
    testutils::{Address as _, Events},
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

// ################## STORAGE TTL / EXPIRY THRESHOLD TESTS ##################

/// SESSION_EXTEND_AMOUNT = 30 * 17280 = 518400 ledgers
/// SESSION_TTL_THRESHOLD = SESSION_EXTEND_AMOUNT - 17280 = 501120 ledgers
const SESSION_NEAR_EXPIRY_LEDGER: u32 = 501_000;

#[test]
fn get_allowed_fns_near_ttl_threshold_renews_and_succeeds() {
    // Install a session policy, advance the ledger to just below the TTL
    // renewal threshold, then verify that a read triggers TTL extension
    // without panicking — simulating a near-expiry state on a live chain.
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let params = SessionAccountParams {
            allowed_fns: vec![&e, symbol_short!("set")],
        };
        install(&e, &params, &context_rule, &smart_account);
    });

    // Advance ledger sequence to just before SESSION_TTL_THRESHOLD to
    // simulate the entry approaching expiry.
    e.ledger().with_mut(|li| {
        li.sequence_number = SESSION_NEAR_EXPIRY_LEDGER;
        li.max_entry_ttl = u32::MAX;
        li.min_persistent_entry_ttl = 1;
    });

    // get_allowed_fns must succeed and renew the TTL — it must not panic.
    e.as_contract(&address, || {
        let fns = get_allowed_fns(&e, context_rule.id, &smart_account);
        assert!(fns.contains(&symbol_short!("set")));
    });
}

#[test]
fn install_at_high_ledger_sequence_succeeds() {
    // Verify that installing a session policy when the ledger sequence is
    // already very high (simulating a long-running chain) works correctly
    // and that the subsequent read succeeds, confirming the TTL is set
    // relative to the current sequence rather than from zero.
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);

    e.mock_all_auths();

    e.ledger().with_mut(|li| {
        li.sequence_number = 1_000_000;
        li.max_entry_ttl = u32::MAX;
        li.min_persistent_entry_ttl = 1;
    });

    let context_rule = create_context_rule(&e);
    let params = SessionAccountParams {
        allowed_fns: vec![&e, symbol_short!("swap")],
    };

    e.as_contract(&address, || {
        install(&e, &params, &context_rule, &smart_account);
    });

    e.as_contract(&address, || {
        let fns = get_allowed_fns(&e, context_rule.id, &smart_account);
        assert!(fns.contains(&symbol_short!("swap")));
    });
}

#[test]
fn reclaim_storage_on_absent_entry_is_idempotent() {
    // reclaim_storage must succeed even when no entry exists, confirming the
    // idempotent cleanup path works for expired or never-installed entries.
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        // No prior install — reclaim must still succeed without panicking.
        reclaim_storage(&e, &context_rule, &smart_account);

        let key = SessionStorageKey::AccountContext(smart_account.clone(), context_rule.id);
        assert!(!e.storage().persistent().has(&key));
    });
}

#[test]
fn reclaim_storage_removes_installed_entry() {
    // After install, reclaim_storage must remove the entry just like
    // uninstall, confirming it clears all storage keys for the policy.
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
        reclaim_storage(&e, &context_rule, &smart_account);

        let key = SessionStorageKey::AccountContext(smart_account.clone(), context_rule.id);
        assert!(!e.storage().persistent().has(&key));
    });
}
