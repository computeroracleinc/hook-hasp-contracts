extern crate std;

use soroban_sdk::{
    auth::{Context, ContractContext},
    contract, symbol_short,
    testutils::{Address as _, Events, Ledger, LedgerInfo},
    Address, Env, Vec,
};
use stellar_accounts::smart_account::{ContextRule, ContextRuleType, Signer};

use crate::rate_limit::*;

#[contract]
struct MockContract;

fn create_context_rule(e: &Env) -> ContextRule {
    let signer = Address::generate(e);
    let mut signers = Vec::new(e);
    signers.push_back(Signer::Delegated(signer));

    ContextRule {
        id: 1,
        context_type: ContextRuleType::CallContract(Address::generate(e)),
        name: soroban_sdk::String::from_str(e, "rate-limit"),
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

fn default_params(max_calls: u32, period: u32) -> RateLimitAccountParams {
    RateLimitAccountParams { max_calls_per_window: max_calls, period_ledgers: period }
}

// ############ INSTALL ############

#[test]
fn install_success() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let context_rule = create_context_rule(&e);
        let params = default_params(5, 100);

        install(&e, &params, &context_rule, &smart_account);

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
        install(&e, &default_params(5, 100), &context_rule, &smart_account);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn install_rejects_zero_max_calls() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let context_rule = create_context_rule(&e);
        install(&e, &default_params(0, 100), &context_rule, &smart_account);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn install_rejects_zero_period() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        let context_rule = create_context_rule(&e);
        install(&e, &default_params(5, 0), &context_rule, &smart_account);
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn install_rejects_already_installed() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);
    let params = default_params(5, 100);

    e.mock_all_auths();

    e.as_contract(&address, || {
        install(&e, &params, &context_rule, &smart_account);
    });
    e.as_contract(&address, || {
        install(&e, &params, &context_rule, &smart_account);
    });
}

// ############ ENFORCE ############

#[test]
fn enforce_allows_within_limit() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        install(&e, &default_params(2, 100), &context_rule, &smart_account);
    });

    e.as_contract(&address, || {
        let context = create_contract_context(&e, symbol_short!("swap"));
        enforce(&e, &context, &context_rule.signers, &context_rule, &smart_account);
        assert!(!e.events().all().events().is_empty());
    });
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn enforce_rejects_when_limit_exceeded() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        install(&e, &default_params(1, 100), &context_rule, &smart_account);
    });

    // First call — allowed.
    e.as_contract(&address, || {
        let context = create_contract_context(&e, symbol_short!("swap"));
        enforce(&e, &context, &context_rule.signers, &context_rule, &smart_account);
    });

    // Second call — must panic with RateLimitExceeded (#4).
    e.as_contract(&address, || {
        let context = create_contract_context(&e, symbol_short!("swap"));
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
        let context = create_contract_context(&e, symbol_short!("swap"));
        enforce(&e, &context, &context_rule.signers, &context_rule, &smart_account);
    });
}

#[test]
fn enforce_allows_after_window_expires() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        // Window of 5 ledgers, limit of 1 call.
        install(&e, &default_params(1, 5), &context_rule, &smart_account);
    });

    // First call at ledger 1.
    e.ledger().set(LedgerInfo { sequence_number: 1, timestamp: 5, ..e.ledger().get() });
    e.as_contract(&address, || {
        let context = create_contract_context(&e, symbol_short!("swap"));
        enforce(&e, &context, &context_rule.signers, &context_rule, &smart_account);
    });

    // Advance past the window (ledger 1 is now outside the [seq-5, seq] range
    // when seq = 7, cutoff = 2, so entry at ledger 1 is evicted).
    e.ledger().set(LedgerInfo { sequence_number: 7, timestamp: 35, ..e.ledger().get() });
    e.as_contract(&address, || {
        // The window has rolled; the first call aged out, so this succeeds.
        let context = create_contract_context(&e, symbol_short!("swap"));
        enforce(&e, &context, &context_rule.signers, &context_rule, &smart_account);
        assert!(!e.events().all().events().is_empty());
    });
}

#[test]
fn enforce_tracks_different_fns_independently() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        install(&e, &default_params(1, 100), &context_rule, &smart_account);
    });

    e.as_contract(&address, || {
        // "swap" — first call.
        enforce(
            &e,
            &create_contract_context(&e, symbol_short!("swap")),
            &context_rule.signers,
            &context_rule,
            &smart_account,
        );
        // "get" — different function, independent counter, should succeed.
        enforce(
            &e,
            &create_contract_context(&e, symbol_short!("get")),
            &context_rule.signers,
            &context_rule,
            &smart_account,
        );
    });
}

// ############ UNINSTALL ############

#[test]
fn uninstall_success() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        install(&e, &default_params(5, 100), &context_rule, &smart_account);
    });

    e.as_contract(&address, || {
        uninstall(&e, &context_rule, &smart_account);
        assert_eq!(e.events().all().events().len(), 1);
    });

    e.as_contract(&address, || {
        let key =
            RateLimitStorageKey::AccountContext(smart_account.clone(), context_rule.id);
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

// ############ CHECK POLICY ############

#[test]
fn check_policy_returns_remaining_calls() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        install(&e, &default_params(3, 100), &context_rule, &smart_account);
    });

    e.as_contract(&address, || {
        // No calls yet — all 3 slots available.
        let (would_pass, remaining) =
            check_policy(&e, context_rule.id, &smart_account, &symbol_short!("swap"));
        assert!(would_pass);
        assert_eq!(remaining, 3);
    });

    // Use one slot.
    e.as_contract(&address, || {
        enforce(
            &e,
            &create_contract_context(&e, symbol_short!("swap")),
            &context_rule.signers,
            &context_rule,
            &smart_account,
        );
    });

    e.as_contract(&address, || {
        let (would_pass, remaining) =
            check_policy(&e, context_rule.id, &smart_account, &symbol_short!("swap"));
        assert!(would_pass);
        assert_eq!(remaining, 2);
    });
}

#[test]
fn check_policy_returns_false_when_limit_reached() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        install(&e, &default_params(1, 100), &context_rule, &smart_account);
    });

    e.as_contract(&address, || {
        enforce(
            &e,
            &create_contract_context(&e, symbol_short!("swap")),
            &context_rule.signers,
            &context_rule,
            &smart_account,
        );
    });

    e.as_contract(&address, || {
        let (would_pass, remaining) =
            check_policy(&e, context_rule.id, &smart_account, &symbol_short!("swap"));
        assert!(!would_pass);
        assert_eq!(remaining, 0);
    });
}

#[test]
fn check_policy_is_read_only() {
    let e = Env::default();
    let address = e.register(MockContract, ());
    let smart_account = Address::generate(&e);
    let context_rule = create_context_rule(&e);

    e.mock_all_auths();

    e.as_contract(&address, || {
        install(&e, &default_params(2, 100), &context_rule, &smart_account);
    });

    e.as_contract(&address, || {
        // Calling check_policy repeatedly must not change the result.
        let r1 = check_policy(&e, context_rule.id, &smart_account, &symbol_short!("swap"));
        let r2 = check_policy(&e, context_rule.id, &smart_account, &symbol_short!("swap"));
        assert_eq!(r1, r2);
    });
}
