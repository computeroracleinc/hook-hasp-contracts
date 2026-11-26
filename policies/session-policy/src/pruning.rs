use soroban_sdk::{Address, Env, Vec};
use stellar_accounts::smart_account::ContextRule;

use crate::SessionStorageKey;

/// Removes policy state only for rules that are known to have expired.
/// Authorization is required because the rule metadata is supplied by the
/// caller and must not let an arbitrary account's entries be deleted.
pub fn prune_expired_sessions(
    e: &Env,
    context_rules: &Vec<ContextRule>,
    smart_account: &Address,
) -> u32 {
    smart_account.require_auth();

    let current_ledger = e.ledger().sequence();
    let mut pruned = 0u32;

    for context_rule in context_rules.iter() {
        let Some(valid_until) = context_rule.valid_until else {
            continue;
        };
        if current_ledger <= valid_until {
            continue;
        }

        let key = SessionStorageKey::AccountContext(smart_account.clone(), context_rule.id);
        let had_persistent_entry = e.storage().persistent().has(&key);
        let had_temporary_entry = e.storage().temporary().has(&key);

        if had_persistent_entry {
            e.storage().persistent().remove(&key);
        }
        if had_temporary_entry {
            e.storage().temporary().remove(&key);
        }
        if had_persistent_entry || had_temporary_entry {
            pruned = pruned.saturating_add(1);
        }
    }

    pruned
}
