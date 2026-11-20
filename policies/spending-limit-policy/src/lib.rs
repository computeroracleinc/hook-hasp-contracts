//! Rolling-window spending limit policy for Latch smart accounts.
//!
//! The policy retains the upstream spending-limit interface while storing each
//! non-negative spending amount as unsigned LEB128. This keeps small transfer
//! amounts compact without limiting the range of supported token amounts.
#![no_std]

use soroban_sdk::{
    auth::{Context, ContractContext},
    contract, contractimpl, contracttype, panic_with_error, symbol_short, Address, Bytes, Env,
    TryFromVal, Vec,
};
use stellar_accounts::{
    policies::{
        spending_limit,
        spending_limit::{
            SpendingLimitAccountParams, SpendingLimitData, SpendingLimitError,
            SpendingLimitStorageKey,
        },
        Policy,
    },
    smart_account::{ContextRule, ContextRuleType, Signer},
};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
struct CompactSpendingEntry {
    amount: Bytes,
    ledger_sequence: u32,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
struct CompactSpendingLimitData {
    spending_limit: i128,
    period_ledgers: u32,
    spending_history: Vec<CompactSpendingEntry>,
    cached_total_spent: i128,
}

const DAY_IN_LEDGERS: u32 = 17280;
const POLICY_EXTEND_AMOUNT: u32 = 30 * DAY_IN_LEDGERS;
const POLICY_TTL_THRESHOLD: u32 = POLICY_EXTEND_AMOUNT - DAY_IN_LEDGERS;

fn encode_amount(e: &Env, amount: i128) -> Bytes {
    let mut remaining = amount as u128;
    let mut encoded = Bytes::new(e);
    loop {
        let mut byte = (remaining & 0x7f) as u8;
        remaining >>= 7;
        if remaining != 0 {
            byte |= 0x80;
        }
        encoded.push_back(byte);
        if remaining == 0 {
            return encoded;
        }
    }
}

fn decode_amount(e: &Env, encoded: &Bytes) -> i128 {
    let mut amount = 0u128;
    let mut shift = 0u32;
    let mut index = 0u32;

    for byte in encoded.iter() {
        if shift > 126 {
            panic_with_error!(e, SpendingLimitError::NotAllowed)
        }
        let part = (byte & 0x7f) as u128;
        if part > (i128::MAX as u128 >> shift) {
            panic_with_error!(e, SpendingLimitError::NotAllowed)
        }
        amount |= part << shift;
        index += 1;

        if byte & 0x80 == 0 {
            if index != encoded.len() || (index > 1 && part == 0) {
                panic_with_error!(e, SpendingLimitError::NotAllowed)
            }
            return amount as i128;
        }
        shift += 7;
    }

    panic_with_error!(e, SpendingLimitError::NotAllowed)
}

fn compress_data(e: &Env, data: SpendingLimitData) -> CompactSpendingLimitData {
    let mut spending_history = Vec::new(e);
    for entry in data.spending_history.iter() {
        if entry.amount < 0 {
            panic_with_error!(e, SpendingLimitError::NotAllowed)
        }
        spending_history.push_back(CompactSpendingEntry {
            amount: encode_amount(e, entry.amount),
            ledger_sequence: entry.ledger_sequence,
        });
    }

    CompactSpendingLimitData {
        spending_limit: data.spending_limit,
        period_ledgers: data.period_ledgers,
        spending_history,
        cached_total_spent: data.cached_total_spent,
    }
}

fn expand_data(e: &Env, data: CompactSpendingLimitData) -> SpendingLimitData {
    let mut spending_history = Vec::new(e);
    for entry in data.spending_history.iter() {
        spending_history.push_back(spending_limit::SpendingEntry {
            amount: decode_amount(e, &entry.amount),
            ledger_sequence: entry.ledger_sequence,
        });
    }

    SpendingLimitData {
        spending_limit: data.spending_limit,
        period_ledgers: data.period_ledgers,
        spending_history,
        cached_total_spent: data.cached_total_spent,
    }
}

fn load_data(e: &Env, context_rule_id: u32, smart_account: &Address) -> SpendingLimitData {
    let key = SpendingLimitStorageKey::AccountContext(smart_account.clone(), context_rule_id);
    let data = e
        .storage()
        .persistent()
        .get::<_, CompactSpendingLimitData>(&key)
        .inspect(|_| {
            e.storage().persistent().extend_ttl(
                &key,
                POLICY_TTL_THRESHOLD,
                POLICY_EXTEND_AMOUNT,
            );
        })
        .unwrap_or_else(|| panic_with_error!(e, SpendingLimitError::SmartAccountNotInstalled));
    expand_data(e, data)
}

fn save_data(
    e: &Env,
    context_rule_id: u32,
    smart_account: &Address,
    data: SpendingLimitData,
) {
    let key = SpendingLimitStorageKey::AccountContext(smart_account.clone(), context_rule_id);
    e.storage().persistent().set(&key, &compress_data(e, data));
}

fn cleanup_old_entries(
    spending_history: &mut Vec<spending_limit::SpendingEntry>,
    current_ledger: u32,
    period_ledgers: u32,
) -> i128 {
    let cutoff_ledger = current_ledger.saturating_sub(period_ledgers);
    let mut removed_total = 0i128;

    while let Some(entry) = spending_history.get(0) {
        if entry.ledger_sequence <= cutoff_ledger {
            removed_total = removed_total.saturating_add(entry.amount);
            spending_history.pop_front();
        } else {
            break;
        }
    }

    removed_total
}

#[contract]
pub struct SpendingLimitPolicy;

#[contractimpl]
impl Policy for SpendingLimitPolicy {
    type AccountParams = SpendingLimitAccountParams;

    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();
        if authenticated_signers.is_empty() {
            panic_with_error!(e, SpendingLimitError::NotAllowed)
        }

        let event_context = context.clone();
        let Context::Contract(ContractContext { fn_name, args, .. }) = context else {
            panic_with_error!(e, SpendingLimitError::NotAllowed)
        };
        if fn_name != symbol_short!("transfer") {
            panic_with_error!(e, SpendingLimitError::NotAllowed)
        }
        let amount_val =
            args.get(2).unwrap_or_else(|| panic_with_error!(e, SpendingLimitError::NotAllowed));
        let Ok(amount) = i128::try_from_val(e, &amount_val) else {
            panic_with_error!(e, SpendingLimitError::NotAllowed)
        };
        if amount < 0 {
            panic_with_error!(e, SpendingLimitError::LessThanZero)
        }

        let mut data = load_data(e, context_rule.id, &smart_account);
        let current_ledger = e.ledger().sequence();
        let removed_amount = cleanup_old_entries(
            &mut data.spending_history,
            current_ledger,
            data.period_ledgers,
        );
        data.cached_total_spent = data
            .cached_total_spent
            .checked_sub(removed_amount)
            .unwrap_or_else(|| panic_with_error!(e, SpendingLimitError::NotAllowed));

        let total_spent = data
            .cached_total_spent
            .checked_add(amount)
            .unwrap_or_else(|| panic_with_error!(e, SpendingLimitError::SpendingLimitExceeded));
        if total_spent > data.spending_limit {
            panic_with_error!(e, SpendingLimitError::SpendingLimitExceeded)
        }
        if data.spending_history.len() >= spending_limit::MAX_HISTORY_ENTRIES {
            panic_with_error!(e, SpendingLimitError::HistoryCapacityExceeded)
        }

        data.spending_history
            .push_back(spending_limit::SpendingEntry { amount, ledger_sequence: current_ledger });
        data.cached_total_spent = total_spent;
        save_data(e, context_rule.id, &smart_account, data.clone());

        spending_limit::SpendingLimitEnforced {
            smart_account,
            context: event_context,
            context_rule_id: context_rule.id,
            amount,
            total_spent_in_period: total_spent,
        }
        .publish(e);
    }

    fn install(
        e: &Env,
        install_params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();
        if !matches!(context_rule.context_type, ContextRuleType::CallContract(_)) {
            panic_with_error!(e, SpendingLimitError::OnlyCallContractAllowed)
        }
        if install_params.spending_limit <= 0 || install_params.period_ledgers == 0 {
            panic_with_error!(e, SpendingLimitError::InvalidLimitOrPeriod)
        }

        let key = SpendingLimitStorageKey::AccountContext(smart_account.clone(), context_rule.id);
        if e.storage().persistent().has(&key) {
            panic_with_error!(e, SpendingLimitError::AlreadyInstalled)
        }

        let data = SpendingLimitData {
            spending_limit: install_params.spending_limit,
            period_ledgers: install_params.period_ledgers,
            spending_history: Vec::new(e),
            cached_total_spent: 0,
        };
        e.storage().persistent().set(&key, &compress_data(e, data));

        spending_limit::SpendingLimitInstalled {
            smart_account,
            context_rule_id: context_rule.id,
            spending_limit: install_params.spending_limit,
            period_ledgers: install_params.period_ledgers,
        }
        .publish(e);
    }

    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        smart_account.require_auth();
        let key = SpendingLimitStorageKey::AccountContext(smart_account.clone(), context_rule.id);
        if !e.storage().persistent().has(&key) {
            panic_with_error!(e, SpendingLimitError::SmartAccountNotInstalled)
        }
        e.storage().persistent().remove(&key);

        spending_limit::SpendingLimitUninstalled {
            smart_account,
            context_rule_id: context_rule.id,
        }
        .publish(e);
    }
}

#[contractimpl]
impl SpendingLimitPolicy {
    pub fn get_spending_limit_data(
        e: &Env,
        context_rule_id: u32,
        smart_account: Address,
    ) -> SpendingLimitData {
        load_data(e, context_rule_id, &smart_account)
    }

    pub fn set_spending_limit(
        e: Env,
        spending_limit: i128,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        smart_account.require_auth();
        if spending_limit <= 0 {
            panic_with_error!(&e, SpendingLimitError::InvalidLimitOrPeriod)
        }

        let mut data = load_data(&e, context_rule.id, &smart_account);
        data.spending_limit = spending_limit;
        save_data(&e, context_rule.id, &smart_account, data);

        spending_limit::SpendingLimitChanged {
            smart_account,
            context_rule_id: context_rule.id,
            spending_limit,
        }
        .publish(&e);
    }
}

#[cfg(test)]
mod test;
