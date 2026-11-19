#![no_std]

mod allowlist;

pub use allowlist::{
    SessionAccountParams, SessionData, SessionError, SessionRevoked, SessionStorageKey,
    REVOCATION_BITS_PER_WORD,
};
use soroban_sdk::{auth::Context, contract, contractimpl, Address, Env, Symbol, Vec};
use stellar_accounts::{
    policies::Policy,
    smart_account::{ContextRule, Signer},
};

#[contract]
pub struct SessionPolicy;

#[contractimpl]
impl Policy for SessionPolicy {
    type AccountParams = SessionAccountParams;

    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        allowlist::enforce(e, &context, &authenticated_signers, &context_rule, &smart_account)
    }

    fn install(
        e: &Env,
        install_params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        allowlist::install(e, &install_params, &context_rule, &smart_account)
    }

    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        allowlist::uninstall(e, &context_rule, &smart_account)
    }
}

#[contractimpl]
impl SessionPolicy {
    /// Revokes a session before its natural expiry. Only the smart account
    /// owner can call this, and the next authorization attempt with that
    /// session fails immediately.
    ///
    /// # Errors
    ///
    /// * Refer to [`SessionError`] for the validation failures.
    pub fn revoke_session(e: &Env, session_id: u32, smart_account: Address) {
        allowlist::revoke_session(e, session_id, &smart_account)
    }

    /// Returns whether a session ID has been revoked for the smart account.
    pub fn is_revoked(e: &Env, session_id: u32, smart_account: Address) -> bool {
        allowlist::is_revoked(e, session_id, &smart_account)
    }

    pub fn get_allowed_fns(e: &Env, context_rule_id: u32, smart_account: Address) -> Vec<Symbol> {
        allowlist::get_allowed_fns(e, context_rule_id, &smart_account)
    }
}

#[cfg(test)]
mod test;
