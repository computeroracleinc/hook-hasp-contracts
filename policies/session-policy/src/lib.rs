#![no_std]

mod allowlist;

pub use allowlist::{SessionAccountParams, SessionData, SessionError, SessionStorageKey};
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

    /// Enforces the session policy: the context must be a `Context::Contract`
    /// invocation whose `fn_name` is in the installed allowlist. Requires
    /// authorization from the smart account.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `context` - The authorization context.
    /// * `authenticated_signers` - The list of authenticated signers.
    /// * `context_rule` - The context rule for this policy.
    /// * `smart_account` - The address of the smart account.
    ///
    /// # Errors
    ///
    /// * [`SessionError::MethodNotAllowed`] - When there are no authenticated
    ///   signers, the context is not a `Context::Contract` invocation, or the
    ///   function name is not in the allowlist.
    /// * refer to [`SessionPolicy::get_allowed_fns`] errors.
    ///
    /// # Events
    ///
    /// * topics - `["session_enforced", smart_account: Address]`
    /// * data - `[context_rule_id: u32, fn_name: Symbol]`
    fn enforce(
        e: &Env,
        context: Context,
        authenticated_signers: Vec<Signer>,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        allowlist::enforce(e, &context, &authenticated_signers, &context_rule, &smart_account)
    }

    /// Installs the session policy on a smart account. Only `CallContract`
    /// context type is allowed, since the allowlisted function names are only
    /// meaningful when pinned to one target contract. Requires authorization
    /// from the smart account.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `install_params` - Installation parameters containing the allowed function names.
    /// * `context_rule` - The context rule for this policy.
    /// * `smart_account` - The address of the smart account.
    ///
    /// # Errors
    ///
    /// * [`SessionError::OnlyCallContractAllowed`] - When the context rule type is
    ///   not `CallContract`.
    /// * [`SessionError::InvalidAllowedFns`] - When `allowed_fns` is empty or
    ///   exceeds `MAX_ALLOWED_FNS`.
    /// * [`SessionError::AlreadyInstalled`] - When the policy was already installed
    ///   for this smart account and context rule.
    ///
    /// # Events
    ///
    /// * topics - `["session_installed", smart_account: Address]`
    /// * data - `[context_rule_id: u32, allowed_fns: Vec<Symbol>]`
    fn install(
        e: &Env,
        install_params: Self::AccountParams,
        context_rule: ContextRule,
        smart_account: Address,
    ) {
        allowlist::install(e, &install_params, &context_rule, &smart_account)
    }

    /// Uninstalls the session policy from a smart account, removing all stored
    /// allowlist data for the account and context rule. Requires authorization
    /// from the smart account.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `context_rule` - The context rule for this policy.
    /// * `smart_account` - The address of the smart account.
    ///
    /// # Errors
    ///
    /// * [`SessionError::SmartAccountNotInstalled`] - When the policy is not
    ///   installed for the given smart account and context rule.
    ///
    /// # Events
    ///
    /// * topics - `["session_uninstalled", smart_account: Address]`
    /// * data - `[context_rule_id: u32]`
    fn uninstall(e: &Env, context_rule: ContextRule, smart_account: Address) {
        allowlist::uninstall(e, &context_rule, &smart_account)
    }
}

#[contractimpl]
impl SessionPolicy {
    /// Retrieves the allowlist for a smart account's session policy.
    ///
    /// # Arguments
    ///
    /// * `e` - Access to the Soroban environment.
    /// * `context_rule_id` - The context rule ID for this policy.
    /// * `smart_account` - The address of the smart account.
    ///
    /// # Returns
    ///
    /// A vector of allowed function names ([`Symbol`]).
    ///
    /// # Errors
    ///
    /// * [`SessionError::SmartAccountNotInstalled`] - When the smart account does
    ///   not have a session policy installed.
    pub fn get_allowed_fns(e: &Env, context_rule_id: u32, smart_account: Address) -> Vec<Symbol> {
        allowlist::get_allowed_fns(e, context_rule_id, &smart_account)
    }
}

#[cfg(test)]
mod test;
