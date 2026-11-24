extern crate std;

use std::collections::HashMap;
use std::panic::catch_unwind;
use std::vec::Vec as StdVec;

use proptest::prelude::*;
use soroban_sdk::{
    auth::{Context, ContractContext},
    testutils::Address as _,
    Address, Env, IntoVal, Map, Symbol, Vec,
};
use stellar_accounts::{
    policies::weighted_threshold::*,
    smart_account::{ContextRule, ContextRuleType, Signer},
};

use crate::WeightedThresholdPolicy;

/// Number of distinct signers available in the fuzzing pool.
const NUM_SIGNERS: usize = 6;

/// Context rule ID used across tests.
const RULE_ID: u32 = 1;

/// Represents an abstract action on the weighted threshold policy.
#[derive(Clone, Debug)]
pub enum Action {
    /// Install policy with initial weights and threshold.
    Install {
        weights: StdVec<u32>,
        threshold: u32,
    },
    /// Set/update threshold.
    SetThreshold {
        threshold: u32,
    },
    /// Set/update a signer's weight.
    SetSignerWeight {
        signer_idx: usize,
        weight: u32,
    },
    /// Enforce authorization with a subset of authenticated signers.
    Enforce {
        authenticated_mask: StdVec<bool>,
        include_unknown_signer: bool,
    },
    /// Uninstall the policy.
    Uninstall,
}

/// Abstract model tracking the expected state of the policy.
#[derive(Clone, Debug, Default)]
pub struct WeightedThresholdModel {
    pub installed: bool,
    pub threshold: u32,
    pub weights: HashMap<usize, u32>,
}

impl WeightedThresholdModel {
    pub fn total_weight(&self) -> u64 {
        self.weights.values().map(|&w| w as u64).sum()
    }
}

/// Actual system state holding the Soroban environment and contract instances.
pub struct WeightedThresholdSystem {
    pub env: Env,
    pub policy_address: Address,
    pub smart_account: Address,
    pub signers: StdVec<Address>,
    pub unknown_signer: Address,
    pub context_rule: ContextRule,
    pub auth_context: Context,
}

impl WeightedThresholdSystem {
    pub fn new() -> Self {
        let env = Env::default();
        env.mock_all_auths();

        let policy_address = env.register(WeightedThresholdPolicy, ());
        let smart_account = Address::generate(&env);

        let mut signers = StdVec::new();
        let mut sdk_signers = Vec::new(&env);
        for _ in 0..NUM_SIGNERS {
            let addr = Address::generate(&env);
            sdk_signers.push_back(Signer::Delegated(addr.clone()));
            signers.push(addr);
        }

        let unknown_signer = Address::generate(&env);

        let context_rule = ContextRule {
            id: RULE_ID,
            context_type: ContextRuleType::Default,
            name: soroban_sdk::String::from_str(&env, "weighted_threshold"),
            signers: sdk_signers,
            signer_ids: Vec::new(&env),
            policies: Vec::new(&env),
            policy_ids: Vec::new(&env),
            valid_until: None,
        };

        let auth_context = Context::Contract(ContractContext {
            contract: Address::generate(&env),
            fn_name: Symbol::new(&env, "execute"),
            args: ().into_val(&env),
        });

        Self {
            env,
            policy_address,
            smart_account,
            signers,
            unknown_signer,
            context_rule,
            auth_context,
        }
    }
}

impl WeightedThresholdModel {
    fn apply(mut state: Self, transition: &Action) -> Self {
        match transition {
            Action::Install { weights, threshold } => {
                let total: u64 = weights.iter().map(|&w| w as u64).sum();
                // Valid install requirements in stellar-accounts:
                // threshold > 0 && threshold <= total_weight && total_weight <= u32::MAX
                if *threshold > 0 && (*threshold as u64) <= total && total <= (u32::MAX as u64) {
                    state.installed = true;
                    state.threshold = *threshold;
                    state.weights.clear();
                    for (i, &w) in weights.iter().enumerate() {
                        state.weights.insert(i, w);
                    }
                }
            }
            Action::SetThreshold { threshold } => {
                let total = state.total_weight();
                if *threshold > 0 && (*threshold as u64) <= total {
                    state.threshold = *threshold;
                }
            }
            Action::SetSignerWeight { signer_idx, weight } => {
                let mut candidate_weights = state.weights.clone();
                candidate_weights.insert(*signer_idx, *weight);
                let total: u64 = candidate_weights.values().map(|&w| w as u64).sum();
                if (state.threshold as u64) <= total && total <= (u32::MAX as u64) {
                    state.weights = candidate_weights;
                }
            }
            Action::Enforce { .. } => {
                // Enforce does not alter the configuration state.
            }
            Action::Uninstall => {
                state.installed = false;
                state.threshold = 0;
                state.weights.clear();
            }
        }
        state
    }
}

impl WeightedThresholdSystem {
    fn apply(
        state: Self,
        ref_state: &WeightedThresholdModel,
        transition: Action,
    ) -> Self {
        match transition {
            Action::Install { weights, threshold } => {
                let e = &state.env;
                let mut map = Map::new(e);
                for (i, &w) in weights.iter().enumerate() {
                    map.set(Signer::Delegated(state.signers[i].clone()), w);
                }

                let total: u64 = weights.iter().map(|&w| w as u64).sum();
                let should_succeed =
                    threshold > 0 && (threshold as u64) <= total && total <= (u32::MAX as u64);

                let params = WeightedThresholdAccountParams {
                    signer_weights: map,
                    threshold,
                };

                let smart_account = state.smart_account.clone();
                let context_rule = state.context_rule.clone();
                let env_clone = state.env.clone();

                let result = catch_unwind(std::panic::AssertUnwindSafe(|| {
                    env_clone.as_contract(&state.policy_address, || {
                        install(&env_clone, &params, &context_rule, &smart_account);
                    });
                }));

                assert_eq!(
                    result.is_ok(),
                    should_succeed,
                    "Install expectation mismatch: should_succeed={}, threshold={}, total={}",
                    should_succeed,
                    threshold,
                    total
                );

                if should_succeed {
                    state.env.as_contract(&state.policy_address, || {
                        assert_eq!(
                            get_threshold(&state.env, RULE_ID, &state.smart_account),
                            threshold
                        );
                    });
                }
            }
            Action::SetThreshold { threshold } => {
                let total = ref_state.total_weight();
                let should_succeed = threshold > 0 && (threshold as u64) <= total;

                let smart_account = state.smart_account.clone();
                let context_rule = state.context_rule.clone();
                let env_clone = state.env.clone();

                let result = catch_unwind(std::panic::AssertUnwindSafe(|| {
                    env_clone.as_contract(&state.policy_address, || {
                        set_threshold(&env_clone, threshold, &context_rule, &smart_account);
                    });
                }));

                assert_eq!(
                    result.is_ok(),
                    should_succeed,
                    "SetThreshold expectation mismatch: should_succeed={}, threshold={}, total={}",
                    should_succeed,
                    threshold,
                    total
                );

                if should_succeed {
                    state.env.as_contract(&state.policy_address, || {
                        assert_eq!(
                            get_threshold(&state.env, RULE_ID, &state.smart_account),
                            threshold
                        );
                    });
                }
            }
            Action::SetSignerWeight { signer_idx, weight } => {
                let mut candidate_weights = ref_state.weights.clone();
                candidate_weights.insert(signer_idx, weight);
                let total: u64 = candidate_weights.values().map(|&w| w as u64).sum();
                let should_succeed =
                    (ref_state.threshold as u64) <= total && total <= (u32::MAX as u64);

                let smart_account = state.smart_account.clone();
                let context_rule = state.context_rule.clone();
                let signer = Signer::Delegated(state.signers[signer_idx].clone());
                let env_clone = state.env.clone();

                let result = catch_unwind(std::panic::AssertUnwindSafe(|| {
                    env_clone.as_contract(&state.policy_address, || {
                        set_signer_weight(&env_clone, &signer, weight, &context_rule, &smart_account);
                    });
                }));

                assert_eq!(
                    result.is_ok(),
                    should_succeed,
                    "SetSignerWeight expectation mismatch: should_succeed={}, threshold={}, total={}",
                    should_succeed,
                    ref_state.threshold,
                    total
                );

                if should_succeed {
                    state.env.as_contract(&state.policy_address, || {
                        let weights =
                            get_signer_weights(&state.env, &state.context_rule, &state.smart_account);
                        assert_eq!(weights.get(signer).unwrap(), weight);
                    });
                }
            }
            Action::Enforce {
                authenticated_mask,
                include_unknown_signer,
            } => {
                // Compute valid weight sum of authenticated signers according to reference state
                let mut valid_weight_sum: u64 = 0;
                let mut auth_signers = Vec::new(&state.env);

                for (i, &is_auth) in authenticated_mask.iter().enumerate() {
                    if is_auth {
                        auth_signers.push_back(Signer::Delegated(state.signers[i].clone()));
                        if let Some(&w) = ref_state.weights.get(&i) {
                            valid_weight_sum += w as u64;
                        }
                    }
                }

                if include_unknown_signer {
                    auth_signers.push_back(Signer::Delegated(state.unknown_signer.clone()));
                    // unknown_signer has no configured weight in the policy, contributes 0
                }

                // Core invariant: approval granted if and only if valid weight sum >= threshold
                let should_grant_approval = valid_weight_sum >= (ref_state.threshold as u64);

                let smart_account = state.smart_account.clone();
                let context_rule = state.context_rule.clone();
                let auth_context = state.auth_context.clone();
                let env_clone = state.env.clone();

                let result = catch_unwind(std::panic::AssertUnwindSafe(|| {
                    env_clone.as_contract(&state.policy_address, || {
                        enforce(
                            &env_clone,
                            &auth_context,
                            &auth_signers,
                            &context_rule,
                            &smart_account,
                        );
                    });
                }));

                let approval_granted = result.is_ok();

                assert_eq!(
                    approval_granted,
                    should_grant_approval,
                    "INVARIANT VIOLATION: approval_granted ({}) != should_grant_approval ({}) \
                     [valid_weight_sum={}, threshold={}]",
                    approval_granted,
                    should_grant_approval,
                    valid_weight_sum,
                    ref_state.threshold
                );
            }
            Action::Uninstall => {
                let smart_account = state.smart_account.clone();
                let context_rule = state.context_rule.clone();
                let env_clone = state.env.clone();

                let result = catch_unwind(std::panic::AssertUnwindSafe(|| {
                    env_clone.as_contract(&state.policy_address, || {
                        uninstall(&env_clone, &context_rule, &smart_account);
                    });
                }));

                assert!(result.is_ok(), "Uninstall should succeed when installed");
            }
        }

        state
    }
}

fn action_strategy() -> BoxedStrategy<Action> {
    let weight_strategy = 0u32..=1_000u32;
    let threshold_strategy = 0u32..=6_000u32;
    prop_oneof![
        threshold_strategy.prop_map(|threshold| Action::SetThreshold { threshold }),
        (0..NUM_SIGNERS, weight_strategy)
            .prop_map(|(signer_idx, weight)| Action::SetSignerWeight { signer_idx, weight }),
        (
            proptest::collection::vec(any::<bool>(), NUM_SIGNERS),
            any::<bool>(),
        )
            .prop_map(|(authenticated_mask, include_unknown_signer)| Action::Enforce {
                authenticated_mask,
                include_unknown_signer,
            }),
    ]
    .boxed()
}

// 1) Stateful test using proptest
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        .. ProptestConfig::default()
    })]
    #[test]
    fn test_weighted_threshold_stateful_fuzz(
        weights in proptest::collection::vec(1u32..=1_000u32, NUM_SIGNERS),
        threshold_ratio in 1u32..=100u32,
        actions in proptest::collection::vec(action_strategy(), 1..25)
    ) {
        let total: u64 = weights.iter().map(|&w| w as u64).sum();
        let threshold = ((total * threshold_ratio as u64) / 100).max(1) as u32;

        let mut model = WeightedThresholdModel::default();
        let mut sys = WeightedThresholdSystem::new();
        let install = Action::Install { weights, threshold };
        model = WeightedThresholdModel::apply(model, &install);
        sys = WeightedThresholdSystem::apply(sys, &model, install);

        for action in actions {
            model = WeightedThresholdModel::apply(model, &action);
            sys = WeightedThresholdSystem::apply(sys, &model, action);
        }
    }
}

/// 2) Stateful continuous fuzzing runner across 10,000 randomized state transitions.
/// Acceptance criteria: Invariant holds across 10,000 randomized state transitions.
#[test]
fn test_weighted_threshold_10k_state_transitions() {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    let mut rng = StdRng::seed_from_u64(0xFEED_FACE_CAFE_BEEF);
    let mut total_transitions = 0usize;
    let target_transitions = 10_000usize;

    while total_transitions < target_transitions {
        let mut sys = WeightedThresholdSystem::new();
        let mut model = WeightedThresholdModel::default();

        // 1. Initial installation with randomized weights and threshold
        let num_signers = NUM_SIGNERS;
        let weights: StdVec<u32> = (0..num_signers).map(|_| rng.gen_range(1..=1_000)).collect();
        let total_w: u64 = weights.iter().map(|&w| w as u64).sum();
        let threshold: u32 = rng.gen_range(1..=total_w as u32);

        let install_action = Action::Install {
            weights: weights.clone(),
            threshold,
        };

        model = WeightedThresholdModel::apply(model, &install_action);
        sys = WeightedThresholdSystem::apply(sys, &model, install_action);
        total_transitions += 1;

        // Perform random sequence of transitions while installed
        let seq_len = rng.gen_range(20..=60);
        for _ in 0..seq_len {
            if total_transitions >= target_transitions {
                break;
            }

            let choice = rng.gen_range(0..100);
            let action = if choice < 30 {
                // SetThreshold
                let total = model.total_weight();
                // 80% reachable threshold, 20% unreachable threshold (to test rejection)
                let new_threshold = if rng.gen_bool(0.8) && total > 0 {
                    rng.gen_range(1..=(total as u32))
                } else {
                    rng.gen_range(0..=(total as u32 + 500))
                };
                Action::SetThreshold {
                    threshold: new_threshold,
                }
            } else if choice < 60 {
                // SetSignerWeight
                let signer_idx = rng.gen_range(0..NUM_SIGNERS);
                let new_weight = rng.gen_range(0..=1_000);
                Action::SetSignerWeight {
                    signer_idx,
                    weight: new_weight,
                }
            } else if choice < 95 {
                // Enforce authorization
                let authenticated_mask: StdVec<bool> =
                    (0..NUM_SIGNERS).map(|_| rng.gen_bool(0.5)).collect();
                let include_unknown_signer = rng.gen_bool(0.3);
                Action::Enforce {
                    authenticated_mask,
                    include_unknown_signer,
                }
            } else {
                // Uninstall & reinstall
                Action::Uninstall
            };

            let is_uninstall = matches!(action, Action::Uninstall);
            model = WeightedThresholdModel::apply(model, &action);
            sys = WeightedThresholdSystem::apply(sys, &model, action);
            total_transitions += 1;

            if is_uninstall {
                // Reinstall to continue state transitions
                let new_weights: StdVec<u32> =
                    (0..NUM_SIGNERS).map(|_| rng.gen_range(1..=1_000)).collect();
                let new_total: u64 = new_weights.iter().map(|&w| w as u64).sum();
                let new_threshold: u32 = rng.gen_range(1..=new_total as u32);
                let reinstall = Action::Install {
                    weights: new_weights,
                    threshold: new_threshold,
                };
                model = WeightedThresholdModel::apply(model, &reinstall);
                sys = WeightedThresholdSystem::apply(sys, &model, reinstall);
                total_transitions += 1;
            }
        }
    }

    assert!(
        total_transitions >= target_transitions,
        "Completed {} transitions (target {})",
        total_transitions,
        target_transitions
    );
}
