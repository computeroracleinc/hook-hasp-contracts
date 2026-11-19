# Soroban Cross-Contract Authorization & Invariant Guide

This guide establishes the formal verification invariant checklist and operational principles for safe cross-contract authorization delegation across Soroban smart contracts, with special focus on Latch Smart Accounts, policy engines, verifiers, and satellite contracts.

---

## 1. Executive Summary & Core Primitives

In Soroban, authorization is explicit and hierarchical. The Stellar host tracks authorization trees (`SorobanAuthorizationEntry`) during transaction simulation and execution. When contracts invoke cross-contract calls, authorization does not automatically transfer unless explicitly requested and structured.

Understanding the distinction between authorization mechanisms is essential to prevent signature replay, authorization hijacking, confused deputy attacks, and privilege escalation.

### 1.1 `require_auth` vs `require_auth_for_args` Nuances

Soroban provides two primary methods on `Address` to assert authorization:

```rust
// Method 1: Implicit top-level arguments
address.require_auth();

// Method 2: Explicit customized arguments
address.require_auth_for_args(args);
```

| Dimension | `address.require_auth()` | `address.require_auth_for_args(args)` |
|---|---|---|
| **What is authorized?** | The exact function name being invoked and the exact parameter list passed into that function invocation. | The exact function name being invoked and the custom argument list specified in `args` (a Soroban `Vec<Val>`). |
| **Call frame binding** | Binds strictly to the enclosing function's formal arguments. | Decouples authorization arguments from the outer function's direct arguments. |
| **Typical use case** | Standard contract entrypoints where caller authorization covers the exact inputs (e.g. `vault.withdraw(amount, recipient)` where `owner.require_auth()` signs `[amount, recipient]`). | Meta-transactions, gas-sponsorship, fee-forwarders, batched calls, or relayers where the outer wrapper has additional arguments (relayer fees, nonces, signatures) not part of the underlying authorized action. |
| **Risk of misuse** | If an outer function wraps an inner call and calls `require_auth()`, the signer authorizes the *wrapper* arguments, not the inner call directly. If argument order or types change, signature verification fails or binds unintentionally. | If `args` omits critical state or constraints (e.g., omitting recipient or amount), a malicious actor can reuse the authorization payload with altered values. |
| **Auth Tree Location** | Appears in the authorization tree at the current contract invocation node. | Appears in the authorization tree with the explicit vector of values passed as payload. |

#### Critical Nuance: Argument Truncation & Wildcards
- `require_auth_for_args` must **never** omit parameters that affect state transition, asset movement, or execution routing.
- If a forwarder or proxy receives a user-signed authorization to call a downstream target, the arguments signed by the user must match either the outer call's arguments or the inner call's arguments precisely.

---

## 2. Soroban Authorization Tree Architecture

### 2.1 Tree Structure and Sub-Invocations

Soroban authorizations are modeled as trees of contract invocations:

```
Transaction Envelope
└── Root Invocation: Contract A (e.g., FeeForwarder or Smart Account)
    ├── Auth: Address 1 (Signed root args)
    └── Sub-Invocation: Contract B (e.g., Token or Target)
        └── Auth: Address 1 (Authorized sub-invocation via tree delegation)
```

1. **Root Authorizations**: Signatures or custom account approvals attached to the transaction envelope for top-level invocations.
2. **Sub-Invocations (`sub_invocations`)**: Child nodes under a parent authorization entry. If a parent contract calls a child contract on behalf of a user, the host expects the user's authorization entry to contain a sub-invocation pointing to the child contract and function.
3. **No Ambient Authority**: A contract cannot call another contract and assert the caller's authorization without an explicit tree node authorizing that sub-call.

---

## 3. Formal Invariant Checklist for Authorization Trees

When designing, implementing, or auditing cross-contract authorization delegation in Soroban contracts, verify each invariant below.

```
+-----------------------------------------------------------------------------------------+
|                               INVARIANT CHECKLIST MATRIX                                |
+----+--------------------------------------------+-----------------------+---------------+
| ID | Invariant Category                         | Target Rule           | Severity      |
+----+--------------------------------------------+-----------------------+---------------+
| I1 | Delegation Scoping & Principle of Least Priv| Invocation Narrowing  | Critical      |
| I2 | Argument Completeness                      | Auth Args Parity      | Critical      |
| I3 | Replay & Nonce Defense                     | Uniqueness & Nonces   | Critical      |
| I4 | Confused Deputy Prevention                 | Context Authentication| High          |
| I5 | Contract Self-Auth Discipline              | Current Contract Auth | High          |
| I6 | Host Function Context Separation           | Native Deploy Auth    | High          |
| I7 | Policy & Rule Invariant Matching           | ContextRule Routing   | Medium        |
| I8 | Error Propagation & Atomicity              | Fail-Closed Semantics | High          |
+----+--------------------------------------------+-----------------------+---------------+
```

### Invariant 1: Delegation Scoping & Least Privilege (Sub-Invocation Specificity)
- **Checklist Item**: Every sub-invocation authorized by a smart account or user must be bounded to the exact contract address, function symbol, and arguments required.
- **Invariant**:
  $$\forall \text{ node } n \in \text{AuthTree}, \; \text{target}(n) = \text{intended\_contract} \land \text{fn}(n) = \text{intended\_fn}$$
- **Verification Rule**: Never construct authorization entries with wildcard sub-invocations unless the contract is an explicit administrative delegate. The contract must not ask users to authorize blanket calls to arbitrary targets.

### Invariant 2: Argument Completeness in `require_auth_for_args`
- **Checklist Item**: Any use of `require_auth_for_args(args)` must include every parameter influencing the outcome of the authorized action.
- **Invariant**:
  $$\text{SemanticStateTransition}(f, \vec{a}) = \text{SemanticStateTransition}(f, \vec{a}') \iff \vec{a} = \vec{a}'$$
- **Verification Rule**:
  - Never strip amounts, destination addresses, or operational boundaries from `args`.
  - In meta-transactions and relayers, fee parameters and relayer rewards must either be part of `args` or explicitly bounded so that relayers cannot siphon user funds.

### Invariant 3: Replay Prevention & Tree Freshness
- **Checklist Item**: Signatures and authorization trees must be single-use and bound to the current ledger / transaction session.
- **Invariant**:
  $$\forall \text{ auth\_payload } P, \; \text{Count}(\text{Execution}(P)) \le 1$$
- **Verification Rule**:
  - Host authorization enforces ledger sequence and transaction sequence counters.
  - When storing secondary authorization nonces (e.g. for custom account verification or signed off-chain messages), nonce increments must happen prior to downstream execution.
  - Context rules in Latch Smart Accounts must honor expiration ledgers (`valid_until`).

### Invariant 4: Confused Deputy & Cross-Contract Caller Verification
- **Checklist Item**: In multi-contract flows, an intermediate contract must not allow untrusted callers to trigger actions on behalf of another entity without authenticating that caller.
- **Invariant**:
  $$\text{ExecuteAs}(A, B) \implies \text{HasAuth}(A)$$
- **Verification Rule**:
  - If Contract A calls Contract B, and Contract B calls `user.require_auth()`, the transaction will fail unless `user` explicitly included Contract B as a sub-invocation under Contract A in their authorization tree.
  - Contracts must not rely on `env.invoker()` (which is deprecated/removed in modern Soroban) and must instead rely on `Address::require_auth()`.

### Invariant 5: Contract Self-Authorization (`e.current_contract_address().require_auth()`)
- **Checklist Item**: Internal management functions (e.g., policy installation, upgrades, signer updates) must require authorization from the contract itself.
- **Invariant**:
  $$\text{IsAdminMutation}(\text{fn}) \implies \text{Asserts}(e.current\_contract\_address().require\_auth())$$
- **Verification Rule**:
  - When an account calls its own administrative endpoints (e.g. `batch_add_signer`, `upgrade`), calling `e.current_contract_address().require_auth()` routes authorization through the account's own `__check_auth` / `Default` rule.
  - Verify that no public unauthenticated path exists to mutate signers, policies, or thresholds.

### Invariant 6: Host Function Context Separation (Deployments vs Direct Calls)
- **Checklist Item**: Distinguish between direct contract calls and host function operations (`create_contract_v2` / `deploy_v2`).
- **Invariant**:
  $$\text{AuthContext}(\text{Deploy}) \ne \text{AuthContext}(\text{ContractCall})$$
- **Verification Rule**:
  - When deploying satellite contracts via `e.deployer().with_current_contract(...)`, the host generates a `CreateContractHostFn` or `CreateContractWithCtorHostFn` context.
  - Do **not** insert redundant `e.current_contract_address().require_auth()` calls on methods where the underlying host function already requires deployer authorization, as this creates incompatible double-authorization demands.

### Invariant 7: Policy & ContextRule Routing Integrity
- **Checklist Item**: Soroban custom accounts map execution contexts to specific `ContextRule`s.
- **Invariant**:
  $$\forall C \in \text{Contexts}, \; \text{SelectRule}(C) \in \{\text{Default}, \text{CallContract}(\text{target}), \text{CreateContract}(\text{wasm})\}$$
- **Verification Rule**:
  - If a rule is scoped to `ContextRuleType::CallContract(token)`, that rule must never authorize calls to a different target address.
  - Verify that `spending_limit_policy` and `session_policy` enforce rule scopes correctly and reject attachment to wildcard/default rules if that violates least privilege.

### Invariant 8: Fail-Closed Semantics & Atomic Rollback
- **Checklist Item**: If any sub-contract authorization or execution fails, the entire authorization chain must fail and roll back state.
- **Invariant**:
  $$\neg \text{Auth}(\text{SubCall}_i) \implies \text{Rollback}(\text{All})$$
- **Verification Rule**:
  - Cross-contract calls must not suppress errors or swallow failed authorizations unless specifically building fallback mechanics with well-audited invariants.

---

## 4. Threat Models & Attack Patterns

### 4.1 Confused Deputy via Nested Calls
An attacker tricks contract `Proxy` into invoking `Token.transfer(victim, attacker, amount)`. If `Proxy` has pre-existing authorization over `Token` on behalf of `victim`, and does not validate the caller's rights, funds are drained.
- **Mitigation**: Require `victim.require_auth()` inside `Proxy` before delegating, or structure the call so that `Token` requires `victim.require_auth()` and requires `Proxy` as an explicit authorization tree node signed by `victim`.

### 4.2 Parameter Tampering with `require_auth_for_args`
A relay contract takes a signed intent with arguments `[amount, recipient]` and forwards it to a DeFi protocol. If the relayer calls `require_auth_for_args([amount])` without including `recipient`, a front-running relayer can substitute `recipient` with their own address while keeping the authorization check valid.
- **Mitigation**: The argument vector passed to `require_auth_for_args` must bind all critical parameters.

### 4.3 Ambient Authority Illusion
Developers assuming that calling `caller.require_auth()` in Contract A allows Contract A to make arbitrary downstream calls on `caller`'s behalf.
- **Reality**: In Soroban, downstream contract calls will panic with `HostError: Error(Auth, MissingTxAuth)` unless sub-invocations were declared in the authorization tree during simulation.

---

## 5. Soroban Test Authoring: Mocking Auth Trees

When testing Soroban contracts with `soroban-sdk`:

1. **`env.mock_all_auths()`**:
   - Useful for unit testing business logic in isolation.
   - **Caution**: `mock_all_auths()` automatically approves **every** `require_auth` and `require_auth_for_args` call regardless of address, hierarchy, or argument match. It masks authorization bugs and sub-invocation tree mismatch.
2. **`env.mock_auths(&[MockAuth])`**:
   - Compulsory for formal cross-contract testing.
   - Allows explicit specification of `MockAuthInvoke` and sub-invocations.
   - Validates that the exact tree expected by Soroban host is formed during runtime.

Example pattern:
```rust
env.mock_auths(&[
    MockAuth {
        address: &user,
        invoke: &MockAuthInvoke {
            contract: &forwarder_address,
            fn_name: "forward",
            args: (&target_address, &call_args).into_val(&env),
            sub_invocations: &[
                MockAuthInvoke {
                    contract: &target_address,
                    fn_name: "execute",
                    args: call_args.into_val(&env),
                    sub_invocations: &[],
                }
            ],
        },
    }
]);
```

---

## 6. Audit Verification Protocol

Auditors and developers should execute this step-by-step audit protocol before merging cross-contract code:

1. [ ] **Identify Every `require_auth` Call**: Catalogue all invocations in the codebase.
2. [ ] **Verify `require_auth_for_args` Completeness**: Check that every parameter in `args` cannot be manipulated to alter execution semantics.
3. [ ] **Inspect Sub-Invocation Boundaries**: Ensure that delegated calls do not grant transitive authority beyond the caller's explicit intent.
4. [ ] **Check Self-Invocation Guards**: Ensure admin methods that mutate contract state are guarded with `e.current_contract_address().require_auth()`.
5. [ ] **Test with `mock_auths` (not just `mock_all_auths`)**: Confirm that cross-contract flows pass with strictly mocked authorization trees.
