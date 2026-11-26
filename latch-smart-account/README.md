# Latch Smart Account

A programmable wallet contract for Soroban. Replaces static private-key authorization with flexible, rule-based multi-signer authorization. Deployed by the Latch Account Factory — one instance per user.

Built on [OpenZeppelin Stellar Contracts](https://github.com/OpenZeppelin/stellar-contracts).

---

## Architecture

<img width="2383" height="2560" alt="smartaccount" src="https://github.com/user-attachments/assets/73b919ce-7137-4c2e-b03e-4fc45d50f999" />


The contract implements five OpenZeppelin interfaces: `CustomAccountInterface` (`__check_auth`), `SmartAccount` (context rule CRUD), `ExecutionEntryPoint` (`execute`), `Pausable` (`pause`, `unpause`, `paused`), and `Upgradeable` (`upgrade`). The Latch layer adds constructor setup, `batch_add_signer`, `batch_transfer`, flash-loan callback registry, threshold fallback recovery, timelocked signer rotation, `upgrade`, and emergency pause on `execute`.

---

## Public Interface

**Constructor** — called once by the factory at deploy:
```rust
fn __constructor(env: &Env, signers: Vec<Signer>, policies: Map<Address, Val>)
```
Creates a single `Default` context rule named `"default"` with the provided signers and policies. No expiry.

**`batch_add_signer`** — adds multiple signers to an existing rule in one call. Requires self-auth.
```rust
fn batch_add_signer(env: &Env, context_rule_id: u32, signers: Vec<Signer>)
```

**Threshold Fallback Recovery** — configures secondary recovery signers with an extended inactivity delay (default 14 days / 241,920 ledgers) and domain-separated recovery digests:
- `set_recovery_config(env, recovery_signers, threshold, inactivity_delay_ledgers)` — self-auth
- `recover_signers(env, context_rule_id, new_signers, signatures)` — replaces signers after inactivity delay + threshold guardian auth
- `touch_activity(env)` / `is_recovery_eligible(env)`

**Timelocked Signer Rotation Queue** — enforces configurable timelock delays on signer proposals and prevents instant delay reductions:
- `set_signer_timelock_delay(env, delay)` — immediately increases delay (self-auth; reductions require timelocked `propose_timelock_delay_change` / `accept_timelock_delay_change`)
- `propose_signer(env, context_rule_id, action)` / `accept_signer(env, proposal_id)` / `cancel_signer_proposal(env, proposal_id)`

**`upgrade`** — replaces the account's own WASM in place, preserving storage. Requires self-auth — gated by `e.current_contract_address().require_auth()`, the same as every other mutation here. No external admin involved. See [`UPGRADE_PATH.md`](../docs/UPGRADE_PATH.md) for the full reasoning.
```rust
fn upgrade(env: &Env, new_wasm_hash: BytesN<32>, operator: Address)
```

**Inherited from `SmartAccount`** (all require self-auth except reads):

| Function | Description |
|---|---|
| `add_context_rule(type, name, valid_until, signers, policies)` | Create a named rule |
| `remove_context_rule(id)` | Delete a rule |
| `add_signer(rule_id, signer)` / `remove_signer(rule_id, signer_id)` | Manage signers |
| `add_policy(rule_id, address, params)` / `remove_policy(rule_id, address)` | Manage policies |
| `get_context_rule(id)` / `get_context_rules_count()` | Read-only queries |

**Inherited from `ExecutionEntryPoint`**: `execute(contract, function, args)` — calls another contract as this account. Requires self-auth, guarded by `when_not_paused` and a temporary-storage re-entrancy lock.

**Inherited from `Pausable`**:
- `pause(caller)` — triggers emergency pause, freezing outgoing `execute` and `batch_transfer` calls. Strictly requires `caller == e.current_contract_address()` with self-auth.
- `unpause(caller)` — lifts emergency pause. Strictly requires `caller == e.current_contract_address()` with self-auth.
- `paused()` — returns current pause state (`bool`).

**Atomic Batch Execution & Rollback Guarantee**: When executing multi-step operations (`batch_add_signer` or multi-operation transactions dispatched through the smart account), execution is strictly atomic within the Soroban host frame — if step $N$ panics or fails validation (e.g. duplicate signer, policy rejection, or target contract revert), all state mutations from steps $1 \dots N-1$ are rolled back atomically.

---

## Key Concepts

**Context rules** govern authorization for a scope of actions. Each has a type (`Default` = catch-all, `CallContract(address)` = specific contract), a set of signers, attached policies, and an optional ledger expiry. Every account starts with one `Default` rule.

**Signers** come in two families:

| Family | Auth mechanism |
|---|---|
| `Signer::Delegated(Address)` | Native Stellar account authorization |
| `Signer::External(verifier, key_data)` | `verifier.verify(key_data, payload, sig)` |

External kinds: Ed25519 (32-byte key), Secp256k1 (65-byte `0x04`-prefixed), WebAuthn (P-256 + credential ID).

**Policies** are external contracts called after signature verification. Interface: `enforce`, `install`, `uninstall`. The system uses OZ `SimpleThresholdPolicy` for M-of-N multisig.

---

## Security

- **No external admin.** No owner key, no third-party upgrade authority. The account can upgrade its own code, but only via the same self-authorization every other mutation already requires — there is no separate admin or proxy contract that can act on the account's behalf.
- **Self-auth on every mutation.** No bypass exists.
- **Auth logic is upstream.** `do_check_auth` is a pinned OZ library function — no custom auth code here.

**Risks:**
- **Threshold drift:** Removing signers without updating the threshold policy can make the threshold unreachable and lock the account permanently.
- **Default rule expiry:** If the default rule expires, no transaction can be authorized. Don't set `valid_until` on it.
- **Policy trust:** A malicious or buggy policy at a given address can block or compromise authorization for that rule's scope.
- **Upgrade risk:** Authorizing `upgrade()` to a malicious or buggy WASM replaces the account's entire logic — the highest-blast-radius action any signer set can take. It carries the same authorization weight as `add_signer`/`remove_policy` today (see `UPGRADE_PATH.md` for why that's a pre-existing property of the whole design, not something new), but the consequence of getting it wrong is much larger. Storage is preserved across an upgrade, so a bad upgrade doesn't just misbehave — it takes the account's existing signers and funds with it.

---

## Development

```bash
# Build
stellar contract build

# Test
cargo test
```

Requires Rust toolchain + Stellar CLI v25.2.0+.
