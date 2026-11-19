# Formal Security Proof: Threshold Policy Signature Verification

This document provides a formal cryptographic security proof for the `threshold-policy` contract (`policies/threshold-policy/src/lib.rs`) and its underlying OpenZeppelin `simple_threshold` enforcement logic, demonstrating that threshold authorization reduces to the Existential Unforgeability under Chosen Message Attacks (EUF-CMA) of the underlying signature schemes.

## 1. System Model & Definitions

### 1.1 Entities and Parameters
- **Smart Account** $A$: A Soroban contract implementing `__check_auth(signature_payload, signatures, auth_contexts)`.
- **Context Rule** $R$: A rule identified by `context_rule_id` $\in \mathbb{N}$ associated with an ordered set of authorized signers $S = \{s_1, s_2, \dots, s_n\}$ and a threshold policy instance with parameter $t \in \mathbb{N}$ ($1 \le t \le n$).
- **Underlying Signature Schemes**: Each signer $s_i \in S$ is bound to a verifier contract $V_i \in \{\text{Ed25519}, \text{P-256}, \text{secp256k1}, \text{WebAuthn}\}$ and a public key $pk_i$.
- **Authentication Payload**: $m \in \{0, 1\}^*$ is the Soroban `signature_payload` (a 32-byte hash committing to the transaction invocation, network ID, nonce, and `auth_contexts`).

### 1.2 Protocol Execution (`enforce`)
When an action governed by rule $R$ is invoked:
1. The smart account's `__check_auth` verifies each submitted signature $\sigma_j$ against its corresponding signer $s_j \in S$ by calling $V_j.\text{verify}(m, pk_j, \sigma_j)$.
2. Only signers for which $V_j.\text{verify}(m, pk_j, \sigma_j) = \text{true}$ are included in the deduplicated `authenticated_signers` vector $S_{\text{auth}} \subseteq S$.
3. `ThresholdPolicy::enforce` delegates to `simple_threshold::enforce`, which asserts:
   $$|S_{\text{auth}} \cap S| \ge t$$
   and panics (aborting the transaction) otherwise.

### 1.3 Security Definition (Threshold Unforgeability)
A threshold policy $(S, t)$ is **$(t, n)$-unforgeable** if no probabilistic polynomial-time (PPT) adversary $\mathcal{A}$, given:
- Public keys $\{pk_1, \dots, pk_n\}$ for $S$,
- Corruption of at most $c < t$ signers $C \subset S$ ($|C| \le t - 1$),
- Access to signing oracles $\mathcal{O}_{\text{Sign}}(pk_i, \cdot)$ for all honest signers $s_i \in S \setminus C$,

can produce a valid authorization for a fresh payload $m^*$ (never queried to $\mathcal{O}_{\text{Sign}}$ for at least $t - |C|$ distinct honest signers) that passes `ThresholdPolicy::enforce` with non-negligible probability.

---

## 2. Formal Security Reduction

### Theorem 1 (Threshold Policy Unforgeability)
Suppose each underlying signature scheme $\Sigma_i = (\text{KeyGen}_i, \text{Sign}_i, \text{Verify}_i)$ used by signers in $S$ is $\text{EUF-CMA}$-secure. Then the $t$-of-$n$ `ThresholdPolicy` is $(t, n)$-unforgeable. Specifically, for any PPT adversary $\mathcal{A}$ breaking $(t, n)$-unforgeability with advantage $\epsilon_{\text{thresh}}$, there exists a PPT adversary $\mathcal{B}$ breaking $\text{EUF-CMA}$ of at least one underlying signature scheme $\Sigma_k$ with advantage:
$$\epsilon_{\text{EUF-CMA}} \ge \frac{\epsilon_{\text{thresh}}}{n - |C|}$$

### Proof
Assume for contradiction that a PPT adversary $\mathcal{A}$ succeeds in forging a valid threshold authorization for a fresh payload $m^*$ with non-negligible probability $\epsilon_{\text{thresh}}$, while corrupting a set $C \subset S$ of size $|C| \le t - 1$.

We construct a PPT reduction $\mathcal{B}$ that plays the $\text{EUF-CMA}$ game against a challenger $\mathcal{C}$ for a target honest signer $s_{i^*} \in S \setminus C$:

1. **Setup**:
   - $\mathcal{C}$ generates a challenge keypair $(pk^*, sk^*)$ for $\Sigma_{i^*}$ and gives $pk^*$ to $\mathcal{B}$.
   - $\mathcal{B}$ picks an index $i^* \xleftarrow{\$} \{1, \dots, n\} \setminus C$ uniformly at random.
   - $\mathcal{B}$ sets $pk_{i^*} = pk^*$. For all other signers $s_i \in S \setminus \{s_{i^*}\}$, $\mathcal{B}$ runs $\text{KeyGen}_i$ itself to obtain $(pk_i, sk_i)$, giving $\mathcal{A}$ the public keys $\{pk_1, \dots, pk_n\}$ and the secret keys $\{sk_i : i \in C\}$ for the corrupted set.

2. **Oracle Simulation**:
   - When $\mathcal{A}$ queries $\mathcal{O}_{\text{Sign}}(pk_i, m)$ for $i \neq i^*$, $\mathcal{B}$ computes $\sigma_i \leftarrow \text{Sign}_i(sk_i, m)$ using its own key $sk_i$.
   - When $\mathcal{A}$ queries $\mathcal{O}_{\text{Sign}}(pk_{i^*}, m)$, $\mathcal{B}$ forwards $m$ to its $\text{EUF-CMA}$ challenger $\mathcal{C}$ and returns the resulting signature $\sigma^*$ to $\mathcal{A}$.

3. **Forgery Extraction**:
   - Eventually, $\mathcal{A}$ outputs a payload $m^*$ and a set of authenticated signers $S_{\text{auth}} \subseteq S$ with corresponding signatures $\{\sigma_j\}_{s_j \in S_{\text{auth}}}$ that passes `ThresholdPolicy::enforce`.
   - By the `enforce` invariant, $|S_{\text{auth}} \cap S| \ge t$.
   - Since $|C| \le t - 1$, by the pigeonhole principle, $S_{\text{auth}}$ must contain at least $t - |C| \ge 1$ honest signers $H = S_{\text{auth}} \setminus C$.
   - For at least one honest signer $s_h \in H$, $m^*$ was not queried to $\mathcal{O}_{\text{Sign}}(pk_h, \cdot)$ (otherwise $m^*$ would not be fresh).
   - Since $i^*$ was chosen uniformly at random from $S \setminus C$ (size $n - |C|$) and $\mathcal{A}$'s view is independent of $i^*$, we have $\Pr[s_{i^*} \in H \text{ and } m^* \text{ unqueried for } s_{i^*}] \ge \frac{1}{n - |C|}$.
   - Whenever this event occurs, $\mathcal{B}$ outputs $(m^*, \sigma_{i^*})$ as its $\text{EUF-CMA}$ forgery to $\mathcal{C}$. Since `ThresholdPolicy::enforce` only accepts signers that passed $V_{i^*}.\text{verify}(m^*, pk^*, \sigma_{i^*}) = \text{true}$, $(m^*, \sigma_{i^*})$ is a valid forgery against $\Sigma_{i^*}$.

Thus, $\epsilon_{\text{EUF-CMA}} \ge \frac{\epsilon_{\text{thresh}}}{n - |C|}$. Since $\epsilon_{\text{thresh}}$ is non-negligible and $n - |C| \le n$ is polynomial, $\epsilon_{\text{EUF-CMA}}$ is non-negligible, contradicting the $\text{EUF-CMA}$ security of $\Sigma_{i^*}$. $\blacksquare$

---

## 3. Implementation & Trust Boundary Mapping

The reduction above relies on the following concrete properties of the Latch / OpenZeppelin Soroban implementation:

1. **Deduplication of `authenticated_signers`**: `__check_auth` in `LatchSmartAccount` (via OZ `SmartAccount`) deduplicates verified signers before passing `authenticated_signers` to `ThresholdPolicy::enforce`, preventing a single compromised key from being counted multiple times toward $t$.
2. **Domain Separation**: Soroban's `signature_payload` ($m$) is computed by the host and binds the network passphrase, contract address, nonce, and `auth_contexts`, preventing cross-contract or cross-chain replay.
3. **Threshold Bounds**: `ThresholdPolicy::install` and `set_threshold` enforce $1 \le t \le |S|$ at the time of configuration.
4. **Signer-Set Divergence Caveat**: As documented in [`AUDIT_SCOPE.md`](AUDIT_SCOPE.md#known-and-accepted-risks-please-confirm-dont-rediscover), `remove_signer` does not automatically re-validate $t \le |S|$. Administrators must update $t$ via `set_threshold` in the same transaction when modifying $S$.
