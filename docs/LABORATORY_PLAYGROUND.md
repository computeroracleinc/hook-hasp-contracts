# Stellar Laboratory Interactive Contract Playground

This guide walks through deploying a `LatchSmartAccount`, attaching policies (`session-policy`, `spending-limit-policy`), and executing contract calls interactively using **Stellar Laboratory** (<https://lab.stellar.org/>).

## Prerequisites

1. Open [Stellar Laboratory](https://lab.stellar.org/) and select **Testnet** in the top-right network selector.
2. Under **Account -> Create Account**, generate a keypair and click **Get test network lumens** (Friendbot) to fund it.
3. Have the deployed Testnet contract IDs ready (or deploy them via `scripts/bootstrap-testnet.sh`).

---

## Step 1: Deploy a Smart Account via `factory-contract`

1. Navigate to **Transactions -> Build Transaction**.
2. Set **Source Account** to your funded Testnet public key and click **Fetch next sequence**.
3. Add Operation -> **Invoke Contract Function**:
   - **Contract ID**: `<FACTORY_CONTRACT_ID>`
   - **Function Name**: `deploy`
   - **Arguments**:
     - `salt` (`BytesN<32>`): 64 hex characters (e.g., `0000...0001`).
     - `signers` (`Vec<Signer>`): Initial `Delegated` or `External` signers.
     - `policies` (`Map<Address, Val>`): Empty map `{}` or initial policy configurations.
4. Click **Simulate Transaction** to populate Soroban footprint/resources, then **Sign & Submit**.
5. Inspect the transaction result events for `account_created` — copy the returned `C...` smart account address.

---

## Step 2: Attach a `session-policy` Context Rule

1. Open **Transactions -> Build Transaction** with your owner account as source.
2. Add Operation -> **Invoke Contract Function**:
   - **Contract ID**: `<SMART_ACCOUNT_ID>`
   - **Function Name**: `add_context_rule`
   - **Arguments**:
     - `context_type`: `CallContract(<TARGET_DAPP_CONTRACT_ID>)`
     - `name`: `"dapp-session"`
     - `valid_until`: `Some(<FUTURE_LEDGER_SEQ>)` (or `None`)
     - `signers`: `[Delegated(<SESSION_KEY_PUBLIC_KEY>)]`
     - `policies`: `{ "<SESSION_POLICY_ID>": { "allowed_fns": ["transfer", "swap"] } }`
3. Simulate, sign with the owner key, and submit.

---

## Step 3: Verify Policy Configuration (Read-Only Simulation)

1. Go to **Smart Contracts -> Contract Explorer** in Stellar Laboratory.
2. Enter `<SESSION_POLICY_ID>` and invoke `get_allowed_fns`:
   - `context_rule_id`: `1` (or the rule ID emitted in `session_installed`)
   - `smart_account`: `<SMART_ACCOUNT_ID>`
3. Click **Simulate** — the output displays the allowlisted `Symbol` list (`["transfer", "swap"]`).

---

## Step 4: Execute a Scoped Call Using the Session Signer

1. Build an invocation against `<TARGET_DAPP_CONTRACT_ID>` (e.g., `transfer`) where the `from` / auth source is `<SMART_ACCOUNT_ID>`.
2. Simulate the transaction in Laboratory so Soroban generates the `__check_auth` authorization entry for `<SMART_ACCOUNT_ID>`.
3. Sign the Soroban auth entry with `<SESSION_KEY>` and submit.
4. Verify the `session_enforced` event in the transaction's **Events** tab.
