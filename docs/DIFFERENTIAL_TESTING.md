# Differential Testing: Soroban SDK In-Memory Host vs Real Testnet

## Overview

Differential testing exercises identical sequences of transactions across two execution environments:
1. **Local Soroban SDK Simulated Host**: The in-memory Rust host execution environment used during unit and integration tests (`soroban-sdk::Env`).
2. **Real Soroban Testnet / RPC Node**: The actual Soroban network (or local standalone testnet sandbox node) executing transactions submitted via Soroban JSON-RPC (`simulateTransaction` and `sendTransaction`).

The objective is to verify operational and state parity between local simulated execution and live network execution.

## Differential Dimensions Verified

1. **Transaction Simulation Parity (`simulateTransaction`)**:
   - Compares simulation return values and status (`SUCCESS` vs `FAILED`).
   - Compares transaction foot-print / storage read-write sets.
   - Compares CPU/memory resource consumption bounds and authorization payloads.

2. **State Transition & Ledger Parity**:
   - State entry values (contract instance storage, temporary data, persistent data).
   - Storage key derivation (`ScVal` formatting and cryptographic hashing).
   - State tree / LedgerEntry hashes computed across storage changes.

3. **Error & Revert Parity**:
   - Revert reason codes, panic behavior, and precondition failure consistency across host simulator and real testnet runtime.

## Test Sequences

The differential suite defines canonical transaction sequences across representative contracts:
- **Verifier Contracts (`ed25519-verifier`, `p256-verifier`, `secp256k1-verifier`)**: Signature verification and invalid signature rejection across environments.
- **Policy Contracts (`spending-limit-policy`, `threshold-policy`, `recipient-allowlist-policy`)**: Rule evaluation, state accumulation across multiple ledgers, and unauthorized call rejection.
- **Template Contracts (`timelock-vault`, `vesting-schedule`)**: State progression, balance calculations, deposit and claim invariants.

## Running the Differential Test Harness

The differential suite is designed to run in two modes:
1. **Local Mode (Mock/Recorded Live Parity Check)**: Runs the differential harness comparing local host results against pre-recorded or deterministic testnet RPC node snapshots without requiring external network access.
2. **Live Testnet Mode**: Configured with `SOROBAN_RPC_URL` and `NETWORK_PASSPHRASE` pointing to the Stellar Testnet (or local Soroban RPC container) to run real-time differential validation.

```bash
# Run differential test verification script
python3 scripts/differential_test_runner.py

# Run with custom RPC endpoint:
SOROBAN_RPC_URL="https://soroban-testnet.stellar.org" \
NETWORK_PASSPHRASE="Test SDF Network ; September 2015" \
python3 scripts/differential_test_runner.py --live
```
