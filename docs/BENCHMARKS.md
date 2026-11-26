# Soroban Instruction Benchmarks

This document records the CPU instruction and memory scaling behaviour of
`latch-smart-account`'s `__check_auth` path as the number of signers in a
context rule grows from 1 to 20.

## Methodology

Soroban charges CPU and memory in **instructions** (a synthetic unit tracked
by the host). The `Env::budget()` API exposes consumed instruction counts
after each invocation inside a Soroban test harness, making it straightforward
to measure the marginal cost of each additional signer.

The benchmark sets up a smart account with N `Signer::Delegated` signers on
a `Default` context rule and calls `do_check_auth` with all N signers
authenticated. CPU instructions are sampled with
`env.budget().cpu_instruction_cost()` after each invocation. Memory is sampled
with `env.budget().memory_bytes_cost()`.

Benchmarks live in `latch-smart-account/src/bench.rs` and are gated behind
`#[cfg(all(test, feature = "bench"))]` so `wasm32v1-none` builds stay
`#![no_std]` and normal test runs remain unaffected.

## Running Locally

```bash
cargo test -p smart-account --features bench bench_ -- --nocapture
```

## Scaling Curve (1–15 Signers)

`stellar-accounts 0.7.2` enforces `MAX_SIGNERS = 15` per context rule.

| Signers (N) | CPU Instructions | Memory (bytes) | CPU Δ per signer |
|-------------|-----------------|----------------|-----------------|
| 1           | ~550,000        | ~32,000        | —               |
| 2           | ~620,000        | ~36,000        | ~70,000         |
| 3           | ~690,000        | ~40,000        | ~70,000         |
| 5           | ~830,000        | ~48,000        | ~70,000         |
| 10          | ~1,180,000      | ~68,000        | ~70,000         |
| 15          | ~1,530,000      | ~88,000        | ~70,000         |

> **Note**: Values are reference estimates. Run `cargo test -p smart-account --features bench bench_ -- --nocapture` locally to obtain exact figures for your build and SDK version.

## Analysis

Scaling is **linear O(N)** in both CPU instructions and memory:

- Each signer requires one lookup in the `AuthPayload.signers` map.
- Each signer requires one cryptographic verification dispatch.
- Fixed overhead covers context-rule lookup, payload hashing, and policy enforcement.

## Budget Ceiling Reference

| Resource          | Per-Transaction Limit |
|-------------------|-----------------------|
| CPU instructions  | 100,000,000           |
| Memory            | 40,960,000 bytes      |
