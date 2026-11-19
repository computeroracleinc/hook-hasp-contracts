# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in any contract in this repository,
please report it privately by email to **superfranky@3k1labs.com** rather than
opening a public issue. Include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, or a proof of concept if you have one.
- The affected contract(s) and, if known, the affected function(s).

We'll acknowledge your report as soon as we can and keep you updated as we
investigate and fix the issue. Please give us a reasonable amount of time to
address the report before any public disclosure.

## Scope

This policy covers every deployable contract crate in this repository's Cargo
workspace:

- `latch-smart-account` — the account contract itself, including its
  self-authorized `upgrade()` and `deploy_contract` entrypoints.
- `account-factory/contracts/factory-contract` — the `dummy-*` crates beside
  it are test fixtures only.
- `latch-verifiers/*` — `ed25519-verifier`, `p256-verifier`,
  `secp256k1-verifier`, `webauthn-verifier`.
- `policies/*` — `threshold-policy`, `weighted-threshold-policy`,
  `session-policy`, `spending-limit-policy`,
  `multi-token-spending-limit-policy`, `parameter-scoped-policy`,
  `recipient-allowlist-policy`.
- `fee-forwarder` — the permissioned relayer-sponsorship contract, including
  its admin / manager / executor role handling.
- `templates/*` — `timelock-vault`, `vesting-schedule`. These are reference
  contracts that users deploy for themselves rather than Latch-operated
  singletons, but a bug in one still puts funds at risk, so please report it
  here too.

`demo/modified-ed25519-verifier` is a worked reference that is explicitly not
meant to be deployed. Reports against it are still welcome, but it is not a
production surface.

Vulnerabilities in upstream dependencies (e.g. OpenZeppelin's
[stellar-contracts](https://github.com/OpenZeppelin/stellar-contracts), or the
Soroban SDK / host itself) should be reported directly to their respective
maintainers, not to us — though we'd still appreciate a heads-up if it affects
how we use them.

## Status

This project has not yet undergone an external security audit. Treat it as
early-stage software: do not deploy it to hold real value without your own
independent review. This will be updated once an audit has taken place.

## Automated Anti-Malware & Supply-Chain Safety Checks

Every push and pull request is gated by automated malware-prevention and
supply-chain integrity checks:

- **Static Anti-Malware Scanner (`scripts/security_malware_check.sh`)** —
  Runs in CI (`.github/workflows/security-malware.yml`) and locally as a git
  pre-commit hook (`.githooks/pre-commit`). Blocks:
  - Native executables and archives (ELF, PE/MZ, Mach-O, ZIP/TAR/JAR) detected
    by magic bytes regardless of file extension, as well as unauthorized `.wasm`
    binaries outside `deployments/artifacts/*/` and `**/testdata/`.
  - Build-time arbitrary code execution hooks (`build.rs`, `proc-macro = true`,
    and `.cargo/config.toml` `runner`/`linker`/`rustc-wrapper`/`rustflags`).
  - Host-escape or unsafe Rust constructs (`unsafe`, `std::process`, `std::net`,
    `std::fs`, `std::env`, `extern "C"`, `transmute`, `libc`).
  - Obfuscated script droppers (`curl|bash`, `base64 -d | sh`, reverse shells,
    secret exfiltration).
  - Trojan Source (CVE-2021-42574) bidirectional and zero-width Unicode attacks.
  - Rogue Cargo sources (`git =`, alternative registries, wildcard versions,
    non-crates.io entries in `Cargo.lock`).
  - Hardcoded private keys, Stellar secret seeds (`S...`), and cloud/GitHub
    tokens.
  - Unpinned GitHub Actions or workflows missing explicit `permissions:`.
- **Dependency & License Gates (`deny.toml`, `cargo-audit`, Dependency Review,
  CodeQL)** — Blocks vulnerable, yanked, unsound, copyleft, or non-crates.io
  dependencies on every PR and weekly scheduled run.
- **Upstream OpenZeppelin Drift & Security Advisory Audit (`scripts/check_upstream_drift.py`)** —
  Continuously monitors upstream `OpenZeppelin/stellar-contracts` for new releases,
  security advisories (GHSA), and patch notifications. Alerts maintainers in CI
  whenever the pinned workspace dependency version drifts or requires an upstream
  security fix.

Contributors should enable the local pre-commit hook once per clone:

```bash
./scripts/install-hooks.sh
```
