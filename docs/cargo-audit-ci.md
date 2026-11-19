# Automated cargo-audit CI Verification & Security Audit Report

## Issue Reference
- **Issue**: #90 ([Supply] Set up automated cargo-audit in CI to catch vulnerable or malicious dependencies)
- **Status**: Implemented & Verified

## Objective & Scope
The objective is to integrate automated `cargo-audit` into GitHub Actions workflow to scan `Cargo.lock` against the RustSec Advisory Database on every commit (`push`), pull request (`pull_request`), and on a weekly cron schedule (`schedule: 0 6 * * 1`), ensuring known CVEs and malicious crates are blocked before code merges.

## Implementation Details

### 1. GitHub Actions CI Workflow Integration
In [`.github/workflows/security-malware.yml`](../.github/workflows/security-malware.yml), the `cargo-audit` job is configured as follows:
- **Triggers**:
  - `push` to `main` and `experimental`
  - `pull_request` to `main` and `experimental`
  - `schedule`: weekly cron (`0 6 * * 1`)
  - `workflow_dispatch` for manual runs
- **Security & Least-Privilege Permissions**:
  - Pinned `permissions: contents: read`
  - SHA-pinned GitHub Action: `rustsec/audit-check@69366f33c96575abad1ee0dba8212993eecbe998` (`v2.0.0`)
  - Runs directly against the workspace [`Cargo.lock`](../Cargo.lock)
  - Passes `${{ secrets.GITHUB_TOKEN }}` to handle GitHub API rate-limiting during advisory database fetching

### 2. Multi-Layer Supply Chain Defense Architecture
`cargo-audit` works in tandem with complementary supply-chain and malware defenses in the repository:
1. **`cargo-audit` (RustSec Advisory Database)**:
   - Scans dependency tree in `Cargo.lock` for CVEs, yanked versions, and reported vulnerabilities.
   - Configured with `ignore: RUSTSEC-2026-0387` (crypto-bigint 0.5.5 timing side-channel), which is strictly confined to `soroban-env-host` off-chain dev-dependencies / test harnesses; on-chain Soroban WASM contracts execute signature verifications via host syscalls.
2. **`cargo-deny` (`deny.toml`)**:
   - Enforces advisory checks (`yanked = "deny"`, `unsound = "all"`, `unmaintained = "workspace"`).
   - Enforces license compliance (`allow` list for permissive licenses; copyleft GPL/AGPL denied).
   - Enforces crate bans (bans native C dependencies like `openssl-sys`, `libssh2-sys`, `curl-sys`).
   - Enforces source registry isolation (`allow-registry = ["https://github.com/rust-lang/crates.io-index"]`, rogue git sources and unknown registries denied).
3. **Static Anti-Malware Scanner (`scripts/security_malware_check.sh`)**:
   - Blocks unauthorized native executables (ELF, PE/MZ, Mach-O, ZIP/TAR).
   - Blocks build-time execution hooks (`build.rs`, `proc-macro = true`, `.cargo/config.toml` runners).
   - Blocks unsafe Rust OS/network escapes (`std::process`, `std::net`, `std::fs`, `libc`, `transmute`).
   - Blocks Trojan Source Unicode attacks (CVE-2021-42574) and leaked credentials.
4. **GitHub Dependency Review Action**:
   - Blocks pull requests introducing vulnerable or copyleft dependencies at the PR boundary.

### 3. Verification & Compliance
- Security policy documentation in [`SECURITY.md`](../SECURITY.md) accurately references `cargo-audit` under "Automated Anti-Malware & Supply-Chain Safety Checks".
- Script validation tests (`./scripts/test_security_malware_check.sh` and `./scripts/security_malware_check.sh`) pass 100% cleanly.
- Strict SHA pinning is observed across all actions in `.github/workflows/security-malware.yml`.
