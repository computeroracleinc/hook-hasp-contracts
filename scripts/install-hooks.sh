#!/usr/bin/env bash
# Configures git to use the repository-managed .githooks directory so the
# anti-malware & supply-chain scanner runs automatically before every commit.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
chmod +x "$REPO_ROOT/.githooks/pre-commit" "$REPO_ROOT/scripts/security_malware_check.sh" "$REPO_ROOT/scripts/test_security_malware_check.sh" "$REPO_ROOT/scripts/license_compliance_check.sh" "$REPO_ROOT/scripts/test_license_compliance_check.sh"
git -C "$REPO_ROOT" config core.hooksPath .githooks
echo "Configured core.hooksPath=.githooks (pre-commit anti-malware check is now active)."
