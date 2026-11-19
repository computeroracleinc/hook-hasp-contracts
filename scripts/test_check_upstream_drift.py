#!/usr/bin/env python3
"""
Unit and functional tests for check_upstream_drift.py
"""

import sys
import unittest
from pathlib import Path

# Add scripts directory to path
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root / "scripts"))

from check_upstream_drift import (
    parse_semver,
    is_version_lower,
    extract_pinned_oz_versions,
    check_version_vulnerable_to_advisory,
)


class TestSemverAndDrift(unittest.TestCase):
    def test_parse_semver(self):
        self.assertEqual(parse_semver("0.7.2"), (0, 7, 2, ""))
        self.assertEqual(parse_semver("=0.7.2"), (0, 7, 2, ""))
        self.assertEqual(parse_semver("v0.7.3"), (0, 7, 3, ""))
        self.assertEqual(parse_semver("v0.8.0-rc.1"), (0, 8, 0, "rc.1"))

    def test_is_version_lower(self):
        self.assertTrue(is_version_lower("0.7.2", "0.7.3"))
        self.assertTrue(is_version_lower("0.7.2", "0.8.0"))
        self.assertFalse(is_version_lower("0.7.3", "0.7.2"))
        self.assertFalse(is_version_lower("0.7.2", "0.7.2"))
        self.assertTrue(is_version_lower("0.8.0-rc.1", "0.8.0"))
        self.assertFalse(is_version_lower("0.8.0", "0.8.0-rc.1"))

    def test_extract_pinned_oz_versions(self):
        pinned = extract_pinned_oz_versions(repo_root / "Cargo.toml")
        self.assertIn("stellar-accounts", pinned)
        self.assertEqual(pinned["stellar-accounts"], "0.7.2")
        self.assertIn("stellar-contract-utils", pinned)
        self.assertEqual(pinned["stellar-contract-utils"], "0.7.2")

    def test_check_version_vulnerable_to_advisory(self):
        advisory = {
            "ghsa_id": "GHSA-jpg9-m7w4-c7wc",
            "summary": "Delegated signers can authorize a smart account without keys",
            "vulnerabilities": [
                {
                    "package": {"name": "stellar-accounts"},
                    "vulnerable_version_range": "< 0.7.3",
                    "patched_versions": "0.7.3",
                },
                {
                    "package": {"name": "stellar-accounts"},
                    "vulnerable_version_range": ">= 0.8.0-rc.1, < 0.8.0",
                    "patched_versions": "0.8.0",
                },
            ],
        }

        # 0.7.2 is < 0.7.3 -> should be vulnerable
        is_vuln, patched = check_version_vulnerable_to_advisory("0.7.2", "stellar-accounts", advisory)
        self.assertTrue(is_vuln)
        self.assertEqual(patched, "0.7.3")

        # 0.7.3 is patched -> not vulnerable
        is_vuln, _ = check_version_vulnerable_to_advisory("0.7.3", "stellar-accounts", advisory)
        self.assertFalse(is_vuln)

        # 0.8.0-rc.2 is in range [0.8.0-rc.1, 0.8.0) -> vulnerable
        is_vuln, patched = check_version_vulnerable_to_advisory("0.8.0-rc.2", "stellar-accounts", advisory)
        self.assertTrue(is_vuln)

        # 0.8.0 is patched -> not vulnerable
        is_vuln, _ = check_version_vulnerable_to_advisory("0.8.0", "stellar-accounts", advisory)
        self.assertFalse(is_vuln)

        # Unrelated package should not match
        is_vuln, _ = check_version_vulnerable_to_advisory("0.7.2", "stellar-tokens", advisory)
        self.assertFalse(is_vuln)


if __name__ == "__main__":
    unittest.main()
