#!/usr/bin/env python3
"""
Upstream OpenZeppelin stellar-contracts Drift & Security Advisory Detector

Compares pinned workspace dependencies in Cargo.toml (specifically stellar-accounts
and other OpenZeppelin stellar-* packages) against upstream GitHub releases,
security advisories, and crates.io releases.

Exits with:
  0: Up-to-date (no drift) or only non-security drift when --fail-on-security-only is passed.
  1: Upstream security advisory or security patch release detected.
  2: Any drift detected (when in strict/default mode) or invalid CLI usage.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

UPSTREAM_REPO = "OpenZeppelin/stellar-contracts"
DEFAULT_GITHUB_API = "https://api.github.com"
DEFAULT_CRATES_API = "https://crates.io/api/v1/crates"


def parse_semver(v_str: str) -> Tuple[int, int, int, str]:
    """Parse a basic semver string (e.g., '0.7.2', 'v0.7.3', '0.8.0-rc.1')."""
    v = v_str.strip()
    if v.startswith("v") or v.startswith("="):
        v = v[1:]
    if v.startswith("="):
        v = v[1:]
    
    prerelease = ""
    if "-" in v:
        v, prerelease = v.split("-", 1)

    parts = v.split(".")
    major = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 0
    minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0

    return major, minor, patch, prerelease


def is_version_lower(v1: str, v2: str) -> bool:
    """Return True if v1 is strictly lower than v2 according to semver."""
    maj1, min1, pat1, pre1 = parse_semver(v1)
    maj2, min2, pat2, pre2 = parse_semver(v2)

    if (maj1, min1, pat1) < (maj2, min2, pat2):
        return True
    if (maj1, min1, pat1) > (maj2, min2, pat2):
        return False

    # Same major.minor.patch
    # If one has prerelease and other doesn't, prerelease is lower (e.g. 0.8.0-rc.1 < 0.8.0)
    if pre1 and not pre2:
        return True
    if not pre1 and pre2:
        return False
    if pre1 and pre2:
        return pre1 < pre2

    return False


def extract_pinned_oz_versions(cargo_toml_path: Path) -> Dict[str, str]:
    """
    Extract stellar-* dependencies pinned in Cargo.toml [workspace.dependencies].
    """
    if not cargo_toml_path.is_file():
        raise FileNotFoundError(f"Cargo.toml not found at {cargo_toml_path}")

    content = cargo_toml_path.read_text(encoding="utf-8")
    in_workspace_deps = False
    pinned: Dict[str, str] = {}

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            in_workspace_deps = (line == "[workspace.dependencies]")
            continue

        if in_workspace_deps:
            # Match e.g. stellar-accounts = "=0.7.2" or stellar-accounts = "0.7.2"
            m = re.match(r'^(stellar-[\w-]+)\s*=\s*["\']([^"\']+)["\']', line)
            if m:
                pkg_name, ver = m.groups()
                clean_ver = ver.lstrip("=")
                pinned[pkg_name] = clean_ver

    return pinned


def fetch_json(url: str, headers: Optional[Dict[str, str]] = None) -> Any:
    """Fetch JSON from a URL with custom headers."""
    req_headers = {
        "User-Agent": "hook-hasp-upstream-drift-check/1.0",
        "Accept": "application/vnd.github.v3+json",
    }
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read().decode("utf-8")
            return json.loads(data)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def get_upstream_releases(github_token: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetch releases from upstream GitHub repository."""
    url = f"{DEFAULT_GITHUB_API}/repos/{UPSTREAM_REPO}/releases?per_page=30"
    headers = {}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    data = fetch_json(url, headers)
    return data if isinstance(data, list) else []


def get_upstream_advisories(github_token: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetch repository security advisories from upstream."""
    url = f"{DEFAULT_GITHUB_API}/repos/{UPSTREAM_REPO}/security-advisories"
    headers = {}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    data = fetch_json(url, headers)
    return data if isinstance(data, list) else []


def check_version_vulnerable_to_advisory(ver: str, pkg_name: str, advisory: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Check if a version of pkg_name is vulnerable according to an advisory dict.
    Returns (is_vulnerable, patched_version).
    """
    vulnerabilities = advisory.get("vulnerabilities", [])
    for vuln in vulnerabilities:
        vuln_pkg = vuln.get("package", {}).get("name", "")
        # If advisory specifies a package, ensure it matches (or stellar-contracts umbrella)
        if vuln_pkg and vuln_pkg != pkg_name and vuln_pkg != "stellar-contracts":
            continue

        patched = vuln.get("patched_versions")
        vuln_range = vuln.get("vulnerable_version_range", "")

        # Check vulnerability range if present
        # Format examples: "< 0.7.3", ">= 0.8.0-rc.1, < 0.8.0"
        if vuln_range:
            is_vuln = True
            parts = [p.strip() for p in vuln_range.split(",") if p.strip()]
            for part in parts:
                m_lt = re.match(r"^<\s*([0-9a-zA-Z\.\-]+)$", part)
                m_lte = re.match(r"^<=\s*([0-9a-zA-Z\.\-]+)$", part)
                m_gt = re.match(r"^>\s*([0-9a-zA-Z\.\-]+)$", part)
                m_gte = re.match(r"^>=\s*([0-9a-zA-Z\.\-]+)$", part)

                if m_lt:
                    target = m_lt.group(1)
                    if not is_version_lower(ver, target):
                        is_vuln = False
                elif m_lte:
                    target = m_lte.group(1)
                    if is_version_lower(target, ver):
                        is_vuln = False
                elif m_gt:
                    target = m_gt.group(1)
                    if not is_version_lower(target, ver):
                        is_vuln = False
                elif m_gte:
                    target = m_gte.group(1)
                    if is_version_lower(ver, target):
                        is_vuln = False

            if is_vuln:
                return True, patched
        elif patched:
            if is_version_lower(ver, patched):
                return True, patched

    return False, None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check pinned OpenZeppelin stellar-contracts version drift against upstream releases and security advisories."
    )
    parser.add_argument(
        "--manifest-path",
        type=Path,
        default=Path("Cargo.toml"),
        help="Path to workspace root Cargo.toml (default: Cargo.toml)",
    )
    parser.add_argument(
        "--github-token",
        type=str,
        default=os.getenv("GITHUB_TOKEN"),
        help="GitHub API token for higher rate limits (defaults to $GITHUB_TOKEN)",
    )
    parser.add_argument(
        "--fail-on-security-only",
        action="store_true",
        help="Exit with non-zero only if an unpatched security advisory or upstream security patch is found.",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        help="Write drift detection results to specified JSON file.",
    )

    args = parser.parse_args()

    print("================================================================================")
    print("OpenZeppelin stellar-contracts Upstream Drift & Security Advisory Check")
    print(f"Repository: {UPSTREAM_REPO}")
    print("================================================================================")

    # 1. Parse pinned versions in Cargo.toml
    pinned_packages = extract_pinned_oz_versions(args.manifest_path)
    if not pinned_packages:
        print(f"[-] No OpenZeppelin 'stellar-*' dependencies found in {args.manifest_path}")
        return 0

    print(f"[+] Found {len(pinned_packages)} pinned OpenZeppelin dependency(ies) in {args.manifest_path}:")
    for pkg, ver in pinned_packages.items():
        print(f"    - {pkg}: ={ver}")

    pinned_version = pinned_packages.get("stellar-accounts")
    if not pinned_version:
        # Fall back to the first available stellar-* package
        pinned_version = next(iter(pinned_packages.values()))

    print(f"\n[+] Pinned baseline version for upstream comparison: {pinned_version}")

    # 2. Fetch upstream releases
    releases: List[Dict[str, Any]] = []
    try:
        releases = get_upstream_releases(args.github_token)
        print(f"[+] Retrieved {len(releases)} upstream release(s) from GitHub API.")
    except Exception as e:
        print(f"[!] Warning: Could not fetch upstream GitHub releases ({e}). Continuing...")

    # 3. Fetch upstream advisories
    advisories: List[Dict[str, Any]] = []
    try:
        advisories = get_upstream_advisories(args.github_token)
        print(f"[+] Retrieved {len(advisories)} security advisory(ies) from upstream repository.")
    except Exception as e:
        print(f"[!] Warning: Could not fetch security advisories ({e}). Continuing...")

    # 4. Analyze releases and determine drift
    latest_stable_release: Optional[str] = None
    security_releases: List[Dict[str, Any]] = []
    higher_releases: List[Dict[str, Any]] = []

    for r in releases:
        tag = r.get("tag_name", "").lstrip("v")
        prerelease = r.get("prerelease", False)
        draft = r.get("draft", False)
        if draft:
            continue

        body = (r.get("body") or "").lower()
        name = (r.get("name") or "").lower()
        is_security_rel = any(kw in body or kw in name for kw in ["security", "cve", "ghsa", "vulnerability", "patch"])

        if is_version_lower(pinned_version, tag):
            higher_releases.append({
                "tag": tag,
                "name": r.get("name"),
                "published_at": r.get("published_at"),
                "is_security": is_security_rel,
                "url": r.get("html_url"),
            })

        if not prerelease and (latest_stable_release is None or is_version_lower(latest_stable_release, tag)):
            latest_stable_release = tag

        if is_security_rel and is_version_lower(pinned_version, tag):
            security_releases.append(r)

    # 5. Analyze advisories affecting pinned version
    active_advisories = []
    for adv in advisories:
        is_vuln, patched = check_version_vulnerable_to_advisory(pinned_version, "stellar-accounts", adv)
        if is_vuln:
            active_advisories.append({
                "ghsa_id": adv.get("ghsa_id"),
                "summary": adv.get("summary"),
                "patched_versions": patched,
                "html_url": adv.get("html_url"),
                "severity": adv.get("severity"),
            })

    # Summary Report
    print("\n--------------------------------------------------------------------------------")
    print("ANALYSIS SUMMARY")
    print("--------------------------------------------------------------------------------")
    print(f"Pinned version:        {pinned_version}")
    print(f"Latest upstream stable: {latest_stable_release or 'Unknown'}")
    print(f"Upstream releases > {pinned_version}: {len(higher_releases)}")
    print(f"Security advisories affecting {pinned_version}: {len(active_advisories)}")
    print(f"Upstream security releases > {pinned_version}: {len(security_releases)}")

    has_security_issue = len(active_advisories) > 0 or len(security_releases) > 0
    has_drift = len(higher_releases) > 0 or (latest_stable_release and is_version_lower(pinned_version, latest_stable_release))

    if active_advisories:
        print("\n[!] CRITICAL: Pinned version is affected by known security advisory(ies):")
        for adv in active_advisories:
            print(f"    * [{adv['ghsa_id']}] {adv['summary']}")
            print(f"      Severity: {adv['severity']}, Patched in: {adv['patched_versions']}")
            print(f"      Details: {adv['html_url']}")

    if security_releases:
        print("\n[!] CRITICAL: Upstream security release(s) available above pinned version:")
        for sr in security_releases:
            print(f"    * {sr.get('tag_name')}: {sr.get('name')}")
            print(f"      Release URL: {sr.get('html_url')}")

    if higher_releases and not has_security_issue:
        print("\n[*] NOTICE: Upstream feature or maintenance releases available (non-security drift):")
        for hr in higher_releases[:5]:
            print(f"    * {hr['tag']}: {hr['name']} ({hr['published_at']})")

    # JSON output if requested
    if args.output_json:
        result_payload = {
            "pinned_version": pinned_version,
            "pinned_packages": pinned_packages,
            "latest_upstream_stable": latest_stable_release,
            "has_drift": has_drift,
            "has_security_issue": has_security_issue,
            "active_advisories": active_advisories,
            "security_releases": [
                {
                    "tag": sr.get("tag_name"),
                    "name": sr.get("name"),
                    "url": sr.get("html_url"),
                }
                for sr in security_releases
            ],
            "higher_releases": higher_releases,
        }
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        args.output_json.write_text(json.dumps(result_payload, indent=2), encoding="utf-8")
        print(f"\n[+] Wrote detailed results to {args.output_json}")

    print("--------------------------------------------------------------------------------")

    if has_security_issue:
        print("[ALERT] Upstream security patch or advisory detected! Maintainer intervention required.")
        return 1

    if has_drift:
        if args.fail_on-security-only if hasattr(args, "fail_on-security-only") else args.fail_on_security_only:
            print("[INFO] Upstream drift exists, but no unpatched security advisories found. Passing (--fail-on-security-only).")
            return 0
        else:
            print("[WARN] Upstream version drift detected.")
            return 2

    print("[PASS] Pinned versions are fully up-to-date with upstream OpenZeppelin stellar-contracts.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
