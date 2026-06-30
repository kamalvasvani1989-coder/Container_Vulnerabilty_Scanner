#!/usr/bin/env python3
"""
Container image vulnerability scanner — Sprint 1 orchestration layer.

Wraps Trivy: runs it, parses its JSON, applies a pass/fail policy gate,
and reports the result.

Four jobs, kept separate on purpose:
  1. run_trivy   — shell out to Trivy, capture JSON. Failure here is a
                   TOOL error (scanner broke), not a policy decision.
  2. parse       — pull vulnerabilities + severities out of Trivy's JSON.
  3. apply_gate  — count by severity, compare to thresholds, decide.
  4. report      — print a summary and exit with a meaningful code.

Exit codes (CI/CD in the next sprint keys off these):
  0  PASS        — scan ran, policy satisfied
  1  POLICY FAIL — scan ran, too many vulnerabilities (block the build)
  2  TOOL ERROR  — could not scan or could not read config (alert someone)

The distinction between exit 1 and exit 2 is the whole point: a broken
scanner must never look like a passing build, and a vulnerability block
must never look like a crash.
"""

import argparse
import json
import subprocess
import sys

import yaml

# Exit codes as named constants, so the intent is readable everywhere.
EXIT_PASS = 0
EXIT_POLICY_FAIL = 1
EXIT_TOOL_ERROR = 2

DEFAULT_POLICY_PATH = "policy.yaml"


# --- Job 1: run Trivy -------------------------------------------------------

def run_trivy(image):
    """
    Run Trivy against an image and return its parsed JSON as a dict.

    Raises RuntimeError on any tool-level failure (Trivy missing, image
    not found, bad output). The caller turns that into exit code 2.

    Note: we do NOT use Trivy's own --exit-code flag. We want Trivy to
    exit 0 whenever the *scan itself* succeeds, regardless of what it
    found, so that a non-zero exit unambiguously means the tool failed.
    The pass/fail decision is ours to make, in apply_gate().
    """
    cmd = [
        "trivy", "image",
        "--format", "json",
        "--quiet",
        image,
    ]
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "Trivy is not installed or not on PATH. "
            "Install it (see the setup guide) and try again."
        )

    if completed.returncode != 0:
        # Trivy ran but failed — e.g. image not found, network error.
        raise RuntimeError(
            f"Trivy failed (exit {completed.returncode}).\n"
            f"{completed.stderr.strip()}"
        )

    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Could not parse Trivy JSON output: {exc}")


# --- Job 2: parse -----------------------------------------------------------

def parse_vulnerabilities(trivy_output):
    """
    Extract a flat list of vulnerabilities from Trivy's JSON.

    Trivy nests them under Results[].Vulnerabilities[]. Some Result
    entries (clean layers) have no 'Vulnerabilities' key at all, so we
    tolerate that with .get(..., []).

    Returns a list of dicts, each with the fields we care about.
    """
    vulns = []
    for result in trivy_output.get("Results", []) or []:
        for v in result.get("Vulnerabilities", []) or []:
            vulns.append({
                "id": v.get("VulnerabilityID", "UNKNOWN"),
                "severity": (v.get("Severity") or "UNKNOWN").upper(),
                "package": v.get("PkgName", ""),
                "installed": v.get("InstalledVersion", ""),
                "fixed": v.get("FixedVersion", ""),
            })
    return vulns


def count_by_severity(vulns):
    """Return a dict of severity -> count, e.g. {'CRITICAL': 1, 'HIGH': 7}."""
    counts = {}
    for v in vulns:
        sev = v["severity"]
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# --- Config loading (a config problem is a TOOL error, exit 2) --------------

def load_policy(path):
    """
    Load thresholds from the policy YAML.

    A missing or malformed policy file is a TOOL/config error, not a
    policy failure — the gate can't run, so it must not silently pass.
    """
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        raise RuntimeError(f"Policy file not found: {path}")
    except yaml.YAMLError as exc:
        raise RuntimeError(f"Policy file is not valid YAML: {exc}")

    if not isinstance(data, dict) or "thresholds" not in data:
        raise RuntimeError(
            f"Policy file {path} must contain a 'thresholds' section."
        )

    thresholds = data["thresholds"]
    if not isinstance(thresholds, dict):
        raise RuntimeError("'thresholds' must be a mapping of severity to a number.")

    # Normalise keys to uppercase and validate values are integers.
    clean = {}
    for sev, limit in thresholds.items():
        if not isinstance(limit, int):
            raise RuntimeError(
                f"Threshold for {sev} must be a whole number, got {limit!r}."
            )
        clean[str(sev).upper()] = limit
    return clean


# --- Job 3: apply the policy gate -------------------------------------------

def apply_gate(counts, thresholds):
    """
    Decide pass/fail by comparing severity counts to thresholds.

    A severity breaches the gate when its count EXCEEDS (>) its limit.
    Only severities listed in the policy are enforced; anything not
    listed (e.g. MEDIUM, LOW) is reported but does not gate.

    Returns (passed: bool, breaches: list of human-readable strings).
    """
    breaches = []
    for sev, limit in thresholds.items():
        found = counts.get(sev, 0)
        if found > limit:
            breaches.append(
                f"{sev}: found {found}, limit is {limit}"
            )
    return (len(breaches) == 0, breaches)


# --- Job 4: report ----------------------------------------------------------

def report(image, counts, thresholds, passed, breaches):
    """Print a human-readable summary of the scan and the gate decision."""
    print(f"\nScan results for: {image}")
    print("-" * 50)

    if counts:
        # Show severities in a sensible order, then any extras.
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        seen = [s for s in order if s in counts]
        seen += [s for s in counts if s not in order]
        for sev in seen:
            gated = " (gated)" if sev in thresholds else ""
            print(f"  {sev:<9} {counts[sev]}{gated}")
    else:
        print("  No vulnerabilities found.")

    print("-" * 50)
    if passed:
        print("RESULT: PASS — policy satisfied.\n")
    else:
        print("RESULT: FAIL — policy gate breached:")
        for b in breaches:
            print(f"  - {b}")
        print()


# --- Entry point ------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Scan a container image with Trivy and apply a policy gate."
    )
    parser.add_argument("image", help="Image to scan, e.g. python:3.9-slim")
    parser.add_argument(
        "--policy",
        default=DEFAULT_POLICY_PATH,
        help=f"Path to the policy YAML (default: {DEFAULT_POLICY_PATH})",
    )
    args = parser.parse_args()

    # Load config first — a config error is a tool error, and there's no
    # point scanning if we can't evaluate the result.
    try:
        thresholds = load_policy(args.policy)
    except RuntimeError as exc:
        print(f"CONFIG ERROR: {exc}", file=sys.stderr)
        return EXIT_TOOL_ERROR

    # Run the scan.
    try:
        trivy_output = run_trivy(args.image)
    except RuntimeError as exc:
        print(f"TOOL ERROR: {exc}", file=sys.stderr)
        return EXIT_TOOL_ERROR

    # Parse, count, gate, report.
    vulns = parse_vulnerabilities(trivy_output)
    counts = count_by_severity(vulns)
    passed, breaches = apply_gate(counts, thresholds)
    report(args.image, counts, thresholds, passed, breaches)

    return EXIT_PASS if passed else EXIT_POLICY_FAIL


if __name__ == "__main__":
    sys.exit(main())