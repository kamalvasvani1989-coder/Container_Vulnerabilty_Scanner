#!/usr/bin/env python3
"""
Container image vulnerability scanner — orchestration layer.

Wraps Trivy: runs it, parses its JSON, applies a pass/fail policy gate,
and reports the result.

Four jobs, kept separate on purpose:
  1. run_trivy   — shell out to Trivy, capture JSON. Failure here is a
                   TOOL error (scanner broke), not a policy decision.
  2. parse       — pull vulnerabilities + severities out of Trivy's JSON.
  3. apply_gate  — count by severity, compare to thresholds, decide.
  4. report      — print a summary and exit with a meaningful code.

Sprint 3 addition — optional output files (--output-dir DIR):
  trivy-report.json  — Trivy's raw JSON, byte-for-byte as Trivy produced it.
  scan-summary.json  — our verdict: counts, thresholds, breaches, status.
Both come from the SAME single scan, so the report and the gate decision
can never disagree. Downstream tools (HTML report, Slack) read these files
and never re-decide pass/fail themselves.

Exit codes (CI/CD keys off these):
  0  PASS        — scan ran, policy satisfied
  1  POLICY FAIL — scan ran, too many vulnerabilities (block the build)
  2  TOOL ERROR  — could not scan, read config, or write outputs

The distinction between exit 1 and exit 2 is the whole point: a broken
scanner must never look like a passing build, and a vulnerability block
must never look like a crash.
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

import yaml

# Exit codes as named constants, so the intent is readable everywhere.
EXIT_PASS = 0
EXIT_POLICY_FAIL = 1
EXIT_TOOL_ERROR = 2

STATUS_BY_EXIT = {
    EXIT_PASS: "PASS",
    EXIT_POLICY_FAIL: "FAIL",
    EXIT_TOOL_ERROR: "ERROR",
}

DEFAULT_POLICY_PATH = "policy.yaml"
REPORT_FILENAME = "trivy-report.json"
SUMMARY_FILENAME = "scan-summary.json"
SUMMARY_SCHEMA_VERSION = 1

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


# --- Job 1: run Trivy -------------------------------------------------------

def run_trivy(image):
    """
    Run Trivy against an image.

    Returns (raw_json_text, parsed_dict). The raw text is kept so it can be
    saved untouched as the report artifact.

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
        return completed.stdout, json.loads(completed.stdout)
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


def ordered_severities(counts):
    """Severities in a sensible display order, then any unexpected extras."""
    seen = [s for s in SEVERITY_ORDER if s in counts]
    seen += sorted(s for s in counts if s not in SEVERITY_ORDER)
    return seen


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
    # (bool is a subclass of int in Python, so reject it explicitly —
    # "HIGH: yes" must not quietly become a limit of 1.)
    clean = {}
    for sev, limit in thresholds.items():
        if isinstance(limit, bool) or not isinstance(limit, int):
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

    Returns (passed: bool, breaches: list of dicts with
    severity / found / limit). Structured rather than pre-formatted text,
    so the console, the summary file and later the HTML report and Slack
    message can each present it their own way.
    """
    breaches = []
    for sev, limit in thresholds.items():
        found = counts.get(sev, 0)
        if found > limit:
            breaches.append({"severity": sev, "found": found, "limit": limit})
    return (len(breaches) == 0, breaches)


# --- Job 4: report ----------------------------------------------------------

def report(image, counts, thresholds, passed, breaches):
    """Print a human-readable summary of the scan and the gate decision."""
    print(f"\nScan results for: {image}")
    print("-" * 50)

    if counts:
        for sev in ordered_severities(counts):
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
            print(f"  - {b['severity']}: found {b['found']}, limit is {b['limit']}")
        print()


# --- Output files (Sprint 3) ------------------------------------------------

def build_summary(image, exit_code, *, counts=None, thresholds=None,
                  breaches=None, trivy_output=None, error=None):
    """
    Build the scan-summary.json content.

    This is the single source of truth for the verdict. Anything that
    presents results later (HTML report, Slack) reads 'status' from here
    instead of re-applying the policy.
    """
    counts = counts or {}
    trivy_meta = (trivy_output or {}).get("Trivy") or {}
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "image": image,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": STATUS_BY_EXIT[exit_code],
        "exit_code": exit_code,
        "trivy_version": trivy_meta.get("Version"),
        "total": sum(counts.values()),
        "counts": {sev: counts[sev] for sev in ordered_severities(counts)},
        "thresholds": thresholds,
        "breaches": breaches or [],
        "error": error,
    }


def write_outputs(output_dir, summary, raw_report=None):
    """
    Write scan-summary.json (always) and trivy-report.json (when a scan
    produced one) into output_dir.

    Raises RuntimeError if the files can't be written. The caller treats
    that as a TOOL error: if CI expects these artifacts and they are
    missing, the tool is broken, even if the scan itself passed.
    """
    try:
        os.makedirs(output_dir, exist_ok=True)
        if raw_report is not None:
            with open(os.path.join(output_dir, REPORT_FILENAME), "w") as f:
                f.write(raw_report)
        with open(os.path.join(output_dir, SUMMARY_FILENAME), "w") as f:
            json.dump(summary, f, indent=2)
            f.write("\n")
    except OSError as exc:
        raise RuntimeError(f"Could not write output files to {output_dir}: {exc}")


def fail_with_tool_error(label, exc, image, output_dir, thresholds=None):
    """
    Print a tool error, try to leave an ERROR summary behind (so Slack
    can still say "the scanner broke" later), and return exit code 2.
    """
    print(f"{label}: {exc}", file=sys.stderr)
    if output_dir:
        summary = build_summary(image, EXIT_TOOL_ERROR,
                                thresholds=thresholds, error=str(exc))
        try:
            write_outputs(output_dir, summary)
        except RuntimeError as write_exc:
            # Already failing with exit 2; just make the extra problem visible.
            print(f"OUTPUT ERROR: {write_exc}", file=sys.stderr)
    return EXIT_TOOL_ERROR


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
    parser.add_argument(
        "--output-dir",
        default=None,
        help=(f"If set, write {REPORT_FILENAME} and {SUMMARY_FILENAME} "
              "into this directory (created if missing)."),
    )
    args = parser.parse_args()

    # Load config first — a config error is a tool error, and there's no
    # point scanning if we can't evaluate the result.
    try:
        thresholds = load_policy(args.policy)
    except RuntimeError as exc:
        return fail_with_tool_error("CONFIG ERROR", exc, args.image, args.output_dir)

    # Run the scan.
    try:
        raw_report, trivy_output = run_trivy(args.image)
    except RuntimeError as exc:
        return fail_with_tool_error("TOOL ERROR", exc, args.image,
                                    args.output_dir, thresholds)

    # Parse, count, gate, report.
    vulns = parse_vulnerabilities(trivy_output)
    counts = count_by_severity(vulns)
    passed, breaches = apply_gate(counts, thresholds)
    report(args.image, counts, thresholds, passed, breaches)
    exit_code = EXIT_PASS if passed else EXIT_POLICY_FAIL

    # Write artifacts last, from the same scan the gate just judged.
    if args.output_dir:
        summary = build_summary(
            args.image, exit_code,
            counts=counts, thresholds=thresholds,
            breaches=breaches, trivy_output=trivy_output,
        )
        try:
            write_outputs(args.output_dir, summary, raw_report)
        except RuntimeError as exc:
            print(f"OUTPUT ERROR: {exc}", file=sys.stderr)
            return EXIT_TOOL_ERROR
        print(f"Wrote {REPORT_FILENAME} and {SUMMARY_FILENAME} to {args.output_dir}/")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
