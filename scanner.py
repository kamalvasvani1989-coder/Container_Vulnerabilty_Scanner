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

Sprint 5 addition — exceptions (approved known vulnerabilities):
  policy.yaml may list CVEs that are accepted for a limited time. Each one
  needs a reason, an approver, an approval date and an expiry (at most
  MAX_EXCEPTION_DAYS after approval). A matching CVE is still REPORTED
  (it is still in the image) but does not count towards the gate.
  - An expired exception stops applying, so the CVE gates again.
  - A malformed exception is a config error (exit 2): a broken waiver
    must never quietly pass a build.
  scan-summary.json keeps 'counts' as everything found, and adds
  'gated_counts' (what the gate judged), 'excepted' (each waived finding)
  and 'exceptions' (state of every exception that applies to this image),
  so exceptions can be tracked over time.

Sprint 5 addition — retry and error handling:
  A Trivy failure is often temporary (vulnerability DB download, registry
  or network hiccup), so Trivy is tried up to TRIVY_ATTEMPTS times, waiting
  longer each time, with a time limit per attempt. Only if every attempt
  fails is it a TOOL ERROR (exit 2), exactly as before. scan-summary.json
  records how many attempts it took, so flaky runs are visible.

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
import time
from datetime import date, datetime, timezone

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
SUMMARY_SCHEMA_VERSION = 2

# Exceptions: the longest an approval may last, and when to start warning.
MAX_EXCEPTION_DAYS = 90
EXPIRING_SOON_DAYS = 7
EXCEPTION_REQUIRED = ("id", "reason", "approved_by", "approved_on", "expires")
EXCEPTION_OPTIONAL = ("package", "image")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

# Retry (Sprint 5). Worst case: 3 x 5 min + 1 min of waiting = 16 min,
# inside the Jenkins job's 20-minute limit. A normal scan takes ~1 minute.
TRIVY_ATTEMPTS = 3
TRIVY_RETRY_WAITS = (15, 45)        # seconds before attempt 2 and 3
TRIVY_TIMEOUT_SECONDS = 300


class TrivyError(RuntimeError):
    """Trivy could not produce a usable result; carries the attempt count."""
    def __init__(self, message, attempts):
        super().__init__(message)
        self.attempts = attempts


# --- Job 1: run Trivy -------------------------------------------------------

def run_trivy_once(image, timeout=TRIVY_TIMEOUT_SECONDS):
    """
    One Trivy run. Returns (raw_json_text, parsed_dict).

    Raises FileNotFoundError if Trivy isn't installed (no point retrying)
    and RuntimeError for anything that may be temporary.

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
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Trivy did not finish within {timeout} seconds.")

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


def run_trivy(image, attempts=None, waits=None, timeout=None, sleep=None):
    """
    Run Trivy, retrying temporary failures.

    Returns (raw_json_text, parsed_dict, attempts_used).
    Raises TrivyError (a RuntimeError) once every attempt has failed, or at
    once if Trivy is not installed. The caller turns that into exit code 2.

    Every failure is retried, including permanent ones such as a mistyped
    image name: telling them apart from Trivy's messages is unreliable, and
    a wrong "not temporary" guess would skip a retry that could have worked.
    The cost of retrying a permanent error is about a minute.
    """
    # Defaults are read at call time, so tests can shorten the waits.
    attempts = attempts or TRIVY_ATTEMPTS
    waits = TRIVY_RETRY_WAITS if waits is None else waits
    timeout = timeout or TRIVY_TIMEOUT_SECONDS
    sleep = sleep or time.sleep
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            raw, parsed = run_trivy_once(image, timeout)
            if attempt > 1:
                print(f"Trivy succeeded on attempt {attempt} of {attempts}.")
            return raw, parsed, attempt
        except FileNotFoundError:
            raise TrivyError(
                "Trivy is not installed or not on PATH. "
                "Install it (see the setup guide) and try again.",
                attempt,
            )
        except RuntimeError as exc:
            last_error = exc
            if attempt < attempts:
                wait = waits[min(attempt - 1, len(waits) - 1)]
                # Headline plus Trivy's last error line: that's the reason.
                lines = [l.strip() for l in str(exc).splitlines() if l.strip()]
                brief = lines[0] + (f" {lines[-1][:200]}" if len(lines) > 1 else "")
                print(f"WARNING: Trivy attempt {attempt} of {attempts} failed: "
                      f"{brief} Retrying in {wait}s.", file=sys.stderr)
                sleep(wait)
    raise TrivyError(f"{last_error}\n(gave up after {attempts} attempts)", attempts)


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


def load_policy_and_exceptions(path, today=None):
    """
    Load thresholds AND exceptions from the policy YAML.

    Returns (thresholds, exceptions). Any problem in either is a config
    error (RuntimeError -> exit 2).
    """
    thresholds = load_policy(path)
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    exceptions = validate_exceptions(data.get("exceptions"), today or date.today())
    return thresholds, exceptions


# --- Exceptions (Sprint 5) --------------------------------------------------

def _as_date(value, field, where):
    """YAML turns 2026-10-20 into a date already; also accept the string."""
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError:
            pass
    raise RuntimeError(f"{where}: '{field}' must be a date like 2026-12-31, got {value!r}.")


def validate_exceptions(raw, today):
    """
    Check every exception entry strictly and return a clean list.

    Strict on purpose: an unknown key (e.g. a typo 'expiry') or a missing
    approver must stop the pipeline, not silently waive a vulnerability.
    Expired entries are VALID here; they simply stop applying later.
    """
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise RuntimeError("'exceptions' must be a list of entries (or left empty).")

    clean = []
    for n, entry in enumerate(raw, start=1):
        where = f"Exception #{n}"
        if not isinstance(entry, dict):
            raise RuntimeError(f"{where} must be a mapping with id, reason, approved_by, approved_on, expires.")
        if entry.get("id"):
            where = f"Exception #{n} ({entry.get('id')})"

        unknown = set(entry) - set(EXCEPTION_REQUIRED) - set(EXCEPTION_OPTIONAL)
        if unknown:
            raise RuntimeError(f"{where}: unknown field(s) {', '.join(sorted(map(str, unknown)))}. "
                               f"Allowed: {', '.join(EXCEPTION_REQUIRED + EXCEPTION_OPTIONAL)}.")
        missing = [k for k in EXCEPTION_REQUIRED if entry.get(k) in (None, "")]
        if missing:
            raise RuntimeError(f"{where}: missing required field(s) {', '.join(missing)}.")

        for k in ("id", "reason", "approved_by") + EXCEPTION_OPTIONAL:
            if k in entry and entry[k] is not None and not isinstance(entry[k], str):
                raise RuntimeError(f"{where}: '{k}' must be text, got {entry[k]!r}.")

        approved_on = _as_date(entry["approved_on"], "approved_on", where)
        expires = _as_date(entry["expires"], "expires", where)
        if approved_on > today:
            raise RuntimeError(f"{where}: approved_on {approved_on} is in the future.")
        if expires < approved_on:
            raise RuntimeError(f"{where}: expires {expires} is before approved_on {approved_on}.")
        if (expires - approved_on).days > MAX_EXCEPTION_DAYS:
            raise RuntimeError(f"{where}: lasts {(expires - approved_on).days} days; "
                               f"the maximum is {MAX_EXCEPTION_DAYS}. Re-approve it when it runs out.")

        clean.append({
            "id": entry["id"].strip(),
            "package": (entry.get("package") or "").strip() or None,
            "image": (entry.get("image") or "").strip() or None,
            "reason": entry["reason"].strip(),
            "approved_by": entry["approved_by"].strip(),
            "approved_on": approved_on,
            "expires": expires,
        })
    return clean


def image_repository(image):
    """'python:3.9-slim' -> 'python'; 'reg:5000/app:1' -> 'reg:5000/app'."""
    name = image.split("@", 1)[0]
    last = name.rsplit("/", 1)[-1]
    if ":" in last:
        name = name[: len(name) - len(last)] + last.split(":", 1)[0]
    return name


def exception_applies_to_image(exc, image):
    """
    No image -> applies to every image. An image WITH a tag must match
    exactly; WITHOUT a tag it matches any tag of that repository.
    """
    if not exc["image"]:
        return True
    if exc["image"] == image:
        return True
    has_tag = exc["image"] != image_repository(exc["image"]) or "@" in exc["image"]
    return not has_tag and exc["image"] == image_repository(image)


def apply_exceptions(vulns, exceptions, image, today):
    """
    Split findings into (gated, excepted) and describe each exception.

    Returns (gated_vulns, excepted, states):
      gated_vulns  findings the gate still judges
      excepted     one record per waived finding (with its exception)
      states       one record per exception that applies to this image:
                   state active / expiring_soon / expired, and 'matched'
                   (0 matched + not expired = no longer needed, e.g. patched)
    """
    in_scope = [e for e in exceptions if exception_applies_to_image(e, image)]
    states = []
    for e in in_scope:
        days_left = (e["expires"] - today).days
        if days_left < 0:
            state = "expired"
        elif days_left <= EXPIRING_SOON_DAYS:
            state = "expiring_soon"
        else:
            state = "active"
        states.append({**e, "days_left": days_left, "state": state, "matched": 0})

    gated, excepted = [], []
    for v in vulns:
        hit = None
        for st in states:
            if st["id"] == v["id"] and (not st["package"] or st["package"] == v["package"]):
                st["matched"] += 1
                if st["state"] != "expired":
                    hit = hit or st
        if hit:
            excepted.append({
                **v,
                "fix_available": bool(v["fixed"]),
                "reason": hit["reason"],
                "approved_by": hit["approved_by"],
                "expires": hit["expires"].isoformat(),
                "days_left": hit["days_left"],
            })
        else:
            gated.append(v)

    for st in states:
        st["approved_on"] = st["approved_on"].isoformat()
        st["expires"] = st["expires"].isoformat()
    return gated, excepted, states


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

def report(image, counts, thresholds, passed, breaches, gated_counts=None,
           excepted=(), states=()):
    """Print a human-readable summary of the scan and the gate decision."""
    gated_counts = counts if gated_counts is None else gated_counts
    print(f"\nScan results for: {image}")
    print("-" * 50)

    if counts:
        for sev in ordered_severities(counts):
            gated = " (gated)" if sev in thresholds else ""
            waived = counts[sev] - gated_counts.get(sev, 0)
            note = f"  [{waived} excepted]" if waived else ""
            print(f"  {sev:<9} {counts[sev]}{gated}{note}")
    else:
        print("  No vulnerabilities found.")

    if states:
        print("-" * 50)
        print("Exceptions for this image:")
        for st in states:
            pkg = f" ({st['package']})" if st["package"] else ""
            if st["state"] == "expired":
                what = f"EXPIRED on {st['expires']}, no longer applied"
            elif st["state"] == "expiring_soon":
                what = f"expires {st['expires']} ({st['days_left']} days left)"
            else:
                what = f"active until {st['expires']}"
            used = (f"matched {st['matched']}" if st["matched"]
                    else "matched nothing (patched? remove it)")
            print(f"  {st['id']}{pkg}: {what}; {used}")
        fixable = sorted({e["id"] for e in excepted if e["fix_available"]})
        if fixable:
            print(f"  Fix now available for excepted: {', '.join(fixable)}")

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
                  breaches=None, trivy_output=None, error=None,
                  gated_counts=None, excepted=None, exception_states=None,
                  attempts=None):
    """
    Build the scan-summary.json content.

    This is the single source of truth for the verdict. Anything that
    presents results later (HTML report, Slack) reads 'status' from here
    instead of re-applying the policy.
    """
    counts = counts or {}
    gated = counts if gated_counts is None else gated_counts
    trivy_meta = (trivy_output or {}).get("Trivy") or {}
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "image": image,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status": STATUS_BY_EXIT[exit_code],
        "exit_code": exit_code,
        "trivy_version": trivy_meta.get("Version"),
        # How many Trivy runs it took (Sprint 5); None = Trivy never ran.
        "attempts": attempts,
        "total": sum(counts.values()),
        "counts": {sev: counts[sev] for sev in ordered_severities(counts)},
        # What the gate judged: counts minus excepted findings.
        "gated_counts": {sev: gated[sev] for sev in ordered_severities(gated)},
        "thresholds": thresholds,
        "breaches": breaches or [],
        "excepted": excepted or [],
        "exceptions": exception_states or [],
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


def fail_with_tool_error(label, exc, image, output_dir, thresholds=None,
                         attempts=None):
    """
    Print a tool error, try to leave an ERROR summary behind (so Slack
    can still say "the scanner broke" later), and return exit code 2.
    """
    print(f"{label}: {exc}", file=sys.stderr)
    if output_dir:
        summary = build_summary(image, EXIT_TOOL_ERROR,
                                thresholds=thresholds, error=str(exc),
                                attempts=attempts)
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
    today = date.today()
    try:
        thresholds, exceptions = load_policy_and_exceptions(args.policy, today)
    except RuntimeError as exc:
        return fail_with_tool_error("CONFIG ERROR", exc, args.image, args.output_dir)

    # Run the scan.
    try:
        raw_report, trivy_output, attempts = run_trivy(args.image)
    except TrivyError as exc:
        return fail_with_tool_error("TOOL ERROR", exc, args.image,
                                    args.output_dir, thresholds, exc.attempts)

    # Parse, count, gate, report.
    vulns = parse_vulnerabilities(trivy_output)
    counts = count_by_severity(vulns)
    gated_vulns, excepted, states = apply_exceptions(vulns, exceptions, args.image, today)
    gated_counts = count_by_severity(gated_vulns)
    passed, breaches = apply_gate(gated_counts, thresholds)
    report(args.image, counts, thresholds, passed, breaches,
           gated_counts, excepted, states)
    exit_code = EXIT_PASS if passed else EXIT_POLICY_FAIL

    # Write artifacts last, from the same scan the gate just judged.
    if args.output_dir:
        summary = build_summary(
            args.image, exit_code,
            counts=counts, thresholds=thresholds,
            breaches=breaches, trivy_output=trivy_output,
            gated_counts=gated_counts, excepted=excepted,
            exception_states=states, attempts=attempts,
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
