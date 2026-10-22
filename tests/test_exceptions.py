#!/usr/bin/env python3
"""
Sprint 5 tests: exceptions (approved known vulnerabilities).

Run from the repo root:   python -m unittest discover -s tests -v

The end-to-end tests put a FAKE `trivy` on PATH that prints a canned
result (1 CRITICAL in openssl, 2 HIGH), so they run in seconds with no
Docker, no network and no Trivy database.
"""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from datetime import date, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import scanner  # noqa: E402

TODAY = date.today()
FAKE_TRIVY_OUTPUT = {
    "Trivy": {"Version": "fake"},
    "Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "CVE-2026-0001", "Severity": "CRITICAL",
         "PkgName": "openssl", "InstalledVersion": "3.0.1", "FixedVersion": "3.0.2"},
        {"VulnerabilityID": "CVE-2026-0002", "Severity": "HIGH",
         "PkgName": "zlib", "InstalledVersion": "1.2", "FixedVersion": ""},
        {"VulnerabilityID": "CVE-2026-0003", "Severity": "HIGH",
         "PkgName": "curl", "InstalledVersion": "8.0", "FixedVersion": ""},
    ]}],
}


def exc(**over):
    """A valid exception entry; override fields per test."""
    e = {"id": "CVE-2026-0001", "reason": "test", "approved_by": "Tester",
         "approved_on": TODAY - timedelta(days=10), "expires": TODAY + timedelta(days=30)}
    e.update(over)
    return {k: v for k, v in e.items() if v is not None}


class ValidationTests(unittest.TestCase):
    def check_rejected(self, entry, words):
        with self.assertRaises(RuntimeError) as ctx:
            scanner.validate_exceptions([entry], TODAY)
        self.assertIn(words, str(ctx.exception))

    def test_valid_entry(self):
        clean = scanner.validate_exceptions([exc(package="openssl")], TODAY)
        self.assertEqual(clean[0]["package"], "openssl")

    def test_empty_or_missing_section(self):
        self.assertEqual(scanner.validate_exceptions(None, TODAY), [])
        self.assertEqual(scanner.validate_exceptions([], TODAY), [])

    def test_missing_approver(self):
        self.check_rejected(exc(approved_by=None), "approved_by")

    def test_missing_expiry(self):
        self.check_rejected(exc(expires=None), "expires")

    def test_typo_in_field_name(self):
        entry = exc(); entry["expiry"] = "2026-12-31"
        self.check_rejected(entry, "unknown field")

    def test_bad_date(self):
        self.check_rejected(exc(expires="31/12/2026"), "must be a date")

    def test_longer_than_90_days(self):
        self.check_rejected(exc(approved_on=TODAY, expires=TODAY + timedelta(days=91)), "maximum is 90")

    def test_exactly_90_days_allowed(self):
        scanner.validate_exceptions([exc(approved_on=TODAY, expires=TODAY + timedelta(days=90))], TODAY)

    def test_approved_in_future(self):
        self.check_rejected(exc(approved_on=TODAY + timedelta(days=1)), "in the future")

    def test_expires_before_approval(self):
        self.check_rejected(exc(approved_on=TODAY - timedelta(days=5),
                                expires=TODAY - timedelta(days=6)), "before approved_on")

    def test_expired_entry_is_still_valid(self):
        # Expired is not a mistake; it just stops applying.
        scanner.validate_exceptions([exc(approved_on=TODAY - timedelta(days=40),
                                         expires=TODAY - timedelta(days=1))], TODAY)


class MatchingTests(unittest.TestCase):
    VULNS = scanner.parse_vulnerabilities(FAKE_TRIVY_OUTPUT)

    def run_apply(self, entries, image="vuln-scanner-test:ci"):
        clean = scanner.validate_exceptions(entries, TODAY)
        return scanner.apply_exceptions(self.VULNS, clean, image, TODAY)

    def test_active_exception_waives_the_cve(self):
        gated, excepted, states = self.run_apply([exc()])
        self.assertEqual([v["id"] for v in excepted], ["CVE-2026-0001"])
        self.assertNotIn("CVE-2026-0001", [v["id"] for v in gated])
        self.assertTrue(excepted[0]["fix_available"])
        self.assertEqual(states[0]["state"], "active")

    def test_expired_exception_does_not_waive(self):
        gated, excepted, states = self.run_apply(
            [exc(approved_on=TODAY - timedelta(days=40), expires=TODAY - timedelta(days=1))])
        self.assertEqual(excepted, [])
        self.assertEqual(states[0]["state"], "expired")
        self.assertEqual(states[0]["matched"], 1)

    def test_expires_today_still_applies(self):
        _, excepted, states = self.run_apply([exc(expires=TODAY)])
        self.assertEqual(len(excepted), 1)
        self.assertEqual(states[0]["state"], "expiring_soon")

    def test_wrong_package_does_not_waive(self):
        _, excepted, states = self.run_apply([exc(package="zlib")])
        self.assertEqual(excepted, [])
        self.assertEqual(states[0]["matched"], 0)

    def test_image_without_tag_matches_any_tag(self):
        _, excepted, _ = self.run_apply([exc(image="vuln-scanner-test")])
        self.assertEqual(len(excepted), 1)

    def test_image_with_tag_must_match_exactly(self):
        _, excepted, states = self.run_apply([exc(image="vuln-scanner-test:other")])
        self.assertEqual(excepted, [])
        self.assertEqual(states, [])  # not in scope for this image at all

    def test_other_image_not_affected(self):
        _, excepted, states = self.run_apply([exc(image="python")])
        self.assertEqual((excepted, states), ([], []))

    def test_unused_exception_is_reported(self):
        # e.g. the CVE was patched: the exception matched nothing.
        _, _, states = self.run_apply([exc(id="CVE-2099-9999")])
        self.assertEqual(states[0]["matched"], 0)


class EndToEndTests(unittest.TestCase):
    """Run scanner.py as CI does, with a fake trivy, and check exit codes."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        bindir = os.path.join(self.tmp, "bin")
        os.makedirs(bindir)
        with open(os.path.join(self.tmp, "out.json"), "w") as f:
            json.dump(FAKE_TRIVY_OUTPUT, f)
        fake = os.path.join(bindir, "trivy")
        with open(fake, "w") as f:
            f.write(f"#!/bin/sh\ncat '{self.tmp}/out.json'\n")
        os.chmod(fake, 0o755)
        self.env = dict(os.environ, PATH=bindir + os.pathsep + os.environ["PATH"])

    def run_scan(self, exceptions_yaml):
        policy = os.path.join(self.tmp, "policy.yaml")
        with open(policy, "w") as f:
            f.write("thresholds:\n  CRITICAL: 0\n  HIGH: 10\n" + textwrap.dedent(exceptions_yaml))
        out = os.path.join(self.tmp, "reports")
        p = subprocess.run([sys.executable, os.path.join(ROOT, "scanner.py"),
                            "vuln-scanner-test:ci", "--policy", policy, "--output-dir", out],
                           env=self.env, capture_output=True, text=True)
        with open(os.path.join(out, "scan-summary.json")) as f:
            return p.returncode, json.load(f), p.stdout + p.stderr

    def test_no_exceptions_fails_on_critical(self):
        code, summary, _ = self.run_scan("exceptions: []\n")
        self.assertEqual((code, summary["status"]), (1, "FAIL"))

    def test_exception_turns_fail_into_pass(self):
        code, summary, out = self.run_scan(f"""
            exceptions:
              - id: CVE-2026-0001
                package: openssl
                reason: test
                approved_by: Tester
                approved_on: {TODAY - timedelta(days=1)}
                expires: {TODAY + timedelta(days=30)}
            """)
        self.assertEqual((code, summary["status"]), (0, "PASS"))
        self.assertEqual(summary["counts"]["CRITICAL"], 1)           # still reported
        self.assertNotIn("CRITICAL", summary["gated_counts"])         # not gated
        self.assertEqual(summary["excepted"][0]["id"], "CVE-2026-0001")
        self.assertEqual(summary["schema_version"], 2)
        self.assertIn("excepted", out)

    def test_expired_exception_blocks_again(self):
        code, summary, out = self.run_scan(f"""
            exceptions:
              - id: CVE-2026-0001
                reason: test
                approved_by: Tester
                approved_on: {TODAY - timedelta(days=40)}
                expires: {TODAY - timedelta(days=1)}
            """)
        self.assertEqual((code, summary["status"]), (1, "FAIL"))
        self.assertEqual(summary["exceptions"][0]["state"], "expired")
        self.assertIn("EXPIRED", out)

    def test_malformed_exception_is_tool_error(self):
        code, summary, _ = self.run_scan("""
            exceptions:
              - id: CVE-2026-0001
                reason: forgot the approver and dates
            """)
        self.assertEqual((code, summary["status"]), (2, "ERROR"))
        self.assertIn("missing required", summary["error"])


if __name__ == "__main__":
    unittest.main()
