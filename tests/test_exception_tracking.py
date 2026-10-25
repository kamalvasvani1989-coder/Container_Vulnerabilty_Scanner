#!/usr/bin/env python3
"""
Sprint 5 tests: tracking exceptions in the report and the weekly digest.

Run from the repo root:   python -m unittest discover -s tests -v
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
import digest  # noqa: E402
import notify  # noqa: E402
import report  # noqa: E402

TRIVY = {"Results": [{"Vulnerabilities": [
    {"VulnerabilityID": "CVE-2026-0001", "Severity": "CRITICAL",
     "PkgName": "openssl", "InstalledVersion": "3.0.1", "FixedVersion": "3.0.2"},
    {"VulnerabilityID": "CVE-2026-0002", "Severity": "HIGH",
     "PkgName": "zlib", "InstalledVersion": "1.2", "FixedVersion": ""},
]}]}


def state(id_, st, matched, days_left=30):
    return {"id": id_, "package": None, "image": None, "reason": "r", "approved_by": "Tester",
            "approved_on": "2026-10-01", "expires": "2026-12-01", "days_left": days_left,
            "state": st, "matched": matched}


SUMMARY_V2 = {
    "schema_version": 2, "image": "vuln-scanner-test:ci", "scanned_at": "2026-10-22T09:00:00+00:00",
    "status": "PASS", "exit_code": 0, "trivy_version": "0.76.0", "total": 2,
    "counts": {"CRITICAL": 1, "HIGH": 1}, "gated_counts": {"HIGH": 1},
    "thresholds": {"CRITICAL": 0, "HIGH": 10}, "breaches": [],
    "excepted": [{"id": "CVE-2026-0001", "severity": "CRITICAL", "package": "openssl",
                  "installed": "3.0.1", "fixed": "3.0.2", "fix_available": True,
                  "reason": "r", "approved_by": "Tester", "expires": "2026-12-01", "days_left": 40}],
    "exceptions": [state("CVE-2026-0001", "active", 1), state("CVE-2099-9999", "active", 0)],
    "error": None,
}
SUMMARY_V1 = {k: v for k, v in SUMMARY_V2.items()
              if k not in ("gated_counts", "excepted", "exceptions")}
SUMMARY_V1.update(schema_version=1, status="FAIL", exit_code=1,
                  breaches=[{"severity": "CRITICAL", "found": 1, "limit": 0}])


def render(summary):
    return report.render(report.build_context(summary, TRIVY), report.DEFAULT_TEMPLATE_DIR)


class ReportTests(unittest.TestCase):
    def test_exceptions_section_and_markers(self):
        html = render(SUMMARY_V2)
        self.assertIn("Exceptions for this image (2)", html)
        self.assertIn("Not found: remove?", html)          # CVE-2099-9999 matched nothing
        self.assertIn("Until 2026-12-01", html)            # marker on the waived finding
        self.assertIn("A fix is now available for", html)
        self.assertIn("<th class=\"num\">Excepted</th>", html)

    def test_old_summary_renders_without_exception_parts(self):
        html = render(SUMMARY_V1)
        self.assertIn("Blocked by the policy gate", html)
        self.assertNotIn("Exceptions for this image", html)
        self.assertNotIn("<th class=\"num\">Excepted</th>", html)
        self.assertNotIn("<th>Exception</th>", html)


class DigestTests(unittest.TestCase):
    def test_counts_only_no_cve_ids(self):
        s = dict(SUMMARY_V2, exceptions=[
            state("CVE-A", "active", 1), state("CVE-B", "expiring_soon", 1, 3),
            state("CVE-C", "expired", 1, -2), state("CVE-D", "active", 0)])
        line = digest.exceptions_line(s)
        for words in ("1 active", "1 expiring within 7 days", "1 expired",
                      "1 no longer found", "fix now available for 1"):
            self.assertIn(words, line)
        self.assertNotIn("CVE-", line)   # Slack carries no CVE details

    def test_none_and_old_summaries(self):
        self.assertEqual(digest.exceptions_line(dict(SUMMARY_V2, exceptions=[])), "*Exceptions:* none")
        self.assertIsNone(digest.exceptions_line(SUMMARY_V1))


class SlackAlertTests(unittest.TestCase):
    def alert_text(self, summary):
        payload = notify.build_message(summary, ["CRITICAL"])
        return "\n".join(b["text"]["text"] for b in payload["blocks"])

    def test_blocked_alert_mentions_exceptions_count_only(self):
        s = dict(SUMMARY_V2, status="FAIL", exit_code=1,
                 breaches=[{"severity": "HIGH", "found": 11, "limit": 10}])
        text = self.alert_text(s)
        self.assertIn("1 excepted (approved), not counted", text)
        self.assertNotIn("CVE-", text)   # Slack carries no CVE details

    def test_no_line_without_exceptions(self):
        self.assertNotIn("excepted", self.alert_text(SUMMARY_V1))


if __name__ == "__main__":
    unittest.main()
