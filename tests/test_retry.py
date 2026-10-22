#!/usr/bin/env python3
"""
Sprint 5 tests: retry logic and error handling.

Run from the repo root:   python -m unittest discover -s tests -v

Trivy is replaced by a fake script that fails a set number of times, and
Slack by a tiny local web server, so nothing real is called. Waits are
shortened to zero, so the tests take seconds.
"""

import io
import json
import os
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import notify  # noqa: E402
import scanner  # noqa: E402

TRIVY_JSON = {"Trivy": {"Version": "fake"}, "Results": [{"Vulnerabilities": [
    {"VulnerabilityID": "CVE-2026-0002", "Severity": "HIGH", "PkgName": "zlib",
     "InstalledVersion": "1.2", "FixedVersion": ""}]}]}


class FakeTrivy:
    """A `trivy` on PATH that fails the first `fail_times` runs."""

    def __init__(self, fail_times, hang=False):
        self.dir = tempfile.mkdtemp()
        json_path = os.path.join(self.dir, "out.json")
        with open(json_path, "w") as f:
            json.dump(TRIVY_JSON, f)
        self.counter = os.path.join(self.dir, "count")
        script = os.path.join(self.dir, "trivy")
        with open(script, "w") as f:
            f.write(f"""#!/bin/sh
n=$(cat '{self.counter}' 2>/dev/null || echo 0); n=$((n+1)); echo $n > '{self.counter}'
{"sleep 5" if hang else ":"}
if [ "$n" -le {fail_times} ]; then echo "FATAL: failed to download vulnerability DB" >&2; exit 1; fi
cat '{json_path}'
""")
        os.chmod(script, 0o755)
        self.patch = mock.patch.dict(os.environ, {"PATH": self.dir + os.pathsep + os.environ["PATH"]})

    def __enter__(self):
        self.patch.start()
        return self

    def __exit__(self, *exc):
        self.patch.stop()

    @property
    def runs(self):
        with open(self.counter) as f:
            return int(f.read())


def quiet(fn, *args, **kwargs):
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
        return fn(*args, **kwargs), err.getvalue()


class TrivyRetryTests(unittest.TestCase):
    def setUp(self):
        self.waits = []

    def run_trivy(self, **kw):
        return quiet(scanner.run_trivy, "img:1", sleep=self.waits.append, **kw)

    def test_success_first_time(self):
        with FakeTrivy(0) as t:
            (_, parsed, attempts), _ = self.run_trivy()
        self.assertEqual((attempts, t.runs, self.waits), (1, 1, []))

    def test_temporary_failure_recovers(self):
        with FakeTrivy(2) as t:
            (_, parsed, attempts), err = self.run_trivy()
        self.assertEqual((attempts, t.runs), (3, 3))
        self.assertEqual(self.waits, [15, 45])          # waits grow
        self.assertIn("attempt 1 of 3 failed", err)
        self.assertIn("failed to download vulnerability DB", err)   # the reason is shown

    def test_gives_up_after_three(self):
        with FakeTrivy(99) as t:
            with self.assertRaises(scanner.TrivyError) as ctx:
                self.run_trivy()
        self.assertEqual((ctx.exception.attempts, t.runs), (3, 3))
        self.assertIn("gave up after 3 attempts", str(ctx.exception))
        self.assertIn("failed to download vulnerability DB", str(ctx.exception))

    def test_timeout_is_retried(self):
        with FakeTrivy(0, hang=True) as t:
            with self.assertRaises(scanner.TrivyError) as ctx:
                self.run_trivy(attempts=2, timeout=1)
        self.assertIn("did not finish within 1 seconds", str(ctx.exception))
        self.assertEqual(t.runs, 2)

    def test_trivy_missing_is_not_retried(self):
        with mock.patch.dict(os.environ, {"PATH": tempfile.mkdtemp()}):
            with self.assertRaises(scanner.TrivyError) as ctx:
                self.run_trivy()
        self.assertEqual(ctx.exception.attempts, 1)
        self.assertEqual(self.waits, [])
        self.assertIn("not installed", str(ctx.exception))


class ScannerExitCodeTests(unittest.TestCase):
    """The exit-code contract still holds with retries in place."""

    def run_main(self, fail_times):
        out = tempfile.mkdtemp()
        argv = ["scanner.py", "img:1", "--policy", os.path.join(ROOT, "policy.yaml"),
                "--output-dir", out]
        with FakeTrivy(fail_times), mock.patch.object(sys, "argv", argv), \
                mock.patch.object(scanner, "TRIVY_RETRY_WAITS", (0, 0)):
            code, _ = quiet(scanner.main)
        with open(os.path.join(out, "scan-summary.json")) as f:
            return code, json.load(f)

    def test_flaky_trivy_still_passes_and_records_attempts(self):
        code, summary = self.run_main(1)
        self.assertEqual((code, summary["status"], summary["attempts"]), (0, "PASS", 2))

    def test_broken_trivy_is_tool_error_never_pass(self):
        code, summary = self.run_main(99)
        self.assertEqual((code, summary["status"], summary["attempts"]), (2, "ERROR", 3))
        self.assertIn("gave up after 3 attempts", summary["error"])


class FakeSlack(BaseHTTPRequestHandler):
    replies = []            # (status, body, headers) per request, in order
    received = 0

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        status, body, headers = FakeSlack.replies[min(FakeSlack.received, len(FakeSlack.replies) - 1)]
        FakeSlack.received += 1
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


class SlackRetryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), FakeSlack)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/hook"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def post(self, replies):
        """Run post_to_slack against the fake server (https check bypassed)."""
        FakeSlack.replies, FakeSlack.received = replies, 0
        waits = []
        real_once = notify.post_to_slack_once
        with mock.patch.object(notify, "post_to_slack_once",
                               lambda _url, p: real_once(self.url, p)):
            try:
                quiet(notify.post_to_slack, "https://hooks.slack.invalid/x", {"text": "t"},
                      sleep=waits.append)
                error = None
            except RuntimeError as exc:
                error = str(exc)
        return error, FakeSlack.received, waits

    def test_ok_first_time(self):
        self.assertEqual(self.post([(200, "ok", {})]), (None, 1, []))

    def test_server_error_then_ok(self):
        error, sent, waits = self.post([(500, "oops", {}), (503, "busy", {}), (200, "ok", {})])
        self.assertEqual((error, sent, waits), (None, 3, [5, 15]))

    def test_rate_limit_honours_retry_after(self):
        error, sent, waits = self.post([(429, "slow down", {"Retry-After": "7"}), (200, "ok", {})])
        self.assertEqual((error, sent, waits), (None, 2, [7]))

    def test_revoked_webhook_is_not_retried(self):
        error, sent, waits = self.post([(404, "no_service", {})])
        self.assertEqual((sent, waits), (1, []))
        self.assertIn("404", error)

    def test_gives_up_after_three(self):
        error, sent, _ = self.post([(500, "down", {})])
        self.assertEqual(sent, 3)
        self.assertIn("gave up after 3 attempts", error)

    def test_webhook_url_never_in_error(self):
        error, _, _ = self.post([(400, "invalid_payload", {})])
        self.assertNotIn("hooks.slack", error)


if __name__ == "__main__":
    unittest.main()
