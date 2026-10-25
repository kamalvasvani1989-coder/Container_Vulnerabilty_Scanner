#!/usr/bin/env python3
"""
Sprint 3 — daily/weekly summary alert.

Collects the scan-summary.json from every scan workflow run in the last
N days (default 7) and posts one summary message to Slack: how many scans
ran, how many passed, were blocked or errored, which images were blocked
and why, and the latest result on the main branch.

Sprint 5: also how the exceptions (approved known vulnerabilities) stand
on the latest main scan: how many are active, expiring soon, expired,
no longer matched (e.g. patched), and how many now have a fix. Counts
only, in line with the no-CVE-details rule; the report has the details.

No database is needed: GitHub already keeps each run's trivy-scan-report
artifact, so this reads the history straight from there. That keeps the
running cost at zero.

Runs in GitHub Actions (weekly-digest.yml) with:
  GITHUB_TOKEN       — the workflow's own token, with actions: read
  GITHUB_REPOSITORY  — owner/repo (set by Actions)
  SLACK_WEBHOOK_URL  — the same secret notify.py uses

Like notify.py, the message carries no links and no CVE details.

Usage:
  python src/digest.py                 # last 7 days
  python src/digest.py --days 1        # daily summary
  python src/digest.py --dry-run       # print the message, don't send it

Exit codes:
  0  summary sent (or printed with --dry-run, or webhook not configured)
  2  could not read the scan history or send the message
"""

import argparse
import io
import json
import os
import sys
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone

from notify import post_to_slack, slack_escape, worst_severity
from scanner import SUMMARY_FILENAME

EXIT_OK = 0
EXIT_ERROR = 2

ARTIFACT_NAME = "trivy-scan-report"
DEFAULT_WORKFLOW = "scan.yml"
TIMEOUT_SECONDS = 30
MAX_BLOCKED_LISTED = 10


# --- GitHub API -------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Stop urllib following redirects, so we can follow them ourselves."""
    def redirect_request(self, *args, **kwargs):
        return None


_no_redirect_opener = urllib.request.build_opener(_NoRedirect)


class GitHub:
    def __init__(self, token, repo, api_url):
        self.token = token
        self.repo = repo
        self.api_url = api_url.rstrip("/")

    def _request(self, url):
        return urllib.request.Request(url, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

    def get_json(self, path):
        try:
            with urllib.request.urlopen(self._request(self.api_url + path),
                                        timeout=TIMEOUT_SECONDS) as r:
                return json.load(r)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"GitHub API {path} returned {exc.code}")
        except (urllib.error.URLError, OSError) as exc:
            raise RuntimeError(f"Could not reach the GitHub API: {exc}")

    def download(self, url):
        """
        Download an artifact zip. GitHub answers with a redirect to a
        short-lived storage URL; that second request must NOT carry our
        token, so the redirect is followed manually without it.
        """
        try:
            try:
                with _no_redirect_opener.open(self._request(url), timeout=TIMEOUT_SECONDS) as r:
                    return r.read()
            except urllib.error.HTTPError as exc:
                if exc.code not in (301, 302, 303, 307, 308):
                    raise
                location = exc.headers.get("Location")
            with urllib.request.urlopen(location, timeout=TIMEOUT_SECONDS) as r:
                return r.read()
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Artifact download returned {exc.code}")
        except (urllib.error.URLError, OSError) as exc:
            raise RuntimeError(f"Artifact download failed: {exc}")

    def runs_since(self, workflow, since):
        """All completed runs of the workflow created on or after 'since'."""
        runs, page = [], 1
        created = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        while True:
            data = self.get_json(
                f"/repos/{self.repo}/actions/workflows/{workflow}/runs"
                f"?status=completed&created=%3E%3D{created}&per_page=100&page={page}"
            )
            batch = data.get("workflow_runs", [])
            runs.extend(batch)
            if len(batch) < 100:
                return runs
            page += 1

    def summary_for_run(self, run_id):
        """The scan-summary.json from a run's artifact, or None if unavailable."""
        data = self.get_json(f"/repos/{self.repo}/actions/runs/{run_id}/artifacts")
        for art in data.get("artifacts", []):
            if art.get("name") == ARTIFACT_NAME and not art.get("expired"):
                blob = self.download(art["archive_download_url"])
                with zipfile.ZipFile(io.BytesIO(blob)) as z:
                    if SUMMARY_FILENAME in z.namelist():
                        return json.loads(z.read(SUMMARY_FILENAME))
        return None


# --- Summarise --------------------------------------------------------------

def collect(github, workflow, since):
    """One record per scan run: when, where, and what the scanner decided."""
    records = []
    for run in github.runs_since(workflow, since):
        summary = github.summary_for_run(run["id"])
        records.append({
            "when": run.get("created_at", ""),
            "branch": run.get("head_branch") or "unknown",
            "event": run.get("event", ""),
            # A run with no summary broke before the scanner could write one.
            "status": (summary or {}).get("status", "ERROR"),
            "summary": summary,
        })
    records.sort(key=lambda r: r["when"])
    return records


def exceptions_line(summary):
    """
    One line on the exceptions in a scan summary, counts only.
    None for older summaries (schema 1) that predate exceptions.
    """
    if "exceptions" not in summary:
        return None
    exceptions = summary.get("exceptions") or []
    if not exceptions:
        return "*Exceptions:* none"
    expired = sum(e.get("state") == "expired" for e in exceptions)
    unused = sum(e.get("state") != "expired" and not e.get("matched") for e in exceptions)
    soon = sum(e.get("state") == "expiring_soon" and e.get("matched") for e in exceptions)
    active = len(exceptions) - expired - unused - soon
    fixable = len({e.get("id") for e in summary.get("excepted") or [] if e.get("fix_available")})
    parts = [f"{active} active"]
    if soon:
        parts.append(f":hourglass: {soon} expiring within 7 days")
    if expired:
        parts.append(f":no_entry: {expired} expired")
    if unused:
        parts.append(f"{unused} no longer found (remove?)")
    if fixable:
        parts.append(f":wrench: fix now available for {fixable}")
    return "*Exceptions:* " + ", ".join(parts) + ". Details in the latest scan report."


def build_digest(records, days, since, now):
    period = f"{since:%d %b} – {now:%d %b %Y}"
    label = "Daily" if days == 1 else ("Weekly" if days == 7 else f"{days}-day")
    headline = f":bar_chart: {label} vulnerability summary ({period})"

    if not records:
        body = "No scans ran in this period."
        return {"text": headline, "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*{headline}*"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": body}},
        ]}

    total = len(records)
    passed = sum(r["status"] == "PASS" for r in records)
    failed = sum(r["status"] == "FAIL" for r in records)
    errored = sum(r["status"] == "ERROR" for r in records)

    lines = [
        f"*Scans run:* {total}",
        f":white_check_mark: Passed: {passed}    :no_entry: Blocked: {failed}    "
        f":warning: Errors: {errored}",
    ]

    # Latest result on main: the current state of what would ship.
    main_runs = [r for r in records if r["branch"] == "main" and r["summary"]]
    if main_runs:
        latest = main_runs[-1]["summary"]
        counts = latest.get("counts") or {}
        crit, high = counts.get("CRITICAL", 0), counts.get("HIGH", 0)
        lines.append(f"*Latest on main:* {latest.get('status')} "
                     f"(CRITICAL {crit}, HIGH {high})")

        exc_line = exceptions_line(latest)
        if exc_line:
            lines.append(exc_line)

    blocked = [r for r in records if r["status"] == "FAIL" and r["summary"]]
    if blocked:
        lines.append("")
        lines.append("*Blocked scans:*")
        for r in blocked[-MAX_BLOCKED_LISTED:]:
            s = r["summary"]
            worst = worst_severity(s.get("counts") or {}) or "n/a"
            reasons = ", ".join(f"{b['severity']} {b['found']}/{b['limit']}"
                                for b in s.get("breaches") or [])
            lines.append(f"• {r['when'][:10]}  `{slack_escape(r['branch'])}`  "
                         f"{slack_escape(s.get('image', 'unknown'))}: worst {worst} ({reasons})")
        if len(blocked) > MAX_BLOCKED_LISTED:
            lines.append(f"…and {len(blocked) - MAX_BLOCKED_LISTED} more.")

    if errored:
        lines.append("")
        lines.append(f":warning: {errored} scan(s) did not complete. "
                     "These are tool problems, not policy results; check the scan workflow.")

    return {"text": headline, "blocks": [
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*{headline}*"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
    ]}


# --- Entry point ------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Post a summary of recent scans to Slack.")
    parser.add_argument("--days", type=int, default=7,
                        help="How many days to cover (default: 7; use 1 for daily)")
    parser.add_argument("--workflow", default=DEFAULT_WORKFLOW,
                        help=f"Scan workflow file name (default: {DEFAULT_WORKFLOW})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the Slack message instead of sending it")
    args = parser.parse_args()

    if args.days < 1:
        print("DIGEST ERROR: --days must be 1 or more.", file=sys.stderr)
        return EXIT_ERROR

    token = os.environ.get("GITHUB_TOKEN", "").strip()
    repo = os.environ.get("GITHUB_REPOSITORY", "").strip()
    api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    if not token or not repo:
        print("DIGEST ERROR: GITHUB_TOKEN and GITHUB_REPOSITORY must be set.", file=sys.stderr)
        return EXIT_ERROR

    now = datetime.now(timezone.utc)
    since = now - timedelta(days=args.days)

    try:
        records = collect(GitHub(token, repo, api_url), args.workflow, since)
    except (RuntimeError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        print(f"DIGEST ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR

    payload = build_digest(records, args.days, since, now)
    print(f"Collected {len(records)} scan run(s) from the last {args.days} day(s).")

    if args.dry_run:
        print(json.dumps(payload, indent=2))
        return EXIT_OK

    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if not webhook_url:
        print("::notice::SLACK_WEBHOOK_URL is not set, so no summary was sent.")
        return EXIT_OK

    try:
        post_to_slack(webhook_url, payload)
    except RuntimeError as exc:
        print(f"DIGEST ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print("Summary sent to Slack.")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
