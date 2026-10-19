#!/usr/bin/env python3
"""
Sprint 3, step 4 — Slack alert.

Reads scan-summary.json (written by scanner.py) and posts a short message
to a Slack channel through an incoming webhook when a scan needs
attention:
  FAIL   — the policy gate blocked the image
  ERROR  — the scanner itself broke (no pass/fail decision was made)
A PASS sends nothing: alerts that fire on every success get ignored.

The webhook URL is a secret. It is read from the SLACK_WEBHOOK_URL
environment variable (a GitHub Actions secret in CI) and is never printed.
If it isn't set, the script skips the alert with a notice instead of
failing, so the pipeline still works before Slack is configured.

Like report.py, this never re-decides pass/fail. The verdict comes from
scan-summary.json only.

Usage:
  python notify.py                          # reads reports/scan-summary.json
  python notify.py --input-dir reports --run-url https://...

Exit codes:
  0  alert sent, or nothing to send (PASS, or webhook not configured)
  2  the alert could not be sent
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

from scanner import SEVERITY_ORDER, SUMMARY_FILENAME

EXIT_OK = 0
EXIT_ERROR = 2

TIMEOUT_SECONDS = 10


def slack_escape(text):
    """Slack treats &, < and > as control characters in message text."""
    return (str(text).replace("&", "&amp;")
                     .replace("<", "&lt;")
                     .replace(">", "&gt;"))


def load_summary(input_dir):
    """
    Load scan-summary.json. If it's missing, the pipeline broke before the
    scanner could write it — that still deserves an alert, as an ERROR.
    """
    path = os.path.join(input_dir, SUMMARY_FILENAME)
    try:
        with open(path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {
            "status": "ERROR",
            "image": "unknown",
            "error": (f"{SUMMARY_FILENAME} was not found. The pipeline failed "
                      "before or during the scan step; check the run log."),
        }
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "status": "ERROR",
            "image": "unknown",
            "error": f"Could not read {path}: {exc}",
        }


def run_url_from_env():
    """Link to this GitHub Actions run, where the reports can be downloaded."""
    server = os.environ.get("GITHUB_SERVER_URL")
    repo = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if server and repo and run_id:
        return f"{server}/{repo}/actions/runs/{run_id}"
    return None


def build_message(summary, run_url):
    """Build the Slack payload: a plain-text fallback plus formatted blocks."""
    status = summary.get("status")
    image = slack_escape(summary.get("image", "unknown"))

    if status == "FAIL":
        headline = f":red_circle: Blocked by the policy gate: {image}"
        lines = ["The build is blocked until these are fixed:"]
        for b in summary.get("breaches") or []:
            lines.append(f"• *{b['severity']}*: {b['found']} found, limit is {b['limit']}")
        counts = summary.get("counts") or {}
        shown = [s for s in SEVERITY_ORDER if s in counts]
        if shown:
            lines.append("All findings: " + ", ".join(f"{s} {counts[s]}" for s in shown))
    else:
        headline = f":warning: Scan did not complete: {image}"
        lines = [
            "The scanner hit an error, so no pass/fail decision was made. "
            "This is a tool problem, not a policy result.",
            "```" + slack_escape(summary.get("error") or "No error details.") + "```",
        ]

    # Where it came from, when running in GitHub Actions.
    context = []
    branch = os.environ.get("GITHUB_HEAD_REF") or os.environ.get("GITHUB_REF_NAME")
    if branch:
        context.append(f"Branch: `{slack_escape(branch)}`")
    sha = os.environ.get("GITHUB_SHA")
    if sha:
        context.append(f"Commit: `{sha[:7]}`")
    if run_url:
        context.append(f"<{run_url}|Open the run and download the HTML/PDF report>")

    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*{headline}*"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
    ]
    if context:
        blocks.append({"type": "context",
                       "elements": [{"type": "mrkdwn", "text": "  |  ".join(context)}]})

    # 'text' is what notifications and screen readers show.
    return {"text": headline, "blocks": blocks}


def post_to_slack(webhook_url, payload):
    """POST the payload. Raises RuntimeError without ever echoing the URL."""
    # Check the scheme ourselves: urllib's own errors quote the full URL,
    # which would leak the secret into the CI log.
    if not webhook_url.startswith("https://"):
        raise RuntimeError("SLACK_WEBHOOK_URL must be an https:// Slack webhook URL.")
    try:
        request = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read().decode("utf-8", errors="replace").strip()
            if response.status != 200 or body != "ok":
                raise RuntimeError(f"Slack replied {response.status}: {body}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"Slack rejected the message ({exc.code}): {detail}")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach Slack: {exc.reason}")
    except ValueError:
        raise RuntimeError("SLACK_WEBHOOK_URL is not a valid URL.")
    except OSError as exc:
        # Timeouts and other socket errors; str(exc) here never includes the URL.
        raise RuntimeError(f"Could not reach Slack: {exc}")


def main():
    parser = argparse.ArgumentParser(description="Send a Slack alert for a failed or broken scan.")
    parser.add_argument("--input-dir", default="reports",
                        help="Folder containing scan-summary.json (default: reports)")
    parser.add_argument("--run-url", default=None,
                        help="Link to include in the message (default: this GitHub Actions run)")
    args = parser.parse_args()

    summary = load_summary(args.input_dir)
    status = summary.get("status")

    if status == "PASS":
        print("Scan passed; no Slack alert needed.")
        return EXIT_OK

    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if not webhook_url:
        # GitHub Actions shows '::notice::' lines as annotations on the run.
        print("::notice::SLACK_WEBHOOK_URL is not set, so no Slack alert was sent.")
        return EXIT_OK

    payload = build_message(summary, args.run_url or run_url_from_env())
    try:
        post_to_slack(webhook_url, payload)
    except RuntimeError as exc:
        print(f"NOTIFY ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(f"Slack alert sent ({status}).")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
