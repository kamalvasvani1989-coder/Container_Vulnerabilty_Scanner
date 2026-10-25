#!/usr/bin/env python3
"""
Sprint 3, step 4 — Slack alert.

Reads scan-summary.json (written by scanner.py) and posts a short message
to a Slack channel through an incoming webhook when a scan needs
attention:
  FAIL   — the policy gate blocked the image
  ERROR  — the scanner itself broke (no pass/fail decision was made)
A PASS sends nothing: alerts that fire on every success get ignored.

Alerts are customised by severity level (Sprint 3 brief):
  the colour and wording follow the worst severity found, and severities
  listed under alerts.mention_channel_on in policy.yaml (default: CRITICAL)
  make the alert @channel, so everyone is notified immediately.

The webhook URL is a secret. It is read from the SLACK_WEBHOOK_URL
environment variable (a GitHub Actions secret in CI) and is never printed.
If it isn't set, the script skips the alert with a notice instead of
failing, so the pipeline still works before Slack is configured.

Like report.py, this never re-decides pass/fail. The verdict comes from
scan-summary.json only.

Sprint 5: temporary Slack problems (network, 429, 5xx) are retried up
to 3 times; a 4xx is not, because a bad webhook won't fix itself.

The message carries the verdict and counts only. It deliberately contains
no links: the full HTML/PDF reports stay in the GitHub Actions artifact,
behind repository access, and never get posted into the channel.

Usage:
  python src/notify.py                          # reads reports/scan-summary.json
  python src/notify.py --input-dir reports --policy policy.yaml
  python src/notify.py --dry-run                # print the message, don't send it

Exit codes:
  0  alert sent, or nothing to send (PASS, or webhook not configured)
  2  the alert could not be sent
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

import yaml

from scanner import DEFAULT_POLICY_PATH, SEVERITY_ORDER, SUMMARY_FILENAME

EXIT_OK = 0
EXIT_ERROR = 2

TIMEOUT_SECONDS = 10

# Used when policy.yaml has no 'alerts' section.
DEFAULT_MENTION_ON = ["CRITICAL"]

# Visual level per worst severity found.
SEVERITY_STYLE = {
    "CRITICAL": (":red_circle:", "Critical vulnerabilities found"),
    "HIGH": (":large_orange_circle:", "High-severity vulnerabilities found"),
    "MEDIUM": (":large_yellow_circle:", "Medium-severity vulnerabilities found"),
    "LOW": (":large_blue_circle:", "Low-severity vulnerabilities found"),
    "UNKNOWN": (":white_circle:", "Vulnerabilities found"),
}


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


def load_alert_config(policy_path):
    """
    Read alerts.mention_channel_on from policy.yaml.

    Allowed values: severity names (CRITICAL, HIGH, ...) and ERROR.
    The alert must still go out if this section is missing or wrong, so
    problems fall back to the default with a warning instead of failing.
    """
    try:
        with open(policy_path, "r") as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as exc:
        print(f"::warning::Could not read {policy_path} ({exc}); "
              f"using default mention_channel_on {DEFAULT_MENTION_ON}.")
        return DEFAULT_MENTION_ON

    alerts = data.get("alerts") if isinstance(data, dict) else None
    if alerts is None:
        return DEFAULT_MENTION_ON
    mention_on = alerts.get("mention_channel_on") if isinstance(alerts, dict) else None
    if not isinstance(mention_on, list) or not all(isinstance(x, str) for x in mention_on):
        print("::warning::alerts.mention_channel_on in policy.yaml must be a list "
              f"like [CRITICAL]; using default {DEFAULT_MENTION_ON}.")
        return DEFAULT_MENTION_ON
    return [x.upper() for x in mention_on]


def worst_severity(counts):
    """The most severe level with at least one finding, or None."""
    for sev in SEVERITY_ORDER:
        if counts.get(sev, 0) > 0:
            return sev
    return None


def should_mention(summary, mention_on):
    """@channel when the scan errored (if ERROR is listed) or found any listed severity."""
    if summary.get("status") == "ERROR":
        return "ERROR" in mention_on
    counts = summary.get("counts") or {}
    return any(counts.get(sev, 0) > 0 for sev in mention_on)


def ci_source():
    """
    Which CI system is sending this alert, from variables each one sets
    automatically: GitHub Actions sets GITHUB_ACTIONS=true and
    GITHUB_RUN_NUMBER; Jenkins sets BUILD_NUMBER in every shell step, plus
    JENKINS_HOME (always) and JENKINS_URL (once its URL is configured).
    Checked in that order. None for a manual run, so the message then has
    no Source label.
    """
    env = os.environ
    if env.get("GITHUB_ACTIONS") == "true":
        run = env.get("GITHUB_RUN_NUMBER", "").strip()
        return f"GitHub Actions run #{run}" if run.isdigit() else "GitHub Actions"
    if env.get("BUILD_NUMBER") and (env.get("JENKINS_URL") or env.get("JENKINS_HOME")):
        build = env.get("BUILD_NUMBER", "").strip()
        return f"Jenkins build #{build}" if build.isdigit() else "Jenkins"
    return None


def build_message(summary, mention_on=DEFAULT_MENTION_ON):
    """Build the Slack payload: a plain-text fallback plus formatted blocks."""
    status = summary.get("status")
    image = slack_escape(summary.get("image", "unknown"))

    if status == "FAIL":
        counts = summary.get("counts") or {}
        emoji, label = SEVERITY_STYLE.get(worst_severity(counts), (":red_circle:", "Policy limits exceeded"))
        headline = f"{emoji} {label}, build blocked: {image}"
        lines = ["The build is blocked until these are fixed:"]
        for b in summary.get("breaches") or []:
            lines.append(f"• *{b['severity']}*: {b['found']} found, limit is {b['limit']}")
        shown = [s for s in SEVERITY_ORDER if s in counts]
        if shown:
            lines.append("All findings: " + ", ".join(f"{s} {counts[s]}" for s in shown))
        # Sprint 5: say when approved exceptions explain the gap between
        # "found" above and "All findings". Count only: no CVE IDs in Slack.
        excepted = len(summary.get("excepted") or [])
        if excepted:
            lines.append(f"{excepted} excepted (approved), not counted. See the report.")
    else:
        headline = f":warning: Scan did not complete: {image}"
        lines = [
            "The scanner hit an error, so no pass/fail decision was made. "
            "This is a tool problem, not a policy result.",
            "```" + slack_escape(summary.get("error") or "No error details.") + "```",
        ]

    # Where it came from. Source tells the reader which CI system to open,
    # since Jenkins passes its branch/commit in GitHub's format (Sprint 6).
    context = []
    source = ci_source()
    if source:
        context.append(f"Source: {source}")
    branch = os.environ.get("GITHUB_HEAD_REF") or os.environ.get("GITHUB_REF_NAME")
    if branch:
        context.append(f"Branch: `{slack_escape(branch)}`")
    sha = os.environ.get("GITHUB_SHA")
    if sha:
        context.append(f"Commit: `{sha[:7]}`")

    mention = should_mention(summary, mention_on)
    # <!channel> is Slack's syntax for an @channel mention.
    title = f"<!channel> *{headline}*" if mention else f"*{headline}*"

    blocks = [
        {"type": "section", "text": {"type": "mrkdwn", "text": title}},
        {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
    ]
    if context:
        blocks.append({"type": "context",
                       "elements": [{"type": "mrkdwn", "text": "  |  ".join(context)}]})

    # 'text' is what notifications and screen readers show.
    text = f"<!channel> {headline}" if mention else headline
    return {"text": text, "blocks": blocks}


# Retry (Sprint 5): a missed alert is the costly failure, so temporary
# problems are retried. A 4xx (bad or revoked webhook, bad message) is not:
# it won't fix itself, and retrying would only delay the error.
SLACK_ATTEMPTS = 3
SLACK_RETRY_WAITS = (5, 15)          # seconds before attempt 2 and 3
MAX_RETRY_AFTER_SECONDS = 30


class SlackError(RuntimeError):
    """A failed post. 'retryable' says whether trying again could help."""
    def __init__(self, message, retryable, retry_after=None):
        super().__init__(message)
        self.retryable = retryable
        self.retry_after = retry_after


def post_to_slack_once(webhook_url, payload):
    """One POST. Raises SlackError without ever echoing the URL."""
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
                raise SlackError(f"Slack replied {response.status}: {body}", retryable=False)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace").strip()
        message = f"Slack rejected the message ({exc.code}): {detail}"
        if exc.code == 429:                 # rate limited: wait as told
            try:
                retry_after = int(exc.headers.get("Retry-After", ""))
            except ValueError:
                retry_after = None
            raise SlackError(message, retryable=True, retry_after=retry_after)
        raise SlackError(message, retryable=exc.code >= 500)
    except urllib.error.URLError as exc:
        raise SlackError(f"Could not reach Slack: {exc.reason}", retryable=True)
    except ValueError:
        raise SlackError("SLACK_WEBHOOK_URL is not a valid URL.", retryable=False)
    except OSError as exc:
        # Timeouts and other socket errors; str(exc) here never includes the URL.
        raise SlackError(f"Could not reach Slack: {exc}", retryable=True)


def post_to_slack(webhook_url, payload, attempts=None, waits=None, sleep=None):
    """
    POST the payload, retrying temporary failures (network errors, 429,
    5xx). Raises RuntimeError once it gives up, without echoing the URL.
    """
    # Check the scheme ourselves: urllib's own errors quote the full URL,
    # which would leak the secret into the CI log.
    if not webhook_url.startswith("https://"):
        raise RuntimeError("SLACK_WEBHOOK_URL must be an https:// Slack webhook URL.")
    # Defaults are read at call time, so tests can shorten the waits.
    attempts = attempts or SLACK_ATTEMPTS
    waits = SLACK_RETRY_WAITS if waits is None else waits
    sleep = sleep or time.sleep
    for attempt in range(1, attempts + 1):
        try:
            post_to_slack_once(webhook_url, payload)
            if attempt > 1:
                print(f"Slack accepted the message on attempt {attempt} of {attempts}.")
            return
        except SlackError as exc:
            if not exc.retryable:
                raise RuntimeError(str(exc))
            if attempt == attempts:
                raise RuntimeError(f"{exc} (gave up after {attempts} attempts)")
            wait = waits[min(attempt - 1, len(waits) - 1)]
            if exc.retry_after is not None:
                wait = min(max(exc.retry_after, 1), MAX_RETRY_AFTER_SECONDS)
            print(f"WARNING: Slack attempt {attempt} of {attempts} failed ({exc}); "
                  f"retrying in {wait}s.", file=sys.stderr)
            sleep(wait)


def main():
    parser = argparse.ArgumentParser(description="Send a Slack alert for a failed or broken scan.")
    parser.add_argument("--input-dir", default="reports",
                        help="Folder containing scan-summary.json (default: reports)")
    parser.add_argument("--policy", default=DEFAULT_POLICY_PATH,
                        help=f"Policy file with the alerts section (default: {DEFAULT_POLICY_PATH})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the Slack message instead of sending it")
    args = parser.parse_args()

    summary = load_summary(args.input_dir)
    status = summary.get("status")

    if status == "PASS":
        print("Scan passed; no Slack alert needed.")
        return EXIT_OK

    payload = build_message(summary, load_alert_config(args.policy))
    if args.dry_run:
        print(json.dumps(payload, indent=2))
        return EXIT_OK

    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if not webhook_url:
        # GitHub Actions shows '::notice::' lines as annotations on the run.
        print("::notice::SLACK_WEBHOOK_URL is not set, so no Slack alert was sent.")
        return EXIT_OK

    try:
        post_to_slack(webhook_url, payload)
    except RuntimeError as exc:
        print(f"NOTIFY ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(f"Slack alert sent ({status}).")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
