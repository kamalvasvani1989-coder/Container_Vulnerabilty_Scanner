#!/usr/bin/env python3
"""
Sprint 3, step 2 — HTML report.

Reads the two files scanner.py writes with --output-dir:
  scan-summary.json  — the verdict (status, counts, thresholds, breaches)
  trivy-report.json  — Trivy's raw JSON (the per-CVE detail)
and renders them into one self-contained HTML page.

This script never re-decides pass/fail. The verdict comes from
scan-summary.json only, so the report can't disagree with the gate.

Usage:
  python report.py                       # reads reports/, writes reports/report.html
  python report.py --input-dir reports --output reports/report.html

Exit codes:
  0  report written
  2  could not read the inputs or write the report
"""

import argparse
import json
import os
import sys

from jinja2 import Environment, FileSystemLoader, select_autoescape

# Reuse the scanner's own parser, so the report reads Trivy's JSON
# exactly the way the gate did.
from scanner import (
    REPORT_FILENAME,
    SEVERITY_ORDER,
    SUMMARY_FILENAME,
    parse_vulnerabilities,
)

EXIT_OK = 0
EXIT_ERROR = 2

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_TEMPLATE_DIR = os.path.join(HERE, "templates")
TEMPLATE_NAME = "report.html.j2"


def load_json(path, required):
    """Load a JSON file. Missing optional files return None."""
    if not os.path.exists(path):
        if required:
            raise RuntimeError(f"Required file not found: {path}")
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read {path}: {exc}")


def severity_rank(sev):
    """CRITICAL first, then HIGH ... UNKNOWN, then anything unexpected."""
    return SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)


def build_context(summary, trivy_output):
    """Everything the template needs, already sorted and shaped."""
    vulns = parse_vulnerabilities(trivy_output) if trivy_output else []
    vulns.sort(key=lambda v: (severity_rank(v["severity"]), v["id"], v["package"]))

    thresholds = summary.get("thresholds") or {}
    counts = summary.get("counts") or {}
    breached = {b["severity"] for b in summary.get("breaches") or []}

    # One row per severity in a fixed order, so the counts block always
    # has the same shape (zeros included) from report to report.
    severities = [s for s in SEVERITY_ORDER]
    severities += sorted(s for s in counts if s not in SEVERITY_ORDER)
    severity_rows = [
        {
            "name": sev,
            "count": counts.get(sev, 0),
            "limit": thresholds.get(sev),
            "gated": sev in thresholds,
            "breached": sev in breached,
        }
        for sev in severities
    ]

    return {
        "summary": summary,
        "severity_rows": severity_rows,
        "vulns": vulns,
        "fixable": sum(1 for v in vulns if v["fixed"]),
    }


def render(context, template_dir):
    env = Environment(
        loader=FileSystemLoader(template_dir),
        # Autoescape matters: CVE and package fields come from outside
        # sources and must never be able to inject HTML into the report.
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return env.get_template(TEMPLATE_NAME).render(**context)


def main():
    parser = argparse.ArgumentParser(description="Render a scan as an HTML report.")
    parser.add_argument("--input-dir", default="reports",
                        help="Folder containing scanner.py's output files (default: reports)")
    parser.add_argument("--output", default=None,
                        help="HTML file to write (default: <input-dir>/report.html)")
    parser.add_argument("--template-dir", default=DEFAULT_TEMPLATE_DIR,
                        help="Folder containing report.html.j2")
    args = parser.parse_args()
    output = args.output or os.path.join(args.input_dir, "report.html")

    try:
        summary = load_json(os.path.join(args.input_dir, SUMMARY_FILENAME), required=True)
        # On a tool error there is no Trivy report — that's expected.
        trivy_output = load_json(os.path.join(args.input_dir, REPORT_FILENAME), required=False)
        html = render(build_context(summary, trivy_output), args.template_dir)
        with open(output, "w") as f:
            f.write(html)
    except Exception as exc:  # any failure here is a reporting error, never a verdict
        print(f"REPORT ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(f"Wrote {output}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
