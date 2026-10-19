#!/usr/bin/env python3
"""
Sprint 4 — Prometheus exporter for scan history.

GitHub Actions runs in the cloud and Jenkins runs locally, so neither can
push metrics into a local Prometheus. Instead this exporter PULLS the scan
history every few minutes from the artifacts both pipelines already keep:

  GitHub   trivy-scan-report artifact of each scan.yml run (same API as digest.py)
  Jenkins  archived reports/** of each build of the job (local Jenkins API)

and serves it as Prometheus metrics on /metrics. No database: the
artifacts are the history.

Definitions (each scan is compared with the previous scan of the SAME
image from the SAME pipeline; only scans of main / Jenkins builds count
towards trends, PR scans only count towards scan results):
  found     CVE (vulnerability ID + package) not in the previous scan
  resolved  in the previous scan, gone now
  pending   open in the latest scan, split into fix available / no fix yet

A scan that ERRORed has no vulnerability list. It is counted as an error
and never as "everything resolved": a broken scanner must never look like
a clean image (same rule as scanner.py's exit codes).

Metrics:
  vuln_pending{source,image,severity,fix}      gauge
  vuln_found_total{source,image,severity}      counter
  vuln_resolved_total{source,image,severity}   counter
  scans_total{source,image,status}             counter  (PASS/FAIL/ERROR)
  scan_last_result{source,image}               gauge    (scanner exit code 0/1/2)
  scan_last_timestamp_seconds{source,image}    gauge
  exporter_source_up{source}                   gauge    (1 = last fetch worked)
  exporter_last_poll_timestamp_seconds{source} gauge

Counters must only ever go up, but GitHub expires artifacts after ~90 days
and Jenkins keeps only the last 30 builds. So the exporter remembers which
scans it already counted in a small JSON state file (--state-file) and only
adds new ones; old scans dropping out of the history never lower a counter.

Configuration (environment variables; secrets never on the command line):
  GITHUB_TOKEN        fine-grained PAT, this repo only, Actions: read
  GITHUB_REPOSITORY   owner/repo
  JENKINS_URL         e.g. http://localhost:8080   (unset = Jenkins skipped)
  JENKINS_USER        Jenkins username
  JENKINS_TOKEN       Jenkins API token
  JENKINS_JOB         job name (default vuln-scanner)

Usage:
  python exporter.py                                   # serve on 127.0.0.1:9105
  python exporter.py --once                            # one fetch, print metrics, exit
  python exporter.py --state-file /data/state.json --listen 0.0.0.0:9105

Exit codes (--once):
  0  every configured source was read
  2  a source could not be read (metrics are still printed)
"""

import argparse
import base64
import io
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from digest import ARTIFACT_NAME, DEFAULT_WORKFLOW, GitHub
from scanner import REPORT_FILENAME, SEVERITY_ORDER, SUMMARY_FILENAME

EXIT_OK = 0
EXIT_ERROR = 2

EXIT_BY_STATUS = {"PASS": 0, "FAIL": 1, "ERROR": 2}
DEFAULT_LISTEN = "127.0.0.1:9105"
DEFAULT_INTERVAL = 300          # seconds between fetches
GITHUB_HISTORY_DAYS = 90        # GitHub's default artifact retention
TIMEOUT_SECONDS = 30
STATE_VERSION = 1

# The repo's own image is tagged differently per pipeline
# (vuln-scanner-test:ci, vuln-scanner-test:jenkins-<N>). Normalise it so
# it is one series per pipeline instead of a new image every build.
REPO_IMAGE = "vuln-scanner-test"


def normalise_image(image):
    if not image:
        return REPO_IMAGE
    if image.split(":", 1)[0] == REPO_IMAGE:
        return REPO_IMAGE
    return image


# --- Reading one scan's files ----------------------------------------------

def vulns_from_report(trivy_output):
    """
    {"CVE-ID|package": {"severity": ..., "fix": bool}} from Trivy's JSON.
    Keyed by ID + package, so a CVE fixed in one package but still present
    in another is tracked separately.
    """
    vulns = {}
    for result in trivy_output.get("Results", []) or []:
        for v in result.get("Vulnerabilities", []) or []:
            key = f'{v.get("VulnerabilityID", "UNKNOWN")}|{v.get("PkgName", "")}'
            vulns[key] = {
                "severity": (v.get("Severity") or "UNKNOWN").upper(),
                "fix": bool(v.get("FixedVersion")),
            }
    return vulns


def make_scan(key, source, when, main, summary, report, fallback_image):
    """One normalised scan record, whatever pipeline it came from."""
    if summary is None:
        # No scan-summary.json: the pipeline broke before the scanner
        # could write one. That is an error, not a clean scan.
        status, image = "ERROR", fallback_image
    else:
        status = summary.get("status", "ERROR")
        image = summary.get("image") or fallback_image
        when = summary.get("scanned_at") or when
    vulns = None
    if status != "ERROR" and report is not None:
        vulns = vulns_from_report(report)
    return {
        "key": key,
        "source": source,
        "image": normalise_image(image),
        "when": when,
        "main": main,
        "status": status,
        "vulns": vulns,
    }


# --- Source: GitHub Actions -------------------------------------------------

class GitHubSource:
    name = "github"

    def __init__(self, token, repo, workflow=DEFAULT_WORKFLOW,
                 api_url="https://api.github.com"):
        self.gh = GitHub(token, repo, api_url)
        self.workflow = workflow

    def files_for_run(self, run_id):
        """(summary, report, found) from a run's artifact. found=False if
        the artifact expired, so the run is skipped rather than miscounted."""
        data = self.gh.get_json(f"/repos/{self.gh.repo}/actions/runs/{run_id}/artifacts")
        for art in data.get("artifacts", []):
            if art.get("name") != ARTIFACT_NAME:
                continue
            if art.get("expired"):
                return None, None, False
            blob = self.gh.download(art["archive_download_url"])
            with zipfile.ZipFile(io.BytesIO(blob)) as z:
                names = z.namelist()
                summary = json.loads(z.read(SUMMARY_FILENAME)) if SUMMARY_FILENAME in names else None
                report = json.loads(z.read(REPORT_FILENAME)) if REPORT_FILENAME in names else None
            return summary, report, True
        return None, None, True

    def new_scans(self, seen):
        since = datetime.now(timezone.utc) - timedelta(days=GITHUB_HISTORY_DAYS)
        scans = []
        for run in self.gh.runs_since(self.workflow, since):
            key = f'github:{run["id"]}:{run.get("run_attempt", 1)}'
            if key in seen:
                continue
            summary, report, found = self.files_for_run(run["id"])
            if not found:
                seen.add(key)       # expired: nothing to count, don't ask again
                continue
            main = run.get("event") != "pull_request" and run.get("head_branch") == "main"
            scans.append(make_scan(key, self.name, run.get("created_at", ""), main,
                                   summary, report, REPO_IMAGE))
        return scans


# --- Source: Jenkins --------------------------------------------------------

class JenkinsSource:
    name = "jenkins"

    def __init__(self, url, user, token, job):
        self.url = url.rstrip("/")
        self.job = urllib.parse.quote(job)
        cred = base64.b64encode(f"{user}:{token}".encode()).decode()
        self.headers = {"Authorization": f"Basic {cred}"}

    def _get(self, path):
        req = urllib.request.Request(self.url + path, headers=self.headers)
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as r:
                return r.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise RuntimeError(f"Jenkins {path} returned {exc.code}")
        except (urllib.error.URLError, OSError) as exc:
            raise RuntimeError(f"Could not reach Jenkins at {self.url}: {exc}")

    def _artifact(self, number, filename):
        raw = self._get(f"/job/{self.job}/{number}/artifact/reports/{filename}")
        return json.loads(raw) if raw else None

    def new_scans(self, seen):
        tree = "builds[number,result,building,timestamp,actions[parameters[name,value]]]"
        raw = self._get(f"/job/{self.job}/api/json?tree={urllib.parse.quote(tree)}")
        if raw is None:
            raise RuntimeError(f"Jenkins job '{urllib.parse.unquote(self.job)}' not found")
        scans = []
        for b in json.loads(raw).get("builds", []):
            if b.get("building"):
                continue            # count it once it has finished
            # Timestamp in the key: build numbers restart if Jenkins is rebuilt.
            key = f'jenkins:{b["number"]}:{b.get("timestamp")}'
            if key in seen:
                continue
            summary = self._artifact(b["number"], SUMMARY_FILENAME)
            if summary is None and b.get("result") == "ABORTED":
                seen.add(key)       # stopped by a person, not a scan result
                continue
            report = self._artifact(b["number"], REPORT_FILENAME) if summary else None
            params = {p.get("name"): p.get("value")
                      for a in b.get("actions") or [] if a
                      for p in a.get("parameters") or []}
            when = datetime.fromtimestamp((b.get("timestamp") or 0) / 1000,
                                          timezone.utc).isoformat(timespec="seconds")
            # The Jenkins job tracks main, so every build counts towards trends.
            scans.append(make_scan(key, self.name, when, True, summary, report,
                                   (params.get("SCAN_IMAGE") or "").strip() or REPO_IMAGE))
        return scans


# --- State: what has been counted so far -----------------------------------

def series_id(source, image):
    return f"{source}|{image}"


class State:
    """
    Everything the metrics are built from. Saved to a JSON file so
    counters survive restarts and history expiry.
    """

    def __init__(self):
        self.seen = set()       # scan keys already counted
        self.series = {}        # series_id -> latest main-branch scan data
        self.found = {}         # "series|severity" -> int
        self.resolved = {}
        self.scans = {}         # "source|image|status" -> int

    @classmethod
    def load(cls, path):
        st = cls()
        if path and os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
            if data.get("version") != STATE_VERSION:
                raise RuntimeError(f"State file {path} has an unknown version")
            st.seen = set(data["seen"])
            st.series = data["series"]
            st.found, st.resolved, st.scans = data["found"], data["resolved"], data["scans"]
        return st

    def save(self, path):
        if not path:
            return
        data = {"version": STATE_VERSION, "seen": sorted(self.seen), "series": self.series,
                "found": self.found, "resolved": self.resolved, "scans": self.scans}
        # Write to a temp file and rename, so a crash never leaves half a file.
        folder = os.path.dirname(os.path.abspath(path))
        fd, tmp = tempfile.mkstemp(dir=folder, prefix=".exporter-state-")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.replace(tmp, path)

    def add(self, scan):
        sid = series_id(scan["source"], scan["image"])
        skey = f'{sid}|{scan["status"]}'
        self.scans[skey] = self.scans.get(skey, 0) + 1
        self.seen.add(scan["key"])
        if not scan["main"]:
            return                  # PR scans: counted as results only

        s = self.series.setdefault(sid, {"source": scan["source"], "image": scan["image"],
                                         "last_when": "", "last_status": None,
                                         "last_vulns_when": "", "vulns": None})
        if scan["when"] >= s["last_when"]:
            s["last_when"], s["last_status"] = scan["when"], scan["status"]

        # Found/resolved only between two scans that both produced a list,
        # and only moving forwards in time (a late-arriving older scan
        # must not rewind the comparison).
        if scan["vulns"] is None or scan["when"] < s["last_vulns_when"]:
            return
        prev = s["vulns"] or {}
        cur = scan["vulns"]
        for k in cur.keys() - prev.keys():
            fkey = f'{sid}|{cur[k]["severity"]}'
            self.found[fkey] = self.found.get(fkey, 0) + 1
        for k in prev.keys() - cur.keys():
            rkey = f'{sid}|{prev[k]["severity"]}'
            self.resolved[rkey] = self.resolved.get(rkey, 0) + 1
        s["vulns"], s["last_vulns_when"] = cur, scan["when"]


# --- Prometheus text format -------------------------------------------------

def _label(value):
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _line(name, labels, value):
    inner = ",".join(f'{k}="{_label(v)}"' for k, v in labels.items())
    return f"{name}{{{inner}}} {value}"


def _epoch(iso):
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        return 0


def render(state, health):
    out = []

    def metric(name, kind, help_text, lines):
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} {kind}")
        out.extend(lines)

    pending, found, resolved, last_result, last_ts = [], [], [], [], []
    for sid, s in sorted(state.series.items()):
        base = {"source": s["source"], "image": s["image"]}
        vulns = s["vulns"] or {}
        for sev in SEVERITY_ORDER:
            # Every severity always gets a value, so "0" shows as 0 and
            # not as "No data" on the dashboard.
            for fix in (True, False):
                n = sum(1 for v in vulns.values() if v["severity"] == sev and v["fix"] == fix)
                pending.append(_line("vuln_pending",
                                     {**base, "severity": sev,
                                      "fix": "available" if fix else "none"}, n))
            found.append(_line("vuln_found_total", {**base, "severity": sev},
                               state.found.get(f"{sid}|{sev}", 0)))
            resolved.append(_line("vuln_resolved_total", {**base, "severity": sev},
                                  state.resolved.get(f"{sid}|{sev}", 0)))
        if s["last_status"]:
            last_result.append(_line("scan_last_result", base,
                                     EXIT_BY_STATUS.get(s["last_status"], 2)))
            last_ts.append(_line("scan_last_timestamp_seconds", base, int(_epoch(s["last_when"]))))

    scans = []
    for key, n in sorted(state.scans.items()):
        source, image, status = key.split("|")
        scans.append(_line("scans_total", {"source": source, "image": image, "status": status}, n))

    metric("vuln_pending", "gauge",
           "Vulnerabilities open in the latest main-branch scan.", pending)
    metric("vuln_found_total", "counter",
           "Vulnerabilities seen for the first time compared with the previous scan.", found)
    metric("vuln_resolved_total", "counter",
           "Vulnerabilities in the previous scan that are gone now.", resolved)
    metric("scans_total", "counter", "Scans by result (PASS, FAIL, ERROR).", scans)
    metric("scan_last_result", "gauge",
           "Latest main-branch scan result as the scanner exit code: 0 pass, 1 blocked, 2 error.",
           last_result)
    metric("scan_last_timestamp_seconds", "gauge",
           "When the latest main-branch scan ran (Unix time).", last_ts)
    metric("exporter_source_up", "gauge", "1 if the last fetch from this source worked.",
           [_line("exporter_source_up", {"source": n}, h["up"]) for n, h in sorted(health.items())])
    metric("exporter_last_poll_timestamp_seconds", "gauge", "When this source was last fetched.",
           [_line("exporter_last_poll_timestamp_seconds", {"source": n}, h["at"])
            for n, h in sorted(health.items())])
    return "\n".join(out) + "\n"


# --- Polling and serving ----------------------------------------------------

class Exporter:
    def __init__(self, sources, state_file):
        self.sources = sources
        self.state_file = state_file
        self.state = State.load(state_file)
        self.health = {s.name: {"up": 0, "at": 0} for s in sources}
        self.lock = threading.Lock()
        self.text = render(self.state, self.health)

    def poll(self):
        """Fetch new scans from every source. Returns True if all worked."""
        all_ok = True
        new = []
        for src in self.sources:
            try:
                new.extend(src.new_scans(self.state.seen))
                self.health[src.name] = {"up": 1, "at": int(time.time())}
            except (RuntimeError, zipfile.BadZipFile, json.JSONDecodeError, KeyError) as exc:
                # Keep the last known values; exporter_source_up shows the problem.
                print(f"FETCH ERROR ({src.name}): {exc}", file=sys.stderr)
                self.health[src.name] = {"up": 0, "at": int(time.time())}
                all_ok = False
        with self.lock:
            for scan in sorted(new, key=lambda s: s["when"]):
                self.state.add(scan)
            if new:
                print(f"Counted {len(new)} new scan(s).", file=sys.stderr)
            try:
                self.state.save(self.state_file)
            except OSError as exc:
                print(f"STATE ERROR: could not save {self.state_file}: {exc}", file=sys.stderr)
                all_ok = False
            self.text = render(self.state, self.health)
        return all_ok

    def metrics(self):
        with self.lock:
            return self.text


def serve(exporter, listen, interval):
    host, port = listen.rsplit(":", 1)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.split("?")[0] != "/metrics":
                self.send_error(404)
                return
            body = exporter.metrics().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass                    # Prometheus scrapes often; keep the log quiet

    def loop():
        while True:
            exporter.poll()
            time.sleep(interval)

    threading.Thread(target=loop, daemon=True).start()
    print(f"Serving metrics on http://{host}:{port}/metrics (fetch every {interval}s)",
          file=sys.stderr)
    ThreadingHTTPServer((host, int(port)), Handler).serve_forever()


def build_sources():
    """Sources from environment variables. A missing GitHub config is an error."""
    token, repo = os.environ.get("GITHUB_TOKEN"), os.environ.get("GITHUB_REPOSITORY")
    if not token or not repo:
        raise RuntimeError("GITHUB_TOKEN and GITHUB_REPOSITORY must be set")
    sources = [GitHubSource(token, repo,
                            api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"))]
    jenkins_url = os.environ.get("JENKINS_URL")
    if jenkins_url:
        user, jtoken = os.environ.get("JENKINS_USER"), os.environ.get("JENKINS_TOKEN")
        if not user or not jtoken:
            raise RuntimeError("JENKINS_URL is set, so JENKINS_USER and JENKINS_TOKEN must be too")
        sources.append(JenkinsSource(jenkins_url, user, jtoken,
                                     os.environ.get("JENKINS_JOB", "vuln-scanner")))
    else:
        print("JENKINS_URL not set: Jenkins history skipped.", file=sys.stderr)
    return sources


def main():
    parser = argparse.ArgumentParser(description="Prometheus exporter for vulnerability scan history.")
    parser.add_argument("--listen", default=DEFAULT_LISTEN, help=f"host:port (default {DEFAULT_LISTEN})")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL,
                        help=f"seconds between fetches (default {DEFAULT_INTERVAL})")
    parser.add_argument("--state-file", help="JSON file that keeps counters across restarts")
    parser.add_argument("--once", action="store_true", help="fetch once, print metrics, exit")
    args = parser.parse_args()

    try:
        exporter = Exporter(build_sources(), args.state_file)
    except (RuntimeError, OSError, json.JSONDecodeError) as exc:
        print(f"CONFIG ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.once:
        ok = exporter.poll()
        sys.stdout.write(exporter.metrics())
        return EXIT_OK if ok else EXIT_ERROR

    serve(exporter, args.listen, args.interval)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
