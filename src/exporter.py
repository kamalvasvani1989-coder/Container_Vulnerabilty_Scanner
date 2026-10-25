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

Prometheus takes the first value of a brand-new counter as its starting
point, not as an increase. So every image always reports all three scan
statuses (starting at 0), and counters for an image that first appears
after start-up are shown as 0 for one fetch cycle before their real value,
so the rise is recorded. (History loaded at the very first start is
published straight away.)

Configuration (environment variables; secrets never on the command line):
  GITHUB_TOKEN        fine-grained PAT, this repo only, Actions: read
  GITHUB_REPOSITORY   owner/repo
  JENKINS_URL         e.g. http://localhost:8080   (unset = Jenkins skipped)
  JENKINS_USER        Jenkins username
  JENKINS_TOKEN       Jenkins API token
  JENKINS_JOB         job name (default vuln-scanner)

History backfill (--backfill FILE): Prometheus only records from the moment
it first scrapes the exporter. To show trends from before that, this mode
replays the full history with the SAME counting code, one sample every
4 minutes, and writes it as OpenMetrics with the original timestamps. It
stops just before live data begins (asked from Prometheus), so backfilled
counters end exactly where the live ones start. monitoring/backfill.sh
then loads the file with `promtool tsdb create-blocks-from openmetrics`.
It never reads or writes the live state file.

Usage:
  python src/exporter.py                                   # serve on 127.0.0.1:9105
  python src/exporter.py --once                            # one fetch, print metrics, exit
  python src/exporter.py --state-file /data/state.json --listen 0.0.0.0:9105
  python src/exporter.py --backfill history.om --prometheus-url http://prometheus:9090

Exit codes (--once, --backfill):
  0  every configured source was read (and, for --backfill, the file written)
  2  a source could not be read, or no history file could be written
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
BACKFILL_STEP = 240             # seconds between backfilled samples; under
                                # Prometheus' 5-minute lookback, so no gaps
LIVE_SERIES = 'up{job="vuln-exporter"}'      # Prometheus' own record of each scrape

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


def counter_families(state):
    """(family, series_id) pairs that have counters, for spotting new ones."""
    pairs = {("vulns", sid) for sid in state.series}
    pairs |= {("scans", key.rsplit("|", 1)[0]) for key in state.scans}
    return pairs


def collect(state, health, held=frozenset()):
    """
    The metric values, without formatting: a list of
    (name, kind, help, [(labels, value), ...]). Shared by the live
    /metrics page and by --backfill, so the two can never disagree.
    Counters in 'held' are reported as 0 for this cycle.
    """
    pending, found, resolved, last_result, last_ts = [], [], [], [], []
    for sid, s in sorted(state.series.items()):
        base = {"source": s["source"], "image": s["image"]}
        vulns = s["vulns"] or {}
        hold_vulns = ("vulns", sid) in held
        for sev in SEVERITY_ORDER:
            # Every severity always gets a value, so "0" shows as 0 and
            # not as "No data" on the dashboard.
            for fix in (True, False):
                n = sum(1 for v in vulns.values() if v["severity"] == sev and v["fix"] == fix)
                pending.append(({**base, "severity": sev,
                                 "fix": "available" if fix else "none"}, n))
            found.append(({**base, "severity": sev},
                          0 if hold_vulns else state.found.get(f"{sid}|{sev}", 0)))
            resolved.append(({**base, "severity": sev},
                             0 if hold_vulns else state.resolved.get(f"{sid}|{sev}", 0)))
        if s["last_status"]:
            last_result.append((base, EXIT_BY_STATUS.get(s["last_status"], 2)))
            last_ts.append((base, int(_epoch(s["last_when"]))))

    # All three statuses for every image, so a first FAIL or ERROR is a
    # rise from 0 that Prometheus records, not a new series it ignores.
    scans = []
    for sid in sorted({key.rsplit("|", 1)[0] for key in state.scans}):
        source, image = sid.split("|", 1)
        for status in ("PASS", "FAIL", "ERROR"):
            n = 0 if ("scans", sid) in held else state.scans.get(f"{sid}|{status}", 0)
            scans.append(({"source": source, "image": image, "status": status}, n))

    return [
        ("vuln_pending", "gauge",
         "Vulnerabilities open in the latest main-branch scan.", pending),
        ("vuln_found_total", "counter",
         "Vulnerabilities seen for the first time compared with the previous scan.", found),
        ("vuln_resolved_total", "counter",
         "Vulnerabilities in the previous scan that are gone now.", resolved),
        ("scans_total", "counter", "Scans by result (PASS, FAIL, ERROR).", scans),
        ("scan_last_result", "gauge",
         "Latest main-branch scan result as the scanner exit code: 0 pass, 1 blocked, 2 error.",
         last_result),
        ("scan_last_timestamp_seconds", "gauge",
         "When the latest main-branch scan ran (Unix time).", last_ts),
        ("exporter_source_up", "gauge", "1 if the last fetch from this source worked.",
         [({"source": n}, h["up"]) for n, h in sorted(health.items())]),
        ("exporter_last_poll_timestamp_seconds", "gauge", "When this source was last fetched.",
         [({"source": n}, h["at"]) for n, h in sorted(health.items())]),
    ]


def render(state, health, held=frozenset()):
    """Prometheus text format for the live /metrics page."""
    out = []
    for name, kind, help_text, samples in collect(state, health, held):
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} {kind}")
        out.extend(_line(name, labels, value) for labels, value in samples)
    return "\n".join(out) + "\n"


# --- History backfill -------------------------------------------------------

def _prom_query(prometheus_url, query, at=None):
    params = {"query": query}
    if at is not None:
        params["time"] = at
    url = prometheus_url.rstrip("/") + "/api/v1/query?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS) as r:
            return json.load(r)["data"]["result"]
    except (urllib.error.URLError, OSError, KeyError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not query Prometheus at {prometheus_url}: {exc}")


def live_start(prometheus_url):
    """
    (Unix time of the very first live scrape of the exporter, the job and
    instance labels Prometheus gave it). Two cheap queries: first find the
    hour it falls in, then read that hour's raw samples and take the earliest.
    The labels are copied onto the backfill so history and live data are the
    SAME series; without them each series would appear twice.
    """
    hourly = _prom_query(prometheus_url, f"min_over_time(timestamp({LIVE_SERIES})[90d:1h])")
    # No whole-hour mark since the stack started: it started within the last hour.
    around = min(float(r["value"][1]) for r in hourly) if hourly else time.time()
    raw = _prom_query(prometheus_url, f"{LIVE_SERIES}[1h]", at=around)
    stamps = [(float(t), r["metric"]) for r in raw for t, _ in r.get("values", [])]
    if not stamps:
        raise RuntimeError("Prometheus has no live data from the exporter yet; start the stack first")
    first, metric = min(stamps, key=lambda pair: pair[0])
    return first, {"job": metric.get("job", ""), "instance": metric.get("instance", "")}


def _om_line(name, labels, value, ts):
    inner = ",".join(f'{k}="{_label(v)}"' for k, v in labels.items())
    return f"{name}{{{inner}}} {value} {ts}"


def backfill(sources, out_path, until, target_labels):
    """
    Replay every scan before 'until' and write OpenMetrics samples every
    BACKFILL_STEP seconds, with the live job/instance labels added.
    Returns (scans, series, samples, first, last).
    """
    scans, seen = [], set()
    for src in sources:
        scans.extend(src.new_scans(seen))       # a fetch error stops the backfill
    usable = []
    for scan in scans:
        t = _epoch(scan["when"])
        if not t:
            print(f"Skipping scan {scan['key']}: unreadable time {scan['when']!r}", file=sys.stderr)
        elif t < until:
            usable.append((t, scan))
    if not usable:
        raise RuntimeError("No scans before live data started: nothing to backfill")
    # Same order as the live exporter uses.
    usable.sort(key=lambda pair: pair[1]["when"])

    state = State()
    series = {}         # (name, labels) -> [(t, value) at each change], first entry = start
    order = []          # family (name, kind, help) in output order
    first = int(min(t for t, _ in usable) // BACKFILL_STEP * BACKFILL_STEP)
    grid = range(first, int(until) - 60, BACKFILL_STEP)
    i, before = 0, set()
    pending = sorted(usable, key=lambda pair: pair[0])
    for t in grid:
        applied = []
        while i < len(pending) and pending[i][0] <= t:
            applied.append(pending[i][1])
            i += 1
        for scan in sorted(applied, key=lambda s: s["when"]):
            state.add(scan)
        # A counter that first appears now starts at 0 for one sample, so
        # its rise is recorded (same rule as the live exporter).
        now = counter_families(state)
        held = frozenset(now - before)
        before = now
        for name, kind, help_text, samples in collect(state, {}, held):
            if (name, kind, help_text) not in order:
                order.append((name, kind, help_text))
            for labels, value in samples:
                key = (name, tuple(labels.items()))
                changes = series.setdefault(key, [])
                if not changes or changes[-1][1] != value:
                    changes.append((t, value))
    last = grid[-1] if len(grid) else first

    count = written_series = 0
    with open(out_path, "w") as f:
        for name, kind, help_text in order:
            if not any(k[0] == name for k in series):
                continue
            # OpenMetrics names a counter family without the _total suffix.
            family = name[:-len("_total")] if kind == "counter" else name
            f.write(f"# HELP {family} {help_text}\n# TYPE {family} {kind}\n")
            for (sname, labels), changes in series.items():
                if sname != name:
                    continue
                # Skip a counter that was always 0: it adds nothing. Gauges are
                # kept even at 0, because 0 is a real answer there (0 open LOW;
                # last result 0 = PASS) and the dashboard shows it for past dates.
                if kind == "counter" and not any(v for _, v in changes):
                    continue
                written_series += 1
                idx = 0
                for t in range(changes[0][0], last + 1, BACKFILL_STEP):
                    while idx + 1 < len(changes) and changes[idx + 1][0] <= t:
                        idx += 1
                    f.write(_om_line(name, {**dict(labels), **target_labels},
                                     changes[idx][1], t) + "\n")
                    count += 1
        f.write("# EOF\n")
    return len(usable), written_series, count, first, last


# --- Polling and serving ----------------------------------------------------

class Exporter:
    def __init__(self, sources, state_file):
        self.sources = sources
        self.state_file = state_file
        self.state = State.load(state_file)
        self.health = {s.name: {"up": 0, "at": 0} for s in sources}
        self.lock = threading.Lock()
        self.held = frozenset()     # counters shown as 0 for one cycle
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
            first_load = not self.state.seen
            before = counter_families(self.state)
            for scan in sorted(new, key=lambda s: s["when"]):
                self.state.add(scan)
            # Counters that appeared just now start at 0 for one cycle, so
            # Prometheus sees them rise. Not for the very first history load.
            self.held = frozenset() if first_load else frozenset(counter_families(self.state) - before)
            if new:
                print(f"Counted {len(new)} new scan(s).", file=sys.stderr)
            try:
                self.state.save(self.state_file)
            except OSError as exc:
                print(f"STATE ERROR: could not save {self.state_file}: {exc}", file=sys.stderr)
                all_ok = False
            self.text = render(self.state, self.health, self.held)
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
    parser.add_argument("--backfill", metavar="FILE",
                        help="write the scan history as OpenMetrics to FILE for promtool, then exit")
    parser.add_argument("--prometheus-url", default="http://prometheus:9090",
                        help="where --backfill asks when live data started")
    args = parser.parse_args()

    if args.backfill:
        try:
            until, target = live_start(args.prometheus_url)
            scans, nseries, samples, first, last = backfill(build_sources(), args.backfill,
                                                            until, target)
        except (RuntimeError, OSError, zipfile.BadZipFile, json.JSONDecodeError, KeyError) as exc:
            print(f"BACKFILL ERROR: {exc}", file=sys.stderr)
            return EXIT_ERROR
        span = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        print(f"Backfill: {scans} scans replayed, {nseries} series, {samples} samples, "
              f"{span(first)} to {span(last)} -> {args.backfill}", file=sys.stderr)
        return EXIT_OK

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
