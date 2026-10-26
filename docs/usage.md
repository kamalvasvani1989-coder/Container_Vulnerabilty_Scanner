# Usage

All commands run from the repository root with the venv active (`source .venv/bin/activate`).

## Scan an image locally

```bash
python src/scanner.py python:3.9-slim --output-dir reports
echo $?        # 0 PASS, 1 FAIL, 2 ERROR
```

| Option | Default | Meaning |
|---|---|---|
| `image` | (required) | Any image Trivy can read: a local image or one in a registry |
| `--policy FILE` | `policy.yaml` | Policy to apply |
| `--output-dir DIR` | (none) | Also write `trivy-report.json` and `scan-summary.json` to `DIR` |

The console shows the counts per severity (`(gated)` marks severities with a limit, `[N excepted]` shows approved exceptions), the state of every exception that applies to the image, and the result.

To scan the project's own image:

```bash
docker build -t vuln-scanner-test:local sample-app
python src/scanner.py vuln-scanner-test:local --output-dir reports
```

## Reports

```bash
python src/report.py --input-dir reports --pdf
```

Writes `reports/report.html` and `reports/report.pdf` from the two JSON files. The report shows the verdict, a table per severity (found, excepted, counted, limit, result), the exceptions for this image with their state (**Active**, **Expires in N days**, **Expired, counted again**, **Not found: remove?**), and every finding, most severe first, with the fixed version or "No fix yet". A failed or broken scan still gets a report.

`reports/` is git-ignored. In CI the same files are kept as artifacts (see below).

On a cloud VM without a browser, copy the folder to your computer with `scp` and open it there ([setup.md → From a Windows laptop without WSL](setup.md#from-a-windows-laptop-without-wsl) shows the PowerShell version).

## GitHub Actions

| Trigger | What happens |
|---|---|
| Pull request to `main` | `scan` check: unit tests, build `sample-app/`, scan, report, Slack alert on failure. A red check blocks the merge |
| Push to `main` | Same as a PR, for the merged code |
| Daily, 08:00 IST | Rescan: rebuilds the image (picks up patched base layers) and applies the current policy. New CVEs published since the last scan can fail it |
| **Run workflow** (manual) | On demand, with two optional inputs (below) |

**Run workflow** (Actions → Container Image Scan → Run workflow):

| Input | Default | Meaning |
|---|---|---|
| Image to scan | empty | Empty = build and scan the repo image. Or any image, e.g. `python:3.9-slim` |
| Policy file | `policy.yaml` | Any policy file in the repository, e.g. `tests/demo-policy-exceptions-pass.yaml` |

Inputs are checked before use: an image name may contain only image-name characters, and the policy must be a file inside the repository.

**Reports from a run:** open the run → Artifacts → `trivy-scan-report` (zip with the HTML, PDF and both JSON files). GitHub keeps artifacts for about 90 days.

GitHub may start scheduled runs late, by up to a few hours when its runners are busy.

## Jenkins

The `vuln-scanner` job polls `main` every 5 minutes and builds new commits automatically with the defaults. For anything else use **Build with Parameters**:

| Parameter | Default | Meaning |
|---|---|---|
| `SCAN_IMAGE` | empty | Empty = build and scan the repo image (`sample-app/`). Or any image, e.g. `python:3.9-slim` |
| `POLICY_FILE` | `policy.yaml` | Policy file path inside the repository |

Stages: Resolve parameters → Set up Python → Unit tests → Build image (only for the repo image) → Scan → Report → Policy gate. The build ends **SUCCESS** (exit 0), **"Blocked by policy"** (exit 1) or **"Tool error, investigate"** (exit 2). Reports are under the build's **Build Artifacts**; Jenkins keeps the last 30 builds.

## Slack alerts

Sent only when a scan fails or breaks; passing scans are silent.

| Situation | Alert |
|---|---|
| Blocked, worst severity CRITICAL | 🔴 with `@channel` (configurable, see [configuration.md](configuration.md)) |
| Blocked, other severities | 🟠 HIGH, 🟡 MEDIUM, ... without `@channel` |
| Tool or configuration error | ⚠️ "Scan did not complete" with the error message |

Each alert lists the breached limits and all counts, mentions excepted findings as a count only, and ends with a footer such as `Source: Jenkins build #18 | Branch: main | Commit: 887e6a9` or `Source: GitHub Actions run #79 | ...`, so you know which system to open. Alerts never contain links or CVE IDs; the details are in the report.

To preview an alert without sending it:

```bash
python src/notify.py --input-dir reports --dry-run
```

## Weekly summary

`weekly-digest.yml` posts a summary of the last 7 days of GitHub Actions scans every Monday at 09:00 IST: scans run, passed / blocked / errors, the latest result for the repo image on `main`, exception counts, and each blocked scan with its reason. Run it on demand with Actions → Weekly Vulnerability Summary → Run workflow (optionally a different number of days).

Manual scans of other images (for example `python:3.9-slim`) are counted and listed when blocked, but never become "Latest on main", which always describes the repo's own image. Jenkins builds are not included; they appear on the dashboard.

## Dashboard

Grafana at http://localhost:3000 → **Container Vulnerability Scanner**.

| Panel | Shows |
|---|---|
| Open vulnerabilities by severity | Currently open findings, per severity |
| Pending: fix available vs no fix yet | Which open findings can be fixed by updating |
| Pending vulnerabilities over time | Trend of open findings |
| Found vs resolved per day | New findings and fixed findings |
| Scan results in range | Passed / Blocked / Error |
| Latest status per image | Last result for each image and source |
| Data sources / Data age | Whether GitHub and Jenkins are reachable, and how fresh the data is |

Filters at the top: **Source** (GitHub, Jenkins), **Image**, **Severity**, plus the date range. The exporter fetches new scans every 5 minutes and Prometheus scrapes every minute, so a new scan shows up within about 6 minutes.

Pull-request scans count in the scan totals but not in the trends, so a deliberately vulnerable test PR doesn't distort them. Excepted findings remain "pending": they are still in the image.

## Demo: exceptions end to end

The demo policies in `tests/` gate on CRITICAL only and except the CRITICAL findings of `python:3.9-slim`:

| Policy file | Expected |
|---|---|
| `tests/demo-policy-exceptions-pass.yaml` | PASS: all 6 CRITICAL findings excepted |
| `tests/demo-policy-exceptions-expired.yaml` | FAIL: one exception expired, its CVE counts again |
| `tests/demo-policy-exceptions-broken.yaml` | ERROR (exit 2): one exception has no approver |

Run them with `SCAN_IMAGE=python:3.9-slim` on either CI system, or locally with `--policy`. The CVE IDs were taken from Trivy on 22 Oct 2026, and one demo exception expires on 27 Oct 2026; re-check both before a demo (see [maintenance.md](maintenance.md)).
