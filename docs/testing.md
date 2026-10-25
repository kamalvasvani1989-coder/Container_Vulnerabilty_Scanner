# Testing

## Unit tests

```bash
python -m unittest discover -s tests
```

**50 tests**, about 3 seconds, standard library only: no Docker, network or real Trivy (a fake `trivy` script and a fake Slack server are used). Both pipelines run them before building or scanning, so a failing test stops the pipeline early.

| File | Tests | What it proves |
|---|---|---|
| `tests/test_exceptions.py` | 23 | Exception validation (missing approver or expiry, typo'd field, bad date, more than 90 days, future approval), matching (package and image scope, tag rules, expiry day still applies, unused exceptions reported), and end-to-end exit codes (FAIL turns PASS with an exception, an expired one blocks again, a malformed one is exit 2) |
| `tests/test_exception_tracking.py` | 14 | Report shows the exceptions table and markers; old summaries still render; the digest's exception line has counts but no CVE IDs; "Latest on main" ignores manual scans of other images; Slack alerts show "N excepted" only when relevant; the alert footer names its source (GitHub Actions run, Jenkins build, or none for a manual run) |
| `tests/test_retry.py` | 13 | Trivy succeeds first time, recovers from temporary failures, gives up after 3 attempts, timeouts are retried, a missing Trivy is not; a broken Trivy is ERROR, never PASS; Slack retries 5xx and 429 (honouring `Retry-After`), does not retry 404, and never prints the webhook URL |

The tests are independent of the CI environment: they clear the variables GitHub (`GITHUB_*`) and Jenkins (`BUILD_NUMBER`, `JENKINS_HOME`, `JENKINS_URL`) set, and were checked with no, GitHub-like and Jenkins-like variables.

## Cross-CI test matrix (Sprint 6, 25 Oct 2026)

The same five cases on both CI systems, with identical inputs: Jenkins **Build with Parameters** and the GitHub **Run workflow** inputs.

| # | Image | Policy file | Expected | Jenkins | GitHub Actions |
|---|---|---|---|---|---|
| 1 | repo image | `policy.yaml` | PASS | #13 PASS | #71 PASS |
| 2 | `python:3.9-slim` | `policy.yaml` | FAIL | #14 FAIL | #72 FAIL |
| 3 | `python:3.9-slim` | `tests/demo-policy-exceptions-pass.yaml` | PASS | #15 PASS | #74 PASS |
| 4 | `python:3.9-slim` | `tests/demo-policy-exceptions-expired.yaml` | FAIL | #16 FAIL | #75 FAIL |
| 5 | `python:3.9-slim` | `tests/demo-policy-exceptions-broken.yaml` | ERROR | #17 ERROR | #76 ERROR |

**Result: 10 of 10 runs as expected, and each case produced identical output on both systems.**

| Case | Output on both systems |
|---|---|
| 1 | HIGH 4, MEDIUM 2, LOW 1 → PASS, exit 0, no alert |
| 2 | CRITICAL 6/0, HIGH 122/10 → FAIL, exit 1, `@channel` alert |
| 3 | `CRITICAL 6 (gated) [6 excepted]` → PASS; one exception "expires in 2 days", one "matched nothing (patched? remove it)"; no alert |
| 4 | `CVE-2026-8376 ... EXPIRED on 2026-09-01, no longer applied` → CRITICAL 1/0 → FAIL; alert "5 excepted (approved), not counted" |
| 5 | `CONFIG ERROR: Exception #4 (CVE-2026-8376): missing required field(s) approved_by.` → exit 2; report still written; ⚠️ "Scan did not complete" alert without `@channel` |

Before the matrix, the demo policies' CVE IDs were re-checked against Trivy's current data (same four IDs; one package renamed to `libssl3t64`, which the CVE-only exception still covers).

### Problems the testing found (and fixed)

| Found | Cause | Fix |
|---|---|---|
| Unit tests failed on the GitHub runner only (PR #26, first run) | The Slack-alert tests didn't expect the Branch/Commit footer that appears when `GITHUB_*` variables are set | Tests clear those variables; a new test covers the footer (PR #26) |
| Alerts from Jenkins and GitHub were identical, so you couldn't tell which system to open | Jenkins passes its branch and commit in GitHub's format | Footer now starts with `Source: Jenkins build #N` or `Source: GitHub Actions run #N` (PR #27); verified with Jenkins #18 and GitHub #79 |

## Other Sprint 6 checks

| Change | How it was tested |
|---|---|
| Line endings, pinned requirements, Node 24 actions (PR #23) | Content-only diff empty apart from `.gitattributes`; `pip install -r` changed nothing; PR check green without the Node 20 warning; Jenkins #10 installs from `requirements.txt`; weekly digest run green |
| Folder structure (PR #24) | 42/42 tests; local build from `sample-app/`, scan PASS, HTML + PDF; exporter rebuilt and scraped (`up=1`); PR check green; Jenkins #11; weekly digest from `src/` |
| `deploy.sh` (PR #25) | `shellcheck` clean; sandbox tests with Docker stubbed out (ports, prompts, `.env` permissions, rejected values, idempotence); real runs of `check`, `setup`, `jenkins`, `monitoring`, `status`; re-runs leave containers running |

## Earlier sprints

- **Sprint 2:** direct push to `main` rejected; vulnerable PR blocked from merging; Jenkins repo image PASS and `python:3.9-slim` blocked; the tool-error path proved by a real misconfiguration.
- **Sprint 3:** HTML, PDF and JSON reports for PASS and FAIL; Slack alerts locally and from CI; severity-based `@channel`; weekly digest.
- **Sprint 4:** exporter counting logic, `/metrics` output, backfill against real Prometheus and promtool; 5-check dashboard usability test (filters, date ranges, a source going down and coming back).
- **Sprint 5:** 42 unit tests; live Jenkins exception tests A/B/C; retry behaviour under GitHub's real `bash -e`.
