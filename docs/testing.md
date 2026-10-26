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

## Beta testing

### Tester #0: dry run by the author as an outside user (25–26 Oct 2026)

A separate free GitHub account forked the repository; everything was set up from the docs alone on a **fresh AWS EC2 instance** (free plan, `m7i-flex.large`, Ubuntu 24.04, Sydney), operated from a **Windows laptop without WSL**, with a **new Slack workspace**.

| Task | Result |
|---|---|
| `deploy.sh check` | No FAIL; the expected WARNs, each naming the command that fixes it |
| 1 Set up | 20 seconds; Pango and Trivy installed; 50 tests OK |
| 2 / 3 Scans | `python:3.9-slim` FAIL exit 1 (CRITICAL 6, HIGH 122); `python:3.13-alpine` PASS exit 0 |
| 4 Report | Generated on the VM, copied to the laptop, opened |
| 5 Exception | `[1 excepted]`, CRITICAL 6 → 5, still FAIL |
| 6 Broken exception | `CONFIG ERROR ... approved_by`, exit 2 |
| 7 Jenkins on EC2 | `DOCKER_GID` detected (988 on Docker Engine); repo image PASS, `python:3.9-slim` blocked; without a Slack credential the build still ends correctly |
| 8 GitHub Actions on the fork | FAIL as expected; Slack step skipped cleanly without the secret; the fork's daily rescan ran on its own |
| 9 Slack (new workspace) | Alerts from both systems: `Source: GitHub Actions run #3` and `Source: Jenkins build #3` |
| 10 Dashboard on EC2 | Exporter, GitHub and Jenkins OK on the first try; range panels needed the backfill (below) |

Same counts as on WSL, Jenkins and GitHub Actions: identical results on four platforms.

### Feedback log

| # | Source | Feedback | Decision |
|---|---|---|---|
| 1 | Author, CI test matrix | Jenkins and GitHub alerts look identical | Fixed in PR #27 (Source label) |
| 2 | Tester #0, issue #30 | Cloud VM guide doesn't cover Windows without WSL | Fixed in PR #36: PowerShell section (ssh, `icacls`, tunnel, `scp`) |
| 3 | Tester #0, issue #31 | No way described to open the report from a cloud VM | Fixed in PR #36: `scp` instructions in the beta guide and usage |
| 4 | Tester #0, issue #32 | Workflows in a fork must each be enabled | Fixed in PR #36: task 8 and troubleshooting |
| 5 | Tester #0, issue #33 | A ready-made exception example would help | Fixed in PR #36: copy-paste commands with today's date |
| 6 | Tester #0, issue #34 | `setup` output noisy on a cloud VM | Fixed in PR #36: apt output to a log file, shown only on failure; wording |
| 7 | Tester #0, issue #35 | Range panels empty on a new install until `backfill.sh` | Fixed in PR #36: setup step no longer "optional", `deploy.sh` reminds on first run, troubleshooting row |

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
