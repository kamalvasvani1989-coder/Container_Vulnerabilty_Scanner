# Troubleshooting and known limitations

## Setup (`deploy.sh`, WSL)

| Symptom | Fix |
|---|---|
| `./deploy.sh check` shows `[FAIL] Docker is installed but not running` | Start Docker Desktop. In WSL also enable Settings → Resources → WSL Integration → your distro |
| `docker: command not found` in WSL | Same WSL Integration setting as above |
| `[FAIL] Port 8080 is used by something else` | Another program holds the port. Stop it, or check with `ss -ltnp \| grep 8080` |
| `ensurepip is not available` | `sudo apt install python3-venv python3-pip`, delete `.venv`, run `./deploy.sh setup` again |
| `externally-managed-environment` from pip | The venv isn't active: `source .venv/bin/activate` (never use `--break-system-packages`) |
| `$'\r': command not found` when running a script | Windows line endings from a copied file: `sed -i 's/\r$//' <file>` |
| `./deploy.sh monitoring`: `Jenkins' network (jenkins_default) not found` | Start Jenkins first: `./deploy.sh jenkins` |
| `... must not contain $ or spaces` at a prompt | Docker Compose would misread the value; choose one without `$` or spaces |
| A pasted multi-line `sudo` block does nothing | The password prompt swallowed the lines: run `sudo -v` first, then paste one line at a time |

## Scanner and policy

| Symptom | Cause | Fix |
|---|---|---|
| `CONFIG ERROR: Exception #N (...): missing required field(s) ...` (exit 2) | An exception lacks `id`, `reason`, `approved_by`, `approved_on` or `expires` | Add the field |
| `unknown field(s) expiry` | Typo in a field name | Use the exact names from [configuration.md](configuration.md) |
| `lasts N days; the maximum is 90` | Expiry too far after approval | Shorten it; re-approve when it runs out |
| `approved_on ... is in the future` | Wrong date | Use today's date or earlier |
| Exception "matched nothing (patched? remove it)" | The CVE is no longer in the image, or `package`/`image` doesn't match | Remove it if patched; otherwise check the scope (`image` with a tag must match exactly) |
| A build fails although an exception "worked" before | The exception expired | Patch, or re-approve with new dates through a PR |
| `WARNING: Trivy attempt 1 of 3 failed: ... TOOMANYREQUESTS` | Trivy's database download was rate-limited | Usually recovers on the next attempt; if all 3 fail, re-run later |
| `Trivy is not installed or not on PATH` | Trivy missing | `./deploy.sh setup` installs 0.76.0 |
| `Policy file not found` / `not valid YAML` | Wrong path or broken YAML | Fix the file; this is always exit 2, never a pass |

## GitHub Actions

| Symptom | Fix |
|---|---|
| "Send Slack alert" shows ⊘ | Normal: skipped because the scan passed |
| `scan_image contains characters not allowed` / `policy_file must be a file in this repository` | The Run workflow inputs were rejected before use. Use an image name like `python:3.9-slim` and a repository path like `tests/demo-policy-exceptions-pass.yaml` |
| No **Run workflow** button | Open the workflow in the Actions tab; the button is at the top right of its run list. The workflow file must be on `main` |
| Scheduled run started hours late | GitHub delays scheduled runs when runners are busy; nothing to fix |
| Scheduled runs stopped | GitHub pauses schedules after 60 days without repository activity: re-enable the workflow in the Actions tab |
| `git push` to `main` rejected (`GH013`) | Expected: the branch ruleset requires a PR |
| A unit test passes locally but fails only on GitHub | Look for code that reads `GITHUB_*` variables, which the runner always sets. Tests must clear them (see `tests/test_exception_tracking.py`) |

## Jenkins

| Symptom | Cause | Fix |
|---|---|---|
| No builds after merges; Git Polling Log says "No changes" on another branch | Branch Specifier points at an old branch | Configure → Pipeline → Branch Specifier `*/main` → Save |
| Still polling the old branch after saving | Pipeline jobs poll with the settings of the last **completed** build | Run one build manually; polling then follows the new branch |
| No automatic build after a merge you already built by hand | Polling only builds commits Jenkins hasn't built yet | Nothing to fix |
| **Build with Parameters** missing | The job hasn't run yet; parameters come from the `Jenkinsfile` | Click **Build Now** once |
| `permission denied ... docker.sock` | The Jenkins user isn't in the Docker socket's group | `ci/jenkins/.env` must hold the right `DOCKER_GID`; delete the file and run `./deploy.sh jenkins` to detect it again |
| Times shown in UTC | The container runs on UTC | Your user → Account → Time Zone |
| HTML report in Jenkins looks unstyled | Jenkins' Content Security Policy (left at its secure default) | Open `report.pdf`, or download the HTML |

## Slack

| Symptom | Fix |
|---|---|
| No alert for a passing scan | By design: alerts are sent for FAIL and ERROR only |
| Two identical-looking alerts | One per CI system; the footer says `Source: Jenkins build #N` or `Source: GitHub Actions run #N` |
| `Slack rejected the message (404): no_service` | The webhook was revoked: create a new one and update the GitHub secret and the Jenkins credential |
| `SLACK_WEBHOOK_URL is not set` notice, no alert | Secret missing. Also expected for PRs from forks, which GitHub runs without secrets |
| Testing the webhook without breaking a build | Run **Weekly Vulnerability Summary** manually: it always posts |

## Monitoring

| Symptom | Fix |
|---|---|
| Exporter log: Jenkins 401 | `JENKINS_USER` must be the Jenkins user **ID**, not the display name |
| A changed `monitoring/.env` value isn't used | `docker compose -f monitoring/docker-compose.yml up -d` recreates the exporter |
| Dashboard "Data sources: NOT REACHABLE" | Start the source (`./deploy.sh jenkins`), then `docker restart vuln-scanner-exporter` for an immediate fetch |
| A new scan isn't on the dashboard yet | Wait up to ~6 minutes (exporter every 5 min, Prometheus every minute) |
| Check whether Prometheus scrapes the exporter | `curl -s -G http://localhost:9090/api/v1/query --data-urlencode 'query=up{job="vuln-exporter"}'` → value `"1"` |

## Known limitations

None of these is an open bug: each was reviewed and accepted, or has a workaround.

| Area | Limitation | Note |
|---|---|---|
| Exceptions | Identified by CVE ID (plus optional package and image) | A new finding with the same ID in the same package is also waived; scope with `package` and `image` where it matters |
| Exceptions | Demo policies hold CVE IDs from 22 Oct 2026 and fixed dates | Refresh before a demo ([maintenance.md](maintenance.md)) |
| Scanner | Every Trivy failure is retried, including permanent ones (e.g. a mistyped image) | A real error is reported about a minute later; telling temporary from permanent errors by Trivy's message is unreliable |
| Scanner | UNKNOWN severity is shown but not gated | Trivy has no rating for these yet |
| Reports | In the PDF, the exception column of the findings table is cut off when exceptions exist | The full dates are in the exceptions table above it |
| CI | Local Jenkins can't receive GitHub webhooks | Polls `main` every 5 minutes |
| CI | Scheduled GitHub runs can start late | GitHub's scheduling |
| CI | `ubuntu-latest` is moving to Ubuntu 26 (GitHub notice) | Runs pass on it; the notice is informational |
| Digest | Covers GitHub Actions scans only | Jenkins scans are on the dashboard |
| Dashboard | "Data age" measures the last fetch attempt, not the last success | The NOT REACHABLE tile still flags a failing source |
| Dashboard | "Found vs resolved per day" bars straddle two days | Grafana bar alignment |
| Dashboard | History only reaches as far back as the artifacts | GitHub ~90 days, Jenkins last 30 builds |
| Dashboard | Excepted CVEs still count as pending | Deliberate: they are still in the image |
| Tests | On Python 3.14, two `ResourceWarning` lines from the Slack retry tests | Harmless (Python closes the objects itself); not shown on Python 3.11/3.13 |
| Security | Tokens are visible via `docker inspect` to anyone with Docker access on the machine | Acceptable for a local lab; Jenkins with the Docker socket already has that level of access |
