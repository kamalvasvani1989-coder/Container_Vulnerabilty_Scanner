# Configuration

## `policy.yaml`

One file controls the gate, the alerts and the exceptions. Change it through a pull request: the `main` branch is protected, so the Git history records who changed what and why.

### Thresholds

```yaml
thresholds:
  CRITICAL: 0
  HIGH: 10
```

- A severity fails when its count **exceeds** the limit: `HIGH: 10` allows 10 and blocks 11.
- Only listed severities are gated. MEDIUM, LOW and UNKNOWN are reported but never block unless you add them.
- Use Trivy's severity names: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN` (case does not matter). Limits must be whole numbers (`yes`/`true` is rejected).
- A missing or invalid policy is a configuration error (exit 2), never a pass.

### Alerts

```yaml
alerts:
  mention_channel_on: [CRITICAL]
```

Severities whose alerts mention `@channel`. Allowed: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`, and `ERROR` (to also `@channel` tool errors). If the section is missing or invalid, the default `[CRITICAL]` is used with a warning; the alert itself is always sent.

### Exceptions (approved known vulnerabilities)

Use an exception instead of raising a threshold: a raised threshold lets **every** new finding of that severity through, an exception covers one named CVE for a limited time.

```yaml
exceptions:
  - id: CVE-2026-12345
    package: openssl              # optional: only this package (default: any)
    image: vuln-scanner-test      # optional: only this image; without a tag = any tag
    reason: No upstream fix yet; the affected function is not used
    approved_by: Kamal Vasvani
    approved_on: 2026-10-22
    expires: 2026-12-31           # at most 90 days after approved_on
```

| Field | Required | Rule |
|---|---|---|
| `id` | yes | The CVE (or advisory) ID as Trivy reports it |
| `reason` | yes | Why it is acceptable for now |
| `approved_by` | yes | A named person |
| `approved_on` | yes | `YYYY-MM-DD`, not in the future |
| `expires` | yes | `YYYY-MM-DD`, at most 90 days after `approved_on` |
| `package` | no | Limit to one package; without it the exception covers the CVE in every package (e.g. the 3 OpenSSL packages) |
| `image` | no | With a tag (`python:3.9-slim`): that exact image. Without a tag (`vuln-scanner-test`): any tag |

How it behaves:

- **Active:** the finding is still listed in reports but not counted against the limits.
- **Expires within 7 days:** still active; flagged in the console, report and weekly digest.
- **Expired:** no longer applied; the CVE counts again and can block the build.
- **Matched nothing:** the CVE is no longer in the image (probably patched); the report says "Not found: remove?".
- **Fix available:** the console and report say when an excepted CVE now has a fixed version: patch instead of renewing.
- **Any mistake** (missing field, bad date, unknown field such as `expiry`, more than 90 days) stops the scan as a configuration error (exit 2) naming the exception. A broken exception can never turn into a pass.

Slack alerts and the digest show exception **counts** only, never CVE IDs.

## CI inputs

| System | Input | Default |
|---|---|---|
| GitHub Actions (Run workflow) | `scan_image`, `policy_file` | empty (repo image), `policy.yaml` |
| Jenkins (Build with Parameters) | `SCAN_IMAGE`, `POLICY_FILE` | empty (repo image), `policy.yaml` |

Push, PR and scheduled runs always use the defaults.

## Secrets

Secret values are never committed or printed. Names and locations:

| Where | Name | Used by | Notes |
|---|---|---|---|
| GitHub → Settings → Secrets → Actions | `SLACK_WEBHOOK_URL` | `scan.yml`, `weekly-digest.yml` | Slack incoming webhook URL |
| Jenkins → Credentials (Secret text) | `slack-webhook-url` | `Jenkinsfile` | Same webhook URL |
| `monitoring/.env` (git-ignored, 600) | `GITHUB_REPOSITORY` | exporter | `owner/repo` whose scan history the dashboard shows; not a secret |
| `monitoring/.env` | `GITHUB_TOKEN` | exporter | Fine-grained token: this repo only, Actions read-only. Has an expiry |
| `monitoring/.env` | `JENKINS_USER`, `JENKINS_TOKEN` | exporter | Jenkins user **ID** and API token. Has an expiry if you set one |
| `monitoring/.env` | `GRAFANA_ADMIN_PASSWORD` | Grafana | Applied on Grafana's first start only |
| `ci/jenkins/.env` (git-ignored) | `DOCKER_GID` | Jenkins | Group of the Docker socket; not a secret, machine-specific |

`monitoring/.env.example` lists the variables with comments. `./deploy.sh monitoring` fills in missing values at a hidden prompt; edit the file directly to change one.

The digest uses the workflow's own `GITHUB_TOKEN` with `actions: read` and `contents: read` only; no personal token is needed there.

## Versions

| Component | Version | Where it is pinned |
|---|---|---|
| Trivy | 0.76.0 | `scan.yml`, `ci/jenkins/Dockerfile`, `deploy.sh` (change all three together) |
| Python packages | PyYAML 6.0.3, Jinja2 3.1.6, WeasyPrint 70.0 | `requirements.txt`, `monitoring/exporter.Dockerfile` (PyYAML) |
| GitHub Actions | checkout 7.0.1, setup-python 7.0.0, cache 6.1.0, upload-artifact 7.0.1 | the two workflow files |
| Prometheus / Grafana | 3.5.0 / 12.1.0 | `monitoring/docker-compose.yml` |
| Image under test | `python:3.13-alpine` | `sample-app/Dockerfile` |
