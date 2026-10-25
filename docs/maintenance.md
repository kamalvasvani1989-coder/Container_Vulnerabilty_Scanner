# Maintenance

## Calendar

| When | Task |
|---|---|
| Every Monday | Read the weekly digest in Slack: blocked scans, errors, exceptions expiring within 7 days |
| When an exception nears expiry | Patch the image, or re-approve the exception with new dates through a PR (at most 90 days) |
| Before a demo with the demo policies | Refresh their CVE IDs and dates (below) |
| Before ~17 Jan 2027 | Renew the exporter's GitHub token and Jenkins API token (below) |
| When Trivy or an action has a new release | Bump the pinned version deliberately (below) |
| After 60 days without commits | Check that GitHub hasn't paused the scheduled rescan (Actions tab) |

## Renew the exporter's tokens

The dashboard stops receiving new scans when either token expires; the data sources panel then shows NOT REACHABLE.

1. **GitHub:** Settings → Developer settings → Fine-grained tokens → regenerate the exporter token (this repository only, Actions: Read-only).
2. **Jenkins:** your user → Security → API Token → add a new token, then revoke the old one.
3. Edit `monitoring/.env` and replace `GITHUB_TOKEN` and/or `JENKINS_TOKEN`. Keep the file's permissions at 600.
4. Recreate the exporter so it reads the new values:
   ```bash
   docker compose -f monitoring/docker-compose.yml up -d
   ```
5. Check: the dashboard's data sources panel shows OK within a few minutes.

## Rotate the Slack webhook

If the webhook is revoked or leaked: create a new incoming webhook for the Slack app, then update **both** the GitHub secret `SLACK_WEBHOOK_URL` and the Jenkins credential `slack-webhook-url`. Test by running **Weekly Vulnerability Summary** manually.

## Refresh the demo policies

`tests/demo-policy-exceptions-*.yaml` except the CRITICAL findings Trivy reported for `python:3.9-slim` on 22 Oct 2026. The Trivy database changes daily, and one demo exception expires on 27 Oct 2026.

1. List today's CRITICAL findings:
   ```bash
   trivy image --severity CRITICAL --format json --quiet python:3.9-slim | python3 -c 'import sys,json; [print(v["VulnerabilityID"], v["PkgName"]) for r in json.load(sys.stdin).get("Results",[]) for v in r.get("Vulnerabilities") or []]'
   ```
2. Update the IDs in the three files if they changed.
3. Move `approved_on` to a recent date and keep each `expires` within 90 days of it. Keep the deliberate differences: one exception expiring within 7 days (pass file), one expired (expired file), one without `approved_by` (broken file).
4. Change them through a PR like any other file.

## Version bumps

| Component | Where | Notes |
|---|---|---|
| Trivy | `.github/workflows/scan.yml`, `ci/jenkins/Dockerfile` (`TRIVY_VERSION`), `deploy.sh` (`TRIVY_VERSION`) | Change all three together, so both CI systems and local scans agree. Then `./deploy.sh jenkins` rebuilds the Jenkins image |
| Python packages | `requirements.txt`; PyYAML also in `monitoring/exporter.Dockerfile` | Check the new versions support Python 3.10+, run the tests, then `./deploy.sh monitoring` rebuilds the exporter |
| GitHub Actions | `uses:` lines in both workflows | Pin exact versions, and pick releases at least two weeks old |
| Prometheus, Grafana | `monitoring/docker-compose.yml` | Read the release notes first; data lives in volumes |
| Jenkins | `ci/jenkins/Dockerfile` (`jenkins/jenkins:lts-jdk21`) | `./deploy.sh jenkins` picks up a new LTS on rebuild |

Every bump goes through a PR, so the `scan` check (including the unit tests) runs before it reaches `main`.

## Backups

All state lives in Docker volumes, which `./deploy.sh down` and re-runs never delete:

| Volume | Holds |
|---|---|
| `jenkins_jenkins_home` | Jenkins jobs, credentials, build history, Trivy cache |
| `vuln-monitoring_prometheus_data` | Metric history (90 days) |
| `vuln-monitoring_grafana_data` | Grafana users and settings (dashboards come from Git) |
| `vuln-monitoring_exporter_data` | Which scans the exporter has already counted |

Back up a volume to the current folder (example for Jenkins):

```bash
docker run --rm -v jenkins_jenkins_home:/data -v "$PWD":/backup alpine tar czf /backup/jenkins_home.tgz -C /data .
```

GitHub Actions history and reports live on GitHub (artifacts kept about 90 days); the source of truth for code and policy is the Git repository.
