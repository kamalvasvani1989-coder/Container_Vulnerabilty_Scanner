# Cost

## Current running cost: $0

| Component | Choice | Cost | Why it's free |
|---|---|---|---|
| Scanner | Trivy (open source) | $0 | No licence |
| CI | GitHub Actions on a **public** repository | $0 | Standard runners are free and unmetered for public repositories |
| CI | Jenkins in local Docker | $0 | Runs on an existing machine |
| Vulnerability database | Trivy DB, cached between runs | $0 | Fewer downloads, faster runs |
| Reports | Generated in CI, kept as artifacts | $0 | No storage service; artifacts expire on their own |
| Alerts | Slack free plan + incoming webhook | $0 | No bot or API tier needed |
| Weekly summary | Reads existing artifacts | $0 | No database |
| Dashboard | Exporter + Prometheus + Grafana in local Docker | $0 | Open source; Prometheus data is a few MB |
| Exceptions | A section in `policy.yaml` | $0 | Git is the approval record; no extra service |

## Choices made to keep it that way

1. **One scan per build.** The verdict, reports, alerts, digest and dashboard all read the same two JSON files, instead of re-scanning.
2. **Trivy database cache** in CI.
3. **Minimal base image** (`python:3.13-alpine`): 4 HIGH instead of 122 for `python:3.9-slim`, so fewer blocked builds and less remediation work.
4. **Alerts only on FAIL/ERROR:** passing scans and passing daily rescans are silent.
5. **Webhooks**, not a full Slack API integration.
6. **No database:** CI artifacts double as scan history for the digest and the dashboard.
7. **Pull-model exporter** instead of a Pushgateway or a hosted metrics service.
8. **Local Jenkins and monitoring** instead of always-on cloud servers.
9. **Rescans on GitHub only** (daily); Jenkins scans on demand, so the same image isn't scanned twice a day.
10. **Short, bounded retries** instead of failing and re-running whole pipelines.
11. **Unit tests run first**, so a broken change fails in seconds, before the image build and the scan.

## What production would cost

Prices checked on 25 Oct 2026, AWS Mumbai (ap-south-1), Linux on-demand, USD. They change; confirm with the AWS Pricing Calculator before relying on them.

**If the repository were private,** GitHub Actions would bill minutes beyond the plan's allowance. A scan run takes about 1 minute:

| Usage per month | Minutes | Cost |
|---|---|---|
| Daily rescans (30) + ~100 PR/push runs + 4 digests | ~135 | $0 (GitHub Free includes 2,000 Linux minutes for private repositories) |
| Beyond the allowance | per minute | $0.006 (standard 2-core Linux runner) |

**If Jenkins and monitoring moved to the cloud** (one VM for Jenkins, Prometheus, Grafana and the exporter):

| Item | Assumption | Approx. per month |
|---|---|---|
| EC2 `t3.medium` (2 vCPU, 4 GB) | always on, 730 h × $0.0448 | ~$32.70 |
| EBS gp3 disk | 30 GB × ~$0.09/GB (Mumbai) | ~$2.70 |
| **Total, always on** | | **~$35** |
| **Total, working hours only** | 10 h × 22 days = 220 h | **~$12.60** |

Small costs not counted: data transfer out, snapshots for backup, and a static IP if kept while the VM is stopped.

### How to keep production cost low

- **Stop the VM outside working hours** (scheduled start/stop): about two thirds cheaper, as above.
- **Smallest instance that fits.** 4 GB is comfortable for Jenkins plus the monitoring stack; measure before sizing up.
- **Use GitHub Actions instead of a separate CI server** if only one CI system is needed: then the VM only runs the monitoring stack.
- **A hosted Grafana free tier** instead of self-hosting Grafana (check its current limits).
- **Keep retention short:** 90 days of metrics and artifacts matches the 90-day exception limit.
- **Public repository or self-hosted runner** for the scans, where the organisation allows it.

### Sources

Looked up on 25 Oct 2026 from price trackers that republish the providers' list prices; confirm on the official pages before relying on them.

- GitHub Actions: Linux 2-core $0.006/min since 1 Jan 2026; GitHub Free includes 2,000 minutes/month for private repositories; standard runners are free for public repositories (GitHub Docs, "GitHub Actions billing").
- EC2 `t3.medium` in ap-south-1: $0.0448/hour on-demand (AWS EC2 On-Demand pricing).
- EBS gp3: $0.08/GB-month in us-east-1; Mumbai is slightly higher, about $0.09 (AWS EBS pricing).
