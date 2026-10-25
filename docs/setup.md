# Setup

This sets up the whole project on one machine: the scanner, a local Jenkins, and the monitoring stack (exporter, Prometheus, Grafana). GitHub Actions needs no installation, only the repository settings in [step 6](#6-github-secret-and-branch-ruleset).

Everything runs locally and is bound to `127.0.0.1`. **Local lab use only:** Jenkins mounts the Docker socket, which gives it full control of Docker on the machine.

## 1. Prerequisites

| Need | Notes |
|---|---|
| Ubuntu on WSL2, or Linux | Tested on Ubuntu (WSL2) on Windows |
| Docker Desktop | Settings → Resources → WSL Integration → enable your Ubuntu distro |
| Git, curl, Python 3.10+ with venv | `sudo apt install git curl python3 python3-venv python3-pip` |
| A Slack workspace | For alerts: an app with an incoming webhook to a channel such as `#vuln-alerts` |
| A GitHub account | Fork or clone of this repository; admin rights for secrets and rulesets |

Free ports needed: 8080 (Jenkins), 9090 (Prometheus), 3000 (Grafana).

## 2. Get the code and check prerequisites

```bash
git clone https://github.com/kamalvasvani1989-coder/Container_Vulnerabilty_Scanner.git vuln-scanner
cd vuln-scanner
./deploy.sh check
```

`check` changes nothing. Fix any `[FAIL]` line before continuing; `[WARN]` lines are things the next commands set up.

## 3. Python, Trivy and PDF libraries

```bash
./deploy.sh setup
```

Creates `.venv`, installs `requirements.txt`, installs Trivy 0.76.0 and the Pango libraries if missing (asks for your sudo password only then), and runs the unit tests.

## 4. Jenkins

```bash
./deploy.sh jenkins
```

The first run builds the Jenkins image (Jenkins LTS + Python, Pango, Docker CLI, Trivy 0.76.0), writes the Docker socket's group to `ci/jenkins/.env` as `DOCKER_GID`, starts Jenkins and waits until it answers.

**One-time Jenkins setup (manual):**

1. Open http://localhost:8080 and unlock Jenkins with the password from:
   `docker exec vuln-scanner-jenkins cat /var/jenkins_home/secrets/initialAdminPassword`
2. Install the suggested plugins and create your admin user. Note your **user ID** (the part after `/user/` in your profile URL); the monitoring stack needs it.
3. Optional: your user → Account → Time Zone (the container runs on UTC).
4. **Slack credential:** Manage Jenkins → Credentials → System → Global → Add Credentials → kind *Secret text*, ID `slack-webhook-url`, secret = the Slack webhook URL.
5. **Job:** New Item → name `vuln-scanner` → *Pipeline* →
   - Pipeline → Definition: *Pipeline script from SCM*, SCM: *Git*
   - Repository URL: your repository's HTTPS URL
   - Branch Specifier: `*/main`
   - Script Path: `Jenkinsfile`
6. Save, then click **Build Now** once. The first build registers the `SCAN_IMAGE` and `POLICY_FILE` parameters and the 5-minute polling schedule, which are defined in the `Jenkinsfile`. After that the menu shows **Build with Parameters**.
7. **API token for the exporter:** your user → Security → API Token → Add new token. Copy it for step 5.

## 5. Monitoring (exporter, Prometheus, Grafana)

Create a **GitHub fine-grained personal access token** first: Settings → Developer settings → Fine-grained tokens → this repository only → Repository permissions → *Actions: Read-only*. Choose an expiry and note it for [maintenance](maintenance.md).

```bash
./deploy.sh monitoring
```

It needs Jenkins running (it joins Jenkins' Docker network) and asks for four values at a hidden prompt, saved only in the git-ignored `monitoring/.env` (permissions 600):

| Value | What to enter |
|---|---|
| `GITHUB_TOKEN` | The fine-grained token above |
| `JENKINS_USER` | Your Jenkins **user ID** (not the display name) |
| `JENKINS_TOKEN` | The Jenkins API token from step 4.7 |
| `GRAFANA_ADMIN_PASSWORD` | A password for Grafana's `admin` user (used on Grafana's first start only) |

Values containing `$` or spaces are refused, because Docker Compose would misread them.

Open http://localhost:3000, log in as `admin`, and open **Dashboards → Vulnerability Scanner → Container Vulnerability Scanner**. The datasource and dashboard are provisioned from files in `monitoring/grafana/`; nothing is clicked together by hand.

Optional: load the scan history from before the stack existed (run once, with the stack up):

```bash
bash monitoring/backfill.sh
```

## 6. GitHub secret and branch ruleset

In the repository on GitHub:

1. **Secret:** Settings → Secrets and variables → Actions → New repository secret → name `SLACK_WEBHOOK_URL`, value = the webhook URL only (not a whole `curl` command).
2. **Branch ruleset:** Settings → Rules → Rulesets → New branch ruleset, target `main` (this project's ruleset is named `Vul_BR_Rule`):
   - Require a pull request before merging
   - Require status checks to pass → add the check **`scan`**
   - Block force pushes (recommended)

From then on nothing reaches `main` without a green `scan` check, and a direct push to `main` is rejected (`GH013`).

The workflows need no other setup: `scan.yml` runs on every push and PR to `main`, daily at 08:00 IST and on demand; `weekly-digest.yml` runs on Mondays at 09:00 IST and on demand.

## 7. Check everything

```bash
./deploy.sh status
```

Expected: the four containers `Up`, and Jenkins, Prometheus and Grafana responding. Then open a small PR to see the `scan` check run, or follow [usage.md](usage.md).

## Start, stop, re-run

| Command | Effect |
|---|---|
| `./deploy.sh status` | Containers and endpoints |
| `./deploy.sh down` | Stop both stacks; all data (jobs, history, dashboard) is kept in Docker volumes |
| `./deploy.sh jenkins` then `./deploy.sh monitoring` | Start again |
| `./deploy.sh all` | Run every step; safe on a machine that is already set up |

Re-running never restarts a container whose image hasn't changed, so it is safe even while a Jenkins build is running.
