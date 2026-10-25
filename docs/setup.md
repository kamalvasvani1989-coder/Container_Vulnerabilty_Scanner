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

Work in **your own copy** of the repository, because GitHub secrets, the branch ruleset, Actions runs and the dashboard's token all belong to a repository:

- **Fork** it on GitHub (Fork button), or
- if you already own the original, create an empty repository and push a copy:
  `git clone --bare <original-url> tmp.git && cd tmp.git && git push --mirror <your-new-repo-url> && cd .. && rm -rf tmp.git`

Then clone your copy:

```bash
git clone https://github.com/<you>/<your-repo>.git vuln-scanner
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

It needs Jenkins running (it joins Jenkins' Docker network) and asks for five values (secrets at a hidden prompt), saved only in the git-ignored `monitoring/.env` (permissions 600):

| Value | What to enter |
|---|---|
| `GITHUB_REPOSITORY` | Your repository as `owner/repo`; press Enter to accept the value read from your clone |
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

## On a cloud VM instead of WSL

For example on AWS EC2 with Ubuntu 24.04 LTS. The differences from WSL:

| Topic | What to do |
|---|---|
| Size | 2 vCPU, 4–8 GB RAM, 30 GB disk: e.g. `t3.medium`. On an AWS **free plan** account (created on or after 15 Jul 2025) use a free-plan-eligible type instead: `m7i-flex.large` (8 GB, recommended) or `c7i-flex.large` (4 GB); usage is paid from the account's credits |
| Network | Allow inbound **SSH (22) from your IP only**. Do not open 8080, 3000 or 9090: the services listen on `127.0.0.1` |
| Docker | Docker Engine instead of Docker Desktop: `curl -fsSL https://get.docker.com \| sudo sh`, then `sudo usermod -aG docker "$USER"` and log out and back in |
| Packages | `sudo apt update && sudo apt install -y git curl python3 python3-venv python3-pip` |
| Web UIs | Reach them through an SSH tunnel, then open `http://localhost:8080` / `:3000` / `:9090` in your own browser: `ssh -i key.pem -L 8080:localhost:8080 -L 3000:localhost:3000 -L 9090:localhost:9090 ubuntu@<vm-ip>` |
| Cost | About $0.045/hour for `t3.medium` in Mumbai (more in some regions). **Stop or terminate the VM when you are done** ([cost.md](cost.md)) |

Everything else (`deploy.sh`, the one-time steps) is the same.

## Start, stop, re-run

| Command | Effect |
|---|---|
| `./deploy.sh status` | Containers and endpoints |
| `./deploy.sh down` | Stop both stacks; all data (jobs, history, dashboard) is kept in Docker volumes |
| `./deploy.sh jenkins` then `./deploy.sh monitoring` | Start again |
| `./deploy.sh all` | Run every step; safe on a machine that is already set up |

Re-running never restarts a container whose image hasn't changed, so it is safe even while a Jenkins build is running.
