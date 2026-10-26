# Beta testing guide

Thank you for testing! This takes about **1–2 hours**. You set the scanner up on your own machine (WSL on Windows, Linux, or a cloud VM) using only the docs, try a few tasks, and report what was unclear or broken. **Everything you find is useful**, including "I wasn't sure what this step meant".

Never paste tokens, passwords or webhook URLs into an issue or screenshot.

## 1. Get your own copy

1. Fork this repository on GitHub (**Fork**, top right). Your copy is where your secrets and runs live.
2. On a cloud VM, first follow [setup.md → On a cloud VM](setup.md#on-a-cloud-vm-instead-of-wsl) (including connecting from Windows without WSL).
3. Clone your fork and check your machine:
   ```bash
   git clone https://github.com/<you>/<your-fork>.git vuln-scanner
   cd vuln-scanner
   ./deploy.sh check
   ```

## 2. Core tasks (no accounts needed)

| # | Task | How | You should see |
|---|---|---|---|
| 1 | Set up | `./deploy.sh setup` | Venv, Trivy, PDF libraries installed; `Ran 50 tests`, `OK` |
| 2 | Scan a vulnerable image | `source .venv/bin/activate` then `python src/scanner.py python:3.9-slim --output-dir reports; echo $?` | `RESULT: FAIL`, exit `1` |
| 3 | Scan a clean image | `python src/scanner.py python:3.13-alpine; echo $?` | `RESULT: PASS`, exit `0` |
| 4 | Read the report | `python src/report.py --input-dir reports --pdf` (uses the files from task 2), then open `reports/report.html`: on WSL `explorer.exe reports`; on a cloud VM copy the folder to your computer first (see [below](#viewing-the-report-from-a-cloud-vm)) | Find: how many CRITICAL findings, and the "Fixed in" version of one of them |
| 5 | Approve an exception | Pick **one** CRITICAL CVE from the report and run the commands [below](#task-5-commands) | `[1 excepted]` (or more) next to CRITICAL; still FAIL because of the others |
| 6 | Break it on purpose | `sed -i '/approved_by:/d' /tmp/my-policy.yaml` then `python src/scanner.py python:3.9-slim --policy /tmp/my-policy.yaml; echo $?` | `CONFIG ERROR ... missing required field(s) approved_by`, exit `2` |

### Task 5 commands

Copies the policy and adds one exception with today's date and a 30-day expiry (the maximum is 90 days):

```bash
read -r -p "CVE ID from the report (e.g. CVE-2026-13221): " CVE
read -r -p "Its package (e.g. perl-base): " PKG
cp policy.yaml /tmp/my-policy.yaml
sed -i 's/^exceptions: \[\]$/exceptions:/' /tmp/my-policy.yaml
cat >> /tmp/my-policy.yaml << EOF
  - id: $CVE
    package: $PKG
    reason: Beta test
    approved_by: Beta Tester
    approved_on: $(date +%F)
    expires: $(date -d '+30 days' +%F)
EOF
tail -8 /tmp/my-policy.yaml
python src/scanner.py python:3.9-slim --policy /tmp/my-policy.yaml; echo $?
```

### Viewing the report from a cloud VM

The VM has no browser: copy `reports/` to your computer with `scp`, from a terminal **on your computer** (not in the SSH session):

- Linux / macOS / WSL: `scp -i my-key.pem -r ubuntu@<vm-ip>:~/vuln-scanner/reports ./vm-reports`
- Windows PowerShell: see [setup.md → From a Windows laptop without WSL](setup.md#from-a-windows-laptop-without-wsl)

## 3. Optional tasks (more setup)

| # | Task | Docs | You should see |
|---|---|---|---|
| 7 | Jenkins | `./deploy.sh jenkins` + one-time steps in [setup.md §4](setup.md#4-jenkins); then **Build with Parameters** with `SCAN_IMAGE=python:3.9-slim` | Build red: "Blocked by policy" |
| 8 | GitHub Actions | On your fork: Actions tab → **I understand my workflows, go ahead and enable them**; then open **each** workflow and click **Enable workflow** (GitHub disables scheduled workflows in forks). Then **Run workflow** with image `python:3.9-slim` ([usage.md](usage.md#github-actions)) | Run red; `trivy-scan-report` artifact with the reports. From then on your fork also rescans daily |
| 9 | Slack | Create a free Slack workspace + incoming webhook; add it as the `SLACK_WEBHOOK_URL` secret on your fork ([setup.md §6](setup.md#6-github-secret-and-branch-ruleset)); repeat task 8 | Alert ending `Source: GitHub Actions run #N` |
| 10 | Dashboard | `./deploy.sh monitoring` ([setup.md §5](setup.md#5-monitoring-exporter-prometheus-grafana)), then **once** `bash monitoring/backfill.sh`; open Grafana (on a cloud VM through the SSH tunnel) | Your scans under Source / Image filters; "Scan results in selected range" counts the earlier scans too |

## 4. Report

For each problem or suggestion, open an issue on the **original** repository: **Issues → New issue → Beta feedback**. One issue per finding is easiest to track. If everything worked, one issue saying so (with your setup type and time taken) is just as valuable.

## 5. Clean up

```bash
./deploy.sh down          # stops containers; data is kept
```

On a cloud VM: **stop or terminate the instance** so it doesn't keep costing money. To remove everything locally: `docker compose -f monitoring/docker-compose.yml down -v` and `docker compose -f ci/jenkins/docker-compose.yml down -v` (deletes the data volumes).
