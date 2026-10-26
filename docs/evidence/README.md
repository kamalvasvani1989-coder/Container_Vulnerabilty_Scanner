# Evidence

Screenshots from all six sprints, grouped by what they prove. Full details: [testing.md](../testing.md), [usage.md](../usage.md).

## Scanner and policy gate

**01.** Sprint 1: first local scan of `python:3.9-slim`, policy FAIL, exit code 1

![Sprint 1: first local scan of python:3.9-slim, policy FAIL, exit code 1](01-scanner-first-scan-fail-exit1.png)

**02.** Sprint 1: base image comparison; `python:3.13-alpine` chosen for the image under test

![Sprint 1: base image comparison; python:3.13-alpine chosen for the image under test](02-base-image-comparison.png)

**26.** `policy.yaml`: thresholds, Slack mentions, exceptions

![policy.yaml: thresholds, Slack mentions, exceptions](26-policy-yaml.png)

## CI/CD gate: GitHub Actions and Jenkins

**03.** Sprint 2: direct push to `main` rejected by the branch ruleset (GH013)

![Sprint 2: direct push to main rejected by the branch ruleset (GH013)](03-direct-push-to-main-rejected.png)

**04.** Sprint 2: PR with a vulnerable image; the required `scan` check failed, merge blocked

![Sprint 2: PR with a vulnerable image; the required scan check failed, merge blocked](04-pr-blocked-by-required-scan-check.png)

**05.** Sprint 2: same PR after switching to the alpine base image; all checks passed

![Sprint 2: same PR after switching to the alpine base image; all checks passed](05-pr-checks-passed-after-fix.png)

**06.** Branch ruleset `Vul_BR_Rule`: active, no bypass, targets `main`

![Branch ruleset Vul_BR_Rule: active, no bypass, targets main](06-ruleset-active-target-main.png)

**07.** Ruleset rules: restrict deletions, require a PR, required status check `scan`, block force pushes

![Ruleset rules: restrict deletions, require a PR, required status check scan, block force pushes](07-ruleset-rules-required-check-scan.png)

**08.** Sprint 2: Jenkins build PASS with archived reports

![Sprint 2: Jenkins build PASS with archived reports](08-jenkins-pass-artifacts.png)

**09.** Sprint 2: Jenkins build of `python:3.9-slim` blocked by policy

![Sprint 2: Jenkins build of python:3.9-slim blocked by policy](09-jenkins-python3.9-slim-blocked.png)

**10.** Jenkins **Build with Parameters** (`SCAN_IMAGE`, `POLICY_FILE`)

![Jenkins Build with Parameters (SCAN_IMAGE, POLICY_FILE)](10-jenkins-build-with-parameters.png)

**11.** GitHub **Run workflow** with the same two inputs (Sprint 6 CI parity)

![GitHub Run workflow with the same two inputs (Sprint 6 CI parity)](11-github-run-workflow-inputs.png)

**20.** Sprint 5: on-demand rescan from the Actions tab

![Sprint 5: on-demand rescan from the Actions tab](20-on-demand-rescan.png)

**27.** GitHub Actions secrets: names only (`SLACK_WEBHOOK_URL`)

![GitHub Actions secrets: names only (SLACK_WEBHOOK_URL)](27-secrets-names-only.png)

## Reports and notifications

**12.** Sprint 3: HTML report of a failed scan

![Sprint 3: HTML report of a failed scan](12-html-report-fail.png)

**13.** Sprint 3: PDF report

![Sprint 3: PDF report](13-pdf-report.png)

**14.** Sprint 3: blocked PR and its Slack alert

![Sprint 3: blocked PR and its Slack alert](14-slack-alert-blocked-pr.png)

**15.** Sprint 6: alerts from both CI systems, told apart by the `Source:` footer

![Sprint 6: alerts from both CI systems, told apart by the Source: footer](15-slack-alerts-with-source-label.png)

**16.** Sprint 3: weekly vulnerability summary in Slack

![Sprint 3: weekly vulnerability summary in Slack](16-weekly-summary-in-slack.png)

## Dashboard

**17.** Sprint 4: Grafana dashboard, all data sources OK

![Sprint 4: Grafana dashboard, all data sources OK](17-dashboard.png)

**18.** Sprint 4 usability test: filters by source, image and severity

![Sprint 4 usability test: filters by source, image and severity](18-dashboard-filters.png)

**19.** Sprint 4 usability test: Jenkins stopped, dashboard shows NOT REACHABLE

![Sprint 4 usability test: Jenkins stopped, dashboard shows NOT REACHABLE](19-dashboard-source-not-reachable.png)

## Approved exceptions

**21.** Sprint 5 test A: approved exceptions turn the vulnerable image into a PASS

![Sprint 5 test A: approved exceptions turn the vulnerable image into a PASS](21-exception-pass-jenkins.png)

**22.** Sprint 5 test B: an expired exception is no longer applied, the build is blocked

![Sprint 5 test B: an expired exception is no longer applied, the build is blocked](22-expired-exception-console.png)

**23.** Sprint 5 test B: PDF report, expired exception in red, active ones greyed out

![Sprint 5 test B: PDF report, expired exception in red, active ones greyed out](23-expired-exception-pdf.png)

**24.** Sprint 5 test C: exception without an approver is a configuration error (exit 2), never a pass

![Sprint 5 test C: exception without an approver is a configuration error (exit 2), never a pass](24-broken-exception-config-error.png)

**25.** Sprint 5 test C: Slack "Scan did not complete" tool-error alert

![Sprint 5 test C: Slack "Scan did not complete" tool-error alert](25-tool-error-slack-alert.png)

## Testing on both CI systems

**28.** Sprint 6 test matrix on Jenkins: PASS, policy FAIL and ERROR builds in the stage view

![Sprint 6 test matrix on Jenkins: PASS, policy FAIL and ERROR builds in the stage view](28-jenkins-stage-view-test-matrix.png)

**29.** Sprint 6 matrix case 3 on Jenkins: 6 CRITICAL findings excepted, PASS

![Sprint 6 matrix case 3 on Jenkins: 6 CRITICAL findings excepted, PASS](29-matrix-case3-exceptions-jenkins.png)

**30.** Sprint 6 matrix case 3 on GitHub Actions: identical output

![Sprint 6 matrix case 3 on GitHub Actions: identical output](30-matrix-case3-exceptions-github.png)

**31.** Sprint 6 matrix case 2: blocked alerts from both systems with identical counts

![Sprint 6 matrix case 2: blocked alerts from both systems with identical counts](31-matrix-both-systems-slack.png)

**32.** Unit tests running in GitHub Actions before the scan

![Unit tests running in GitHub Actions before the scan](32-unit-tests-in-github-actions.png)

**33.** Unit tests running in Jenkins before the scan (50 tests)

![Unit tests running in Jenkins before the scan (50 tests)](33-unit-tests-in-jenkins.png)

## Beta testing and feedback

**34.** Beta test: fresh AWS EC2 instance (free plan, Sydney)

![Beta test: fresh AWS EC2 instance (free plan, Sydney)](34-beta-ec2-instance.png)

**35.** Beta test: report generated on EC2, opened on a Windows laptop

![Beta test: report generated on EC2, opened on a Windows laptop](35-beta-report-on-windows-laptop.png)

**36.** Beta test: GitHub Actions on the tester's fork; Slack step skipped cleanly without the secret

![Beta test: GitHub Actions on the tester's fork; Slack step skipped cleanly without the secret](36-beta-fork-github-actions.png)

**37.** Beta test: Jenkins on EC2 set up through an SSH tunnel

![Beta test: Jenkins on EC2 set up through an SSH tunnel](37-beta-jenkins-on-ec2.png)

**38.** Beta test: Grafana dashboard on EC2, all data sources OK

![Beta test: Grafana dashboard on EC2, all data sources OK](38-beta-dashboard-on-ec2.png)

**39.** Beta test: alerts in a brand-new Slack workspace from GitHub run #3 and Jenkins build #3

![Beta test: alerts in a brand-new Slack workspace from GitHub run #3 and Jenkins build #3](39-beta-new-slack-workspace.png)

**40.** Beta test: findings filed as issues #30-#35 with the Beta feedback form

![Beta test: findings filed as issues #30-#35 with the Beta feedback form](40-beta-feedback-issues.png)

**41.** PR #36 fixes all six findings, linked to the issues

![PR #36 fixes all six findings, linked to the issues](41-beta-fix-pr-linked-issues.png)

**42.** Issues #30-#35 closed automatically by PR #36

![Issues #30-#35 closed automatically by PR #36](42-beta-issues-closed.png)
