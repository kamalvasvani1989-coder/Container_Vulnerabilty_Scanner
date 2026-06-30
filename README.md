# Container Vulnerability Scanner — Sprint 1

The Python orchestration layer. It runs Trivy against a container image,
parses the results, applies a pass/fail policy gate, and exits with a code
that CI/CD can act on.

## Files

- `scanner.py`  — the wrapper (run Trivy, parse, gate, report).
- `policy.yaml` — the tunable gate thresholds.

## One-time setup

From inside your project folder, with your virtual environment active
(`source .venv/bin/activate` — your prompt should show `(.venv)`):

```bash
pip install pyyaml
```

That's the only dependency. Everything else is the Python standard library,
and Trivy itself (already installed from the setup guide).

## Running it

```bash
python scanner.py python:3.9-slim
```

Use a different policy file if you want:

```bash
python scanner.py python:3.9-slim --policy policy.yaml
```

`python:3.9-slim` is the deliberately-vulnerable image from the setup guide,
so you'll see the gate actually fail on its first run.

## What the exit codes mean

The script prints a summary AND sets an exit code. The exit code is what
CI/CD will use in the next sprint.

| Code | Meaning      | When |
|------|--------------|------|
| 0    | PASS         | Scan ran, policy satisfied |
| 1    | POLICY FAIL  | Scan ran, too many vulnerabilities — block the build |
| 2    | TOOL ERROR   | Couldn't scan or couldn't read the policy — alert someone |

Check the exit code after a run:

```bash
python scanner.py python:3.9-slim
echo "exit code: $?"
```

The split between 1 and 2 is deliberate. A broken scanner (exit 2) must
never be mistaken for a passing build, and a vulnerability block (exit 1)
must never be mistaken for a crash.

## Tuning the gate

Open `policy.yaml`. It looks like this:

```yaml
thresholds:
  CRITICAL: 0
  HIGH: 10
```

A severity fails the build when its count **exceeds** the limit. So with
`HIGH: 10`, a scan finding exactly 10 HIGHs still passes; 11 fails.
`CRITICAL: 0` means any critical fails — zero tolerance.

### Temporarily raising a limit

When an app has more HIGHs than allowed and the fix isn't released yet,
raise the number to unblock the build for now:

```yaml
thresholds:
  CRITICAL: 0
  HIGH: 20   # raised from 10 on 2026-06-30 for app-x, pending
             # upstream patch; review by 2026-07-15
```

Then commit the change with a clear message:

```bash
git add policy.yaml
git commit -m "Raise HIGH gate to 20 for app-x pending upstream patch"
```

The Git history is your audit trail. Tighten the number again once the
image is fixed. A proper dated-exception mechanism (per-CVE, with automatic
expiry) arrives in a later sprint — this manual approach is the Sprint 1
stand-in.

## How it works (the four jobs)

1. **Run Trivy** — calls `trivy image --format json --quiet <image>` and
   captures the JSON from stdout. Trivy's own `--exit-code` is deliberately
   not used, so a non-zero exit from Trivy unambiguously means the tool
   failed, not that vulnerabilities were found.
2. **Parse** — walks `Results[].Vulnerabilities[]`, tolerating clean layers
   that have no vulnerabilities key.
3. **Apply gate** — counts by severity, compares to the thresholds.
4. **Report** — prints the summary and returns the exit code.