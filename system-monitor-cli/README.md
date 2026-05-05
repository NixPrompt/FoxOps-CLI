# FoxOps System-Monitor-CLI

A dependency-free Python CLI for auditing network reachability and local Windows
hardening posture against defined baselines.

The tool is designed for NOC/SOC-style checks: readable console output,
structured JSON for automation, timestamped logs, clear exit codes, and no
automatic remediation.

Disclaimer: this tool reports specific observed findings from the runner's point
of view. It does not prove a system is secure, replace endpoint protection, or
perform remediation.

## Current Capabilities

- Cross-platform network checks:
  - ICMP ping
  - TCP port reachability
  - Repeated or comma-separated multi-host input
  - Hosts-file input for repeatable target lists
  - Optional bounded network concurrency with deterministic output order
- Windows hardening audit:
  - Built-in `Guest` account disabled
  - Built-in `Administrator` account disabled
  - Current main user requires a password
  - Minimum password length policy
  - Lockout threshold, duration, and observation window
- Operator output:
  - Stable check IDs
  - `OK`, `WARN`, and `FAIL` statuses
  - `actual` and `required` fields where applicable
- Automation output:
  - JSON summary
  - Host-grouped network results
  - Hardening result group
  - Flat result list

## Project Layout

```text
system-monitor-cli/
  check_result.py       # Shared result model and JSON serialization
  hardening_checks.py   # Read-only Windows account and password policy checks
  monitor.py            # CLI entry point, logging, orchestration
  monitor_checks.py     # Compatibility exports
  network_checks.py     # Ping and TCP port checks
  output_format.py      # Text and JSON renderers
  result_policy.py      # Host normalization, summaries, exit codes
  examples/
    hosts.txt           # Sample hosts-file input
    sample-output.json  # Representative JSON output
    sample-monitor.log  # Representative log output
  docs/
    TRUST_BOUNDARIES.md # Runtime authority and audit-only boundaries
  TODO.md               # Project roadmap
  README.md
```

## Quick Start

Run a network check:

```powershell
python .\monitor.py --host google.com --port 443
```

Run multiple host checks:

```powershell
python .\monitor.py --host google.com,github.com,1.1.1.1 --port 443
```

Run checks from a hosts file:

```powershell
python .\monitor.py --hosts-file .\hosts.txt --port 443 --output json
```

Try the included sample file:

```powershell
python .\monitor.py --hosts-file .\examples\hosts.txt --port 443 --workers 4 --output json
```

Hosts files accept one hostname or IP per line. Blank lines and lines starting
with `#` are ignored. Comma-separated entries are also accepted.

Example `hosts.txt`:

```text
# public targets
google.com
github.com

# local edge checks
192.168.1.1
1.1.1.1,8.8.8.8
```

Combine ad hoc hosts with a repeatable hosts file:

```powershell
python .\monitor.py --host emergency-router.example.com --hosts-file .\hosts.txt --port 443
```

If the hosts file is missing or unreadable, the CLI exits with runtime error
code `2`.

Run Windows hardening audit from Windows PowerShell:

```powershell
python .\monitor.py --hardening --output json
```

Run network and hardening checks together:

```powershell
python .\monitor.py --host github.com --port 443 --hardening --output json
```

Use a custom timeout or log file:

```powershell
python .\monitor.py --host 8.8.8.8 --port 53 --timeout 2 --log-file .\logs\network.log
```

Run multi-host checks with bounded network concurrency:

```powershell
python .\monitor.py --hosts-file .\hosts.txt --port 443 --workers 4 --output json
```

`--workers` defaults to `1`. Windows hardening checks remain sequential.

On Windows, use `py`, `python`, or a full Python path depending on local PATH
setup.

## Runtime Notes

- Network checks are cross-platform and describe connectivity from the runner's
  point of view.
- Windows hardening checks should be run from Windows PowerShell.
- If hardening cannot run on the current host, the tool reports `WARN` and exits
  cleanly.
- Remediation is explicitly out of scope.

## Hardening Baseline

Hardening mode is audit-only. It reads local Windows state and does not change
users, password policy, firewall rules, services, registry settings, or packages.

Current baseline:

- Guest account: disabled
- Administrator account: disabled
- Main user password: required
- Minimum password length: `>= 12`
- Lockout threshold: `1-10` attempts
- Lockout duration: `>= 10` minutes
- Lockout observation window: `>= 10` minutes

Example text output:

```text
[OK] account_hardening.Guest actual=disabled required=disabled - Guest account is disabled
[OK] account_hardening.Administrator actual=disabled required=disabled - Administrator account is disabled
[OK] account_hardening.ASUS1 actual=required required=required - ASUS1 requires a password
[FAIL] account_policy.min_password_length actual=0 required=>=12 - Minimum password length is 0; required >= 12
[OK] account_policy.lockout_threshold actual=10 required=1-10 - Lockout threshold is 10 attempts
```

## JSON Output

Use JSON for automation:

```powershell
python .\monitor.py --host google.com --hardening --output json
```

JSON includes a summary, grouped results, and the full flat result list:

```json
{
  "summary": {
    "OK": 6,
    "WARN": 0,
    "FAIL": 1
  },
  "groups": {
    "hosts": {
      "google.com": [
        {
          "check_id": "ping.google.com",
          "status": "OK",
          "details": {
            "host": "google.com",
            "timeout": 3
          }
        }
      ]
    },
    "hardening": [
      {
        "check_id": "account_policy.min_password_length",
        "status": "FAIL",
        "details": {
          "actual": 0,
          "required": ">=12"
        }
      }
    ]
  },
  "results": []
}
```

See [`examples/sample-output.json`](examples/sample-output.json) for a complete
network-only JSON example.

## Logging

Each result is written to the selected log file with a timestamp and stable
key-value fields.

Default log path:

```text
monitor.log
```

Example log line:

```text
2026-05-04T15:48:22-0700 INFO check=account_policy.min_password_length status=FAIL actual=0 required=>=12 message=Minimum password length is 0; required >= 12
```

See [`examples/sample-monitor.log`](examples/sample-monitor.log) for a short
network-check log example.

## Exit Codes

```text
0  All checks returned OK or WARN only
1  One or more checks returned FAIL
2  CLI/runtime error before checks could complete
```

## Running Tests

```powershell
pip install -r requirements-dev.txt
pytest
```

GitHub Actions runs the pytest suite on push and pull request.

## Roadmap

See `TODO.md` for planned work, including tests, CI, SMB/File Sharing audits,
Linux/WSL hardening, configurable baselines, and a design-only future `--fix`
discussion.

Remediation remains explicitly out of scope.
