# System Monitor CLI

A dependency-free Python CLI for auditing network reachability and local Windows
hardening posture against defined baselines.

The tool is designed for NOC/SOC-style checks: readable console output, structured JSON for
automation, timestamped logs, clear exit codes, and no automatic remediation.

## Current Capabilities

- Cross-platform network checks:
  - ICMP ping
  - TCP port reachability
  - repeated or comma-separated multi-host input
- Windows hardening audit:
  - built-in `Guest` account disabled
  - built-in `Administrator` account disabled
  - current main user requires a password
  - minimum password length policy
  - lockout threshold, duration, and observation window
- Operator output:
  - stable check IDs
  - `OK`, `WARN`, and `FAIL` statuses
  - `actual` and `required` fields where applicable
- Automation output:
  - JSON summary
  - host-grouped network results
  - hardening result group
  - flat result list

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

On Windows, use `py`, `python`, or a full Python path depending on local PATH setup.

## Trust Boundaries

Network checks are cross-platform and describe connectivity from the runner's point of view.

Windows hardening checks should be run from Windows PowerShell, not WSL, unless WSL is
explicitly being used as a bridge to call `powershell.exe`.

Linux/WSL hardening is planned as a separate future module. WSL can audit Linux state, but it
should not claim Windows authority unless bridging to Windows PowerShell.

See [docs/TRUST_BOUNDARIES.md](docs/TRUST_BOUNDARIES.md) for the full trust model.

## Hardening Baseline

Hardening mode is audit-only. It reads local Windows state and does not change users,
password policy, firewall rules, services, registry settings, or packages.

Current baseline:

```text
Guest account: disabled
Administrator account: disabled
Main user password: required
Minimum password length: >= 12
Lockout threshold: 1-10 attempts
Lockout duration: >= 10 minutes
Lockout observation window: >= 10 minutes
```

Example text output:

```text
[OK] account_hardening.Guest actual=disabled required=disabled - Guest account is disabled
[OK] account_hardening.Administrator actual=disabled required=disabled - Administrator account is disabled
[OK] account_hardening.ASUS1 actual=required required=required - ASUS1 requires a password
[FAIL] account_policy.min_password_length actual=0 required=>=12 - Minimum password length is 0; required >= 12
[OK] account_policy.lockout_threshold actual=10 required=1-10 - Lockout threshold is 10 attempts
```

If hardening is run from Linux, WSL, macOS, or a Windows host without required commands, the
tool reports `WARN` and exits cleanly.

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

## Logging

Each result is written to the selected log file with a timestamp and stable key-value fields.

Default log path:

```text
monitor.log
```

Example log line:

```text
2026-05-04T15:48:22-0700 INFO check=account_policy.min_password_length status=FAIL actual=0 required=>=12 message=Minimum password length is 0; required >= 12
```

## Exit Codes

```text
0  All checks returned OK or WARN only
1  One or more checks returned FAIL
2  CLI/runtime error before checks could complete
```

## Roadmap

See [TODO.md](TODO.md) for planned work, including tests, CI, SMB/File Sharing audits,
Linux/WSL hardening, configurable baselines, and a design-only future `--fix` discussion.

Remediation remains explicitly out of scope for the current tool.
