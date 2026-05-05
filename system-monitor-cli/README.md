# System Monitor CLI

A small dependency-free Python CLI that audits Windows system configuration and network
health against defined security baselines, with structured outputs suitable for automation.

## Structure

```text
system-monitor-cli/
  check_result.py      # Shared OK/WARN/FAIL result model
  hardening_checks.py  # Windows account and password policy audit checks
  monitor.py           # CLI entry point, logging, output formatting
  monitor_checks.py    # Compatibility exports
  network_checks.py    # Ping and TCP port checks
  output_format.py     # Text and JSON renderers
  result_policy.py     # Host normalization, summaries, exit codes
  docs/
    TRUST_BOUNDARIES.md
  README.md
```

## Usage

Check host availability and TCP port reachability:

```powershell
python .\monitor.py --host example.com --port 443
```

Check multiple hosts:

```powershell
python .\monitor.py --host example.com --host 8.8.8.8 --port 443
```

Comma-separated hosts are also supported:

```powershell
python .\monitor.py --host example.com,8.8.8.8 --port 443
```

Run read-only Windows hardening checks:

```powershell
python .\monitor.py --hardening
```

Run both check groups:

```powershell
python .\monitor.py --host example.com --port 443 --hardening
```

Use a custom timeout or log file:

```powershell
python .\monitor.py --host 8.8.8.8 --port 53 --timeout 2 --log-file .\monitor.log
```

Emit JSON for automation:

```powershell
python .\monitor.py --host example.com --hardening --output json
```

On Windows, use `py`, `python`, or a full Python path depending on your local PATH setup.

## Hardening Audit

Hardening mode is audit-only. It reads local Windows state and does not change users,
password policy, firewall rules, services, or registry settings.

Windows hardening checks should be run from Windows PowerShell, not WSL, unless you are
explicitly using WSL as a bridge to call `powershell.exe`.

Baseline policy:

```text
Guest account: disabled
Administrator account: disabled
Main user password: required
Minimum password length: >= 12
Lockout threshold: 1-10 attempts
Lockout duration: >= 10 minutes
Lockout observation window: >= 10 minutes
```

Example output:

```text
[OK] account_hardening.Guest actual=disabled required=disabled - Guest account is disabled
[OK] account_hardening.Administrator actual=disabled required=disabled - Administrator account is disabled
[OK] account_hardening.ASUS1 actual=required required=required - ASUS1 requires a password
[FAIL] account_policy.min_password_length actual=0 required=>=12 - Minimum password length is 0; required >= 12
[OK] account_policy.lockout_threshold actual=10 required=1-10 - Lockout threshold is 10 attempts
[OK] account_policy.lockout_duration actual=10 required=>=10 unit=minutes - Lockout duration is 10 minutes
[OK] account_policy.lockout_window actual=10 required=>=10 unit=minutes - Lockout observation window is 10 minutes
```

## JSON Output

JSON output includes a summary and one record per check:
It also groups network results by host so automation does not need to parse target strings.

```json
{
  "summary": {
    "OK": 6,
    "WARN": 0,
    "FAIL": 1
  },
  "groups": {
    "hosts": {
      "example.com": [
        {
          "check_id": "ping.example.com",
          "status": "OK",
          "details": {
            "host": "example.com",
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

If run on WSL, Linux, macOS, or a Windows host without required commands, the audit reports
`WARN` and exits cleanly.

## Trust Boundaries

Network checks are cross-platform and describe connectivity from the runner's point of view.
Windows hardening checks trust Windows PowerShell only. Linux hardening should live in a
separate module later.

See [docs/TRUST_BOUNDARIES.md](docs/TRUST_BOUNDARIES.md) for the full trust model.

## Logging

Each result is written to the selected log file with a timestamp and stable key-value fields:

```text
2026-05-04T15:48:22-0700 INFO check=account_policy.min_password_length status=FAIL actual=0 required=>=12 message=Minimum password length is 0; required >= 12
```

Default log path:

```text
monitor.log
```

## Exit Codes

```text
0  All checks returned OK or WARN only
1  One or more checks returned FAIL
2  CLI/runtime error before checks could complete
```
