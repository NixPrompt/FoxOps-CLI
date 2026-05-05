# FoxOps CLI

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
  - DNS resolution
  - ICMP ping
  - TCP port reachability
  - HTTP status checks for URLs
  - TLS certificate expiry checks for HTTPS URLs
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
  - Run-level JSON metadata
  - JSON summary
  - Host-grouped network results
  - Hardening result group
  - Flat result list
  - Optional JSON file output with parent directory creation

## Project Layout

```text
.
|-- monitor.py            # CLI entry point, logging, orchestration
|-- check_result.py       # Shared result model and JSON serialization
|-- evidence.py           # Run-level evidence metadata helpers
|-- hardening_checks.py   # Read-only Windows account and password policy checks
|-- monitor_checks.py     # Compatibility exports
|-- network_checks.py     # DNS, ping, TCP port, HTTP, and TLS checks
|-- output_format.py      # Text and JSON renderers
|-- result_policy.py      # Host normalization, summaries, exit codes
|-- examples/
|   |-- hosts.txt
|   |-- sample-output.json
|   `-- sample-monitor.log
|-- docs/
|   |-- AGENT_RULES.md
|   `-- TRUST_BOUNDARIES.md
|-- tests/
|-- TODO.md
`-- README.md
```

## Quick Start

Canonical demo command:

```powershell
python .\monitor.py --hosts-file .\examples\hosts.txt --port 443 --workers 4 --output json
```

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

Write JSON to a file while keeping JSON on stdout:

```powershell
python .\monitor.py --hosts-file .\hosts.txt --port 443 --output json --output-file .\reports\latest.json
```

Run web checks for an HTTP or HTTPS URL:

```powershell
python .\monitor.py --url https://example.com --output json
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
- URL checks use HTTP `HEAD` requests and read-only TLS certificate inspection.
- TLS certificate checks run for HTTPS URLs. HTTP URLs report a `WARN` skip for
  TLS.
- TLS certificate status is `FAIL` when expired, `WARN` when expiring in 30 days
  or less, and `OK` beyond that window.
- Windows hardening checks should be run from Windows PowerShell.
- If hardening cannot run on the current host, the tool reports `WARN` and exits
  cleanly.
- Under WSL, hardening reports `source=wsl`, explains that WSL is not
  authoritative for Windows local users or password policy, and tells operators
  to rerun from Windows PowerShell.
- Remediation is explicitly out of scope.
- Future automated changes should follow
  [`docs/AGENT_RULES.md`](docs/AGENT_RULES.md).

## Hardening Baseline

Hardening mode is audit-only. It reads local Windows state and does not change
users, password policy, firewall rules, services, registry settings, or packages.

Note: In FoxOps, "hardening" means a read-only posture audit against selected
baseline expectations. The tool reports observed hardening posture; it does not
apply hardening, remediate findings, or claim that the system is secure.

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
python .\monitor.py --host example.com --port 443 --output json
```

Persist the same JSON payload to a file:

```powershell
python .\monitor.py --host example.com --port 443 --output json --output-file .\reports\example.json
```

FoxOps creates parent directories for `--output-file` when possible. If the
file cannot be written, it prints a clear `[FAIL]` message to stderr and exits
with runtime error code `2`. Output files are currently supported for JSON runs
only.

JSON includes run metadata, a summary, grouped results, and the full flat result
list. Top-level key order is stable: `metadata`, `summary`, `groups`, `results`.

```json
{
  "metadata": {
    "started_at": "2026-05-05T15:42:10-07:00",
    "completed_at": "2026-05-05T15:42:14-07:00",
    "duration_ms": 4120,
    "source": "local_runner",
    "runner": "noc-runner-01",
    "platform": "Windows",
    "output_schema": "foxops.v1"
  },
  "summary": {
    "OK": 3,
    "WARN": 0,
    "FAIL": 0
  },
  "groups": {
    "hosts": {
      "example.com": [
        {
          "check_id": "dns_resolution.example.com",
          "name": "dns_resolution",
          "target": "example.com",
          "status": "OK",
          "message": "resolved 2 address(es)",
          "details": {
            "host": "example.com",
            "timeout": 3,
            "addresses": [
              "93.184.216.34",
              "2606:2800:220:1:248:1893:25c8:1946"
            ]
          }
        },
        {
          "check_id": "ping.example.com",
          "name": "ping",
          "target": "example.com",
          "status": "OK",
          "message": "host responded to ping",
          "details": {
            "host": "example.com",
            "timeout": 3
          }
        },
        {
          "check_id": "tcp_port.example.com:443",
          "name": "tcp_port",
          "target": "example.com:443",
          "status": "OK",
          "message": "port is open",
          "details": {
            "host": "example.com",
            "port": 443,
            "timeout": 3
          }
        }
      ]
    },
    "urls": {},
    "hardening": []
  },
  "results": [
    {
      "check_id": "dns_resolution.example.com",
      "name": "dns_resolution",
      "target": "example.com",
      "status": "OK",
      "message": "resolved 2 address(es)",
      "details": {
        "host": "example.com",
        "timeout": 3,
        "addresses": [
          "93.184.216.34",
          "2606:2800:220:1:248:1893:25c8:1946"
        ]
      }
    },
    {
      "check_id": "ping.example.com",
      "name": "ping",
      "target": "example.com",
      "status": "OK",
      "message": "host responded to ping",
      "details": {
        "host": "example.com",
        "timeout": 3
      }
    },
    {
      "check_id": "tcp_port.example.com:443",
      "name": "tcp_port",
      "target": "example.com:443",
      "status": "OK",
      "message": "port is open",
      "details": {
        "host": "example.com",
        "port": 443,
        "timeout": 3
      }
    }
  ]
}
```

See [`examples/sample-output.json`](examples/sample-output.json) for the same
network-only JSON example as a standalone file.

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

## Troubleshooting

### Python Not Found

On Windows, `python` may not be on `PATH`. Try the Python launcher:

```powershell
py .\monitor.py --host google.com --port 443
```

You can also use a full path to a Python executable.

### Ping Unavailable

If the runner cannot execute `ping`, the ping check reports `WARN` and the TCP
port check still runs. This keeps the network check useful on stripped-down
hosts or locked-down shells.

### PowerShell Vs WSL Hardening

Windows hardening checks should be run from Windows PowerShell:

```powershell
python .\monitor.py --hardening --output json
```

If you run from WSL or another non-Windows context, FoxOps reports a `WARN`
capability result instead of claiming Windows authority.

WSL output is intentionally specific:

```text
[WARN] capability.hardening source=wsl reason=not_authoritative_for_windows_hardening action=run_from_windows_powershell - skipped: WSL is a Linux environment and is not authoritative for Windows local users or password policy; run from Windows PowerShell instead
```

Native Linux and macOS also skip Windows hardening with `WARN`, but they report
their own runner source, such as `source=linux` or `source=darwin`.

### Missing Hosts File

If `--hosts-file` points to a missing or unreadable file, FoxOps prints a clear
`[FAIL]` message to stderr and exits with runtime error code `2`.

## Roadmap

See `TODO.md` for planned work, including tests, CI, SMB/File Sharing audits,
Linux/WSL hardening, configurable baselines, and a design-only future `--fix`
discussion.

Remediation remains explicitly out of scope.
