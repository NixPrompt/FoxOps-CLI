# TODO

## Next: Stabilize Core Contracts

- Add tests for `result_policy.py`
  - OK/WARN-only results exit `0`
  - any FAIL exits `1`
  - runtime errors use runtime error code
- Add tests for `output_format.py`
  - text output includes status, check_id, details, message
  - JSON output includes summary, groups, and results
- Add tests for `hardening_checks.py`
  - non-Windows hardening returns WARN
  - `net accounts` parsing handles `None` and numeric values
- Add sample fixtures for Windows command output

## Automation / CI

- Add GitHub Actions workflow
  - run tests on Linux
  - run tests on Windows
  - run import/smoke test for `monitor.py`
- Add a daily/weekly automation prompt for:
  - regression scan
  - proposal scan
  - TODO consistency scan

## Trust Boundary Improvements

- Add explicit runner/source metadata to results
  - `source=local_runner`
  - `source=windows_powershell`
  - `source=wsl`
  - `source=linux_native`
- Add environment detection helper
  - Windows
  - Linux
  - WSL
  - unknown
- Make WARN skip messages explain the trust boundary

## Windows Audit Expansion

- Add SMB/File Sharing audit checks
  - check `LanmanServer`
  - check File and Printer Sharing firewall rules
- Add Defender status audit
  - real-time protection status
  - tamper protection if available
- Add firewall profile audit
  - domain/private/public enabled status
- Add local admin group audit
  - list local Administrators group members
  - WARN on unexpected accounts

## Network Checks

- Add DNS resolution check
- Add HTTP status check
- Add TLS certificate expiry check
- Add host deduplication while preserving operator-provided order
- Add per-host JSON summaries
- Add timeout/retry policy

## Linux / WSL Expansion

- Add `linux_hardening_checks.py`
- Start with read-only checks:
  - `/etc/os-release`
  - `/etc/login.defs`
  - SSH password auth setting
  - listening ports with `ss`
- Add WSL-specific caveats:
  - WSL can audit Linux state
  - WSL should not claim Windows authority unless bridging

## Configurable Baselines

- Add optional `baseline.json`
- Keep safe defaults in code
- Allow custom thresholds for:
  - password length
  - lockout threshold
  - lockout duration
  - lockout window
- Validate baseline schema before use

## Documentation

- Add JSON output examples
- Add Windows PowerShell examples
- Add WSL/Linux examples
- Add "What this tool does not prove" section
- Add troubleshooting section:
  - Python not found
  - WSL path issues
  - PowerShell vs WSL hardening behavior

## Future Design Only: Fix Mode

- Do not implement `--fix` yet
- Add `docs/FIX_MODE_DESIGN.md` before any remediation code
- Define:
  - allowed fixes
  - blocked fixes
  - dry-run behavior
  - confirmation behavior
  - admin requirements
  - logging format
  - verification after change
  - rollback notes

## Explicitly Out of Scope For Now

- Automatic remediation
- Password changes
- Registry writes
- Deleting users
- Removing admin rights
- Exploit testing
- LAN scanning
- "System secure" claims
