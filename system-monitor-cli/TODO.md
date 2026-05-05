# FoxOps-CLI Roadmap

FoxOps-CLI should stay safe, read-only, deterministic, and useful for NOC-style
triage. Each phase should leave the tool cloneable, runnable, and explainable.

## Phase 1: Make It Usable And Demoable

Goal: someone can clone it, run it, and immediately understand what it does.

- Keep README examples current for:
  - single-host checks
  - comma-separated hosts
  - `--hosts-file`
  - `--workers`
  - JSON output
  - Windows hardening
- Add troubleshooting notes:
  - Python not found
  - ping unavailable
  - PowerShell vs WSL hardening behavior
  - missing or unreadable hosts file
- Add sample fixtures:
  - `examples/hosts.txt`
  - example JSON output
  - example log output
- Keep tests and GitHub Actions healthy:
  - Linux pytest run
  - Windows pytest run
  - import/smoke test for `monitor.py`
- Normalize no-input exit reporting across shells.
- Add current test-count note to README when the suite stabilizes.
- Add sample Windows command-output fixtures for hardening parser tests.

## Phase 2: Add NOC Runbook Features

Goal: make it feel like a tiny CLI version of how a NOC tech thinks.

- Add timeout/retry policy with conservative defaults.
- Consider optional streaming or fail-fast execution mode for incident workflows.
- Consider case-insensitive host deduplication while preserving first spelling.
- Improve WARN messages so skipped checks clearly explain what to do next.
- Keep network output deterministic unless an explicit streaming mode is added.

## Phase 3: Make It Ticket/Evidence Friendly

Goal: turn checks into artifacts.

- Add `--output-file` for JSON evidence capture.
- Add per-host JSON summaries.
- Add runner/source metadata to results:
  - `source=local_runner`
  - `source=windows_powershell`
  - `source=wsl`
  - `source=linux_native`
- Add timestamp and command metadata to evidence output.
- Add optional markdown summary report for tickets.
- Keep the stable JSON schema: `summary`, `groups`, `results`.

## Phase 4: Add Windows And Linux Admin Audit Depth

Goal: expand audit coverage while keeping it safe and read-only.

- Expand Windows audit checks:
  - SMB/File Sharing service state
  - File and Printer Sharing firewall rules
  - Defender real-time protection status
  - firewall profile status
  - local Administrators group members
- Add `linux_hardening_checks.py` for local Linux audits:
  - `/etc/os-release`
  - `/etc/login.defs`
  - SSH password auth setting
  - listening ports with `ss`
  - local user and group context
- Add WSL-aware messages:
  - WSL can audit Linux state
  - WSL should not claim Windows authority unless bridging to PowerShell
- Do not add SSH remote audit until local Linux behavior is mature.

## Phase 5: Add Profiles

Goal: let operators choose repeatable check sets without changing code.

- Add optional profile configuration.
- Keep safe defaults in code.
- Validate profile schema before use.
- Support named profiles such as:
  - `network-basic`
  - `windows-hardening`
  - `linux-hardening`
  - `ticket-evidence`
- Allow configurable baselines for:
  - password length
  - lockout threshold
  - lockout duration
  - lockout window
  - TLS expiry warning days

## Phase 6: Make It Portfolio-Grade

Goal: make FoxOps-CLI look and feel like a production-quality security/NOC tool.

- Add polished docs:
  - architecture overview
  - trust-boundary guide
  - sample runbook workflows
  - "What this tool does not prove"
  - screenshots or terminal captures
- Add release hygiene:
  - changelog
  - version flag
  - tagged releases
  - packaging notes
- Add CI polish:
  - linting
  - Windows and Linux test matrix
  - coverage report
- Add automation prompts for:
  - regression scan
  - TODO consistency scan
  - docs consistency scan
  - CI failure triage

## Future Design Only: Fix Mode

- Do not implement `--fix` yet.
- Add `docs/FIX_MODE_DESIGN.md` before any remediation code.
- Define:
  - allowed fixes
  - blocked fixes
  - dry-run behavior
  - confirmation behavior
  - admin requirements
  - logging format
  - verification after change
  - rollback notes

## Explicitly Out Of Scope For Now

- Automatic remediation
- Password changes
- Registry writes
- Deleting users
- Removing admin rights
- Exploit testing
- LAN scanning
- Credential harvesting
- Remote SSH administration
- "System secure" claims
