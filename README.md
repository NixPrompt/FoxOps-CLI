# FoxOps CLI

FoxOps CLI is an audit-only command-line toolkit for repeatable NOC/SOC-style
checks.

Current scope:

- Network reachability from the local runner
- TCP host:port validation
- Repeatable multi-host input from CLI arguments or hosts files
- Windows local account and password-policy inspection
- Structured JSON output for automation and audit logs

The active CLI lives in [`system-monitor-cli/`](system-monitor-cli/).

FoxOps does not perform remediation, exploit testing, credential harvesting,
firewall changes, or automatic system modification.
