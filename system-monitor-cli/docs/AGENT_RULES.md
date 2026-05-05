# FoxOps Agent Rules

FoxOps is audit-only.

Agents must not add:

- Automatic remediation
- `--fix` behavior
- Password changes
- Registry writes
- Firewall changes
- Package installs or removals
- Deleting users
- Changing group membership
- Credential collection
- Exploit testing
- CIDR expansion
- LAN discovery
- Remote SSH administration
- Claims that a system is secure, compliant, or risk-free

Agents must not pass arbitrary user-supplied values into shell or PowerShell
command strings without safe argument handling.

Allowed work:

- Read-only local checks
- Checks against explicitly provided hosts or URLs
- Structured JSON and text output
- Deterministic ordering
- Logging and clear error handling
- Tests
- Documentation
- Examples
- Clearer warnings
