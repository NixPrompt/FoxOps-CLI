# FoxOps CLI

FoxOps CLI is an audit-first toolkit for inspecting system state, network reachability, and security posture across environments.

It is part of a broader FoxOps philosophy:

> Observe systems clearly, respect trust boundaries, and never change state without explicit intent.

---

## 🔍 What FoxOps CLI Provides

FoxOps CLI tools are designed to be:

- **Audit-only by default**
- **Cross-environment aware** (Windows, WSL, Linux)
- **Trust-boundary explicit**
- **Structured-output first** (human + machine readable)

Current capabilities include:

### Network Checks (Cross-Platform)
- ICMP reachability (ping)
- TCP connectivity (host:port)
- Runner-perspective validation

### Windows Hardening Audit (PowerShell Only)
- Local account state (Guest, Administrator, main user)
- Password policy (minimum length, requirement flags)
- Account lockout policy

### Structured Output
- Stable `check_id` values
- `status`, `message`, `details`
- JSON output for automation pipelines

---

## 🧠 FoxOps Philosophy

FoxOps tools follow strict rules:

### 1. Audit-First
- No system modifications by default
- No automatic remediation
- No hidden side effects

### 2. Trust Boundaries Are Explicit
Every result must be explainable based on where it came from.

| Environment | Authority |
|------------|----------|
| Network     | Local runner perspective |
| Windows     | Windows PowerShell |
| WSL         | Linux environment (not Windows) |
| Linux       | Linux-native tools |

Example:

```text
WSL → google.com:443 reachable
≠ Windows firewall exposure
