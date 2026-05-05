# FoxOps Trust Boundaries

This tool audits specific controls from the point of view of the environment where it runs.
It does not certify that a whole system is secure.

## Network Checks

Network checks are cross-platform and low risk. They ask:

```text
Can this runner ping a host?
Can this runner open a TCP connection to host:port?
```

Supported runners include Windows PowerShell, WSL, Linux, and macOS.

Network results describe connectivity from the local runner only. A successful check from WSL
does not prove the same path from native Windows, another host, or the router.

Hosts files are input convenience only. They provide repeatable target lists; they do not imply
network discovery, CIDR expansion, or authorization to scan a network.

FoxOps checks explicitly provided hosts and URLs only. It does not expand CIDR ranges,
discover hosts, or scan networks.

## Windows Hardening

Windows hardening checks trust Windows-native state and should be run from Windows PowerShell:

```powershell
python .\monitor.py --hardening --output json
```

Note: In FoxOps, "hardening" means a read-only posture audit against selected
baseline expectations. The tool reports observed hardening posture; it does not
apply hardening, remediate findings, or claim that the system is secure.

These checks use Windows commands such as:

```text
Get-LocalUser
net accounts
net user
```

Do not treat WSL as an authoritative Windows hardening context. WSL can see Windows files under
`/mnt/c`, but it does not natively own Windows local users, password policy, Defender state,
firewall policy, SMB server configuration, or services.

If WSL explicitly calls `powershell.exe`, that should be treated as a Windows PowerShell bridge,
not native Linux state.

## Linux And WSL Hardening

Linux hardening should be implemented as a separate module later. It should trust Linux-native
state such as:

```text
/etc/os-release
/etc/login.defs
/etc/ssh/sshd_config
id
groups
ss -lntup
systemctl
ufw or firewalld
```

WSL is a Linux environment with caveats. It can reliably report WSL distro state, Linux users,
Linux packages, and Linux listening ports. Some service and firewall checks may not apply the
same way they do on a full Linux host.

## Remediation Boundary

The tool is audit-only.

It may run read-only commands, parse configuration, probe network reachability, print findings,
write logs, and return exit codes.

It must not run remediation commands such as:

```text
Disable-LocalUser
Set-Service
Stop-Service
Set-NetFirewallRule
net accounts /minpwlen:12
registry writes
package installs
```

If remediation is added later, it should be behind an explicit mode with clear confirmations and
separate documentation.

Until then, remediation remains explicitly out of scope.

Future automated changes should also follow [AGENT_RULES.md](AGENT_RULES.md).

## Reporting Rules

The tool should report what it actually observed:

```text
[OK] network.google.com:443 source=local_runner - TCP connection succeeded
[WARN] windows_hardening source=wsl - skipped; run from Windows PowerShell
[FAIL] account_policy.min_password_length actual=0 required=>=12
```

It should not overclaim with broad statements such as:

```text
system secure
no risk found
fully hardened
```

## Summary

```text
Network checks trust the runner's network view.
Windows hardening trusts Windows PowerShell only.
Linux hardening should trust Linux-native commands only.
WSL is Linux unless explicitly bridging to PowerShell.
The tool reports findings; it does not fix them.
```
