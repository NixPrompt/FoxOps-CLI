import json
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from check_result import CheckResult


MIN_PASSWORD_LENGTH_POLICY = 12
LOCKOUT_THRESHOLD_MIN = 1
LOCKOUT_THRESHOLD_MAX = 10
LOCKOUT_DURATION_MINUTES = 10
LOCKOUT_WINDOW_MINUTES = 10
WSL_ENVIRONMENT_MARKERS = ("WSL_DISTRO_NAME", "WSL_INTEROP")


@dataclass
class LocalUserState:
    name: str
    enabled: bool | None
    password_required: bool | None


@dataclass
class NetAccountsPolicy:
    min_password_length: int | None
    lockout_threshold: int | None
    lockout_duration: int | None
    lockout_window: int | None


def check_hardening_capability() -> CheckResult:
    """Report whether Windows hardening checks can run on this host."""
    system = platform.system().lower()
    if system != "windows":
        if _is_wsl_environment():
            return CheckResult(
                "capability",
                "hardening",
                "WARN",
                (
                    "skipped: WSL is a Linux environment and is not authoritative for "
                    "Windows local users or password policy; run from Windows PowerShell instead"
                ),
                {
                    "source": "wsl",
                    "reason": "not_authoritative_for_windows_hardening",
                    "action": "run_from_windows_powershell",
                },
            )

        return CheckResult(
            "capability",
            "hardening",
            "WARN",
            f"skipped: Windows hardening checks only run from Windows PowerShell; this runner is {system}",
            {
                "source": system or "unknown",
                "reason": "not_windows",
                "action": "run_from_windows_powershell",
            },
        )

    if shutil.which("net") is None:
        return CheckResult(
            "capability",
            "hardening",
            "WARN",
            "skipped: net command not found; run from a Windows PowerShell session with Windows system commands on PATH",
            {
                "source": "windows",
                "reason": "net_command_not_found",
                "action": "run_from_windows_powershell_with_net_on_path",
            },
        )

    return CheckResult(
        "capability",
        "hardening",
        "OK",
        "Windows hardening checks available",
        {"source": "windows"},
    )


def _is_wsl_environment() -> bool:
    if platform.system().lower() != "linux":
        return False

    if any(os.environ.get(marker) for marker in WSL_ENVIRONMENT_MARKERS):
        return True

    kernel_release = _read_linux_kernel_release().lower()
    kernel_tokens = kernel_release.replace("_", "-").replace(".", "-").split("-")
    return bool({"microsoft", "wsl", "wsl2"} & set(kernel_tokens))


def _read_linux_kernel_release() -> str:
    try:
        return Path("/proc/sys/kernel/osrelease").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def check_windows_account_hardening() -> list[CheckResult]:
    """Run read-only Windows local account and password policy checks."""
    capability = check_hardening_capability()
    if capability.status != "OK":
        return [capability]

    results = [
        _check_builtin_user_disabled("Guest"),
        _check_builtin_user_disabled("Administrator"),
    ]

    main_user = os.environ.get("USERNAME")
    if main_user:
        results.append(_check_main_user_password_required(main_user))
    else:
        results.append(CheckResult("account_hardening", "main_user", "WARN", "USERNAME was not available"))

    results.extend(_check_net_accounts_policy())
    return results


def _check_builtin_user_disabled(username: str) -> CheckResult:
    user = _get_local_user(username)
    if user.enabled is None:
        return CheckResult("account_hardening", username, "WARN", "could not read account enabled state")
    actual = "enabled" if user.enabled else "disabled"
    if user.enabled:
        return CheckResult(
            "account_hardening",
            username,
            "FAIL",
            f"{username} account is enabled",
            {"actual": actual, "required": "disabled"},
        )
    return CheckResult(
        "account_hardening",
        username,
        "OK",
        f"{username} account is disabled",
        {"actual": actual, "required": "disabled"},
    )


def _check_main_user_password_required(username: str) -> CheckResult:
    user = _get_local_user(username)
    if user.password_required is None:
        return CheckResult("account_hardening", username, "WARN", "could not read password-required state")
    actual = "required" if user.password_required else "not_required"
    if user.password_required:
        return CheckResult(
            "account_hardening",
            username,
            "OK",
            f"{username} requires a password",
            {"actual": actual, "required": "required"},
        )
    return CheckResult(
        "account_hardening",
        username,
        "FAIL",
        f"{username} does not require a password",
        {"actual": actual, "required": "required"},
    )


def _check_net_accounts_policy() -> list[CheckResult]:
    policy = _get_net_accounts_policy()
    if policy is None:
        return [CheckResult("account_policy", "net_accounts", "WARN", "could not read net accounts policy")]

    return [
        _check_min_password_length(policy.min_password_length),
        _check_lockout_threshold(policy.lockout_threshold),
        _check_lockout_duration(policy.lockout_duration),
        _check_lockout_window(policy.lockout_window),
    ]


def _check_min_password_length(value: int | None) -> CheckResult:
    if value is None:
        return CheckResult("account_policy", "min_password_length", "WARN", "could not read policy")
    details = {"actual": value, "required": f">={MIN_PASSWORD_LENGTH_POLICY}"}
    if value >= MIN_PASSWORD_LENGTH_POLICY:
        return CheckResult(
            "account_policy",
            "min_password_length",
            "OK",
            f"Minimum password length is {value}",
            details,
        )
    return CheckResult(
        "account_policy",
        "min_password_length",
        "FAIL",
        f"Minimum password length is {value}; required >= {MIN_PASSWORD_LENGTH_POLICY}",
        details,
    )


def _check_lockout_threshold(value: int | None) -> CheckResult:
    if value is None:
        return CheckResult("account_policy", "lockout_threshold", "WARN", "could not read policy")
    details = {"actual": value, "required": f"{LOCKOUT_THRESHOLD_MIN}-{LOCKOUT_THRESHOLD_MAX}"}
    if LOCKOUT_THRESHOLD_MIN <= value <= LOCKOUT_THRESHOLD_MAX:
        return CheckResult(
            "account_policy",
            "lockout_threshold",
            "OK",
            f"Lockout threshold is {value} attempts",
            details,
        )
    return CheckResult(
        "account_policy",
        "lockout_threshold",
        "FAIL",
        f"Lockout threshold is {value}; required {LOCKOUT_THRESHOLD_MIN}-{LOCKOUT_THRESHOLD_MAX}",
        details,
    )


def _check_lockout_duration(value: int | None) -> CheckResult:
    if value is None:
        return CheckResult("account_policy", "lockout_duration", "WARN", "could not read policy")
    details = {"actual": value, "required": f">={LOCKOUT_DURATION_MINUTES}", "unit": "minutes"}
    if value >= LOCKOUT_DURATION_MINUTES:
        return CheckResult(
            "account_policy",
            "lockout_duration",
            "OK",
            f"Lockout duration is {value} minutes",
            details,
        )
    return CheckResult(
        "account_policy",
        "lockout_duration",
        "FAIL",
        f"Lockout duration is {value} minutes; required >= {LOCKOUT_DURATION_MINUTES}",
        details,
    )


def _check_lockout_window(value: int | None) -> CheckResult:
    if value is None:
        return CheckResult("account_policy", "lockout_window", "WARN", "could not read policy")
    details = {"actual": value, "required": f">={LOCKOUT_WINDOW_MINUTES}", "unit": "minutes"}
    if value >= LOCKOUT_WINDOW_MINUTES:
        return CheckResult(
            "account_policy",
            "lockout_window",
            "OK",
            f"Lockout observation window is {value} minutes",
            details,
        )
    return CheckResult(
        "account_policy",
        "lockout_window",
        "FAIL",
        f"Lockout observation window is {value} minutes; required >= {LOCKOUT_WINDOW_MINUTES}",
        details,
    )


def _get_local_user(username: str) -> LocalUserState:
    user = _get_local_user_with_powershell(username)
    if user is not None:
        return user
    return _get_local_user_with_net(username)


def _get_local_user_with_powershell(username: str) -> LocalUserState | None:
    if shutil.which("powershell") is None:
        return None

    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        (
            f"Get-LocalUser -Name '{username}' | "
            "Select-Object Name,Enabled,PasswordRequired | ConvertTo-Json -Compress"
        ),
    ]

    try:
        returncode, output = _run_command(command)
    except Exception:
        return None

    if returncode != 0 or not output:
        return None

    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return None

    return LocalUserState(
        name=str(payload.get("Name", username)),
        enabled=payload.get("Enabled"),
        password_required=payload.get("PasswordRequired"),
    )


def _get_local_user_with_net(username: str) -> LocalUserState:
    try:
        returncode, output = _run_command(["net", "user", username])
    except Exception:
        return LocalUserState(username, None, None)

    if returncode != 0:
        return LocalUserState(username, None, None)

    active = _extract_net_value(output, "Account active")
    password_required = _extract_net_value(output, "Password required")

    return LocalUserState(
        name=username,
        enabled=_yes_no_to_bool(active),
        password_required=_yes_no_to_bool(password_required),
    )


def _get_net_accounts_policy() -> NetAccountsPolicy | None:
    try:
        returncode, output = _run_command(["net", "accounts"])
    except Exception:
        return None

    if returncode != 0:
        return None

    return NetAccountsPolicy(
        min_password_length=_extract_int_value(output, "Minimum password length"),
        lockout_threshold=_extract_int_value(output, "Lockout threshold"),
        lockout_duration=_extract_int_value(output, "Lockout duration (minutes)"),
        lockout_window=_extract_int_value(output, "Lockout observation window (minutes)"),
    )


def _run_command(command: list[str], timeout: int = 10) -> tuple[int, str]:
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    output = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part.strip())
    return completed.returncode, output


def _extract_net_value(output: str, label: str) -> str | None:
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith(label.lower()):
            return stripped[len(label) :].lstrip(" :\t")
    return None


def _extract_int_value(output: str, label: str) -> int | None:
    value = _extract_net_value(output, label)
    if value is None:
        return None

    first_token = value.split()[0]
    if first_token.lower() == "none":
        return 0

    try:
        return int(first_token)
    except ValueError:
        return None


def _yes_no_to_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized.startswith("yes"):
        return True
    if normalized.startswith("no"):
        return False
    return None
