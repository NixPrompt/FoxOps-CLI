from pathlib import Path

import hardening_checks
from check_result import CheckResult


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_check_hardening_capability_warns_on_non_windows(monkeypatch):
    monkeypatch.setattr(hardening_checks.platform, "system", lambda: "Linux")
    monkeypatch.setattr(hardening_checks, "_read_linux_kernel_release", lambda: "6.8.0-generic")
    monkeypatch.setattr(hardening_checks.os, "environ", {})

    result = hardening_checks.check_hardening_capability()

    assert result == CheckResult(
        "capability",
        "hardening",
        "WARN",
        "skipped: Windows hardening checks only run from Windows PowerShell; this runner is linux",
        {
            "source": "linux",
            "reason": "not_windows",
            "action": "run_from_windows_powershell",
        },
    )


def test_check_hardening_capability_explains_wsl_skip_from_environment(monkeypatch):
    monkeypatch.setattr(hardening_checks.platform, "system", lambda: "Linux")
    monkeypatch.setattr(hardening_checks.os, "environ", {"WSL_DISTRO_NAME": "Ubuntu"})
    monkeypatch.setattr(hardening_checks, "_read_linux_kernel_release", lambda: "6.8.0-generic")

    result = hardening_checks.check_hardening_capability()

    assert result == CheckResult(
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


def test_check_hardening_capability_explains_wsl_skip_from_kernel_release(monkeypatch):
    monkeypatch.setattr(hardening_checks.platform, "system", lambda: "Linux")
    monkeypatch.setattr(hardening_checks.os, "environ", {})
    monkeypatch.setattr(hardening_checks, "_read_linux_kernel_release", lambda: "5.15.90.1-microsoft-standard-WSL2")

    result = hardening_checks.check_hardening_capability()

    assert result.details["source"] == "wsl"
    assert result.details["reason"] == "not_authoritative_for_windows_hardening"
    assert "run from Windows PowerShell instead" in result.message


def test_check_hardening_capability_warns_on_macos_without_wsl_probe(monkeypatch):
    monkeypatch.setattr(hardening_checks.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(hardening_checks.os, "environ", {"WSL_DISTRO_NAME": "Ubuntu"})

    result = hardening_checks.check_hardening_capability()

    assert result == CheckResult(
        "capability",
        "hardening",
        "WARN",
        "skipped: Windows hardening checks only run from Windows PowerShell; this runner is darwin",
        {
            "source": "darwin",
            "reason": "not_windows",
            "action": "run_from_windows_powershell",
        },
    )


def test_check_hardening_capability_does_not_treat_wsl_substring_as_wsl(monkeypatch):
    monkeypatch.setattr(hardening_checks.platform, "system", lambda: "Linux")
    monkeypatch.setattr(hardening_checks.os, "environ", {})
    monkeypatch.setattr(hardening_checks, "_read_linux_kernel_release", lambda: "6.8.0-newsletter-build")

    result = hardening_checks.check_hardening_capability()

    assert result.details["source"] == "linux"
    assert result.details["reason"] == "not_windows"


def test_check_hardening_capability_warns_when_net_command_is_missing(monkeypatch):
    monkeypatch.setattr(hardening_checks.platform, "system", lambda: "Windows")
    monkeypatch.setattr(hardening_checks.shutil, "which", lambda command: None if command == "net" else command)

    result = hardening_checks.check_hardening_capability()

    assert result == CheckResult(
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


def test_check_hardening_capability_reports_windows_available(monkeypatch):
    monkeypatch.setattr(hardening_checks.platform, "system", lambda: "Windows")
    monkeypatch.setattr(hardening_checks.shutil, "which", lambda command: "net" if command == "net" else None)

    result = hardening_checks.check_hardening_capability()

    assert result == CheckResult(
        "capability",
        "hardening",
        "OK",
        "Windows hardening checks available",
        {"source": "windows"},
    )


def test_check_windows_account_hardening_returns_capability_when_command_execution_fails(monkeypatch):
    monkeypatch.setattr(hardening_checks.platform, "system", lambda: "Windows")

    def fake_which(command: str) -> str | None:
        if command == "net":
            return "net"
        if command == "powershell":
            return None
        return command

    def fake_run_command(command: list[str], timeout: int = 10) -> tuple[int, str]:
        raise OSError(f"simulated failure for {' '.join(command)}")

    monkeypatch.setattr(hardening_checks.shutil, "which", fake_which)
    monkeypatch.setattr(hardening_checks, "_run_command", fake_run_command)
    monkeypatch.setattr(hardening_checks.os, "environ", {})

    results = hardening_checks.check_windows_account_hardening()

    assert results == [
        CheckResult("account_hardening", "Guest", "WARN", "could not read account enabled state"),
        CheckResult("account_hardening", "Administrator", "WARN", "could not read account enabled state"),
        CheckResult("account_hardening", "main_user", "WARN", "USERNAME was not available"),
        CheckResult("account_policy", "net_accounts", "WARN", "could not read net accounts policy"),
    ]


def test_run_command_returns_joined_stdout_and_stderr(monkeypatch):
    class CompletedProcess:
        returncode = 0
        stdout = "primary output\n"
        stderr = "secondary output\n"

    monkeypatch.setattr(hardening_checks.subprocess, "run", lambda *args, **kwargs: CompletedProcess())

    returncode, output = hardening_checks._run_command(["net", "accounts"])

    assert returncode == 0
    assert output == "primary output\nsecondary output"


def test_get_local_user_with_powershell_returns_none_when_subprocess_command_is_missing(monkeypatch):
    monkeypatch.setattr(hardening_checks.shutil, "which", lambda command: "powershell" if command == "powershell" else None)

    def fake_run(*args, **kwargs):
        raise FileNotFoundError("powershell not found")

    monkeypatch.setattr(hardening_checks.subprocess, "run", fake_run)

    result = hardening_checks._get_local_user_with_powershell("Guest")

    assert result is None


def test_get_net_accounts_policy_returns_none_when_subprocess_fails(monkeypatch):
    def fake_run(*args, **kwargs):
        raise hardening_checks.subprocess.CalledProcessError(returncode=1, cmd=args[0])

    monkeypatch.setattr(hardening_checks.subprocess, "run", fake_run)

    result = hardening_checks._get_net_accounts_policy()

    assert result is None


def test_get_local_user_with_net_parses_enabled_fixture(monkeypatch):
    output = (FIXTURES_DIR / "windows-net-user-enabled.txt").read_text(encoding="utf-8")

    monkeypatch.setattr(hardening_checks, "_run_command", lambda command: (0, output))

    result = hardening_checks._get_local_user_with_net("Guest")

    assert result == hardening_checks.LocalUserState(
        name="Guest",
        enabled=True,
        password_required=False,
    )


def test_get_local_user_with_net_parses_disabled_fixture(monkeypatch):
    output = (FIXTURES_DIR / "windows-net-user-disabled.txt").read_text(encoding="utf-8")

    monkeypatch.setattr(hardening_checks, "_run_command", lambda command: (0, output))

    result = hardening_checks._get_local_user_with_net("Administrator")

    assert result == hardening_checks.LocalUserState(
        name="Administrator",
        enabled=False,
        password_required=True,
    )


def test_get_net_accounts_policy_parses_baseline_ok_fixture(monkeypatch):
    output = (FIXTURES_DIR / "windows-net-accounts-baseline-ok.txt").read_text(encoding="utf-8")

    monkeypatch.setattr(hardening_checks, "_run_command", lambda command: (0, output))

    result = hardening_checks._get_net_accounts_policy()

    assert result == hardening_checks.NetAccountsPolicy(
        min_password_length=14,
        lockout_threshold=5,
        lockout_duration=15,
        lockout_window=15,
    )


def test_get_net_accounts_policy_parses_weak_fixture(monkeypatch):
    output = (FIXTURES_DIR / "windows-net-accounts-baseline-weak.txt").read_text(encoding="utf-8")

    monkeypatch.setattr(hardening_checks, "_run_command", lambda command: (0, output))

    result = hardening_checks._get_net_accounts_policy()

    assert result == hardening_checks.NetAccountsPolicy(
        min_password_length=0,
        lockout_threshold=0,
        lockout_duration=0,
        lockout_window=0,
    )


def test_get_local_user_with_powershell_returns_none_for_unexpected_output(monkeypatch):
    monkeypatch.setattr(hardening_checks.shutil, "which", lambda command: "powershell" if command == "powershell" else None)

    class CompletedProcess:
        returncode = 0
        stdout = "not-json"
        stderr = ""

    monkeypatch.setattr(hardening_checks.subprocess, "run", lambda *args, **kwargs: CompletedProcess())

    result = hardening_checks._get_local_user_with_powershell("Administrator")

    assert result is None


def test_extract_int_value_handles_none_and_numeric_values():
    assert hardening_checks._extract_int_value("Some other label 5", "Minimum password length") is None
    assert hardening_checks._extract_int_value("Minimum password length               None", "Minimum password length") == 0
    assert hardening_checks._extract_int_value("Lockout threshold                    Never", "Lockout threshold") == 0
    assert hardening_checks._extract_int_value("Minimum password length               14", "Minimum password length") == 14


def test_policy_checks_warn_when_value_is_missing():
    assert hardening_checks._check_min_password_length(None) == CheckResult(
        "account_policy",
        "min_password_length",
        "WARN",
        "could not read policy",
    )
    assert hardening_checks._check_lockout_threshold(None) == CheckResult(
        "account_policy",
        "lockout_threshold",
        "WARN",
        "could not read policy",
    )
    assert hardening_checks._check_lockout_duration(None) == CheckResult(
        "account_policy",
        "lockout_duration",
        "WARN",
        "could not read policy",
    )
    assert hardening_checks._check_lockout_window(None) == CheckResult(
        "account_policy",
        "lockout_window",
        "WARN",
        "could not read policy",
    )


def test_policy_checks_fail_when_values_do_not_meet_baseline():
    assert hardening_checks._check_min_password_length(0) == CheckResult(
        "account_policy",
        "min_password_length",
        "FAIL",
        "Minimum password length is 0; required >= 12",
        {"actual": 0, "required": ">=12"},
    )
    assert hardening_checks._check_lockout_threshold(0) == CheckResult(
        "account_policy",
        "lockout_threshold",
        "FAIL",
        "Lockout threshold is 0; required 1-10",
        {"actual": 0, "required": "1-10"},
    )
    assert hardening_checks._check_lockout_duration(0) == CheckResult(
        "account_policy",
        "lockout_duration",
        "FAIL",
        "Lockout duration is 0 minutes; required >= 10",
        {"actual": 0, "required": ">=10", "unit": "minutes"},
    )
    assert hardening_checks._check_lockout_window(0) == CheckResult(
        "account_policy",
        "lockout_window",
        "FAIL",
        "Lockout observation window is 0 minutes; required >= 10",
        {"actual": 0, "required": ">=10", "unit": "minutes"},
    )


def test_policy_checks_ok_when_values_meet_baseline():
    assert hardening_checks._check_min_password_length(12).status == "OK"
    assert hardening_checks._check_lockout_threshold(5).status == "OK"
    assert hardening_checks._check_lockout_duration(10).status == "OK"
    assert hardening_checks._check_lockout_window(10).status == "OK"
