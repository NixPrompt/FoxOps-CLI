# FoxOps Manual Smoke Tests

Use these checks after feature work, before merging larger branches, or when
validating a fresh clone. They are read-only.

## Baseline

```powershell
python .\monitor.py --help
python -m pytest
```

Expected:

- `--help` exits successfully and lists CLI options.
- pytest passes on the local runner.

## Network JSON

```powershell
python .\monitor.py --host 127.0.0.1 --port 443 --timeout 1 --output json
```

Expected:

- JSON top-level keys are `metadata`, `summary`, `groups`, `results`.
- `groups.hosts` contains `127.0.0.1`.
- `groups.host_summaries` contains `127.0.0.1`.
- Exit code is `0` if all checks are `OK`/`WARN`, or `1` if any check is `FAIL`.

## Evidence File

```powershell
python .\monitor.py --host 127.0.0.1 --port 443 --timeout 1 --output json --output-file .\reports\smoke.json
```

Expected:

- The JSON printed to stdout matches `reports\smoke.json`.
- Parent directories are created when possible.
- `--output-file` without `--output json` exits with code `2`.

## Windows Hardening

Run from Windows PowerShell:

```powershell
python .\monitor.py --hardening --output json
```

Expected:

- The command is read-only.
- Results report observed local account and password-policy posture.
- Findings do not claim the system is secure or remediated.

## WSL Hardening Boundary

Run from WSL:

```bash
python ./monitor.py --hardening --output json
```

Expected:

- The command exits cleanly.
- The hardening result is a `WARN` capability skip.
- The result includes `source=wsl`.
- The message tells the operator to run from Windows PowerShell for Windows
  hardening authority.

## Sample JSON

```powershell
python -m json.tool .\examples\sample-output.json
```

Expected:

- The file parses as valid JSON.
- It contains `metadata`, `summary`, `groups`, and `results`.
- `groups.hosts` remains grouped result lists.
- `groups.host_summaries` remains grouped status counts.
