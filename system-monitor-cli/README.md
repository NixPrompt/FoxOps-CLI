# System Monitor CLI

A small dependency-free Python CLI for basic host and port checks.

## Project Structure

```text
system-monitor-cli/
  monitor.py          # CLI entry point
  monitor_checks.py   # Reusable ping and port check functions
  README.md           # Usage notes
```

## Example Usage

Check a host with the default port `443`:

```powershell
python .\monitor.py --host example.com
```

On Windows, use `py` or a full Python path if `python` points to the Microsoft Store shim.

Check a specific port and log file:

```powershell
python .\monitor.py --host example.com --port 443 --log-file .\monitor.log
```

Use a shorter timeout:

```powershell
python .\monitor.py --host 8.8.8.8 --port 53 --timeout 2
```

Each run writes timestamped results to the selected log file and prints a short status summary.
