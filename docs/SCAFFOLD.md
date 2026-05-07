# FoxOps Change Scaffold

Use this scaffold when adding checks, CLI options, output fields, examples, or
documentation. It keeps changes small, auditable, and consistent with the
read-only mission.

## Change Intent

- Operator question:
- Expected evidence:
- Runtime context:
- Out of scope:

## Safety Boundary

- Read-only commands or probes used:
- Files read:
- Files written:
- External targets contacted:
- Why this does not perform remediation:

## Implementation Shape

- Check module:
- CLI flag or input path:
- Result `name`:
- Result `target`:
- Required `details` keys:
- Status behavior:
  - `OK`:
  - `WARN`:
  - `FAIL`:
- Runtime error behavior:

## Output Contract

- Text output example:

```text
[OK] check_name.target key=value - observed condition
```

- JSON location:
- Schema compatibility notes:
- Log line expectations:

## Tests

- Unit tests:
- Integration tests:
- Fixture files:
- Failure cases:
- Cross-platform behavior:

## Documentation

- README examples updated:
- Trust boundary notes updated:
- Roadmap or TODO updated:
- Sample output updated:

## Review Checklist

- The change is read-only.
- Hosts, URLs, and files are explicitly provided by the operator.
- Output order is deterministic.
- Errors are clear and return the right exit code.
- Tests cover success and failure paths.
- Documentation matches actual CLI behavior.
