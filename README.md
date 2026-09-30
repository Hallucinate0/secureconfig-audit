# SecureConfig Audit

SecureConfig Audit is a small open-source security auditing toolkit for developers and maintainers.
It scans configuration files and environment-style inputs for common security mistakes such as
hard-coded secrets, insecure HTTP URLs, debug mode, weak passwords, permissive file permissions,
and unsafe configuration patterns.

## Why this project exists

Configuration is part of the application's attack surface, but it is often reviewed less carefully
than application code. SecureConfig Audit provides a fast, deterministic local check that can run
before a commit, in CI, or during release preparation.

## Features

- Secret and credential pattern detection
- Insecure HTTP URL detection
- Debug/development mode detection
- Weak password and token heuristics
- File permission checks
- JSON and `.env` style configuration support
- Machine-readable JSON output
- Exit codes suitable for CI
- No network access required
- Unit tests and GitHub Actions CI

## Installation

```bash
git clone https://github.com/YOUR-USERNAME/secureconfig-audit.git
cd secureconfig-audit
python -m pip install -e .
```

## Usage

```bash
secureconfig-audit scan .
```

JSON output:

```bash
secureconfig-audit scan . --format json
```

Fail CI when findings reach a selected severity:

```bash
secureconfig-audit scan . --fail-on high
```

## Example

```text
$ secureconfig-audit scan examples

HIGH   examples/.env.example:3  Potential hard-coded secret
HIGH   examples/app.json:8      Debug mode is enabled
MEDIUM examples/app.json:4      Insecure HTTP URL

3 finding(s)
```

## Security model

The scanner is intentionally local and deterministic. It does not upload files or configuration
values anywhere. Findings are heuristic and should be reviewed by a developer.

## Development

```bash
python -m pip install -e ".[dev]"
pytest -q
```

## License

MIT
