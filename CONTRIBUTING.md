# Contributing

1. Fork the repository.
2. Create a focused branch.
3. Add or update tests for behavior changes.
4. Run `pytest -q`.
5. Run `secureconfig-audit scan secureconfig_audit`.
6. Open a pull request explaining the change.

Please keep the scanner deterministic and avoid network access in the core package.
