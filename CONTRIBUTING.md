# Contributing

Rechnungsprobe works with untrusted XML and executes untrusted importer targets.
Read `docs/security-model.md` before changing parsers, validators, runners,
predicates, archives, or output handling.

Keep pull requests narrow and start with a failing fixture. Mutators must prove
their output remains valid. Shrinkers must preserve both validity and the target
failure. Runner changes need timeout, output-limit, path, environment, and process
cleanup tests.

Run:

```bash
python -m pytest
python -m ruff check .
python -m mypy
```

Do not include real customer invoices or private importer data in tests or issues.
