# Rechnungsprobe

**Your invoice is valid. Is your importer?**

Rechnungsprobe is a planned property-based compatibility tester for German
e-invoice software. It starts with valid XRechnung UBL invoices, applies semantic
changes that remain valid under a pinned profile, sends them to a black-box
importer, and shrinks failures into small, still-valid reproductions.

It answers a different question from a validator:

- a validator asks whether an invoice follows the format and business rules;
- Rechnungsprobe asks whether receiving software accepts and preserves the valid
  invoices it may encounter.

> **Status:** pre-0.1 research and development. The package and CLI shell are
> runnable, but invoice generation, validation, target execution, and shrinking
> are not implemented yet. Do not use it for compliance, tax, or accounting
> decisions.

## Intended command

```bash
rechnungsprobe fuzz \
  --profile xrechnung-ubl \
  --command 'docker run --rm -i acme/importer:pr' \
  --predicate 'jq -e .accepted'
```

A useful finding must satisfy all of these:

1. the mutated invoice passes the pinned official validation profile;
2. the importer failure or round-trip field loss reproduces consistently;
3. the reduced invoice remains valid;
4. the result records the profile artifact, target image or executable, command,
   resource policy, seed, and hashes needed to reproduce it.

The first release is intentionally limited to one pinned XRechnung UBL profile.
It will not include a GUI, Peppol transport, invoice authoring, ZUGFeRD, PDF
rendering, tax advice, or accounting-system connectors.

Read [docs/product.md](docs/product.md), [docs/architecture.md](docs/architecture.md),
[docs/security-model.md](docs/security-model.md), and
[docs/quality-plan.md](docs/quality-plan.md) for the exact plan.

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m mypy
```

Apache-2.0 licensed.
