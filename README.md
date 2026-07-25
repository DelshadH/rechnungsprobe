# Rechnungsprobe

**Your invoice is valid. Is your importer?**

Rechnungsprobe is a pre-release command-line compatibility tester for German
e-invoice software. It starts with an XRechnung UBL seed, applies deterministic
semantic mutations, validates every candidate with pinned official KoSIT
artifacts, sends valid candidates to a black-box importer, and reduces a matching
failure to a still-valid 1-minimal reproduction under its declared operations.

A validator asks whether an invoice follows a profile. Rechnungsprobe asks
whether receiving software accepts and preserves the valid invoices it may
encounter.

> **Status:** the end-to-end vertical slice is implemented, but this is still
> pre-0.1 research software. It has one bundled seed and no responsibly disclosed
> findings against real importers. It is not a compliance, tax, legal, or
> accounting tool.

## Requirements

- Python 3.11–3.13.
- A Java runtime available as `java` for the bundled KoSIT validator.
- Docker only when using the container target runner.

The supported profile is pinned as
`xrechnung-ubl-3.0.2-2026-01-31`: KoSIT validator 1.6.2 and XRechnung
configuration 2026-01-31. Their versions, sources, licenses, and SHA-256 values
are recorded in [docs/research.md](docs/research.md) and verified before use.
Campaigns do not fetch profile artifacts from the network.

## Install and run

```bash
python -m pip install -e ".[dev]"

rechnungsprobe fuzz \
  --output run \
  --count 20 \
  --predicate crash \
  -- python importer.py
```

Everything after `--` is an argument vector; Rechnungsprobe does not invoke a
shell. For a local target, `--input-mode file` appends the fixed filename
`input.xml` to the command. A container file target mounts the invoice read-only
at `/input/invoice.xml`; its command must name that path explicitly. For example:

```bash
rechnungsprobe fuzz \
  --output run \
  --container registry.example/importer@sha256:<64-hex-digest> \
  --input-mode file \
  --predicate crash \
  -- importer-command /input/invoice.xml
```

Container images must be digest-pinned. The Docker runner disables networking,
uses a read-only root filesystem, drops capabilities and privileges, and applies
resource limits. The local runner applies time, CPU, memory, process, file, and
output bounds, but it is not a hard host sandbox and does not disable target
network access.

Other predicates are `timeout`, bounded stdout `json`, `output-invalid`, and
declared `field-loss`. The latter two require `--output-file`; field loss also
requires one or more `--field` declarations.

Each campaign writes deterministic corpus metadata and XML cases, `result.json`,
and `junit.xml`. The first stable finding also produces a deterministic
`.rechnungsprobe` capsule containing the reduced invoice, replay specification,
and reports.

```bash
rechnungsprobe verify run/case-000000.rechnungsprobe
rechnungsprobe replay run/case-000000.rechnungsprobe
```

`verify` checks the bounded archive, hashes, canonical reports, invoice structure,
and recorded metadata. `replay` additionally revalidates the invoice with the
pinned official profile and reruns the exact recorded target and predicate.
Because capsules are untrusted, replaying a local-process target requires the
explicit `--allow-local-target` flag; inspect the verified metadata first.
Replay rejects resource policies above fixed safety caps and verifies the target
executable/image, command, and I/O configuration digest before execution.

Exit status is `0` for a clean campaign or reproduced replay, `1` when a campaign
finds a match or a replay no longer matches, and `2` for an operational or
security error.

The first release remains intentionally limited to one XRechnung UBL profile.
It excludes a GUI, Peppol transport, invoice authoring, ZUGFeRD, PDF rendering,
tax advice, and accounting-system connectors. The outstanding release evidence
is tracked in [docs/quality-plan.md](docs/quality-plan.md).

## Development

```bash
python -m pytest
python -m ruff check .
python -m mypy
python -m build
```

Apache-2.0 licensed.
