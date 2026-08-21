# Rechnungsprobe

**Your invoice is valid. Is your importer?**

Rechnungsprobe is a command-line compatibility tester for XRechnung UBL
importers. It creates deterministic semantic variants, validates every candidate
with pinned official KoSIT artifacts, runs a declared importer, and reduces a
matching failure to a still-valid 1-minimal reproduction under declared
operations.

Version `0.1.0a2` is a technically reviewed alpha candidate. The recorded
research gate validated 10,000 unique semantic fingerprints and locally
retained three private compatibility observations across three of five
open-source importer adapters. Public commitments do not independently
substantiate them; details remain private before maintainer notification. Rechnungsprobe does
not establish tax, legal, accounting, or general compliance correctness.

## Requirements

- CPython 3.11, 3.12, or 3.13.
- Java available as `java` for the bundled KoSIT validator.
- Docker for the recommended isolated importer path.

The only released profile is
`xrechnung-ubl-3.0.2-2026-01-31`, using KoSIT validator 1.6.2 and configuration
2026-01-31. Versions, source URLs, licenses, and SHA-256 values are pinned and
verified offline before use.

## Install

After the owner-authorized publication:

```bash
python -m pip install rechnungsprobe==0.1.0a2
rechnungsprobe --version
```

For a source checkout:

```bash
python -m pip install --require-hashes -r requirements/ci.txt
python -m pip install --no-deps --no-build-isolation .
```

## Generate and validate a corpus

```bash
rechnungsprobe corpus \
  --output corpus \
  --count 1000 \
  --seed 42

rechnungsprobe corpus-gate \
  --output gate \
  --count 10000 \
  --seed 42
```

Corpus generation is deterministic, resumable, and shardable through the Python
API. A corpus gate records the corpus root, validation root, mutator and
interaction coverage, profile identity, and execution environment.
The validation root binds each invoice digest and outcome to a normalized KoSIT
semantic-report digest; volatile report timestamps and workspace paths are
excluded.

## Test a digest-pinned container

```bash
rechnungsprobe fuzz \
  --output run \
  --count 20 \
  --seed 42 \
  --container sha256:<64-hex-local-image-id> \
  --input-mode file \
  --output-file roundtrip.xml \
  --predicate output-invalid \
  -- importer-command /input/invoice.xml
```

Registry references pinned as `name@sha256:<digest>` are also accepted. The
runner disables networking, uses a read-only root filesystem, drops
capabilities, sets `no-new-privileges`, uses an unprivileged user, and bounds
processes, memory, CPU, time, output, input, and file growth. Daemon-owned
containers are explicitly killed, removed, and checked after the Docker client
exits or times out.

Predicates are `crash`, `timeout`, bounded stdout `json`, `output-invalid`, and
declared `field-loss`. Output predicates require `--output-file`; field loss
also requires one or more `--field` values.

## Trusted local execution

Local commands are non-isolated and can access the host filesystem and network.
They require explicit current-user authority:

```bash
rechnungsprobe fuzz \
  --trusted-local \
  --output run \
  --predicate crash \
  -- python importer.py
```

Rechnungsprobe uses argument vectors rather than a shell, cleans the inherited
environment, stages regular-file arguments into the workspace, and applies
resource bounds. These measures do not turn local execution into a sandbox.

## Verify and replay

```bash
rechnungsprobe verify finding.rechnungsprobe
rechnungsprobe replay finding.rechnungsprobe
```

`verify` is strictly non-executing. It checks the bounded archive, member order,
hashes, canonical reports, safe XML, semantic fingerprint, profile, predicate,
and target metadata.

Container capsules replay through the bounded networkless container path. A
capsule-described local command never executes by default. Supply a trusted
replacement:

```bash
rechnungsprobe replay finding.rechnungsprobe \
  --replacement-command python reviewed-importer.py
```

The alternative
`--unsafe-use-capsule-local-command` is deliberately conspicuous and executes
the capsule-described host command without isolation.

Exit status is `0` for a clean campaign or reproduced replay, `1` when a
campaign finds a match or replay no longer matches, and `2` for an operational
or security error.

## Evidence and limitations

- [Benchmark](docs/benchmark.md)
- [Methodology](docs/methodology.md)
- [Security model](docs/security-model.md)
- [Finding format](docs/finding-format.md)
- [Responsible disclosure](docs/disclosure.md)
- [Compatibility policy](docs/compatibility.md)
- [Quality plan](docs/quality-plan.md)

The alpha covers one XRechnung UBL profile. It excludes a GUI, Peppol transport,
invoice authoring, ZUGFeRD/PDF processing, tax advice, and production accounting
connectors. Minimality is 1-minimal under `invoice-node-value-v1`, not globally
minimal.

## Development

```bash
python -m pytest
python -m ruff check .
python -m mypy
python -m build --no-isolation
```

Apache-2.0 licensed. See [SUPPORT.md](SUPPORT.md) and [SECURITY.md](SECURITY.md).
