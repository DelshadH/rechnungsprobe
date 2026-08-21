# Rechnungsprobe 0.1.0a2 benchmark

## Scope

This benchmark tests XRechnung UBL importer compatibility. It does not assess
tax, legal, or accounting correctness. Results are observations of exact
open-source versions under the documented resource policy, not claims about
newer versions or hosted services.

## Profile and corpus

- Profile: XRechnung UBL 3.0.2 configuration dated 2026-01-31.
- Validator: KoSIT validator 1.6.2.
- Corpus seed: campaign seed 42.
- Corpus size: 10,000 invoices with 10,000 unique semantic fingerprints.
- Coverage: all 20 released mutators and all 380 ordered two-mutator
  interaction buckets.
- Corpus root:
  `sha256:bfe4b154a8d8d2d2776b8cd85f45d613c3e17ed7630711f96d35448470a624c7`.
- Validation root:
  `sha256:d45bde3dd0eae2182560173ef0b6fb1a4c36c7d398aa3c774efa992ec2651e88`.

The machine-readable environment, artifact hashes, coverage, and roots are in
`research/evidence/corpus-gate.json`.

## Importer selection

Five active UBL readers with practical library or CLI adapters were selected:
Jasy, esvit/einvoicing, num-num/ubl-invoice, josemmo/einvoicing, and ph-ubl.
The exact source commits, package integrity values, licenses, base-image
digests, lockfiles, and content-addressed research images are recorded in
`research/importers/catalog.json`.

Every campaign target ran with no network, a read-only root filesystem, dropped
capabilities, `no-new-privileges`, an unprivileged user, bounded processes,
memory, CPU, time, output, and file growth. Source invoices were validated
before target execution. Candidate reductions were revalidated, and final
findings were replayed five times from clean workspaces.

## Results

Three locally reproduced compatibility observations were retained across three
importers:

| Evidence | Classification | Reproductions | 1-minimal |
| --- | --- | ---: | --- |
| RP-2026-001 | crash | 5 | yes |
| RP-2026-002 | crash during round-trip | 5 | yes |
| RP-2026-003 | invalid round-trip / preservation loss | 5 | yes |

The public branch keeps the mapping and capsules private until maintainers have
a reasonable notification path. Capsule hashes and classifications in
`research/results.json` are cryptographic commitments, not enough to reproduce
or independently audit the observations. The private capsules are explicitly
not release assets or Python package data.

## Dependency review

Jasy reported no npm advisories. Both Composer graphs reported no advisories or
abandoned packages. Esvit's dependency graph includes
GHSA-gh4j-gqv2-49f6, a moderate XML-builder injection advisory. Its first
patched release is the incompatible `fast-xml-parser` 5.7.0 major, outside
`einvoicing` 0.0.3's declared 4.x range. Rechnungsprobe exercises only the
reader, in a networkless read-only container, but the advisory remains a stated
research-target limitation rather than being suppressed or overridden.

## Limitations

- The campaign is compatibility research, not proof that an importer is
  generally incorrect.
- Only one pinned XRechnung profile and UBL syntax are covered.
- Public evidence is deliberately anonymized before maintainer notification and
  does not independently substantiate the three private observations.
- Container image IDs identify the reviewed local build products. Base images,
  direct versions, and available lockfiles are pinned, but transitive build
  graphs are not uniformly checksum-locked and byte-identical image rebuilds
  are not claimed. No public container registry is claimed.
- KoSIT process startup dominates reduction time. Batched validation preserves
  deterministic greedy order but does not make minimization globally optimal.
- The reported minimum is 1-minimal only under `invoice-node-value-v1`.

## Reproduction

Build an adapter with `docker build --provenance=false --pull=false` from the
pinned inputs to obtain a functionally comparable target; matching the recorded
local image ID is not promised. Exact observation replay additionally requires
the corresponding private capsule and recorded image, so it is unavailable
from the public branch until disclosure. Capsule verification is non-executing.
Container replay remains networkless and bounded; local replay requires a
replacement command or an explicit unsafe opt-in.
