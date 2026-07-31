# Rechnungsprobe 0.1.0a1 benchmark

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
  `sha256:7fb3a04261779dc211f277f26ec7626636a954b24f23326cd318fb681faa511b`.
- Validation root:
  `sha256:1d85b79045877e66c1ea369bfc8977e5bd383ade1b649fbbeed438b5c1ecf11c`.

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

Three genuine findings were retained across three importers:

| Evidence | Classification | Reproductions | 1-minimal |
| --- | --- | ---: | --- |
| RP-2026-001 | crash | 5 | yes |
| RP-2026-002 | crash during round-trip | 5 | yes |
| RP-2026-003 | invalid round-trip / preservation loss | 5 | yes |

The public branch keeps the mapping anonymized until maintainers have a
reasonable notification path. Capsule hashes and classifications are in
`research/results.json`; disclosure-safe capsules are release assets, not
Python package data.

## Dependency review

Jasy reported no npm advisories. Both Composer graphs reported no advisories or
abandoned packages. Esvit's dependency graph includes
GHSA-gh4j-gqv2-49f6, a moderate XML-builder injection advisory with no upstream
fix available for that package version. Rechnungsprobe exercises only its
reader, in a networkless read-only container, but the advisory remains a stated
research-target limitation rather than being suppressed.

## Limitations

- The campaign is compatibility research, not proof that an importer is
  generally incorrect.
- Only one pinned XRechnung profile and UBL syntax are covered.
- Public evidence is deliberately anonymized before maintainer notification.
- Container image IDs are local content-addressed build products; rebuild
  inputs are pinned, but no public container registry is claimed.
- KoSIT process startup dominates reduction time. Batched validation preserves
  deterministic greedy order but does not make minimization globally optimal.
- The reported minimum is 1-minimal only under `invoice-node-value-v1`.

## Reproduction

Build an adapter with `docker build --provenance=false --pull=false`, verify its
image ID against the catalog, then use `rechnungsprobe replay` with the capsule.
Verification is non-executing. Container replay remains networkless and bounded;
local replay requires a replacement command or an explicit unsafe opt-in.
