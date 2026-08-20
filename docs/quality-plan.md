# Quality plan

## Completed product and research gates

- [x] One official XRechnung 3.0.2 UBL profile is pinned with source, license,
  version, SHA-256, offline operation, corruption checks, structured report
  parsing, and bounded validator execution.
- [x] The corpus is deterministic, resumable, shardable, and covers every
  released mutator and declared ordered interaction bucket.
- [x] A recorded gate validates 10,000 invoices with 10,000 unique semantic
  fingerprints. Its corpus and validation roots and full environment record are
  in `research/evidence/corpus-gate.json`.
- [x] Five active open-source UBL readers have lock-controlled, digest-pinned
  adapters and exact source/license metadata.
- [x] Three private compatibility observations across three importers were
  locally validated, reduced, checked as 1-minimal, and reproduced five times.
  Public commitments do not independently substantiate them; mapping and
  capsules remain private pending maintainer notification.
- [x] Verification is non-executing; capsule local commands have no default
  authority; trusted local execution is conspicuously non-isolated.
- [x] Container execution is networkless, read-only, unprivileged, bounded, and
  explicitly cleans daemon-owned containers after client timeout or exit.
- [x] Malformed XML/JSON/ZIP, XXE/DTD/XInclude, traversal, symlink/junction,
  archive bomb, command substitution, output/file flood, timeout, process tree,
  and target file substitution cases have regressions.

## Release-candidate gates

- [x] Exact-head CI passes Python 3.11-3.13 on Ubuntu, macOS, and Windows,
  including installed-wheel smoke tests.
- [x] Ruff, strict mypy, package build, package inventory, reproducible
  wheel/sdist, dependency/secret/license/security scans, strict SBOM generation,
  and checksum generation pass for the frozen technical candidate.
- [x] A clean public clone proves install, help, version, corpus, verify, and
  replay flows without source-tree dependence.
- [x] Three fresh-context independent reviewers and a separate adjudicator
  review the frozen SHA; validated P0/P1 and release-blocking P2 findings are
  remediated failing-first, followed by a second adversarial review.
- [x] Canonical `main`, CI-only no-force-push/no-deletion protection, protected
  release tags, and the exact-tag least-privilege OIDC publication workflow are
  configured.
- [x] The GitHub `pypi` environment, tag-only OIDC job, and fail-closed publisher
  handoff are configured without exposing or inventing credentials. PyPI-side
  trusted-publisher state is not publicly discoverable and is not probed by an
  unauthorized upload.

## Publication-only gates

These actions are deliberately unavailable before the owner's final `PUBLISH`
decision: create the exact version tag, generate GitHub attestations in the tag
workflow, perform the OIDC registry upload, and create the GitHub release. A
`NO` decision creates none of them.

The technical candidate is ready when every release-candidate gate above is
checked. Readiness does not authorize a tag, GitHub release, or registry
publication.

## Importer-disclosure gate

- [x] The public tree contains only anonymized commitments and a documented
  private handoff process; capsules and importer mappings are excluded from
  source, package data, and release assets.
- [ ] Before any importer-linked contact or public finding, the owner verifies
  custody of the private mapping and capsule against `research/results.json`,
  repeats the clean digest-pinned replay, and selects the maintainer's private
  contact path.

The unchecked item blocks importer-linked disclosure, not an anonymized alpha
publication. See [disclosure.md](disclosure.md).
