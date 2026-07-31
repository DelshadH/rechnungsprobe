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
- [x] Three genuine findings across three importers are officially validated,
  reduced, independently verified as 1-minimal, and reproduced five times.
  Public mapping remains anonymized pending maintainer notification.
- [x] Verification is non-executing; capsule local commands have no default
  authority; trusted local execution is conspicuously non-isolated.
- [x] Container execution is networkless, read-only, unprivileged, bounded, and
  explicitly cleans daemon-owned containers after client timeout or exit.
- [x] Malformed XML/JSON/ZIP, XXE/DTD/XInclude, traversal, symlink/junction,
  archive bomb, command substitution, output/file flood, timeout, process tree,
  and target file substitution cases have regressions.

## Release-candidate gates

- [ ] Exact-head CI passes Python 3.11-3.13 on Ubuntu, macOS, and Windows,
  including installed-wheel smoke tests.
- [ ] Ruff, strict mypy, package build, package inventory, reproducible
  wheel/sdist, dependency/secret/license/deep security scans, SBOM, checksums,
  and attestations pass at the frozen release SHA.
- [ ] A clean public clone proves install, help, version, corpus, verify, and
  replay flows without source-tree dependence.
- [ ] Three fresh-context independent reviewers and a separate adjudicator
  review the frozen SHA; validated P0/P1 and release-blocking P2 findings are
  remediated failing-first, followed by a second adversarial review.
- [ ] Canonical `main`, CI-only no-force-push/no-deletion protection, protected
  release tags, and the exact-tag least-privilege OIDC publication workflow are
  configured.
- [ ] PyPI authentication and trusted-publisher readiness are probed without
  exposing or inventing credentials.

The release remains blocked until every unchecked gate above is complete.
Creating a tag, GitHub release, or registry publication additionally requires
the owner's final `PUBLISH` decision.
