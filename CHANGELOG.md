# Changelog

All notable changes will be recorded here.

## 0.1.0a2 - Unreleased

- Add a deterministic content-derived CycloneDX serial number and run the exact
  SBOM attestation-format preflight in normal CI.

- Added deterministic, resumable, shardable corpus generation and a recorded
  10,000-fingerprint official-validation gate.
- Added nine-kind finding taxonomy, real/synthetic classification, semantic
  comparison, complete provenance, strict schemas, and deterministic capsules.
- Added safe-by-default replay authority: verification never executes, local
  commands require a replacement or explicit unsafe opt-in, and containers are
  digest-pinned, networkless, bounded, and daemon-cleaned.
- Added Windows Job Object and POSIX process-group containment, hostile archive,
  JSON, XML, path, junction, timeout, output, process-tree, and target
  substitution regressions.
- Added five pinned open-source importer adapters and locally retained three
  private, anonymized, five-times-reproduced compatibility observations.
- Added Python 3.11-3.13 / Ubuntu-macOS-Windows CI, hash-locked CI
  dependencies, release documentation, benchmark, support policy, and
  compatibility policy.
- Hardened failure reduction to preserve the exact observed signature, bound
  real records and capsules to complete provenance, and closed container output
  accounting gaps by mounting only one declared output file.
- Added clean-root reproducible builds, exact-SHA successful-CI release gating,
  least-privilege split publication jobs, package-member inventory, and SBOM
  coverage for bundled validation artifacts.
- Hash normalized validation-report semantics rather than volatile KoSIT
  timestamps and workspace paths.
- Reject nondeterministic complete observations during final reproduction.
- Retry bounded workspace accounting only when an entry vanishes during a
  concurrent scan; persistent churn and all other inspection failures remain
  fail-closed.
- Update Hatchling to 1.32.0 with a regenerated hash lock and pin reviewed attestation,
  artifact-upload, and PyPI publication actions to verified upstream commits.
- Document the private maintainer-disclosure handoff without publishing importer
  mappings or finding capsules.

## 0.1.0a1 - Not published

- The immutable release tag was created, but publication stopped before artifact
  upload, PyPI, or GitHub release creation when the SBOM attestation preflight
  rejected the reproducible CycloneDX document.
