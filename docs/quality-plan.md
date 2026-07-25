# Quality plan

## Completed feasibility work

- Dated collision and adjacent-tool searches are recorded in
  [research.md](research.md), including OIOFuzz non-overlap.
- One official XRechnung 3.0.2 UBL profile is pinned with source, license, and
  SHA-256 metadata; artifacts and one official seed are vendored.
- Six importer projects were reviewed for harness feasibility. Mustangproject
  and ph-ubl are the first intended real targets.
- The vertical slice now generates deterministic semantic candidates, validates
  them before target execution, evaluates five predicate types, revalidates while
  shrinking, checks 1-minimality, reproduces, reports, packages, verifies, and
  replays findings.
- Unit and integration fixtures cover malformed XML, XXE/DTD/XInclude,
  traversal, symlinks, duplicate/archive-bomb members, process time/output/file
  bounds, digest pinning, validator artifact tampering, reports, capsules, and
  replay.

These facts establish an implemented pre-release vertical slice, not a 0.1
release.

## Release gates

- [ ] Validate 10,000 unique semantic fingerprints with the pinned official
  profile, proving material seed differences, every released mutator, and
  declared interaction coverage. The test suite already checks deterministic
  generation and uniqueness for 10,000 candidates; the full official-validation
  evidence run is still outstanding.
- [ ] Expand from one bundled seed to twenty licensed, representative invoices.
- [ ] Find at least three independently classified real failures or meaningful
  round-trip losses across at least two open-source importers. Synthetic-only
  findings do not qualify.
- [ ] Reproduce every publishable finding five times from a clean,
  digest-pinned container after 1-minimal reduction and private scope review.
- [ ] Prove byte-identical corpus and result metadata from the same recorded
  inputs in independent clean environments.
- [ ] Reproduce the complete Python 3.11–3.13
  install/test/build/CLI/replay matrix in clean-checkout CI. On 25 July 2026,
  isolated local environments for all three versions each passed 155 tests
  (plus one Windows-only POSIX permission skip), built wheel/sdist, installed
  the wheel, and smoke-tested the CLI.
- [ ] Exercise the Docker isolation path against adversarial fixtures on the
  supported host platforms. The Docker client was present during the local
  review, but its daemon was not running, so no container integration result is
  claimed.
- [ ] Complete dependency, secret, license, and deep security scans. The latest
  Codex deep-security run was blocked by service usage limits before producing a
  canonical report; it must be rerun rather than treated as passed. The
  25 July 2026 Python runtime audit found no known vulnerabilities, the
  development environment audit was clean after updating its unrelated
  `setuptools`, source-focused Bandit-compatible Ruff rules passed, and a
  repository secret-pattern check found no matches. The subprocess and
  ElementTree rules were manually reviewed against the validated argument-vector
  runner and Expat security preflight. The vendored Java artifact and a canonical
  full scan remain outstanding.
- [ ] Repeat package/name/trademark and ecosystem searches immediately before
  publication.

## Required clean-checkout commands

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m mypy
python -m build
rechnungsprobe --version
rechnungsprobe fuzz --help
rechnungsprobe replay --help
rechnungsprobe verify --help
```

Release reports must continue to distinguish profile/format validity from tax,
legal, and accounting correctness.
