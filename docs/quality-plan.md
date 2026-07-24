# Quality plan

- Search GitHub, GitLab, Maven Central, npm, PyPI, crates.io, Docker Hub, and general web for combinations of XRechnung/EN16931 with fuzz, property-based, mutation, shrink, delta-debugging, importer testing, round-trip, and conformance.
- Inspect current KoSIT validator/test-suite capabilities for generative or minimization features.
- Read OIOFuzz and document feature-by-feature non-overlap; kill the idea if the implementation reduces to a German port of that work.
- Inspect at least five active open-source invoice parsers/importers and verify a command-line test harness is practical.
- Confirm redistribution/licensing of official schemas, Schematron artifacts, and seed invoices.
- Confirm the selected XRechnung profile/version and its supported UBL syntax.
- Run the 12-hour kill-gate vertical slice before repository polish. Require three distinct semantic fingerprints, not formatting-only mutants.
- Rename before publication if a direct product/name collision appears.

## Release gates

- 10,000 unique semantic fingerprints, materially different from their seed,
  covering every released mutator and interaction bucket, pass the pinned profile.
- At least three independently classified real failures or meaningful round-trip
  losses across at least two open-source importers; synthetic-only findings do
  not qualify.
- Every published finding minimizes to a still-valid invoice, is 1-minimal under
  declared operations, and reproduces five times from a clean container.
- The same recorded inputs produce byte-identical corpus and result metadata.
- XXE, path traversal, archive bombs, command timeout, resource exhaustion, and
  output-flood fixtures are rejected or contained.
- A clean Python 3.11–3.13 matrix installs, tests, builds wheel/sdist, smoke-tests
  the CLI, replays a finding capsule, and verifies its hashes.
