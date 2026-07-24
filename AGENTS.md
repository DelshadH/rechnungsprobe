# Repository instructions

## Goal

Build Rechnungsprobe into a secure, reproducible command-line compatibility
tester for XRechnung UBL importers. Its distinctive result is a small invoice
that is still valid under a pinned official profile and still demonstrates the
same importer failure or material round-trip loss.

## Read first

1. `README.md`
2. `docs/product.md`
3. `docs/security-model.md`
4. `docs/architecture.md`
5. `docs/quality-plan.md`
6. `docs/research.md`

## Commands

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m mypy
python -m build
```

Support Python 3.11 through 3.13. Keep the CLI scriptable, deterministic, and
usable in CI. Prefer small modules and explicit data formats.

## Product rules

- Begin with one pinned XRechnung UBL profile and official validation artifacts.
  Record version, source URL, license, and SHA-256; never silently fetch “latest.”
- A mutant counts only after validation. Blind XML edits and invalid random
  documents are not product findings.
- Implement semantic mutators against typed invoice concepts and cross-field
  constraints. Every mutator needs positive and negative fixtures.
- Shrinking must revalidate every candidate and preserve the exact failure
  predicate. Report 1-minimality under declared operations, not a global minimum.
- Same inputs, seed, profile artifact, mutator version, target digest, command,
  and resource policy must produce byte-identical corpus and result metadata.
- Separate format validity from tax, legal, and accounting correctness in every
  report and document.
- Use plain German or English technical prose. Avoid filler, exaggerated novelty,
  and claims not backed by real open-source importer findings.

## Security boundaries

- Treat invoice XML, profile artifacts, archives, target output, predicates,
  commands, and filesystem paths as untrusted.
- Disable DTDs, external entities, XInclude, and network access in XML parsing and
  validation. Bound document depth, attributes, text, attachments, and expansion.
- Reject path traversal, symbolic-link escapes, decompression bombs, output
  floods, and oversized result capsules.
- Run importers in disposable directories or containers with no secrets, no
  network by default, a read-only input mount where possible, dropped privileges,
  and strict CPU, memory, process, time, and output limits.
- Prefer an argument vector over shell execution. If a shell command is supported,
  label the trust boundary clearly and never interpolate invoice data into it.
- Do not publish a third-party finding before reproducing it, checking scope, and
  giving the maintainer a reasonable private disclosure path.
- Review new dependencies for license, maintenance, install-time behavior, and
  known vulnerabilities.

## Completion standard

A feature is complete only when the real CLI path works from a clean checkout,
tests include malformed and adversarial inputs, documentation matches behavior,
and its claim is reproducible. A 0.1 release additionally requires the gates in
`docs/quality-plan.md`, dependency and secret scans, container isolation tests,
and responsible-disclosure handling for every real finding.
