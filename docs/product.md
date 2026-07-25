# Rechnungsprobe

## Product

Rechnungsprobe is a validity-preserving property-based compatibility tester and
failure minimizer for German e-invoice importers, starting with XRechnung UBL.

```bash
rechnungsprobe fuzz \
  --output run \
  --count 20 \
  --predicate crash \
  -- python importer.py
```

It begins with a known invoice seed, applies typed semantic mutations, validates
every result under a pinned official profile, sends valid candidates to a
declared black-box importer, and minimizes a matching crash, timeout, invalid
round-trip document, JSON condition, or declared material field loss.

Validators and fixed conformance suites answer “does this invoice comply?”
Rechnungsprobe asks the operational inverse: “does my software accept and
preserve the compliant invoices it may encounter?”

## Current state

The pre-0.1 vertical slice is implemented for XRechnung 3.0.2 UBL Invoice using
KoSIT validator 1.6.2 and configuration 2026-01-31. It includes:

- one bundled official seed and twenty deterministic typed mutators;
- official validation before importer execution and during every reduction;
- bounded local and digest-pinned Docker targets;
- crash, timeout, bounded JSON, output-validity, and declared field-loss
  predicates;
- structure-aware reduction, an independent 1-minimality check, repeated
  reproduction, canonical JSON/JUnit output, deterministic capsules, integrity
  verification, and exact replay.

This is not yet a product release. It has not met the real-importer, twenty-seed,
cross-version, container-evidence, or full security-scan gates in
[quality-plan.md](quality-plan.md). There are no public third-party findings.

## Distinctive proof

A useful finding must show all of the following:

1. The original and reduced invoices pass the named pinned official profile.
2. The same declared importer behavior persists under one exact predicate.
3. The reducer reaches 1-minimality under its declared invoice operations.
4. The behavior reproduces repeatedly against an unchanged target digest.
5. The capsule records the profile, command, predicate, resource policy, hashes,
   reports, and replay configuration.

The claim is importer compatibility under a named profile—not tax, legal, or
accounting correctness.

## Scope through 0.1

- XRechnung UBL only; one pinned profile/version.
- Twenty licensed seed invoices covering common business cases.
- At least twelve released constraint-aware semantic mutators.
- Black-box stdin/file targets in a bounded local process or isolated container.
- Deterministic corpus, JSON/JUnit output, and one-command issue capsules.
- Responsible disclosure for every real third-party finding.

No GUI, Peppol transport, tax/legal advice, PDF rendering, ZUGFeRD, invoice
authoring UI, SaaS, or accounting-system connectors.

## Hard proof gates

- 10,000 unique canonical semantic fingerprints all differ materially from their
  seed, cover every released mutator and declared interaction bucket, and pass
  the pinned official profile before importer execution.
- At least three independently classified importer failures or meaningful
  round-trip losses across at least two real open-source importer projects.
  Duplicate manifestations of one root cause count once; synthetic-only evidence
  does not qualify.
- Every published finding minimizes to a still-valid invoice and reproduces five
  times from a clean digest-pinned container.
- Shrinking is 1-minimal under declared invoice-node/value operations.
- Identical recorded inputs produce byte-identical corpus and result metadata.
- XXE, traversal, archive bombs, output floods, resource exhaustion, and command
  timeouts are rejected or contained.

## Positioning

Targeted searches on 24 July 2026 found validators, generators, readers, fixed
XRechnung suites, and the adjacent Danish OIOFuzz research project, but no
verified direct match for this complete product boundary. That is a dated search,
not proof of novelty. Rechnungsprobe must not be described as the first invoice
or UBL fuzzer. Sources and the feature comparison are in
[research.md](research.md).

Working name: `Rechnungsprobe`; package and executable: `rechnungsprobe`.
Tagline: **“Your invoice is valid. Is your importer?”**
