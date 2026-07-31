# Rechnungsprobe product boundary

Rechnungsprobe is a validity-preserving property-based compatibility tester and
failure minimizer for XRechnung UBL importers.

It begins with a known invoice seed, applies typed semantic mutations, validates
every result under a pinned official profile, sends only valid candidates to a
declared black-box importer, and minimizes a matching crash, timeout, invalid
round-trip document, JSON condition, or declared material field loss.

Validators answer “does this invoice comply?” Rechnungsprobe asks “does this
importer accept and preserve the valid invoices it may encounter?”

## Current alpha candidate

The `0.1.0a1` candidate supports XRechnung 3.0.2 UBL Invoice with KoSIT
validator 1.6.2 and configuration 2026-01-31. It includes:

- one licensed official seed, 20 typed mutators, and all 380 ordered two-mutator
  interaction buckets;
- a recorded official-validation gate covering 10,000 unique semantic
  fingerprints;
- bounded trusted-local and recommended content-addressed container targets;
- crash, timeout, bounded JSON, output-validity, and declared field-loss
  predicates;
- deterministic reduction, independent 1-minimality verification, repeated
  reproduction, complete provenance, JSON/JUnit reports, and bounded capsules;
- five open-source importer adapters and three private, anonymized compatibility
  observations across three importers, each locally reproduced five times and
  reported as 1-minimal. Public commitments are not independent proof.

The finding mapping remains anonymized pending a reasonable maintainer
notification path. Remaining exact-head CI, packaging, security, repository,
and independent-review gates are tracked in
[quality-plan.md](quality-plan.md).

## Distinctive proof

A retained finding shows:

1. Original and reduced source invoices pass the pinned official profile.
2. One exact importer behavior persists under one declared predicate.
3. The reducer reaches 1-minimality under `invoice-node-value-v1`.
4. The behavior reproduces repeatedly against one target digest.
5. The capsule records profile, command, predicate, policy, observations,
   hashes, and minimization proof.

The claim is importer compatibility under a named profile—not tax, legal, or
accounting correctness.

## Scope

The alpha covers XRechnung UBL and one pinned profile. It provides scriptable
stdin/file targets, deterministic corpus and result formats, and one-command
finding verification/replay.

It excludes a GUI, Peppol transport, tax or legal advice, PDF rendering,
ZUGFeRD, invoice authoring, SaaS, and production accounting connectors.

## Hard proof gates

- 10,000 materially distinct semantic fingerprints cover every released
  mutator and declared interaction bucket and pass the official profile.
- Report the actual number of private or public importer observations without
  fabricating evidence or blocking the entire alpha on a target count alone.
- Every claimed retained observation is valid, repeatedly reproduced against a
  recorded target, and 1-minimal under declared operations; public claims state
  whether the evidence is independently reproducible.
- Identical recorded inputs produce byte-identical corpus and result metadata.
- Hostile XML, JSON, archives, paths, commands, outputs, and process trees are
  rejected or contained within documented boundaries.

Targeted searches repeated on 26 July 2026 found adjacent validators,
generators, readers, suites, and OIOFuzz, but no verified direct match for this
complete boundary. This is a dated search, not a novelty claim. Rechnungsprobe
must not be called the first invoice or UBL fuzzer.
