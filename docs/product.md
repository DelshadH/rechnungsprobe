# RechnungsProbe

## The idea

A validity-preserving property-based fuzzer, compatibility tester, and failure minimizer for German e-invoice importers—starting with XRechnung UBL.

```bash
rechnungsprobe fuzz \
  --profile xrechnung-ubl \
  --command 'docker run --rm -i acme/importer:pr' \
  --predicate 'jq -e .accepted'
```

It begins with officially valid invoice seeds, applies semantic mutations that remain valid under the selected schema/business-rule profile, sends each invoice to the user's importer, and minimizes any crash, rejection, misclassification, or round-trip data loss into the smallest still-valid invoice.

## Why this is a better German wedge

Validators and fixed conformance suites answer “does this invoice comply?” RechnungsProbe answers the inverse operational question: “does my software accept and preserve the wide space of invoices that are compliant?” The distinction becomes more valuable as German businesses move from controlled pilot samples to diverse B2B e-invoice traffic.

Targeted searches on 24 July 2026 found open-source validators, generators, readers, and fixed XRechnung test suites, but no direct public tool combining **XRechnung-valid semantic generation, arbitrary importer black-box execution, round-trip preservation oracles, and automatic validity-preserving shrinking**. This is a dated search result, not proof of nonexistence; repeat it before naming or launch.

Adjacent prior art must be acknowledged: the 2023 OIOFuzz thesis built a guided model-based black-box fuzzer for Danish OIOUBL/OIORASP Schematron validation. RechnungsProbe is viable only if it proves a different operational target: German XRechnung receiver/importer compatibility, semantic round-trip preservation, reproducible one-command capsules, and automatic 1-minimal reduction. Do not position it as the first invoice or UBL fuzzer.

## Killer demo

1. An invoice passes the official validation artifacts.
2. A popular or fixture importer crashes, rejects it, or loses a material field on round-trip.
3. RechnungsProbe reduces a large invoice to a tiny still-valid XML file.
4. The issue attachment contains the invoice, profile/version, exact command, predicate, and validator evidence.

## v0.1, ten-day boundary

- XRechnung UBL only; one pinned profile/version.
- Official validation artifact integration, with artifact hash/version in every result.
- Twelve validity-preserving semantic mutators.
- Black-box stdin/file command runner in Docker or local process.
- Predicates: nonzero/crash, timeout, stdout JSON expression, output XML invalid, declared field loss after round-trip.
- Structure-aware shrinking that revalidates every candidate.
- Deterministic seed/corpus, JUnit/JSON output, and one-command issue capsule.
- Twenty seed invoices covering common business cases.

No GUI, Peppol transport, tax/legal advice, PDF rendering, ZUGFeRD, invoice creation UI, SaaS, or accounting-system connectors in v0.1.

## Initial mutators

- optional seller/buyer identifiers and endpoint schemes;
- multiple VAT categories/rates where profile-valid;
- allowances and charges;
- payment means and due-date combinations;
- references and attachments within size limits;
- Unicode, whitespace, long-but-valid text, and address variants;
- unit codes, quantity/price scale, and rounding boundary cases;
- line ordering and repeated optional groups;
- zero/negative values only where business rules permit;
- profile-valid missing optional fields;
- extension content only where accepted by the chosen profile;
- cross-field changes generated from business-rule constraints, never blind XML edits.

Each mutator must prove the produced invoice still passes the pinned validator before the importer result is considered a product finding.

## Hard proof gates

- 10,000 **unique canonical semantic fingerprints** all differ materially from their seed, cover every released mutator and declared interaction bucket, and pass the pinned official validation profile before importer execution. Duplicate XML, formatting-only variants, or repeated seeds do not count.
- At least three independently classified importer failures or meaningful round-trip losses are found across at least two real open-source importer projects; duplicate manifestations of one root cause count once. No synthetic-only launch.
- Every published finding minimizes to a still-valid invoice and reproduces five times from a clean container.
- Shrinker is 1-minimal under declared invoice-node/value operations.
- Same seed, profile artifact, mutator implementation hashes, target image digest, command, and resource policy produce byte-identical corpus and result metadata.
- XML external entities, path traversal, zip bombs, output floods, and command timeouts are blocked.
- Reports avoid legal conclusions and distinguish format validity from tax/accounting correctness.

## Name and positioning

Working name: `RechnungsProbe`. Keep the capitalization for readability; package/executable may be `rechnungsprobe`. Repeat GitHub, package registry, general web, domain, and trademark searches immediately before publication.

Tagline: **“Your invoice is valid. Is your importer?”**
