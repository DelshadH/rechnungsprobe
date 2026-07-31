# Research record

Last repeated: **26 July 2026**. This is a dated feasibility check, not proof
that no similar project or mark exists.

## Collision check

An exact `rechnungsprobe` search found this repository and no other software
project or package in:

- [GitHub repository search](https://github.com/search?q=rechnungsprobe&type=repositories)
  and [GitLab project search](https://gitlab.com/search?search=rechnungsprobe);
- [PyPI](https://pypi.org/search/?q=rechnungsprobe),
  [npm](https://www.npmjs.com/search?q=rechnungsprobe), and
  [crates.io](https://crates.io/search?q=rechnungsprobe);
- [Maven Central](https://central.sonatype.com/search?q=rechnungsprobe) and
  [Docker Hub](https://hub.docker.com/search?q=rechnungsprobe).

Broad GitHub and GitLab searches combined XRechnung, EN 16931, UBL, or
e-invoice with `fuzz`, `fuzzer`, `mutation testing`, `property based`, `shrink`,
`importer`, and `roundtrip`. They found validators, fixed suites, generators,
viewers, and import libraries, but no direct match for the complete product
boundary below.

The German word *Rechnungsprobe* also has ordinary dictionary and historical
uses. The search is not formal trademark clearance. Repeat the registry, web,
domain, and official trademark searches before any 0.1 publication.

## Adjacent prior art: OIOFuzz

Primary sources:

- [Aalborg University thesis PDF](https://projekter.aau.dk/projekter/files/538309774/cs_23_ds_10_06_master_thesis.pdf)
- [public proof-of-concept source](https://github.com/fulei345/P10-Code)

The 2023 thesis describes OIOFuzz as a guided, model-based black-box fuzzer for
the Schematron-validation path of the Danish OIORASP .NET client. It mutates
OIOUBL field values and structure, observes exceptions/crashes and coverage,
and found a Schematron error from a duplicated field. Its public source has no
detected software license, so Rechnungsprobe neither copies nor redistributes it.
The thesis also states a separate publication condition; this project cites and
summarizes it instead of republishing it.

| Boundary | OIOFuzz | Rechnungsprobe |
| --- | --- | --- |
| Format | Danish OIOUBL/OIORASP | German XRechnung 3.0.2 UBL |
| Target | one OIORASP Schematron-validation client | user-declared black-box importer |
| Candidate rule | schema-guided field/structure mutation | typed semantic mutation, then official profile validation |
| Oracle | exception, crash, outcome, coverage | crash, timeout, JSON, output validity, declared field loss |
| Reduction | no minimizer described | validation- and predicate-preserving shrink with an independent 1-minimality check |
| Reproduction | research campaign | deterministic metadata and one-command capsule |

The idea remains viable only while these differences are real in the code. It
must not be described as the first UBL or invoice fuzzer.

## Pinned KoSIT profile and redistribution

The single supported profile is XRechnung 3.0.2 UBL Invoice:

| Artifact | Official release | SHA-256 |
| --- | --- | --- |
| KoSIT validator | [1.6.2](https://github.com/itplr-kosit/validator/releases/tag/v1.6.2) | `244978514ad48f67c7573acfffc8f4fd73d81feda6f276710033f9913579857e` |
| Validator configuration | [2026-01-31](https://github.com/itplr-kosit/validator-configuration-xrechnung/releases/tag/v2026-01-31) | `6a5a5911a421b25fbc423f62f93f894df7b236f5d73ca4f84bb222a945082704` |
| XRechnung Schematron | [2.5.0](https://github.com/itplr-kosit/xrechnung-schematron/releases/tag/v2.5.0) | `a0f3d82737759bee8591c298ff24983a8f1c667f85e45a34863c75a242bc6f43` |
| Fixed testsuite | [2026-01-31](https://github.com/itplr-kosit/xrechnung-testsuite/releases/tag/v2026-01-31) | `a1e2b26d7de6db6903076d4a8548b66ca603e7b25ad17233202a73cfbfeb29ee` |

KoSIT marks these repositories Apache-2.0. The validator-configuration license
also carries the XRechnung/EN 16931 CEN and DIN notice. Vendored artifacts keep
the upstream license texts under `third_party/`; generated or copied seed data
records its source tag and digest. This is a practical redistribution finding,
not legal advice.

## Importer campaign

Five active UBL readers were selected with practical adapters: Jasy,
esvit/einvoicing, num-num/ubl-invoice, josemmo/einvoicing, and ph-ubl. Exact
selection and runtime commits, package integrity values, licenses, lockfiles,
base-image digests, and research image IDs are recorded in
`research/importers/catalog.json`.

The official-validation campaign retained three genuine findings across three
importers: two crashes and one invalid round-trip/preservation loss. Each final
source invoice is valid, each finding reproduced five times, and each is
1-minimal under `invoice-node-value-v1`. The mapping remains anonymized until a
reasonable maintainer notification path is completed. See
[benchmark.md](benchmark.md) for scope and limitations.
