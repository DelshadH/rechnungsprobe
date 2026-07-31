# Architecture

## Modules

- `profiles`: one pinned validator/configuration pair, integrity metadata, and
  safe artifact materialization.
- `xmlsafe` and `security`: bounded XML parsing, regular-file checks, and safe
  ZIP extraction.
- `model`: typed XRechnung UBL invoice concepts, parsing, serialization, and
  canonical semantic fingerprints.
- `mutators`, `corpus`, and `gates`: deterministic semantic transformations,
  resumable/shardable corpus generation, and machine-readable official
  validation evidence.
- `validate`: bounded invocation of the vendored KoSIT validator with external
  XML access restricted to the extracted configuration repository.
- `process` and `target`: bounded process-tree execution, staged local files,
  digest-pinned Docker execution, and verified daemon cleanup.
- `predicates`: crash, timeout, stdout JSON, output-validity, and declared
  field-loss oracles.
- `shrink`: structure-aware reduction and an independent 1-minimality check.
- `findings`, `comparison`, and `provenance`: precise classification, normalized
  semantic comparison, and complete campaign identity.
- `reporting`, `capsule`, and `replay`: canonical JSON/JUnit reports,
  deterministic bounded finding archives, and exact replay specifications.
- `campaign`: orchestration across generation, validation, execution, reduction,
  reproduction, and export.
- `cli`: stable commands, machine-readable output, and exit codes.

## Processing pipeline

1. Load the bundled seed through the bounded XML parser.
2. Generate candidates deterministically from the campaign seed and record each
   typed mutator and token.
3. Validate the entire corpus in batches with the pinned official profile.
   Invalid candidates abort the campaign and never reach the importer.
4. Run each valid candidate against the declared target and evaluate one
   predicate.
5. On the first match, shrink typed invoice operations while revalidating and
   preserving the same predicate and target digest. Independent candidates in
   one frontier may share a KoSIT batch; target evaluations remain ordered and
   uncached.
6. Independently check 1-minimality, then revalidate and reproduce the reduced
   case the requested number of times with byte-identical complete observations.
7. Export canonical reports and a deterministic finding capsule.

The campaign currently stops after its first stable finding. This keeps
reduction cost bounded and makes the resulting artifact suitable for one issue
report. A new output directory is required for every campaign.

Invalid invoices are generator, mutator, or profile failures—not importer
findings. Format validity is also separate from tax, legal, and accounting
correctness.

## Reproducibility boundary

Corpus XML and metadata are functions of the bundled seed, campaign seed,
generator/mutator versions, and pinned profile identifier. Finding metadata also
records the target digest, argument vector, input/output mode, predicate, and
resource policy. JSON, JUnit, XML serialization, and ZIP member ordering are
canonicalized.

For local targets, the digest covers the resolved executable plus command and
mode configuration; it cannot capture every host library or operating-system
dependency. Strong publication evidence therefore requires a digest-pinned
container replay from a clean environment.

## Extension boundary

The first release supports only XRechnung 3.0.2 UBL Invoice under the pinned
2026-01-31 KoSIT configuration. Explicit profile and target data structures
leave room for future formats, but a plugin system is out of scope until the
initial implementation has found and responsibly handled real issues.
