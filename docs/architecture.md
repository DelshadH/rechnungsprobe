# Architecture

## Modules

- `profiles`: pinned validator artifacts, hashes, licenses, and supported syntax.
- `model`: typed invoice concepts used by mutators and shrinkers.
- `corpus`: deterministic seed loading and semantic fingerprints.
- `mutators`: constraint-aware, validity-preserving invoice transformations.
- `validate`: isolated invocation of the pinned official validation profile.
- `target`: bounded local-process and container runners.
- `predicate`: crash, timeout, stdout JSON, output validity, and field-loss oracles.
- `shrink`: structure-aware reduction that revalidates every candidate.
- `capsule`: deterministic finding archives with hashes and reproduction metadata.
- `cli`: stable commands, exit codes, JSON output, and JUnit export.

## Processing pipeline

1. Load a known-valid seed and verify it with the pinned profile.
2. Select deterministic semantic mutations from a recorded seed.
3. Validate the mutant before executing the importer.
4. Run the importer with explicit resource and isolation policies.
5. Evaluate one declared failure predicate.
6. If it fails, shrink invoice operations while preserving validity and failure.
7. Verify 1-minimality, reproduce repeatedly, and export a finding capsule.

Invalid invoices are corpus or mutator failures, not importer findings.

## Extension boundary

The first release supports one XRechnung UBL profile. Profile and target
interfaces should be explicit, but a plugin system is out of scope until the
initial implementation has found and responsibly handled real issues.
