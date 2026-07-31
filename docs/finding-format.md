# Finding and capsule format

`result.json` uses the strict `finding-v1` schema. A record declares its
taxonomy kind, real or synthetic evidence class, exact profile and target
identity, invoice hashes, mutation history, bounded process result,
reproductions, 1-minimality, and provenance.

A `.rechnungsprobe` capsule is a deterministic ZIP containing, in fixed order:

1. `manifest.json`
2. `invoice.xml`
3. `replay.json`
4. `result.json`
5. `junit.xml`

The verifier enforces exact member names and order, duplicate rejection, regular
file modes, size and compression-ratio limits, canonical JSON/JUnit bytes, XML
safety limits, and all cross-file hashes. Verification never executes a target.

Capsule local commands are descriptions, not authority. Replay uses a
digest-pinned container by default where available. A local command requires a
current-user replacement command or the conspicuous unsafe capsule-command
opt-in.
