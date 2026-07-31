# Research methodology

Rechnungsprobe begins with a typed invoice model, not arbitrary XML edits.
Mutators preserve cross-field totals and declared profile constraints. A
candidate becomes eligible for importer execution only after the pinned KoSIT
adapter validates it.

Campaign identity includes the seed bytes and semantic fingerprint, campaign
seed, ordered mutation history, profile and artifact hashes, target
configuration digest, resource policy, observation hashes, reproduction count,
and minimization proof.

Reduction is deterministic greedy 1-minimization under
`invoice-node-value-v1`. Independent candidates in one reduction frontier may
be validated in one KoSIT batch, but target predicates are evaluated in the
same declared order and are never memoized. Independent verification reruns
every one-step reduction from the final invoice.

Format validity is reported separately from semantic preservation and from tax,
legal, or accounting correctness. The latter three are outside the 0.1 claim.
