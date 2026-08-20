# Private importer disclosure

The public repository contains only anonymized evidence identifiers,
classifications, reproduction counts, and capsule SHA-256 commitments. Importer
mappings, capsules, detailed logs, and maintainer correspondence are private and
must not be added to a pull request, release asset, issue, or package.

Before contacting a maintainer for any observation, the owner must complete the
following handoff in a private workspace:

1. Locate the importer mapping and capsule, then verify the capsule SHA-256
   against `research/results.json`.
2. Run `rechnungsprobe verify` and repeat the digest-pinned container replay from
   clean workspaces. Confirm the exact predicate, affected source revision and
   image digest, profile, resource policy, and reproduction count.
3. Check the current upstream version and narrow the affected scope. Do not claim
   that a newer version is affected without reproducing it.
4. Remove customer data, credentials, host paths, and unrelated importer output.
   Share only generated identifiers and the minimized valid invoice needed to
   reproduce the behavior.
5. Select a reasonable private channel from the maintainer's published security
   policy or contact information. Record the channel, contact date, requested
   acknowledgement date, response, remediation status, and any embargo privately.
6. Provide the validity evidence, exact replay command, expected and observed
   behavior, impact boundary, and a statement that Rechnungsprobe does not assess
   tax, legal, or accounting correctness.

If the private mapping or capsule is unavailable, its commitment is not enough
to contact a maintainer or claim independent reproducibility. The observation
must remain anonymized. Governance permits that limited public count to remain
in the alpha, but no importer-linked disclosure or public finding may proceed.
