# Recovery

If a release artifact or tag is inconsistent with its reviewed SHA, stop
publication, preserve the evidence, revoke the affected release where the
registry permits, and publish a correction under a new version. Never retarget
an existing release tag.

If a validator or profile artifact is found corrupt, disable that profile by a
normal reviewed commit and require a new pinned version and hash. Existing
capsules retain their original identity and must not be silently reinterpreted.

If a finding is later disputed, retain its capsule and add a superseding result
with the exact importer and profile versions. Do not rewrite prior evidence.
