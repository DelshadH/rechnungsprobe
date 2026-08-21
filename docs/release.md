# Release procedure

Release candidates are built from a clean exact SHA with
`SOURCE_DATE_EPOCH` set to the commit timestamp. Two separate clean source
roots under the same pinned CI toolchain must produce byte-identical wheel and
sdist files. Package-member inventory, metadata, console entry point,
installed-wheel smoke tests, checksums, an SBOM covering Python dependencies
and bundled KoSIT/profile/seed artifacts, and attestations are verified before
publication.

The publication workflow accepts a protected `v*` tag only when it exactly
matches the project version and the same commit already has a successful
`main` push run of `ci.yml`. Its build job has read-only repository and Actions
access plus job-scoped attestation authority. The PyPI job receives only OIDC;
a separate post-publication job receives only `contents: write` to create the
matching GitHub release. It rebuilds at the tag, attests exact artifacts, and
publishes to PyPI through trusted publishing.

Normal CI generates the same reproducible CycloneDX document used by the release
workflow. The preflight requires a deterministic content-derived `serialNumber`
in addition to strict CycloneDX 1.6 validity because GitHub's SBOM attestation
parser requires that identity field.

Creating the tag, GitHub release, or PyPI publication requires the owner's final
`PUBLISH` decision. Preparing and reviewing the workflow does not grant that
authority.
