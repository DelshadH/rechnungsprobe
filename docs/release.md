# Release procedure

Release candidates are built from a clean exact SHA with
`SOURCE_DATE_EPOCH` set to the commit timestamp. Two independent builds must
produce byte-identical wheel and sdist files. Inventory, metadata, console
entry point, installed-wheel smoke tests, checksums, SBOM, and attestations are
verified before publication.

The publication workflow accepts a protected `v*` tag only when it exactly
matches the project version. Its build job has read-only repository access and
job-scoped `id-token: write`; the publish job receives only OIDC and the
`contents: write` needed to create the matching GitHub release. It rebuilds at
the tag, attests exact artifacts, and publishes to PyPI through trusted
publishing.

Creating the tag, GitHub release, or PyPI publication requires the owner's final
`PUBLISH` decision. Preparing and reviewing the workflow does not grant that
authority.
