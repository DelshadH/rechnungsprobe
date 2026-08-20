# Governance

Rechnungsprobe is maintained through public issues and pull requests. Technical
release gates are exact-head CI and independent AI review; the project does not
claim human audit, outside adoption, or multiple maintainers.

Changes to schemas, the security boundary, validator artifacts, mutator
semantics, or release workflows require regression tests and an explicit
changelog entry. No branch rule may permit force pushes or deletion of the
canonical branch or protected release tags.

Responsible disclosure takes precedence over benchmark completeness. Findings
may remain anonymized without blocking an alpha release. The private handoff
requirements are defined in [disclosure.md](disclosure.md).
