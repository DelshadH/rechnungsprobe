# Security policy

Please report suspected vulnerabilities privately through
[GitHub Security Advisories](https://github.com/DelshadH/rechnungsprobe/security/advisories/new).
Do not attach real invoices, customer data, credentials, or confidential importer
output. Use generated fixtures and synthetic identifiers.

High-priority areas include XML external entity or expansion attacks, validator
network access, archive traversal or bombs, command injection, container escape,
output floods, resource-limit bypass, and sensitive data in reports.

Verification is non-executing. Prefer digest-pinned container replay. Trusted
local targets are explicitly non-isolated and can access the host filesystem and
network; a capsule local command never receives execution authority by default.

Supported security fixes target the current `0.1` alpha line. Do not run the
tool against production systems or use its output as tax, legal, accounting, or
compliance advice.
