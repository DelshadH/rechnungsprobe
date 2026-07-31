# Compatibility policy

The 0.1 line supports CPython 3.11, 3.12, and 3.13 on current Ubuntu, macOS, and
Windows GitHub-hosted runners. The CLI and JSON formats are scriptable and use
documented exit codes.

Schemas carrying `v1` are strict within the 0.1 line. Unknown fields, duplicate
JSON keys, non-finite numbers, excessive nesting, and unsupported variants are
rejected. A future incompatible format will use a new schema URI.

The only released validation profile is
`xrechnung-ubl-3.0.2-2026-01-31`. Profiles are never selected as “latest” and
are accepted only with their declared SHA-256 values.
