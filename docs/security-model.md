# Security model

## Untrusted inputs

Invoice XML, profile artifacts, archives, importer images and executables, command
output, predicates, filenames, and saved finding capsules are untrusted.

## Required controls

- Parse XML with DTDs, external entities, XInclude, and network access disabled.
- Bound XML size, depth, attributes, text nodes, attachment size, and validation
  output before expensive processing.
- Pin validation artifacts by version and SHA-256. Never download an unverified
  artifact during a finding run.
- Run targets in disposable directories or containers without credentials and
  without network access by default. Apply CPU, memory, process, file, time, and
  output limits.
- Do not interpolate invoice data into a shell command. Keep trusted configuration
  separate from untrusted document content.
- Build result archives deterministically and reject absolute paths, `..`,
  symbolic links, duplicate members, and suspicious compression ratios.
- Treat third-party failures as potentially sensitive until responsible
  disclosure is complete.

## Trust boundary

Rechnungsprobe can show that a document passed a named validation profile and
triggered a reproducible software behavior. It does not establish tax, legal, or
accounting correctness, and it is not a hardened sandbox for arbitrary hostile
native code on the host.
