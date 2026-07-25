# Security model

## Untrusted inputs

Invoice XML, profile artifacts, archives, importer images and executables,
command output, predicate data, filesystem paths, and saved finding capsules are
untrusted.

## Implemented controls

- XML is size- and structure-bounded before tree parsing. DTDs, entity
  declarations, XInclude, and network identifiers are rejected.
- The KoSIT validator JAR and configuration ZIP are vendored, version-pinned,
  and SHA-256 verified before every materialization. Campaigns never fetch
  `latest` or access the network for profile data.
- Archive extraction and capsule verification reject traversal, absolute paths,
  links, duplicate members, oversized data, and suspicious compression ratios.
- Importer commands are argument vectors executed with `shell=False`; invoice
  data is never interpolated into a command.
- Target input, combined output, process count, CPU, memory, elapsed time,
  created files, and file growth are bounded. Output XML must be a bounded
  regular file below the target workspace, with no linked path components.
- Local target temporary-directory variables point into the disposable
  workspace. Existing executable/script arguments are resolved and hashed before
  the target changes directory.
- Finding capsules use a fixed member set and order, canonical contents, hashes,
  bounded parsing, and deterministic ZIP metadata.

## Target isolation

The preferred untrusted-target boundary is the container runner. It requires an
image digest and invokes Docker with no network, a read-only root filesystem, no
capabilities, no-new-privileges, an unprivileged user, bounded processes and
memory, a constrained temporary filesystem, and read-only invoice input. Only a
declared output directory is writable.

The local runner is a compatibility option, not a hardened sandbox. It provides
resource monitoring, a clean reduced environment, a disposable working
directory, and no shell, but the target retains the current user's host
permissions and may access the host network or files visible to that user. Do
not run hostile native code locally. Use a dedicated disposable machine or the
container runner, and keep secrets out of the parent environment.

Docker itself and the configured daemon remain trusted infrastructure. A
container runtime vulnerability is outside Rechnungsprobe's containment claim.

## Validation boundary

The validator runs as a bounded local Java process. Java external DTD access and
extension functions are disabled; schema and stylesheet access are restricted
to local files needed by the pinned configuration. Artifact integrity is checked
before Java starts. The Java runtime and operating system are trusted.

`verify` establishes capsule integrity and internal consistency; it does not
execute Java or the importer. `replay` performs official profile revalidation
before executing the recorded target. Capsules whose replay resource policies
exceed fixed safety caps are rejected, and local-process replay requires an
explicit `--allow-local-target` opt-in because a capsule can name any host
executable. The target digest covers executable or image content/identity plus
the argument vector and I/O configuration, and is checked before execution.

## Trust statement

Rechnungsprobe can show that a document passed a named validation profile and
triggered a reproducible software behavior under a recorded predicate. It does
not establish tax, legal, or accounting correctness. Third-party findings remain
private until reproduction, scope review, and a reasonable maintainer disclosure
path are complete.
