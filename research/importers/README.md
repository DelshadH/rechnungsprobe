# Importer research adapters

These adapters are research fixtures, not runtime dependencies of Rechnungsprobe.
Each build pins its base image and direct importer version. Campaign execution
uses the resulting content-addressed local image ID (`sha256:...`) with networking
disabled by Rechnungsprobe.

Catalog image IDs identify the reviewed local products; they are not a promise
that every adapter rebuild is byte-identical. Transitive dependency graphs are
not uniformly checksum-locked, and no public registry is claimed.

The adapters accept `/input/invoice.xml`. Round-trip-capable adapters write
`/output/roundtrip.xml`; parse-only adapters emit bounded JSON to stdout.
