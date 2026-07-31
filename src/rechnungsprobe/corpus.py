from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path

from rechnungsprobe.model import parse_invoice, semantic_fingerprint, serialize_invoice
from rechnungsprobe.mutators import MUTATORS, mutate
from rechnungsprobe.profiles import XRECHNUNG_UBL_3_0_2
from rechnungsprobe.security import SecurityError, open_regular_file
from rechnungsprobe.xmlsafe import load_xml

GENERATOR_VERSION = "2"
MUTATOR_VERSION = "1"
MUTATOR_ORDER = tuple(MUTATORS)
INTERACTION_BUCKETS = tuple(
    f"{primary}+{secondary}"
    for primary in MUTATOR_ORDER
    for secondary in MUTATOR_ORDER
    if secondary != primary
)


@dataclass(frozen=True, slots=True)
class MutationRecord:
    name: str
    token: int
    version: str = MUTATOR_VERSION


@dataclass(frozen=True, slots=True)
class Candidate:
    index: int
    campaign_seed: int
    seed_sha256: str
    seed_fingerprint: str
    operations: tuple[MutationRecord, ...]
    fingerprint: str
    xml_sha256: str
    xml: bytes


def _candidate_digest(campaign_seed: int, index: int) -> bytes:
    return hashlib.sha256(
        (f"rechnungsprobe-campaign-v{GENERATOR_VERSION}\0{campaign_seed}\0{index}").encode()
    ).digest()


def generate_candidates(
    seed_path: Path,
    *,
    count: int,
    campaign_seed: int,
    shard_index: int = 0,
    shard_count: int = 1,
) -> tuple[Candidate, ...]:
    if not 1 <= count <= 100_000:
        raise SecurityError("candidate count must be between one and 100000")
    if not 0 <= campaign_seed < 2**63:
        raise SecurityError("campaign seed must be a non-negative 63-bit integer")
    if not 1 <= shard_count <= 100 or not 0 <= shard_index < shard_count:
        raise SecurityError("corpus shard coordinates are invalid")

    seed_document = load_xml(seed_path)
    seed_invoice = parse_invoice(seed_document.data)
    seed_fingerprint = semantic_fingerprint(seed_invoice)
    candidates: list[Candidate] = []
    fingerprints: set[str] = set()
    for index in range(shard_index, count, shard_count):
        digest = _candidate_digest(campaign_seed, index)
        primary_name = MUTATOR_ORDER[index % len(MUTATOR_ORDER)]
        unique_token = (campaign_seed << 32) | index
        primary_token = (
            unique_token
            if primary_name == "invoice-id"
            else int.from_bytes(digest[:8], "big") % 1_000_000_000
        )
        operations = [MutationRecord(primary_name, primary_token)]
        invoice = mutate(seed_invoice, primary_name, token=primary_token)

        if index >= len(MUTATOR_ORDER):
            interaction_names = tuple(
                name for name in MUTATOR_ORDER if name != primary_name
            )
            interaction_cycle = (index - len(MUTATOR_ORDER)) // len(MUTATOR_ORDER)
            interaction_name = interaction_names[interaction_cycle % len(interaction_names)]
            interaction_token = (
                unique_token
                if interaction_name == "invoice-id"
                else int.from_bytes(digest[16:24], "big") % 1_000_000_000
            )
            invoice = mutate(invoice, interaction_name, token=interaction_token)
            operations.append(MutationRecord(interaction_name, interaction_token))

        if all(operation.name != "invoice-id" for operation in operations):
            invoice = mutate(invoice, "invoice-id", token=unique_token)
            operations.append(MutationRecord("invoice-id", unique_token))

        xml = serialize_invoice(invoice)
        fingerprint = semantic_fingerprint(invoice)
        if fingerprint == seed_fingerprint or fingerprint in fingerprints:
            raise RuntimeError("candidate generation produced a semantic collision")
        fingerprints.add(fingerprint)
        candidates.append(
            Candidate(
                index=index,
                campaign_seed=campaign_seed,
                seed_sha256=seed_document.sha256,
                seed_fingerprint=seed_fingerprint,
                operations=tuple(operations),
                fingerprint=fingerprint,
                xml_sha256=hashlib.sha256(xml).hexdigest(),
                xml=xml,
            )
        )
    return tuple(candidates)


def corpus_manifest(candidates: tuple[Candidate, ...]) -> bytes:
    if not candidates:
        raise SecurityError("corpus manifest requires at least one candidate")
    ordered = tuple(sorted(candidates, key=lambda candidate: candidate.index))
    first = ordered[0]
    if (
        len({candidate.index for candidate in ordered}) != len(ordered)
        or any(
            candidate.campaign_seed != first.campaign_seed
            or candidate.seed_sha256 != first.seed_sha256
            or candidate.seed_fingerprint != first.seed_fingerprint
            for candidate in ordered
        )
    ):
        raise SecurityError("corpus candidates do not share one provenance")
    root = hashlib.sha256(b"rechnungsprobe-corpus-root-v1\0")
    for candidate in ordered:
        root.update(candidate.index.to_bytes(8, "big"))
        root.update(bytes.fromhex(candidate.fingerprint))
        root.update(bytes.fromhex(candidate.xml_sha256))
    interactions = tuple(
        f"{candidate.operations[0].name}+{candidate.operations[1].name}"
        for candidate in ordered
        if candidate.index >= len(MUTATOR_ORDER) and len(candidate.operations) >= 2
    )
    payload = {
        "campaign_seed": first.campaign_seed,
        "candidate_count": len(ordered),
        "candidates": [
            {
                "fingerprint": candidate.fingerprint,
                "index": candidate.index,
                "operations": [
                    {
                        "name": operation.name,
                        "token": operation.token,
                        "version": operation.version,
                    }
                    for operation in candidate.operations
                ],
                "xml_sha256": candidate.xml_sha256,
            }
            for candidate in ordered
        ],
        "corpus_root_sha256": f"sha256:{root.hexdigest()}",
        "generator_version": GENERATOR_VERSION,
        "interaction_buckets": sorted(set(interactions)),
        "profile_id": XRECHNUNG_UBL_3_0_2.identifier,
        "seed_fingerprint": first.seed_fingerprint,
        "seed_sha256": first.seed_sha256,
    }
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _read_existing(path: Path, *, max_bytes: int) -> bytes:
    with open_regular_file(path, max_bytes=max_bytes) as source:
        return source.read(max_bytes + 1)


def materialize_corpus(
    output: Path,
    *,
    seed_path: Path,
    count: int,
    campaign_seed: int,
    shard_index: int = 0,
    shard_count: int = 1,
    resume: bool = False,
) -> bytes:
    """Write one deterministic shard, resuming only byte-identical prior work."""

    candidates = generate_candidates(
        seed_path,
        count=count,
        campaign_seed=campaign_seed,
        shard_index=shard_index,
        shard_count=shard_count,
    )
    manifest = corpus_manifest(candidates)
    output = output.absolute()
    if output.exists():
        resolved = output.resolve(strict=True)
        if (
            not resume
            or output != resolved
            or output.is_symlink()
            or not output.is_dir()
        ):
            raise SecurityError("corpus output already exists or is unsafe")
        if {path.name for path in output.iterdir()} - {"cases", "corpus.json"}:
            raise SecurityError("corpus output contains unexpected entries")
    else:
        parent = output.parent.resolve(strict=True)
        if output.parent.is_symlink() or not parent.is_dir():
            raise SecurityError("corpus output parent must be a real directory")
        output = parent / output.name
        output.mkdir()

    case_root = output / "cases"
    if case_root.exists():
        if case_root.is_symlink() or not case_root.is_dir():
            raise SecurityError("corpus case directory is unsafe")
    else:
        case_root.mkdir()

    for candidate in candidates:
        path = case_root / f"case-{candidate.index:06d}.xml"
        if path.exists():
            existing = _read_existing(path, max_bytes=2 * 1024 * 1024)
            if not hmac.compare_digest(existing, candidate.xml):
                raise SecurityError(f"existing corpus case does not match: {path.name}")
        else:
            with path.open("xb") as destination:
                destination.write(candidate.xml)

    manifest_path = output / "corpus.json"
    if manifest_path.exists():
        existing_manifest = _read_existing(manifest_path, max_bytes=32 * 1024 * 1024)
        if not hmac.compare_digest(existing_manifest, manifest):
            raise SecurityError("existing corpus manifest does not match")
    else:
        with manifest_path.open("xb") as destination:
            destination.write(manifest)
    return manifest
