from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from rechnungsprobe.model import parse_invoice, semantic_fingerprint, serialize_invoice
from rechnungsprobe.mutators import MUTATORS, mutate
from rechnungsprobe.profiles import XRECHNUNG_UBL_3_0_2
from rechnungsprobe.security import SecurityError
from rechnungsprobe.xmlsafe import load_xml

GENERATOR_VERSION = "1"
MUTATOR_VERSION = "1"
MUTATOR_ORDER = tuple(MUTATORS)


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
) -> tuple[Candidate, ...]:
    if not 1 <= count <= 100_000:
        raise SecurityError("candidate count must be between one and 100000")
    if not 0 <= campaign_seed < 2**63:
        raise SecurityError("campaign seed must be a non-negative 63-bit integer")

    seed_document = load_xml(seed_path)
    seed_invoice = parse_invoice(seed_document.data)
    seed_fingerprint = semantic_fingerprint(seed_invoice)
    candidates: list[Candidate] = []
    fingerprints: set[str] = set()
    for index in range(count):
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
            interaction_name = MUTATOR_ORDER[
                int.from_bytes(digest[8:16], "big") % len(MUTATOR_ORDER)
            ]
            if interaction_name != primary_name and interaction_name != "invoice-id":
                interaction_token = int.from_bytes(digest[16:24], "big") % 1_000_000_000
                invoice = mutate(invoice, interaction_name, token=interaction_token)
                operations.append(MutationRecord(interaction_name, interaction_token))

        if primary_name != "invoice-id":
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
    first = candidates[0]
    payload = {
        "campaign_seed": first.campaign_seed,
        "candidate_count": len(candidates),
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
            for candidate in candidates
        ],
        "generator_version": GENERATOR_VERSION,
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
