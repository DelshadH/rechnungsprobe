from __future__ import annotations

import hashlib
import hmac
import stat
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

from rechnungsprobe.model import parse_invoice, semantic_fingerprint
from rechnungsprobe.replay import ReplaySpecification, parse_replay_json, replay_json
from rechnungsprobe.reporting import (
    REPORT_SCHEMA,
    FindingRecord,
    finding_json,
    finding_junit,
    finding_record_from_payload,
    strict_json,
)
from rechnungsprobe.security import SecurityError, open_regular_file
from rechnungsprobe.target import ContainerTarget, target_configuration_digest
from rechnungsprobe.xmlsafe import parse_xml_bytes

CAPSULE_SCHEMA = "https://rechnungsprobe.dev/schemas/capsule-v1"
_MEMBERS = (
    "manifest.json",
    "invoice.xml",
    "replay.json",
    "result.json",
    "junit.xml",
)
_MEMBER_LIMITS = {
    "manifest.json": 64 * 1024,
    "invoice.xml": 2 * 1024 * 1024,
    "replay.json": 128 * 1024,
    "result.json": 2 * 1024 * 1024,
    "junit.xml": 2 * 1024 * 1024,
}


@dataclass(frozen=True, slots=True)
class VerifiedCapsule:
    record: FindingRecord
    invoice_xml: bytes
    replay: ReplaySpecification
    result_json: bytes
    junit_xml: bytes


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(payload: object) -> bytes:
    import json

    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _zip_info(name: str) -> zipfile.ZipInfo:
    information = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    information.compress_type = zipfile.ZIP_STORED
    information.create_system = 3
    information.external_attr = (stat.S_IFREG | 0o644) << 16
    information.flag_bits = 0x800
    return information


def create_finding_capsule(
    output_path: Path,
    *,
    record: FindingRecord,
    invoice_xml: bytes,
    replay: ReplaySpecification,
) -> str:
    document = parse_xml_bytes(invoice_xml)
    if not hmac.compare_digest(document.sha256, record.invoice_sha256):
        raise SecurityError("finding invoice hash does not match its record")
    invoice = parse_invoice(invoice_xml)
    if not hmac.compare_digest(semantic_fingerprint(invoice), record.fingerprint):
        raise SecurityError("finding fingerprint does not match its invoice")
    result_json = finding_json((record,))
    junit_xml = finding_junit((record,))
    replay_document = replay_json(replay)
    if replay.predicate.name != record.predicate:
        raise SecurityError("finding predicate does not match its replay configuration")
    if isinstance(replay.target, ContainerTarget) and not hmac.compare_digest(
        target_configuration_digest(replay.target),
        record.target_digest,
    ):
        raise SecurityError("finding target configuration does not match its digest")
    members = {
        "invoice.xml": invoice_xml,
        "junit.xml": junit_xml,
        "replay.json": replay_document,
        "result.json": result_json,
    }
    manifest = _json_bytes(
        {
            "files": {
                name: {"sha256": _sha256(data), "size": len(data)}
                for name, data in sorted(members.items())
            },
            "profile_id": record.profile_id,
            "schema": CAPSULE_SCHEMA,
            "target_digest": record.target_digest,
        }
    )
    members["manifest.json"] = manifest

    output_path = output_path.absolute()
    parent = output_path.parent.resolve(strict=True)
    if parent.is_symlink() or not parent.is_dir():
        raise SecurityError("capsule parent must be a real directory")
    output_path = parent / output_path.name
    if output_path.exists() or output_path.is_symlink():
        raise SecurityError("capsule output already exists")

    created = False
    try:
        with output_path.open("xb") as raw:
            created = True
            with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_STORED) as archive:
                for name in _MEMBERS:
                    archive.writestr(_zip_info(name), members[name])
        return _hash_file(output_path)
    except Exception:
        if created:
            output_path.unlink(missing_ok=True)
        raise


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open_regular_file(path, max_bytes=16 * 1024 * 1024) as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _read_members(path: Path) -> dict[str, bytes]:
    _hash_file(path)
    try:
        with (
            open_regular_file(path, max_bytes=16 * 1024 * 1024) as raw,
            zipfile.ZipFile(raw, "r") as archive,
        ):
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            if len(names) != len(set(names)):
                raise SecurityError("capsule contains a duplicate member")
            if tuple(names) != _MEMBERS:
                raise SecurityError("capsule has an unexpected member set or order")
            result: dict[str, bytes] = {}
            for entry in entries:
                unix_mode = entry.external_attr >> 16 if entry.create_system == 3 else 0
                if (
                    entry.is_dir()
                    or (unix_mode and not stat.S_ISREG(unix_mode))
                    or entry.flag_bits & 0x1
                    or entry.file_size > _MEMBER_LIMITS[entry.filename]
                    or entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    or (
                        entry.file_size
                        and (
                            entry.compress_size == 0 or entry.file_size / entry.compress_size > 100
                        )
                    )
                ):
                    raise SecurityError("capsule contains an unsafe member")
                data = archive.read(entry)
                if len(data) != entry.file_size:
                    raise SecurityError("capsule member size is inconsistent")
                result[entry.filename] = data
            return result
    except (zipfile.BadZipFile, EOFError, zlib.error) as error:
        raise SecurityError("capsule is not a valid bounded ZIP archive") from error


def verify_finding_capsule(path: Path) -> VerifiedCapsule:
    members = _read_members(path)
    manifest = strict_json(members["manifest.json"], max_bytes=64 * 1024)
    if not isinstance(manifest, dict) or set(manifest) != {
        "files",
        "profile_id",
        "schema",
        "target_digest",
    }:
        raise SecurityError("capsule manifest has an invalid shape")
    if manifest["schema"] != CAPSULE_SCHEMA or not isinstance(manifest["files"], dict):
        raise SecurityError("capsule manifest schema is unsupported")
    expected_files = {"invoice.xml", "replay.json", "result.json", "junit.xml"}
    if set(manifest["files"]) != expected_files:
        raise SecurityError("capsule manifest file set is invalid")
    for name in expected_files:
        descriptor = manifest["files"][name]
        if not isinstance(descriptor, dict) or set(descriptor) != {"sha256", "size"}:
            raise SecurityError("capsule file descriptor is invalid")
        if (
            descriptor["size"] != len(members[name])
            or not isinstance(descriptor["sha256"], str)
            or not hmac.compare_digest(descriptor["sha256"], _sha256(members[name]))
        ):
            raise SecurityError("capsule member hash or size does not match")

    result = strict_json(members["result.json"])
    if (
        not isinstance(result, dict)
        or set(result) != {"findings", "schema"}
        or result["schema"] != REPORT_SCHEMA
        or not isinstance(result["findings"], list)
        or len(result["findings"]) != 1
    ):
        raise SecurityError("capsule result report is invalid")
    record = finding_record_from_payload(result["findings"][0])
    if (
        record.profile_id != manifest["profile_id"]
        or record.target_digest != manifest["target_digest"]
    ):
        raise SecurityError("capsule manifest and result disagree")
    replay = parse_replay_json(members["replay.json"])
    if replay.predicate.name != record.predicate:
        raise SecurityError("capsule replay predicate and result disagree")
    if isinstance(replay.target, ContainerTarget) and not hmac.compare_digest(
        target_configuration_digest(replay.target),
        record.target_digest,
    ):
        raise SecurityError("capsule target configuration does not match its digest")

    document = parse_xml_bytes(members["invoice.xml"])
    if not hmac.compare_digest(document.sha256, record.invoice_sha256):
        raise SecurityError("capsule invoice hash does not match")
    invoice = parse_invoice(document.data)
    if not hmac.compare_digest(semantic_fingerprint(invoice), record.fingerprint):
        raise SecurityError("capsule invoice fingerprint does not match")
    parse_xml_bytes(members["junit.xml"])
    if members["junit.xml"] != finding_junit((record,)):
        raise SecurityError("capsule JUnit report is not canonical")
    if members["result.json"] != finding_json((record,)):
        raise SecurityError("capsule JSON report is not canonical")
    return VerifiedCapsule(
        record=record,
        invoice_xml=document.data,
        replay=replay,
        result_json=members["result.json"],
        junit_xml=members["junit.xml"],
    )
