from __future__ import annotations

import json
import math
import re
from dataclasses import asdict, dataclass
from typing import Any, cast

# Report XML is constructed and serialized here, never parsed.
from xml.etree import ElementTree  # nosec B405

from rechnungsprobe.findings import FindingKind, classify_finding
from rechnungsprobe.provenance import (
    FindingProvenance,
    provenance_from_payload,
    provenance_payload,
)
from rechnungsprobe.security import SecurityError

REPORT_SCHEMA = "https://rechnungsprobe.dev/schemas/finding-v1"
_SHA256 = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
_TERMINATIONS = {
    "exited",
    "timeout",
    "output_limit",
    "memory_limit",
    "cpu_limit",
    "process_limit",
    "file_limit",
}


@dataclass(frozen=True, slots=True)
class FindingRecord:
    case_id: str
    predicate: str
    profile_id: str
    target_digest: str
    invoice_sha256: str
    fingerprint: str
    termination: str
    returncode: int | None
    details: tuple[str, ...]
    mutations: tuple[str, ...]
    one_minimal: bool
    reproductions: int
    synthetic: bool
    provenance: FindingProvenance | None = None

    @property
    def finding_kind(self) -> FindingKind:
        return classify_finding(
            self.predicate,
            termination=self.termination,
            details=self.details,
        )

    @property
    def evidence_class(self) -> str:
        return "synthetic" if self.synthetic else "real"

    def __post_init__(self) -> None:
        if not self.synthetic and self.provenance is None:
            raise SecurityError("real finding record requires provenance")
        text_values = (
            self.case_id,
            self.predicate,
            self.profile_id,
            self.target_digest,
            self.fingerprint,
            *self.details,
            *self.mutations,
        )
        if (
            not self.case_id
            or len(self.case_id) > 80
            or any(not value or len(value) > 2000 for value in text_values)
            or _SHA256.fullmatch(self.target_digest) is None
            or _SHA256.fullmatch(self.invoice_sha256) is None
            or _SHA256.fullmatch(self.fingerprint) is None
            or self.termination not in _TERMINATIONS
            or len(self.details) > 64
            or len(self.mutations) > 64
            or not 1 <= self.reproductions <= 100
        ):
            raise SecurityError("finding record is invalid or exceeds its limits")
        if self.provenance is not None and (
            self.provenance.target_digest != self.target_digest
            or self.provenance.profile.get("identifier") != self.profile_id
            or len(self.provenance.observations) != self.reproductions
            or self.provenance.minimization.one_minimal != self.one_minimal
            or any(
                observation.termination != self.termination
                or observation.returncode != self.returncode
                for observation in self.provenance.observations
            )
        ):
            raise SecurityError("finding record and provenance disagree")


def _record_payload(record: FindingRecord) -> dict[str, object]:
    payload = asdict(record)
    payload["details"] = list(record.details)
    payload["mutations"] = list(record.mutations)
    payload["finding_kind"] = record.finding_kind
    payload["evidence_class"] = record.evidence_class
    payload["provenance"] = (
        provenance_payload(record.provenance) if record.provenance is not None else None
    )
    return payload


def finding_record_from_payload(payload: object) -> FindingRecord:
    if not isinstance(payload, dict):
        raise SecurityError("finding record must be a JSON object")
    expected = {
        "case_id",
        "predicate",
        "profile_id",
        "target_digest",
        "invoice_sha256",
        "fingerprint",
        "termination",
        "returncode",
        "details",
        "mutations",
        "one_minimal",
        "reproductions",
        "synthetic",
        "finding_kind",
        "evidence_class",
        "provenance",
    }
    if set(payload) != expected:
        raise SecurityError("finding record has unexpected fields")
    details = payload["details"]
    mutations = payload["mutations"]
    returncode = payload["returncode"]
    reproductions = payload["reproductions"]
    if (
        not all(
            isinstance(payload[key], str)
            for key in expected
            - {
                "returncode",
                "details",
                "mutations",
                "one_minimal",
                "reproductions",
                "synthetic",
                "provenance",
            }
        )
        or not isinstance(details, list)
        or not all(isinstance(value, str) for value in details)
        or not isinstance(mutations, list)
        or not all(isinstance(value, str) for value in mutations)
        or (returncode is not None and type(returncode) is not int)
        or type(payload["one_minimal"]) is not bool
        or type(reproductions) is not int
        or type(payload["synthetic"]) is not bool
        or payload["evidence_class"] not in {"real", "synthetic"}
    ):
        raise SecurityError("finding record has invalid JSON types")
    record = FindingRecord(
        case_id=payload["case_id"],
        predicate=payload["predicate"],
        profile_id=payload["profile_id"],
        target_digest=payload["target_digest"],
        invoice_sha256=payload["invoice_sha256"],
        fingerprint=payload["fingerprint"],
        termination=payload["termination"],
        returncode=returncode,
        details=tuple(details),
        mutations=tuple(mutations),
        one_minimal=payload["one_minimal"],
        reproductions=reproductions,
        synthetic=payload["synthetic"],
        provenance=(
            provenance_from_payload(payload["provenance"])
            if payload["provenance"] is not None
            else None
        ),
    )
    if (
        payload["finding_kind"] != record.finding_kind
        or payload["evidence_class"] != record.evidence_class
    ):
        raise SecurityError("finding classification is inconsistent with its evidence")
    return record


def finding_json(records: tuple[FindingRecord, ...]) -> bytes:
    ordered = sorted(records, key=lambda record: (record.case_id, record.predicate))
    payload = {
        "findings": [_record_payload(record) for record in ordered],
        "schema": REPORT_SCHEMA,
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


def finding_junit(records: tuple[FindingRecord, ...]) -> bytes:
    ordered = sorted(records, key=lambda record: (record.case_id, record.predicate))
    suite = ElementTree.Element(
        "testsuite",
        {
            "failures": str(len(ordered)),
            "name": "rechnungsprobe",
            "tests": str(len(ordered)),
        },
    )
    for record in ordered:
        case = ElementTree.SubElement(
            suite,
            "testcase",
            {
                "classname": f"rechnungsprobe.{record.predicate}",
                "name": record.case_id,
            },
        )
        message = "; ".join(record.details) or record.predicate
        failure = ElementTree.SubElement(
            case,
            "failure",
            {
                "message": message,
                "type": record.predicate,
            },
        )
        failure.text = (
            f"profile={record.profile_id}\n"
            f"target={record.target_digest}\n"
            f"invoice_sha256={record.invoice_sha256}\n"
            f"finding_kind={record.finding_kind}\n"
            f"evidence_class={record.evidence_class}\n"
            f"one_minimal={str(record.one_minimal).lower()}\n"
        )
    return (
        cast(
            bytes,
            ElementTree.tostring(
                suite,
                encoding="utf-8",
                xml_declaration=True,
                short_empty_elements=True,
            ),
        )
        + b"\n"
    )


def strict_json(data: bytes, *, max_bytes: int = 2 * 1024 * 1024) -> Any:
    if len(data) > max_bytes:
        raise SecurityError("JSON document exceeds the size limit")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise SecurityError("document is not strict JSON") from error

    depth = 0
    structural_tokens = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            structural_tokens += 1
            if depth > 64:
                raise SecurityError("JSON document exceeds the nesting limit")
        elif character in "]}":
            depth -= 1
        elif character in ",:":
            structural_tokens += 1
        if structural_tokens > 100_000:
            raise SecurityError("JSON document exceeds the structural limit")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise SecurityError(f"JSON contains duplicate key: {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise SecurityError(f"JSON contains non-finite number: {value}")

    def parse_float(value: str) -> float:
        if len(value) > 128:
            raise SecurityError("JSON number exceeds the length limit")
        parsed = float(value)
        if not math.isfinite(parsed):
            raise SecurityError(f"JSON contains non-finite number: {value}")
        return parsed

    def parse_int(value: str) -> int:
        if len(value) > 128:
            raise SecurityError("JSON number exceeds the length limit")
        return int(value)

    try:
        return json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
            parse_float=parse_float,
            parse_int=parse_int,
        )
    except SecurityError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError, OverflowError) as error:
        raise SecurityError("document is not strict JSON") from error
