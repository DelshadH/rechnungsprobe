from __future__ import annotations

import json

import pytest

from rechnungsprobe.reporting import (
    FindingRecord,
    finding_json,
    finding_junit,
    strict_json,
)
from rechnungsprobe.security import SecurityError


def _record() -> FindingRecord:
    return FindingRecord(
        case_id="case-0001",
        predicate="declared-field-loss",
        profile_id="xrechnung-ubl-3.0.2-2026-01-31",
        target_digest="sha256:" + ("a" * 64),
        invoice_sha256="b" * 64,
        fingerprint="sha256:" + ("c" * 64),
        termination="exited",
        returncode=0,
        details=("buyer_reference", 'escaped <&" text'),
        mutations=("buyer-reference@1",),
        one_minimal=True,
        reproductions=5,
        synthetic=True,
    )


def test_json_and_junit_are_byte_deterministic() -> None:
    record = _record()

    assert finding_json((record,)) == finding_json((record,))
    assert finding_junit((record,)) == finding_junit((record,))
    assert finding_json((record,)).endswith(b"\n")
    assert finding_junit((record,)).endswith(b"\n")


def test_reports_make_finding_kind_and_evidence_class_explicit() -> None:
    record = _record()

    payload = json.loads(finding_json((record,)))

    assert payload["findings"][0]["finding_kind"] == "field-lost-or-altered"
    assert payload["findings"][0]["evidence_class"] == "synthetic"
    assert b"finding_kind=field-lost-or-altered" in finding_junit((record,))
    assert b"evidence_class=synthetic" in finding_junit((record,))


def test_junit_escapes_untrusted_details() -> None:
    document = finding_junit((_record(),))

    assert b"escaped &lt;&amp;&quot; text" in document
    assert b'tests="1"' in document
    assert b'failures="1"' in document


def test_record_order_does_not_change_reports() -> None:
    first = _record()
    second = FindingRecord(
        case_id="case-0000",
        predicate=first.predicate,
        profile_id=first.profile_id,
        target_digest=first.target_digest,
        invoice_sha256="d" * 64,
        fingerprint="sha256:" + ("e" * 64),
        termination="timeout",
        returncode=None,
        details=("timeout",),
        mutations=(),
        one_minimal=True,
        reproductions=5,
        synthetic=True,
    )

    assert finding_json((first, second)) == finding_json((second, first))
    assert finding_junit((first, second)) == finding_junit((second, first))


@pytest.mark.parametrize(
    "document",
    [
        b"[" * 2_000 + b"]" * 2_000,
        b'{"number":' + b"9" * 5_000 + b"}",
    ],
)
def test_strict_json_normalizes_hostile_parser_limits(document: bytes) -> None:
    with pytest.raises(SecurityError):
        strict_json(document)
