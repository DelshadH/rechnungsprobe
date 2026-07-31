from __future__ import annotations

import pytest

from rechnungsprobe.findings import (
    FindingKind,
    classify_finding,
)
from rechnungsprobe.security import SecurityError


@pytest.mark.parametrize(
    ("predicate", "termination", "details", "expected"),
    [
        ("import-rejected", "exited", (), "valid-invoice-rejected"),
        ("parse-error", "exited", (), "accepted-but-parsed-incorrectly"),
        ("declared-field-loss", "exited", ("buyer_reference",), "field-lost-or-altered"),
        ("declared-field-loss", "exited", ("tax_total",), "totals-or-tax-changed"),
        (
            "optional-construct",
            "exited",
            ("invoice.note",),
            "optional-valid-construct-mishandled",
        ),
        ("crash-or-nonzero", "exited", (), "crash"),
        ("timeout", "timeout", (), "timeout-or-resource-exhaustion"),
        ("nondeterminism", "exited", (), "nondeterminism"),
        ("output-invalid", "exited", (), "round-trip-loss"),
    ],
)
def test_classifier_emits_the_declared_finding_taxonomy(
    predicate: str,
    termination: str,
    details: tuple[str, ...],
    expected: FindingKind,
) -> None:
    assert classify_finding(predicate, termination=termination, details=details) == expected


def test_classifier_rejects_an_undeclared_predicate() -> None:
    with pytest.raises(SecurityError, match="classification"):
        classify_finding("unknown", termination="exited", details=())
