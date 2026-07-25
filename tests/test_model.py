from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

import pytest

from rechnungsprobe.model import (
    ModelError,
    parse_invoice,
    semantic_fingerprint,
    serialize_invoice,
)
from rechnungsprobe.profiles import bundled_seed_path


def test_official_seed_round_trips_semantically() -> None:
    invoice = parse_invoice(bundled_seed_path())
    serialized = serialize_invoice(invoice)
    reparsed = parse_invoice(serialized)

    assert reparsed == invoice
    assert semantic_fingerprint(reparsed) == semantic_fingerprint(invoice)
    assert serialized.endswith(b"\n")


def test_fingerprint_normalizes_decimal_representation() -> None:
    invoice = parse_invoice(bundled_seed_path())
    line = replace(invoice.lines[0], quantity=Decimal("1.000"))
    equivalent = replace(invoice, lines=(line, *invoice.lines[1:]))

    assert semantic_fingerprint(equivalent) == semantic_fingerprint(invoice)


def test_model_rejects_missing_lines() -> None:
    invoice = parse_invoice(bundled_seed_path())

    with pytest.raises(ModelError, match="line"):
        replace(invoice, lines=()).validate()


def test_model_rejects_duplicate_line_identifiers() -> None:
    invoice = parse_invoice(bundled_seed_path())
    duplicate = replace(invoice.lines[1], identifier=invoice.lines[0].identifier)

    with pytest.raises(ModelError, match="unique"):
        replace(invoice, lines=(invoice.lines[0], duplicate)).validate()


def test_model_rejects_non_finite_decimal() -> None:
    invoice = parse_invoice(bundled_seed_path())
    invalid = replace(invoice.lines[0], price=Decimal("NaN"))

    with pytest.raises(ModelError, match="finite"):
        replace(invoice, lines=(invalid, *invoice.lines[1:])).validate()
