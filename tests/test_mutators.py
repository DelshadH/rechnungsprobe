from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from rechnungsprobe.model import ModelError, parse_invoice, semantic_fingerprint, serialize_invoice
from rechnungsprobe.mutators import MUTATORS, mutate
from rechnungsprobe.profiles import bundled_seed_path
from rechnungsprobe.validate import validate_invoices

EXPECTED_MUTATORS = {
    "invoice-id",
    "buyer-reference",
    "invoice-note-unicode",
    "seller-endpoint",
    "buyer-endpoint",
    "seller-name",
    "buyer-name",
    "payment-terms",
    "line-order",
    "line-description",
    "line-identifier",
    "quantity-scale",
    "price-scale",
    "vat-rate",
    "line-note",
    "seller-identifier",
    "address-variant",
    "add-line",
    "remove-optionals",
    "payment-due-date",
}


def test_released_mutator_set_is_explicit() -> None:
    assert set(MUTATORS) == EXPECTED_MUTATORS


@pytest.mark.parametrize("name", sorted(EXPECTED_MUTATORS))
def test_mutator_is_deterministic_and_material(name: str) -> None:
    invoice = parse_invoice(bundled_seed_path())

    first = mutate(invoice, name, token=42)
    second = mutate(invoice, name, token=42)

    assert first == second
    assert serialize_invoice(first) == serialize_invoice(second)
    assert semantic_fingerprint(first) == semantic_fingerprint(second)
    assert semantic_fingerprint(first) != semantic_fingerprint(invoice)
    first.validate()


@pytest.mark.parametrize("name", sorted(EXPECTED_MUTATORS))
def test_mutator_rejects_invalid_negative_fixture(name: str) -> None:
    invoice = parse_invoice(bundled_seed_path())
    invalid = replace(invoice, lines=())

    with pytest.raises(ModelError):
        mutate(invalid, name, token=42)


def test_mutators_produce_unique_semantic_fingerprints() -> None:
    invoice = parse_invoice(bundled_seed_path())
    fingerprints = {semantic_fingerprint(mutate(invoice, name, token=42)) for name in MUTATORS}

    assert len(fingerprints) == len(MUTATORS)


def test_every_released_mutator_passes_the_pinned_official_profile(
    tmp_path: Path,
) -> None:
    invoice = parse_invoice(bundled_seed_path())
    cases = {name: serialize_invoice(mutate(invoice, name, token=42)) for name in MUTATORS}

    results = validate_invoices(cases, workspace=tmp_path)

    assert set(results) == set(MUTATORS)
    assert {name: result.errors for name, result in results.items() if not result.valid} == {}
