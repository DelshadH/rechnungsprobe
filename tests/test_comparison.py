from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

from rechnungsprobe.comparison import compare_semantics
from rechnungsprobe.model import parse_invoice
from rechnungsprobe.profiles import bundled_seed_path


def test_semantic_comparison_separates_field_loss_from_totals_changes() -> None:
    source = parse_invoice(bundled_seed_path())
    imported = replace(source, buyer_reference="ALTERED")
    roundtrip = replace(
        imported,
        lines=(replace(imported.lines[0], price=Decimal("99.00")), *imported.lines[1:]),
    )

    comparison = compare_semantics(source, imported=imported, roundtrip=roundtrip)

    assert comparison.imported_changed_fields == ("buyer_reference",)
    assert comparison.roundtrip_changed_fields == (
        "lines[0].price",
        "line_total",
        "tax_total",
        "payable_total",
    )
    assert comparison.totals_or_tax_changed is True
    assert comparison.roundtrip_loss is True


def test_semantic_comparison_declares_preserved_invariants_for_equal_models() -> None:
    source = parse_invoice(bundled_seed_path())

    comparison = compare_semantics(source, imported=source, roundtrip=source)

    assert comparison.imported_changed_fields == ()
    assert comparison.roundtrip_changed_fields == ()
    assert comparison.totals_or_tax_changed is False
    assert comparison.roundtrip_loss is False
