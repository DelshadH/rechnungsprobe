from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from typing import Any

from rechnungsprobe.model import Invoice

_TOTAL_FIELDS = ("line_total", "tax_total", "payable_total")


@dataclass(frozen=True, slots=True)
class SemanticComparison:
    imported_changed_fields: tuple[str, ...]
    roundtrip_changed_fields: tuple[str, ...]
    totals_or_tax_changed: bool
    roundtrip_loss: bool


def _changed_fields(before: Any, after: Any, prefix: str = "") -> tuple[str, ...]:
    if is_dataclass(before) and is_dataclass(after) and type(before) is type(after):
        changed: list[str] = []
        for field in fields(before):
            name = f"{prefix}.{field.name}" if prefix else field.name
            changed.extend(
                _changed_fields(
                    getattr(before, field.name),
                    getattr(after, field.name),
                    name,
                )
            )
        return tuple(changed)
    if isinstance(before, tuple) and isinstance(after, tuple):
        changed = []
        common = min(len(before), len(after))
        for index in range(common):
            changed.extend(_changed_fields(before[index], after[index], f"{prefix}[{index}]"))
        if len(before) != len(after):
            changed.append(f"{prefix}.length")
        return tuple(changed)
    return () if before == after else (prefix,)


def _invoice_changes(before: Invoice, after: Invoice) -> tuple[str, ...]:
    changed = list(_changed_fields(before, after))
    for field in _TOTAL_FIELDS:
        if getattr(before, field) != getattr(after, field):
            changed.append(field)
    return tuple(changed)


def compare_semantics(
    source: Invoice,
    *,
    imported: Invoice,
    roundtrip: Invoice,
) -> SemanticComparison:
    """Compare normalized source, importer, and round-trip invoice semantics."""

    source.validate()
    imported.validate()
    roundtrip.validate()
    imported_changes = _invoice_changes(source, imported)
    roundtrip_changes = _invoice_changes(imported, roundtrip)
    return SemanticComparison(
        imported_changed_fields=imported_changes,
        roundtrip_changed_fields=roundtrip_changes,
        totals_or_tax_changed=any(
            field in _TOTAL_FIELDS for field in (*imported_changes, *roundtrip_changes)
        ),
        roundtrip_loss=bool(roundtrip_changes),
    )
