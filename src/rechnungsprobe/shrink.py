from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from decimal import Decimal
from typing import Literal

from rechnungsprobe.model import (
    Invoice,
    InvoiceLine,
    ModelError,
    Party,
    semantic_fingerprint,
    serialize_invoice,
)

ValidityCheck = Callable[[bytes], bool]
BatchValidityCheck = Callable[[tuple[bytes, ...]], tuple[bool, ...]]
FindingCheck = Callable[[bytes], bool]
PartyName = Literal["seller", "buyer"]
PartyOptionalField = Literal[
    "trading_name",
    "tax_identifier",
    "legal_identifier",
    "legal_form",
    "party_identifier",
    "contact_name",
    "contact_phone",
    "contact_email",
]
PartyTextField = Literal["endpoint", "registration_name", "street", "city", "postal_code"]
LineOptionalField = Literal[
    "note",
    "description",
    "order_line_identifier",
    "seller_item_identifier",
]
LineTextField = Literal["identifier", "name", "note", "description"]
InvoiceTextField = Literal[
    "identifier",
    "buyer_reference",
    "payment_terms",
    "payee_account_identifier",
]


@dataclass(frozen=True, slots=True)
class Reduction:
    operation: str
    invoice: Invoice


@dataclass(frozen=True, slots=True)
class ShrinkResult:
    invoice: Invoice
    attempts: int
    accepted: tuple[str, ...]
    fingerprint: str


@dataclass(frozen=True, slots=True)
class MinimalityResult:
    minimal: bool
    attempts: int
    reducing_operation: str | None


def _text_reductions(value: str) -> Iterator[tuple[str, str]]:
    if len(value) <= 1:
        return
    midpoint = (len(value) + 1) // 2
    values = (
        ("keep-prefix-half", value[:midpoint]),
        ("keep-suffix-half", value[len(value) // 2 :]),
        ("drop-last-character", value[:-1]),
        ("drop-first-character", value[1:]),
        ("replace-minimal", "A"),
    )
    seen: set[str] = set()
    for operation, candidate in values:
        if candidate and candidate != value and candidate not in seen:
            seen.add(candidate)
            yield operation, candidate


def _replace_party(invoice: Invoice, party_name: PartyName, party: Party) -> Invoice:
    if party_name == "seller":
        return replace(invoice, seller=party)
    return replace(invoice, buyer=party)


def _remove_party_optional(party: Party, field_name: PartyOptionalField) -> Party:
    if field_name == "trading_name":
        return replace(party, trading_name=None)
    if field_name == "tax_identifier":
        return replace(party, tax_identifier=None)
    if field_name == "legal_identifier":
        return replace(party, legal_identifier=None)
    if field_name == "legal_form":
        return replace(party, legal_form=None)
    if field_name == "party_identifier":
        return replace(party, party_identifier=None)
    if field_name == "contact_name":
        return replace(party, contact_name=None)
    if field_name == "contact_phone":
        return replace(party, contact_phone=None)
    return replace(party, contact_email=None)


def _replace_party_text(party: Party, field_name: PartyTextField, value: str) -> Party:
    if field_name == "endpoint":
        return replace(party, endpoint=value)
    if field_name == "registration_name":
        return replace(party, registration_name=value)
    if field_name == "street":
        return replace(party, street=value)
    if field_name == "city":
        return replace(party, city=value)
    return replace(party, postal_code=value)


def _party_reductions(
    invoice: Invoice,
    party_name: PartyName,
    party: Party,
) -> Iterator[Reduction]:
    optional_fields: tuple[PartyOptionalField, ...] = (
        "trading_name",
        "tax_identifier",
        "legal_identifier",
        "legal_form",
        "party_identifier",
        "contact_name",
        "contact_phone",
        "contact_email",
    )
    for optional_name in optional_fields:
        if getattr(party, optional_name) is not None:
            reduced_party = _remove_party_optional(party, optional_name)
            yield Reduction(
                f"remove-{party_name}-{optional_name}",
                _replace_party(invoice, party_name, reduced_party),
            )

    text_fields: tuple[PartyTextField, ...] = (
        "endpoint",
        "registration_name",
        "street",
        "city",
        "postal_code",
    )
    for text_name in text_fields:
        text_value = getattr(party, text_name)
        for operation, reduced_value in _text_reductions(text_value):
            reduced_party = _replace_party_text(party, text_name, reduced_value)
            yield Reduction(
                f"{party_name}-{text_name}-{operation}",
                _replace_party(invoice, party_name, reduced_party),
            )


def _replace_line(invoice: Invoice, index: int, line: InvoiceLine) -> Invoice:
    lines = list(invoice.lines)
    lines[index] = line
    return replace(invoice, lines=tuple(lines))


def _remove_line_optional(line: InvoiceLine, field_name: LineOptionalField) -> InvoiceLine:
    if field_name == "note":
        return replace(line, note=None)
    if field_name == "description":
        return replace(line, description=None)
    if field_name == "order_line_identifier":
        return replace(line, order_line_identifier=None)
    return replace(line, seller_item_identifier=None)


def _replace_line_text(
    line: InvoiceLine,
    field_name: LineTextField,
    value: str,
) -> InvoiceLine:
    if field_name == "identifier":
        return replace(line, identifier=value)
    if field_name == "name":
        return replace(line, name=value)
    if field_name == "note":
        return replace(line, note=value)
    return replace(line, description=value)


def _replace_invoice_text(
    invoice: Invoice,
    field_name: InvoiceTextField,
    value: str,
) -> Invoice:
    if field_name == "identifier":
        return replace(invoice, identifier=value)
    if field_name == "buyer_reference":
        return replace(invoice, buyer_reference=value)
    if field_name == "payment_terms":
        return replace(invoice, payment_terms=value)
    return replace(invoice, payee_account_identifier=value)


def _line_reductions(
    invoice: Invoice,
    index: int,
    line: InvoiceLine,
) -> Iterator[Reduction]:
    optional_fields: tuple[LineOptionalField, ...] = (
        "note",
        "description",
        "order_line_identifier",
        "seller_item_identifier",
    )
    for optional_name in optional_fields:
        if getattr(line, optional_name) is not None:
            yield Reduction(
                f"line-{index}-remove-{optional_name}",
                _replace_line(invoice, index, _remove_line_optional(line, optional_name)),
            )
    if line.period_start is not None:
        yield Reduction(
            f"line-{index}-remove-period",
            _replace_line(
                invoice,
                index,
                replace(line, period_start=None, period_end=None),
            ),
        )
    if line.classification_code is not None:
        yield Reduction(
            f"line-{index}-remove-classification",
            _replace_line(
                invoice,
                index,
                replace(
                    line,
                    classification_code=None,
                    classification_list=None,
                ),
            ),
        )

    text_fields: tuple[LineTextField, ...] = (
        "identifier",
        "name",
        "note",
        "description",
    )
    for text_name in text_fields:
        text_value = getattr(line, text_name)
        if text_value is None:
            continue
        for operation, reduced_value in _text_reductions(text_value):
            yield Reduction(
                f"line-{index}-{text_name}-{operation}",
                _replace_line(
                    invoice,
                    index,
                    _replace_line_text(line, text_name, reduced_value),
                ),
            )

    for numeric_name, numeric_value in (
        ("quantity", line.quantity),
        ("price", line.price),
    ):
        for numeric_reduced in (
            Decimal(1),
            numeric_value.quantize(Decimal("0.01")),
        ):
            if numeric_reduced != numeric_value:
                reduced_line = (
                    replace(line, quantity=numeric_reduced)
                    if numeric_name == "quantity"
                    else replace(line, price=numeric_reduced)
                )
                yield Reduction(
                    f"line-{index}-{numeric_name}-to-{numeric_reduced}",
                    _replace_line(invoice, index, reduced_line),
                )


def one_step_reductions(invoice: Invoice) -> tuple[Reduction, ...]:
    """Enumerate the declared deterministic structure-aware reduction relation."""

    invoice.validate()
    reductions: list[Reduction] = []
    if invoice.note is not None:
        reductions.append(Reduction("remove-invoice-note", replace(invoice, note=None)))
    if invoice.payment_due_date is not None:
        reductions.append(
            Reduction("remove-payment-due-date", replace(invoice, payment_due_date=None))
        )
    if len(invoice.lines) > 1:
        for index in range(len(invoice.lines) - 1, -1, -1):
            reductions.append(
                Reduction(
                    f"remove-line-{index}",
                    replace(
                        invoice,
                        lines=invoice.lines[:index] + invoice.lines[index + 1 :],
                    ),
                )
            )

    reductions.extend(_party_reductions(invoice, "seller", invoice.seller))
    reductions.extend(_party_reductions(invoice, "buyer", invoice.buyer))

    invoice_text_fields: tuple[InvoiceTextField, ...] = (
        "identifier",
        "buyer_reference",
        "payment_terms",
        "payee_account_identifier",
    )
    for field_name in invoice_text_fields:
        value = getattr(invoice, field_name)
        for operation, reduced_value in _text_reductions(value):
            reductions.append(
                Reduction(
                    f"{field_name}-{operation}",
                    _replace_invoice_text(invoice, field_name, reduced_value),
                )
            )

    for index, line in enumerate(invoice.lines):
        reductions.extend(_line_reductions(invoice, index, line))

    original = semantic_fingerprint(invoice)
    unique: dict[str, Reduction] = {}
    for reduction in reductions:
        try:
            reduction.invoice.validate()
            fingerprint = semantic_fingerprint(reduction.invoice)
        except ModelError:
            continue
        if fingerprint != original and fingerprint not in unique:
            unique[fingerprint] = reduction
    return tuple(unique.values())


def _check_initial(
    invoice: Invoice,
    *,
    is_valid: ValidityCheck,
    preserves_finding: FindingCheck,
) -> bytes:
    invoice_xml = serialize_invoice(invoice)
    if not is_valid(invoice_xml):
        raise ValueError("initial finding does not pass the pinned profile")
    if not preserves_finding(invoice_xml):
        raise ValueError("initial invoice does not reproduce the declared finding")
    return invoice_xml


def shrink_invoice(
    invoice: Invoice,
    *,
    is_valid: ValidityCheck,
    preserves_finding: FindingCheck,
    validate_batch: BatchValidityCheck | None = None,
) -> ShrinkResult:
    """Greedily reach a deterministic 1-minimal invoice."""

    initial_xml = _check_initial(
        invoice,
        is_valid=is_valid,
        preserves_finding=preserves_finding,
    )
    attempts = 1
    current = invoice
    accepted: list[str] = []
    checked = {initial_xml}
    while True:
        changed = False
        pending: list[tuple[Reduction, bytes]] = []
        for reduction in one_step_reductions(current):
            candidate_xml = serialize_invoice(reduction.invoice)
            if candidate_xml in checked:
                continue
            checked.add(candidate_xml)
            attempts += 1
            pending.append((reduction, candidate_xml))
        validities = (
            validate_batch(tuple(candidate for _reduction, candidate in pending))
            if validate_batch is not None and pending
            else tuple(is_valid(candidate) for _reduction, candidate in pending)
        )
        if len(validities) != len(pending):
            raise ValueError("batch validity check returned an unexpected result count")
        for (reduction, candidate_xml), valid in zip(pending, validities, strict=True):
            if not valid:
                continue
            if not preserves_finding(candidate_xml):
                continue
            current = reduction.invoice
            accepted.append(reduction.operation)
            changed = True
            break
        if not changed:
            break
    return ShrinkResult(
        invoice=current,
        attempts=attempts,
        accepted=tuple(accepted),
        fingerprint=semantic_fingerprint(current),
    )


def verify_one_minimal(
    invoice: Invoice,
    *,
    is_valid: ValidityCheck,
    preserves_finding: FindingCheck,
    validate_batch: BatchValidityCheck | None = None,
) -> MinimalityResult:
    """Independently rerun every declared one-step reduction."""

    _check_initial(
        invoice,
        is_valid=is_valid,
        preserves_finding=preserves_finding,
    )
    attempts = 1
    candidates = tuple(
        (reduction, serialize_invoice(reduction.invoice))
        for reduction in one_step_reductions(invoice)
    )
    validities = (
        validate_batch(tuple(candidate for _reduction, candidate in candidates))
        if validate_batch is not None and candidates
        else tuple(is_valid(candidate) for _reduction, candidate in candidates)
    )
    if len(validities) != len(candidates):
        raise ValueError("batch validity check returned an unexpected result count")
    for (reduction, candidate_xml), valid in zip(candidates, validities, strict=True):
        attempts += 1
        if valid and preserves_finding(candidate_xml):
            return MinimalityResult(
                minimal=False,
                attempts=attempts,
                reducing_operation=reduction.operation,
            )
    return MinimalityResult(
        minimal=True,
        attempts=attempts,
        reducing_operation=None,
    )
