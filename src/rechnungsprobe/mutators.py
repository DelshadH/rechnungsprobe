from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

from rechnungsprobe.model import Invoice, InvoiceLine

Mutator = Callable[[Invoice, int], Invoice]


def _replace_first(invoice: Invoice, line: InvoiceLine) -> Invoice:
    return replace(invoice, lines=(line, *invoice.lines[1:]))


def _invoice_id(invoice: Invoice, token: int) -> Invoice:
    return replace(invoice, identifier=f"RP-{token:08d}")


def _buyer_reference(invoice: Invoice, token: int) -> Invoice:
    return replace(invoice, buyer_reference=f"LEITWEG-ID-{token:08d}")


def _invoice_note_unicode(invoice: Invoice, token: int) -> Invoice:
    return replace(invoice, note=f"Prüfung № {token} – gültige Unicode-Zeichen")


def _seller_endpoint(invoice: Invoice, token: int) -> Invoice:
    return replace(
        invoice,
        seller=replace(invoice.seller, endpoint=f"seller-{token}@example.invalid"),
    )


def _buyer_endpoint(invoice: Invoice, token: int) -> Invoice:
    return replace(
        invoice,
        buyer=replace(invoice.buyer, endpoint=f"buyer-{token}@example.invalid"),
    )


def _seller_name(invoice: Invoice, token: int) -> Invoice:
    return replace(
        invoice,
        seller=replace(
            invoice.seller,
            trading_name=f"Musterlieferant {token}",
            registration_name=f"Musterlieferant GmbH {token}",
        ),
    )


def _buyer_name(invoice: Invoice, token: int) -> Invoice:
    return replace(
        invoice,
        buyer=replace(invoice.buyer, registration_name=f"Musterkunde {token}"),
    )


def _payment_terms(invoice: Invoice, token: int) -> Invoice:
    days = token % 28 + 1
    return replace(invoice, payment_terms=f"Zahlbar innerhalb von {days} Tagen.")


def _line_order(invoice: Invoice, _token: int) -> Invoice:
    return replace(invoice, lines=tuple(reversed(invoice.lines)))


def _line_description(invoice: Invoice, token: int) -> Invoice:
    line = replace(invoice.lines[0], description=f"Leistung – Variante {token}")
    return _replace_first(invoice, line)


def _line_identifier(invoice: Invoice, token: int) -> Invoice:
    line = replace(invoice.lines[0], identifier=f"POSITION-{token:08d}")
    return _replace_first(invoice, line)


def _quantity_scale(invoice: Invoice, token: int) -> Invoice:
    quantity = Decimal(token % 7 + 2) / Decimal(4)
    line = replace(invoice.lines[0], quantity=quantity)
    return _replace_first(invoice, line)


def _price_scale(invoice: Invoice, token: int) -> Invoice:
    price = (Decimal(token % 997 + 101) / Decimal(100)).quantize(Decimal("0.01"))
    line = replace(invoice.lines[0], price=price)
    return _replace_first(invoice, line)


def _vat_rate(invoice: Invoice, _token: int) -> Invoice:
    rate = Decimal(19) if invoice.lines[0].vat_rate != Decimal(19) else Decimal(7)
    return replace(
        invoice,
        lines=tuple(replace(line, vat_rate=rate) for line in invoice.lines),
    )


def _line_note(invoice: Invoice, token: int) -> Invoice:
    line = replace(invoice.lines[0], note=f"Hinweis zur Position {token}")
    return _replace_first(invoice, line)


def _seller_identifier(invoice: Invoice, token: int) -> Invoice:
    return replace(
        invoice,
        seller=replace(invoice.seller, party_identifier=f"DE-RP-{token:08d}"),
    )


def _address_variant(invoice: Invoice, token: int) -> Invoice:
    return replace(
        invoice,
        seller=replace(
            invoice.seller,
            street=f"Prüfstraße {token % 200 + 1}",
            city="Köln",
            postal_code="50667",
        ),
    )


def _add_line(invoice: Invoice, token: int) -> Invoice:
    added = replace(
        invoice.lines[0],
        identifier=f"ZUSATZ-{token:08d}",
        quantity=Decimal(1),
        price=Decimal("1.00"),
        name=f"Zusatzposition {token}",
        note=None,
        description=None,
        period_start=None,
        period_end=None,
        order_line_identifier=None,
        seller_item_identifier=None,
        classification_code=None,
        classification_list=None,
    )
    return replace(invoice, lines=(*invoice.lines, added))


def _remove_optionals(invoice: Invoice, _token: int) -> Invoice:
    line = replace(
        invoice.lines[0],
        note=None,
        description=None,
        period_start=None,
        period_end=None,
        order_line_identifier=None,
        seller_item_identifier=None,
        classification_code=None,
        classification_list=None,
    )
    return replace(invoice, note=None, lines=(line, *invoice.lines[1:]))


def _payment_due_date(invoice: Invoice, token: int) -> Invoice:
    return replace(
        invoice,
        payment_due_date=invoice.issue_date + timedelta(days=token % 28 + 1),
    )


MUTATORS: dict[str, Mutator] = {
    "invoice-id": _invoice_id,
    "buyer-reference": _buyer_reference,
    "invoice-note-unicode": _invoice_note_unicode,
    "seller-endpoint": _seller_endpoint,
    "buyer-endpoint": _buyer_endpoint,
    "seller-name": _seller_name,
    "buyer-name": _buyer_name,
    "payment-terms": _payment_terms,
    "line-order": _line_order,
    "line-description": _line_description,
    "line-identifier": _line_identifier,
    "quantity-scale": _quantity_scale,
    "price-scale": _price_scale,
    "vat-rate": _vat_rate,
    "line-note": _line_note,
    "seller-identifier": _seller_identifier,
    "address-variant": _address_variant,
    "add-line": _add_line,
    "remove-optionals": _remove_optionals,
    "payment-due-date": _payment_due_date,
}


def mutate(invoice: Invoice, name: str, *, token: int) -> Invoice:
    invoice.validate()
    try:
        mutator = MUTATORS[name]
    except KeyError as error:
        raise ValueError(f"unknown mutator: {name}") from error
    mutated = mutator(invoice, token)
    mutated.validate()
    return mutated
