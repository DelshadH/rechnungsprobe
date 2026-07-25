from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, fields, is_dataclass
from datetime import date
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from pathlib import Path
from typing import Any, cast
from xml.etree import ElementTree

from rechnungsprobe.xmlsafe import load_xml, parse_xml_bytes

UBL = "urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
CBC = "urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
CAC = "urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
NS = {"ubl": UBL, "cbc": CBC, "cac": CAC}
MONEY_QUANTUM = Decimal("0.01")

ElementTree.register_namespace("ubl", UBL)
ElementTree.register_namespace("cbc", CBC)
ElementTree.register_namespace("cac", CAC)


class ModelError(ValueError):
    """Raised when an invoice violates the supported semantic model."""


def _required_text(element: ElementTree.Element, path: str) -> str:
    found = element.find(path, NS)
    if found is None or found.text is None or not found.text.strip():
        raise ModelError(f"required invoice field is missing: {path}")
    return found.text


def _optional_text(element: ElementTree.Element, path: str) -> str | None:
    found = element.find(path, NS)
    if found is None or found.text is None:
        return None
    return found.text or None


def _decimal(value: str, field: str) -> Decimal:
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise ModelError(f"{field} is not a decimal") from error
    if not parsed.is_finite():
        raise ModelError(f"{field} must be finite")
    return parsed


def _date(value: str, field: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise ModelError(f"{field} is not an ISO date") from error


def _validate_text(value: str | None, field: str, limit: int = 1000) -> None:
    if value is None:
        return
    if not value or len(value) > limit:
        raise ModelError(f"{field} has an invalid length")
    if any(ord(character) < 32 and character not in "\t\n\r" for character in value):
        raise ModelError(f"{field} contains an XML control character")


def _validate_decimal(value: Decimal, field: str, *, positive: bool) -> None:
    if not value.is_finite():
        raise ModelError(f"{field} must be finite")
    if positive and value <= 0:
        raise ModelError(f"{field} must be positive")
    if not positive and value < 0:
        raise ModelError(f"{field} must not be negative")
    exponent = cast(int, value.as_tuple().exponent)
    if abs(value) > Decimal(1000000000) or exponent < -6:
        raise ModelError(f"{field} is outside the supported numeric bounds")


@dataclass(frozen=True, slots=True)
class Party:
    endpoint: str
    endpoint_scheme: str
    registration_name: str
    street: str
    city: str
    postal_code: str
    country_code: str
    trading_name: str | None = None
    tax_identifier: str | None = None
    legal_identifier: str | None = None
    legal_form: str | None = None
    party_identifier: str | None = None
    contact_name: str | None = None
    contact_phone: str | None = None
    contact_email: str | None = None

    def validate(self, field: str) -> None:
        for name in (
            "endpoint",
            "endpoint_scheme",
            "registration_name",
            "street",
            "city",
            "postal_code",
            "country_code",
        ):
            _validate_text(getattr(self, name), f"{field}.{name}")
        for name in (
            "trading_name",
            "tax_identifier",
            "legal_identifier",
            "legal_form",
            "party_identifier",
            "contact_name",
            "contact_phone",
            "contact_email",
        ):
            _validate_text(getattr(self, name), f"{field}.{name}")
        if len(self.country_code) != 2 or not self.country_code.isalpha():
            raise ModelError(f"{field}.country_code must be a two-letter code")
        if self.endpoint_scheme == "EM" and "@" not in self.endpoint:
            raise ModelError(f"{field}.endpoint must be an email for scheme EM")


@dataclass(frozen=True, slots=True)
class InvoiceLine:
    identifier: str
    quantity: Decimal
    unit_code: str
    price: Decimal
    name: str
    vat_category: str
    vat_rate: Decimal
    note: str | None = None
    description: str | None = None
    period_start: date | None = None
    period_end: date | None = None
    order_line_identifier: str | None = None
    seller_item_identifier: str | None = None
    classification_code: str | None = None
    classification_list: str | None = None

    @property
    def line_extension(self) -> Decimal:
        return (self.quantity * self.price).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)

    def validate(self, index: int) -> None:
        prefix = f"lines[{index}]"
        for name in ("identifier", "unit_code", "name", "vat_category"):
            _validate_text(getattr(self, name), f"{prefix}.{name}")
        for name in (
            "note",
            "description",
            "order_line_identifier",
            "seller_item_identifier",
            "classification_code",
            "classification_list",
        ):
            _validate_text(getattr(self, name), f"{prefix}.{name}", limit=5000)
        _validate_decimal(self.quantity, f"{prefix}.quantity", positive=True)
        _validate_decimal(self.price, f"{prefix}.price", positive=False)
        _validate_decimal(self.vat_rate, f"{prefix}.vat_rate", positive=True)
        if self.vat_category != "S":
            raise ModelError(f"{prefix}.vat_category must be S in the pinned profile")
        if (self.period_start is None) != (self.period_end is None):
            raise ModelError(f"{prefix}.period must have both dates")
        if (
            self.period_start is not None
            and self.period_end is not None
            and self.period_end < self.period_start
        ):
            raise ModelError(f"{prefix}.period dates are reversed")
        if (self.classification_code is None) != (self.classification_list is None):
            raise ModelError(f"{prefix}.classification must have code and list")


@dataclass(frozen=True, slots=True)
class Invoice:
    customization_id: str
    profile_id: str
    identifier: str
    issue_date: date
    invoice_type_code: str
    currency: str
    buyer_reference: str
    seller: Party
    buyer: Party
    payment_means_code: str
    payee_account_identifier: str
    payment_terms: str
    lines: tuple[InvoiceLine, ...]
    note: str | None = None
    payment_due_date: date | None = None

    @property
    def line_total(self) -> Decimal:
        return sum((line.line_extension for line in self.lines), Decimal()).quantize(MONEY_QUANTUM)

    @property
    def tax_total(self) -> Decimal:
        return sum(
            (
                (line.line_extension * line.vat_rate / Decimal(100)).quantize(
                    MONEY_QUANTUM,
                    rounding=ROUND_HALF_UP,
                )
                for line in self.lines
            ),
            Decimal(),
        ).quantize(MONEY_QUANTUM)

    @property
    def payable_total(self) -> Decimal:
        return (self.line_total + self.tax_total).quantize(MONEY_QUANTUM)

    def validate(self) -> None:
        for name in (
            "customization_id",
            "profile_id",
            "identifier",
            "invoice_type_code",
            "currency",
            "buyer_reference",
            "payment_means_code",
            "payee_account_identifier",
            "payment_terms",
        ):
            _validate_text(getattr(self, name), name, limit=5000)
        _validate_text(self.note, "note", limit=5000)
        self.seller.validate("seller")
        self.buyer.validate("buyer")
        if self.currency != "EUR":
            raise ModelError("only EUR is supported by the pinned seed model")
        if not 1 <= len(self.lines) <= 100:
            raise ModelError("invoice must contain between one and 100 lines")
        identifiers: set[str] = set()
        rates: set[Decimal] = set()
        for index, line in enumerate(self.lines):
            line.validate(index)
            if line.identifier in identifiers:
                raise ModelError("line identifiers must be unique")
            identifiers.add(line.identifier)
            rates.add(line.vat_rate.normalize())
        if len(rates) != 1:
            raise ModelError("the first profile model supports one VAT rate per invoice")
        if self.payment_due_date is not None and self.payment_due_date < self.issue_date:
            raise ModelError("payment due date precedes issue date")


def _parse_party(element: ElementTree.Element) -> Party:
    endpoint = element.find("cbc:EndpointID", NS)
    if endpoint is None:
        raise ModelError("party endpoint is missing")
    return Party(
        endpoint=endpoint.text or "",
        endpoint_scheme=endpoint.attrib.get("schemeID", ""),
        registration_name=_required_text(
            element,
            "cac:PartyLegalEntity/cbc:RegistrationName",
        ),
        street=_required_text(element, "cac:PostalAddress/cbc:StreetName"),
        city=_required_text(element, "cac:PostalAddress/cbc:CityName"),
        postal_code=_required_text(element, "cac:PostalAddress/cbc:PostalZone"),
        country_code=_required_text(
            element,
            "cac:PostalAddress/cac:Country/cbc:IdentificationCode",
        ),
        trading_name=_optional_text(element, "cac:PartyName/cbc:Name"),
        tax_identifier=_optional_text(element, "cac:PartyTaxScheme/cbc:CompanyID"),
        legal_identifier=_optional_text(
            element,
            "cac:PartyLegalEntity/cbc:CompanyID",
        ),
        legal_form=_optional_text(
            element,
            "cac:PartyLegalEntity/cbc:CompanyLegalForm",
        ),
        party_identifier=_optional_text(element, "cac:PartyIdentification/cbc:ID"),
        contact_name=_optional_text(element, "cac:Contact/cbc:Name"),
        contact_phone=_optional_text(element, "cac:Contact/cbc:Telephone"),
        contact_email=_optional_text(element, "cac:Contact/cbc:ElectronicMail"),
    )


def _parse_line(element: ElementTree.Element, currency: str) -> InvoiceLine:
    quantity = element.find("cbc:InvoicedQuantity", NS)
    price = element.find("cac:Price/cbc:PriceAmount", NS)
    if quantity is None or price is None:
        raise ModelError("invoice line quantity or price is missing")
    line = InvoiceLine(
        identifier=_required_text(element, "cbc:ID"),
        quantity=_decimal(quantity.text or "", "line quantity"),
        unit_code=quantity.attrib.get("unitCode", ""),
        price=_decimal(price.text or "", "line price"),
        name=_required_text(element, "cac:Item/cbc:Name"),
        vat_category=_required_text(element, "cac:Item/cac:ClassifiedTaxCategory/cbc:ID"),
        vat_rate=_decimal(
            _required_text(
                element,
                "cac:Item/cac:ClassifiedTaxCategory/cbc:Percent",
            ),
            "line VAT rate",
        ),
        note=_optional_text(element, "cbc:Note"),
        description=_optional_text(element, "cac:Item/cbc:Description"),
        period_start=(
            _date(value, "line period start")
            if (value := _optional_text(element, "cac:InvoicePeriod/cbc:StartDate"))
            else None
        ),
        period_end=(
            _date(value, "line period end")
            if (value := _optional_text(element, "cac:InvoicePeriod/cbc:EndDate"))
            else None
        ),
        order_line_identifier=_optional_text(
            element,
            "cac:OrderLineReference/cbc:LineID",
        ),
        seller_item_identifier=_optional_text(
            element,
            "cac:Item/cac:SellersItemIdentification/cbc:ID",
        ),
        classification_code=_optional_text(
            element,
            "cac:Item/cac:CommodityClassification/cbc:ItemClassificationCode",
        ),
        classification_list=(
            classification.attrib.get("listID")
            if (
                classification := element.find(
                    "cac:Item/cac:CommodityClassification/cbc:ItemClassificationCode",
                    NS,
                )
            )
            is not None
            else None
        ),
    )
    reported = _decimal(
        _required_text(element, "cbc:LineExtensionAmount"),
        "line extension amount",
    )
    if reported.quantize(MONEY_QUANTUM) != line.line_extension:
        raise ModelError("line extension amount does not match quantity and price")
    extension = element.find("cbc:LineExtensionAmount", NS)
    if extension is not None and extension.attrib.get("currencyID") != currency:
        raise ModelError("line extension currency does not match invoice currency")
    return line


def parse_invoice(source: Path | bytes) -> Invoice:
    document = load_xml(source) if isinstance(source, Path) else parse_xml_bytes(source)
    root = document.root
    if root.tag != f"{{{UBL}}}Invoice":
        raise ModelError("document is not a UBL Invoice")
    currency = _required_text(root, "cbc:DocumentCurrencyCode")
    supplier = root.find("cac:AccountingSupplierParty/cac:Party", NS)
    customer = root.find("cac:AccountingCustomerParty/cac:Party", NS)
    if supplier is None or customer is None:
        raise ModelError("supplier or customer party is missing")
    due_date_text = _optional_text(root, "cac:PaymentMeans/cbc:PaymentDueDate")
    invoice = Invoice(
        customization_id=_required_text(root, "cbc:CustomizationID"),
        profile_id=_required_text(root, "cbc:ProfileID"),
        identifier=_required_text(root, "cbc:ID"),
        issue_date=_date(_required_text(root, "cbc:IssueDate"), "issue date"),
        invoice_type_code=_required_text(root, "cbc:InvoiceTypeCode"),
        currency=currency,
        buyer_reference=_required_text(root, "cbc:BuyerReference"),
        seller=_parse_party(supplier),
        buyer=_parse_party(customer),
        payment_means_code=_required_text(
            root,
            "cac:PaymentMeans/cbc:PaymentMeansCode",
        ),
        payee_account_identifier=_required_text(
            root,
            "cac:PaymentMeans/cac:PayeeFinancialAccount/cbc:ID",
        ),
        payment_terms=_required_text(root, "cac:PaymentTerms/cbc:Note"),
        lines=tuple(
            _parse_line(element, currency) for element in root.findall("cac:InvoiceLine", NS)
        ),
        note=_optional_text(root, "cbc:Note"),
        payment_due_date=(_date(due_date_text, "payment due date") if due_date_text else None),
    )
    invoice.validate()
    reported_line_total = _decimal(
        _required_text(root, "cac:LegalMonetaryTotal/cbc:LineExtensionAmount"),
        "line total",
    )
    reported_tax = _decimal(
        _required_text(root, "cac:TaxTotal/cbc:TaxAmount"),
        "tax total",
    )
    reported_payable = _decimal(
        _required_text(root, "cac:LegalMonetaryTotal/cbc:PayableAmount"),
        "payable total",
    )
    if reported_line_total.quantize(MONEY_QUANTUM) != invoice.line_total:
        raise ModelError("reported line total does not match lines")
    if reported_tax.quantize(MONEY_QUANTUM) != invoice.tax_total:
        raise ModelError("reported tax total does not match lines")
    if reported_payable.quantize(MONEY_QUANTUM) != invoice.payable_total:
        raise ModelError("reported payable total does not match lines")
    return invoice


def _tag(namespace: str, local: str) -> str:
    return f"{{{namespace}}}{local}"


def _add(
    parent: ElementTree.Element,
    namespace: str,
    local: str,
    text: str | None = None,
    attributes: dict[str, str] | None = None,
) -> ElementTree.Element:
    element = ElementTree.SubElement(parent, _tag(namespace, local), attributes or {})
    element.text = text
    return element


def _decimal_text(value: Decimal) -> str:
    normalized = value.normalize()
    if normalized == 0:
        return "0"
    return format(normalized, "f")


def _money_text(value: Decimal) -> str:
    return format(value.quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP), ".2f")


def _serialize_party(parent: ElementTree.Element, party: Party) -> None:
    party_element = _add(parent, CAC, "Party")
    _add(
        party_element,
        CBC,
        "EndpointID",
        party.endpoint,
        {"schemeID": party.endpoint_scheme},
    )
    if party.party_identifier is not None:
        identification = _add(party_element, CAC, "PartyIdentification")
        _add(identification, CBC, "ID", party.party_identifier)
    if party.trading_name is not None:
        party_name = _add(party_element, CAC, "PartyName")
        _add(party_name, CBC, "Name", party.trading_name)
    address = _add(party_element, CAC, "PostalAddress")
    _add(address, CBC, "StreetName", party.street)
    _add(address, CBC, "CityName", party.city)
    _add(address, CBC, "PostalZone", party.postal_code)
    country = _add(address, CAC, "Country")
    _add(country, CBC, "IdentificationCode", party.country_code)
    if party.tax_identifier is not None:
        tax_scheme = _add(party_element, CAC, "PartyTaxScheme")
        _add(tax_scheme, CBC, "CompanyID", party.tax_identifier)
        scheme = _add(tax_scheme, CAC, "TaxScheme")
        _add(scheme, CBC, "ID", "VAT")
    legal = _add(party_element, CAC, "PartyLegalEntity")
    _add(legal, CBC, "RegistrationName", party.registration_name)
    if party.legal_identifier is not None:
        _add(legal, CBC, "CompanyID", party.legal_identifier)
    if party.legal_form is not None:
        _add(legal, CBC, "CompanyLegalForm", party.legal_form)
    if any((party.contact_name, party.contact_phone, party.contact_email)):
        contact = _add(party_element, CAC, "Contact")
        if party.contact_name is not None:
            _add(contact, CBC, "Name", party.contact_name)
        if party.contact_phone is not None:
            _add(contact, CBC, "Telephone", party.contact_phone)
        if party.contact_email is not None:
            _add(contact, CBC, "ElectronicMail", party.contact_email)


def serialize_invoice(invoice: Invoice) -> bytes:
    invoice.validate()
    root = ElementTree.Element(_tag(UBL, "Invoice"))
    _add(root, CBC, "CustomizationID", invoice.customization_id)
    _add(root, CBC, "ProfileID", invoice.profile_id)
    _add(root, CBC, "ID", invoice.identifier)
    _add(root, CBC, "IssueDate", invoice.issue_date.isoformat())
    _add(root, CBC, "InvoiceTypeCode", invoice.invoice_type_code)
    if invoice.note is not None:
        _add(root, CBC, "Note", invoice.note)
    _add(root, CBC, "DocumentCurrencyCode", invoice.currency)
    _add(root, CBC, "BuyerReference", invoice.buyer_reference)
    supplier = _add(root, CAC, "AccountingSupplierParty")
    _serialize_party(supplier, invoice.seller)
    customer = _add(root, CAC, "AccountingCustomerParty")
    _serialize_party(customer, invoice.buyer)
    payment = _add(root, CAC, "PaymentMeans")
    _add(payment, CBC, "PaymentMeansCode", invoice.payment_means_code)
    if invoice.payment_due_date is not None:
        _add(payment, CBC, "PaymentDueDate", invoice.payment_due_date.isoformat())
    account = _add(payment, CAC, "PayeeFinancialAccount")
    _add(account, CBC, "ID", invoice.payee_account_identifier)
    terms = _add(root, CAC, "PaymentTerms")
    _add(terms, CBC, "Note", invoice.payment_terms)

    tax = _add(root, CAC, "TaxTotal")
    _add(tax, CBC, "TaxAmount", _money_text(invoice.tax_total), {"currencyID": invoice.currency})
    subtotal = _add(tax, CAC, "TaxSubtotal")
    _add(
        subtotal,
        CBC,
        "TaxableAmount",
        _money_text(invoice.line_total),
        {"currencyID": invoice.currency},
    )
    _add(
        subtotal,
        CBC,
        "TaxAmount",
        _money_text(invoice.tax_total),
        {"currencyID": invoice.currency},
    )
    category = _add(subtotal, CAC, "TaxCategory")
    _add(category, CBC, "ID", "S")
    _add(category, CBC, "Percent", _decimal_text(invoice.lines[0].vat_rate))
    tax_scheme = _add(category, CAC, "TaxScheme")
    _add(tax_scheme, CBC, "ID", "VAT")

    totals = _add(root, CAC, "LegalMonetaryTotal")
    for local, amount in (
        ("LineExtensionAmount", invoice.line_total),
        ("TaxExclusiveAmount", invoice.line_total),
        ("TaxInclusiveAmount", invoice.payable_total),
        ("PayableAmount", invoice.payable_total),
    ):
        _add(
            totals,
            CBC,
            local,
            _money_text(amount),
            {"currencyID": invoice.currency},
        )

    for line in invoice.lines:
        line_element = _add(root, CAC, "InvoiceLine")
        _add(line_element, CBC, "ID", line.identifier)
        if line.note is not None:
            _add(line_element, CBC, "Note", line.note)
        _add(
            line_element,
            CBC,
            "InvoicedQuantity",
            _decimal_text(line.quantity),
            {"unitCode": line.unit_code},
        )
        _add(
            line_element,
            CBC,
            "LineExtensionAmount",
            _money_text(line.line_extension),
            {"currencyID": invoice.currency},
        )
        if line.period_start is not None and line.period_end is not None:
            period = _add(line_element, CAC, "InvoicePeriod")
            _add(period, CBC, "StartDate", line.period_start.isoformat())
            _add(period, CBC, "EndDate", line.period_end.isoformat())
        if line.order_line_identifier is not None:
            order = _add(line_element, CAC, "OrderLineReference")
            _add(order, CBC, "LineID", line.order_line_identifier)
        item = _add(line_element, CAC, "Item")
        if line.description is not None:
            _add(item, CBC, "Description", line.description)
        _add(item, CBC, "Name", line.name)
        if line.seller_item_identifier is not None:
            seller_item = _add(item, CAC, "SellersItemIdentification")
            _add(seller_item, CBC, "ID", line.seller_item_identifier)
        if line.classification_code is not None and line.classification_list is not None:
            classification = _add(item, CAC, "CommodityClassification")
            _add(
                classification,
                CBC,
                "ItemClassificationCode",
                line.classification_code,
                {"listID": line.classification_list},
            )
        line_tax = _add(item, CAC, "ClassifiedTaxCategory")
        _add(line_tax, CBC, "ID", line.vat_category)
        _add(line_tax, CBC, "Percent", _decimal_text(line.vat_rate))
        line_scheme = _add(line_tax, CAC, "TaxScheme")
        _add(line_scheme, CBC, "ID", "VAT")
        price = _add(line_element, CAC, "Price")
        _add(
            price,
            CBC,
            "PriceAmount",
            _decimal_text(line.price),
            {"currencyID": invoice.currency},
        )

    return (
        cast(
            bytes,
            ElementTree.tostring(
                root,
                encoding="utf-8",
                xml_declaration=True,
                short_empty_elements=True,
            ),
        )
        + b"\n"
    )


def _canonical_value(value: Any) -> Any:
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ModelError("fingerprint decimal must be finite")
        return _decimal_text(value)
    if isinstance(value, date):
        return value.isoformat()
    if is_dataclass(value):
        return {field.name: _canonical_value(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, tuple):
        return [_canonical_value(item) for item in value]
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    if isinstance(value, float) and math.isfinite(value):
        return repr(value)
    raise ModelError(f"unsupported fingerprint value: {type(value).__name__}")


def semantic_fingerprint(invoice: Invoice) -> str:
    invoice.validate()
    payload = json.dumps(
        {"model": "xrechnung-ubl-3.0.2-v1", "invoice": _canonical_value(invoice)},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
