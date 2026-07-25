from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from typing import Any

from rechnungsprobe.model import Invoice, ModelError, parse_invoice
from rechnungsprobe.reporting import strict_json
from rechnungsprobe.security import SecurityError
from rechnungsprobe.target import TargetResult
from rechnungsprobe.validate import ValidationResult

JsonScalar = str | int | bool | None


@dataclass(frozen=True, slots=True)
class EvaluationContext:
    input_xml: bytes
    output_validation: ValidationResult | None = None


@dataclass(frozen=True, slots=True)
class PredicateEvaluation:
    predicate: str
    matched: bool
    details: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CrashPredicate:
    name: str = "crash-or-nonzero"

    def evaluate(
        self,
        result: TargetResult,
        _context: EvaluationContext,
    ) -> PredicateEvaluation:
        matched = result.process.termination == "exited" and result.process.returncode not in {
            None,
            0,
        }
        return PredicateEvaluation(self.name, matched)


@dataclass(frozen=True, slots=True)
class TimeoutPredicate:
    name: str = "timeout"

    def evaluate(
        self,
        result: TargetResult,
        _context: EvaluationContext,
    ) -> PredicateEvaluation:
        return PredicateEvaluation(
            self.name,
            result.process.termination == "timeout",
        )


def _check_json_bounds(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
    budget = budget if budget is not None else [10_000]
    budget[0] -= 1
    if budget[0] < 0 or depth > 32:
        raise SecurityError("JSON output exceeds structural limits")
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 1000:
                raise SecurityError("JSON object key exceeds limits")
            _check_json_bounds(child, depth + 1, budget)
    elif isinstance(value, list):
        for child in value:
            _check_json_bounds(child, depth + 1, budget)
    elif not isinstance(value, (str, int, bool, type(None), float)):
        raise SecurityError("JSON output contains an unsupported value")


def _json_pointer(value: Any, pointer: str) -> Any:
    if pointer == "":
        return value
    if not pointer.startswith("/") or len(pointer) > 1000:
        raise SecurityError("JSON pointer is invalid")
    current = value
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            raise SecurityError("JSON pointer does not resolve")
    return current


@dataclass(frozen=True, slots=True)
class JsonPredicate:
    pointer: str
    expected: JsonScalar
    name: str = "stdout-json"

    def evaluate(
        self,
        result: TargetResult,
        _context: EvaluationContext,
    ) -> PredicateEvaluation:
        if len(result.process.stdout) > 1024 * 1024:
            raise SecurityError("JSON output exceeds the size limit")
        value = strict_json(result.process.stdout, max_bytes=1024 * 1024)
        _check_json_bounds(value)
        actual = _json_pointer(value, self.pointer)
        return PredicateEvaluation(
            self.name,
            actual == self.expected and type(actual) is type(self.expected),
            (f"pointer={self.pointer}",),
        )


@dataclass(frozen=True, slots=True)
class OutputValidityPredicate:
    name: str = "output-invalid"

    def evaluate(
        self,
        result: TargetResult,
        context: EvaluationContext,
    ) -> PredicateEvaluation:
        if result.output_xml is None:
            return PredicateEvaluation(self.name, True, ("output XML is missing",))
        if context.output_validation is None:
            raise SecurityError("output-validity predicate requires official validation")
        return PredicateEvaluation(
            self.name,
            not context.output_validation.valid,
            context.output_validation.errors,
        )


_FIELD_SELECTORS = {
    "identifier",
    "buyer_reference",
    "issue_date",
    "payment_terms",
    "payment_due_date",
    "seller.endpoint",
    "seller.registration_name",
    "seller.party_identifier",
    "buyer.endpoint",
    "buyer.registration_name",
    "lines.identifier",
    "lines.name",
    "lines.description",
    "lines.note",
    "lines.quantity",
    "lines.price",
    "lines.vat_rate",
}


def _scalar(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, Decimal):
        return format(value.normalize(), "f")
    if isinstance(value, date):
        return value.isoformat()
    return str(value)


def _field_value(invoice: Invoice, selector: str) -> object:
    if selector in {
        "identifier",
        "buyer_reference",
        "issue_date",
        "payment_terms",
        "payment_due_date",
    }:
        return _scalar(getattr(invoice, selector))
    if selector.startswith(("seller.", "buyer.")):
        party_name, field_name = selector.split(".", 1)
        return _scalar(getattr(getattr(invoice, party_name), field_name))
    if selector.startswith("lines."):
        field_name = selector.split(".", 1)[1]
        return tuple(_scalar(getattr(line, field_name)) for line in invoice.lines)
    raise SecurityError(f"unsupported field selector: {selector}")


@dataclass(frozen=True, slots=True)
class DeclaredFieldLossPredicate:
    fields: tuple[str, ...]
    name: str = "declared-field-loss"

    def __post_init__(self) -> None:
        if not self.fields or len(self.fields) > 32 or len(set(self.fields)) != len(self.fields):
            raise SecurityError("field selector list is invalid")
        if any(field not in _FIELD_SELECTORS for field in self.fields):
            raise SecurityError("unsupported field selector")

    def evaluate(
        self,
        result: TargetResult,
        context: EvaluationContext,
    ) -> PredicateEvaluation:
        if result.output_xml is None:
            return PredicateEvaluation(self.name, True, ("output XML is missing",))
        try:
            source = parse_invoice(context.input_xml)
            output = parse_invoice(result.output_xml)
        except (ModelError, SecurityError):
            return PredicateEvaluation(
                self.name,
                True,
                ("output is not a comparable supported invoice",),
            )
        lost = tuple(
            field
            for field in self.fields
            if _field_value(source, field) != _field_value(output, field)
        )
        return PredicateEvaluation(self.name, bool(lost), lost)
