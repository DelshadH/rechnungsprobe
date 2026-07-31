from __future__ import annotations

from typing import Literal

from rechnungsprobe.security import SecurityError

FindingKind = Literal[
    "valid-invoice-rejected",
    "accepted-but-parsed-incorrectly",
    "field-lost-or-altered",
    "totals-or-tax-changed",
    "optional-valid-construct-mishandled",
    "crash",
    "timeout-or-resource-exhaustion",
    "nondeterminism",
    "round-trip-loss",
]

_PREDICATE_KINDS: dict[str, FindingKind] = {
    "import-rejected": "valid-invoice-rejected",
    "parse-error": "accepted-but-parsed-incorrectly",
    "optional-construct": "optional-valid-construct-mishandled",
    "crash-or-nonzero": "crash",
    "timeout": "timeout-or-resource-exhaustion",
    "nondeterminism": "nondeterminism",
    "output-invalid": "round-trip-loss",
}
_RESOURCE_TERMINATIONS = {
    "timeout",
    "output_limit",
    "memory_limit",
    "cpu_limit",
    "process_limit",
    "file_limit",
}
_TOTAL_FIELDS = {"line_total", "tax_total", "payable_total"}


def classify_finding(
    predicate: str,
    *,
    termination: str,
    details: tuple[str, ...],
) -> FindingKind:
    """Map one observed predicate result to the public finding taxonomy."""

    if termination in _RESOURCE_TERMINATIONS:
        return "timeout-or-resource-exhaustion"
    if predicate == "declared-field-loss":
        return (
            "totals-or-tax-changed"
            if any(detail in _TOTAL_FIELDS for detail in details)
            else "field-lost-or-altered"
        )
    try:
        return _PREDICATE_KINDS[predicate]
    except KeyError as error:
        raise SecurityError("finding predicate has no declared classification") from error
