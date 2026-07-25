from __future__ import annotations

from dataclasses import replace

import pytest

from rechnungsprobe.model import parse_invoice, serialize_invoice
from rechnungsprobe.predicates import (
    CrashPredicate,
    DeclaredFieldLossPredicate,
    EvaluationContext,
    JsonPredicate,
    OutputValidityPredicate,
    TimeoutPredicate,
)
from rechnungsprobe.process import ProcessResult
from rechnungsprobe.profiles import bundled_seed_path
from rechnungsprobe.security import SecurityError
from rechnungsprobe.target import TargetResult
from rechnungsprobe.validate import ValidationResult


def _target_result(
    *,
    termination: str = "exited",
    returncode: int | None = 0,
    stdout: bytes = b"",
    output_xml: bytes | None = None,
) -> TargetResult:
    return TargetResult(
        process=ProcessResult(
            termination=termination,  # type: ignore[arg-type]
            returncode=returncode,
            stdout=stdout,
            stderr=b"",
        ),
        output_xml=output_xml,
        target_digest="sha256:" + "0" * 64,
    )


def test_crash_and_timeout_predicates_are_distinct() -> None:
    context = EvaluationContext(input_xml=b"<Invoice/>")

    assert CrashPredicate().evaluate(_target_result(returncode=3), context).matched
    assert (
        not CrashPredicate()
        .evaluate(
            _target_result(termination="timeout", returncode=-9),
            context,
        )
        .matched
    )
    assert (
        TimeoutPredicate()
        .evaluate(
            _target_result(termination="timeout", returncode=-9),
            context,
        )
        .matched
    )


def test_json_predicate_uses_a_bounded_pointer_not_code() -> None:
    result = _target_result(stdout=b'{"accepted":true,"count":2}')
    context = EvaluationContext(input_xml=b"<Invoice/>")

    evaluation = JsonPredicate(pointer="/accepted", expected=True).evaluate(result, context)

    assert evaluation.matched


def test_json_predicate_rejects_duplicate_object_keys() -> None:
    result = _target_result(stdout=b'{"accepted":true,"accepted":false}')

    with pytest.raises(SecurityError, match="duplicate"):
        JsonPredicate(pointer="/accepted", expected=True).evaluate(
            result,
            EvaluationContext(input_xml=b"<Invoice/>"),
        )


def test_json_predicate_rejects_non_finite_numbers() -> None:
    result = _target_result(stdout=b'{"accepted":NaN}')

    with pytest.raises(SecurityError, match="non-finite"):
        JsonPredicate(pointer="/accepted", expected=True).evaluate(
            result,
            EvaluationContext(input_xml=b"<Invoice/>"),
        )


def test_json_predicate_rejects_overflowing_numbers() -> None:
    result = _target_result(stdout=b'{"value":1e999}')

    with pytest.raises(SecurityError, match="non-finite"):
        JsonPredicate(pointer="/value", expected=None).evaluate(
            result,
            EvaluationContext(input_xml=b"<Invoice/>"),
        )


def test_output_validity_predicate_uses_official_validation_result() -> None:
    invalid = ValidationResult(
        valid=False,
        profile_id="profile",
        exit_code=0,
        errors=("invalid",),
        report_sha256="0" * 64,
    )
    context = EvaluationContext(
        input_xml=b"<Invoice/>",
        output_validation=invalid,
    )

    assert (
        OutputValidityPredicate()
        .evaluate(
            _target_result(output_xml=b"<Invoice/>"),
            context,
        )
        .matched
    )


def test_declared_field_loss_detects_only_requested_semantics() -> None:
    invoice = parse_invoice(bundled_seed_path())
    changed = replace(invoice, buyer_reference="changed")
    result = _target_result(output_xml=serialize_invoice(changed))
    context = EvaluationContext(input_xml=serialize_invoice(invoice))

    assert DeclaredFieldLossPredicate(("buyer_reference",)).evaluate(result, context).matched
    assert (
        not DeclaredFieldLossPredicate(("seller.endpoint",))
        .evaluate(
            result,
            context,
        )
        .matched
    )


@pytest.mark.parametrize(
    ("output_xml", "detail"),
    [
        (None, "output XML is missing"),
        (b"<not-an-invoice/>", "output is not a comparable supported invoice"),
    ],
)
def test_declared_field_loss_matches_missing_or_uncomparable_output(
    output_xml: bytes | None,
    detail: str,
) -> None:
    invoice = serialize_invoice(parse_invoice(bundled_seed_path()))

    evaluation = DeclaredFieldLossPredicate(("buyer_reference",)).evaluate(
        _target_result(output_xml=output_xml),
        EvaluationContext(input_xml=invoice),
    )

    assert evaluation.matched
    assert evaluation.details == (detail,)


def test_declared_field_loss_rejects_undeclared_selector() -> None:
    with pytest.raises(SecurityError, match="field selector"):
        DeclaredFieldLossPredicate(("__class__",))
