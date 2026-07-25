from __future__ import annotations

from dataclasses import replace

from rechnungsprobe.model import parse_invoice, serialize_invoice
from rechnungsprobe.profiles import bundled_seed_path
from rechnungsprobe.shrink import shrink_invoice, verify_one_minimal


def test_shrinker_revalidates_before_evaluating_the_predicate() -> None:
    seed = parse_invoice(bundled_seed_path())
    finding = replace(
        seed,
        note="TRIGGER-" + ("noise-" * 20),
        lines=(*seed.lines, replace(seed.lines[0], identifier="extra-line")),
    )
    validated: set[bytes] = set()
    predicate_inputs: list[bytes] = []

    def is_valid(candidate: bytes) -> bool:
        parse_invoice(candidate)
        validated.add(candidate)
        return b"invalid-candidate" not in candidate

    def preserves_finding(candidate: bytes) -> bool:
        assert candidate in validated
        predicate_inputs.append(candidate)
        return b"TRIGGER" in candidate

    result = shrink_invoice(
        finding,
        is_valid=is_valid,
        preserves_finding=preserves_finding,
    )

    assert len(serialize_invoice(result.invoice)) < len(serialize_invoice(finding))
    assert result.attempts == len(validated)
    assert result.accepted
    assert predicate_inputs
    assert b"TRIGGER" in serialize_invoice(result.invoice)


def test_invalid_candidate_never_reaches_the_finding_predicate() -> None:
    seed = parse_invoice(bundled_seed_path())
    finding = replace(seed, note="TRIGGER")
    rejected = 0
    evaluated = 0

    def is_valid(candidate: bytes) -> bool:
        nonlocal rejected
        if b">TRIGGER</cbc:Note>" not in candidate:
            rejected += 1
            return False
        return True

    def preserves_finding(_candidate: bytes) -> bool:
        nonlocal evaluated
        evaluated += 1
        return True

    shrink_invoice(
        finding,
        is_valid=is_valid,
        preserves_finding=preserves_finding,
    )

    assert rejected > 0
    assert evaluated >= 1


def test_independent_verifier_detects_and_then_confirms_one_minimality() -> None:
    seed = parse_invoice(bundled_seed_path())
    finding = replace(seed, note="TRIGGER and removable text")

    def is_valid(candidate: bytes) -> bool:
        parse_invoice(candidate)
        return True

    def preserves_finding(candidate: bytes) -> bool:
        return b"TRIGGER" in candidate

    before = verify_one_minimal(
        finding,
        is_valid=is_valid,
        preserves_finding=preserves_finding,
    )
    shrunk = shrink_invoice(
        finding,
        is_valid=is_valid,
        preserves_finding=preserves_finding,
    )
    after = verify_one_minimal(
        shrunk.invoice,
        is_valid=is_valid,
        preserves_finding=preserves_finding,
    )

    assert not before.minimal
    assert before.reducing_operation is not None
    assert after.minimal
    assert after.reducing_operation is None


def test_shrinker_is_deterministic() -> None:
    seed = parse_invoice(bundled_seed_path())
    finding = replace(seed, note="TRIGGER-" + ("noise" * 8))

    def is_valid(candidate: bytes) -> bool:
        parse_invoice(candidate)
        return True

    def preserves_finding(candidate: bytes) -> bool:
        return b"TRIGGER" in candidate

    first = shrink_invoice(
        finding,
        is_valid=is_valid,
        preserves_finding=preserves_finding,
    )
    second = shrink_invoice(
        finding,
        is_valid=is_valid,
        preserves_finding=preserves_finding,
    )

    assert first == second
