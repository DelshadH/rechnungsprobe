from __future__ import annotations

import json

import pytest

from rechnungsprobe.corpus import corpus_manifest, generate_candidates
from rechnungsprobe.mutators import MUTATORS
from rechnungsprobe.profiles import bundled_seed_path
from rechnungsprobe.security import SecurityError


def test_candidate_generation_is_byte_deterministic() -> None:
    first = generate_candidates(bundled_seed_path(), count=50, campaign_seed=20260724)
    second = generate_candidates(bundled_seed_path(), count=50, campaign_seed=20260724)

    assert first == second
    assert corpus_manifest(first) == corpus_manifest(second)


def test_candidates_are_unique_material_and_cover_every_mutator() -> None:
    candidates = generate_candidates(
        bundled_seed_path(),
        count=len(MUTATORS),
        campaign_seed=7,
    )

    assert len({candidate.fingerprint for candidate in candidates}) == len(candidates)
    assert all(candidate.seed_fingerprint != candidate.fingerprint for candidate in candidates)
    assert {candidate.operations[0].name for candidate in candidates} == set(MUTATORS)


def test_generation_scales_to_ten_thousand_unique_semantics() -> None:
    candidates = generate_candidates(
        bundled_seed_path(),
        count=10_000,
        campaign_seed=42,
    )

    assert len({candidate.fingerprint for candidate in candidates}) == 10_000


def test_manifest_is_canonical_json() -> None:
    candidates = generate_candidates(bundled_seed_path(), count=2, campaign_seed=3)
    encoded = corpus_manifest(candidates)

    assert encoded.endswith(b"\n")
    assert (
        json.dumps(
            json.loads(encoded),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        + b"\n"
        == encoded
    )


@pytest.mark.parametrize("count", [0, -1, 100_001])
def test_generation_rejects_unbounded_counts(count: int) -> None:
    with pytest.raises(SecurityError, match="count"):
        generate_candidates(bundled_seed_path(), count=count, campaign_seed=1)
