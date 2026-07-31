from __future__ import annotations

import json

import pytest

from rechnungsprobe.corpus import (
    INTERACTION_BUCKETS,
    corpus_manifest,
    generate_candidates,
    materialize_corpus,
)
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


def test_shards_recompose_the_exact_unsharded_candidate_sequence() -> None:
    complete = generate_candidates(bundled_seed_path(), count=41, campaign_seed=13)
    shards = tuple(
        candidate
        for shard_index in range(4)
        for candidate in generate_candidates(
            bundled_seed_path(),
            count=41,
            campaign_seed=13,
            shard_index=shard_index,
            shard_count=4,
        )
    )

    assert tuple(sorted(shards, key=lambda candidate: candidate.index)) == complete


def test_manifest_records_a_stable_root_hash_and_interaction_coverage() -> None:
    count = len(MUTATORS) + len(INTERACTION_BUCKETS)
    candidates = generate_candidates(bundled_seed_path(), count=count, campaign_seed=23)

    payload = json.loads(corpus_manifest(candidates))

    assert payload["corpus_root_sha256"].startswith("sha256:")
    assert len(payload["corpus_root_sha256"]) == 71
    assert set(payload["interaction_buckets"]) == set(INTERACTION_BUCKETS)
    assert corpus_manifest(tuple(reversed(candidates))) == corpus_manifest(candidates)


def test_interaction_buckets_cover_all_distinct_ordered_pairs() -> None:
    expected = {
        f"{primary}+{secondary}"
        for primary in MUTATORS
        for secondary in MUTATORS
        if primary != secondary
    }

    assert len(INTERACTION_BUCKETS) == 380
    assert set(INTERACTION_BUCKETS) == expected
    assert any(bucket.endswith("+invoice-id") for bucket in INTERACTION_BUCKETS)


@pytest.mark.parametrize(
    ("shard_index", "shard_count"),
    [(-1, 2), (2, 2), (0, 0), (0, 101)],
)
def test_generation_rejects_invalid_shard_coordinates(
    shard_index: int,
    shard_count: int,
) -> None:
    with pytest.raises(SecurityError, match="shard"):
        generate_candidates(
            bundled_seed_path(),
            count=10,
            campaign_seed=1,
            shard_index=shard_index,
            shard_count=shard_count,
        )


def test_corpus_materialization_resumes_only_byte_identical_cases(tmp_path: object) -> None:
    from pathlib import Path

    output = Path(str(tmp_path)) / "corpus"
    first = materialize_corpus(
        output,
        seed_path=bundled_seed_path(),
        count=8,
        campaign_seed=31,
    )
    missing = output / "cases" / "case-000003.xml"
    missing.unlink()

    resumed = materialize_corpus(
        output,
        seed_path=bundled_seed_path(),
        count=8,
        campaign_seed=31,
        resume=True,
    )

    assert resumed == first
    assert missing.is_file()
    assert (output / "corpus.json").read_bytes() == first

    missing.write_bytes(b"tampered")
    with pytest.raises(SecurityError, match="does not match"):
        materialize_corpus(
            output,
            seed_path=bundled_seed_path(),
            count=8,
            campaign_seed=31,
            resume=True,
        )


@pytest.mark.parametrize("count", [0, -1, 100_001])
def test_generation_rejects_unbounded_counts(count: int) -> None:
    with pytest.raises(SecurityError, match="count"):
        generate_candidates(bundled_seed_path(), count=count, campaign_seed=1)
