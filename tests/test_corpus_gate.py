from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from rechnungsprobe.corpus import INTERACTION_BUCKETS
from rechnungsprobe.gates import run_corpus_gate
from rechnungsprobe.mutators import MUTATORS
from rechnungsprobe.profiles import XRECHNUNG_UBL_3_0_2
from rechnungsprobe.validate import ValidationResult


def test_corpus_gate_records_complete_machine_readable_evidence(tmp_path: Path) -> None:
    def valid(
        cases: Mapping[str, bytes],
        _workspace: Path,
    ) -> dict[str, ValidationResult]:
        return {
            case_id: ValidationResult(
                valid=True,
                profile_id=XRECHNUNG_UBL_3_0_2.identifier,
                exit_code=0,
                errors=(),
                report_sha256=f"{index:064x}",
            )
            for index, case_id in enumerate(cases)
        }

    encoded = run_corpus_gate(
        tmp_path / "gate",
        count=len(MUTATORS) + len(INTERACTION_BUCKETS),
        campaign_seed=41,
        validator=valid,
        environment={
            "java": "test-java",
            "operating_system": "test-os",
            "python": "test-python",
        },
    )
    payload = json.loads(encoded)

    assert payload["status"] == "passed"
    assert payload["validated_count"] == len(MUTATORS) + len(INTERACTION_BUCKETS)
    assert payload["unique_semantic_fingerprints"] == payload["validated_count"]
    assert set(payload["mutators_covered"]) == set(MUTATORS)
    assert set(payload["interaction_buckets_covered"]) == set(INTERACTION_BUCKETS)
    assert payload["corpus_root_sha256"].startswith("sha256:")
    assert payload["validation_root_sha256"].startswith("sha256:")
    assert payload["profile"]["validator_sha256"] == XRECHNUNG_UBL_3_0_2.validator_sha256
    assert payload["environment"]["java"] == "test-java"
    assert (tmp_path / "gate" / "validation.json").read_bytes() == encoded
