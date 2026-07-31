from __future__ import annotations

import hashlib
import hmac
import json
import platform
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from tempfile import TemporaryDirectory

from rechnungsprobe.corpus import (
    INTERACTION_BUCKETS,
    corpus_manifest,
    generate_candidates,
    materialize_corpus,
)
from rechnungsprobe.mutators import MUTATORS
from rechnungsprobe.process import ProcessPolicy, run_bounded_process
from rechnungsprobe.profiles import XRECHNUNG_UBL_3_0_2, bundled_seed_path
from rechnungsprobe.security import SecurityError, open_regular_file
from rechnungsprobe.validate import ValidationResult, validate_invoices

GateValidator = Callable[
    [Mapping[str, bytes], Path],
    dict[str, ValidationResult],
]


def _official_validator(
    cases: Mapping[str, bytes],
    workspace: Path,
) -> dict[str, ValidationResult]:
    return validate_invoices(cases, workspace=workspace)


def _environment_record() -> dict[str, str]:
    with TemporaryDirectory(prefix="rp-java-version-") as temporary:
        result = run_bounded_process(
            ("java", "-version"),
            cwd=Path(temporary),
            policy=ProcessPolicy(
                timeout_seconds=5,
                cpu_seconds=3,
                max_memory_bytes=256 * 1024 * 1024,
                max_processes=2,
                max_output_bytes=64 * 1024,
                max_file_growth_bytes=1024 * 1024,
                max_created_files=8,
            ),
        )
    java = (result.stderr or result.stdout).decode("utf-8", errors="replace").strip()
    if result.termination != "exited" or result.returncode != 0 or not java:
        raise SecurityError("Java runtime version could not be recorded")
    return {
        "java": java,
        "operating_system": platform.platform(),
        "python": sys.version,
    }


def _canonical_json(payload: object) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def run_corpus_gate(
    output: Path,
    *,
    count: int = 10_000,
    campaign_seed: int = 42,
    validator: GateValidator = _official_validator,
    environment: Mapping[str, str] | None = None,
) -> bytes:
    """Generate and officially validate a complete deterministic corpus gate."""

    candidates = generate_candidates(
        bundled_seed_path(),
        count=count,
        campaign_seed=campaign_seed,
    )
    materialize_corpus(
        output,
        seed_path=bundled_seed_path(),
        count=count,
        campaign_seed=campaign_seed,
        resume=output.exists(),
    )
    manifest = json.loads(corpus_manifest(candidates))
    mutators_covered = {candidate.operations[0].name for candidate in candidates}
    interactions_covered = {
        f"{candidate.operations[0].name}+{candidate.operations[1].name}"
        for candidate in candidates
        if candidate.index >= len(MUTATORS) and len(candidate.operations) >= 2
    }
    if mutators_covered != set(MUTATORS):
        raise SecurityError("corpus gate does not cover every released mutator")
    if interactions_covered != set(INTERACTION_BUCKETS):
        raise SecurityError("corpus gate does not cover every declared interaction bucket")

    validation_root = hashlib.sha256(b"rechnungsprobe-validation-root-v2\0")
    with TemporaryDirectory(prefix="rp-corpus-gate-") as temporary:
        workspace_root = Path(temporary)
        for offset in range(0, len(candidates), 64):
            batch_candidates = candidates[offset : offset + 64]
            cases = {
                f"case-{candidate.index:06d}": candidate.xml
                for candidate in batch_candidates
            }
            results = validator(cases, workspace_root / f"batch-{offset // 64:06d}")
            if set(results) != set(cases):
                raise SecurityError("validator returned an unexpected corpus gate result set")
            for case_id in sorted(results):
                result = results[case_id]
                candidate = next(
                    candidate
                    for candidate in batch_candidates
                    if f"case-{candidate.index:06d}" == case_id
                )
                if not result.valid or result.profile_id != XRECHNUNG_UBL_3_0_2.identifier:
                    detail = "; ".join(result.errors) or "official validation failed"
                    raise SecurityError(f"{case_id} failed the corpus gate: {detail}")
                if result.report_sha256 is None or len(result.report_sha256) != 64:
                    raise SecurityError("validator result lacks a bounded report digest")
                validation_root.update(case_id.encode("ascii"))
                validation_root.update(bytes.fromhex(candidate.xml_sha256))
                validation_root.update(result.profile_id.encode("utf-8"))
                validation_root.update(result.exit_code.to_bytes(4, "big", signed=True))
                for error in result.errors:
                    validation_root.update(error.encode("utf-8"))
                validation_root.update(bytes.fromhex(result.report_sha256))

    recorded_environment = dict(environment or _environment_record())
    if (
        set(recorded_environment) != {"java", "operating_system", "python"}
        or any(
            not isinstance(value, str) or not value or len(value) > 4000
            for value in recorded_environment.values()
        )
    ):
        raise SecurityError("corpus gate environment record is incomplete")
    payload = {
        "campaign_seed": campaign_seed,
        "corpus_root_sha256": manifest["corpus_root_sha256"],
        "environment": recorded_environment,
        "generator_version": manifest["generator_version"],
        "interaction_buckets_covered": sorted(interactions_covered),
        "mutators_covered": sorted(mutators_covered),
        "profile": {
            "configuration_sha256": XRECHNUNG_UBL_3_0_2.configuration_sha256,
            "configuration_version": XRECHNUNG_UBL_3_0_2.configuration_version,
            "identifier": XRECHNUNG_UBL_3_0_2.identifier,
            "validator_sha256": XRECHNUNG_UBL_3_0_2.validator_sha256,
            "validator_version": XRECHNUNG_UBL_3_0_2.validator_version,
        },
        "schema": "https://rechnungsprobe.dev/schemas/corpus-gate-v1",
        "status": "passed",
        "unique_semantic_fingerprints": len(
            {candidate.fingerprint for candidate in candidates}
        ),
        "validated_count": len(candidates),
        "validation_root_sha256": f"sha256:{validation_root.hexdigest()}",
    }
    encoded = _canonical_json(payload)
    path = output.absolute() / "validation.json"
    if path.exists():
        with open_regular_file(path, max_bytes=4 * 1024 * 1024) as source:
            existing = source.read(4 * 1024 * 1024 + 1)
        if not hmac.compare_digest(existing, encoded):
            raise SecurityError("existing corpus validation evidence does not match")
    else:
        with path.open("xb") as destination:
            destination.write(encoded)
    return encoded
