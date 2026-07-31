from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from rechnungsprobe.capsule import create_finding_capsule
from rechnungsprobe.corpus import Candidate, corpus_manifest, generate_candidates
from rechnungsprobe.model import parse_invoice, serialize_invoice
from rechnungsprobe.predicates import (
    EvaluationContext,
    OutputValidityPredicate,
    PredicateEvaluation,
)
from rechnungsprobe.process import ProcessPolicy
from rechnungsprobe.profiles import XRECHNUNG_UBL_3_0_2, bundled_seed_path
from rechnungsprobe.provenance import (
    FindingProvenance,
    MinimizationProof,
    Observation,
    observation_from_result,
    profile_payload,
    resource_policy_payload,
)
from rechnungsprobe.replay import ReplayPredicate, ReplaySpecification
from rechnungsprobe.reporting import FindingRecord, finding_json, finding_junit
from rechnungsprobe.security import SecurityError
from rechnungsprobe.shrink import shrink_invoice, verify_one_minimal
from rechnungsprobe.target import (
    ContainerTarget,
    LocalTarget,
    TargetResult,
    resolve_local_target,
    run_container_target,
    run_local_target,
)
from rechnungsprobe.validate import ValidationResult, validate_invoices
from rechnungsprobe.xmlsafe import load_xml

Validator = Callable[[Mapping[str, bytes], Path], dict[str, ValidationResult]]
CampaignTarget = LocalTarget | ContainerTarget
Runner = Callable[[CampaignTarget, bytes, Path, ProcessPolicy], TargetResult]


@dataclass(frozen=True, slots=True)
class CampaignResult:
    candidate_count: int
    finding_count: int
    profile_id: str


@dataclass(slots=True)
class _WorkspaceSequence:
    validation_root: Path
    target_root: Path
    validation_index: int = 0
    target_index: int = 0

    def next_validation(self) -> Path:
        path = self.validation_root / f"validation-{self.validation_index:08d}"
        self.validation_index += 1
        return path

    def next_target(self) -> Path:
        path = self.target_root / f"target-{self.target_index:08d}"
        self.target_index += 1
        return path


def _official_validator(
    cases: Mapping[str, bytes],
    workspace: Path,
) -> dict[str, ValidationResult]:
    return validate_invoices(cases, workspace=workspace)


def _bounded_target_runner(
    target: CampaignTarget,
    invoice_xml: bytes,
    workspace: Path,
    policy: ProcessPolicy,
) -> TargetResult:
    if isinstance(target, ContainerTarget):
        return run_container_target(
            target,
            invoice_xml,
            workspace=workspace,
            policy=policy,
        )
    return run_local_target(
        target,
        invoice_xml,
        workspace=workspace,
        policy=policy,
    )


def _new_output_directory(path: Path) -> Path:
    absolute = path.absolute()
    unresolved_parent = absolute.parent
    parent = unresolved_parent.resolve(strict=True)
    if unresolved_parent != parent or parent.is_symlink() or not parent.is_dir():
        raise SecurityError("campaign output parent must be a real directory")
    output = parent / absolute.name
    if output.exists() or output.is_symlink():
        raise SecurityError("campaign output already exists")
    output.mkdir()
    return output


def _write_new(path: Path, data: bytes) -> None:
    with path.open("xb") as output:
        output.write(data)


def _validate_corpus(
    candidates: tuple[Candidate, ...],
    *,
    validator: Validator,
    workspaces: _WorkspaceSequence,
) -> None:
    seed = load_xml(bundled_seed_path()).data
    cases = [("seed", seed)]
    cases.extend((f"case-{candidate.index:06d}", candidate.xml) for candidate in candidates)
    for offset in range(0, len(cases), 64):
        batch = dict(cases[offset : offset + 64])
        results = validator(batch, workspaces.next_validation())
        if set(results) != set(batch):
            raise SecurityError("validator returned an unexpected result set")
        invalid = {
            case_id: result.errors for case_id, result in results.items() if not result.valid
        }
        if invalid:
            first_case = min(invalid)
            detail = "; ".join(invalid[first_case]) or "official validation failed"
            raise SecurityError(f"{first_case} is invalid under the pinned profile: {detail}")


def _valid(
    invoice_xml: bytes,
    *,
    validator: Validator,
    workspaces: _WorkspaceSequence,
) -> bool:
    result = validator({"candidate": invoice_xml}, workspaces.next_validation())
    if set(result) != {"candidate"}:
        raise SecurityError("validator returned an unexpected result set")
    return result["candidate"].valid


def _run_and_evaluate(
    invoice_xml: bytes,
    *,
    target: CampaignTarget,
    predicate: ReplayPredicate,
    policy: ProcessPolicy,
    runner: Runner,
    validator: Validator,
    workspaces: _WorkspaceSequence,
) -> tuple[TargetResult, PredicateEvaluation]:
    target_result = runner(
        target,
        invoice_xml,
        workspaces.next_target(),
        policy,
    )
    output_validation = None
    if isinstance(predicate, OutputValidityPredicate) and target_result.output_xml is not None:
        try:
            validation = validator(
                {"output": target_result.output_xml},
                workspaces.next_validation(),
            )
            if set(validation) != {"output"}:
                raise SecurityError("validator returned an unexpected result set")
            output_validation = validation["output"]
        except SecurityError as error:
            output_validation = ValidationResult(
                valid=False,
                profile_id=XRECHNUNG_UBL_3_0_2.identifier,
                exit_code=1,
                errors=(str(error),),
                report_sha256=None,
            )
    evaluation = predicate.evaluate(
        target_result,
        EvaluationContext(
            input_xml=invoice_xml,
            output_validation=output_validation,
        ),
    )
    return target_result, evaluation


def _finding_record(
    candidate: Candidate,
    *,
    invoice_xml: bytes,
    fingerprint: str,
    target_result: TargetResult,
    evaluation: PredicateEvaluation,
    one_minimal: bool,
    reproductions: int,
    synthetic: bool,
    provenance: FindingProvenance,
) -> FindingRecord:
    return FindingRecord(
        case_id=f"case-{candidate.index:06d}",
        predicate=evaluation.predicate,
        profile_id=XRECHNUNG_UBL_3_0_2.identifier,
        target_digest=target_result.target_digest,
        invoice_sha256=hashlib.sha256(invoice_xml).hexdigest(),
        fingerprint=fingerprint,
        termination=target_result.process.termination,
        returncode=target_result.process.returncode,
        details=evaluation.details,
        mutations=tuple(
            f"{operation.name}@{operation.version}:{operation.token}"
            for operation in candidate.operations
        ),
        one_minimal=one_minimal,
        reproductions=reproductions,
        synthetic=synthetic,
        provenance=provenance,
    )


def run_campaign(
    *,
    output_path: Path,
    count: int,
    campaign_seed: int,
    target: CampaignTarget,
    predicate: ReplayPredicate,
    policy: ProcessPolicy | None = None,
    reproductions: int = 5,
    validator: Validator = _official_validator,
    runner: Runner = _bounded_target_runner,
) -> CampaignResult:
    """Run a deterministic local campaign and emit verified finding capsules."""

    if count > 10_000:
        raise SecurityError("CLI campaigns are limited to 10000 candidates")
    if not 1 <= reproductions <= 100:
        raise SecurityError("reproductions must be between one and 100")
    if runner is _bounded_target_runner and isinstance(target, LocalTarget):
        target = resolve_local_target(target)
    synthetic = validator is not _official_validator or runner is not _bounded_target_runner
    output_root = _new_output_directory(output_path)
    corpus_root = output_root / "corpus"
    target_work_root = output_root / ".work"
    corpus_root.mkdir()
    target_work_root.mkdir()

    candidates = generate_candidates(
        bundled_seed_path(),
        count=count,
        campaign_seed=campaign_seed,
    )
    process_policy = policy or ProcessPolicy()
    records: list[FindingRecord] = []

    with TemporaryDirectory(prefix="rpv-") as temporary:
        workspaces = _WorkspaceSequence(
            validation_root=Path(temporary),
            target_root=target_work_root,
        )
        _validate_corpus(
            candidates,
            validator=validator,
            workspaces=workspaces,
        )
        validity_cache = {
            hashlib.sha256(candidate.xml).hexdigest(): True for candidate in candidates
        }
        validity_cache[hashlib.sha256(load_xml(bundled_seed_path()).data).hexdigest()] = True
        _write_new(output_root / "corpus.json", corpus_manifest(candidates))
        for candidate in candidates:
            _write_new(corpus_root / f"case-{candidate.index:06d}.xml", candidate.xml)

        for candidate in candidates:
            initial_result, initial_evaluation = _run_and_evaluate(
                candidate.xml,
                target=target,
                predicate=predicate,
                policy=process_policy,
                runner=runner,
                validator=validator,
                workspaces=workspaces,
            )
            if not initial_evaluation.matched:
                continue
            target_digest = initial_result.target_digest

            def is_valid(invoice_xml: bytes) -> bool:
                digest = hashlib.sha256(invoice_xml).hexdigest()
                if digest in validity_cache:
                    return validity_cache[digest]
                valid = _valid(
                    invoice_xml,
                    validator=validator,
                    workspaces=workspaces,
                )
                validity_cache[digest] = valid
                return valid

            def validate_batch(invoice_documents: tuple[bytes, ...]) -> tuple[bool, ...]:
                missing: dict[str, bytes] = {}
                for invoice_xml in invoice_documents:
                    digest = hashlib.sha256(invoice_xml).hexdigest()
                    if digest not in validity_cache:
                        missing[digest] = invoice_xml
                missing_items = tuple(missing.items())
                for offset in range(0, len(missing_items), 64):
                    batch = missing_items[offset : offset + 64]
                    cases = {
                        f"candidate-{index:04d}": invoice_xml
                        for index, (_digest, invoice_xml) in enumerate(batch)
                    }
                    results = validator(cases, workspaces.next_validation())
                    if set(results) != set(cases):
                        raise SecurityError("validator returned an unexpected result set")
                    for index, (digest, _invoice_xml) in enumerate(batch):
                        validity_cache[digest] = results[f"candidate-{index:04d}"].valid
                return tuple(
                    validity_cache[hashlib.sha256(invoice_xml).hexdigest()]
                    for invoice_xml in invoice_documents
                )

            def preserves_finding(
                invoice_xml: bytes,
                expected_digest: str = target_digest,
            ) -> bool:
                result, evaluation = _run_and_evaluate(
                    invoice_xml,
                    target=target,
                    predicate=predicate,
                    policy=process_policy,
                    runner=runner,
                    validator=validator,
                    workspaces=workspaces,
                )
                if result.target_digest != expected_digest:
                    raise SecurityError("target digest changed during reduction")
                return evaluation.matched

            shrunk = shrink_invoice(
                parse_invoice(candidate.xml),
                is_valid=is_valid,
                preserves_finding=preserves_finding,
                validate_batch=validate_batch,
            )
            minimality = verify_one_minimal(
                shrunk.invoice,
                is_valid=is_valid,
                preserves_finding=preserves_finding,
                validate_batch=validate_batch,
            )
            if not minimality.minimal:
                raise SecurityError("independent 1-minimality verification failed")

            reduced_xml = serialize_invoice(shrunk.invoice)
            final_result: TargetResult | None = None
            final_evaluation: PredicateEvaluation | None = None
            observations: list[Observation] = []
            for _ in range(reproductions):
                if not is_valid(reduced_xml):
                    raise SecurityError("reduced invoice failed reproduction validation")
                final_result, final_evaluation = _run_and_evaluate(
                    reduced_xml,
                    target=target,
                    predicate=predicate,
                    policy=process_policy,
                    runner=runner,
                    validator=validator,
                    workspaces=workspaces,
                )
                if final_result.target_digest != target_digest:
                    raise SecurityError("target digest changed during reproduction")
                if not final_evaluation.matched:
                    raise SecurityError("finding did not reproduce consistently")
                observations.append(observation_from_result(final_result))
            if final_result is None or final_evaluation is None:
                raise RuntimeError("reproduction loop produced no target result")
            record = _finding_record(
                candidate,
                invoice_xml=reduced_xml,
                fingerprint=shrunk.fingerprint,
                target_result=final_result,
                evaluation=final_evaluation,
                one_minimal=minimality.minimal,
                reproductions=reproductions,
                synthetic=synthetic,
                provenance=FindingProvenance(
                    campaign_seed=candidate.campaign_seed,
                    seed_sha256=candidate.seed_sha256,
                    seed_fingerprint=candidate.seed_fingerprint,
                    profile=profile_payload(XRECHNUNG_UBL_3_0_2),
                    target_digest=target_digest,
                    resource_policy=resource_policy_payload(process_policy),
                    observations=tuple(observations),
                    minimization=MinimizationProof(
                        algorithm="greedy-1-minimal-v1",
                        declared_operations="invoice-node-value-v1",
                        attempts=shrunk.attempts,
                        accepted_operations=shrunk.accepted,
                        one_minimal=minimality.minimal,
                        verification_attempts=minimality.attempts,
                    ),
                ),
            )
            create_finding_capsule(
                output_root / f"{record.case_id}.rechnungsprobe",
                record=record,
                invoice_xml=reduced_xml,
                replay=ReplaySpecification(
                    target=target,
                    predicate=predicate,
                    policy=process_policy,
                ),
            )
            records.append(record)
            break

    ordered = tuple(records)
    _write_new(output_root / "result.json", finding_json(ordered))
    _write_new(output_root / "junit.xml", finding_junit(ordered))
    return CampaignResult(
        candidate_count=len(candidates),
        finding_count=len(records),
        profile_id=XRECHNUNG_UBL_3_0_2.identifier,
    )
