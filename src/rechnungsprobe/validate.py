from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from rechnungsprobe.process import ProcessPolicy, ProcessResult, run_bounded_process
from rechnungsprobe.profiles import XRECHNUNG_UBL_3_0_2, Profile, materialize_profile
from rechnungsprobe.security import SecurityError
from rechnungsprobe.xmlsafe import XmlLimits, load_xml, parse_xml_bytes


@dataclass(frozen=True, slots=True)
class ValidationResult:
    valid: bool
    profile_id: str
    exit_code: int
    errors: tuple[str, ...]
    report_sha256: str | None


_CASE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
_TERMINATION_EXIT_CODES = {
    "timeout": 124,
    "output_limit": 125,
    "memory_limit": 126,
    "cpu_limit": 127,
    "process_limit": 128,
    "file_limit": 129,
}


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _report_errors(report_path: Path) -> tuple[tuple[str, ...], str]:
    document = load_xml(
        report_path,
        XmlLimits(
            max_bytes=8 * 1024 * 1024,
            max_elements=100_000,
            max_attributes=200_000,
            max_text=8 * 1024 * 1024,
        ),
    )
    errors: list[str] = []
    for element in document.root.iter():
        if _local_name(element.tag) not in {"assertion", "message"}:
            continue
        flag = element.attrib.get("flag", "").casefold()
        if flag in {"fatal", "error"}:
            text = " ".join("".join(element.itertext()).split())
            errors.append(text[:1000])
    return tuple(errors), document.sha256


def _failure_results(
    case_ids: tuple[str, ...],
    profile: Profile,
    *,
    exit_code: int,
    error: str,
) -> dict[str, ValidationResult]:
    return {
        case_id: ValidationResult(
            valid=False,
            profile_id=profile.identifier,
            exit_code=exit_code,
            errors=(error,),
            report_sha256=None,
        )
        for case_id in case_ids
    }


def _process_failure(
    completed: ProcessResult,
    case_ids: tuple[str, ...],
    profile: Profile,
) -> dict[str, ValidationResult] | None:
    if completed.termination == "exited":
        return None
    return _failure_results(
        case_ids,
        profile,
        exit_code=_TERMINATION_EXIT_CODES[completed.termination],
        error=f"validator reached its {completed.termination.replace('_', ' ')}",
    )


def validate_invoices(
    cases: Mapping[str, bytes],
    *,
    workspace: Path,
    timeout_seconds: float = 120.0,
    profile: Profile = XRECHNUNG_UBL_3_0_2,
) -> dict[str, ValidationResult]:
    """Validate up to 64 in-memory invoices in one pinned KoSIT invocation."""

    if not 1 <= len(cases) <= 64:
        raise SecurityError("validation batch must contain between one and 64 cases")
    case_ids = tuple(cases)
    if any(_CASE_ID.fullmatch(case_id) is None for case_id in case_ids):
        raise SecurityError("validation case identifier is unsafe")
    documents = {case_id: parse_xml_bytes(data) for case_id, data in cases.items()}
    if sum(len(document.data) for document in documents.values()) > 32 * 1024 * 1024:
        raise SecurityError("validation batch exceeds the total input limit")

    workspace = workspace.absolute()
    if workspace.exists() and (
        workspace.is_symlink() or not workspace.is_dir() or any(workspace.iterdir())
    ):
        raise SecurityError("validation workspace must be an empty real directory")
    if workspace.exists():
        workspace = workspace.resolve(strict=True)
    else:
        parent = workspace.parent.resolve(strict=True)
        if workspace.parent.is_symlink() or not parent.is_dir():
            raise SecurityError("validation workspace parent must be a real directory")
        workspace = parent / workspace.name
        workspace.mkdir()
    materialized = materialize_profile(profile, workspace / "profile")
    input_dir = workspace / "inputs"
    report_dir = workspace / "reports"
    java_temp = workspace / "java-tmp"
    input_dir.mkdir()
    report_dir.mkdir()
    java_temp.mkdir()

    input_paths: dict[str, Path] = {}
    for index, case_id in enumerate(case_ids):
        path = input_dir / f"case-{index:04d}.xml"
        with path.open("xb") as output:
            output.write(documents[case_id].data)
        input_paths[case_id] = path

    relative_validator = materialized.validator_path.relative_to(workspace)
    relative_scenario = materialized.scenario_path.relative_to(workspace)
    relative_repository = materialized.root.relative_to(workspace)
    command = [
        "java",
        "-Xms32m",
        "-Xmx384m",
        "-XX:ActiveProcessorCount=2",
        "-XX:+ExitOnOutOfMemoryError",
        "-Djava.io.tmpdir=java-tmp",
        "-Djavax.xml.accessExternalDTD=",
        "-Djavax.xml.accessExternalSchema=file",
        "-Djavax.xml.accessExternalStylesheet=file",
        "-Djdk.xml.enableExtensionFunctions=false",
        "-jar",
        str(relative_validator),
        "-s",
        str(relative_scenario),
        "-r",
        str(relative_repository),
        "-o",
        "reports",
        *(str(path.relative_to(workspace)) for path in input_paths.values()),
    ]
    completed = run_bounded_process(
        command,
        cwd=workspace,
        policy=ProcessPolicy(
            timeout_seconds=timeout_seconds,
            cpu_seconds=max(1.0, timeout_seconds * 0.9),
            max_memory_bytes=640 * 1024 * 1024,
            max_processes=4,
            max_output_bytes=4 * 1024 * 1024,
            max_file_growth_bytes=min(
                128 * 1024 * 1024,
                len(cases) * 8 * 1024 * 1024,
            ),
            max_created_files=len(cases) + 32,
        ),
    )
    if failure := _process_failure(completed, case_ids, profile):
        return failure

    expected_reports = {
        case_id: report_dir / f"{path.stem}-report.xml" for case_id, path in input_paths.items()
    }
    actual_reports = set(report_dir.glob("*-report.xml"))
    if actual_reports != set(expected_reports.values()):
        return _failure_results(
            case_ids,
            profile,
            exit_code=completed.returncode or 1,
            error="validator did not produce the exact expected report set",
        )

    results: dict[str, ValidationResult] = {}
    for case_id in case_ids:
        try:
            errors, report_sha256 = _report_errors(expected_reports[case_id])
        except SecurityError as error:
            results[case_id] = ValidationResult(
                valid=False,
                profile_id=profile.identifier,
                exit_code=completed.returncode or 1,
                errors=(str(error),),
                report_sha256=None,
            )
            continue
        if completed.returncode:
            errors = (*errors, "validator exited unsuccessfully")
        results[case_id] = ValidationResult(
            valid=completed.returncode == 0 and not errors,
            profile_id=profile.identifier,
            exit_code=completed.returncode or 0,
            errors=errors,
            report_sha256=report_sha256,
        )
    return results


def validate_invoice(
    invoice_path: Path,
    *,
    workspace: Path,
    timeout_seconds: float = 45.0,
    profile: Profile = XRECHNUNG_UBL_3_0_2,
) -> ValidationResult:
    document = load_xml(invoice_path)
    return validate_invoices(
        {"invoice": document.data},
        workspace=workspace,
        timeout_seconds=timeout_seconds,
        profile=profile,
    )["invoice"]
