from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

from rechnungsprobe import campaign
from rechnungsprobe.campaign import CampaignTarget, run_campaign
from rechnungsprobe.capsule import verify_finding_capsule
from rechnungsprobe.model import parse_invoice
from rechnungsprobe.predicates import CrashPredicate, OutputValidityPredicate
from rechnungsprobe.process import ProcessPolicy, ProcessResult
from rechnungsprobe.profiles import XRECHNUNG_UBL_3_0_2
from rechnungsprobe.reporting import finding_record_from_payload
from rechnungsprobe.target import LocalTarget, TargetResult
from rechnungsprobe.validate import ValidationResult


def test_campaign_revalidates_shrinks_verifies_and_reproduces_a_finding(
    tmp_path: Path,
) -> None:
    validated: set[bytes] = set()
    validation_counts: dict[bytes, int] = {}
    executed: list[bytes] = []

    def validator(
        cases: Mapping[str, bytes],
        _workspace: Path,
    ) -> dict[str, ValidationResult]:
        results: dict[str, ValidationResult] = {}
        for case_id, invoice_xml in cases.items():
            parse_invoice(invoice_xml)
            validated.add(invoice_xml)
            validation_counts[invoice_xml] = validation_counts.get(invoice_xml, 0) + 1
            results[case_id] = ValidationResult(
                valid=True,
                profile_id=XRECHNUNG_UBL_3_0_2.identifier,
                exit_code=0,
                errors=(),
                report_sha256="a" * 64,
            )
        return results

    def runner(
        _target: CampaignTarget,
        invoice_xml: bytes,
        _workspace: Path,
        _policy: ProcessPolicy,
    ) -> TargetResult:
        assert invoice_xml in validated
        executed.append(invoice_xml)
        returncode = 23 if b"RP-" in invoice_xml else 0
        return TargetResult(
            process=ProcessResult(
                termination="exited",
                returncode=returncode,
                stdout=b"",
                stderr=b"",
            ),
            output_xml=None,
            target_digest="sha256:" + "b" * 64,
        )

    result = run_campaign(
        output_path=tmp_path / "campaign",
        count=1,
        campaign_seed=7,
        target=LocalTarget(command=("synthetic-importer",), input_mode="stdin"),
        predicate=CrashPredicate(),
        policy=ProcessPolicy(),
        reproductions=3,
        validator=validator,
        runner=runner,
    )

    assert result.finding_count == 1
    report = json.loads((tmp_path / "campaign" / "result.json").read_bytes())
    finding = report["findings"][0]
    assert finding["one_minimal"] is True
    assert finding["reproductions"] == 3
    assert finding["synthetic"] is True
    provenance = finding["provenance"]
    assert provenance["campaign_seed"] == 7
    assert len(provenance["seed_sha256"]) == 64
    assert len(provenance["seed_fingerprint"]) == 64
    assert provenance["profile"]["identifier"] == XRECHNUNG_UBL_3_0_2.identifier
    assert (
        provenance["profile"]["validator_sha256"]
        == XRECHNUNG_UBL_3_0_2.validator_sha256
    )
    assert provenance["target_digest"] == "sha256:" + "b" * 64
    assert provenance["resource_policy"]["timeout_milliseconds"] == 10_000
    assert len(provenance["observations"]) == 3
    assert provenance["minimization"]["algorithm"] == "greedy-1-minimal-v1"
    assert provenance["minimization"]["one_minimal"] is True
    assert provenance["minimization"]["verification_attempts"] >= 1
    capsule = tmp_path / "campaign" / "case-000000.rechnungsprobe"
    verified = verify_finding_capsule(capsule)
    assert verified.record == finding_record_from_payload(finding)
    assert b"RP-" in verified.invoice_xml
    assert len(executed) >= 4
    assert max(validation_counts.values()) <= 2


def test_campaign_officially_validates_roundtrip_output_before_matching(
    tmp_path: Path,
) -> None:
    validated_inputs: set[bytes] = set()
    invalid_output = b"<Invoice/>"

    def validator(
        cases: Mapping[str, bytes],
        _workspace: Path,
    ) -> dict[str, ValidationResult]:
        results: dict[str, ValidationResult] = {}
        for case_id, invoice_xml in cases.items():
            if invoice_xml == invalid_output:
                results[case_id] = ValidationResult(
                    valid=False,
                    profile_id=XRECHNUNG_UBL_3_0_2.identifier,
                    exit_code=0,
                    errors=("synthetic invalid output",),
                    report_sha256="c" * 64,
                )
            else:
                parse_invoice(invoice_xml)
                validated_inputs.add(invoice_xml)
                results[case_id] = ValidationResult(
                    valid=True,
                    profile_id=XRECHNUNG_UBL_3_0_2.identifier,
                    exit_code=0,
                    errors=(),
                    report_sha256="a" * 64,
                )
        return results

    def runner(
        _target: CampaignTarget,
        invoice_xml: bytes,
        _workspace: Path,
        _policy: ProcessPolicy,
    ) -> TargetResult:
        assert invoice_xml in validated_inputs
        return TargetResult(
            process=ProcessResult(
                termination="exited",
                returncode=0,
                stdout=b"",
                stderr=b"",
            ),
            output_xml=invalid_output,
            target_digest="sha256:" + "d" * 64,
        )

    result = run_campaign(
        output_path=tmp_path / "campaign",
        count=1,
        campaign_seed=7,
        target=LocalTarget(
            command=("synthetic-importer",),
            input_mode="stdin",
            output_file="roundtrip.xml",
        ),
        predicate=OutputValidityPredicate(),
        reproductions=1,
        validator=validator,
        runner=runner,
    )

    assert result.finding_count == 1
    report = json.loads((tmp_path / "campaign" / "result.json").read_bytes())
    assert report["findings"][0]["details"] == ["synthetic invalid output"]


def test_campaign_shrinking_preserves_the_exact_failure_signature(
    tmp_path: Path,
) -> None:
    def validator(
        cases: Mapping[str, bytes],
        _workspace: Path,
    ) -> dict[str, ValidationResult]:
        for invoice_xml in cases.values():
            parse_invoice(invoice_xml)
        return {
            case_id: ValidationResult(
                valid=True,
                profile_id=XRECHNUNG_UBL_3_0_2.identifier,
                exit_code=0,
                errors=(),
                report_sha256="a" * 64,
            )
            for case_id in cases
        }

    def runner(
        _target: CampaignTarget,
        invoice_xml: bytes,
        _workspace: Path,
        _policy: ProcessPolicy,
    ) -> TargetResult:
        return TargetResult(
            process=ProcessResult(
                termination="exited",
                returncode=23 if b"#ADU#" in invoice_xml else 42,
                stdout=b"",
                stderr=b"",
            ),
            output_xml=None,
            target_digest="sha256:" + "b" * 64,
        )

    result = run_campaign(
        output_path=tmp_path / "campaign",
        count=1,
        campaign_seed=7,
        target=LocalTarget(command=("synthetic-importer",), input_mode="stdin"),
        predicate=CrashPredicate(),
        policy=ProcessPolicy(),
        reproductions=2,
        validator=validator,
        runner=runner,
    )

    assert result.finding_count == 1
    verified = verify_finding_capsule(
        tmp_path / "campaign" / "case-000000.rechnungsprobe"
    )
    assert verified.record.returncode == 23
    assert b"#ADU#" in verified.invoice_xml


def test_campaign_capsule_records_resolved_local_target_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    importer = tmp_path / "importer.py"
    importer.write_text(
        "import sys\nsys.stdin.buffer.read()\nraise SystemExit(23)\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    def validator(
        cases: Mapping[str, bytes],
        *,
        workspace: Path,
    ) -> dict[str, ValidationResult]:
        del workspace
        for invoice_xml in cases.values():
            parse_invoice(invoice_xml)
        return {
            case_id: ValidationResult(
                valid=True,
                profile_id=XRECHNUNG_UBL_3_0_2.identifier,
                exit_code=0,
                errors=(),
                report_sha256="a" * 64,
            )
            for case_id in cases
        }

    monkeypatch.setattr(campaign, "validate_invoices", validator)
    result = run_campaign(
        output_path=tmp_path / "campaign",
        count=1,
        campaign_seed=7,
        target=LocalTarget(
            command=(sys.executable, "importer.py"),
            input_mode="stdin",
        ),
        predicate=CrashPredicate(),
        reproductions=1,
    )

    assert result.finding_count == 1
    verified = verify_finding_capsule(
        tmp_path / "campaign" / "case-000000.rechnungsprobe"
    )
    assert isinstance(verified.replay.target, LocalTarget)
    assert Path(verified.replay.target.command[1]) == importer.resolve()
    assert verified.record.synthetic is False
