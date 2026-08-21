from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from rechnungsprobe import cli
from rechnungsprobe.campaign import CampaignResult
from rechnungsprobe.capsule import create_finding_capsule
from rechnungsprobe.cli import main
from rechnungsprobe.model import parse_invoice, semantic_fingerprint, serialize_invoice
from rechnungsprobe.predicates import (
    CrashPredicate,
    DeclaredFieldLossPredicate,
    JsonPredicate,
)
from rechnungsprobe.process import ProcessPolicy
from rechnungsprobe.profiles import XRECHNUNG_UBL_3_0_2, bundled_seed_path
from rechnungsprobe.replay import ReplaySpecification
from rechnungsprobe.reporting import FindingRecord
from rechnungsprobe.target import (
    ContainerTarget,
    LocalTarget,
    run_local_target,
    target_configuration_digest,
)


def test_help_path_exits_successfully(capsys: object) -> None:
    assert main([]) == 0


def test_version_reports_the_release_candidate_version(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as completed:
        main(["--version"])

    assert completed.value.code == 0
    assert capsys.readouterr().out == "rechnungsprobe 0.1.0a2\n"


def test_verify_command_checks_a_real_capsule(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    invoice_xml = serialize_invoice(parse_invoice(bundled_seed_path()))
    record = FindingRecord(
        case_id="synthetic-cli",
        predicate="crash-or-nonzero",
        profile_id=XRECHNUNG_UBL_3_0_2.identifier,
        target_digest="sha256:" + "a" * 64,
        invoice_sha256=hashlib.sha256(invoice_xml).hexdigest(),
        fingerprint=semantic_fingerprint(parse_invoice(invoice_xml)),
        termination="exited",
        returncode=23,
        details=("synthetic fixture",),
        mutations=("invoice-id@1",),
        one_minimal=True,
        reproductions=5,
        synthetic=True,
    )
    capsule = tmp_path / "finding.rechnungsprobe"
    create_finding_capsule(
        capsule,
        record=record,
        invoice_xml=invoice_xml,
        replay=ReplaySpecification(
            target=LocalTarget(
                command=("synthetic-importer",),
                input_mode="stdin",
            ),
            predicate=CrashPredicate(),
            policy=ProcessPolicy(),
        ),
    )

    assert main(["verify", str(capsule)]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "case_id": "synthetic-cli",
        "execution": "not-performed",
        "profile_id": XRECHNUNG_UBL_3_0_2.identifier,
        "status": "verified",
        "target_kind": "local",
    }


def test_verify_command_reports_hostile_capsule_without_a_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    capsule = tmp_path / "hostile.rechnungsprobe"
    capsule.write_bytes(b"not a zip archive")

    assert main(["verify", str(capsule)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "error": "capsule is not a valid bounded ZIP archive",
        "status": "error",
    }


def test_corpus_command_materializes_a_deterministic_shard(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "corpus"

    assert (
        main(
            [
                "corpus",
                "--output",
                str(output),
                "--count",
                "7",
                "--seed",
                "11",
                "--shard-count",
                "3",
                "--shard-index",
                "1",
            ]
        )
        == 0
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["candidate_count"] == 2
    assert payload["corpus_root_sha256"].startswith("sha256:")
    assert sorted(path.name for path in (output / "cases").iterdir()) == [
        "case-000001.xml",
        "case-000004.xml",
    ]


def test_fuzz_command_runs_the_real_validated_no_finding_path(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "campaign"

    exit_code = main(
        [
            "fuzz",
            "--output",
            str(output),
            "--count",
            "1",
            "--seed",
            "7",
            "--predicate",
            "crash",
            "--input-mode",
            "stdin",
            "--trusted-local",
            "--",
            sys.executable,
            "-c",
            "import sys; sys.stdin.buffer.read()",
        ]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    assert json.loads(captured.err) == {
        "execution_mode": "trusted-local-command",
        "status": "warning",
        "warning": (
            "local command execution is non-isolated and may access "
            "the host filesystem and network"
        ),
    }
    assert json.loads(captured.out) == {
        "candidate_count": 1,
        "finding_count": 0,
        "profile_id": XRECHNUNG_UBL_3_0_2.identifier,
        "status": "passed",
    }
    assert json.loads((output / "corpus.json").read_bytes())["candidate_count"] == 1
    assert json.loads((output / "result.json").read_bytes())["findings"] == []
    assert (output / "junit.xml").is_file()
    assert (output / "corpus" / "case-000000.xml").is_file()


def test_fuzz_refuses_a_local_target_without_trusted_local_authority(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def must_not_run_campaign(**_arguments: object) -> CampaignResult:
        raise AssertionError("campaign started without local execution authority")

    monkeypatch.setattr(cli, "run_campaign", must_not_run_campaign)

    assert (
        main(
            [
                "fuzz",
                "--output",
                str(tmp_path / "campaign"),
                "--",
                sys.executable,
                "-c",
                "raise SystemExit(23)",
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(captured.err) == {
        "error": "local fuzz targets require --trusted-local",
        "status": "error",
    }


def test_fuzz_command_returns_ci_failure_when_a_finding_exists(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def completed_campaign(**_arguments: object) -> CampaignResult:
        return CampaignResult(
            candidate_count=3,
            finding_count=1,
            profile_id=XRECHNUNG_UBL_3_0_2.identifier,
        )

    monkeypatch.setattr(cli, "run_campaign", completed_campaign)

    exit_code = main(
        [
            "fuzz",
            "--output",
            str(tmp_path / "campaign"),
            "--trusted-local",
            "--",
            sys.executable,
            "-c",
            "pass",
        ]
    )

    assert exit_code == 1
    assert json.loads(capsys.readouterr().out) == {
        "candidate_count": 3,
        "finding_count": 1,
        "profile_id": XRECHNUNG_UBL_3_0_2.identifier,
        "status": "findings",
    }


def test_fuzz_json_flags_build_a_bounded_data_predicate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def completed_campaign(**arguments: object) -> CampaignResult:
        captured.update(arguments)
        return CampaignResult(
            candidate_count=1,
            finding_count=0,
            profile_id=XRECHNUNG_UBL_3_0_2.identifier,
        )

    monkeypatch.setattr(cli, "run_campaign", completed_campaign)

    assert (
        main(
            [
                "fuzz",
                "--output",
                str(tmp_path / "campaign"),
                "--predicate",
                "json",
                "--json-pointer",
                "/accepted",
                    "--json-expected",
                    "true",
                    "--trusted-local",
                    "--",
                sys.executable,
            ]
        )
        == 0
    )
    assert captured["predicate"] == JsonPredicate(
        pointer="/accepted",
        expected=True,
    )


def test_fuzz_field_loss_flags_declare_output_and_compared_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def completed_campaign(**arguments: object) -> CampaignResult:
        captured.update(arguments)
        return CampaignResult(
            candidate_count=1,
            finding_count=0,
            profile_id=XRECHNUNG_UBL_3_0_2.identifier,
        )

    monkeypatch.setattr(cli, "run_campaign", completed_campaign)

    assert (
        main(
            [
                "fuzz",
                "--output",
                str(tmp_path / "campaign"),
                "--predicate",
                "field-loss",
                "--field",
                "buyer_reference",
                "--field",
                "lines.description",
                    "--output-file",
                    "roundtrip.xml",
                    "--trusted-local",
                    "--",
                sys.executable,
            ]
        )
        == 0
    )
    assert captured["predicate"] == DeclaredFieldLossPredicate(
        ("buyer_reference", "lines.description")
    )
    assert captured["target"] == LocalTarget(
        command=(sys.executable,),
        input_mode="stdin",
        output_file="roundtrip.xml",
    )


def test_fuzz_container_flag_builds_a_digest_pinned_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def completed_campaign(**arguments: object) -> CampaignResult:
        captured.update(arguments)
        return CampaignResult(
            candidate_count=1,
            finding_count=0,
            profile_id=XRECHNUNG_UBL_3_0_2.identifier,
        )

    monkeypatch.setattr(cli, "run_campaign", completed_campaign)
    image = "example/importer@sha256:" + "e" * 64

    assert (
        main(
            [
                "fuzz",
                "--output",
                str(tmp_path / "campaign"),
                "--container",
                image,
                "--input-mode",
                "file",
                "--output-file",
                "roundtrip.xml",
                "--",
                "import",
                "/input/invoice.xml",
                "/output/roundtrip.xml",
            ]
        )
        == 0
    )
    assert captured["target"] == ContainerTarget(
        image=image,
        command=(
            "import",
            "/input/invoice.xml",
            "/output/roundtrip.xml",
        ),
        input_mode="file",
        output_file="roundtrip.xml",
    )


def test_replay_unsafe_authority_reexecutes_the_verified_local_target(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    invoice_xml = serialize_invoice(parse_invoice(bundled_seed_path()))
    target = LocalTarget(
        command=(
            sys.executable,
            "-c",
            "import sys; sys.stdin.buffer.read(); raise SystemExit(23)",
        ),
        input_mode="stdin",
    )
    policy = ProcessPolicy(timeout_seconds=2.0, cpu_seconds=1.0)
    baseline = run_local_target(
        target,
        invoice_xml,
        workspace=tmp_path / "baseline",
        policy=policy,
    )
    record = FindingRecord(
        case_id="synthetic-replay",
        predicate="crash-or-nonzero",
        profile_id=XRECHNUNG_UBL_3_0_2.identifier,
        target_digest=baseline.target_digest,
        invoice_sha256=hashlib.sha256(invoice_xml).hexdigest(),
        fingerprint=semantic_fingerprint(parse_invoice(invoice_xml)),
        termination="exited",
        returncode=23,
        details=(),
        mutations=("invoice-id@1:1",),
        one_minimal=True,
        reproductions=1,
        synthetic=True,
    )
    capsule = tmp_path / "finding.rechnungsprobe"
    create_finding_capsule(
        capsule,
        record=record,
        invoice_xml=invoice_xml,
        replay=ReplaySpecification(
            target=target,
            predicate=CrashPredicate(),
            policy=policy,
        ),
    )

    assert (
        main(["replay", str(capsule), "--unsafe-use-capsule-local-command"])
        == 0
    )
    captured = capsys.readouterr()
    assert json.loads(captured.err) == {
        "execution_mode": "unsafe-capsule-local-command",
        "status": "warning",
        "warning": (
            "local command execution is non-isolated and may access "
            "the host filesystem and network"
        ),
    }
    assert json.loads(captured.out) == {
        "case_id": "synthetic-replay",
        "executed_target_digest": baseline.target_digest,
        "execution_mode": "unsafe-capsule-local-command",
        "predicate": "crash-or-nonzero",
        "recorded_target_digest": baseline.target_digest,
        "status": "reproduced",
    }


def test_replay_command_requires_explicit_consent_for_a_local_target(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invoice_xml = serialize_invoice(parse_invoice(bundled_seed_path()))
    target = LocalTarget(command=("untrusted-host-command",), input_mode="stdin")
    record = FindingRecord(
        case_id="untrusted-local-replay",
        predicate="crash-or-nonzero",
        profile_id=XRECHNUNG_UBL_3_0_2.identifier,
        target_digest="sha256:" + "a" * 64,
        invoice_sha256=hashlib.sha256(invoice_xml).hexdigest(),
        fingerprint=semantic_fingerprint(parse_invoice(invoice_xml)),
        termination="exited",
        returncode=23,
        details=(),
        mutations=("invoice-id@1:1",),
        one_minimal=True,
        reproductions=1,
        synthetic=True,
    )
    capsule = tmp_path / "untrusted.rechnungsprobe"
    create_finding_capsule(
        capsule,
        record=record,
        invoice_xml=invoice_xml,
        replay=ReplaySpecification(
            target=target,
            predicate=CrashPredicate(),
            policy=ProcessPolicy(),
        ),
    )

    def must_not_execute(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("local target executed without explicit consent")

    monkeypatch.setattr(cli, "execute_replay", must_not_execute)

    assert main(["replay", str(capsule)]) == 2
    assert json.loads(capsys.readouterr().err) == {
        "error": (
            "local capsule targets require --replacement-command "
            "or --unsafe-use-capsule-local-command"
        ),
        "status": "error",
    }


def test_replay_accepts_a_replacement_local_argument_vector(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    invoice_xml = serialize_invoice(parse_invoice(bundled_seed_path()))
    recorded_digest = "sha256:" + "a" * 64
    record = FindingRecord(
        case_id="replacement-local-replay",
        predicate="crash-or-nonzero",
        profile_id=XRECHNUNG_UBL_3_0_2.identifier,
        target_digest=recorded_digest,
        invoice_sha256=hashlib.sha256(invoice_xml).hexdigest(),
        fingerprint=semantic_fingerprint(parse_invoice(invoice_xml)),
        termination="exited",
        returncode=23,
        details=(),
        mutations=("invoice-id@1:1",),
        one_minimal=True,
        reproductions=1,
        synthetic=True,
    )
    capsule = tmp_path / "replacement.rechnungsprobe"
    create_finding_capsule(
        capsule,
        record=record,
        invoice_xml=invoice_xml,
        replay=ReplaySpecification(
            target=LocalTarget(
                command=("capsule-command-does-not-exist",),
                input_mode="file",
            ),
            predicate=CrashPredicate(),
            policy=ProcessPolicy(timeout_seconds=2.0, cpu_seconds=1.0),
        ),
    )
    replacement = LocalTarget(
        command=(
            sys.executable,
            "-c",
            (
                "import pathlib,sys; "
                "data=pathlib.Path(sys.argv[1]).read_bytes(); "
                "raise SystemExit(23 if data.startswith(b'<?xml') else 0)"
            ),
        ),
        input_mode="file",
    )

    assert (
        main(
            [
                "replay",
                str(capsule),
                "--replacement-command",
                "--",
                *replacement.command,
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {
        "case_id": "replacement-local-replay",
        "executed_target_digest": target_configuration_digest(replacement),
        "execution_mode": "replacement-local-command",
        "predicate": "crash-or-nonzero",
        "recorded_target_digest": recorded_digest,
        "status": "matched-with-replacement",
    }


def test_replay_preflights_target_digest_before_local_execution(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invoice_xml = serialize_invoice(parse_invoice(bundled_seed_path()))
    target = LocalTarget(
        command=(sys.executable, "-c", "raise SystemExit(23)"),
        input_mode="stdin",
    )
    record = FindingRecord(
        case_id="tampered-local-replay",
        predicate="crash-or-nonzero",
        profile_id=XRECHNUNG_UBL_3_0_2.identifier,
        target_digest="sha256:" + "a" * 64,
        invoice_sha256=hashlib.sha256(invoice_xml).hexdigest(),
        fingerprint=semantic_fingerprint(parse_invoice(invoice_xml)),
        termination="exited",
        returncode=23,
        details=(),
        mutations=("invoice-id@1:1",),
        one_minimal=True,
        reproductions=1,
        synthetic=True,
    )
    capsule = tmp_path / "tampered.rechnungsprobe"
    create_finding_capsule(
        capsule,
        record=record,
        invoice_xml=invoice_xml,
        replay=ReplaySpecification(
            target=target,
            predicate=CrashPredicate(),
            policy=ProcessPolicy(),
        ),
    )

    def must_not_execute(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("target executed before its digest was checked")

    monkeypatch.setattr(cli, "execute_replay", must_not_execute)

    assert (
        main(["replay", str(capsule), "--unsafe-use-capsule-local-command"])
        == 2
    )
    assert json.loads(capsys.readouterr().err) == {
        "error": "replay target configuration does not match the capsule digest",
        "status": "error",
    }
