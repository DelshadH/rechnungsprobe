from __future__ import annotations

import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from rechnungsprobe.capsule import create_finding_capsule, verify_finding_capsule
from rechnungsprobe.model import parse_invoice, semantic_fingerprint, serialize_invoice
from rechnungsprobe.predicates import CrashPredicate
from rechnungsprobe.process import ProcessPolicy
from rechnungsprobe.profiles import XRECHNUNG_UBL_3_0_2, bundled_seed_path
from rechnungsprobe.provenance import (
    FindingProvenance,
    MinimizationProof,
    Observation,
    profile_payload,
    resource_policy_payload,
)
from rechnungsprobe.replay import ReplaySpecification
from rechnungsprobe.reporting import FindingRecord
from rechnungsprobe.security import SecurityError
from rechnungsprobe.target import ContainerTarget, LocalTarget


def _record(invoice: bytes) -> FindingRecord:
    parsed = parse_invoice(invoice)
    import hashlib

    return FindingRecord(
        case_id="synthetic-0001",
        predicate="crash-or-nonzero",
        profile_id=XRECHNUNG_UBL_3_0_2.identifier,
        target_digest="sha256:" + ("a" * 64),
        invoice_sha256=hashlib.sha256(invoice).hexdigest(),
        fingerprint=semantic_fingerprint(parsed),
        termination="exited",
        returncode=23,
        details=("synthetic fixture",),
        mutations=("invoice-id@1",),
        one_minimal=True,
        reproductions=5,
        synthetic=True,
    )


def _replay() -> ReplaySpecification:
    return ReplaySpecification(
        target=LocalTarget(
            command=("synthetic-importer",),
            input_mode="stdin",
        ),
        predicate=CrashPredicate(),
        policy=ProcessPolicy(),
    )


def test_capsule_is_deterministic_and_self_verifying(tmp_path: Path) -> None:
    invoice = serialize_invoice(parse_invoice(bundled_seed_path()))
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"

    create_finding_capsule(
        first,
        record=_record(invoice),
        invoice_xml=invoice,
        replay=_replay(),
    )
    create_finding_capsule(
        second,
        record=_record(invoice),
        invoice_xml=invoice,
        replay=_replay(),
    )

    assert first.read_bytes() == second.read_bytes()
    verified = verify_finding_capsule(first)
    assert verified.invoice_xml == invoice
    assert verified.record.case_id == "synthetic-0001"


def test_capsule_verifier_rejects_modified_member(tmp_path: Path) -> None:
    invoice = serialize_invoice(parse_invoice(bundled_seed_path()))
    capsule = tmp_path / "finding.zip"
    create_finding_capsule(
        capsule,
        record=_record(invoice),
        invoice_xml=invoice,
        replay=_replay(),
    )

    with (
        pytest.warns(UserWarning, match="Duplicate name"),
        zipfile.ZipFile(capsule, "a", compression=zipfile.ZIP_STORED) as archive,
    ):
        archive.writestr("invoice.xml", b"<Invoice/>")

    with pytest.raises(SecurityError, match="duplicate|member|hash"):
        verify_finding_capsule(capsule)


def test_capsule_writer_never_overwrites_existing_file(tmp_path: Path) -> None:
    invoice = serialize_invoice(parse_invoice(bundled_seed_path()))
    capsule = tmp_path / "finding.zip"
    capsule.write_bytes(b"caller-owned")

    with pytest.raises(SecurityError, match="exists"):
        create_finding_capsule(
            capsule,
            record=_record(invoice),
            invoice_xml=invoice,
            replay=_replay(),
        )

    assert capsule.read_bytes() == b"caller-owned"


def test_capsule_verifier_rejects_archive_traversal(tmp_path: Path) -> None:
    capsule = tmp_path / "hostile.zip"
    with zipfile.ZipFile(capsule, "w") as archive:
        archive.writestr("../manifest.json", b"{}")

    with pytest.raises(SecurityError, match="member"):
        verify_finding_capsule(capsule)


def test_capsule_verifier_normalizes_malformed_zip_errors(tmp_path: Path) -> None:
    capsule = tmp_path / "malformed.rechnungsprobe"
    capsule.write_bytes(b"not a zip archive")

    with pytest.raises(SecurityError, match="ZIP"):
        verify_finding_capsule(capsule)


def test_capsule_binds_the_exact_replay_configuration(tmp_path: Path) -> None:
    invoice = serialize_invoice(parse_invoice(bundled_seed_path()))
    capsule = tmp_path / "finding.rechnungsprobe"
    replay = ReplaySpecification(
        target=LocalTarget(
            command=("synthetic-importer",),
            input_mode="stdin",
        ),
        predicate=CrashPredicate(),
        policy=ProcessPolicy(),
    )

    create_finding_capsule(
        capsule,
        record=_record(invoice),
        invoice_xml=invoice,
        replay=replay,
    )

    assert verify_finding_capsule(capsule).replay == replay


def test_capsule_rejects_a_container_configuration_digest_mismatch(
    tmp_path: Path,
) -> None:
    invoice = serialize_invoice(parse_invoice(bundled_seed_path()))
    replay = ReplaySpecification(
        target=ContainerTarget(
            image="example/importer@sha256:" + "f" * 64,
            command=("import",),
            input_mode="stdin",
        ),
        predicate=CrashPredicate(),
        policy=ProcessPolicy(),
    )

    with pytest.raises(SecurityError, match="target configuration"):
        create_finding_capsule(
            tmp_path / "finding.rechnungsprobe",
            record=_record(invoice),
            invoice_xml=invoice,
            replay=replay,
        )


def test_real_finding_record_requires_provenance() -> None:
    invoice = serialize_invoice(parse_invoice(bundled_seed_path()))

    with pytest.raises(SecurityError, match="provenance"):
        replace(_record(invoice), synthetic=False)


def test_capsule_rejects_provenance_that_disagrees_with_replay_policy(
    tmp_path: Path,
) -> None:
    invoice = serialize_invoice(parse_invoice(bundled_seed_path()))
    baseline = _record(invoice)
    observation = Observation(
        termination="exited",
        returncode=23,
        stdout_sha256="0" * 64,
        stderr_sha256="0" * 64,
        output_sha256=None,
    )
    provenance = FindingProvenance(
        campaign_seed=1,
        seed_sha256="1" * 64,
        seed_fingerprint="2" * 64,
        profile=profile_payload(XRECHNUNG_UBL_3_0_2),
        target_digest=baseline.target_digest,
        resource_policy=resource_policy_payload(ProcessPolicy()),
        observations=(observation,) * baseline.reproductions,
        minimization=MinimizationProof(
            algorithm="greedy-1-minimal-v1",
            declared_operations="invoice-node-value-v1",
            attempts=1,
            accepted_operations=(),
            one_minimal=True,
            verification_attempts=1,
        ),
    )
    record = replace(baseline, synthetic=False, provenance=provenance)
    replay = replace(_replay(), policy=ProcessPolicy(timeout_seconds=9))

    with pytest.raises(SecurityError, match="provenance"):
        create_finding_capsule(
            tmp_path / "finding.rechnungsprobe",
            record=record,
            invoice_xml=invoice,
            replay=replay,
        )
