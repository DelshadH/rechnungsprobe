from __future__ import annotations

import json
import stat
import zipfile
from pathlib import Path

import pytest

from tools import release_artifacts
from tools.release_artifacts import augment_sbom, validate_sbom


def test_sbom_augmentation_records_every_bundled_validation_artifact(
    tmp_path: Path,
) -> None:
    path = tmp_path / "sbom.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [],
                "specVersion": "1.6",
                "version": 1,
            }
        ),
        encoding="utf-8",
    )

    augment_sbom(path)

    payload = json.loads(path.read_bytes())
    components = payload["components"]
    assert {component["name"] for component in components} == {
        "KoSIT Validator",
        "XRechnung testsuite seed",
        "XRechnung validator configuration",
    }
    assert all(component["hashes"][0]["alg"] == "SHA-256" for component in components)
    assert all(component["externalReferences"][0]["url"] for component in components)
    serial_number = payload["serialNumber"]
    assert serial_number.startswith("urn:uuid:")
    validate_sbom(path)
    augment_sbom(path)
    assert json.loads(path.read_bytes())["serialNumber"] == serial_number
    payload["version"] = 2
    path.write_text(json.dumps(payload), encoding="utf-8")
    augment_sbom(path)
    assert json.loads(path.read_bytes())["serialNumber"] != serial_number


def test_sbom_validation_rejects_document_that_github_cannot_attest(
    tmp_path: Path,
) -> None:
    path = tmp_path / "sbom.json"
    path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [],
                "specVersion": "1.6",
                "version": 1,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="serialNumber"):
        validate_sbom(path)


def test_sbom_augmentation_rejects_invalid_component_shape(tmp_path: Path) -> None:
    path = tmp_path / "sbom.json"
    path.write_text('{"components":{}}', encoding="utf-8")

    with pytest.raises(TypeError, match="components"):
        augment_sbom(path)


def test_wheel_inventory_rejects_symbolic_links(tmp_path: Path) -> None:
    path = tmp_path / "hostile.whl"
    information = zipfile.ZipInfo("rechnungsprobe/link")
    information.create_system = 3
    information.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(information, b"target")

    with pytest.raises(ValueError, match="regular file"):
        release_artifacts._wheel_inventory(path)


@pytest.mark.parametrize("name", ["../escape", "/absolute", "nested\\windows"])
def test_archive_member_validation_rejects_unsafe_names(name: str) -> None:
    with pytest.raises(ValueError, match="unsafe"):
        release_artifacts._safe_member(name)
