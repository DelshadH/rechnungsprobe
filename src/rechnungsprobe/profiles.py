from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from rechnungsprobe.security import SecurityError, open_regular_file, safe_extract_zip

_PACKAGE_ROOT = Path(__file__).resolve().parent
_DATA_ROOT = _PACKAGE_ROOT / "data"


@dataclass(frozen=True, slots=True)
class Profile:
    identifier: str
    syntax: str
    validator_version: str
    configuration_version: str
    validator_url: str
    configuration_url: str
    validator_sha256: str
    configuration_sha256: str
    license: str
    validator_path: Path
    configuration_path: Path


@dataclass(frozen=True, slots=True)
class MaterializedProfile:
    specification: Profile
    root: Path
    scenario_path: Path
    validator_path: Path
    tree_sha256: str


XRECHNUNG_UBL_3_0_2 = Profile(
    identifier="xrechnung-ubl-3.0.2-2026-01-31",
    syntax="ubl-invoice-2.1",
    validator_version="1.6.2",
    configuration_version="2026-01-31",
    validator_url=(
        "https://github.com/itplr-kosit/validator/releases/download/"
        "v1.6.2/validator-1.6.2-standalone.jar"
    ),
    configuration_url=(
        "https://github.com/itplr-kosit/validator-configuration-xrechnung/releases/download/"
        "v2026-01-31/xrechnung-3.0.2-validator-configuration-2026-01-31.zip"
    ),
    validator_sha256="244978514ad48f67c7573acfffc8f4fd73d81feda6f276710033f9913579857e",
    configuration_sha256="6a5a5911a421b25fbc423f62f93f894df7b236f5d73ca4f84bb222a945082704",
    license="Apache-2.0",
    validator_path=_DATA_ROOT / "artifacts" / "validator-1.6.2-standalone.jar",
    configuration_path=(
        _DATA_ROOT / "artifacts" / "xrechnung-3.0.2-validator-configuration-2026-01-31.zip"
    ),
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open_regular_file(path, max_bytes=512 * 1024 * 1024) as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def bundled_seed_path() -> Path:
    return _DATA_ROOT / "seeds" / "01.01a-INVOICE_ubl.xml"


def materialize_profile(profile: Profile, destination: Path) -> MaterializedProfile:
    if _sha256(profile.validator_path) != profile.validator_sha256:
        raise SecurityError("bundled validator SHA-256 does not match the profile")
    if _sha256(profile.configuration_path) != profile.configuration_sha256:
        raise SecurityError("bundled configuration SHA-256 does not match the profile")

    destination = destination.absolute()
    if destination.exists() and (
        destination.is_symlink() or not destination.is_dir() or any(destination.iterdir())
    ):
        raise SecurityError("profile destination must be an empty real directory")
    parent = destination.parent.resolve(strict=True)
    if destination.parent.is_symlink() or not parent.is_dir():
        raise SecurityError("profile destination parent must be a real directory")
    destination = parent / destination.name
    if not destination.exists():
        destination.mkdir()

    copied_validator = destination / "validator.jar"
    copied_configuration = destination / "configuration.zip"
    created: list[Path] = []
    try:
        for source, target, expected_hash in (
            (profile.validator_path, copied_validator, profile.validator_sha256),
            (
                profile.configuration_path,
                copied_configuration,
                profile.configuration_sha256,
            ),
        ):
            with (
                open_regular_file(source, max_bytes=512 * 1024 * 1024) as input_file,
                target.open("xb") as output_file,
            ):
                created.append(target)
                while chunk := input_file.read(1024 * 1024):
                    output_file.write(chunk)
            if _sha256(target) != expected_hash:
                raise SecurityError("copied profile artifact failed integrity verification")

        repository = destination / "repository"
        extracted = safe_extract_zip(copied_configuration, repository)
    except Exception:
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise

    scenario_path = repository / "scenarios.xml"
    if scenario_path not in extracted:
        raise SecurityError("profile archive does not contain scenarios.xml")

    digest = hashlib.sha256()
    for path in extracted:
        relative = path.relative_to(repository).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(bytes.fromhex(_sha256(path)))
    return MaterializedProfile(
        specification=profile,
        root=repository,
        scenario_path=scenario_path,
        validator_path=copied_validator,
        tree_sha256=digest.hexdigest(),
    )
