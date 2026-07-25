from __future__ import annotations

import hashlib
from pathlib import Path

from rechnungsprobe.profiles import XRECHNUNG_UBL_3_0_2, materialize_profile


def test_profile_is_fully_pinned() -> None:
    profile = XRECHNUNG_UBL_3_0_2

    assert profile.identifier == "xrechnung-ubl-3.0.2-2026-01-31"
    assert profile.syntax == "ubl-invoice-2.1"
    assert profile.validator_version == "1.6.2"
    assert profile.configuration_version == "2026-01-31"
    assert len(profile.validator_sha256) == 64
    assert len(profile.configuration_sha256) == 64
    assert profile.validator_url.startswith("https://github.com/itplr-kosit/")
    assert profile.configuration_url.startswith("https://github.com/itplr-kosit/")
    assert profile.license == "Apache-2.0"


def test_bundled_artifact_hashes_match_manifest() -> None:
    profile = XRECHNUNG_UBL_3_0_2

    assert hashlib.sha256(profile.validator_path.read_bytes()).hexdigest() == (
        profile.validator_sha256
    )
    assert hashlib.sha256(profile.configuration_path.read_bytes()).hexdigest() == (
        profile.configuration_sha256
    )


def test_profile_materialization_is_deterministic(tmp_path: Path) -> None:
    first = materialize_profile(XRECHNUNG_UBL_3_0_2, tmp_path / "first")
    second = materialize_profile(XRECHNUNG_UBL_3_0_2, tmp_path / "second")

    assert first.scenario_path.read_bytes() == second.scenario_path.read_bytes()
    assert first.tree_sha256 == second.tree_sha256
    assert first.scenario_path.name == "scenarios.xml"
