from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from rechnungsprobe import validate
from rechnungsprobe.profiles import XRECHNUNG_UBL_3_0_2, bundled_seed_path
from rechnungsprobe.security import SecurityError
from rechnungsprobe.validate import validate_invoice


def test_official_seed_passes_pinned_kosit_profile(tmp_path: Path) -> None:
    result = validate_invoice(bundled_seed_path(), workspace=tmp_path)

    assert result.valid is True
    assert result.profile_id == "xrechnung-ubl-3.0.2-2026-01-31"
    assert result.exit_code == 0
    assert result.errors == ()
    assert result.report_sha256 is not None


def test_validator_is_not_started_when_jar_integrity_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corrupt_jar = tmp_path / "validator.jar"
    corrupt_jar.write_bytes(b"not the official validator")
    profile = replace(XRECHNUNG_UBL_3_0_2, validator_path=corrupt_jar)

    def forbidden_run(*args: object, **kwargs: object) -> None:
        raise AssertionError("subprocess started before artifact verification")

    monkeypatch.setattr(validate, "run_bounded_process", forbidden_run)

    with pytest.raises(SecurityError, match="validator SHA-256"):
        validate_invoice(
            bundled_seed_path(),
            workspace=tmp_path / "workspace",
            profile=profile,
        )
