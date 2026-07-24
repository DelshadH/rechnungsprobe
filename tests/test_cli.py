from __future__ import annotations

from rechnungsprobe.cli import main


def test_help_path_exits_successfully(capsys: object) -> None:
    assert main([]) == 0
