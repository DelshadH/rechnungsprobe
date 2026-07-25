from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

from rechnungsprobe.process import ProcessPolicy, run_bounded_process
from rechnungsprobe.security import SecurityError


def test_bounded_process_returns_stdout_and_stderr(tmp_path: Path) -> None:
    result = run_bounded_process(
        (
            sys.executable,
            "-c",
            "import sys; print('out'); print('err', file=sys.stderr)",
        ),
        cwd=tmp_path,
        policy=ProcessPolicy(),
    )

    assert result.termination == "exited"
    assert result.returncode == 0
    assert result.stdout == b"out" + os.linesep.encode()
    assert result.stderr == b"err" + os.linesep.encode()


def test_bounded_process_kills_timeout(tmp_path: Path) -> None:
    started = time.monotonic()

    result = run_bounded_process(
        (sys.executable, "-c", "import time; time.sleep(30)"),
        cwd=tmp_path,
        policy=ProcessPolicy(timeout_seconds=0.2),
    )

    assert result.termination == "timeout"
    assert time.monotonic() - started < 3


def test_bounded_process_timeout_includes_blocked_stdin_delivery(tmp_path: Path) -> None:
    started = time.monotonic()

    result = run_bounded_process(
        (sys.executable, "-c", "import time; time.sleep(1)"),
        cwd=tmp_path,
        policy=ProcessPolicy(
            timeout_seconds=0.2,
            cpu_seconds=1,
            max_input_bytes=2 * 1024 * 1024,
        ),
        input_bytes=b"x" * (1024 * 1024),
    )

    assert result.termination == "timeout"
    assert time.monotonic() - started < 0.8


def test_bounded_process_stops_output_flood(tmp_path: Path) -> None:
    result = run_bounded_process(
        (sys.executable, "-c", "import sys; sys.stdout.write('x' * 1000000)"),
        cwd=tmp_path,
        policy=ProcessPolicy(max_output_bytes=1024),
    )

    assert result.termination == "output_limit"
    assert len(result.stdout) + len(result.stderr) == 1024


def test_bounded_process_stops_file_output_flood(tmp_path: Path) -> None:
    result = run_bounded_process(
        (
            sys.executable,
            "-c",
            (
                "from pathlib import Path;"
                "import time;"
                "Path('flood.bin').write_bytes(b'x' * 1000000);"
                "time.sleep(30)"
            ),
        ),
        cwd=tmp_path,
        policy=ProcessPolicy(max_file_growth_bytes=1024),
    )

    assert result.termination == "file_limit"


def test_bounded_process_does_not_inherit_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECHNUNGSPROBE_TEST_SECRET", "must-not-leak")

    result = run_bounded_process(
        (
            sys.executable,
            "-c",
            (
                "import os,sys;"
                "sys.stdout.write(os.environ.get('RECHNUNGSPROBE_TEST_SECRET','absent'))"
            ),
        ),
        cwd=tmp_path,
        policy=ProcessPolicy(),
    )

    assert result.stdout == b"absent"


def test_bounded_process_redirects_temporary_files_into_workspace(
    tmp_path: Path,
) -> None:
    result = run_bounded_process(
        (
            sys.executable,
            "-c",
            (
                "import json,os;"
                "print(json.dumps({key:os.environ.get(key) for key in ('TEMP','TMP','TMPDIR')}))"
            ),
        ),
        cwd=tmp_path,
        policy=ProcessPolicy(),
    )

    temporary_paths = {
        Path(value).resolve()
        for value in json.loads(result.stdout).values()
        if value is not None
    }
    assert temporary_paths == {tmp_path.resolve()}


def test_bounded_process_rejects_shell_command_strings(tmp_path: Path) -> None:
    with pytest.raises(SecurityError, match="argument vector"):
        run_bounded_process(
            f"{sys.executable} -c pass",
            cwd=tmp_path,
            policy=ProcessPolicy(),
        )


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks are unavailable")
def test_bounded_process_rejects_symlink_working_directory(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("creating symlinks is not permitted")

    with pytest.raises(SecurityError, match="working directory"):
        run_bounded_process(
            (sys.executable, "-c", "pass"),
            cwd=link,
            policy=ProcessPolicy(),
        )
