from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import psutil
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


def test_bounded_process_fails_closed_when_workspace_scan_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def denied(_path: object) -> object:
        raise PermissionError("synthetic traversal denial")

    monkeypatch.setattr("rechnungsprobe.process.os.scandir", denied)

    with pytest.raises(SecurityError, match="inspected safely"):
        run_bounded_process(
            (sys.executable, "-c", "pass"),
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


def test_bounded_process_kills_descendants_after_the_parent_exits(tmp_path: Path) -> None:
    pid_file = tmp_path / "child.pid"
    child_code = (
        "import os,pathlib,sys,time; "
        "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
        "time.sleep(30)"
    )
    parent_code = (
        "import pathlib,subprocess,sys,time; "
        "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,"
        "close_fds=True); "
        "p=pathlib.Path(sys.argv[2]); deadline=time.monotonic()+5; "
        "\nwhile not p.exists() and time.monotonic()<deadline: time.sleep(0.01)"
    )

    result = run_bounded_process(
        (sys.executable, "-c", parent_code, child_code, str(pid_file)),
        cwd=tmp_path,
        policy=ProcessPolicy(timeout_seconds=8, cpu_seconds=6),
    )

    assert result.termination == "exited"
    child_pid = int(pid_file.read_text())
    child: psutil.Process | None = None
    try:
        try:
            child = psutil.Process(child_pid)
        except psutil.NoSuchProcess:
            # The process can disappear between pid_exists/Process on POSIX.
            pass
        if child is not None:
            child.wait(timeout=2)
            assert not child.is_running()
    finally:
        try:
            if child is not None and child.is_running():
                child.kill()
        except psutil.NoSuchProcess:
            pass


@pytest.mark.skipif(os.name != "nt", reason="NTFS junction behavior is Windows-specific")
def test_bounded_process_rejects_a_created_junction(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    junction = tmp_path / "escape"
    code = (
        "import subprocess,sys,time; "
        "result=subprocess.run(['cmd','/c','mklink','/J',sys.argv[1],sys.argv[2]],"
        "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        "raise SystemExit(result.returncode) if result.returncode else time.sleep(30)"
    )

    result = run_bounded_process(
        (sys.executable, "-c", code, str(junction), str(outside)),
        cwd=tmp_path,
        policy=ProcessPolicy(timeout_seconds=5, cpu_seconds=4),
    )

    assert result.termination == "file_limit"
