from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from rechnungsprobe import target as target_module
from rechnungsprobe.process import ProcessPolicy, ProcessResult
from rechnungsprobe.security import SecurityError
from rechnungsprobe.target import (
    ContainerTarget,
    LocalTarget,
    build_docker_command,
    run_local_target,
)


def test_local_stdin_target_receives_exact_invoice_bytes(tmp_path: Path) -> None:
    invoice = b"<Invoice/>"
    target = LocalTarget(
        command=(
            sys.executable,
            "-c",
            (
                "import hashlib,json,sys;"
                "data=sys.stdin.buffer.read();"
                "print(json.dumps({'sha256':hashlib.sha256(data).hexdigest()}))"
            ),
        ),
        input_mode="stdin",
    )

    result = run_local_target(
        target,
        invoice,
        workspace=tmp_path,
        policy=ProcessPolicy(),
    )

    assert result.process.returncode == 0
    assert json.loads(result.process.stdout)["sha256"] == hashlib.sha256(invoice).hexdigest()


def test_local_target_resolves_and_hashes_existing_relative_file_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    importer = tmp_path / "importer.py"
    importer.write_text(
        "import hashlib, sys\n"
        "print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    invoice = b"<Invoice/>"

    result = run_local_target(
        LocalTarget(
            command=(sys.executable, "importer.py"),
            input_mode="stdin",
        ),
        invoice,
        workspace=tmp_path / "work",
        policy=ProcessPolicy(),
    )

    assert result.process.returncode == 0
    assert result.process.stdout.strip() == hashlib.sha256(invoice).hexdigest().encode()


def test_local_file_target_gets_fixed_non_interpolated_path(tmp_path: Path) -> None:
    target = LocalTarget(
        command=(
            sys.executable,
            "-c",
            "from pathlib import Path; import sys; print(Path(sys.argv[1]).read_text())",
        ),
        input_mode="file",
    )

    result = run_local_target(
        target,
        b"<Invoice/>",
        workspace=tmp_path,
        policy=ProcessPolicy(),
    )

    assert result.process.stdout.strip() == b"<Invoice/>"


def test_local_target_reads_only_bounded_regular_output_file(tmp_path: Path) -> None:
    target = LocalTarget(
        command=(
            sys.executable,
            "-c",
            "from pathlib import Path; Path('output.xml').write_text('<Invoice/>')",
        ),
        input_mode="stdin",
        output_file="output.xml",
    )

    result = run_local_target(
        target,
        b"<Invoice/>",
        workspace=tmp_path,
        policy=ProcessPolicy(),
    )

    assert result.output_xml == b"<Invoice/>"


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks are unavailable")
def test_local_target_rejects_an_output_through_a_symlinked_parent(
    tmp_path: Path,
) -> None:
    target = LocalTarget(
        command=(
            sys.executable,
            "-c",
            (
                "from pathlib import Path;"
                "Path('../secret.xml').write_text('<Invoice/>');"
                "Path('link').symlink_to('..', target_is_directory=True)"
            ),
        ),
        input_mode="stdin",
        output_file="link/secret.xml",
    )

    with pytest.raises(SecurityError, match="symbolic link"):
        run_local_target(
            target,
            b"<Invoice/>",
            workspace=tmp_path / "work",
            policy=ProcessPolicy(),
        )


@pytest.mark.parametrize("output_file", ["../out.xml", "/out.xml", r"C:\out.xml"])
def test_local_target_rejects_unsafe_output_path(tmp_path: Path, output_file: str) -> None:
    target = LocalTarget(
        command=(sys.executable, "-c", "pass"),
        input_mode="stdin",
        output_file=output_file,
    )

    with pytest.raises(SecurityError, match="output"):
        run_local_target(
            target,
            b"<Invoice/>",
            workspace=tmp_path,
            policy=ProcessPolicy(),
        )


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks are unavailable")
def test_local_target_rejects_a_workspace_below_a_symlinked_parent(
    tmp_path: Path,
) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked"
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError:
        pytest.skip("creating symlinks is not permitted")

    with pytest.raises(SecurityError, match="parent"):
        run_local_target(
            LocalTarget(
                command=(sys.executable, "-c", "pass"),
                input_mode="stdin",
            ),
            b"<Invoice/>",
            workspace=linked_parent / "work",
            policy=ProcessPolicy(),
        )


def test_container_target_requires_digest_and_strict_isolation(tmp_path: Path) -> None:
    digest = "a" * 64
    target = ContainerTarget(
        image=f"example/importer@sha256:{digest}",
        command=("import", "/input/invoice.xml", "/output/output.xml"),
        input_mode="file",
        output_file="output.xml",
    )

    command = build_docker_command(
        target,
        workspace=tmp_path,
        policy=ProcessPolicy(max_memory_bytes=256 * 1024 * 1024, max_processes=4),
    )

    assert command[0:3] == ("docker", "run", "--rm")
    assert "--network=none" in command
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--pids-limit=4" in command
    assert "--memory=268435456" in command
    assert "--memory-swap=268435456" in command
    assert "--cpus=1.0" in command
    assert "--pull=never" in command
    assert target.image in command
    assert os.fspath(tmp_path.absolute()) in " ".join(command)


def test_container_target_rejects_mutable_tag(tmp_path: Path) -> None:
    target = ContainerTarget(
        image="example/importer:latest",
        command=("import",),
        input_mode="stdin",
    )

    with pytest.raises(SecurityError, match="digest"):
        build_docker_command(target, workspace=tmp_path, policy=ProcessPolicy())


def test_container_target_accepts_a_digest_pinned_registry_port(tmp_path: Path) -> None:
    target = ContainerTarget(
        image="localhost:5000/example/importer@sha256:" + "a" * 64,
        command=("import",),
        input_mode="stdin",
    )

    command = build_docker_command(
        target,
        workspace=tmp_path,
        policy=ProcessPolicy(),
    )

    assert target.image in command


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are not enforced on Windows")
def test_container_output_directory_is_writable_by_the_unprivileged_user(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def completed_process(*_args: object, **_kwargs: object) -> ProcessResult:
        return ProcessResult(
            termination="exited",
            returncode=0,
            stdout=b"",
            stderr=b"",
        )

    monkeypatch.setattr(target_module, "run_bounded_process", completed_process)
    target_module.run_container_target(
        ContainerTarget(
            image="example/importer@sha256:" + "a" * 64,
            command=("import",),
            input_mode="stdin",
            output_file="roundtrip.xml",
        ),
        b"<Invoice/>",
        workspace=tmp_path / "work",
        policy=ProcessPolicy(),
    )

    mode = (tmp_path / "work" / "output").stat().st_mode & 0o777
    assert mode == 0o733


def test_container_target_digest_covers_command_and_io_configuration() -> None:
    image = "example/importer@sha256:" + "a" * 64
    baseline = ContainerTarget(
        image=image,
        command=("import",),
        input_mode="stdin",
    )
    variants = (
        ContainerTarget(image=image, command=("import", "--strict"), input_mode="stdin"),
        ContainerTarget(image=image, command=("import",), input_mode="file"),
        ContainerTarget(
            image=image,
            command=("import",),
            input_mode="stdin",
            output_file="roundtrip.xml",
        ),
    )

    digest = target_module.target_configuration_digest(baseline)

    assert digest.startswith("sha256:")
    assert len(digest) == 71
    assert all(target_module.target_configuration_digest(variant) != digest for variant in variants)
