from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from rechnungsprobe.process import ProcessPolicy, ProcessResult, run_bounded_process
from rechnungsprobe.security import SecurityError, open_regular_file
from rechnungsprobe.xmlsafe import parse_xml_bytes

InputMode = Literal["stdin", "file"]
_IMAGE_DIGEST = re.compile(
    r"^(?:sha256:[0-9a-f]{64}|[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64})$"
)
_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


@dataclass(frozen=True, slots=True)
class LocalTarget:
    command: tuple[str, ...]
    input_mode: InputMode
    output_file: str | None = None


@dataclass(frozen=True, slots=True)
class ContainerTarget:
    image: str
    command: tuple[str, ...]
    input_mode: InputMode
    output_file: str | None = None


@dataclass(frozen=True, slots=True)
class TargetResult:
    process: ProcessResult
    output_xml: bytes | None
    target_digest: str


def _output_path(workspace: Path, configured: str | None) -> Path | None:
    if configured is None:
        return None
    portable = configured.replace("\\", "/")
    if (
        not portable
        or portable.startswith("/")
        or _DRIVE_PREFIX.match(portable)
        or "\x00" in portable
    ):
        raise SecurityError("target output path is unsafe")
    path = PurePosixPath(portable)
    if any(part in {"", ".", ".."} for part in path.parts) or len(path.parts) > 8:
        raise SecurityError("target output path is unsafe")
    candidate = workspace.joinpath(*path.parts)
    if not candidate.is_relative_to(workspace):
        raise SecurityError("target output path is unsafe")
    return candidate


def _prepare_workspace(workspace: Path) -> Path:
    workspace = workspace.absolute()
    if workspace.exists():
        resolved = workspace.resolve(strict=True)
        if (
            workspace != resolved
            or workspace.is_symlink()
            or not workspace.is_dir()
            or any(workspace.iterdir())
        ):
            raise SecurityError("target workspace must be an empty real directory")
        workspace = resolved
    else:
        unresolved_parent = workspace.parent
        parent = unresolved_parent.resolve(strict=True)
        if unresolved_parent != parent or parent.is_symlink() or not parent.is_dir():
            raise SecurityError("target workspace parent must be a real directory")
        workspace = parent / workspace.name
        workspace.mkdir()
    return workspace


def _hash_regular_file(path: Path, max_bytes: int = 2 * 1024 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open_regular_file(path, max_bytes=max_bytes) as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _local_target_digest(target: LocalTarget) -> tuple[str, tuple[str, ...]]:
    if not target.command:
        raise SecurityError("local target command is empty")
    executable = shutil.which(target.command[0])
    if executable is None:
        raise SecurityError("local target executable was not found")
    executable_path = Path(executable).resolve(strict=True)
    resolved_arguments: list[str] = []
    file_hashes: dict[str, str] = {
        "executable": _hash_regular_file(executable_path),
    }
    for index, argument in enumerate(target.command[1:], start=1):
        argument_path = Path(argument)
        if argument_path.is_file():
            resolved_path = argument_path.resolve(strict=True)
            file_hashes[f"argument-{index}"] = _hash_regular_file(resolved_path)
            resolved_arguments.append(os.fspath(resolved_path))
        else:
            resolved_arguments.append(argument)
    resolved_command = (os.fspath(executable_path), *resolved_arguments)
    payload = json.dumps(
        {
            "command": resolved_command,
            "files": file_hashes,
            "input_mode": target.input_mode,
            "output_file": target.output_file,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return f"sha256:{hashlib.sha256(payload).hexdigest()}", resolved_command


def resolve_local_target(target: LocalTarget) -> LocalTarget:
    """Resolve executable and existing file arguments for portable replay metadata."""

    _digest, command = _local_target_digest(target)
    return LocalTarget(
        command=command,
        input_mode=target.input_mode,
        output_file=target.output_file,
    )


def _stage_local_command(
    command: tuple[str, ...],
    *,
    workspace: Path,
) -> tuple[str, ...]:
    staged = list(command)
    stage_root = workspace / ".target-files"
    stage_root.mkdir()
    for index, argument in enumerate(command[1:], start=1):
        source = Path(argument)
        if not source.is_file():
            continue
        expected = _hash_regular_file(source)
        suffix = source.suffix if re.fullmatch(r"\.[A-Za-z0-9]{1,10}", source.suffix) else ""
        destination = stage_root / f"argument-{index:03d}{suffix}"
        with (
            open_regular_file(source, max_bytes=2 * 1024 * 1024 * 1024) as input_file,
            destination.open("xb") as output_file,
        ):
            while chunk := input_file.read(1024 * 1024):
                output_file.write(chunk)
        if _hash_regular_file(destination) != expected:
            raise SecurityError("local target file changed while it was staged")
        staged[index] = os.fspath(destination)
    return tuple(staged)


def target_configuration_digest(target: LocalTarget | ContainerTarget) -> str:
    """Hash the executable/image plus every setting that changes target behavior."""

    if isinstance(target, LocalTarget):
        digest, _command = _local_target_digest(target)
        return digest
    if _IMAGE_DIGEST.fullmatch(target.image) is None:
        raise SecurityError("container image must be pinned by sha256 digest")
    if (
        not target.command
        or len(target.command) > 128
        or any(
            not argument or "\x00" in argument or len(argument) > 32_768
            for argument in target.command
        )
    ):
        raise SecurityError("container target command is invalid")
    if target.input_mode not in {"stdin", "file"}:
        raise SecurityError("unknown container target input mode")
    _output_path(Path.cwd().absolute(), target.output_file)
    payload = json.dumps(
        {
            "command": target.command,
            "image": target.image,
            "input_mode": target.input_mode,
            "output_file": target.output_file,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _read_bounded_output(
    path: Path | None,
    *,
    root: Path,
    max_bytes: int = 2 * 1024 * 1024,
) -> bytes | None:
    if path is None or not path.exists():
        return None
    root = root.absolute()
    path = path.absolute()
    if not path.is_relative_to(root):
        raise SecurityError("target output path escaped its workspace")
    current = path.parent
    while current != root:
        if current.is_symlink():
            raise SecurityError("target output path contains a symbolic link")
        current = current.parent
    resolved_root = root.resolve(strict=True)
    if not path.resolve(strict=True).is_relative_to(resolved_root):
        raise SecurityError("target output path escaped its workspace")
    with open_regular_file(path, max_bytes=max_bytes) as source:
        data = source.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise SecurityError("target output exceeds the size limit")
    return data


def run_local_target(
    target: LocalTarget,
    invoice_xml: bytes,
    *,
    workspace: Path,
    policy: ProcessPolicy,
) -> TargetResult:
    parse_xml_bytes(invoice_xml)
    workspace = _prepare_workspace(workspace)
    output_path = _output_path(workspace, target.output_file)
    digest, command = _local_target_digest(target)
    command = _stage_local_command(command, workspace=workspace)
    if target.input_mode == "file":
        input_path = workspace / "input.xml"
        with input_path.open("xb") as output:
            output.write(invoice_xml)
        command = (*command, input_path.name)
        input_bytes = b""
    elif target.input_mode == "stdin":
        input_bytes = invoice_xml
    else:
        raise SecurityError("unknown local target input mode")
    result = run_bounded_process(
        command,
        cwd=workspace,
        policy=policy,
        input_bytes=input_bytes,
    )
    return TargetResult(
        process=result,
        output_xml=_read_bounded_output(output_path, root=workspace),
        target_digest=digest,
    )


def build_docker_command(
    target: ContainerTarget,
    *,
    workspace: Path,
    policy: ProcessPolicy,
) -> tuple[str, ...]:
    if _IMAGE_DIGEST.fullmatch(target.image) is None:
        raise SecurityError("container image must be pinned by sha256 digest")
    if not target.command:
        raise SecurityError("container target command is empty")
    if "," in os.fspath(workspace.absolute()):
        raise SecurityError("container workspace path cannot contain a comma")
    _output_path(workspace.absolute(), target.output_file)
    memory = str(policy.max_memory_bytes)
    ownership = hashlib.sha256(os.fspath(workspace.absolute()).encode("utf-8")).hexdigest()
    cidfile = workspace.absolute() / ".container.cid"
    command: list[str] = [
        "docker",
        "run",
        "--rm",
        f"--cidfile={cidfile}",
        f"--label=rechnungsprobe.run={ownership}",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--pids-limit={policy.max_processes}",
        f"--memory={memory}",
        f"--memory-swap={memory}",
        "--cpus=1.0",
        "--user=65532:65532",
        "--ulimit=nofile=64:64",
        f"--ulimit=nproc={policy.max_processes}:{policy.max_processes}",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=67108864",
    ]
    if target.input_mode == "stdin":
        command.append("-i")
    elif target.input_mode == "file":
        input_path = workspace.absolute() / "input.xml"
        command.extend(
            (
                "--mount",
                f"type=bind,src={input_path},dst=/input/invoice.xml,readonly",
            )
        )
    else:
        raise SecurityError("unknown container target input mode")
    if target.output_file is not None:
        portable_output = PurePosixPath(target.output_file.replace("\\", "/"))
        if len(portable_output.parts) != 1:
            raise SecurityError("container output must be one declared file")
        output_path = _output_path(workspace.absolute() / "output", target.output_file)
        if output_path is None:
            raise RuntimeError("container output path was not created")
        command.extend(
            (
                "--mount",
                f"type=bind,src={output_path},dst=/output/{portable_output.name}",
            )
        )
    command.extend((target.image, *target.command))
    return tuple(command)


def _cleanup_container(workspace: Path, policy: ProcessPolicy) -> None:
    cidfile = workspace / ".container.cid"
    identifiers: list[str] = []
    if cidfile.exists():
        with open_regular_file(cidfile, max_bytes=256) as source:
            identifier = source.read(257).decode("ascii", errors="strict").strip()
        if re.fullmatch(r"[0-9a-f]{12,64}", identifier) is None:
            raise SecurityError("Docker cidfile contains an invalid container identifier")
        identifiers.append(identifier)
    else:
        ownership = hashlib.sha256(os.fspath(workspace.absolute()).encode("utf-8")).hexdigest()
        listed = run_bounded_process(
            ("docker", "ps", "-aq", "--filter", f"label=rechnungsprobe.run={ownership}"),
            cwd=workspace,
            policy=ProcessPolicy(
                timeout_seconds=min(10, policy.timeout_seconds),
                cpu_seconds=min(5, policy.cpu_seconds),
                max_memory_bytes=256 * 1024 * 1024,
                max_processes=4,
                max_output_bytes=16 * 1024,
                max_file_growth_bytes=1024 * 1024,
                max_created_files=8,
            ),
        )
        if listed.termination == "exited" and listed.returncode == 0:
            identifiers.extend(
                identifier
                for identifier in listed.stdout.decode("ascii", errors="strict").splitlines()
                if re.fullmatch(r"[0-9a-f]{12,64}", identifier)
            )
    cleanup_policy = ProcessPolicy(
        timeout_seconds=min(10, policy.timeout_seconds),
        cpu_seconds=min(5, policy.cpu_seconds),
        max_memory_bytes=256 * 1024 * 1024,
        max_processes=4,
        max_output_bytes=16 * 1024,
        max_file_growth_bytes=1024 * 1024,
        max_created_files=8,
    )
    for identifier in tuple(dict.fromkeys(identifiers))[:8]:
        run_bounded_process(
            ("docker", "kill", identifier),
            cwd=workspace,
            policy=cleanup_policy,
        )
        run_bounded_process(
            ("docker", "rm", "-f", identifier),
            cwd=workspace,
            policy=cleanup_policy,
        )
        inspected = run_bounded_process(
            ("docker", "inspect", identifier),
            cwd=workspace,
            policy=cleanup_policy,
        )
        if inspected.termination != "exited" or inspected.returncode in {None, 0}:
            raise SecurityError("Docker container cleanup could not be verified")


def run_container_target(
    target: ContainerTarget,
    invoice_xml: bytes,
    *,
    workspace: Path,
    policy: ProcessPolicy,
) -> TargetResult:
    parse_xml_bytes(invoice_xml)
    workspace = _prepare_workspace(workspace)
    if target.input_mode == "file":
        with (workspace / "input.xml").open("xb") as output:
            output.write(invoice_xml)
        input_bytes = b""
    else:
        input_bytes = invoice_xml
    output_path = None
    if target.output_file is not None:
        output_directory = workspace / "output"
        output_directory.mkdir()
        output_path = _output_path(output_directory, target.output_file)
        if output_path is None:
            raise RuntimeError("container output path was not created")
        with output_path.open("xb"):
            pass
        if os.name != "nt":
            output_path.chmod(0o666)
    command = build_docker_command(target, workspace=workspace, policy=policy)
    try:
        process = run_bounded_process(
            command,
            cwd=workspace,
            policy=policy,
            input_bytes=input_bytes,
        )
    finally:
        _cleanup_container(workspace, policy)
    return TargetResult(
        process=process,
        output_xml=_read_bounded_output(
            output_path,
            root=workspace / "output",
        ),
        target_digest=target_configuration_digest(target),
    )
