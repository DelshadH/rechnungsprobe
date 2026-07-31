from __future__ import annotations

import os
import signal
import stat

# This bounded argument-vector runner requires subprocess; shell use is disabled.
import subprocess  # nosec B404
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import psutil

from rechnungsprobe.security import SecurityError

Termination = Literal[
    "exited",
    "timeout",
    "output_limit",
    "memory_limit",
    "cpu_limit",
    "process_limit",
    "file_limit",
]


@dataclass(frozen=True, slots=True)
class ProcessPolicy:
    timeout_seconds: float = 10.0
    cpu_seconds: float = 8.0
    max_memory_bytes: int = 512 * 1024 * 1024
    max_processes: int = 8
    max_output_bytes: int = 1024 * 1024
    max_input_bytes: int = 2 * 1024 * 1024
    max_file_growth_bytes: int = 16 * 1024 * 1024
    max_created_files: int = 256
    poll_interval_seconds: float = 0.01


@dataclass(frozen=True, slots=True)
class ProcessResult:
    termination: Termination
    returncode: int | None
    stdout: bytes
    stderr: bytes


_INHERITED_ENVIRONMENT = (
    "COMSPEC",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
)


def _clean_environment(
    extra: Mapping[str, str] | None,
    *,
    temporary_directory: Path,
) -> dict[str, str]:
    environment = {key: value for key in _INHERITED_ENVIRONMENT if (value := os.environ.get(key))}
    if os.name != "nt":
        environment.update({"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
    for key, value in (extra or {}).items():
        if not key or "=" in key or "\x00" in key or "\x00" in value:
            raise SecurityError("invalid process environment")
        environment[key] = value
    temporary = os.fspath(temporary_directory)
    environment.update({"TEMP": temporary, "TMP": temporary, "TMPDIR": temporary})
    return environment


def _validated_command(command: Sequence[str]) -> tuple[str, ...]:
    if isinstance(command, (str, bytes)):
        raise SecurityError("process command must be an argument vector, not a shell string")
    arguments = tuple(command)
    if not arguments or len(arguments) > 128:
        raise SecurityError("process argument vector has an invalid length")
    if any(
        not isinstance(argument, str)
        or not argument
        or "\x00" in argument
        or len(argument) > 32_768
        for argument in arguments
    ):
        raise SecurityError("process argument vector contains an invalid argument")
    return arguments


def _kill_process_tree(process: subprocess.Popen[bytes]) -> None:
    try:
        root = psutil.Process(process.pid)
        children = root.children(recursive=True)
    except psutil.Error:
        children = []
        root = None
    for child in reversed(children):
        try:
            child.kill()
        except psutil.Error:
            pass
    if root is not None:
        try:
            root.kill()
        except psutil.Error:
            pass
    try:
        process.kill()
    except OSError:
        pass
    psutil.wait_procs(children, timeout=1)


class _ProcessContainment:
    def __init__(self, process: subprocess.Popen[bytes], max_processes: int) -> None:
        self._job: int | None = None
        self._process_group = process.pid
        if os.name != "nt":
            return

        import ctypes
        from ctypes import wintypes

        class IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class BasicLimitInformation(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class ExtendedLimitInformation(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimitInformation),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        kernel32.SetInformationJobObject.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        )
        kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            _kill_process_tree(process)
            raise SecurityError("could not create a Windows process containment job")
        information = ExtendedLimitInformation()
        information.BasicLimitInformation.LimitFlags = 0x2000 | 0x00000008
        information.BasicLimitInformation.ActiveProcessLimit = max_processes
        if not kernel32.SetInformationJobObject(
            job,
            9,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ) or not kernel32.AssignProcessToJobObject(
            job,
            process._handle,  # type: ignore[attr-defined]
        ):
            kernel32.CloseHandle(job)
            _kill_process_tree(process)
            raise SecurityError("could not assign the process containment job")
        self._job = int(job)

    def close(self) -> None:
        if os.name == "nt":
            if self._job is None:
                return
            import ctypes
            from ctypes import wintypes

            class BasicAccountingInformation(ctypes.Structure):
                _fields_ = [
                    ("TotalUserTime", ctypes.c_longlong),
                    ("TotalKernelTime", ctypes.c_longlong),
                    ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                    ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                    ("TotalPageFaultCount", wintypes.DWORD),
                    ("TotalProcesses", wintypes.DWORD),
                    ("ActiveProcesses", wintypes.DWORD),
                    ("TotalTerminatedProcesses", wintypes.DWORD),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
            kernel32.QueryInformationJobObject.argtypes = (
                wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.c_void_p,
            )
            kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
            kernel32.TerminateJobObject(self._job, 1)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                accounting = BasicAccountingInformation()
                if not kernel32.QueryInformationJobObject(
                    self._job,
                    1,
                    ctypes.byref(accounting),
                    ctypes.sizeof(accounting),
                    None,
                ) or accounting.ActiveProcesses == 0:
                    break
                time.sleep(0.01)
            kernel32.CloseHandle(self._job)
            self._job = None
            return
        kill_process_group = getattr(os, "killpg", None)
        if kill_process_group is not None:
            try:
                kill_process_group(self._process_group, getattr(signal, "SIGKILL", 9))
            except ProcessLookupError:
                pass


def _resource_termination(root: psutil.Process, policy: ProcessPolicy) -> Termination | None:
    try:
        processes = [root, *root.children(recursive=True)]
    except psutil.Error:
        return None
    if len(processes) > policy.max_processes:
        return "process_limit"
    memory = 0
    cpu = 0.0
    for process in processes:
        try:
            memory += process.memory_info().rss
            times = process.cpu_times()
            cpu += times.user + times.system
        except psutil.Error:
            continue
    if memory > policy.max_memory_bytes:
        return "memory_limit"
    if cpu > policy.cpu_seconds:
        return "cpu_limit"
    return None


def _directory_usage(root: Path, scan_limit: int) -> tuple[int, int, bool]:
    total_bytes = 0
    entry_count = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = tuple(os.scandir(directory))
        except OSError:
            return total_bytes, entry_count, True
        for entry in entries:
            entry_count += 1
            if entry_count > scan_limit:
                return total_bytes, entry_count, True
            try:
                metadata = entry.stat(follow_symlinks=False)
                if entry.is_symlink() or (
                    os.name == "nt"
                    and metadata.st_file_attributes
                    & stat.FILE_ATTRIBUTE_REPARSE_POINT
                ):
                    return total_bytes, entry_count, True
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    total_bytes += metadata.st_size
            except OSError:
                return total_bytes, entry_count, True
    return total_bytes, entry_count, False


def run_bounded_process(
    command: Sequence[str],
    *,
    cwd: Path,
    policy: ProcessPolicy,
    input_bytes: bytes = b"",
    environment: Mapping[str, str] | None = None,
) -> ProcessResult:
    """Run an argument vector with bounded input, output, time, memory, and children."""

    arguments = _validated_command(command)
    if len(input_bytes) > policy.max_input_bytes:
        raise SecurityError("process input exceeds the size limit")
    metadata = cwd.lstat()
    if cwd.is_symlink() or not cwd.is_dir():
        raise SecurityError("process working directory must be a real directory")
    if metadata.st_nlink < 1:
        raise SecurityError("process working directory is unavailable")
    if (
        policy.timeout_seconds <= 0
        or policy.cpu_seconds <= 0
        or policy.max_memory_bytes <= 0
        or policy.max_processes <= 0
        or policy.max_output_bytes < 0
        or policy.max_file_growth_bytes < 0
        or policy.max_created_files < 0
        or policy.poll_interval_seconds <= 0
    ):
        raise SecurityError("invalid process resource policy")

    baseline_bytes, baseline_files, baseline_scan_failed = _directory_usage(cwd, 100_000)
    if baseline_scan_failed:
        raise SecurityError("process workspace cannot be inspected safely")
    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    # Arguments were validated above and the shell remains disabled.
    process = subprocess.Popen(  # nosec B603
        arguments,
        cwd=cwd,
        env=_clean_environment(environment, temporary_directory=cwd),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        close_fds=True,
        creationflags=creationflags,
        start_new_session=os.name != "nt",
    )
    containment = _ProcessContainment(process, policy.max_processes)
    started = time.monotonic()
    stdin = process.stdin
    stdout_stream = process.stdout
    stderr_stream = process.stderr
    if stdin is None or stdout_stream is None or stderr_stream is None:
        _kill_process_tree(process)
        raise RuntimeError("subprocess pipes were not created")

    stdout = bytearray()
    stderr = bytearray()
    output_lock = threading.Lock()
    output_limit_reached = threading.Event()
    total_output = 0

    def read_stream(stream: object, destination: bytearray) -> None:
        nonlocal total_output
        reader = stream
        while True:
            chunk = reader.read1(64 * 1024)  # type: ignore[attr-defined]
            if not chunk:
                return
            with output_lock:
                remaining = max(0, policy.max_output_bytes - total_output)
                accepted = chunk[:remaining]
                destination.extend(accepted)
                total_output += len(accepted)
                if len(accepted) != len(chunk):
                    output_limit_reached.set()
                    return

    stdout_thread = threading.Thread(
        target=read_stream,
        args=(stdout_stream, stdout),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=read_stream,
        args=(stderr_stream, stderr),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    def write_stdin() -> None:
        try:
            stdin.write(input_bytes)
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                stdin.close()
            except OSError:
                pass

    stdin_thread = threading.Thread(target=write_stdin, daemon=True)
    stdin_thread.start()

    termination: Termination = "exited"
    try:
        monitored: psutil.Process | None = psutil.Process(process.pid)
    except psutil.NoSuchProcess:
        monitored = None
    while process.poll() is None:
        if output_limit_reached.is_set():
            termination = "output_limit"
            break
        if time.monotonic() - started > policy.timeout_seconds:
            termination = "timeout"
            break
        resource_termination = (
            _resource_termination(monitored, policy) if monitored is not None else None
        )
        if resource_termination is not None:
            termination = resource_termination
            break
        current_bytes, current_files, scan_overflow = _directory_usage(
            cwd,
            baseline_files + policy.max_created_files + 1,
        )
        if (
            scan_overflow
            or current_files - baseline_files > policy.max_created_files
            or current_bytes - baseline_bytes > policy.max_file_growth_bytes
        ):
            termination = "file_limit"
            break
        time.sleep(policy.poll_interval_seconds)

    if termination != "exited":
        _kill_process_tree(process)
    try:
        returncode = process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        _kill_process_tree(process)
        returncode = process.wait(timeout=2)
    containment.close()
    stdout_thread.join(timeout=2)
    stderr_thread.join(timeout=2)
    stdin_thread.join(timeout=2)
    stdout_stream.close()
    stderr_stream.close()
    if termination == "exited" and output_limit_reached.is_set():
        termination = "output_limit"
    if termination == "exited":
        current_bytes, current_files, scan_overflow = _directory_usage(
            cwd,
            baseline_files + policy.max_created_files + 1,
        )
        if (
            scan_overflow
            or current_files - baseline_files > policy.max_created_files
            or current_bytes - baseline_bytes > policy.max_file_growth_bytes
        ):
            termination = "file_limit"
    return ProcessResult(
        termination=termination,
        returncode=returncode,
        stdout=bytes(stdout),
        stderr=bytes(stderr),
    )
