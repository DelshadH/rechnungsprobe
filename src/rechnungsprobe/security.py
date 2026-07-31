from __future__ import annotations

import os
import re
import stat
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import BinaryIO


class SecurityError(ValueError):
    """Raised when hostile or over-limit input is rejected."""


_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


@contextmanager
def open_regular_file(path: Path, *, max_bytes: int) -> Iterator[BinaryIO]:
    """Open one bounded regular file without following a final-component link."""

    before = path.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size > max_bytes
    ):
        raise SecurityError("file must be a bounded regular non-link file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_size > max_bytes
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
        ):
            raise SecurityError("file changed while it was being opened")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            yield source
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _safe_member_parts(name: str) -> tuple[str, ...]:
    portable_name = name.replace("\\", "/")
    if (
        not portable_name
        or portable_name.startswith("/")
        or _DRIVE_PREFIX.match(portable_name)
        or "\x00" in portable_name
    ):
        raise SecurityError(f"unsafe archive path: {name!r}")
    path = PurePosixPath(portable_name)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise SecurityError(f"unsafe archive path: {name!r}")
    return path.parts


def _entry_kind(entry: zipfile.ZipInfo) -> str:
    unix_mode = entry.external_attr >> 16 if entry.create_system == 3 else 0
    file_type = stat.S_IFMT(unix_mode)
    if file_type == stat.S_IFLNK:
        raise SecurityError(f"archive link is not allowed: {entry.filename!r}")
    if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise SecurityError(f"special archive entry is not allowed: {entry.filename!r}")
    return "directory" if file_type == stat.S_IFDIR or entry.is_dir() else "file"


def safe_extract_zip(
    archive_path: Path,
    destination: Path,
    *,
    max_members: int = 512,
    max_member_bytes: int = 16 * 1024 * 1024,
    max_total_bytes: int = 64 * 1024 * 1024,
    max_compression_ratio: float = 100.0,
) -> tuple[Path, ...]:
    """Extract a bounded ZIP without links, traversal, duplicates, or bombs."""

    archive_path = archive_path.resolve(strict=True)
    destination = destination.absolute()
    if destination.exists() and (destination.is_symlink() or not destination.is_dir()):
        raise SecurityError("archive destination must be a real directory")
    if destination.exists() and any(destination.iterdir()):
        raise SecurityError("archive destination must be empty")
    destination_parent = destination.parent.resolve(strict=True)
    if destination_parent.is_symlink() or not destination_parent.is_dir():
        raise SecurityError("archive destination parent must be a real directory")
    destination = destination_parent / destination.name

    validated: list[tuple[zipfile.ZipInfo, tuple[str, ...], str]] = []
    seen: set[str] = set()
    total_bytes = 0
    with zipfile.ZipFile(archive_path, "r") as archive:
        entries = archive.infolist()
        if len(entries) > max_members:
            raise SecurityError("archive has too many members")
        for entry in entries:
            parts = _safe_member_parts(entry.filename)
            normalized = "/".join(parts).casefold()
            if normalized in seen:
                raise SecurityError(f"duplicate archive member: {entry.filename!r}")
            seen.add(normalized)
            kind = _entry_kind(entry)
            if entry.flag_bits & 0x1:
                raise SecurityError("encrypted archive members are not allowed")
            if entry.file_size > max_member_bytes:
                raise SecurityError("archive member exceeds the size limit")
            total_bytes += entry.file_size
            if total_bytes > max_total_bytes:
                raise SecurityError("archive exceeds the total size limit")
            if entry.file_size and (
                entry.compress_size == 0
                or entry.file_size / entry.compress_size > max_compression_ratio
            ):
                raise SecurityError("archive member has a suspicious compression ratio")
            validated.append((entry, parts, kind))

        created_directories: list[Path] = []
        if not destination.exists():
            destination.mkdir()
            created_directories.append(destination)
        extracted: list[Path] = []
        created_files: list[Path] = []

        def ensure_directory(path: Path) -> None:
            missing: list[Path] = []
            current = path
            while current != destination and not current.exists():
                missing.append(current)
                current = current.parent
            if current.is_symlink() or not current.is_dir():
                raise SecurityError("archive extraction encountered an unsafe parent")
            for directory in reversed(missing):
                directory.mkdir()
                created_directories.append(directory)

        try:
            for entry, parts, kind in validated:
                target = destination.joinpath(*parts)
                if not target.is_relative_to(destination):
                    raise SecurityError(f"unsafe archive path: {entry.filename!r}")
                if kind == "directory":
                    ensure_directory(target)
                    continue
                ensure_directory(target.parent)
                if any(parent.is_symlink() for parent in (target, *target.parents)):
                    raise SecurityError("archive extraction encountered a symbolic link")
                written = 0
                with archive.open(entry, "r") as source, target.open("xb") as output:
                    created_files.append(target)
                    while chunk := source.read(64 * 1024):
                        written += len(chunk)
                        if written > entry.file_size or written > max_member_bytes:
                            raise SecurityError("archive member expanded beyond its declared size")
                        output.write(chunk)
                if written != entry.file_size:
                    raise SecurityError("archive member size did not match its declaration")
                extracted.append(target)
        except Exception:
            for path in reversed(created_files):
                path.unlink(missing_ok=True)
            for path in reversed(created_directories):
                try:
                    path.rmdir()
                except OSError:
                    pass
            raise
    return tuple(sorted(extracted, key=lambda path: os.fspath(path.relative_to(destination))))
