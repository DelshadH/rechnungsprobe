from __future__ import annotations

import stat
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from rechnungsprobe.security import SecurityError, safe_extract_zip


def _write_zip(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            archive.writestr(name, data)


@pytest.mark.parametrize(
    "member",
    [
        "../escape.txt",
        "safe/../../escape.txt",
        "/absolute.txt",
        "C:/absolute.txt",
        r"C:\absolute.txt",
    ],
)
def test_safe_extract_rejects_traversal_and_absolute_paths(tmp_path: Path, member: str) -> None:
    archive = tmp_path / "hostile.zip"
    _write_zip(archive, [(member, b"no")])

    with pytest.raises(SecurityError, match="path"):
        safe_extract_zip(archive, tmp_path / "output")


def test_safe_extract_rejects_duplicate_members(tmp_path: Path) -> None:
    archive = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("same.txt", b"one")
        with pytest.warns(UserWarning, match="Duplicate name"):
            output.writestr("same.txt", b"two")

    with pytest.raises(SecurityError, match="duplicate"):
        safe_extract_zip(archive, tmp_path / "output")


def test_safe_extract_rejects_symbolic_links(tmp_path: Path) -> None:
    archive = tmp_path / "link.zip"
    link = zipfile.ZipInfo("link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr(link, "../outside")

    with pytest.raises(SecurityError, match="link"):
        safe_extract_zip(archive, tmp_path / "output")


def test_safe_extract_rejects_suspicious_compression_ratio(tmp_path: Path) -> None:
    archive = tmp_path / "bomb.zip"
    _write_zip(archive, [("zeros.bin", b"\0" * 200_000)])

    with pytest.raises(SecurityError, match="compression ratio"):
        safe_extract_zip(
            archive,
            tmp_path / "output",
            max_compression_ratio=10,
        )


def test_safe_extract_writes_only_regular_bounded_files(tmp_path: Path) -> None:
    archive = tmp_path / "safe.zip"
    _write_zip(archive, [("one/two.txt", b"ok"), ("empty/", b"")])
    output = tmp_path / "output"

    extracted = safe_extract_zip(archive, output)

    assert extracted == (output / "one" / "two.txt",)
    assert (output / "one" / "two.txt").read_bytes() == b"ok"


def test_failed_extract_preserves_caller_owned_destination(tmp_path: Path) -> None:
    archive_path = tmp_path / "corrupt.zip"
    _write_zip(
        archive_path,
        [("first.txt", b"first"), ("second.txt", b"second" * 100)],
    )
    with zipfile.ZipFile(archive_path) as archive:
        second = archive.getinfo("second.txt")
        with archive_path.open("r+b") as raw:
            raw.seek(second.header_offset)
            header = raw.read(30)
            filename_length, extra_length = struct.unpack_from("<HH", header, 26)
            payload_offset = second.header_offset + 30 + filename_length + extra_length
            raw.seek(payload_offset)
            original = raw.read(1)
            raw.seek(payload_offset)
            raw.write(bytes([original[0] ^ 0xFF]))

    destination = tmp_path / "caller-owned"
    destination.mkdir()
    with pytest.raises((SecurityError, zipfile.BadZipFile, EOFError, zlib.error)):
        safe_extract_zip(archive_path, destination)

    assert destination.is_dir()
    assert list(destination.iterdir()) == []
