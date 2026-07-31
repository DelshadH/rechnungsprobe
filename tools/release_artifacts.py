from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_member(name: str) -> PurePosixPath:
    if "\\" in name or not name or name.startswith("/"):
        raise ValueError(f"unsafe archive member: {name!r}")
    path = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"unsafe archive member: {name!r}")
    return path


def _wheel_inventory(path: Path) -> tuple[list[dict[str, object]], dict[str, bytes]]:
    entries: list[dict[str, object]] = []
    contents: dict[str, bytes] = {}
    with zipfile.ZipFile(path) as archive:
        names = [entry.filename for entry in archive.infolist()]
        if len(names) != len(set(names)):
            raise ValueError("wheel contains duplicate members")
        for entry in archive.infolist():
            member = _safe_member(entry.filename)
            mode = entry.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            if entry.is_dir() or (file_type and file_type != stat.S_IFREG):
                raise ValueError(f"wheel member is not a regular file: {entry.filename}")
            if not (
                member.parts[0] == "rechnungsprobe"
                or member.parts[0].startswith("rechnungsprobe-")
            ):
                raise ValueError(f"wheel contains an unexpected top-level path: {entry.filename}")
            data = archive.read(entry)
            contents[entry.filename] = data
            entries.append(
                {
                    "name": entry.filename,
                    "sha256": _sha256(data),
                    "size": len(data),
                }
            )
    return sorted(entries, key=lambda item: str(item["name"])), contents


_SDIST_ROOTS = {
    ".github",
    ".gitignore",
    ".secrets.baseline",
    "AGENTS.md",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "PKG-INFO",
    "README.md",
    "SECURITY.md",
    "SUPPORT.md",
    "docs",
    "pyproject.toml",
    "requirements",
    "research",
    "schemas",
    "src",
    "tests",
    "third_party",
    "tools",
}


def _sdist_inventory(path: Path) -> tuple[list[dict[str, object]], dict[str, bytes]]:
    entries: list[dict[str, object]] = []
    contents: dict[str, bytes] = {}
    with tarfile.open(path, mode="r:gz") as archive:
        names = [entry.name for entry in archive.getmembers()]
        if len(names) != len(set(names)):
            raise ValueError("sdist contains duplicate members")
        roots = {PurePosixPath(name).parts[0] for name in names if name}
        if len(roots) != 1:
            raise ValueError("sdist must contain exactly one root directory")
        for entry in archive.getmembers():
            member = _safe_member(entry.name)
            if entry.isdir():
                continue
            if not entry.isfile() or len(member.parts) < 2:
                raise ValueError(f"sdist member is not a regular rooted file: {entry.name}")
            relative = PurePosixPath(*member.parts[1:])
            if relative.parts[0] not in _SDIST_ROOTS:
                raise ValueError(f"sdist contains an unexpected top-level path: {relative}")
            source = archive.extractfile(entry)
            if source is None:
                raise ValueError(f"sdist member cannot be read: {entry.name}")
            data = source.read()
            contents[str(relative)] = data
            entries.append(
                {
                    "mode": entry.mode,
                    "name": str(relative),
                    "sha256": _sha256(data),
                    "size": len(data),
                }
            )
    return sorted(entries, key=lambda item: str(item["name"])), contents


def _require(contents: dict[str, bytes], required: set[str], archive: str) -> None:
    missing = sorted(required - set(contents))
    if missing:
        raise ValueError(f"{archive} lacks required members: {', '.join(missing)}")


def inventory(dist: Path, output: Path) -> None:
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError("distribution directory must contain one wheel and one sdist")
    wheel_entries, wheel_contents = _wheel_inventory(wheels[0])
    sdist_entries, sdist_contents = _sdist_inventory(sdists[0])
    profile = json.loads(Path("src/rechnungsprobe/data/profile.json").read_bytes())
    validator = profile["validator"]
    configuration = profile["configuration"]
    seed = profile["seed"]
    wheel_required = {
        "rechnungsprobe/__init__.py",
        f"rechnungsprobe/data/artifacts/{validator['filename']}",
        f"rechnungsprobe/data/artifacts/{configuration['filename']}",
        f"rechnungsprobe/data/seeds/{seed['filename']}",
        "rechnungsprobe/schemas/finding-v1.schema.json",
        "rechnungsprobe/third_party/kosit-validator-LICENSE",
    }
    sdist_required = {
        ".secrets.baseline",
        "requirements/ci.txt",
        "requirements/runtime.txt",
        "research/evidence/corpus-gate.json",
        "schemas/finding-v1.schema.json",
        "tools/release_artifacts.py",
    }
    _require(wheel_contents, wheel_required, "wheel")
    _require(sdist_contents, sdist_required, "sdist")
    expected_hashes = {
        f"rechnungsprobe/data/artifacts/{validator['filename']}": validator["sha256"],
        f"rechnungsprobe/data/artifacts/{configuration['filename']}": configuration["sha256"],
        f"rechnungsprobe/data/seeds/{seed['filename']}": seed["sha256"],
    }
    for name, expected in expected_hashes.items():
        if not hmac.compare_digest(_sha256(wheel_contents[name]), expected):
            raise ValueError(f"bundled artifact hash mismatch: {name}")
    payload = {
        "archives": [
            {
                "members": wheel_entries,
                "name": wheels[0].name,
                "sha256": _sha256(wheels[0].read_bytes()),
            },
            {
                "members": sdist_entries,
                "name": sdists[0].name,
                "sha256": _sha256(sdists[0].read_bytes()),
            },
        ],
        "schema": "https://rechnungsprobe.dev/schemas/package-inventory-v1",
    }
    output.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def augment_sbom(path: Path) -> None:
    document: dict[str, Any] = json.loads(path.read_bytes())
    profile = json.loads(Path("src/rechnungsprobe/data/profile.json").read_bytes())
    components = document.setdefault("components", [])
    if not isinstance(components, list):
        raise TypeError("SBOM components must be an array")
    specifications = (
        ("validator", "application", "KoSIT Validator"),
        ("configuration", "data", "XRechnung validator configuration"),
        ("seed", "data", "XRechnung testsuite seed"),
    )
    additions = []
    for key, component_type, name in specifications:
        item = profile[key]
        additions.append(
            {
                "bom-ref": f"rechnungsprobe-bundled:{key}:{item['sha256']}",
                "externalReferences": [
                    {"type": "distribution", "url": item.get("url", item.get("source"))}
                ],
                "hashes": [{"alg": "SHA-256", "content": item["sha256"]}],
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "name": name,
                "properties": [
                    {"name": "rechnungsprobe:bundled-filename", "value": item["filename"]},
                    {"name": "rechnungsprobe:license-notice", "value": item["license"]},
                ],
                "type": component_type,
                "version": item.get("version", profile.get("xrechnung", "unknown")),
            }
        )
    refs = {component.get("bom-ref") for component in components if isinstance(component, dict)}
    components.extend(component for component in additions if component["bom-ref"] not in refs)
    components.sort(key=lambda component: str(component.get("bom-ref", "")))
    path.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def validate_sbom(path: Path) -> None:
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    errors = JsonStrictValidator(SchemaVersion.V1_6).validate_str(
        path.read_text(encoding="utf-8"),
        all_errors=True,
    )
    if errors is not None:
        messages = tuple(str(error) for error in errors)
        raise ValueError("invalid CycloneDX SBOM: " + "; ".join(messages[:10]))


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    inventory_parser = subparsers.add_parser("inventory")
    inventory_parser.add_argument("dist", type=Path)
    inventory_parser.add_argument("output", type=Path)
    sbom_parser = subparsers.add_parser("augment-sbom")
    sbom_parser.add_argument("path", type=Path)
    validate_parser = subparsers.add_parser("validate-sbom")
    validate_parser.add_argument("path", type=Path)
    arguments = parser.parse_args()
    if arguments.command == "inventory":
        inventory(arguments.dist, arguments.output)
    elif arguments.command == "augment-sbom":
        augment_sbom(arguments.path)
    else:
        validate_sbom(arguments.path)


if __name__ == "__main__":
    main()
