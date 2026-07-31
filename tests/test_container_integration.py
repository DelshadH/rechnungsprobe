from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from rechnungsprobe.process import ProcessPolicy
from rechnungsprobe.target import ContainerTarget, run_container_target

ALPINE_IMAGE = (
    "alpine@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce"
)

pytestmark = pytest.mark.skipif(
    os.environ.get("RECHNUNGSPROBE_DOCKER_TESTS") != "1" or shutil.which("docker") is None,
    reason="set RECHNUNGSPROBE_DOCKER_TESTS=1 with Docker available",
)


def test_live_container_has_no_network_and_a_read_only_root(tmp_path: Path) -> None:
    result = run_container_target(
        ContainerTarget(
            image=ALPINE_IMAGE,
            command=(
                "sh",
                "-c",
                "test ! -e /host-marker && ! touch /blocked && ! wget -T 2 -qO- http://1.1.1.1",
            ),
            input_mode="stdin",
        ),
        b"<Invoice/>",
        workspace=tmp_path / "network-and-root",
        policy=ProcessPolicy(timeout_seconds=8),
    )

    assert result.process.termination == "exited"
    assert result.process.returncode == 0


def test_live_container_input_mount_is_read_only(tmp_path: Path) -> None:
    invoice = b"<Invoice/>"
    result = run_container_target(
        ContainerTarget(
            image=ALPINE_IMAGE,
            command=(
                "sh",
                "-c",
                "cat /input/invoice.xml && ! printf x >> /input/invoice.xml",
            ),
            input_mode="file",
        ),
        invoice,
        workspace=tmp_path / "read-only-input",
        policy=ProcessPolicy(timeout_seconds=8),
    )

    assert result.process.termination == "exited"
    assert result.process.returncode == 0
    assert result.process.stdout == invoice


def test_live_container_is_removed_after_client_timeout(tmp_path: Path) -> None:
    workspace = tmp_path / "timeout"
    result = run_container_target(
        ContainerTarget(
            image=ALPINE_IMAGE,
            command=("sh", "-c", "sleep 30"),
            input_mode="stdin",
        ),
        b"<Invoice/>",
        workspace=workspace,
        policy=ProcessPolicy(timeout_seconds=0.5, poll_interval_seconds=0.01),
    )

    ownership = hashlib.sha256(os.fspath(workspace.absolute()).encode()).hexdigest()
    remaining = subprocess.run(
        (
            "docker",
            "ps",
            "-aq",
            "--filter",
            f"label=rechnungsprobe.run={ownership}",
        ),
        check=True,
        capture_output=True,
        timeout=10,
    )

    assert result.process.termination == "timeout"
    assert remaining.stdout.strip() == b""
