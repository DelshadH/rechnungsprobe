from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from typing import cast

from rechnungsprobe.process import ProcessPolicy
from rechnungsprobe.profiles import Profile
from rechnungsprobe.security import SecurityError
from rechnungsprobe.target import TargetResult

_SHA256 = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class Observation:
    termination: str
    returncode: int | None
    stdout_sha256: str
    stderr_sha256: str
    output_sha256: str | None


@dataclass(frozen=True, slots=True)
class MinimizationProof:
    algorithm: str
    declared_operations: str
    attempts: int
    accepted_operations: tuple[str, ...]
    one_minimal: bool
    verification_attempts: int


@dataclass(frozen=True, slots=True)
class FindingProvenance:
    campaign_seed: int
    seed_sha256: str
    seed_fingerprint: str
    profile: dict[str, str]
    target_digest: str
    resource_policy: dict[str, int]
    observations: tuple[Observation, ...]
    minimization: MinimizationProof

    def __post_init__(self) -> None:
        hashes = (
            self.seed_sha256,
            self.seed_fingerprint,
            self.target_digest,
            self.profile.get("validator_sha256", ""),
            self.profile.get("configuration_sha256", ""),
        )
        if (
            not 0 <= self.campaign_seed < 2**63
            or any(_SHA256.fullmatch(value) is None for value in hashes)
            or set(self.profile)
            != {
                "configuration_sha256",
                "configuration_version",
                "identifier",
                "validator_sha256",
                "validator_version",
            }
            or not self.observations
            or any(
                _SHA256.fullmatch(observation.stdout_sha256) is None
                or _SHA256.fullmatch(observation.stderr_sha256) is None
                or (
                    observation.output_sha256 is not None
                    and _SHA256.fullmatch(observation.output_sha256) is None
                )
                for observation in self.observations
            )
            or self.minimization.algorithm != "greedy-1-minimal-v1"
            or self.minimization.declared_operations != "invoice-node-value-v1"
            or self.minimization.attempts < 1
            or self.minimization.verification_attempts < 1
        ):
            raise SecurityError("finding provenance is invalid or incomplete")


def observation_from_result(result: TargetResult) -> Observation:
    return Observation(
        termination=result.process.termination,
        returncode=result.process.returncode,
        stdout_sha256=hashlib.sha256(result.process.stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(result.process.stderr).hexdigest(),
        output_sha256=(
            hashlib.sha256(result.output_xml).hexdigest()
            if result.output_xml is not None
            else None
        ),
    )


def resource_policy_payload(policy: ProcessPolicy) -> dict[str, int]:
    return {
        "cpu_milliseconds": round(policy.cpu_seconds * 1000),
        "max_created_files": policy.max_created_files,
        "max_file_growth_bytes": policy.max_file_growth_bytes,
        "max_input_bytes": policy.max_input_bytes,
        "max_memory_bytes": policy.max_memory_bytes,
        "max_output_bytes": policy.max_output_bytes,
        "max_processes": policy.max_processes,
        "poll_interval_milliseconds": round(policy.poll_interval_seconds * 1000),
        "timeout_milliseconds": round(policy.timeout_seconds * 1000),
    }


def profile_payload(profile: Profile) -> dict[str, str]:
    return {
        "configuration_sha256": profile.configuration_sha256,
        "configuration_version": profile.configuration_version,
        "identifier": profile.identifier,
        "validator_sha256": profile.validator_sha256,
        "validator_version": profile.validator_version,
    }


def provenance_payload(provenance: FindingProvenance) -> dict[str, object]:
    payload = asdict(provenance)
    payload["observations"] = [asdict(observation) for observation in provenance.observations]
    minimization = cast(dict[str, object], payload["minimization"])
    minimization["accepted_operations"] = list(
        provenance.minimization.accepted_operations
    )
    return payload


def provenance_from_payload(payload: object) -> FindingProvenance:
    if not isinstance(payload, dict):
        raise SecurityError("finding provenance must be an object")
    expected = {
        "campaign_seed",
        "seed_sha256",
        "seed_fingerprint",
        "profile",
        "target_digest",
        "resource_policy",
        "observations",
        "minimization",
    }
    if set(payload) != expected:
        raise SecurityError("finding provenance has unexpected fields")
    observations = payload["observations"]
    minimization = payload["minimization"]
    profile = payload["profile"]
    resource_policy = payload["resource_policy"]
    if (
        type(payload["campaign_seed"]) is not int
        or not isinstance(payload["seed_sha256"], str)
        or not isinstance(payload["seed_fingerprint"], str)
        or not isinstance(payload["target_digest"], str)
        or not isinstance(profile, dict)
        or not all(isinstance(key, str) and isinstance(value, str) for key, value in profile.items())
        or not isinstance(resource_policy, dict)
        or not all(
            isinstance(key, str) and type(value) is int
            for key, value in resource_policy.items()
        )
        or not isinstance(observations, list)
        or not isinstance(minimization, dict)
    ):
        raise SecurityError("finding provenance has invalid JSON types")
    parsed_observations: list[Observation] = []
    observation_fields = {
        "termination",
        "returncode",
        "stdout_sha256",
        "stderr_sha256",
        "output_sha256",
    }
    for observation in observations:
        if (
            not isinstance(observation, dict)
            or set(observation) != observation_fields
            or not isinstance(observation["termination"], str)
            or (
                observation["returncode"] is not None
                and type(observation["returncode"]) is not int
            )
            or not isinstance(observation["stdout_sha256"], str)
            or not isinstance(observation["stderr_sha256"], str)
            or (
                observation["output_sha256"] is not None
                and not isinstance(observation["output_sha256"], str)
            )
        ):
            raise SecurityError("finding observation has invalid JSON types")
        parsed_observations.append(Observation(**observation))
    minimization_fields = {
        "algorithm",
        "declared_operations",
        "attempts",
        "accepted_operations",
        "one_minimal",
        "verification_attempts",
    }
    if (
        set(minimization) != minimization_fields
        or not isinstance(minimization["algorithm"], str)
        or not isinstance(minimization["declared_operations"], str)
        or type(minimization["attempts"]) is not int
        or not isinstance(minimization["accepted_operations"], list)
        or not all(
            isinstance(operation, str)
            for operation in minimization["accepted_operations"]
        )
        or type(minimization["one_minimal"]) is not bool
        or type(minimization["verification_attempts"]) is not int
    ):
        raise SecurityError("minimization proof has invalid JSON types")
    return FindingProvenance(
        campaign_seed=payload["campaign_seed"],
        seed_sha256=payload["seed_sha256"],
        seed_fingerprint=payload["seed_fingerprint"],
        profile=dict(profile),
        target_digest=payload["target_digest"],
        resource_policy=dict(resource_policy),
        observations=tuple(parsed_observations),
        minimization=MinimizationProof(
            algorithm=minimization["algorithm"],
            declared_operations=minimization["declared_operations"],
            attempts=minimization["attempts"],
            accepted_operations=tuple(minimization["accepted_operations"]),
            one_minimal=minimization["one_minimal"],
            verification_attempts=minimization["verification_attempts"],
        ),
    )
