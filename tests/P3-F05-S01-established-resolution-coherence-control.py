from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from core.authority import AuthorityState
from core.authority_resolution import (
    AuthorityResolution,
    AuthorityResolutionStatus,
)


TEST_ID = "P3-F05-S01"

EVIDENCE_DIR = (
    ROOT
    / "evidence"
    / "phase-iii"
    / "p3-f05-s01"
)

DEFINITION_PATH = (
    EVIDENCE_DIR
    / "P3-F05-S01-TEST-DEFINITION-001.json"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P3-F05-S01-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR
    / "P3-F05-S01-FIRST-OBSERVED-FREEZE-001.json"
)


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest().upper()


def write_json(
    path: Path,
    document: dict,
) -> None:
    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:
        json.dump(
            document,
            handle,
            indent=2,
            sort_keys=True,
        )
        handle.write("\n")


def write_sidecar(path: Path) -> None:
    sidecar = Path(
        str(path) + ".sha256"
    )

    sidecar.write_text(
        sha256_file(path)
        + "  "
        + path.name
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


definition = json.loads(
    DEFINITION_PATH.read_text(
        encoding="utf-8"
    )
)

authority_resolution_path = (
    ROOT
    / "core"
    / "authority_resolution.py"
)

expected_successor_hash = (
    definition[
        "successor_authority_resolution_sha256"
    ]
)

actual_successor_hash = (
    sha256_file(
        authority_resolution_path
    )
)

source_identity_preserved = (
    actual_successor_hash
    == expected_successor_hash
)


active_authority = (
    AuthorityState.create(
        actor_id=
            "P3-F05-S01-HUMAN-001",

        authority_source=
            "HUMAN_SOVEREIGN_AUTHORITY",

        permissions={
            "SEND"
        },

        epoch=1,
    )
)


revoked_observation = (
    active_authority.revoke_all(
        reason=(
            "P3-F05-S01_CONTRADICTORY_"
            "SAME_LINEAGE_REVOKED_OBSERVATION"
        )
    )
)


same_lineage = (
    active_authority.actor_id
    == revoked_observation.actor_id
    and
    active_authority.authority_source
    == revoked_observation.authority_source
)


material_state_conflict_present = (
    same_lineage
    and
    active_authority.epoch
    != revoked_observation.epoch
    and
    active_authority.status
    != revoked_observation.status
    and
    active_authority.permissions
    != revoked_observation.permissions
)


expected_exception_message = (
    "ESTABLISHED resolution observations "
    "must match executable authority"
)


incoherent_constructed = False
negative_exception_captured = False
negative_exception_type = ""
negative_exception_message = ""


try:

    AuthorityResolution(
        status=
            AuthorityResolutionStatus.ESTABLISHED,

        authority=
            active_authority,

        observations=(
            active_authority,
            revoked_observation,
        ),

        reason=(
            "P3-F05-S01_ATTEMPTED_"
            "INCOHERENT_ESTABLISHED_RESOLUTION"
        ),
    )

    incoherent_constructed = True

except Exception as exc:

    negative_exception_captured = True

    negative_exception_type = (
        type(exc).__name__
    )

    negative_exception_message = (
        str(exc)
    )


negative_control_passed = (
    not incoherent_constructed
    and
    negative_exception_captured
    and
    negative_exception_type
    == "ValueError"
    and
    negative_exception_message
    == expected_exception_message
)


helper_resolution = (
    AuthorityResolution.established(
        active_authority,
        reason=(
            "P3-F05-S01_HELPER_POSITIVE_CONTROL"
        ),
    )
)


helper_positive_passed = (
    helper_resolution.status
    == AuthorityResolutionStatus.ESTABLISHED
    and
    helper_resolution.authority
    == active_authority
    and
    helper_resolution.observations
    == (
        active_authority,
    )
)


duplicate_resolution = (
    AuthorityResolution(
        status=
            AuthorityResolutionStatus.ESTABLISHED,

        authority=
            active_authority,

        observations=(
            active_authority,
            active_authority,
        ),

        reason=(
            "P3-F05-S01_DUPLICATE_COHERENT_"
            "OBSERVATIONS_POSITIVE_CONTROL"
        ),
    )
)


duplicate_positive_passed = (
    duplicate_resolution.status
    == AuthorityResolutionStatus.ESTABLISHED
    and
    duplicate_resolution.authority
    == active_authority
    and
    len(
        duplicate_resolution.observations
    )
    == 2
    and
    all(
        observation
        == active_authority
        for observation
        in duplicate_resolution.observations
    )
)


successor_control_established = (
    source_identity_preserved
    and
    material_state_conflict_present
    and
    negative_control_passed
    and
    helper_positive_passed
    and
    duplicate_positive_passed
)


if successor_control_established:

    classification = (
        "INCOHERENT_ESTABLISHED_RESOLUTION_"
        "REJECTED__COHERENCE_CONTROL_ESTABLISHED"
    )

else:

    classification = (
        "P3-F05-S01_SUCCESSOR_CONTROL_"
        "NOT_ESTABLISHED"
    )


result_document = {
    "test_id":
        TEST_ID,

    "observed_at_utc":
        utc_now(),

    "classification":
        classification,

    "predecessor": {
        "test_id":
            "P3-F05",

        "failure_commit":
            "54c2319",

        "failure_classification":
            (
                "INCOHERENT_ESTABLISHED_RESOLUTION_"
                "EXECUTED__COHERENCE_CONTROL_NOT_ESTABLISHED"
            ),

        "retrospective_repair":
            False,
    },

    "source_identity": {
        "expected_successor_sha256":
            expected_successor_hash,

        "actual_successor_sha256":
            actual_successor_hash,

        "preserved":
            source_identity_preserved,
    },

    "negative_control": {
        "same_lineage":
            same_lineage,

        "material_state_conflict_present":
            material_state_conflict_present,

        "incoherent_constructed":
            incoherent_constructed,

        "exception_captured":
            negative_exception_captured,

        "exception_type":
            negative_exception_type,

        "exception_message":
            negative_exception_message,

        "passed":
            negative_control_passed,

        "active_authority": {
            "canonical_payload":
                active_authority.canonical_payload(),

            "state_hash":
                active_authority.state_hash(),
        },

        "revoked_observation": {
            "canonical_payload":
                revoked_observation.canonical_payload(),

            "state_hash":
                revoked_observation.state_hash(),
        },
    },

    "positive_controls": {
        "established_helper_passed":
            helper_positive_passed,

        "duplicate_identical_observations_passed":
            duplicate_positive_passed,

        "helper_resolution_hash":
            helper_resolution.state_hash(),

        "duplicate_resolution_hash":
            duplicate_resolution.state_hash(),
    },

    "successor_control_established":
        successor_control_established,

    "bounded_interpretation": (
        "This deterministic successor test establishes only that "
        "the native AuthorityResolution representation now rejects "
        "an ESTABLISHED resolution carrying a supplied observation "
        "that differs from its executable authority, while preserving "
        "the tested coherent ESTABLISHED constructions. It does not "
        "establish observation authenticity, resolver correctness, "
        "distributed consensus, freshness, external provenance, or "
        "production deployment behavior."
    ),
}


write_json(
    RESULT_PATH,
    result_document,
)


freeze_document = {
    "test_id":
        TEST_ID,

    "freeze_type":
        "FIRST_OBSERVED_SUCCESSOR_RESULT_FREEZE",

    "frozen_at_utc":
        utc_now(),

    "classification":
        classification,

    "predecessor_failure_commit":
        "54c2319",

    "artifact_hashes_sha256": {
        "test_definition":
            sha256_file(
                DEFINITION_PATH
            ),

        "test_script":
            sha256_file(
                Path(__file__)
            ),

        "result":
            sha256_file(
                RESULT_PATH
            ),

        "successor_authority_resolution":
            sha256_file(
                authority_resolution_path
            ),
    },

    "no_retrospective_repair":
        True,

    "predecessor_evidence_preserved":
        True,
}


write_json(
    FREEZE_PATH,
    freeze_document,
)


for path in (
    RESULT_PATH,
    FREEZE_PATH,
):
    write_sidecar(path)


print()
print(
    "=== P3-F05-S01 FIRST OBSERVED RESULT ==="
)

print(
    "classification:",
    classification,
)

print(
    "source_identity_preserved:",
    source_identity_preserved,
)

print(
    "same_lineage:",
    same_lineage,
)

print(
    "material_state_conflict_present:",
    material_state_conflict_present,
)

print(
    "incoherent_constructed:",
    incoherent_constructed,
)

print(
    "negative_exception_captured:",
    negative_exception_captured,
)

print(
    "negative_exception_type:",
    negative_exception_type,
)

print(
    "negative_exception_message:",
    negative_exception_message,
)

print(
    "negative_control_passed:",
    negative_control_passed,
)

print(
    "helper_positive_passed:",
    helper_positive_passed,
)

print(
    "duplicate_positive_passed:",
    duplicate_positive_passed,
)

print(
    "successor_control_established:",
    successor_control_established,
)

print()
print(
    "RESULT:",
    RESULT_PATH.relative_to(ROOT),
)

print(
    "FREEZE:",
    FREEZE_PATH.relative_to(ROOT),
)


sys.exit(
    0
    if successor_control_established
    else 5
)