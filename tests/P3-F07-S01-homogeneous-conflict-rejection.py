from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(ROOT),
    )

from core.authority import AuthorityState
from core.authority_resolution import (
    AuthorityResolution,
    AuthorityResolutionStatus,
)


TEST_ID = "P3-F07-S01"

ANTECEDENT_COMMIT = (
    "7079fe51443c680caa7e73c98cc53ed5b1f71412"
)

ANTECEDENT_SOURCE_SHA256 = (
    "091997310F5A98F2E160CD1FD0A99D251DB55C1800A415C8B4987DA6554F7857"
)

SUCCESSOR_SOURCE_SHA256 = (
    "D1B052E1F413ADAFA71C8B7D3E0AB470817E901CBA28D1CF145BF10EA7A585EF"
)

EVIDENCE_DIR = (
    ROOT / "evidence" / "phase-iii" / "p3-f07-s01"
)

RESULT_PATH = (
    EVIDENCE_DIR /
    "P3-F07-S01-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR /
    "P3-F07-S01-FIRST-OBSERVED-FREEZE-001.json"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest().upper()


def write_json(path: Path, payload) -> None:
    path.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def write_sidecar(path: Path) -> None:
    digest = sha256(path)

    path.with_name(
        path.name + ".sha256"
    ).write_text(
        f"{digest}  {path.name}\n",
        encoding="utf-8",
        newline="\n",
    )


for path in (
    RESULT_PATH,
    FREEZE_PATH,
    RESULT_PATH.with_name(
        RESULT_PATH.name + ".sha256"
    ),
    FREEZE_PATH.with_name(
        FREEZE_PATH.name + ".sha256"
    ),
):
    if path.exists():
        raise SystemExit(
            "P3-F07-S01 FIRST-OBSERVED ARTIFACT EXISTS - DO NOT RERUN."
        )


source_path = (
    ROOT / "core" / "authority_resolution.py"
)

source_hash = sha256(
    source_path
)

source_identity_preserved = (
    source_hash
    == SUCCESSOR_SOURCE_SHA256
)


active_authority = AuthorityState.create(
    actor_id="P3-F07-S01-HUMAN-001",
    authority_source="HUMAN_SOVEREIGN_AUTHORITY",
    permissions={
        "SEND"
    },
    epoch=1,
)

different_authority = AuthorityState.create(
    actor_id="P3-F07-S01-HUMAN-001",
    authority_source="HUMAN_SOVEREIGN_AUTHORITY",
    permissions={
        "SEND"
    },
    epoch=2,
)


# ------------------------------------------------------------
# POSITIVE CONTROL 1:
# genuine divergence remains representable as CONFLICT
# ------------------------------------------------------------

divergent_conflict = None
divergent_conflict_error = None

try:
    divergent_conflict = AuthorityResolution.conflict(
        (
            active_authority,
            different_authority,
        ),
        reason="P3-F07-S01-DIVERGENT-CONFLICT",
    )
except Exception as exc:
    divergent_conflict_error = {
        "type": type(exc).__name__,
        "message": str(exc),
    }

divergent_conflict_passed = (
    divergent_conflict is not None
    and divergent_conflict_error is None
    and divergent_conflict.status
        == AuthorityResolutionStatus.CONFLICT
    and len(divergent_conflict.observations) == 2
    and divergent_conflict.observations[0]
        != divergent_conflict.observations[1]
)


# ------------------------------------------------------------
# NEGATIVE CONTROL:
# homogeneous observations must no longer form CONFLICT
# ------------------------------------------------------------

homogeneous_conflict = None
homogeneous_error = None

try:
    homogeneous_conflict = AuthorityResolution.conflict(
        (
            active_authority,
            active_authority,
        ),
        reason="P3-F07-S01-HOMOGENEOUS-CONFLICT",
    )
except Exception as exc:
    homogeneous_error = {
        "type": type(exc).__name__,
        "message": str(exc),
    }

homogeneous_rejected = (
    homogeneous_conflict is None
    and homogeneous_error is not None
    and homogeneous_error["type"] == "ValueError"
    and homogeneous_error["message"]
        == (
            "CONFLICT resolution requires "
            "materially different observations"
        )
)


# ------------------------------------------------------------
# EXISTING CONFLICT MINIMUM COUNT CONTROL
# ------------------------------------------------------------

singleton_conflict = None
singleton_error = None

try:
    singleton_conflict = AuthorityResolution.conflict(
        (
            active_authority,
        ),
        reason="P3-F07-S01-SINGLETON-CONFLICT",
    )
except Exception as exc:
    singleton_error = {
        "type": type(exc).__name__,
        "message": str(exc),
    }

minimum_count_control_preserved = (
    singleton_conflict is None
    and singleton_error is not None
    and singleton_error["type"] == "ValueError"
    and singleton_error["message"]
        == (
            "CONFLICT resolution requires "
            "at least two observations"
        )
)


# ------------------------------------------------------------
# P3-F06-S01 PRESERVATION:
# ESTABLISHED requires >=1 observation
# ------------------------------------------------------------

observationless_established = None
observationless_error = None

try:
    observationless_established = AuthorityResolution(
        status=AuthorityResolutionStatus.ESTABLISHED,
        authority=active_authority,
        observations=(),
        reason="P3-F07-S01-OBSERVATIONLESS-ESTABLISHED",
    )
except Exception as exc:
    observationless_error = {
        "type": type(exc).__name__,
        "message": str(exc),
    }

observation_presence_control_preserved = (
    observationless_established is None
    and observationless_error is not None
    and observationless_error["type"] == "ValueError"
    and observationless_error["message"]
        == (
            "ESTABLISHED resolution requires "
            "at least one observation"
        )
)


# ------------------------------------------------------------
# P3-F05-S01 PRESERVATION:
# ESTABLISHED supplied observations must match authority
# ------------------------------------------------------------

incoherent_established = None
incoherent_error = None

try:
    incoherent_established = AuthorityResolution(
        status=AuthorityResolutionStatus.ESTABLISHED,
        authority=active_authority,
        observations=(
            different_authority,
        ),
        reason="P3-F07-S01-INCOHERENT-ESTABLISHED",
    )
except Exception as exc:
    incoherent_error = {
        "type": type(exc).__name__,
        "message": str(exc),
    }

coherence_control_preserved = (
    incoherent_established is None
    and incoherent_error is not None
    and incoherent_error["type"] == "ValueError"
    and incoherent_error["message"]
        == (
            "ESTABLISHED resolution observations must "
            "match executable authority"
        )
)


# ------------------------------------------------------------
# ESTABLISHED POSITIVE CONTROL
# ------------------------------------------------------------

established_positive = None
established_positive_error = None

try:
    established_positive = AuthorityResolution.established(
        active_authority
    )
except Exception as exc:
    established_positive_error = {
        "type": type(exc).__name__,
        "message": str(exc),
    }

established_positive_passed = (
    established_positive is not None
    and established_positive_error is None
    and established_positive.status
        == AuthorityResolutionStatus.ESTABLISHED
    and established_positive.authority
        == active_authority
    and established_positive.observations
        == (
            active_authority,
        )
)


successor_control_established = all(
    (
        source_identity_preserved,
        divergent_conflict_passed,
        homogeneous_rejected,
        minimum_count_control_preserved,
        observation_presence_control_preserved,
        coherence_control_preserved,
        established_positive_passed,
    )
)


if successor_control_established:

    classification = (
        "HOMOGENEOUS_CONFLICT_REJECTED__"
        "CONFLICT_DIVERGENCE_CONTROL_ESTABLISHED"
    )

else:

    classification = (
        "P3-F07-S01_SUCCESSOR_CONTROL_NOT_ESTABLISHED"
    )


result_payload = {
    "test_id": TEST_ID,
    "classification": classification,

    "antecedent_commit":
        ANTECEDENT_COMMIT,

    "antecedent_source_sha256":
        ANTECEDENT_SOURCE_SHA256,

    "successor_source_sha256":
        SUCCESSOR_SOURCE_SHA256,

    "actual_source_sha256":
        source_hash,

    "source_identity_preserved":
        source_identity_preserved,

    "divergent_conflict_control": {
        "passed":
            divergent_conflict_passed,

        "error":
            divergent_conflict_error,
    },

    "homogeneous_conflict_control": {
        "constructed":
            homogeneous_conflict is not None,

        "rejected":
            homogeneous_rejected,

        "error":
            homogeneous_error,
    },

    "minimum_conflict_count_control": {
        "preserved":
            minimum_count_control_preserved,

        "error":
            singleton_error,
    },

    "established_observation_presence_control": {
        "preserved":
            observation_presence_control_preserved,

        "error":
            observationless_error,
    },

    "established_coherence_control": {
        "preserved":
            coherence_control_preserved,

        "error":
            incoherent_error,
    },

    "established_positive_control": {
        "passed":
            established_positive_passed,

        "error":
            established_positive_error,
    },

    "successor_control_established":
        successor_control_established,

    "bounded_claim": (
        "This deterministic successor test establishes only that "
        "the native AuthorityResolution representation rejects a "
        "CONFLICT whose supplied observations are all identical, "
        "while preserving materially divergent CONFLICT representation "
        "and the previously established ESTABLISHED presence/coherence "
        "controls. It does not establish observation authenticity, "
        "resolver correctness, distributed consensus, jurisdictional "
        "freshness, external provenance, or production deployment behavior."
    ),
}


freeze_payload = {
    "test_id": TEST_ID,

    "freeze_type":
        "FIRST_OBSERVED_RESULT_FREEZE",

    "classification":
        classification,

    "antecedent_commit":
        ANTECEDENT_COMMIT,

    "successor_source_sha256":
        SUCCESSOR_SOURCE_SHA256,

    "source_identity_preserved":
        source_identity_preserved,

    "successor_control_established":
        successor_control_established,

    "no_retrospective_repair":
        True,
}


write_json(
    RESULT_PATH,
    result_payload,
)

write_json(
    FREEZE_PATH,
    freeze_payload,
)

write_sidecar(
    RESULT_PATH,
)

write_sidecar(
    FREEZE_PATH,
)


print()
print("=== P3-F07-S01 FIRST OBSERVED RESULT ===")
print(
    "classification:",
    classification,
)
print(
    "source_identity_preserved:",
    source_identity_preserved,
)
print(
    "divergent_conflict_passed:",
    divergent_conflict_passed,
)
print(
    "homogeneous_rejected:",
    homogeneous_rejected,
)
print(
    "minimum_count_control_preserved:",
    minimum_count_control_preserved,
)
print(
    "observation_presence_control_preserved:",
    observation_presence_control_preserved,
)
print(
    "coherence_control_preserved:",
    coherence_control_preserved,
)
print(
    "established_positive_passed:",
    established_positive_passed,
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
