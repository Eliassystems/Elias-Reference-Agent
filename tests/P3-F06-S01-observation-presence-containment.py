from __future__ import annotations

from pathlib import Path
import hashlib
import json

from core.authority import AuthorityState
from core.authority_resolution import (
    AuthorityResolution,
    AuthorityResolutionStatus,
)


ROOT = Path(__file__).resolve().parents[1]

SOURCE = ROOT / "core" / "authority_resolution.py"

EVIDENCE_DIR = (
    ROOT / "evidence" / "phase-iii" / "p3-f06-s01"
)

RESULT_PATH = (
    EVIDENCE_DIR /
    "P3-F06-S01-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR /
    "P3-F06-S01-FIRST-OBSERVED-FREEZE-001.json"
)

EXPECTED_SOURCE_HASH = (
    "091997310F5A98F2E160CD1FD0A99D251DB55C1800A415C8B4987DA6554F7857"
)

BASELINE_COMMIT = (
    "f2a075c67da5764f5508733cb3ed87c9d464f747"
)

ANTECEDENT_CLASSIFICATION = (
    "OBSERVATIONLESS_ESTABLISHED_RESOLUTION_EXECUTED__"
    "OBSERVATION_PRESENCE_CONTROL_NOT_ESTABLISHED"
)

SUCCESS_CLASSIFICATION = (
    "OBSERVATIONLESS_ESTABLISHED_RESOLUTION_REJECTED__"
    "OBSERVATION_PRESENCE_CONTROL_ESTABLISHED"
)

FAILURE_CLASSIFICATION = (
    "P3-F06-S01_SUCCESSOR_CONTROL_NOT_ESTABLISHED"
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
        )
        + "\n",
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
            "P3-F06-S01 FIRST-OBSERVED ARTIFACT EXISTS ? DO NOT RERUN."
        )


actual_source_hash = sha256(SOURCE)

source_identity_preserved = (
    actual_source_hash
    == EXPECTED_SOURCE_HASH
)


active_authority = (
    AuthorityState.create(
        actor_id=
            "P3-F06-S01-HUMAN-001",

        authority_source=
            "HUMAN_SOVEREIGN_AUTHORITY",

        permissions={
            "SEND"
        },

        epoch=1,
    )
)


# ============================================================
# POSITIVE CONTROL 1 ? NATIVE HELPER
# ============================================================

helper_error = None
helper = None

try:
    helper = (
        AuthorityResolution.established(
            active_authority
        )
    )
except Exception as exc:
    helper_error = {
        "type": type(exc).__name__,
        "message": str(exc),
    }

helper_positive_passed = (
    helper_error is None
    and helper is not None
    and helper.status
        == AuthorityResolutionStatus.ESTABLISHED
    and helper.authority
        == active_authority
    and len(helper.observations) == 1
    and helper.observations[0]
        == active_authority
)


# ============================================================
# POSITIVE CONTROL 2 ? DIRECT ONE MATCHING OBSERVATION
# ============================================================

direct_positive_error = None
direct_positive = None

try:
    direct_positive = AuthorityResolution(
        status=
            AuthorityResolutionStatus.ESTABLISHED,

        authority=
            active_authority,

        observations=(
            active_authority,
        ),

        reason=
            "P3-F06-S01-DIRECT-POSITIVE",
    )
except Exception as exc:
    direct_positive_error = {
        "type": type(exc).__name__,
        "message": str(exc),
    }

direct_positive_passed = (
    direct_positive_error is None
    and direct_positive is not None
    and len(
        direct_positive.observations
    ) == 1
)


# ============================================================
# POSITIVE CONTROL 3 ? DUPLICATE MATCHING OBSERVATIONS
# Narrow successor: presence >= 1, not exactly one.
# ============================================================

duplicate_error = None
duplicate_positive = None

try:
    duplicate_positive = AuthorityResolution(
        status=
            AuthorityResolutionStatus.ESTABLISHED,

        authority=
            active_authority,

        observations=(
            active_authority,
            active_authority,
        ),

        reason=
            "P3-F06-S01-DUPLICATE-POSITIVE",
    )
except Exception as exc:
    duplicate_error = {
        "type": type(exc).__name__,
        "message": str(exc),
    }

duplicate_positive_passed = (
    duplicate_error is None
    and duplicate_positive is not None
    and len(
        duplicate_positive.observations
    ) == 2
)


# ============================================================
# ADVERSARIAL CONTROL ? ZERO OBSERVATIONS
# ============================================================

observationless_constructed = False
observationless_error = None

try:
    AuthorityResolution(
        status=
            AuthorityResolutionStatus.ESTABLISHED,

        authority=
            active_authority,

        observations=(),

        reason=
            "P3-F06-S01-OBSERVATIONLESS",
    )

    observationless_constructed = True

except Exception as exc:
    observationless_error = {
        "type": type(exc).__name__,
        "message": str(exc),
    }


observationless_rejected = (
    observationless_constructed is False
    and observationless_error is not None
    and observationless_error["type"]
        == "ValueError"
    and observationless_error["message"]
        == (
            "ESTABLISHED resolution requires "
            "at least one observation"
        )
)


# ============================================================
# REGRESSION CONTROL ? PRESERVE P3-F05-S01 COHERENCE
# ============================================================

unequal_observation = (
    AuthorityState.create(
        actor_id=
            "P3-F06-S01-HUMAN-001",

        authority_source=
            "HUMAN_SOVEREIGN_AUTHORITY",

        permissions={
            "SEND"
        },

        epoch=2,
    )
)

coherence_error = None
incoherent_constructed = False

try:
    AuthorityResolution(
        status=
            AuthorityResolutionStatus.ESTABLISHED,

        authority=
            active_authority,

        observations=(
            unequal_observation,
        ),

        reason=
            "P3-F06-S01-COHERENCE-REGRESSION",
    )

    incoherent_constructed = True

except Exception as exc:
    coherence_error = {
        "type": type(exc).__name__,
        "message": str(exc),
    }


coherence_control_preserved = (
    incoherent_constructed is False
    and coherence_error is not None
    and coherence_error["type"]
        == "ValueError"
    and coherence_error["message"]
        == (
            "ESTABLISHED resolution observations "
            "must match executable authority"
        )
)


# ============================================================
# CLASSIFICATION
# ============================================================

successor_control_established = all(
    (
        source_identity_preserved,
        helper_positive_passed,
        direct_positive_passed,
        duplicate_positive_passed,
        observationless_rejected,
        coherence_control_preserved,
    )
)

classification = (
    SUCCESS_CLASSIFICATION
    if successor_control_established
    else FAILURE_CLASSIFICATION
)


result = {
    "test_id": "P3-F06-S01",
    "classification": classification,

    "source_identity": {
        "expected_sha256":
            EXPECTED_SOURCE_HASH,

        "actual_sha256":
            actual_source_hash,

        "preserved":
            source_identity_preserved,
    },

    "helper_positive_control": {
        "passed":
            helper_positive_passed,

        "error":
            helper_error,

        "observation_count":
            (
                len(helper.observations)
                if helper is not None
                else None
            ),
    },

    "direct_positive_control": {
        "passed":
            direct_positive_passed,

        "error":
            direct_positive_error,
    },

    "duplicate_positive_control": {
        "passed":
            duplicate_positive_passed,

        "error":
            duplicate_error,

        "bounded_semantics":
            "presence >= 1; exactly-one not established",
    },

    "observationless_control": {
        "constructed":
            observationless_constructed,

        "rejected":
            observationless_rejected,

        "error":
            observationless_error,
    },

    "coherence_regression_control": {
        "incoherent_constructed":
            incoherent_constructed,

        "preserved":
            coherence_control_preserved,

        "error":
            coherence_error,
    },

    "runtime_observation": {
        "runtime_invoked": False,
        "consequence_attempted": False,
        "reason": (
            "successor control is evaluated at "
            "AuthorityResolution representation construction"
        ),
    },

    "successor_control_established":
        successor_control_established,

    "bounded_claim": (
        "This deterministic successor test examines only whether "
        "the native AuthorityResolution representation requires "
        "at least one observation for an ESTABLISHED executable "
        "authority while preserving supplied-observation coherence. "
        "It does not establish observation authenticity, resolver "
        "correctness, source authority, distributed consensus, "
        "jurisdictional freshness, external provenance, or "
        "production deployment behavior."
    ),
}


freeze = {
    "test_id": "P3-F06-S01",
    "freeze_type":
        "SUCCESSOR_CONTROL_FIRST_OBSERVED_FREEZE",

    "classification":
        classification,

    "repository_baseline_commit":
        BASELINE_COMMIT,

    "antecedent_failure_classification":
        ANTECEDENT_CLASSIFICATION,

    "antecedent_failure_preserved":
        True,

    "no_retrospective_repair":
        True,

    "successor_control_established":
        successor_control_established,

    "source_sha256":
        actual_source_hash,
}


write_json(
    RESULT_PATH,
    result,
)

write_json(
    FREEZE_PATH,
    freeze,
)

write_sidecar(
    RESULT_PATH,
)

write_sidecar(
    FREEZE_PATH,
)


print()
print("=== P3-F06-S01 FIRST OBSERVED RESULT ===")
print("classification:", classification)
print(
    "source_identity_preserved:",
    source_identity_preserved,
)
print(
    "helper_positive_passed:",
    helper_positive_passed,
)
print(
    "direct_positive_passed:",
    direct_positive_passed,
)
print(
    "duplicate_positive_passed:",
    duplicate_positive_passed,
)
print(
    "observationless_constructed:",
    observationless_constructed,
)
print(
    "observationless_rejected:",
    observationless_rejected,
)
print(
    "coherence_control_preserved:",
    coherence_control_preserved,
)
print(
    "successor_control_established:",
    successor_control_established,
)
print()
print("RESULT:", RESULT_PATH.relative_to(ROOT))
print("FREEZE:", FREEZE_PATH.relative_to(ROOT))
