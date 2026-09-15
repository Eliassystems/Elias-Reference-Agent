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
from core.execution_firewall_v06 import (
    ExecutionFirewallV06,
)
from core.permit_v02 import (
    PermitIssuerV02,
    PermitVerifierV02,
)
from tools.broker_v06 import (
    ToolBrokerV06,
    ToolRequestV06,
)
from tools.messaging_demo_v06 import (
    MessagingDemoToolV06,
)
from witness.ledger import WitnessLedger


TEST_ID = "P3-F07"

BASELINE_COMMIT = (
    "ed6ffa48d5b99951b9b52673f9802f5dad6f517f"
)

EXPECTED_SOURCE_HASHES = {'core/authority.py': 'E949C5C9E75DCB65301701363363AC6D118CD64D3AB38018957DA086EBB6B85C', 'core/authority_resolution.py': '091997310F5A98F2E160CD1FD0A99D251DB55C1800A415C8B4987DA6554F7857', 'core/execution_firewall_v06.py': '688BCA67810747A053A4251974281AC2D5C435C0CEAC36CBFEF85A65A0D9DEBD', 'core/permit_v02.py': '1BE9CED135D1C3E0498728B5E9AE0853E46E1925EA90EFF70A573E0F516C70A5', 'tools/broker_v06.py': 'B220643B322356345E79EA37359D48BCDE004DCE09727B01F8BEC5E6DFCBE26F', 'tools/messaging_demo_v06.py': 'C976315CB420599ACEC8F2D8E5ED0B4FE4FBB9B1B07CBC8CBBA3CBB3E79A67DE', 'witness/ledger.py': 'C940D48351E8F4A06F2008CE720A2187433556E18C49D6378A2FA27E6DCE40E5', 'constitution/constitution.yaml': '6FF2C14C67DF4B009F81551AD55ECD4C1EA314B5827D7B039D0E21AD934D302A'}

EVIDENCE_DIR = (
    ROOT / "evidence" / "phase-iii" / "p3-f07"
)

RESULT_PATH = (
    EVIDENCE_DIR /
    "P3-F07-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR /
    "P3-F07-FIRST-OBSERVED-FREEZE-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR /
    "P3-F07-WITNESS-001.jsonl"
)

FAILURE_CLASSIFICATION = (
    "HOMOGENEOUS_CONFLICT_ACCEPTED__"
    "FALSE_CONFLICT_CAUSED_CONSEQUENCE_REFUSAL"
)

CONTROL_CLASSIFICATION = (
    "HOMOGENEOUS_CONFLICT_REJECTED__"
    "CONFLICT_DIVERGENCE_CONTROL_ESTABLISHED"
)

UNEXPECTED_CLASSIFICATION = (
    "P3-F07_UNEXPECTED_RESULT"
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
    WITNESS_PATH,
    RESULT_PATH.with_name(
        RESULT_PATH.name + ".sha256"
    ),
    FREEZE_PATH.with_name(
        FREEZE_PATH.name + ".sha256"
    ),
    WITNESS_PATH.with_name(
        WITNESS_PATH.name + ".sha256"
    ),
):
    if path.exists():
        raise SystemExit(
            "P3-F07 FIRST-OBSERVED ARTIFACT EXISTS - DO NOT RERUN."
        )


source_identity = {}
source_identity_preserved = True

for relative, expected in EXPECTED_SOURCE_HASHES.items():

    actual = sha256(
        ROOT / relative
    )

    source_identity[relative] = {
        "expected_sha256": expected,
        "actual_sha256": actual,
        "preserved": actual == expected,
    }

    if actual != expected:
        source_identity_preserved = False


# ============================================================
# AUTHORITY
# ============================================================

active_authority = AuthorityState.create(
    actor_id="P3-F07-HUMAN-001",
    authority_source="HUMAN_SOVEREIGN_AUTHORITY",
    permissions={
        "SEND"
    },
    epoch=1,
)


# ============================================================
# POSITIVE REPRESENTATION CONTROL
# Genuine material difference remains representable as CONFLICT.
# ============================================================

different_authority = AuthorityState.create(
    actor_id="P3-F07-HUMAN-001",
    authority_source="HUMAN_SOVEREIGN_AUTHORITY",
    permissions={
        "SEND"
    },
    epoch=2,
)

divergent_conflict = None
divergent_conflict_error = None

try:
    divergent_conflict = AuthorityResolution.conflict(
        (
            active_authority,
            different_authority,
        ),
        reason="P3-F07-DIVERGENT-CONFLICT-CONTROL",
    )
except Exception as exc:
    divergent_conflict_error = {
        "type": type(exc).__name__,
        "message": str(exc),
    }

divergent_conflict_control_passed = (
    divergent_conflict is not None
    and divergent_conflict_error is None
    and divergent_conflict.status
        == AuthorityResolutionStatus.CONFLICT
    and len(divergent_conflict.observations) == 2
    and divergent_conflict.observations[0]
        != divergent_conflict.observations[1]
)


# ============================================================
# ADVERSARIAL REPRESENTATION
# Two identical observations labelled CONFLICT.
# ============================================================

homogeneous_conflict = None
homogeneous_construction_error = None

try:
    homogeneous_conflict = AuthorityResolution.conflict(
        (
            active_authority,
            active_authority,
        ),
        reason="P3-F07-HOMOGENEOUS-CONFLICT",
    )
except Exception as exc:
    homogeneous_construction_error = {
        "type": type(exc).__name__,
        "message": str(exc),
    }

homogeneous_conflict_constructed = (
    homogeneous_conflict is not None
    and homogeneous_construction_error is None
)

homogeneous_observations_identical = (
    homogeneous_conflict_constructed
    and len(homogeneous_conflict.observations) == 2
    and homogeneous_conflict.observations[0]
        == homogeneous_conflict.observations[1]
)


# ============================================================
# PROVEN TIMELINE LEDGER
# ============================================================

timeline = []

class TimelineLedger(
    WitnessLedger
):

    def __init__(
        self,
        path,
        timeline_ref,
    ):

        self._timeline_ref = (
            timeline_ref
        )

        super().__init__(
            path
        )

    def append(
        self,
        *args,
        **kwargs,
    ):

        record = super().append(
            *args,
            **kwargs,
        )

        event_type = kwargs.get(
            "event_type"
        )

        if event_type:

            self._timeline_ref.append(
                "WITNESS:"
                + str(
                    event_type
                )
            )

        return record


# ============================================================
# RESOLVER
# ============================================================

resolver_state = {
    "calls": 0,
    "statuses": [],
    "resolution_hashes": [],
    "observation_counts": [],
    "observation_hashes": [],
}

def authority_resolver():

    resolver_state["calls"] += 1

    call_number = resolver_state["calls"]

    if homogeneous_conflict is None:
        raise RuntimeError(
            "P3-F07_HOMOGENEOUS_CONFLICT_NOT_CONSTRUCTED"
        )

    resolver_state["statuses"].append(
        homogeneous_conflict.status.value
    )

    resolver_state["resolution_hashes"].append(
        homogeneous_conflict.state_hash()
    )

    resolver_state["observation_counts"].append(
        len(
            homogeneous_conflict.observations
        )
    )

    resolver_state["observation_hashes"].append(
        [
            observation.state_hash()
            for observation
            in homogeneous_conflict.observations
        ]
    )

    timeline.append(
        "RESOLVER_CALL_"
        + str(call_number)
        + ":"
        + homogeneous_conflict.status.value
        + ":OBSERVATIONS_"
        + str(
            len(
                homogeneous_conflict.observations
            )
        )
    )

    return homogeneous_conflict


# ============================================================
# NORMAL V06 STACK
# ============================================================

arguments = {
    "content":
        "P3-F07 HOMOGENEOUS CONFLICT CONSEQUENCE REFUSAL TEST"
}

signing_key = (
    b"P3-F07-HOMOGENEOUS-CONFLICT-KEY-0001"
)

issuer = PermitIssuerV02(
    signing_key=signing_key
)

verifier = PermitVerifierV02(
    signing_key=signing_key
)

ledger = TimelineLedger(
    WITNESS_PATH,
    timeline,
)

messaging_tool = (
    MessagingDemoToolV06()
)

firewall = ExecutionFirewallV06(
    verifier=verifier,
    ledger=ledger,
    constitution_path=(
        ROOT
        / "constitution"
        / "constitution.yaml"
    ),
)

broker = ToolBrokerV06(
    firewall=firewall,
    messaging_tool=messaging_tool,
)

intent_hash = (
    "P3-F07-HOMOGENEOUS-CONFLICT-INTENT"
)

permit = issuer.issue(
    authority=
        active_authority,

    intent_hash=
        intent_hash,

    permission=
        "SEND",

    policy_version=
        "ERA-POLICY-001-v0.2.0",

    target=
        "P3-F07-RECIPIENT",

    tool=
        "MESSAGING_DEMO",

    consequence_class=
        "C4",

    arguments=
        arguments,
)

request = ToolRequestV06(
    permit=
        permit,

    current_authority=
        active_authority,

    authority_resolver=
        authority_resolver,

    intent_hash=
        intent_hash,

    permission=
        "SEND",

    policy_version=
        "ERA-POLICY-001-v0.2.0",

    target=
        "P3-F07-RECIPIENT",

    tool_name=
        "MESSAGING_DEMO",

    consequence_class=
        "C4",

    arguments=
        arguments,
)


# ============================================================
# EXECUTION - FIRST OBSERVATION ONLY
# ============================================================

outbox_before = broker.outbox_size()

execution_attempted = False
execution_exception = None
result = None

if (
    source_identity_preserved
    and divergent_conflict_control_passed
    and homogeneous_conflict_constructed
    and homogeneous_observations_identical
):
    execution_attempted = True

    try:
        result = broker.execute(
            request
        )
    except Exception as exc:
        execution_exception = {
            "type": type(exc).__name__,
            "message": str(exc),
        }

outbox_after = broker.outbox_size()

records = ledger.records()

chain_valid, chain_errors = (
    ledger.verify_chain()
)


# ============================================================
# OBSERVED RUNTIME STATE
# ============================================================

result_status = None
result_reasons = []

if result is not None:

    raw_status = getattr(
        result,
        "status",
        None,
    )

    result_status = getattr(
        raw_status,
        "value",
        raw_status,
    )

    raw_reasons = getattr(
        result,
        "reasons",
        (),
    )

    if raw_reasons is not None:
        result_reasons = list(
            raw_reasons
        )


consequence_committed = (
    outbox_after > outbox_before
)

false_conflict_caused_refusal = (
    homogeneous_conflict_constructed
    and homogeneous_observations_identical
    and execution_attempted
    and execution_exception is None
    and result is not None
    and "CONSEQUENCE_AUTHORITY_CONFLICT"
        in result_reasons
    and consequence_committed is False
    and resolver_state["calls"] == 1
    and resolver_state["statuses"]
        == ["CONFLICT"]
)


if false_conflict_caused_refusal:

    classification = (
        FAILURE_CLASSIFICATION
    )

elif (
    homogeneous_conflict_constructed
    is False
    and homogeneous_construction_error
    is not None
):

    classification = (
        CONTROL_CLASSIFICATION
    )

else:

    classification = (
        UNEXPECTED_CLASSIFICATION
    )


result_payload = {
    "test_id": TEST_ID,
    "classification": classification,

    "repository_baseline_commit":
        BASELINE_COMMIT,

    "source_identity":
        source_identity,

    "source_identity_preserved":
        source_identity_preserved,

    "divergent_conflict_control": {
        "passed":
            divergent_conflict_control_passed,

        "error":
            divergent_conflict_error,
    },

    "homogeneous_conflict": {
        "constructed":
            homogeneous_conflict_constructed,

        "observations_identical":
            homogeneous_observations_identical,

        "observation_count":
            (
                len(
                    homogeneous_conflict.observations
                )
                if homogeneous_conflict
                is not None
                else None
            ),

        "error":
            homogeneous_construction_error,
    },

    "resolver": resolver_state,

    "execution": {
        "attempted":
            execution_attempted,

        "exception":
            execution_exception,

        "status":
            result_status,

        "reasons":
            result_reasons,

        "outbox_before":
            outbox_before,

        "outbox_after":
            outbox_after,

        "consequence_committed":
            consequence_committed,
    },

    "witness": {
        "record_count":
            len(records),

        "chain_valid":
            chain_valid,

        "chain_errors":
            chain_errors,
    },

    "false_conflict_caused_refusal":
        false_conflict_caused_refusal,

    "bounded_claim": (
        "This deterministic test examines only whether the native "
        "AuthorityResolution representation permits a CONFLICT composed "
        "solely of identical supplied observations and whether V06 then "
        "treats that supplied status as a consequence-boundary conflict. "
        "It does not establish observation authenticity, resolver correctness, "
        "distributed consensus, jurisdictional freshness, external provenance, "
        "or production deployment behavior."
    ),
}

freeze_payload = {
    "test_id": TEST_ID,
    "freeze_type":
        "FIRST_OBSERVED_RESULT_FREEZE",

    "classification":
        classification,

    "repository_baseline_commit":
        BASELINE_COMMIT,

    "no_retrospective_repair":
        True,

    "source_identity_preserved":
        source_identity_preserved,

    "homogeneous_conflict_constructed":
        homogeneous_conflict_constructed,

    "false_conflict_caused_refusal":
        false_conflict_caused_refusal,
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

if WITNESS_PATH.exists():
    write_sidecar(
        WITNESS_PATH,
    )


print()
print("=== P3-F07 FIRST OBSERVED RESULT ===")
print(
    "classification:",
    classification,
)
print(
    "source_identity_preserved:",
    source_identity_preserved,
)
print(
    "divergent_conflict_control_passed:",
    divergent_conflict_control_passed,
)
print(
    "homogeneous_conflict_constructed:",
    homogeneous_conflict_constructed,
)
print(
    "homogeneous_observations_identical:",
    homogeneous_observations_identical,
)
print(
    "resolver_calls:",
    resolver_state["calls"],
)
print(
    "resolver_statuses:",
    resolver_state["statuses"],
)
print(
    "execution_status:",
    result_status,
)
print(
    "execution_reasons:",
    result_reasons,
)
print(
    "outbox_before:",
    outbox_before,
)
print(
    "outbox_after:",
    outbox_after,
)
print(
    "consequence_committed:",
    consequence_committed,
)
print(
    "false_conflict_caused_refusal:",
    false_conflict_caused_refusal,
)
print(
    "witness_chain_valid:",
    chain_valid,
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
print(
    "WITNESS:",
    WITNESS_PATH.relative_to(ROOT),
)
