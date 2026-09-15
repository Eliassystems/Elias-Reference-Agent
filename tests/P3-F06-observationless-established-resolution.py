from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
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


TEST_ID = "P3-F06"

EVIDENCE_DIR = (
    ROOT
    / "evidence"
    / "phase-iii"
    / "p3-f06"
)

DEFINITION_PATH = (
    EVIDENCE_DIR
    / "P3-F06-TEST-DEFINITION-001.json"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P3-F06-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR
    / "P3-F06-FIRST-OBSERVED-FREEZE-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P3-F06-WITNESS-001.jsonl"
)


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def sha256_file(
    path: Path,
) -> str:
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

        handle.write(
            "\n"
        )


def write_sidecar(
    path: Path,
) -> None:

    Path(
        str(path)
        + ".sha256"
    ).write_text(
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


source_paths = {
    "authority_resolution":
        ROOT
        / "core"
        / "authority_resolution.py",

    "execution_firewall_v06":
        ROOT
        / "core"
        / "execution_firewall_v06.py",

    "permit_v02":
        ROOT
        / "core"
        / "permit_v02.py",

    "broker_v06":
        ROOT
        / "tools"
        / "broker_v06.py",

    "messaging_demo_v06":
        ROOT
        / "tools"
        / "messaging_demo_v06.py",

    "witness_ledger":
        ROOT
        / "witness"
        / "ledger.py",

    "constitution_yaml":
        ROOT
        / "constitution"
        / "constitution.yaml",
}


expected_source_hashes = (
    definition[
        "source_hashes_sha256"
    ]
)


actual_source_hashes = {
    name:
        sha256_file(path)

    for name, path
    in source_paths.items()
}


source_identity_preserved = (
    actual_source_hashes
    == expected_source_hashes
)


# ============================================================
# AUTHORITY
# ============================================================

active_authority = (
    AuthorityState.create(
        actor_id=
            "P3-F06-HUMAN-001",

        authority_source=
            "HUMAN_SOVEREIGN_AUTHORITY",

        permissions={
            "SEND"
        },

        epoch=1,
    )
)


# ============================================================
# POSITIVE REPRESENTATION CONTROL
# ============================================================

helper_resolution = (
    AuthorityResolution.established(
        active_authority,
        reason=(
            "P3-F06-HELPER-"
            "POSITIVE-CONTROL"
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


# ============================================================
# ADVERSARIAL REPRESENTATION
# ============================================================

observationless_resolution = None

construction_exception_captured = False
construction_exception_type = ""
construction_exception_message = ""


try:

    observationless_resolution = (
        AuthorityResolution(
            status=
                AuthorityResolutionStatus.ESTABLISHED,

            authority=
                active_authority,

            observations=(),

            reason=(
                "P3-F06-DIRECT-"
                "OBSERVATIONLESS-ESTABLISHED"
            ),
        )
    )

except Exception as exc:

    construction_exception_captured = True

    construction_exception_type = (
        type(exc).__name__
    )

    construction_exception_message = (
        str(exc)
    )


observationless_constructed = (
    observationless_resolution
    is not None
)


empty_observations_preserved = (
    observationless_constructed
    and
    len(
        observationless_resolution.observations
    )
    == 0
)


native_observationless_established_representation = (
    observationless_constructed
    and
    observationless_resolution.status
    == AuthorityResolutionStatus.ESTABLISHED
    and
    observationless_resolution.authority
    == active_authority
    and
    empty_observations_preserved
)


# ============================================================
# TIMELINE WITNESS
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


resolver_state = {
    "calls": 0,
    "statuses": [],
    "resolution_hashes": [],
    "authority_hashes": [],
    "observation_counts": [],
    "observation_hashes": [],
}


def authority_resolver():

    resolver_state[
        "calls"
    ] += 1

    call_number = (
        resolver_state[
            "calls"
        ]
    )

    if observationless_resolution is None:
        raise RuntimeError(
            "P3-F06_OBSERVATIONLESS_"
            "RESOLUTION_NOT_CONSTRUCTED"
        )

    resolver_state[
        "statuses"
    ].append(
        observationless_resolution.status.value
    )

    resolver_state[
        "resolution_hashes"
    ].append(
        observationless_resolution.state_hash()
    )

    resolver_state[
        "authority_hashes"
    ].append(
        observationless_resolution.authority.state_hash()
    )

    resolver_state[
        "observation_counts"
    ].append(
        len(
            observationless_resolution.observations
        )
    )

    resolver_state[
        "observation_hashes"
    ].append(
        [
            observation.state_hash()
            for observation
            in observationless_resolution.observations
        ]
    )

    timeline.append(
        "RESOLVER_CALL_"
        + str(
            call_number
        )
        + ":"
        + observationless_resolution.status.value
        + ":OBSERVATIONS_"
        + str(
            len(
                observationless_resolution.observations
            )
        )
    )

    return observationless_resolution


# ============================================================
# NORMAL V06 STACK
# ============================================================

arguments = {
    "content":
        "P3-F06 OBSERVATIONLESS ESTABLISHED RESOLUTION TEST"
}


signing_key = (
    b"P3-F06-OBSERVATIONLESS-ESTABLISHED-KEY-0001"
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
    "P3-F06-OBSERVATIONLESS-ESTABLISHED-INTENT"
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
        "P3-F06-RECIPIENT",

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
        "P3-F06-RECIPIENT",

    tool_name=
        "MESSAGING_DEMO",

    consequence_class=
        "C4",

    arguments=
        arguments,
)


# ============================================================
# EXECUTION — FIRST OBSERVATION
# ============================================================

outbox_before = (
    broker.outbox_size()
)


execution_attempted = False
execution_exception_captured = False
execution_exception_type = ""
execution_exception_message = ""
result = None


if (
    source_identity_preserved
    and
    observationless_constructed
):

    execution_attempted = True

    try:

        result = broker.execute(
            request
        )

    except Exception as exc:

        execution_exception_captured = True

        execution_exception_type = (
            type(exc).__name__
        )

        execution_exception_message = (
            str(exc)
        )


outbox_after = (
    broker.outbox_size()
)


outbox_snapshot = (
    broker.outbox_snapshot()
)


records = (
    ledger.records()
)


chain_valid, chain_errors = (
    ledger.verify_chain()
)


event_types = [
    record.get(
        "event_type"
    )
    for record
    in records
]


result_returned = (
    result is not None
)


executed = (
    result.executed
    if result_returned
    else None
)


status = (
    result.status
    if result_returned
    else None
)


reasons = (
    list(
        result.reasons
    )
    if result_returned
    else []
)


receipt_hashes = (
    list(
        result.receipt_hashes
    )
    if result_returned
    else []
)


resolver_called_twice = (
    resolver_state[
        "calls"
    ]
    == 2
)


both_resolutions_established = (
    resolver_state[
        "statuses"
    ]
    == [
        "ESTABLISHED",
        "ESTABLISHED",
    ]
)


both_resolutions_observationless = (
    resolver_state[
        "observation_counts"
    ]
    == [
        0,
        0,
    ]
)


boundary_event_count = (
    event_types.count(
        "CONSEQUENCE_BOUNDARY_REVALIDATED"
    )
)


commit_success_event_count = (
    event_types.count(
        "CONSEQUENCE_COMMIT_AUTHORITY_REVALIDATED"
    )
)


commit_failure_event_count = (
    event_types.count(
        "CONSEQUENCE_COMMIT_AUTHORITY_REVALIDATION_FAILED"
    )
)


completion_event_count = (
    event_types.count(
        "EXECUTION_COMPLETED"
    )
)


refusal_event_count = (
    event_types.count(
        "EXECUTION_REFUSED"
    )
)


consequence_committed = (
    outbox_before == 0
    and
    outbox_after == 1
)


normal_execution_observed = (
    execution_attempted
    and
    not execution_exception_captured
    and
    result_returned
    and
    executed is True
    and
    status == "EXECUTED"
    and
    len(
        reasons
    )
    == 0
    and
    consequence_committed
    and
    boundary_event_count == 1
    and
    commit_success_event_count == 1
    and
    commit_failure_event_count == 0
    and
    completion_event_count == 1
    and
    refusal_event_count == 0
    and
    resolver_called_twice
    and
    both_resolutions_established
    and
    both_resolutions_observationless
    and
    chain_valid
)


observation_presence_control_not_established = (
    source_identity_preserved
    and
    helper_positive_passed
    and
    native_observationless_established_representation
    and
    normal_execution_observed
)


contained_without_commit = (
    observationless_constructed
    and
    outbox_after == outbox_before
    and
    not consequence_committed
)


# ============================================================
# CLASSIFICATION
# ============================================================

if not source_identity_preserved:

    classification = (
        "P3-F06_SOURCE_IDENTITY_MISMATCH__"
        "NOT_EXECUTED"
    )

elif not observationless_constructed:

    classification = (
        "OBSERVATIONLESS_ESTABLISHED_RESOLUTION_"
        "REJECTED_AT_REPRESENTATION__CAUSE_REQUIRES_ANALYSIS"
    )

elif observation_presence_control_not_established:

    classification = (
        "OBSERVATIONLESS_ESTABLISHED_RESOLUTION_EXECUTED__"
        "OBSERVATION_PRESENCE_CONTROL_NOT_ESTABLISHED"
    )

elif contained_without_commit:

    classification = (
        "OBSERVATIONLESS_ESTABLISHED_RESOLUTION_CONTAINED__"
        "CAUSE_REQUIRES_ANALYSIS"
    )

else:

    classification = (
        "OBSERVATIONLESS_ESTABLISHED_RESOLUTION_"
        "FIRST_OBSERVATION_INDETERMINATE"
    )


# ============================================================
# RESULT
# ============================================================

result_document = {
    "test_id":
        TEST_ID,

    "observed_at_utc":
        utc_now(),

    "classification":
        classification,

    "source_identity": {
        "expected_hashes_sha256":
            expected_source_hashes,

        "actual_hashes_sha256":
            actual_source_hashes,

        "preserved":
            source_identity_preserved,
    },

    "positive_representation_control": {
        "helper_status":
            helper_resolution.status.value,

        "helper_observation_count":
            len(
                helper_resolution.observations
            ),

        "helper_observation_hashes": [
            observation.state_hash()
            for observation
            in helper_resolution.observations
        ],

        "passed":
            helper_positive_passed,
    },

    "observationless_representation": {
        "constructed":
            observationless_constructed,

        "construction_exception_captured":
            construction_exception_captured,

        "construction_exception_type":
            construction_exception_type,

        "construction_exception_message":
            construction_exception_message,

        "native_observationless_established_representation":
            native_observationless_established_representation,

        "status":
            (
                observationless_resolution.status.value
                if observationless_constructed
                else None
            ),

        "authority_hash":
            (
                observationless_resolution.authority.state_hash()
                if observationless_constructed
                else None
            ),

        "observation_count":
            (
                len(
                    observationless_resolution.observations
                )
                if observationless_constructed
                else None
            ),

        "state_hash":
            (
                observationless_resolution.state_hash()
                if observationless_constructed
                else None
            ),

        "canonical_payload":
            (
                observationless_resolution.canonical_payload()
                if observationless_constructed
                else None
            ),
    },

    "resolver_observation": {
        "calls":
            resolver_state[
                "calls"
            ],

        "called_twice":
            resolver_called_twice,

        "statuses":
            resolver_state[
                "statuses"
            ],

        "observation_counts":
            resolver_state[
                "observation_counts"
            ],

        "both_resolutions_established":
            both_resolutions_established,

        "both_resolutions_observationless":
            both_resolutions_observationless,

        "resolution_hashes":
            resolver_state[
                "resolution_hashes"
            ],

        "authority_hashes":
            resolver_state[
                "authority_hashes"
            ],

        "observation_hashes":
            resolver_state[
                "observation_hashes"
            ],
    },

    "execution_observation": {
        "attempted":
            execution_attempted,

        "exception_captured":
            execution_exception_captured,

        "exception_type":
            execution_exception_type,

        "exception_message":
            execution_exception_message,

        "result_returned":
            result_returned,

        "executed":
            executed,

        "status":
            status,

        "reasons":
            reasons,

        "receipt_hashes":
            receipt_hashes,

        "outbox_before":
            outbox_before,

        "outbox_after":
            outbox_after,

        "outbox_snapshot":
            list(
                outbox_snapshot
            ),

        "consequence_committed":
            consequence_committed,

        "normal_execution_observed":
            normal_execution_observed,
    },

    "witness_observation": {
        "event_types":
            event_types,

        "timeline":
            timeline,

        "boundary_event_count":
            boundary_event_count,

        "commit_success_event_count":
            commit_success_event_count,

        "commit_failure_event_count":
            commit_failure_event_count,

        "completion_event_count":
            completion_event_count,

        "refusal_event_count":
            refusal_event_count,

        "chain_valid":
            chain_valid,

        "chain_errors":
            chain_errors,
    },

    "observation_presence_control_not_established":
        observation_presence_control_not_established,

    "bounded_interpretation": (
        "This deterministic test examines only whether the native "
        "AuthorityResolution representation and V06 runtime require "
        "observation presence for a supplied ESTABLISHED executable "
        "authority. It does not establish observation authenticity, "
        "resolver correctness, source authority, distributed consensus, "
        "jurisdictional freshness, external provenance, or production "
        "deployment behavior."
    ),
}


write_json(
    RESULT_PATH,
    result_document,
)


# ============================================================
# FREEZE
# ============================================================

freeze_document = {
    "test_id":
        TEST_ID,

    "freeze_type":
        "FIRST_OBSERVED_RESULT_FREEZE",

    "frozen_at_utc":
        utc_now(),

    "classification":
        classification,

    "repository_baseline_commit":
        "b86a0fb801b23198bf4760014f36b1559f614af4",

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

        "witness":
            (
                sha256_file(
                    WITNESS_PATH
                )
                if WITNESS_PATH.exists()
                else None
            ),

        **actual_source_hashes,
    },

    "no_retrospective_repair":
        True,
}


write_json(
    FREEZE_PATH,
    freeze_document,
)


for artifact in (
    RESULT_PATH,
    FREEZE_PATH,
):

    write_sidecar(
        artifact
    )


if WITNESS_PATH.exists():

    write_sidecar(
        WITNESS_PATH
    )


# ============================================================
# FIRST-OBSERVED OUTPUT
# ============================================================

print()
print(
    "=== P3-F06 FIRST OBSERVED RESULT ==="
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
    "helper_positive_passed:",
    helper_positive_passed,
)

print(
    "observationless_constructed:",
    observationless_constructed,
)

print(
    "observation_count:",
    (
        len(
            observationless_resolution.observations
        )
        if observationless_constructed
        else None
    ),
)

print(
    "resolver_calls:",
    resolver_state[
        "calls"
    ],
)

print(
    "resolver_statuses:",
    resolver_state[
        "statuses"
    ],
)

print(
    "resolver_observation_counts:",
    resolver_state[
        "observation_counts"
    ],
)

print(
    "executed:",
    executed,
)

print(
    "status:",
    status,
)

print(
    "reasons:",
    reasons,
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
    "boundary_event_count:",
    boundary_event_count,
)

print(
    "commit_success_event_count:",
    commit_success_event_count,
)

print(
    "commit_failure_event_count:",
    commit_failure_event_count,
)

print(
    "completion_event_count:",
    completion_event_count,
)

print(
    "refusal_event_count:",
    refusal_event_count,
)

print(
    "witness_chain_valid:",
    chain_valid,
)

print(
    "observation_presence_control_not_established:",
    observation_presence_control_not_established,
)

print()
print(
    "RESULT:",
    RESULT_PATH.relative_to(
        ROOT
    ),
)

print(
    "FREEZE:",
    FREEZE_PATH.relative_to(
        ROOT
    ),
)

print(
    "WITNESS:",
    WITNESS_PATH.relative_to(
        ROOT
    ),
)