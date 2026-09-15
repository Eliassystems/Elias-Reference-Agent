from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


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


TEST_ID = "P3-F05"

EVIDENCE_DIR = Path(
    "evidence/phase-iii/p3-f05"
)

DEFINITION_PATH = (
    EVIDENCE_DIR
    / "P3-F05-TEST-DEFINITION-001.json"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P3-F05-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR
    / "P3-F05-FIRST-OBSERVED-FREEZE-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P3-F05-WITNESS-001.jsonl"
)


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(65536),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest().upper()


# ============================================================
# SECONDARY FIRST-OBSERVATION GUARD
# ============================================================

if (
    RESULT_PATH.exists()
    or FREEZE_PATH.exists()
    or WITNESS_PATH.exists()
):
    print(
        "P3-F05 FIRST-OBSERVED ARTIFACT ALREADY EXISTS."
    )
    print(
        "REFUSING RERUN."
    )
    sys.exit(3)


# ============================================================
# STATES
# ============================================================

active_authority = (
    AuthorityState.create(
        actor_id=
            "P3-F05-HUMAN-001",

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
            "P3-F05_CONTRADICTORY_"
            "SAME_LINEAGE_REVOKED_OBSERVATION"
        )
    )
)


# ============================================================
# NATIVE INCOHERENT ESTABLISHED RESOLUTION
#
# No harness wrapper or fake type:
# this uses AuthorityResolution directly.
# ============================================================

incoherent_resolution = (
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
            "P3-F05_ESTABLISHED_WITH_"
            "CONTRADICTORY_NATIVE_OBSERVATIONS"
        ),
    )
)


resolution_constructed = (
    isinstance(
        incoherent_resolution,
        AuthorityResolution,
    )
)


resolution_status_established = (
    incoherent_resolution.status
    == AuthorityResolutionStatus.ESTABLISHED
)


resolution_carries_active_authority = (
    incoherent_resolution.authority
    is not None
    and
    incoherent_resolution.authority.state_hash()
    == active_authority.state_hash()
)


two_observations_preserved = (
    len(
        incoherent_resolution.observations
    )
    == 2
)


same_lineage = (
    active_authority.actor_id
    == revoked_observation.actor_id
    and
    active_authority.authority_source
    == revoked_observation.authority_source
)


status_conflict_present = (
    active_authority.status.value
    != revoked_observation.status.value
)


epoch_conflict_present = (
    active_authority.epoch
    != revoked_observation.epoch
)


permission_conflict_present = (
    active_authority.permissions
    != revoked_observation.permissions
)


hash_conflict_present = (
    active_authority.state_hash()
    != revoked_observation.state_hash()
)


contradictory_observations_present = (
    same_lineage
    and
    status_conflict_present
    and
    epoch_conflict_present
    and
    permission_conflict_present
    and
    hash_conflict_present
)


native_incoherent_established_representation = (
    resolution_constructed
    and
    resolution_status_established
    and
    resolution_carries_active_authority
    and
    two_observations_preserved
    and
    contradictory_observations_present
)


# ============================================================
# TIMELINE WITNESS
# ============================================================

timeline = []


class TimelineLedger(WitnessLedger):

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
                + str(event_type)
            )

        return record


resolver_state = {
    "calls": 0,
    "resolution_hashes": [],
    "statuses": [],
    "authority_hashes": [],
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

    resolver_state[
        "resolution_hashes"
    ].append(
        incoherent_resolution.state_hash()
    )

    resolver_state[
        "statuses"
    ].append(
        incoherent_resolution.status.value
    )

    resolver_state[
        "authority_hashes"
    ].append(
        incoherent_resolution.authority.state_hash()
    )

    resolver_state[
        "observation_hashes"
    ].append(
        [
            observation.state_hash()
            for observation
            in incoherent_resolution.observations
        ]
    )

    timeline.append(
        "RESOLVER_CALL_"
        + str(call_number)
        + ":"
        + incoherent_resolution.status.value
        + ":OBSERVATIONS_"
        + str(
            len(
                incoherent_resolution.observations
            )
        )
    )

    return incoherent_resolution


# ============================================================
# NORMAL V06 STACK
# ============================================================

arguments = {
    "content":
        "P3-F05 ESTABLISHED RESOLUTION COHERENCE TEST"
}


signing_key = (
    b"P3-F05-ESTABLISHED-COHERENCE-KEY-000001"
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
    "P3-F05-ESTABLISHED-RESOLUTION-COHERENCE-INTENT"
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
        "P3-F05-RECIPIENT",

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
        "P3-F05-RECIPIENT",

    tool_name=
        "MESSAGING_DEMO",

    consequence_class=
        "C4",

    arguments=
        arguments,
)


outbox_before = (
    broker.outbox_size()
)


exception_captured = False
exception_type = ""
exception_message = ""
result = None


try:

    result = broker.execute(
        request
    )

except Exception as exc:

    exception_captured = True

    exception_type = (
        type(exc).__name__
    )

    exception_message = (
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
    not exception_captured
    and
    result_returned
    and
    executed is True
    and
    status == "EXECUTED"
    and
    len(reasons) == 0
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
    chain_valid
)


coherence_control_not_established = (
    native_incoherent_established_representation
    and
    normal_execution_observed
)


contained_without_execution = (
    native_incoherent_established_representation
    and
    outbox_after == outbox_before
    and
    executed is False
)


if coherence_control_not_established:

    classification = (
        "INCOHERENT_ESTABLISHED_RESOLUTION_EXECUTED__"
        "COHERENCE_CONTROL_NOT_ESTABLISHED"
    )

elif contained_without_execution:

    classification = (
        "INCOHERENT_ESTABLISHED_RESOLUTION_CONTAINED__"
        "CAUSE_REQUIRES_ANALYSIS"
    )

else:

    classification = (
        "INCOHERENT_ESTABLISHED_RESOLUTION_"
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

    "resolution_representation": {
        "native_authority_resolution":
            resolution_constructed,

        "status":
            incoherent_resolution.status.value,

        "reason":
            incoherent_resolution.reason,

        "state_hash":
            incoherent_resolution.state_hash(),

        "canonical_payload":
            incoherent_resolution.canonical_payload(),

        "executable_authority_hash":
            incoherent_resolution.authority.state_hash(),

        "observation_count":
            len(
                incoherent_resolution.observations
            ),

        "observation_hashes": [
            observation.state_hash()
            for observation
            in incoherent_resolution.observations
        ],

        "same_lineage":
            same_lineage,

        "status_conflict_present":
            status_conflict_present,

        "epoch_conflict_present":
            epoch_conflict_present,

        "permission_conflict_present":
            permission_conflict_present,

        "hash_conflict_present":
            hash_conflict_present,

        "contradictory_observations_present":
            contradictory_observations_present,

        "native_incoherent_established_representation":
            native_incoherent_established_representation,
    },

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

        "both_resolutions_established":
            both_resolutions_established,
    },

    "execution_observation": {
        "exception_captured":
            exception_captured,

        "exception_type":
            exception_type,

        "exception_message":
            exception_message,

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

    "coherence_control_not_established":
        coherence_control_not_established,

    "bounded_interpretation": (
        "This local deterministic test asks only whether the native "
        "AuthorityResolution representation and V06 runtime enforce "
        "coherence between an ESTABLISHED executable authority and the "
        "observations carried by that same supplied resolution. It does "
        "not establish that a production resolver would generate such a "
        "resolution, nor does it prove observation authenticity, "
        "distributed consensus, freshness, or external provenance."
    ),
}


with RESULT_PATH.open(
    "w",
    encoding="utf-8",
) as handle:

    json.dump(
        result_document,
        handle,
        indent=2,
        sort_keys=True,
    )

    handle.write(
        "\n"
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
        "0cc0f62",

    "v06_source_commit":
        "4cd1394",

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
            sha256_file(
                WITNESS_PATH
            ),

        "authority_resolution":
            sha256_file(
                ROOT
                / "core"
                / "authority_resolution.py"
            ),

        "execution_firewall_v06":
            sha256_file(
                ROOT
                / "core"
                / "execution_firewall_v06.py"
            ),

        "broker_v06":
            sha256_file(
                ROOT
                / "tools"
                / "broker_v06.py"
            ),

        "messaging_demo_v06":
            sha256_file(
                ROOT
                / "tools"
                / "messaging_demo_v06.py"
            ),

        "permit_v02":
            sha256_file(
                ROOT
                / "core"
                / "permit_v02.py"
            ),
    },

    "no_retrospective_repair":
        True,
}


with FREEZE_PATH.open(
    "w",
    encoding="utf-8",
) as handle:

    json.dump(
        freeze_document,
        handle,
        indent=2,
        sort_keys=True,
    )

    handle.write(
        "\n"
    )


# ============================================================
# SIDECARS
# ============================================================

for path in (
    DEFINITION_PATH,
    Path(__file__),
    RESULT_PATH,
    WITNESS_PATH,
    FREEZE_PATH,
):

    sidecar = Path(
        str(path)
        + ".sha256"
    )

    sidecar.write_text(
        sha256_file(path)
        + "  "
        + path.name
        + "\n",
        encoding="utf-8",
    )


# ============================================================
# FIRST-OBSERVED OUTPUT
# ============================================================

print()
print(
    "=== P3-F05 FIRST OBSERVED RESULT ==="
)

print(
    "classification:",
    classification,
)

print(
    "resolution_constructed:",
    resolution_constructed,
)

print(
    "resolution_status:",
    incoherent_resolution.status.value,
)

print(
    "resolution_authority_status:",
    incoherent_resolution.authority.status.value,
)

print(
    "observation_count:",
    len(
        incoherent_resolution.observations
    ),
)

print(
    "observation_statuses:",
    [
        observation.status.value
        for observation
        in incoherent_resolution.observations
    ],
)

print(
    "observation_epochs:",
    [
        observation.epoch
        for observation
        in incoherent_resolution.observations
    ],
)

print(
    "contradictory_observations_present:",
    contradictory_observations_present,
)

print(
    "native_incoherent_established_representation:",
    native_incoherent_established_representation,
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
    "receipt_hash_count:",
    len(
        receipt_hashes
    ),
)

print(
    "coherence_control_not_established:",
    coherence_control_not_established,
)

print()
print(
    "RESULT:",
    RESULT_PATH,
)

print(
    "FREEZE:",
    FREEZE_PATH,
)

print(
    "WITNESS:",
    WITNESS_PATH,
)
