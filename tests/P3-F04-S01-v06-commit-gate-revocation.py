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


TEST_ID = "P3-F04-S01"

EVIDENCE_DIR = Path(
    "evidence/phase-iii/p3-f04-s01"
)

DEFINITION_PATH = (
    EVIDENCE_DIR
    / "P3-F04-S01-TEST-DEFINITION-001.json"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P3-F04-S01-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR
    / "P3-F04-S01-FIRST-OBSERVED-FREEZE-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P3-F04-S01-WITNESS-001.jsonl"
)


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def sha256_file(path: Path) -> str:

    digest = hashlib.sha256()

    with path.open(
        "rb"
    ) as handle:

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
        "P3-F04-S01 FIRST-OBSERVED ARTIFACT ALREADY EXISTS."
    )
    print(
        "REFUSING RERUN."
    )
    sys.exit(3)


# ============================================================
# TIMELINE LEDGER
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
                + str(event_type)
            )

        return record


# ============================================================
# LIVE AUTHORITY
# ============================================================

initial_authority = (
    AuthorityState.create(
        actor_id=
            "P3-F04-S01-HUMAN-001",

        authority_source=
            "HUMAN_SOVEREIGN_AUTHORITY",

        permissions={
            "SEND"
        },

        epoch=1,
    )
)


live_authority = {
    "state":
        initial_authority,
}


resolver_state = {
    "calls":
        0,

    "authority_statuses":
        [],

    "authority_epochs":
        [],

    "authority_hashes":
        [],

    "resolution_statuses":
        [],
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

    state = (
        live_authority[
            "state"
        ]
    )

    resolution = (
        AuthorityResolution.established(
            authority=state,

            reason=(
                "P3-F04-S01_"
                "AUTHORITY_OBSERVED_AT_"
                "RESOLUTION_CALL_"
                + str(call_number)
            ),
        )
    )

    resolver_state[
        "authority_statuses"
    ].append(
        state.status.value
    )

    resolver_state[
        "authority_epochs"
    ].append(
        state.epoch
    )

    resolver_state[
        "authority_hashes"
    ].append(
        state.state_hash()
    )

    resolver_state[
        "resolution_statuses"
    ].append(
        resolution.status.value
    )

    timeline.append(
        "RESOLVER_CALL_"
        + str(call_number)
        + ":"
        + state.status.value
        + ":EPOCH_"
        + str(state.epoch)
    )

    return resolution


# ============================================================
# ADVERSARIAL V06 TOOL
#
# Revoke after V06 boundary validation but BEFORE parent
# MessagingDemoToolV06 invokes commit_gate().
# ============================================================

class RevokingMessagingDemoToolV06(
    MessagingDemoToolV06
):

    def __init__(
        self,
        live_authority_ref,
        timeline_ref,
    ):

        super().__init__()

        self._live_authority_ref = (
            live_authority_ref
        )

        self._timeline_ref = (
            timeline_ref
        )

        self.revoked_state = None

    def send(
        self,
        *,
        target: str,
        content: str,
        commit_gate,
    ) -> dict:

        self._timeline_ref.append(
            "ACTION_ENTERED"
        )

        current = (
            self._live_authority_ref[
                "state"
            ]
        )

        revoked = (
            current.revoke_all(
                reason=(
                    "P3-F04-S01_"
                    "POST_BOUNDARY_"
                    "PRE_COMMIT_GATE_REVOCATION"
                )
            )
        )

        self._live_authority_ref[
            "state"
        ] = revoked

        self.revoked_state = (
            revoked
        )

        self._timeline_ref.append(
            "AUTHORITY_REVOKED:"
            + revoked.status.value
            + ":EPOCH_"
            + str(revoked.epoch)
        )

        result = super().send(
            target=target,
            content=content,
            commit_gate=commit_gate,
        )

        self._timeline_ref.append(
            "SIDE_EFFECT_COMMITTED"
        )

        return result


# ============================================================
# NORMAL V06 STACK
# ============================================================

arguments = {
    "content":
        "P3-F04-S01 V06 COMMIT-GATE REVOCATION TEST"
}


signing_key = (
    b"P3-F04-S01-V06-COMMIT-GATE-KEY-000001"
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
    RevokingMessagingDemoToolV06(
        live_authority,
        timeline,
    )
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
    "P3-F04-S01-V06-COMMIT-GATE-REVOCATION-INTENT"
)


permit = issuer.issue(
    authority=
        initial_authority,

    intent_hash=
        intent_hash,

    permission=
        "SEND",

    policy_version=
        "ERA-POLICY-001-v0.2.0",

    target=
        "P3-F04-S01-RECIPIENT",

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
        initial_authority,

    authority_resolver=
        authority_resolver,

    intent_hash=
        intent_hash,

    permission=
        "SEND",

    policy_version=
        "ERA-POLICY-001-v0.2.0",

    target=
        "P3-F04-S01-RECIPIENT",

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


# ============================================================
# OBSERVATIONS
# ============================================================

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


final_authority = (
    live_authority[
        "state"
    ]
)


authority_revoked = (
    final_authority.status.value
    == "REVOKED"
)


authority_epoch_advanced = (
    final_authority.epoch
    > initial_authority.epoch
)


resolver_called_twice = (
    resolver_state[
        "calls"
    ]
    == 2
)


resolver_state_sequence = (
    resolver_state[
        "authority_statuses"
    ]
    == [
        "ACTIVE",
        "REVOKED",
    ]
)


resolver_epoch_sequence = (
    resolver_state[
        "authority_epochs"
    ]
    == [
        1,
        2,
    ]
)


resolution_status_sequence = (
    resolver_state[
        "resolution_statuses"
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


commit_failure_event_count = (
    event_types.count(
        "CONSEQUENCE_COMMIT_AUTHORITY_REVALIDATION_FAILED"
    )
)


commit_success_event_count = (
    event_types.count(
        "CONSEQUENCE_COMMIT_AUTHORITY_REVALIDATED"
    )
)


refusal_event_count = (
    event_types.count(
        "EXECUTION_REFUSED"
    )
)


completion_event_count = (
    event_types.count(
        "EXECUTION_COMPLETED"
    )
)


def position(
    prefix: str
):

    for index, item in enumerate(
        timeline
    ):

        if item.startswith(
            prefix
        ):
            return index

    return None


initial_resolver_position = (
    position(
        "RESOLVER_CALL_1:"
    )
)


boundary_position = (
    position(
        "WITNESS:CONSEQUENCE_BOUNDARY_REVALIDATED"
    )
)


action_position = (
    position(
        "ACTION_ENTERED"
    )
)


revocation_position = (
    position(
        "AUTHORITY_REVOKED:"
    )
)


commit_resolver_position = (
    position(
        "RESOLVER_CALL_2:"
    )
)


commit_failure_position = (
    position(
        "WITNESS:CONSEQUENCE_COMMIT_AUTHORITY_REVALIDATION_FAILED"
    )
)


refusal_position = (
    position(
        "WITNESS:EXECUTION_REFUSED"
    )
)


side_effect_position = (
    position(
        "SIDE_EFFECT_COMMITTED"
    )
)


ordering_observed = (
    initial_resolver_position
        is not None
    and boundary_position
        is not None
    and action_position
        is not None
    and revocation_position
        is not None
    and commit_resolver_position
        is not None
    and commit_failure_position
        is not None
    and refusal_position
        is not None
    and (
        initial_resolver_position
        < boundary_position
        < action_position
        < revocation_position
        < commit_resolver_position
        < commit_failure_position
        < refusal_position
    )
)


required_reasons = {
    "COMMIT_AUTHORITY_REVALIDATION_FAILED",
    "AUTHORITY_EPOCH_CHANGED",
    "AUTHORITY_STATE_HASH_CHANGED",
    "CURRENT_PERMISSION_NOT_ESTABLISHED",
}


required_reasons_present = (
    required_reasons.issubset(
        set(reasons)
    )
)


consequence_contained = (
    outbox_before == 0
    and
    outbox_after == 0
    and
    side_effect_position is None
)


successor_control_established = (
    not exception_captured
    and
    resolver_called_twice
    and
    resolver_state_sequence
    and
    resolver_epoch_sequence
    and
    resolution_status_sequence
    and
    boundary_event_count == 1
    and
    authority_revoked
    and
    authority_epoch_advanced
    and
    ordering_observed
    and
    commit_failure_event_count == 1
    and
    commit_success_event_count == 0
    and
    refusal_event_count == 1
    and
    completion_event_count == 0
    and
    consequence_contained
    and
    executed is False
    and
    status
        == "REFUSED_BEFORE_CONSEQUENCE"
    and
    required_reasons_present
    and
    chain_valid
)


successor_control_defeated = (
    authority_revoked
    and
    side_effect_position
        is not None
    and
    outbox_after
        > outbox_before
)


if successor_control_established:

    classification = (
        "V06_COMMIT_GATE_POST_BOUNDARY_"
        "REVOCATION_CONTAINMENT_ESTABLISHED"
    )

elif successor_control_defeated:

    classification = (
        "V06_COMMIT_GATE_POST_BOUNDARY_"
        "REVOCATION_CONTAINMENT_NOT_ESTABLISHED"
    )

else:

    classification = (
        "V06_COMMIT_GATE_POST_BOUNDARY_"
        "REVOCATION_FIRST_OBSERVATION_INDETERMINATE"
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

    "initial_authority": {
        "canonical_payload":
            initial_authority.canonical_payload(),

        "state_hash":
            initial_authority.state_hash(),
    },

    "final_live_authority": {
        "canonical_payload":
            final_authority.canonical_payload(),

        "state_hash":
            final_authority.state_hash(),

        "revoked":
            authority_revoked,

        "epoch_advanced":
            authority_epoch_advanced,
    },

    "resolver_observation": {
        "calls":
            resolver_state[
                "calls"
            ],

        "called_twice":
            resolver_called_twice,

        "authority_statuses":
            resolver_state[
                "authority_statuses"
            ],

        "authority_epochs":
            resolver_state[
                "authority_epochs"
            ],

        "authority_hashes":
            resolver_state[
                "authority_hashes"
            ],

        "resolution_statuses":
            resolver_state[
                "resolution_statuses"
            ],

        "expected_live_state_sequence_observed":
            resolver_state_sequence,

        "expected_epoch_sequence_observed":
            resolver_epoch_sequence,

        "resolution_status_sequence_observed":
            resolution_status_sequence,
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

        "required_reasons_present":
            required_reasons_present,

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

        "consequence_contained":
            consequence_contained,
    },

    "timeline_observation": {
        "timeline":
            timeline,

        "initial_resolver_position":
            initial_resolver_position,

        "boundary_position":
            boundary_position,

        "action_position":
            action_position,

        "revocation_position":
            revocation_position,

        "commit_resolver_position":
            commit_resolver_position,

        "commit_failure_position":
            commit_failure_position,

        "refusal_position":
            refusal_position,

        "side_effect_position":
            side_effect_position,

        "ordering_observed":
            ordering_observed,
    },

    "witness_observation": {
        "event_types":
            event_types,

        "boundary_event_count":
            boundary_event_count,

        "commit_failure_event_count":
            commit_failure_event_count,

        "commit_success_event_count":
            commit_success_event_count,

        "refusal_event_count":
            refusal_event_count,

        "completion_event_count":
            completion_event_count,

        "chain_valid":
            chain_valid,

        "chain_errors":
            chain_errors,
    },

    "successor_control_established":
        successor_control_established,

    "successor_control_defeated":
        successor_control_defeated,

    "bounded_interpretation": (
        "This deterministic local successor test evaluates whether "
        "V06 contains the specific P3-F04 condition by requiring "
        "authority resolution and permit revalidation inside the "
        "registered MessagingDemoToolV06 commit path immediately "
        "before local outbox mutation. A containment result establishes "
        "only this tested local runtime behaviour. It does not establish "
        "distributed consensus, external network revocation propagation, "
        "operating-system atomicity, external-service transactionality, "
        "or elimination of every possible check-to-use interval."
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

    "antecedent": {
        "p3_f04_result_sha256":
            sha256_file(
                ROOT
                / "evidence"
                / "phase-iii"
                / "p3-f04"
                / "P3-F04-FIRST-OBSERVED-RESULT-001.json"
            ),

        "execution_firewall_v05_sha256":
            sha256_file(
                ROOT
                / "core"
                / "execution_firewall_v05.py"
            ),
    },

    "successor_source_commit":
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
# FIRST OBSERVED OUTPUT
# ============================================================

print()
print(
    "=== P3-F04-S01 FIRST OBSERVED RESULT ==="
)

print(
    "classification:",
    classification,
)

print(
    "resolver_calls:",
    resolver_state[
        "calls"
    ],
)

print(
    "resolver_authority_statuses:",
    resolver_state[
        "authority_statuses"
    ],
)

print(
    "resolver_authority_epochs:",
    resolver_state[
        "authority_epochs"
    ],
)

print(
    "resolver_resolution_statuses:",
    resolver_state[
        "resolution_statuses"
    ],
)

print(
    "authority_revoked:",
    authority_revoked,
)

print(
    "final_authority_epoch:",
    final_authority.epoch,
)

print(
    "ordering_observed:",
    ordering_observed,
)

print(
    "timeline:",
    timeline,
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
    "required_reasons_present:",
    required_reasons_present,
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
    "consequence_contained:",
    consequence_contained,
)

print(
    "commit_failure_event_count:",
    commit_failure_event_count,
)

print(
    "commit_success_event_count:",
    commit_success_event_count,
)

print(
    "completion_event_count:",
    completion_event_count,
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
    "successor_control_established:",
    successor_control_established,
)

print(
    "successor_control_defeated:",
    successor_control_defeated,
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
