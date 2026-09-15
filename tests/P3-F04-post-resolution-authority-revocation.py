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
from core.execution_firewall_v05 import ExecutionFirewallV05
from core.permit_v02 import PermitIssuerV02, PermitVerifierV02
from tools.broker_v05 import ToolBrokerV05, ToolRequestV05
from tools.messaging_demo import MessagingDemoTool
from witness.ledger import WitnessLedger


TEST_ID = "P3-F04"

EVIDENCE_DIR = Path(
    "evidence/phase-iii/p3-f04"
)

DEFINITION_PATH = (
    EVIDENCE_DIR
    / "P3-F04-TEST-DEFINITION-001.json"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P3-F04-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR
    / "P3-F04-FIRST-OBSERVED-FREEZE-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P3-F04-WITNESS-001.jsonl"
)


def utc_now():
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
        "P3-F04 FIRST-OBSERVED ARTIFACT ALREADY EXISTS."
    )
    print("REFUSING RERUN.")
    sys.exit(3)


# ============================================================
# MACHINE-OBSERVABLE TIMELINE
# ============================================================

timeline = []


class TimelineLedger(WitnessLedger):

    def __init__(
        self,
        path,
        timeline_ref,
    ):
        self._timeline_ref = timeline_ref
        super().__init__(path)

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
# INITIAL AUTHORITY
# ============================================================

initial_authority = AuthorityState.create(
    actor_id="P3-F04-HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)


live_authority = {
    "state": initial_authority,
}


resolver_state = {
    "calls": 0,
    "observed_hashes": [],
    "observed_epochs": [],
    "observed_statuses": [],
}


def authority_resolver():

    resolver_state["calls"] += 1

    state = live_authority["state"]

    resolver_state[
        "observed_hashes"
    ].append(
        state.state_hash()
    )

    resolver_state[
        "observed_epochs"
    ].append(
        state.epoch
    )

    resolver_state[
        "observed_statuses"
    ].append(
        state.status.value
    )

    timeline.append(
        "RESOLVER:"
        + state.status.value
        + ":EPOCH_"
        + str(state.epoch)
    )

    return AuthorityResolution.established(
        authority=state,
        reason=(
            "P3-F04_PRESENT_AUTHORITY_"
            "ESTABLISHED_AT_RESOLUTION"
        ),
    )


# ============================================================
# TOOL THAT REVOKES AUTHORITY BEFORE SIDE EFFECT COMMIT
# ============================================================

class RevokingMessagingDemoTool(
    MessagingDemoTool
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
    ) -> dict:

        self._timeline_ref.append(
            "ACTION_ENTERED"
        )

        current = (
            self._live_authority_ref[
                "state"
            ]
        )

        revoked = current.revoke_all(
            reason=(
                "P3-F04_POST_BOUNDARY_"
                "PRE_CONSEQUENCE_REVOCATION"
            )
        )

        self._live_authority_ref[
            "state"
        ] = revoked

        self.revoked_state = revoked

        self._timeline_ref.append(
            "AUTHORITY_REVOKED:"
            + revoked.status.value
            + ":EPOCH_"
            + str(revoked.epoch)
        )

        result = super().send(
            target=target,
            content=content,
        )

        self._timeline_ref.append(
            "SIDE_EFFECT_COMMITTED"
        )

        return result


# ============================================================
# NORMAL V05 STACK
# ============================================================

arguments = {
    "content":
        "P3-F04 POST-RESOLUTION REVOCATION TEST"
}


signing_key = (
    b"P3-F04-POST-RESOLUTION-TOCTOU-KEY-000001"
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
    RevokingMessagingDemoTool(
        live_authority,
        timeline,
    )
)


firewall = ExecutionFirewallV05(
    verifier=verifier,
    ledger=ledger,
    constitution_path=(
        ROOT
        / "constitution"
        / "constitution.yaml"
    ),
)


broker = ToolBrokerV05(
    firewall=firewall,
    messaging_tool=messaging_tool,
)


intent_hash = (
    "P3-F04-POST-RESOLUTION-REVOCATION-INTENT"
)


permit = issuer.issue(
    authority=initial_authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="P3-F04-RECIPIENT",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=arguments,
)


request = ToolRequestV05(
    permit=permit,

    current_authority=
        initial_authority,

    authority_resolver=
        authority_resolver,

    intent_hash=intent_hash,

    permission="SEND",

    policy_version=
        "ERA-POLICY-001-v0.2.0",

    target="P3-F04-RECIPIENT",

    tool_name="MESSAGING_DEMO",

    consequence_class="C4",

    arguments=arguments,
)


outbox_before = broker.outbox_size()


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
    exception_type = type(exc).__name__
    exception_message = str(exc)


outbox_after = broker.outbox_size()

outbox_snapshot = (
    broker.outbox_snapshot()
)


records = ledger.records()

chain_valid, chain_errors = (
    ledger.verify_chain()
)


event_types = [
    record.get("event_type")
    for record in records
]


# ============================================================
# OBSERVED STATES
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
    list(result.reasons)
    if result_returned
    else []
)


final_authority = (
    live_authority["state"]
)


authority_revoked = (
    final_authority.status.value
    == "REVOKED"
)


authority_epoch_advanced = (
    final_authority.epoch
    > initial_authority.epoch
)


resolver_called_once = (
    resolver_state["calls"]
    == 1
)


initial_resolution_was_active = (
    resolver_state[
        "observed_statuses"
    ]
    == ["ACTIVE"]
)


initial_resolution_epoch_one = (
    resolver_state[
        "observed_epochs"
    ]
    == [1]
)


boundary_event_count = (
    event_types.count(
        "CONSEQUENCE_BOUNDARY_REVALIDATED"
    )
)


completion_event_count = (
    event_types.count(
        "EXECUTION_COMPLETED"
    )
)


boundary_event_present_once = (
    boundary_event_count == 1
)


completion_event_present_once = (
    completion_event_count == 1
)


def position(prefix: str):

    for index, item in enumerate(
        timeline
    ):
        if item.startswith(prefix):
            return index

    return None


resolver_position = position(
    "RESOLVER:"
)

boundary_position = position(
    "WITNESS:CONSEQUENCE_BOUNDARY_REVALIDATED"
)

action_position = position(
    "ACTION_ENTERED"
)

revocation_position = position(
    "AUTHORITY_REVOKED:"
)

side_effect_position = position(
    "SIDE_EFFECT_COMMITTED"
)

completion_position = position(
    "WITNESS:EXECUTION_COMPLETED"
)


ordering_observed = (
    resolver_position is not None
    and
    boundary_position is not None
    and
    action_position is not None
    and
    revocation_position is not None
    and
    side_effect_position is not None
    and
    resolver_position
        < boundary_position
        < action_position
        < revocation_position
        < side_effect_position
)


completion_after_side_effect = (
    completion_position is not None
    and
    side_effect_position is not None
    and
    side_effect_position
        < completion_position
)


consequence_committed = (
    outbox_before == 0
    and
    outbox_after == 1
)


revocation_before_consequence = (
    revocation_position is not None
    and
    side_effect_position is not None
    and
    revocation_position
        < side_effect_position
)


post_resolution_revocation_not_contained = (
    not exception_captured
    and
    resolver_called_once
    and
    initial_resolution_was_active
    and
    initial_resolution_epoch_one
    and
    boundary_event_present_once
    and
    authority_revoked
    and
    authority_epoch_advanced
    and
    revocation_before_consequence
    and
    ordering_observed
    and
    consequence_committed
    and
    executed is True
    and
    status == "EXECUTED"
    and
    completion_event_present_once
    and
    completion_after_side_effect
    and
    chain_valid
)


post_resolution_revocation_contained = (
    authority_revoked
    and
    revocation_before_consequence
    and
    outbox_after == outbox_before
    and
    executed is False
)


if post_resolution_revocation_not_contained:

    classification = (
        "POST_RESOLUTION_AUTHORITY_REVOCATION_"
        "CONSEQUENCE_NOT_CONTAINED"
    )

elif post_resolution_revocation_contained:

    classification = (
        "POST_RESOLUTION_AUTHORITY_REVOCATION_"
        "CONSEQUENCE_CONTAINED"
    )

else:

    classification = (
        "POST_RESOLUTION_AUTHORITY_REVOCATION_"
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
            resolver_state["calls"],

        "called_once":
            resolver_called_once,

        "observed_hashes":
            resolver_state[
                "observed_hashes"
            ],

        "observed_epochs":
            resolver_state[
                "observed_epochs"
            ],

        "observed_statuses":
            resolver_state[
                "observed_statuses"
            ],
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

        "outbox_before":
            outbox_before,

        "outbox_after":
            outbox_after,

        "outbox_snapshot":
            list(outbox_snapshot),

        "consequence_committed":
            consequence_committed,
    },

    "timeline_observation": {
        "timeline":
            timeline,

        "resolver_position":
            resolver_position,

        "boundary_position":
            boundary_position,

        "action_position":
            action_position,

        "revocation_position":
            revocation_position,

        "side_effect_position":
            side_effect_position,

        "completion_position":
            completion_position,

        "ordering_observed":
            ordering_observed,

        "revocation_before_consequence":
            revocation_before_consequence,

        "completion_after_side_effect":
            completion_after_side_effect,
    },

    "witness_observation": {
        "event_types":
            event_types,

        "boundary_event_present_once":
            boundary_event_present_once,

        "completion_event_present_once":
            completion_event_present_once,

        "chain_valid":
            chain_valid,

        "chain_errors":
            chain_errors,
    },

    "post_resolution_revocation_not_contained":
        post_resolution_revocation_not_contained,

    "post_resolution_revocation_contained":
        post_resolution_revocation_contained,

    "bounded_interpretation": (
        "This deterministic local test evaluates the V05 interval "
        "after an ESTABLISHED authority resolution and consequence-"
        "boundary revalidation but before the MessagingDemoTool "
        "side effect. A finding that consequence was not contained "
        "means only that V05 did not perform another authority "
        "resolution within this tested local interval. It does not "
        "establish behaviour of production networks, distributed "
        "revocation systems, operating-system primitives, or "
        "transactional external tools."
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

    handle.write("\n")


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

        "execution_firewall_v05":
            sha256_file(
                ROOT
                / "core"
                / "execution_firewall_v05.py"
            ),

        "broker_v05":
            sha256_file(
                ROOT
                / "tools"
                / "broker_v05.py"
            ),

        "messaging_demo":
            sha256_file(
                ROOT
                / "tools"
                / "messaging_demo.py"
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

    handle.write("\n")


for path in (
    DEFINITION_PATH,
    Path(__file__),
    RESULT_PATH,
    WITNESS_PATH,
    FREEZE_PATH,
):
    sidecar = Path(
        str(path) + ".sha256"
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
    "=== P3-F04 FIRST OBSERVED RESULT ==="
)

print(
    "classification:",
    classification,
)

print(
    "resolver_calls:",
    resolver_state["calls"],
)

print(
    "resolver_observed_statuses:",
    resolver_state["observed_statuses"],
)

print(
    "resolver_observed_epochs:",
    resolver_state["observed_epochs"],
)

print(
    "boundary_event_present_once:",
    boundary_event_present_once,
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
    "revocation_before_consequence:",
    revocation_before_consequence,
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
    "witness_chain_valid:",
    chain_valid,
)

print(
    "post_resolution_revocation_not_contained:",
    post_resolution_revocation_not_contained,
)

print(
    "post_resolution_revocation_contained:",
    post_resolution_revocation_contained,
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
