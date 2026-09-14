from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import sys


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from core.authority import (
    AuthorityState,
    AuthorityStatus,
)
from core.permit_v02 import (
    PermitIssuerV02,
    PermitVerifierV02,
)
from core.execution_firewall_v03 import (
    ExecutionFirewallV03,
)
from tools.broker_v03 import (
    ToolBrokerV03,
    ToolRequestV03,
)
from tools.messaging_demo import MessagingDemoTool
from witness.ledger import WitnessLedger


TEST_ID = "P2-H01-R01"

PERMISSION = "SEND"
POLICY_VERSION = "P2-H01-R01-001"

TARGET = "p2-h01-r01@example.test"
TOOL = "MESSAGING_DEMO"
CONSEQUENCE_CLASS = "EXTERNAL_WRITE"

EVIDENCE_DIR = Path(
    "evidence/phase-ii/p2-h01/remediation-001"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P2-H01-R01-FIRST-OBSERVED-RESULT-001.json"
)

LEDGER_PATH = (
    EVIDENCE_DIR
    / "P2-H01-R01-WITNESS-001.jsonl"
)

EVIDENCE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

if RESULT_PATH.exists() or LEDGER_PATH.exists():
    print(
        "P2-H01-R01 FIRST-OBSERVED "
        "ARTIFACT ALREADY EXISTS."
    )
    print("REFUSING RERUN.")
    sys.exit(3)


def utc_now() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


authority_t0 = None
active_status = None

for candidate in AuthorityStatus:

    probe = AuthorityState(
        actor_id="P2-H01-R01-ACTOR",
        authority_source=
            "P2-H01-R01-HARNESS",
        epoch=1,
        permissions=
            frozenset({PERMISSION}),
        status=candidate,
        reason=
            "P2_H01_R01_INITIAL_AUTHORITY",
    )

    if probe.has_authority(PERMISSION):
        authority_t0 = probe
        active_status = candidate
        break


if authority_t0 is None:
    raise RuntimeError(
        "HARNESS_COULD_NOT_CONSTITUTE_VALID_SEND_AUTHORITY"
    )


authority_t1 = AuthorityState(
    actor_id=
        authority_t0.actor_id,
    authority_source=
        authority_t0.authority_source,
    epoch=
        authority_t0.epoch + 1,
    permissions=
        frozenset(),
    status=
        active_status,
    reason=
        "P2_H01_R01_SEND_REMOVED_AFTER_PREAUTH",
)


if authority_t1.has_authority(PERMISSION):
    raise RuntimeError(
        "HARNESS_CHANGED_STATE_STILL_HAS_SEND_AUTHORITY"
    )


live_state = {
    "authority":
        authority_t0,
    "change_triggered":
        False,
    "changed_at_event":
        None,
}


class PostValidationMutationLedger(
    WitnessLedger
):

    def append(
        self,
        *args,
        **kwargs,
    ):

        record = super().append(
            *args,
            **kwargs,
        )

        if (
            kwargs.get("event_type")
            == "PRE_EXECUTION_AUTHORIZED"
        ):
            live_state["authority"] = (
                authority_t1
            )
            live_state["change_triggered"] = (
                True
            )
            live_state["changed_at_event"] = (
                "PRE_EXECUTION_AUTHORIZED"
            )

        return record


signing_key = (
    b"P2-H01-R01-DETERMINISTIC-SIGNING-KEY-00000001"
)

issuer = PermitIssuerV02(
    signing_key=signing_key
)

verifier = PermitVerifierV02(
    signing_key=signing_key
)

ledger = PostValidationMutationLedger(
    LEDGER_PATH
)

firewall = ExecutionFirewallV03(
    verifier=verifier,
    ledger=ledger,
    constitution_path=(
        ROOT
        / "constitution"
        / "constitution.yaml"
    ),
)

messaging_tool = MessagingDemoTool()

broker = ToolBrokerV03(
    firewall=firewall,
    messaging_tool=messaging_tool,
)

objective = (
    "P2-H01-R01 deterministic consequence "
    "boundary authority revalidation test"
)

intent_hash = hashlib.sha256(
    objective.encode("utf-8")
).hexdigest().upper()

arguments = {
    "content":
        "P2-H01-R01 consequence payload"
}

permit = issuer.issue(
    authority=
        authority_t0,
    intent_hash=
        intent_hash,
    permission=
        PERMISSION,
    policy_version=
        POLICY_VERSION,
    target=
        TARGET,
    tool=
        TOOL,
    consequence_class=
        CONSEQUENCE_CLASS,
    arguments=
        arguments,
    ttl_seconds=300,
)

request = ToolRequestV03(
    permit=
        permit,
    current_authority=
        authority_t0,

    # Critical difference from v0.2:
    # this resolves the authoritative state
    # at the actual consequence boundary.
    authority_resolver=
        lambda:
            live_state["authority"],

    intent_hash=
        intent_hash,
    permission=
        PERMISSION,
    policy_version=
        POLICY_VERSION,
    target=
        TARGET,
    tool_name=
        TOOL,
    consequence_class=
        CONSEQUENCE_CLASS,
    arguments=
        arguments,
)

outbox_before = broker.outbox_size()

result = broker.execute(
    request
)

outbox_after = broker.outbox_size()

boundary_authority = (
    live_state["authority"]
)

boundary_send = (
    boundary_authority.has_authority(
        PERMISSION
    )
)

consequence_occurred = (
    outbox_after
    > outbox_before
)

chain_valid, chain_errors = (
    ledger.verify_chain()
)

reasons = list(
    result.reasons
)

required_reasons_present = (
    "AUTHORITY_EPOCH_CHANGED"
    in reasons
    and
    "AUTHORITY_STATE_HASH_CHANGED"
    in reasons
    and
    "CURRENT_PERMISSION_NOT_ESTABLISHED"
    in reasons
)

remediation_pass = (
    live_state["change_triggered"]
    and
    authority_t0.epoch
    != boundary_authority.epoch
    and
    not boundary_send
    and
    not result.executed
    and
    not consequence_occurred
    and
    outbox_before == 0
    and
    outbox_after == 0
    and
    required_reasons_present
    and
    chain_valid
)

classification = (
    "REMEDIATION_PASS"
    if remediation_pass
    else "REMEDIATION_NOT_ESTABLISHED"
)

evidence = {
    "test_id":
        TEST_ID,

    "classification":
        classification,

    "observed_at_utc":
        utc_now(),

    "predecessor_finding":
        "P2-H01_SEAM_EXPOSED",

    "predecessor_result_sha256":
        "40C34A1D8ECE5903B2CF62FF100CE17447868F1B7338A4435E800447998BF9DD",

    "predecessor_freeze_sha256":
        "53995866D1D250697276A5A64F6DA52752F4EB30278BD06DA391765C2E068E61",

    "attack":
        (
            "Authority changes immediately after "
            "PRE_EXECUTION_AUTHORIZED and before "
            "the consequence callable."
        ),

    "authority_t0": {
        "epoch":
            authority_t0.epoch,
        "permission_send":
            authority_t0.has_authority(
                PERMISSION
            ),
        "state_hash":
            authority_t0.state_hash(),
    },

    "authority_at_consequence_boundary": {
        "epoch":
            boundary_authority.epoch,
        "permission_send":
            boundary_send,
        "state_hash":
            boundary_authority.state_hash(),
    },

    "change_triggered":
        live_state["change_triggered"],

    "changed_at_event":
        live_state["changed_at_event"],

    "permit_authority_epoch":
        permit.authority_epoch,

    "firewall_status":
        result.status,

    "firewall_executed":
        result.executed,

    "firewall_reasons":
        reasons,

    "outbox_before":
        outbox_before,

    "outbox_after":
        outbox_after,

    "consequence_occurred":
        consequence_occurred,

    "required_reasons_present":
        required_reasons_present,

    "witness_chain_valid":
        chain_valid,

    "witness_chain_errors":
        list(chain_errors),

    "remediation_pass":
        remediation_pass,

    "nonclaim":
        (
            "This establishes only the frozen "
            "deterministic successor behavior under "
            "P2-H01-R01. It does not establish "
            "distributed revocation propagation or "
            "unbounded real-world concurrency."
        ),
}

RESULT_PATH.write_text(
    json.dumps(
        evidence,
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)

print(
    json.dumps(
        evidence,
        indent=2,
        sort_keys=True,
    )
)

print()

print(
    "P2-H01-R01 CLASSIFICATION:",
    classification,
)

print(
    "RESULT:",
    RESULT_PATH,
)

print(
    "WITNESS:",
    LEDGER_PATH,
)

sys.exit(
    0
    if remediation_pass
    else 2
)
