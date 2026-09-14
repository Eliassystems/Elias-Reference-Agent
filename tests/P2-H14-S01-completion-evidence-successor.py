from __future__ import annotations

from pathlib import Path
import json
import sys


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from core.authority import AuthorityState
from core.execution_firewall_v04 import ExecutionFirewallV04
from core.permit_v02 import PermitIssuerV02, PermitVerifierV02
from tools.broker_v04 import ToolBrokerV04, ToolRequestV04
from tools.messaging_demo import MessagingDemoTool
from witness.ledger import WitnessLedger


TEST_ID = "P2-H14-S01"

EVIDENCE_DIR = Path(
    "evidence/phase-ii/p2-h14-successor"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P2-H14-S01-FIRST-OBSERVED-RESULT-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P2-H14-S01-WITNESS-001.jsonl"
)


EVIDENCE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


if RESULT_PATH.exists() or WITNESS_PATH.exists():

    print(
        "P2-H14-S01 FIRST-OBSERVED ARTIFACT ALREADY EXISTS."
    )

    print("REFUSING RERUN.")

    sys.exit(3)


class CompletionRecordUnavailableLedger(WitnessLedger):
    """
    Deterministic local reliability fixture.

    The ordinary ledger remains available.
    Only the normal EXECUTION_COMPLETED record is unavailable.

    The successor is expected to preserve a distinct
    post-action uncertainty record instead.
    """

    def __init__(self, path):

        super().__init__(path)

        self.completion_attempts = 0

        self.fallback_attempts = 0


    def append(self, *args, **kwargs):

        event_type = kwargs.get(
            "event_type"
        )

        if event_type == "EXECUTION_COMPLETED":

            self.completion_attempts += 1

            raise OSError(
                "P2-H14-S01 deterministic normal "
                "completion record unavailable"
            )

        if event_type == (
            "EXECUTION_COMPLETION_PERSISTENCE_FAILED"
        ):

            self.fallback_attempts += 1

        return super().append(
            *args,
            **kwargs,
        )


authority = AuthorityState.create(
    actor_id="P2-H14-S01-HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)


arguments = {
    "content":
        "P2-H14-S01 LOCAL GOVERNED MESSAGE"
}


signing_key = (
    b"P2-H14-S01-COMPLETION-EVIDENCE-KEY-000001"
)


issuer = PermitIssuerV02(
    signing_key=signing_key
)


verifier = PermitVerifierV02(
    signing_key=signing_key
)


ledger = CompletionRecordUnavailableLedger(
    WITNESS_PATH
)


firewall = ExecutionFirewallV04(
    verifier=verifier,
    ledger=ledger,
    constitution_path=(
        ROOT
        / "constitution"
        / "constitution.yaml"
    ),
)


messaging_tool = MessagingDemoTool()


broker = ToolBrokerV04(
    firewall=firewall,
    messaging_tool=messaging_tool,
)


intent_hash = (
    "P2-H14-S01-COMPLETION-EVIDENCE-INTENT"
)


permit = issuer.issue(
    authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="P2-H14-S01-RECIPIENT",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=arguments,
)


request = ToolRequestV04(
    permit=permit,

    current_authority=authority,

    authority_resolver=(
        lambda:
            authority
    ),

    intent_hash=intent_hash,

    permission="SEND",

    policy_version=
        "ERA-POLICY-001-v0.2.0",

    target="P2-H14-S01-RECIPIENT",

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


records = ledger.records()


event_types = [
    record.get(
        "event_type",
        "",
    )
    for record in records
]


pre_execution_authorized_present = (
    "PRE_EXECUTION_AUTHORIZED"
    in event_types
)


boundary_revalidated_present = (
    "CONSEQUENCE_BOUNDARY_REVALIDATED"
    in event_types
)


normal_completion_absent = (
    "EXECUTION_COMPLETED"
    not in event_types
)


fallback_present = (
    "EXECUTION_COMPLETION_PERSISTENCE_FAILED"
    in event_types
)


fallback_records = [
    record
    for record in records
    if record.get("event_type")
    == "EXECUTION_COMPLETION_PERSISTENCE_FAILED"
]


fallback_record = (
    fallback_records[0]
    if len(fallback_records) == 1
    else {}
)


fallback_truthful = (
    fallback_record.get(
        "execution_result"
    )
    == "EXECUTED_EVIDENCE_INCOMPLETE"
    and
    fallback_record.get(
        "verdict_reason"
    )
    == "EXECUTION_COMPLETION_RECORD_FAILED"
)


result_returned = (
    result is not None
)


result_truthful = (
    result_returned
    and
    result.executed is True
    and
    result.status
    == "EXECUTED_EVIDENCE_INCOMPLETE"
    and
    tuple(result.reasons)
    == (
        "EXECUTION_COMPLETION_RECORD_FAILED",
    )
)


completion_attempted_once = (
    ledger.completion_attempts
    == 1
)


fallback_attempted_once = (
    ledger.fallback_attempts
    == 1
)


consequence_occurred = (
    outbox_before == 0
    and
    outbox_after == 1
)


permit_consumed = (
    ledger.has_consumed_permit(
        permit.permit_id
    )
)


chain_valid, chain_errors = (
    ledger.verify_chain()
)


successor_pass = (
    not exception_captured
    and
    result_returned
    and
    result_truthful
    and
    completion_attempted_once
    and
    fallback_attempted_once
    and
    pre_execution_authorized_present
    and
    boundary_revalidated_present
    and
    normal_completion_absent
    and
    fallback_present
    and
    fallback_truthful
    and
    consequence_occurred
    and
    permit_consumed
    and
    chain_valid
)


classification = (
    "POST_ACTION_COMPLETION_FAILURE_TRUTHFULLY_WITNESSED"
    if successor_pass
    else
    "POST_ACTION_COMPLETION_SUCCESSOR_NOT_ESTABLISHED"
)


evidence = {
    "test_id":
        TEST_ID,

    "classification":
        classification,

    "predecessor_commit":
        "e4e6d2e",

    "exception_captured":
        exception_captured,

    "exception_type":
        exception_type,

    "exception_message":
        exception_message,

    "completion_attempts":
        ledger.completion_attempts,

    "completion_attempted_once":
        completion_attempted_once,

    "fallback_attempts":
        ledger.fallback_attempts,

    "fallback_attempted_once":
        fallback_attempted_once,

    "event_types":
        event_types,

    "pre_execution_authorized_present":
        pre_execution_authorized_present,

    "boundary_revalidated_present":
        boundary_revalidated_present,

    "normal_completion_absent":
        normal_completion_absent,

    "fallback_present":
        fallback_present,

    "fallback_truthful":
        fallback_truthful,

    "result_returned":
        result_returned,

    "result_status":
        (
            result.status
            if result_returned
            else None
        ),

    "result_executed":
        (
            result.executed
            if result_returned
            else None
        ),

    "result_reasons":
        (
            list(result.reasons)
            if result_returned
            else []
        ),

    "result_truthful":
        result_truthful,

    "outbox_before":
        outbox_before,

    "outbox_after":
        outbox_after,

    "consequence_occurred":
        consequence_occurred,

    "permit_consumed":
        permit_consumed,

    "witness_chain_valid":
        chain_valid,

    "witness_chain_errors":
        list(chain_errors),

    "successor_pass":
        successor_pass,

    "bounded_finding":
        (
            "Under frozen deterministic P2-H14-S01, "
            "when the local action returned successfully "
            "but the normal EXECUTION_COMPLETED record "
            "could not be persisted, the successor "
            "attempted a distinct durable uncertainty "
            "record and returned an executed=true state "
            "marked EXECUTED_EVIDENCE_INCOMPLETE."
        ),

    "nonclaim":
        (
            "This establishes only the deterministic "
            "local successor behavior when the normal "
            "completion record fails but the fallback "
            "witness write remains available. It does "
            "not establish recovery when the ledger as "
            "a whole is unavailable, nor external, "
            "distributed or production transaction "
            "assurance."
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
    "P2-H14-S01 CLASSIFICATION:",
    classification,
)


print(
    "RESULT:",
    RESULT_PATH,
)


print(
    "WITNESS:",
    WITNESS_PATH,
)


sys.exit(
    0
    if successor_pass
    else 2
)
