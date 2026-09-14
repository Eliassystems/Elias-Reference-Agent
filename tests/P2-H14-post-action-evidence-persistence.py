from __future__ import annotations

from pathlib import Path
import json
import sys


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from core.authority import AuthorityState
from core.execution_firewall_v03 import ExecutionFirewallV03
from core.permit_v02 import PermitIssuerV02, PermitVerifierV02
from tools.broker_v031 import ToolBrokerV031, ToolRequestV031
from tools.messaging_demo import MessagingDemoTool
from witness.ledger import WitnessLedger


TEST_ID = "P2-H14"

EVIDENCE_DIR = Path(
    "evidence/phase-ii/p2-h14"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P2-H14-FIRST-OBSERVED-RESULT-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P2-H14-WITNESS-001.jsonl"
)


EVIDENCE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


if RESULT_PATH.exists() or WITNESS_PATH.exists():
    print(
        "P2-H14 FIRST-OBSERVED ARTIFACT ALREADY EXISTS."
    )
    print("REFUSING RERUN.")
    sys.exit(3)


class CompletionWriteUnavailableLedger(WitnessLedger):
    """
    Local deterministic reliability fixture.

    All ordinary witness records use the real WitnessLedger.
    Only the EXECUTION_COMPLETED append is made unavailable.
    """

    def __init__(self, path):
        super().__init__(path)

        self.completion_write_attempts = 0


    def append(self, *args, **kwargs):

        event_type = kwargs.get(
            "event_type"
        )

        if event_type == "EXECUTION_COMPLETED":

            self.completion_write_attempts += 1

            raise OSError(
                "P2-H14 deterministic completion-record "
                "persistence unavailable"
            )

        return super().append(
            *args,
            **kwargs,
        )


authority = AuthorityState.create(
    actor_id="P2-H14-HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)


arguments = {
    "content":
        "P2-H14 LOCAL GOVERNED MESSAGE"
}


signing_key = (
    b"P2-H14-LOCAL-EVIDENCE-PERSISTENCE-KEY-000001"
)


issuer = PermitIssuerV02(
    signing_key=signing_key
)

verifier = PermitVerifierV02(
    signing_key=signing_key
)


ledger = CompletionWriteUnavailableLedger(
    WITNESS_PATH
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


broker = ToolBrokerV031(
    firewall=firewall,
    messaging_tool=messaging_tool,
)


intent_hash = (
    "P2-H14-LOCAL-EVIDENCE-PERSISTENCE-INTENT"
)


permit = issuer.issue(
    authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="P2-H14-RECIPIENT",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=arguments,
)


request = ToolRequestV031(
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

    target="P2-H14-RECIPIENT",

    tool_name="MESSAGING_DEMO",

    consequence_class="C4",

    arguments=arguments,
)


outbox_before = broker.outbox_size()


exception_captured = False
exception_type = ""
exception_message = ""
returned_result = None


try:

    returned_result = broker.execute(
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


execution_completed_present = (
    "EXECUTION_COMPLETED"
    in event_types
)


completion_write_attempted_once = (
    ledger.completion_write_attempts
    == 1
)


consequence_occurred = (
    outbox_after
    > outbox_before
)


permit_consumed = (
    ledger.has_consumed_permit(
        permit.permit_id
    )
)


chain_valid, chain_errors = (
    ledger.verify_chain()
)


if (
    exception_captured
    and
    completion_write_attempted_once
    and
    pre_execution_authorized_present
    and
    boundary_revalidated_present
    and
    not execution_completed_present
    and
    consequence_occurred
):

    classification = (
        "POST_ACTION_COMPLETION_RECORD_GAP_OBSERVED"
    )

elif (
    exception_captured
    and
    completion_write_attempted_once
    and
    not consequence_occurred
):

    classification = (
        "POST_ACTION_COMPLETION_WRITE_UNAVAILABLE_WITHOUT_CONSEQUENCE"
    )

else:

    classification = (
        "POST_ACTION_EVIDENCE_BEHAVIOR_NOT_ESTABLISHED"
    )


observation_established = (
    classification
    !=
    "POST_ACTION_EVIDENCE_BEHAVIOR_NOT_ESTABLISHED"
    and
    chain_valid
)


evidence = {
    "test_id":
        TEST_ID,

    "classification":
        classification,

    "predecessor_commit":
        "0b5d724",

    "scenario":
        (
            "A normal local governed SEND reaches the "
            "frozen execution path. The ordinary witness "
            "ledger remains available except that the "
            "EXECUTION_COMPLETED record cannot be persisted."
        ),

    "permit_id":
        permit.permit_id,

    "exception_captured":
        exception_captured,

    "exception_type":
        exception_type,

    "exception_message":
        exception_message,

    "completion_write_attempts":
        ledger.completion_write_attempts,

    "completion_write_attempted_once":
        completion_write_attempted_once,

    "returned_result":
        (
            repr(returned_result)
            if returned_result is not None
            else None
        ),

    "event_types":
        event_types,

    "pre_execution_authorized_present":
        pre_execution_authorized_present,

    "boundary_revalidated_present":
        boundary_revalidated_present,

    "execution_completed_present":
        execution_completed_present,

    "permit_consumed":
        permit_consumed,

    "outbox_before":
        outbox_before,

    "outbox_after":
        outbox_after,

    "consequence_occurred":
        consequence_occurred,

    "witness_chain_valid":
        chain_valid,

    "witness_chain_errors":
        list(chain_errors),

    "observation_established":
        observation_established,

    "bounded_finding":
        (
            "P2-H14 records only the first-observed "
            "deterministic behavior of the frozen local "
            "Reference Agent path when the completion "
            "record cannot be persisted after the "
            "consequence boundary has been revalidated."
        ),

    "nonclaim":
        (
            "This is a local deterministic software "
            "reliability observation only. It does not "
            "establish behavior for external services, "
            "distributed transactions, operating-system "
            "failures, storage hardware, or production "
            "deployment."
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
    "P2-H14 CLASSIFICATION:",
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
    if observation_established
    else 2
)
