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
from core.execution_firewall_v03 import ExecutionFirewallV03
from core.permit_v02 import PermitIssuerV02, PermitVerifierV02
from tools.broker_v031 import ToolBrokerV031, ToolRequestV031
from tools.messaging_demo import MessagingDemoTool
from witness.ledger import WitnessLedger


TEST_ID = "P2-H06"

EVIDENCE_DIR = Path(
    "evidence/phase-ii/p2-h06"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P2-H06-FIRST-OBSERVED-RESULT-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P2-H06-WITNESS-001.jsonl"
)


EVIDENCE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


if RESULT_PATH.exists() or WITNESS_PATH.exists():
    print(
        "P2-H06 FIRST-OBSERVED "
        "ARTIFACT ALREADY EXISTS."
    )
    print("REFUSING RERUN.")
    sys.exit(3)


def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat()


authority = AuthorityState.create(
    actor_id="P2-H06-HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)


intent_text = (
    "Send exactly one governed message "
    "under one execution permit."
)

intent_hash = hashlib.sha256(
    intent_text.encode("utf-8")
).hexdigest().upper()


arguments = {
    "content":
        "P2-H06 SINGLE AUTHORISED CONSEQUENCE"
}


signing_key = (
    b"P2-H06-PERMIT-REPLAY-SIGNING-KEY-000001"
)


issuer = PermitIssuerV02(
    signing_key=signing_key
)

verifier = PermitVerifierV02(
    signing_key=signing_key
)

ledger = WitnessLedger(
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

tool = MessagingDemoTool()

broker = ToolBrokerV031(
    firewall=firewall,
    messaging_tool=tool,
)


permit = issuer.issue(
    authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="P2-H06-RECIPIENT",
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

    target="P2-H06-RECIPIENT",

    tool_name="MESSAGING_DEMO",

    consequence_class="C4",

    arguments=arguments,
)


# ============================================================
# First presentation: expected ordinary authorised execution.
# ============================================================

outbox_before_first = broker.outbox_size()

first_result = broker.execute(
    request
)

outbox_after_first = broker.outbox_size()


first_execution_pass = (
    first_result.executed
    and
    first_result.status == "EXECUTED"
    and
    outbox_before_first == 0
    and
    outbox_after_first == 1
)


# ============================================================
# Second presentation: exact same signed permit and request.
# ============================================================

outbox_before_replay = broker.outbox_size()

replay_result = broker.execute(
    request
)

outbox_after_replay = broker.outbox_size()


replay_reasons = list(
    replay_result.reasons
)


required_reason_present = (
    "PERMIT_ALREADY_CONSUMED"
    in replay_reasons
)


chain_valid, chain_errors = (
    ledger.verify_chain()
)


p2_h06_pass = (
    first_execution_pass
    and
    not replay_result.executed
    and
    replay_result.status
    == "REFUSED_BEFORE_CONSEQUENCE"
    and
    required_reason_present
    and
    outbox_before_replay == 1
    and
    outbox_after_replay == 1
    and
    chain_valid
)


classification = (
    "PERMIT_REPLAY_REFUSED"
    if p2_h06_pass
    else
    "PERMIT_REPLAY_CONTROL_NOT_ESTABLISHED"
)


evidence = {
    "test_id":
        TEST_ID,

    "classification":
        classification,

    "observed_at_utc":
        utc_now(),

    "predecessor_commit":
        "e6c0b0c",

    "attack":
        (
            "A valid signed permit is first consumed "
            "by one authorised consequence and then "
            "the exact same permit/request is "
            "presented a second time."
        ),

    "permit_id":
        permit.permit_id,

    "first_execution":
        {
            "executed":
                first_result.executed,

            "status":
                first_result.status,

            "reasons":
                list(first_result.reasons),

            "outbox_before":
                outbox_before_first,

            "outbox_after":
                outbox_after_first,

            "pass":
                first_execution_pass,
        },

    "replay_execution":
        {
            "executed":
                replay_result.executed,

            "status":
                replay_result.status,

            "reasons":
                replay_reasons,

            "required_reason_present":
                required_reason_present,

            "outbox_before":
                outbox_before_replay,

            "outbox_after":
                outbox_after_replay,

            "second_consequence_occurred":
                outbox_after_replay
                > outbox_before_replay,
        },

    "witness_chain_valid":
        chain_valid,

    "witness_chain_errors":
        list(chain_errors),

    "p2_h06_pass":
        p2_h06_pass,

    "bounded_finding":
        (
            "Under frozen deterministic P2-H06, "
            "a permit that successfully authorised "
            "one consequence did not authorise a "
            "second consequence when the exact same "
            "permit/request was replayed."
        ),

    "nonclaim":
        (
            "This establishes only the frozen "
            "deterministic replay behavior of the "
            "tested permit/firewall/broker path. "
            "It does not establish distributed "
            "single-use coordination or production "
            "replay resistance."
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
    "P2-H06 CLASSIFICATION:",
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
    if p2_h06_pass
    else 2
)
