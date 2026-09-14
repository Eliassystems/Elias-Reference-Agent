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


TEST_ID = "P2-H04"

EVIDENCE_DIR = Path("evidence/phase-ii/p2-h04")

RESULT_PATH = (
    EVIDENCE_DIR
    / "P2-H04-FIRST-OBSERVED-RESULT-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P2-H04-WITNESS-001.jsonl"
)


EVIDENCE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


if RESULT_PATH.exists() or WITNESS_PATH.exists():
    print("P2-H04 FIRST-OBSERVED ARTIFACT ALREADY EXISTS.")
    print("REFUSING RERUN.")
    sys.exit(3)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


authority = AuthorityState.create(
    actor_id="P2-H04-HUMAN-001",
    authority_source="HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)


intent_text = (
    "Send one exact approved governed message."
)

intent_hash = hashlib.sha256(
    intent_text.encode("utf-8")
).hexdigest().upper()


approved_arguments = {
    "content":
        "P2-H04 APPROVED GOVERNED CONTENT"
}


mutated_arguments = {
    "content":
        "P2-H04 MUTATED UNAPPROVED CONTENT"
}


signing_key = (
    b"P2-H04-ACTION-BINDING-SIGNING-KEY-000001"
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


# Permit is constituted for the approved content.
permit = issuer.issue(
    authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version="ERA-POLICY-001-v0.2.0",
    target="P2-H04-RECIPIENT",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=approved_arguments,
)


# Same signed permit, but content is changed after issuance.
mutated_request = ToolRequestV031(
    permit=permit,

    current_authority=authority,

    authority_resolver=(
        lambda:
            authority
    ),

    intent_hash=intent_hash,

    permission="SEND",

    policy_version="ERA-POLICY-001-v0.2.0",

    target="P2-H04-RECIPIENT",

    tool_name="MESSAGING_DEMO",

    consequence_class="C4",

    arguments=mutated_arguments,
)


outbox_before = broker.outbox_size()

result = broker.execute(
    mutated_request
)

outbox_after = broker.outbox_size()


reasons = list(
    result.reasons
)


required_reason_present = (
    "ACTION_BINDING_MISMATCH"
    in reasons
)


chain_valid, chain_errors = (
    ledger.verify_chain()
)


p2_h04_pass = (
    not result.executed
    and
    result.status == "REFUSED_BEFORE_CONSEQUENCE"
    and
    required_reason_present
    and
    outbox_before == 0
    and
    outbox_after == 0
    and
    chain_valid
)


classification = (
    "CONTENT_ACTION_MUTATION_REFUSED"
    if p2_h04_pass
    else
    "CONTENT_ACTION_BINDING_NOT_ESTABLISHED"
)


evidence = {
    "test_id":
        TEST_ID,

    "classification":
        classification,

    "observed_at_utc":
        utc_now(),

    "predecessor_commit":
        "66db677",

    "attack":
        (
            "A valid signed permit constituted for "
            "approved message content is presented "
            "through the frozen v0.3.1 broker with "
            "the message content changed after "
            "permit issuance."
        ),

    "approved_arguments":
        approved_arguments,

    "requested_arguments":
        mutated_arguments,

    "content_changed":
        approved_arguments != mutated_arguments,

    "executed":
        result.executed,

    "status":
        result.status,

    "reasons":
        reasons,

    "required_reason_present":
        required_reason_present,

    "outbox_before":
        outbox_before,

    "outbox_after":
        outbox_after,

    "consequence_occurred":
        outbox_after > outbox_before,

    "witness_chain_valid":
        chain_valid,

    "witness_chain_errors":
        list(chain_errors),

    "p2_h04_pass":
        p2_h04_pass,

    "bounded_finding":
        (
            "Under frozen deterministic P2-H04, "
            "a permit constituted for exact approved "
            "message content did not authorize "
            "execution after that content was changed."
        ),

    "nonclaim":
        (
            "This establishes only the frozen "
            "deterministic content/action binding "
            "behavior of the tested permit/firewall/"
            "broker path. It does not establish all "
            "possible argument mutation classes or "
            "production-system behavior."
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
    "P2-H04 CLASSIFICATION:",
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
    if p2_h04_pass
    else 2
)
