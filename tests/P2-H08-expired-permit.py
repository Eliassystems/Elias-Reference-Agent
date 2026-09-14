from __future__ import annotations

from datetime import datetime, timedelta, timezone
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


TEST_ID = "P2-H08"

EVIDENCE_DIR = Path(
    "evidence/phase-ii/p2-h08"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P2-H08-FIRST-OBSERVED-RESULT-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P2-H08-WITNESS-001.jsonl"
)


EVIDENCE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


if RESULT_PATH.exists() or WITNESS_PATH.exists():
    print(
        "P2-H08 FIRST-OBSERVED "
        "ARTIFACT ALREADY EXISTS."
    )
    print("REFUSING RERUN.")
    sys.exit(3)


def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat()


authority = AuthorityState.create(
    actor_id="P2-H08-HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)


intent_text = (
    "Send one governed message only while "
    "the execution permit remains temporally valid."
)

intent_hash = hashlib.sha256(
    intent_text.encode("utf-8")
).hexdigest().upper()


arguments = {
    "content":
        "P2-H08 APPROVED GOVERNED CONTENT"
}


signing_key = (
    b"P2-H08-EXPIRED-PERMIT-SIGNING-KEY-000001"
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


# ============================================================
# Constitute a valid signed permit in the past with a short TTL.
# At presentation time its expiry boundary has already passed.
# ============================================================

issued_at = (
    datetime.now(timezone.utc)
    - timedelta(minutes=10)
)


permit = issuer.issue(
    authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="P2-H08-RECIPIENT",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=arguments,
    ttl_seconds=60,
    now=issued_at,
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

    target="P2-H08-RECIPIENT",

    tool_name="MESSAGING_DEMO",

    consequence_class="C4",

    arguments=arguments,
)


outbox_before = broker.outbox_size()

result = broker.execute(
    request
)

outbox_after = broker.outbox_size()


reasons = list(
    result.reasons
)


required_reason_present = (
    "PERMIT_EXPIRED"
    in reasons
)


isolated_expiry_reason = (
    set(reasons)
    == {"PERMIT_EXPIRED"}
)


chain_valid, chain_errors = (
    ledger.verify_chain()
)


p2_h08_pass = (
    not result.executed
    and
    result.status
    == "REFUSED_BEFORE_CONSEQUENCE"
    and
    required_reason_present
    and
    isolated_expiry_reason
    and
    outbox_before == 0
    and
    outbox_after == 0
    and
    chain_valid
)


classification = (
    "EXPIRED_PERMIT_REFUSED"
    if p2_h08_pass
    else
    "PERMIT_EXPIRY_CONTROL_NOT_ESTABLISHED"
)


evidence = {
    "test_id":
        TEST_ID,

    "classification":
        classification,

    "observed_at_utc":
        utc_now(),

    "predecessor_commit":
        "a40b67a",

    "attack":
        (
            "A correctly signed and otherwise matching "
            "permit is presented only after its signed "
            "expiry boundary has passed."
        ),

    "permit_id":
        permit.permit_id,

    "permit_issued_at":
        permit.issued_at,

    "permit_expires_at":
        permit.expires_at,

    "executed":
        result.executed,

    "status":
        result.status,

    "reasons":
        reasons,

    "required_reason_present":
        required_reason_present,

    "isolated_expiry_reason":
        isolated_expiry_reason,

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

    "p2_h08_pass":
        p2_h08_pass,

    "bounded_finding":
        (
            "Under frozen deterministic P2-H08, "
            "a correctly signed permit whose expiry "
            "boundary had already passed did not "
            "authorize execution."
        ),

    "nonclaim":
        (
            "This establishes only the frozen "
            "deterministic permit-expiry behavior "
            "of the tested permit/firewall/broker "
            "path. It does not establish distributed "
            "clock synchronization, trusted-time "
            "infrastructure, or production behavior."
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
    "P2-H08 CLASSIFICATION:",
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
    if p2_h08_pass
    else 2
)
