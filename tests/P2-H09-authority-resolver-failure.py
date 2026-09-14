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


TEST_ID = "P2-H09"

EVIDENCE_DIR = Path(
    "evidence/phase-ii/p2-h09"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P2-H09-FIRST-OBSERVED-RESULT-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P2-H09-WITNESS-001.jsonl"
)


EVIDENCE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


if RESULT_PATH.exists() or WITNESS_PATH.exists():
    print(
        "P2-H09 FIRST-OBSERVED "
        "ARTIFACT ALREADY EXISTS."
    )
    print("REFUSING RERUN.")
    sys.exit(3)


def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat()


# ============================================================
# Initial standing is valid.
# The only adversarial condition is that the fresh authority
# resolver fails at the consequence boundary.
# ============================================================

authority = AuthorityState.create(
    actor_id="P2-H09-HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)


intent_text = (
    "Send one governed message only if "
    "fresh authority can be resolved again "
    "at the consequence boundary."
)

intent_hash = hashlib.sha256(
    intent_text.encode("utf-8")
).hexdigest().upper()


arguments = {
    "content":
        "P2-H09 APPROVED GOVERNED CONTENT"
}


signing_key = (
    b"P2-H09-AUTHORITY-RESOLVER-FAILURE-KEY-000001"
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
    target="P2-H09-RECIPIENT",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=arguments,
)


resolver_state = {
    "calls": 0,
}


def failing_authority_resolver():
    resolver_state["calls"] += 1

    raise RuntimeError(
        "P2-H09 deterministic authority resolver failure"
    )


request = ToolRequestV031(
    permit=permit,

    current_authority=authority,

    authority_resolver=
        failing_authority_resolver,

    intent_hash=intent_hash,

    permission="SEND",

    policy_version=
        "ERA-POLICY-001-v0.2.0",

    target="P2-H09-RECIPIENT",

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
    "CONSEQUENCE_AUTHORITY_RESOLUTION_FAILED"
    in reasons
)


isolated_resolution_failure = (
    set(reasons)
    == {
        "CONSEQUENCE_AUTHORITY_RESOLUTION_FAILED"
    }
)


resolver_called_once = (
    resolver_state["calls"] == 1
)


chain_valid, chain_errors = (
    ledger.verify_chain()
)


p2_h09_pass = (
    resolver_called_once
    and
    not result.executed
    and
    result.status
    == "REFUSED_BEFORE_CONSEQUENCE"
    and
    required_reason_present
    and
    isolated_resolution_failure
    and
    outbox_before == 0
    and
    outbox_after == 0
    and
    chain_valid
)


classification = (
    "CONSEQUENCE_AUTHORITY_RESOLUTION_FAILURE_REFUSED"
    if p2_h09_pass
    else
    "CONSEQUENCE_AUTHORITY_RESOLUTION_CONTROL_NOT_ESTABLISHED"
)


evidence = {
    "test_id":
        TEST_ID,

    "classification":
        classification,

    "observed_at_utc":
        utc_now(),

    "predecessor_commit":
        "fb44271",

    "attack":
        (
            "Initial authority and action bindings are "
            "valid, but the required fresh authority "
            "resolver raises an exception when called "
            "at the consequence boundary."
        ),

    "permit_id":
        permit.permit_id,

    "resolver_calls":
        resolver_state["calls"],

    "resolver_called_once":
        resolver_called_once,

    "executed":
        result.executed,

    "status":
        result.status,

    "reasons":
        reasons,

    "required_reason_present":
        required_reason_present,

    "isolated_resolution_failure":
        isolated_resolution_failure,

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

    "p2_h09_pass":
        p2_h09_pass,

    "bounded_finding":
        (
            "Under frozen deterministic P2-H09, "
            "failure of the required fresh-authority "
            "resolver at the consequence boundary did "
            "not authorize execution."
        ),

    "nonclaim":
        (
            "This establishes only the frozen "
            "deterministic resolver-exception behavior "
            "of the tested permit/firewall/broker path. "
            "It does not establish behavior for every "
            "authority service outage, distributed "
            "failure mode, or production deployment."
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
    "P2-H09 CLASSIFICATION:",
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
    if p2_h09_pass
    else 2
)
