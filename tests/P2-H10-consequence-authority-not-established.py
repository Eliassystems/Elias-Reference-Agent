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


TEST_ID = "P2-H10"

EVIDENCE_DIR = Path(
    "evidence/phase-ii/p2-h10"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P2-H10-FIRST-OBSERVED-RESULT-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P2-H10-WITNESS-001.jsonl"
)


EVIDENCE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


if RESULT_PATH.exists() or WITNESS_PATH.exists():
    print(
        "P2-H10 FIRST-OBSERVED "
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
#
# At the consequence boundary the resolver responds, but does
# NOT provide an AuthorityState object.
# ============================================================

authority = AuthorityState.create(
    actor_id="P2-H10-HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)


intent_text = (
    "Send one governed message only if "
    "fresh consequence-boundary authority "
    "is established as a valid AuthorityState."
)

intent_hash = hashlib.sha256(
    intent_text.encode("utf-8")
).hexdigest().upper()


arguments = {
    "content":
        "P2-H10 APPROVED GOVERNED CONTENT"
}


signing_key = (
    b"P2-H10-AUTHORITY-NOT-ESTABLISHED-KEY-000001"
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
    target="P2-H10-RECIPIENT",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=arguments,
)


resolver_state = {
    "calls": 0,
}


# Intentionally returns structured-looking material,
# but NOT an AuthorityState.
def invalid_authority_resolver():
    resolver_state["calls"] += 1

    return {
        "actor_id":
            authority.actor_id,

        "authority_source":
            authority.authority_source,

        "permissions":
            ["SEND"],

        "epoch":
            authority.epoch,

        "claim":
            "LOOKS_LIKE_AUTHORITY_BUT_IS_NOT_AUTHORITY_STATE",
    }


request = ToolRequestV031(
    permit=permit,

    current_authority=authority,

    authority_resolver=
        invalid_authority_resolver,

    intent_hash=intent_hash,

    permission="SEND",

    policy_version=
        "ERA-POLICY-001-v0.2.0",

    target="P2-H10-RECIPIENT",

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
    "CONSEQUENCE_AUTHORITY_NOT_ESTABLISHED"
    in reasons
)


isolated_not_established_reason = (
    set(reasons)
    == {
        "CONSEQUENCE_AUTHORITY_NOT_ESTABLISHED"
    }
)


resolver_called_once = (
    resolver_state["calls"] == 1
)


chain_valid, chain_errors = (
    ledger.verify_chain()
)


p2_h10_pass = (
    resolver_called_once
    and
    not result.executed
    and
    result.status
    == "REFUSED_BEFORE_CONSEQUENCE"
    and
    required_reason_present
    and
    isolated_not_established_reason
    and
    outbox_before == 0
    and
    outbox_after == 0
    and
    chain_valid
)


classification = (
    "CONSEQUENCE_AUTHORITY_NOT_ESTABLISHED_REFUSED"
    if p2_h10_pass
    else
    "CONSEQUENCE_AUTHORITY_TYPE_CONTROL_NOT_ESTABLISHED"
)


evidence = {
    "test_id":
        TEST_ID,

    "classification":
        classification,

    "observed_at_utc":
        utc_now(),

    "predecessor_commit":
        "7420c27",

    "attack":
        (
            "Initial authority and action bindings are "
            "valid. At the consequence boundary the "
            "authority resolver returns structured "
            "authority-like material that is not an "
            "AuthorityState."
        ),

    "permit_id":
        permit.permit_id,

    "resolver_calls":
        resolver_state["calls"],

    "resolver_called_once":
        resolver_called_once,

    "resolver_return_type":
        "dict",

    "resolver_return_is_authority_state":
        False,

    "executed":
        result.executed,

    "status":
        result.status,

    "reasons":
        reasons,

    "required_reason_present":
        required_reason_present,

    "isolated_not_established_reason":
        isolated_not_established_reason,

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

    "p2_h10_pass":
        p2_h10_pass,

    "bounded_finding":
        (
            "Under frozen deterministic P2-H10, "
            "authority-like material returned by the "
            "fresh consequence-boundary resolver did "
            "not establish authority when it was not "
            "an AuthorityState."
        ),

    "nonclaim":
        (
            "This establishes only the frozen "
            "deterministic type/admissibility behavior "
            "of the tested resolver/firewall/broker "
            "path. It does not establish semantic "
            "correctness of all AuthorityState objects, "
            "external authority provenance, distributed "
            "authority assurance, or production behavior."
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
    "P2-H10 CLASSIFICATION:",
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
    if p2_h10_pass
    else 2
)
