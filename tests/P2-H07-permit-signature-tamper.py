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

from core.execution_firewall_v03 import (
    ExecutionFirewallV03,
)

from core.permit_v02 import (
    ExecutionPermitV02,
    PermitIssuerV02,
    PermitVerifierV02,
)

from tools.broker_v031 import (
    ToolBrokerV031,
    ToolRequestV031,
)

from tools.messaging_demo import (
    MessagingDemoTool,
)

from witness.ledger import (
    WitnessLedger,
)


TEST_ID = "P2-H07"

EVIDENCE_DIR = Path(
    "evidence/phase-ii/p2-h07"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P2-H07-FIRST-OBSERVED-RESULT-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P2-H07-WITNESS-001.jsonl"
)


EVIDENCE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


if RESULT_PATH.exists() or WITNESS_PATH.exists():
    print(
        "P2-H07 FIRST-OBSERVED "
        "ARTIFACT ALREADY EXISTS."
    )
    print("REFUSING RERUN.")
    sys.exit(3)


def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat()


# ============================================================
# Frozen authority and exact approved action.
# ============================================================

authority = AuthorityState.create(
    actor_id="P2-H07-HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)


intent_text = (
    "Send one governed message under "
    "an authentic signed permit."
)

intent_hash = hashlib.sha256(
    intent_text.encode("utf-8")
).hexdigest().upper()


arguments = {
    "content":
        "P2-H07 APPROVED GOVERNED CONTENT"
}


signing_key = (
    b"P2-H07-SIGNATURE-TAMPER-SIGNING-KEY-000001"
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
# Issue one valid signed permit.
# ============================================================

valid_permit = issuer.issue(
    authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="P2-H07-RECIPIENT",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=arguments,
)


original_signature = (
    valid_permit.signature
)


# ============================================================
# Tamper ONLY the signature.
#
# The unsigned payload and permit_id remain unchanged.
# ============================================================

tampered_signature = (
    "0" * len(original_signature)
)

if tampered_signature == original_signature:
    tampered_signature = (
        "F" * len(original_signature)
    )


tampered_permit = ExecutionPermitV02(
    permit_id=valid_permit.permit_id,
    signature=tampered_signature,
    **valid_permit.unsigned_payload(),
)


unsigned_payload_unchanged = (
    tampered_permit.unsigned_payload()
    == valid_permit.unsigned_payload()
)

permit_id_unchanged = (
    tampered_permit.permit_id
    == valid_permit.permit_id
)

signature_changed = (
    tampered_permit.signature
    != valid_permit.signature
)


request = ToolRequestV031(
    permit=tampered_permit,

    current_authority=authority,

    authority_resolver=(
        lambda:
            authority
    ),

    intent_hash=intent_hash,

    permission="SEND",

    policy_version=
        "ERA-POLICY-001-v0.2.0",

    target="P2-H07-RECIPIENT",

    tool_name="MESSAGING_DEMO",

    consequence_class="C4",

    arguments=arguments,
)


# ============================================================
# Present tampered permit once.
# ============================================================

outbox_before = broker.outbox_size()

result = broker.execute(
    request
)

outbox_after = broker.outbox_size()


reasons = list(
    result.reasons
)


required_reason_present = (
    "SIGNATURE_INVALID"
    in reasons
)


isolated_signature_reason = (
    set(reasons)
    == {"SIGNATURE_INVALID"}
)


chain_valid, chain_errors = (
    ledger.verify_chain()
)


p2_h07_pass = (
    signature_changed
    and
    unsigned_payload_unchanged
    and
    permit_id_unchanged
    and
    not result.executed
    and
    result.status
    == "REFUSED_BEFORE_CONSEQUENCE"
    and
    required_reason_present
    and
    isolated_signature_reason
    and
    outbox_before == 0
    and
    outbox_after == 0
    and
    chain_valid
)


classification = (
    "PERMIT_SIGNATURE_TAMPER_REFUSED"
    if p2_h07_pass
    else
    "PERMIT_SIGNATURE_CONTROL_NOT_ESTABLISHED"
)


evidence = {
    "test_id":
        TEST_ID,

    "classification":
        classification,

    "observed_at_utc":
        utc_now(),

    "predecessor_commit":
        "c42f0a7",

    "attack":
        (
            "A valid permit is issued and then only "
            "its signature field is replaced while "
            "its unsigned payload, permit_id, action, "
            "authority, policy, target, tool and "
            "consequence class remain unchanged."
        ),

    "permit_id":
        valid_permit.permit_id,

    "signature_changed":
        signature_changed,

    "unsigned_payload_unchanged":
        unsigned_payload_unchanged,

    "permit_id_unchanged":
        permit_id_unchanged,

    "executed":
        result.executed,

    "status":
        result.status,

    "reasons":
        reasons,

    "required_reason_present":
        required_reason_present,

    "isolated_signature_reason":
        isolated_signature_reason,

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

    "p2_h07_pass":
        p2_h07_pass,

    "bounded_finding":
        (
            "Under frozen deterministic P2-H07, "
            "altering only the cryptographic signature "
            "of an otherwise unchanged permit did not "
            "authorize execution."
        ),

    "nonclaim":
        (
            "This establishes only the frozen "
            "deterministic signature-verification "
            "behavior of the tested permit/firewall/"
            "broker path. It does not establish "
            "key-management security, resistance to "
            "key compromise, or production-system "
            "cryptographic security."
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
    "P2-H07 CLASSIFICATION:",
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
    if p2_h07_pass
    else 2
)
