from __future__ import annotations

from dataclasses import replace
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


TEST_ID = "P2-H12"

EVIDENCE_DIR = Path(
    "evidence/phase-ii/p2-h12"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P2-H12-FIRST-OBSERVED-RESULT-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P2-H12-WITNESS-001.jsonl"
)


EVIDENCE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


if RESULT_PATH.exists() or WITNESS_PATH.exists():
    print("P2-H12 FIRST-OBSERVED ARTIFACT ALREADY EXISTS.")
    print("REFUSING RERUN.")
    sys.exit(3)


def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat()


authority = AuthorityState.create(
    actor_id="P2-H12-HUMAN-001",
    authority_source="HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)


intent_text = (
    "Send one governed message only under "
    "the exact cryptographic identity of the "
    "issued execution permit."
)

intent_hash = hashlib.sha256(
    intent_text.encode("utf-8")
).hexdigest().upper()


arguments = {
    "content":
        "P2-H12 APPROVED GOVERNED CONTENT"
}


signing_key = (
    b"P2-H12-PERMIT-ID-TAMPER-SIGNING-KEY-000001"
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


original_permit = issuer.issue(
    authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version="ERA-POLICY-001-v0.2.0",
    target="P2-H12-RECIPIENT",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=arguments,
)


replacement_first_character = (
    "0"
    if original_permit.permit_id[0] != "0"
    else "1"
)

tampered_permit_id = (
    replacement_first_character
    + original_permit.permit_id[1:]
)

tampered_permit = replace(
    original_permit,
    permit_id=tampered_permit_id,
)


permit_id_changed = (
    tampered_permit.permit_id
    != original_permit.permit_id
)

permit_id_length_unchanged = (
    len(tampered_permit.permit_id)
    == len(original_permit.permit_id)
    == 64
)

unsigned_payload_unchanged = (
    tampered_permit.unsigned_payload()
    == original_permit.unsigned_payload()
)

signature_unchanged = (
    tampered_permit.signature
    == original_permit.signature
)

action_hash_unchanged = (
    tampered_permit.action_hash
    == original_permit.action_hash
)

authority_state_hash_unchanged = (
    tampered_permit.authority_state_hash
    == original_permit.authority_state_hash
)


resolver_state = {
    "calls": 0,
}


def authority_resolver():
    resolver_state["calls"] += 1
    return authority


request = ToolRequestV031(
    permit=tampered_permit,
    current_authority=authority,
    authority_resolver=authority_resolver,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version="ERA-POLICY-001-v0.2.0",
    target="P2-H12-RECIPIENT",
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
    "PERMIT_ID_INVALID"
    in reasons
)

isolated_permit_id_reason = (
    set(reasons)
    == {"PERMIT_ID_INVALID"}
)

signature_invalid_absent = (
    "SIGNATURE_INVALID"
    not in reasons
)

resolver_not_called = (
    resolver_state["calls"] == 0
)


chain_valid, chain_errors = (
    ledger.verify_chain()
)


p2_h12_pass = (
    permit_id_changed
    and permit_id_length_unchanged
    and unsigned_payload_unchanged
    and signature_unchanged
    and action_hash_unchanged
    and authority_state_hash_unchanged
    and required_reason_present
    and isolated_permit_id_reason
    and signature_invalid_absent
    and resolver_not_called
    and not result.executed
    and result.status
        == "REFUSED_BEFORE_CONSEQUENCE"
    and outbox_before == 0
    and outbox_after == 0
    and chain_valid
)


classification = (
    "PERMIT_ID_TAMPER_REFUSED"
    if p2_h12_pass
    else
    "PERMIT_ID_INTEGRITY_CONTROL_NOT_ESTABLISHED"
)


evidence = {
    "test_id":
        TEST_ID,

    "classification":
        classification,

    "observed_at_utc":
        utc_now(),

    "predecessor_commit":
        "9294b00",

    "attack":
        (
            "A normally issued valid permit is cloned "
            "with only permit_id changed. The unsigned "
            "payload, signature, action hash and "
            "authority-state hash remain unchanged."
        ),

    "original_permit_id":
        original_permit.permit_id,

    "tampered_permit_id":
        tampered_permit.permit_id,

    "permit_id_changed":
        permit_id_changed,

    "permit_id_length_unchanged":
        permit_id_length_unchanged,

    "unsigned_payload_unchanged":
        unsigned_payload_unchanged,

    "signature_unchanged":
        signature_unchanged,

    "action_hash_unchanged":
        action_hash_unchanged,

    "authority_state_hash_unchanged":
        authority_state_hash_unchanged,

    "resolver_calls":
        resolver_state["calls"],

    "resolver_not_called":
        resolver_not_called,

    "executed":
        result.executed,

    "status":
        result.status,

    "reasons":
        reasons,

    "required_reason_present":
        required_reason_present,

    "isolated_permit_id_reason":
        isolated_permit_id_reason,

    "signature_invalid_absent":
        signature_invalid_absent,

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

    "p2_h12_pass":
        p2_h12_pass,

    "bounded_finding":
        (
            "Under frozen deterministic P2-H12, "
            "changing only the permit identifier did "
            "not alter the signed unsigned payload but "
            "was independently detected as "
            "PERMIT_ID_INVALID before execution."
        ),

    "nonclaim":
        (
            "This establishes only the frozen "
            "deterministic permit-identifier validation "
            "behavior of the tested permit/firewall/"
            "broker path. It does not establish all "
            "cryptographic identity, key-management, "
            "transport-integrity, or production-system "
            "properties."
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
    "P2-H12 CLASSIFICATION:",
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
    if p2_h12_pass
    else 2
)
