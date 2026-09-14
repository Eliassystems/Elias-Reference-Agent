from pathlib import Path
import hashlib
import secrets
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


from core.authority import AuthorityState
from core.execution_firewall_v02 import (
    ExecutionFirewallV02,
)
from core.permit_v02 import (
    PermitIssuerV02,
    PermitVerifierV02,
)
from tools.broker_v02 import (
    ToolBrokerV02,
    ToolRequestV02,
)
from tools.messaging_demo import MessagingDemoTool
from witness.ledger import WitnessLedger


def heading(text):
    print()
    print("=" * 76)
    print(text)
    print("=" * 76)


ledger_path = (
    ROOT
    / "witness"
    / "action_binding_v02_ledger.jsonl"
)

if ledger_path.exists():
    ledger_path.unlink()

ledger = WitnessLedger(ledger_path)

key = secrets.token_bytes(32)

issuer = PermitIssuerV02(key)
verifier = PermitVerifierV02(key)

firewall = ExecutionFirewallV02(
    verifier=verifier,
    ledger=ledger,
    constitution_path=(
        ROOT
        / "constitution"
        / "constitution.yaml"
    ),
)

tool = MessagingDemoTool()

broker = ToolBrokerV02(
    firewall=firewall,
    messaging_tool=tool,
)

authority = AuthorityState.create(
    actor_id="HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)

intent_text = (
    "Send approved governed message "
    "to RECIPIENT-A"
)

intent_hash = hashlib.sha256(
    intent_text.encode("utf-8")
).hexdigest().upper()

approved_arguments = {
    "content":
        "APPROVED GOVERNED CONTENT"
}


heading(
    "CASE A - EXACT ACTION MATCH"
)

permit = issuer.issue(
    authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="RECIPIENT-A",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=approved_arguments,
)

valid_request = ToolRequestV02(
    permit=permit,
    current_authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="RECIPIENT-A",
    tool_name="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=approved_arguments,
)

result = broker.execute(valid_request)

print("STATUS:     ", result.status)
print("EXECUTED:   ", result.executed)
print("OUTBOX SIZE:", broker.outbox_size())

assert result.executed
assert broker.outbox_size() == 1


heading(
    "CASE B - CONTENT CHANGED AFTER PERMIT ISSUE"
)

permit_two = issuer.issue(
    authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="RECIPIENT-A",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=approved_arguments,
)

changed_arguments = {
    "content":
        "UNAPPROVED CHANGED CONTENT"
}

changed_request = ToolRequestV02(
    permit=permit_two,
    current_authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="RECIPIENT-A",
    tool_name="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=changed_arguments,
)

changed_result = broker.execute(
    changed_request
)

print("STATUS:     ", changed_result.status)
print("EXECUTED:   ", changed_result.executed)
print("REASONS:    ", list(changed_result.reasons))
print("OUTBOX SIZE:", broker.outbox_size())

assert not changed_result.executed
assert (
    "ACTION_BINDING_MISMATCH"
    in changed_result.reasons
)
assert broker.outbox_size() == 1


heading(
    "CASE C - TARGET CHANGED AFTER PERMIT ISSUE"
)

permit_three = issuer.issue(
    authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="RECIPIENT-A",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=approved_arguments,
)

target_request = ToolRequestV02(
    permit=permit_three,
    current_authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="RECIPIENT-B",
    tool_name="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=approved_arguments,
)

target_result = broker.execute(
    target_request
)

print("STATUS:     ", target_result.status)
print("EXECUTED:   ", target_result.executed)
print("REASONS:    ", list(target_result.reasons))
print("OUTBOX SIZE:", broker.outbox_size())

assert not target_result.executed
assert (
    "TARGET_BINDING_MISMATCH"
    in target_result.reasons
)
assert (
    "ACTION_BINDING_MISMATCH"
    in target_result.reasons
)
assert broker.outbox_size() == 1


heading(
    "CASE D - AUTHORITY REVOKED"
)

permit_four = issuer.issue(
    authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="RECIPIENT-A",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=approved_arguments,
)

revoked = authority.revoke_permission(
    "SEND",
    reason="HUMAN_VETO",
)

revoked_request = ToolRequestV02(
    permit=permit_four,
    current_authority=revoked,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="RECIPIENT-A",
    tool_name="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=approved_arguments,
)

revoked_result = broker.execute(
    revoked_request
)

print("STATUS:     ", revoked_result.status)
print("EXECUTED:   ", revoked_result.executed)
print("REASONS:    ", list(revoked_result.reasons))
print("OUTBOX SIZE:", broker.outbox_size())

assert not revoked_result.executed
assert (
    "AUTHORITY_EPOCH_CHANGED"
    in revoked_result.reasons
)
assert broker.outbox_size() == 1


heading(
    "CASE E - PERMIT REPLAY"
)

replay = broker.execute(valid_request)

print("STATUS:     ", replay.status)
print("EXECUTED:   ", replay.executed)
print("REASONS:    ", list(replay.reasons))
print("OUTBOX SIZE:", broker.outbox_size())

assert not replay.executed
assert (
    "PERMIT_ALREADY_CONSUMED"
    in replay.reasons
)
assert broker.outbox_size() == 1


heading(
    "VERIFY WITNESS CHAIN"
)

chain_valid, errors = (
    ledger.verify_chain()
)

print("CHAIN VALID:", chain_valid)
print("ERRORS:     ", list(errors))

assert chain_valid


heading("FINAL RESULT")

print(
    "PASS: EXACT APPROVED ACTION EXECUTED"
)
print(
    "PASS: MESSAGE CONTENT BOUND TO PERMIT"
)
print(
    "PASS: CONTENT SUBSTITUTION REFUSED"
)
print(
    "PASS: TARGET SUBSTITUTION REFUSED"
)
print(
    "PASS: AUTHORITY REVOCATION REFUSED"
)
print(
    "PASS: PERMIT REPLAY REFUSED"
)
print(
    "PASS: REFUSED ACTIONS NEVER REACHED TOOL"
)
print(
    "PASS: ACTION-BOUND WITNESS CHAIN VERIFIED"
)

print()
print(
    "FINAL OUTBOX SIZE:",
    broker.outbox_size(),
)
print(
    "OUTBOX SNAPSHOT:",
    broker.outbox_snapshot(),
)
