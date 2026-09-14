from pathlib import Path
import hashlib
import secrets
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


from core.authority import AuthorityState
from core.execution_firewall import ExecutionFirewall
from core.permit import PermitIssuer, PermitVerifier
from tools.broker import ToolBroker, ToolRequest
from tools.messaging_demo import MessagingDemoTool
from witness.ledger import WitnessLedger


def heading(text):
    print()
    print("=" * 76)
    print(text)
    print("=" * 76)


ledger_path = (
    PROJECT_ROOT
    / "witness"
    / "tool_broker_demo_ledger.jsonl"
)

if ledger_path.exists():
    ledger_path.unlink()


ledger = WitnessLedger(ledger_path)

signing_key = secrets.token_bytes(32)

issuer = PermitIssuer(signing_key)
verifier = PermitVerifier(signing_key)

firewall = ExecutionFirewall(
    verifier=verifier,
    ledger=ledger,
    constitution_path=(
        PROJECT_ROOT
        / "constitution"
        / "constitution.yaml"
    ),
)

messaging_tool = MessagingDemoTool()

broker = ToolBroker(
    firewall=firewall,
    messaging_tool=messaging_tool,
)


authority = AuthorityState.create(
    actor_id="HUMAN-001",
    authority_source="HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)

intent_text = (
    "Send governed broker message to RECIPIENT-A"
)

intent_hash = hashlib.sha256(
    intent_text.encode("utf-8")
).hexdigest().upper()


heading("CASE A - BROKERED EXECUTION")

permit = issuer.issue(
    authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version="ERA-POLICY-001-v0.1.0",
    target="RECIPIENT-A",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    ttl_seconds=300,
)

request = ToolRequest(
    permit=permit,
    current_authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version="ERA-POLICY-001-v0.1.0",
    target="RECIPIENT-A",
    tool_name="MESSAGING_DEMO",
    consequence_class="C4",
    arguments={
        "content":
            "Message passed through Elias Tool Broker"
    },
)

result = broker.execute(request)

print("STATUS:     ", result.status)
print("EXECUTED:   ", result.executed)
print("OUTBOX SIZE:", broker.outbox_size())

assert result.executed
assert broker.outbox_size() == 1


heading("CASE B - REPLAY THROUGH BROKER")

replay = broker.execute(request)

print("STATUS:     ", replay.status)
print("EXECUTED:   ", replay.executed)
print("REASONS:    ", list(replay.reasons))
print("OUTBOX SIZE:", broker.outbox_size())

assert not replay.executed
assert "PERMIT_ALREADY_CONSUMED" in replay.reasons
assert broker.outbox_size() == 1


heading("CASE C - TARGET SUBSTITUTION ATTEMPT")

permit_two = issuer.issue(
    authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version="ERA-POLICY-001-v0.1.0",
    target="RECIPIENT-A",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    ttl_seconds=300,
)

substituted_request = ToolRequest(
    permit=permit_two,
    current_authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version="ERA-POLICY-001-v0.1.0",
    target="RECIPIENT-B",
    tool_name="MESSAGING_DEMO",
    consequence_class="C4",
    arguments={
        "content":
            "THIS MUST NOT REACH RECIPIENT-B"
    },
)

substitution = broker.execute(
    substituted_request
)

print("STATUS:     ", substitution.status)
print("EXECUTED:   ", substitution.executed)
print("REASONS:    ", list(substitution.reasons))
print("OUTBOX SIZE:", broker.outbox_size())

assert not substitution.executed
assert (
    "TARGET_BINDING_MISMATCH"
    in substitution.reasons
)
assert broker.outbox_size() == 1


heading("CASE D - AUTHORITY REVOKED BEFORE BROKER EXECUTION")

permit_three = issuer.issue(
    authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version="ERA-POLICY-001-v0.1.0",
    target="RECIPIENT-A",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    ttl_seconds=300,
)

revoked_authority = authority.revoke_permission(
    "SEND",
    reason="HUMAN_VETO",
)

revoked_request = ToolRequest(
    permit=permit_three,
    current_authority=revoked_authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version="ERA-POLICY-001-v0.1.0",
    target="RECIPIENT-A",
    tool_name="MESSAGING_DEMO",
    consequence_class="C4",
    arguments={
        "content":
            "THIS MUST NOT EXECUTE"
    },
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


heading("VERIFY BROKER WITNESS CHAIN")

chain_valid, errors = ledger.verify_chain()

print("CHAIN VALID:", chain_valid)
print("ERRORS:     ", list(errors))

assert chain_valid


heading("FINAL RESULT")

print(
    "PASS: CONSEQUENCE TOOL EXECUTED THROUGH BROKER"
)
print(
    "PASS: BROKER ROUTED CONSEQUENCE THROUGH ELIAS FIREWALL"
)
print(
    "PASS: BROKER REPLAY REFUSED"
)
print(
    "PASS: BROKER TARGET SUBSTITUTION REFUSED"
)
print(
    "PASS: HUMAN REVOCATION PROPAGATED THROUGH BROKER"
)
print(
    "PASS: REFUSED REQUESTS DID NOT REACH CONSEQUENCE TOOL"
)
print(
    "PASS: BROKER WITNESS CHAIN VERIFIED"
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
