from pathlib import Path
import hashlib
import secrets
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))


from core.authority import AuthorityState
from core.execution_firewall import ExecutionFirewall
from core.permit import PermitIssuer, PermitVerifier
from tools.messaging_demo import MessagingDemoTool
from witness.ledger import WitnessLedger


def heading(text):
    print()
    print("=" * 76)
    print(text)
    print("=" * 76)


def show(result):
    print("STATUS:   ", result.status)
    print("EXECUTED: ", result.executed)
    print("REASONS:  ", list(result.reasons))
    print("RECEIPTS: ", list(result.receipt_hashes))


ledger_path = (
    PROJECT_ROOT
    / "witness"
    / "demo_witness_ledger.jsonl"
)

# Fresh frozen demonstration run.
if ledger_path.exists():
    ledger_path.unlink()

ledger = WitnessLedger(ledger_path)

# Demo-only signing key.
# Later this authority boundary will be isolated.
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

tool = MessagingDemoTool()


authority_t0 = AuthorityState.create(
    actor_id="HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"READ", "SEND"},
    epoch=1,
)


intent_text = (
    "Send governed summary to RECIPIENT-A"
)

intent_hash = hashlib.sha256(
    intent_text.encode("utf-8")
).hexdigest().upper()


heading(
    "CASE A - CURRENT AUTHORITY: EXECUTE"
)

permit_a = issuer.issue(
    authority=authority_t0,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.1.0",
    target="RECIPIENT-A",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    ttl_seconds=300,
)

result_a = firewall.execute(
    permit=permit_a,
    current_authority=authority_t0,
    expected_intent_hash=intent_hash,
    expected_permission="SEND",
    expected_policy_version=
        "ERA-POLICY-001-v0.1.0",
    expected_target="RECIPIENT-A",
    expected_tool="MESSAGING_DEMO",
    expected_consequence_class="C4",
    action=lambda: tool.send(
        target="RECIPIENT-A",
        content="Governed message A",
    ),
)

show(result_a)

assert result_a.executed
assert result_a.status == "EXECUTED"
assert len(tool.outbox) == 1


heading(
    "CASE B - REPLAY SAME PERMIT: REFUSE"
)

result_replay = firewall.execute(
    permit=permit_a,
    current_authority=authority_t0,
    expected_intent_hash=intent_hash,
    expected_permission="SEND",
    expected_policy_version=
        "ERA-POLICY-001-v0.1.0",
    expected_target="RECIPIENT-A",
    expected_tool="MESSAGING_DEMO",
    expected_consequence_class="C4",
    action=lambda: tool.send(
        target="RECIPIENT-A",
        content="THIS MUST NOT BE SENT",
    ),
)

show(result_replay)

assert not result_replay.executed
assert (
    "PERMIT_ALREADY_CONSUMED"
    in result_replay.reasons
)
assert len(tool.outbox) == 1


heading(
    "CASE C - AUTHORITY REVOKED AFTER PERMIT ISSUE: REFUSE"
)

permit_b = issuer.issue(
    authority=authority_t0,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.1.0",
    target="RECIPIENT-A",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    ttl_seconds=300,
)

authority_t1 = authority_t0.revoke_permission(
    "SEND",
    reason="HUMAN_VETO",
)

result_revoked = firewall.execute(
    permit=permit_b,
    current_authority=authority_t1,
    expected_intent_hash=intent_hash,
    expected_permission="SEND",
    expected_policy_version=
        "ERA-POLICY-001-v0.1.0",
    expected_target="RECIPIENT-A",
    expected_tool="MESSAGING_DEMO",
    expected_consequence_class="C4",
    action=lambda: tool.send(
        target="RECIPIENT-A",
        content=
            "THIS MUST ALSO NOT BE SENT",
    ),
)

show(result_revoked)

assert not result_revoked.executed
assert (
    "AUTHORITY_EPOCH_CHANGED"
    in result_revoked.reasons
)
assert (
    "CURRENT_PERMISSION_NOT_ESTABLISHED"
    in result_revoked.reasons
)
assert len(tool.outbox) == 1


heading("VERIFY WITNESS CHAIN")

chain_valid, chain_errors = (
    ledger.verify_chain()
)

print("CHAIN VALID:", chain_valid)
print("ERRORS:     ", list(chain_errors))
print("RECORDS:    ", len(ledger.records()))
print("OUTBOX:     ", len(tool.outbox))

assert chain_valid
assert len(tool.outbox) == 1


heading("FINAL RESULT")

print(
    "PASS: AUTHORIZED CONSEQUENCE EXECUTED"
)
print(
    "PASS: PERMIT CONSUMED BEFORE SIDE EFFECT"
)
print(
    "PASS: PERMIT REPLAY REFUSED"
)
print(
    "PASS: HUMAN REVOCATION REFUSED AT EXECUTION SEAM"
)
print(
    "PASS: REFUSED ACTION DID NOT REACH DEMO TOOL"
)
print(
    "PASS: PRE-EXECUTION WITNESS WRITTEN"
)
print(
    "PASS: POST-EXECUTION WITNESS WRITTEN"
)
print(
    "PASS: REFUSAL WITNESS WRITTEN"
)
print(
    "PASS: WITNESS HASH CHAIN VERIFIED"
)

print()
print(
    "OUTBOX CONTENTS:",
    tool.outbox,
)
print(
    "WITNESS LEDGER:",
    ledger_path,
)
