from pathlib import Path
import secrets
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


from agent.model_adapter import (
    DeterministicDemoModel,
)
from agent.runtime import EliasAgentRuntime
from core.authority import AuthorityState
from core.execution_firewall_v02 import (
    ExecutionFirewallV02,
)
from core.permit_v02 import (
    PermitIssuerV02,
    PermitVerifierV02,
)
from tools.broker_v02 import ToolBrokerV02
from tools.messaging_demo import MessagingDemoTool
from witness.ledger import WitnessLedger


def heading(text):
    print()
    print("=" * 78)
    print(text)
    print("=" * 78)


ledger_path = (
    ROOT
    / "witness"
    / "agent_runtime_demo_ledger.jsonl"
)

if ledger_path.exists():
    ledger_path.unlink()

ledger = WitnessLedger(
    ledger_path
)

signing_key = secrets.token_bytes(32)

issuer = PermitIssuerV02(
    signing_key
)

verifier = PermitVerifierV02(
    signing_key
)

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

model = DeterministicDemoModel()

agent = EliasAgentRuntime(
    model=model,
    permit_issuer=issuer,
    broker=broker,
    ledger=ledger,
)


heading(
    "DEMO A - NORMAL GOVERNED AGENT EXECUTION"
)

authority_a = AuthorityState.create(
    actor_id="HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)

result_a = agent.run(
    current_authority=authority_a,
    objective=
        "Prepare and transmit the governed demonstration summary.",
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="RECIPIENT-A",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    constraints=(
        "DO_NOT_CHANGE_TARGET",
        "EXTERNAL_SEND_REQUIRES_CURRENT_STANDING",
    ),
)

print("STATUS:       ", result_a.status)
print("EXECUTED:     ", result_a.executed)
print("MODEL CALLED: ", result_a.model_called)
print("MODEL ID:     ", result_a.model_id)
print("OUTBOX SIZE:  ", broker.outbox_size())

assert result_a.executed
assert result_a.model_called
assert model.calls == 1
assert broker.outbox_size() == 1


heading(
    "DEMO B - NO AUTHORITY: INTELLIGENCE MUST NOT RUN"
)

authority_b = AuthorityState.create(
    actor_id="HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"READ"},
    epoch=10,
)

result_b = agent.run(
    current_authority=authority_b,
    objective=
        "Attempt an external governed transmission.",
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="RECIPIENT-A",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
)

print("STATUS:       ", result_b.status)
print("EXECUTED:     ", result_b.executed)
print("MODEL CALLED: ", result_b.model_called)
print("MODEL CALLS:  ", model.calls)
print("OUTBOX SIZE:  ", broker.outbox_size())
print("REASONS:      ", list(result_b.reasons))

assert not result_b.executed
assert not result_b.model_called
assert (
    result_b.status
    == "REFUSED_BEFORE_INTELLIGENCE"
)
assert model.calls == 1
assert broker.outbox_size() == 1


heading(
    "DEMO C - AUTHORITY REVOKED AFTER INTELLIGENCE"
)

authority_c = AuthorityState.create(
    actor_id="HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=20,
)


def human_veto_at_execution_seam(
    current_authority,
):
    print()
    print(
        "HUMAN ACTION: REVOKE SEND BEFORE CONSEQUENCE"
    )

    return current_authority.revoke_permission(
        "SEND",
        reason=
            "HUMAN_VETO_DURING_AGENT_RUN",
    )


result_c = agent.run(
    current_authority=authority_c,
    objective=
        "Prepare another governed external message.",
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="RECIPIENT-A",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    before_execute_hook=
        human_veto_at_execution_seam,
)

print()
print("STATUS:       ", result_c.status)
print("EXECUTED:     ", result_c.executed)
print("MODEL CALLED: ", result_c.model_called)
print("MODEL CALLS:  ", model.calls)
print("REASONS:      ", list(result_c.reasons))
print("OUTBOX SIZE:  ", broker.outbox_size())

assert result_c.model_called
assert model.calls == 2

assert not result_c.executed

assert (
    "AUTHORITY_EPOCH_CHANGED"
    in result_c.reasons
)

assert (
    "CURRENT_PERMISSION_NOT_ESTABLISHED"
    in result_c.reasons
)

assert broker.outbox_size() == 1


heading(
    "VERIFY COMPLETE AGENT WITNESS CHAIN"
)

chain_valid, errors = (
    ledger.verify_chain()
)

print("CHAIN VALID:", chain_valid)
print("ERRORS:     ", list(errors))
print("RECORDS:    ", len(ledger.records()))
print("OUTBOX SIZE:", broker.outbox_size())

assert chain_valid
assert broker.outbox_size() == 1


heading("FINAL RESULT")

print(
    "PASS: CANONICAL INTENT CONSTITUTED BEFORE INTELLIGENCE"
)

print(
    "PASS: NO AUTHORITY -> MODEL WAS NOT INVOKED"
)

print(
    "PASS: AUTHORIZED INTELLIGENCE RAN INSIDE GOVERNED ENVELOPE"
)

print(
    "PASS: MODEL OUTPUT BOUND TO EXACT ACTION BEFORE EXECUTION"
)

print(
    "PASS: HUMAN VETO AFTER INTELLIGENCE INVALIDATED EXECUTION"
)

print(
    "PASS: CAPABILITY SURVIVED WHILE AUTHORITY DID NOT"
)

print(
    "PASS: REFUSED CONSEQUENCE NEVER REACHED TOOL"
)

print(
    "PASS: COMPLETE AGENT RUN WITNESS CHAIN VERIFIED"
)

print()
print(
    "MODEL TOTAL CALLS:",
    model.calls,
)

print(
    "FINAL OUTBOX SIZE:",
    broker.outbox_size(),
)

print(
    "OUTBOX SNAPSHOT:",
    broker.outbox_snapshot(),
)
