from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json
import sys


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(ROOT),
    )


from agent.model_adapter import (
    DeterministicDemoModel,
)

from agent.runtime import (
    EliasAgentRuntime,
)

from core.authority import (
    AuthorityState,
)

from core.execution_firewall_v03 import (
    ExecutionFirewallV03,
)

from core.permit_v02 import (
    PermitIssuerV02,
    PermitVerifierV02,
)

from tools.broker_v031 import (
    ToolBrokerV031,
)

from tools.messaging_demo import (
    MessagingDemoTool,
)

from witness.ledger import (
    WitnessLedger,
)


TEST_ID = "RG01"

EVIDENCE_DIR = Path(
    "evidence/phase-ii/runtime-regression-001"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "RG01-FIRST-OBSERVED-RESULT-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "RG01-WITNESS-001.jsonl"
)


EVIDENCE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


if RESULT_PATH.exists() or WITNESS_PATH.exists():
    print(
        "RG01 FIRST-OBSERVED ARTIFACT "
        "ALREADY EXISTS."
    )
    print("REFUSING RERUN.")
    sys.exit(3)


def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat()


signing_key = (
    b"RG01-RUNTIME-REGRESSION-SIGNING-KEY-000001"
)


issuer = PermitIssuerV02(
    signing_key=signing_key,
)

verifier = PermitVerifierV02(
    signing_key=signing_key,
)

ledger = WitnessLedger(
    WITNESS_PATH,
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
# CASE A
# Ordinary valid standing must still reach consequence.
# Uses runtime's normal local authority-resolver fallback.
# ============================================================

model_a = DeterministicDemoModel()

agent_a = EliasAgentRuntime(
    model=model_a,
    permit_issuer=issuer,
    broker=broker,
    ledger=ledger,
)


authority_a = AuthorityState.create(
    actor_id="RG01-HUMAN-A",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)


a_outbox_before = broker.outbox_size()


result_a = agent_a.run(
    current_authority=authority_a,

    objective=(
        "Prepare and transmit one governed "
        "runtime regression demonstration."
    ),

    permission="SEND",

    policy_version=
        "ERA-POLICY-001-v0.2.0",

    target="RG01-RECIPIENT-A",

    tool="MESSAGING_DEMO",

    consequence_class="C4",

    constraints=(
        "DO_NOT_CHANGE_TARGET",
    ),
)


a_outbox_after = broker.outbox_size()


case_a_pass = (
    result_a.model_called
    and
    result_a.executed
    and
    a_outbox_after
    == a_outbox_before + 1
)


# ============================================================
# CASE B
# No SEND standing must still refuse before intelligence.
# ============================================================

model_b = DeterministicDemoModel()

agent_b = EliasAgentRuntime(
    model=model_b,
    permit_issuer=issuer,
    broker=broker,
    ledger=ledger,
)


authority_b = AuthorityState.create(
    actor_id="RG01-HUMAN-B",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"READ"},
    epoch=2,
)


b_outbox_before = broker.outbox_size()


result_b = agent_b.run(
    current_authority=authority_b,

    objective=(
        "Attempt a governed external "
        "transmission without SEND authority."
    ),

    permission="SEND",

    policy_version=
        "ERA-POLICY-001-v0.2.0",

    target="RG01-RECIPIENT-B",

    tool="MESSAGING_DEMO",

    consequence_class="C4",
)


b_outbox_after = broker.outbox_size()


case_b_pass = (
    not result_b.model_called
    and
    not result_b.executed
    and
    b_outbox_after
    == b_outbox_before
)


chain_valid, chain_errors = (
    ledger.verify_chain()
)


regression_pass = (
    case_a_pass
    and
    case_b_pass
    and
    chain_valid
)


classification = (
    "RUNTIME_REGRESSION_PASS"
    if regression_pass
    else
    "RUNTIME_REGRESSION_NOT_ESTABLISHED"
)


evidence = {
    "test_id":
        TEST_ID,

    "classification":
        classification,

    "observed_at_utc":
        utc_now(),

    "predecessor":
        "P2-H01-R04_RUNTIME_MIGRATION_PASS",

    "predecessor_freeze_sha256":
        "152F544E26212EE421D4C6E819AE0275D45B21E24B2C3BE1C6B583494913966E",

    "case_a_valid_authority": {
        "model_called":
            result_a.model_called,

        "executed":
            result_a.executed,

        "status":
            result_a.status,

        "reasons":
            list(result_a.reasons),

        "outbox_before":
            a_outbox_before,

        "outbox_after":
            a_outbox_after,

        "pass":
            case_a_pass,
    },

    "case_b_missing_send_authority": {
        "model_called":
            result_b.model_called,

        "executed":
            result_b.executed,

        "status":
            result_b.status,

        "reasons":
            list(result_b.reasons),

        "outbox_before":
            b_outbox_before,

        "outbox_after":
            b_outbox_after,

        "pass":
            case_b_pass,
    },

    "witness_chain_valid":
        chain_valid,

    "witness_chain_errors":
        list(chain_errors),

    "runtime_regression_pass":
        regression_pass,

    "bounded_finding":
        (
            "The frozen migrated runtime retains "
            "ordinary permitted execution and "
            "ordinary pre-intelligence refusal "
            "under this deterministic regression."
        ),

    "nonclaim":
        (
            "This regression does not expand the "
            "P2-H01 bounded claim and does not "
            "establish live-model, distributed, "
            "or production-system behavior."
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
    "RG01 CLASSIFICATION:",
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
    if regression_pass
    else 2
)
