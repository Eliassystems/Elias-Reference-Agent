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


TEST_ID = "P2-H05"

EVIDENCE_DIR = Path(
    "evidence/phase-ii/p2-h05"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P2-H05-FIRST-OBSERVED-RESULT-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P2-H05-WITNESS-001.jsonl"
)


EVIDENCE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


if RESULT_PATH.exists() or WITNESS_PATH.exists():
    print(
        "P2-H05 FIRST-OBSERVED "
        "ARTIFACT ALREADY EXISTS."
    )
    print("REFUSING RERUN.")
    sys.exit(3)


def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat()


authority = AuthorityState.create(
    actor_id="P2-H05-HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)


intent_text = (
    "Send one governed message under "
    "the exact authorised policy version."
)

intent_hash = hashlib.sha256(
    intent_text.encode("utf-8")
).hexdigest().upper()


arguments = {
    "content":
        "P2-H05 APPROVED GOVERNED CONTENT"
}


signing_key = (
    b"P2-H05-POLICY-VERSION-SIGNING-KEY-000001"
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


approved_policy = (
    "ERA-POLICY-001-v0.2.0"
)

mutated_policy = (
    "ERA-POLICY-001-v0.3.0"
)


# Permit constituted under the approved policy version.
permit = issuer.issue(
    authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=approved_policy,
    target="P2-H05-RECIPIENT",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=arguments,
)


# Same signed permit and same action,
# but execution request presents another policy version.
mutated_request = ToolRequestV031(
    permit=permit,

    current_authority=authority,

    authority_resolver=(
        lambda:
            authority
    ),

    intent_hash=intent_hash,

    permission="SEND",

    policy_version=mutated_policy,

    target="P2-H05-RECIPIENT",

    tool_name="MESSAGING_DEMO",

    consequence_class="C4",

    arguments=arguments,
)


outbox_before = broker.outbox_size()

result = broker.execute(
    mutated_request
)

outbox_after = broker.outbox_size()


reasons = list(
    result.reasons
)


required_reason_present = (
    "POLICY_VERSION_MISMATCH"
    in reasons
)


isolated_policy_reason = (
    set(reasons)
    == {"POLICY_VERSION_MISMATCH"}
)


chain_valid, chain_errors = (
    ledger.verify_chain()
)


p2_h05_pass = (
    not result.executed
    and
    result.status
    == "REFUSED_BEFORE_CONSEQUENCE"
    and
    required_reason_present
    and
    isolated_policy_reason
    and
    outbox_before == 0
    and
    outbox_after == 0
    and
    chain_valid
)


classification = (
    "POLICY_VERSION_MUTATION_REFUSED"
    if p2_h05_pass
    else
    "POLICY_VERSION_BINDING_NOT_ESTABLISHED"
)


evidence = {
    "test_id":
        TEST_ID,

    "classification":
        classification,

    "observed_at_utc":
        utc_now(),

    "predecessor_commit":
        "0224c78",

    "attack":
        (
            "A valid signed permit constituted under "
            "ERA-POLICY-001-v0.2.0 is presented "
            "through the frozen v0.3.1 broker with "
            "the execution request claiming "
            "ERA-POLICY-001-v0.3.0 while all other "
            "tested action fields remain unchanged."
        ),

    "permit_policy_version":
        permit.policy_version,

    "requested_policy_version":
        mutated_policy,

    "policy_version_changed":
        permit.policy_version
        != mutated_policy,

    "executed":
        result.executed,

    "status":
        result.status,

    "reasons":
        reasons,

    "required_reason_present":
        required_reason_present,

    "isolated_policy_reason":
        isolated_policy_reason,

    "outbox_before":
        outbox_before,

    "outbox_after":
        outbox_after,

    "consequence_occurred":
        outbox_after
        > outbox_before,

    "witness_chain_valid":
        chain_valid,

    "witness_chain_errors":
        list(chain_errors),

    "p2_h05_pass":
        p2_h05_pass,

    "bounded_finding":
        (
            "Under frozen deterministic P2-H05, "
            "a permit constituted under one policy "
            "version did not authorize execution "
            "when presented under a different policy "
            "version."
        ),

    "nonclaim":
        (
            "This establishes only the frozen "
            "deterministic policy-version binding "
            "behavior of the tested permit/firewall/"
            "broker path. It does not establish "
            "external policy provenance, policy "
            "correctness, or production-system "
            "behavior."
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
    "P2-H05 CLASSIFICATION:",
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
    if p2_h05_pass
    else 2
)
