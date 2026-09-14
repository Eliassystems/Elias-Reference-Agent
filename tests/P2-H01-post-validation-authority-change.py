from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import sys

from core.authority import AuthorityState, AuthorityStatus
from core.permit_v02 import PermitIssuerV02, PermitVerifierV02
from core.execution_firewall_v02 import ExecutionFirewallV02
from tools.broker_v02 import ToolBrokerV02, ToolRequestV02
from tools.messaging_demo import MessagingDemoTool
from witness.ledger import WitnessLedger


TEST_ID = "P2-H01"
PERMISSION = "SEND"
POLICY_VERSION = "P2-H01-001"
TARGET = "p2-h01@example.test"
TOOL = "MESSAGING_DEMO"
CONSEQUENCE_CLASS = "EXTERNAL_WRITE"

EVIDENCE_DIR = Path("evidence/phase-ii/p2-h01")
RESULT_PATH = EVIDENCE_DIR / "P2-H01-FIRST-OBSERVED-RESULT-001.json"
LEDGER_PATH = EVIDENCE_DIR / "P2-H01-WITNESS-001.jsonl"

EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

# First-observed discipline: this exact test ID is one-shot.
if RESULT_PATH.exists() or LEDGER_PATH.exists():
    print("P2-H01 FIRST-OBSERVED ARTIFACT ALREADY EXISTS.")
    print("REFUSING RERUN.")
    sys.exit(3)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# Find an AuthorityStatus that actually establishes SEND
# according to the implementation itself.
authority_t0 = None
active_status = None

for candidate in AuthorityStatus:
    probe = AuthorityState(
        actor_id="P2-H01-ACTOR",
        authority_source="P2-H01-HARNESS",
        epoch=1,
        permissions=frozenset({PERMISSION}),
        status=candidate,
        reason="P2_H01_INITIAL_AUTHORITY",
    )

    if probe.has_authority(PERMISSION):
        authority_t0 = probe
        active_status = candidate
        break

if authority_t0 is None:
    raise RuntimeError(
        "HARNESS_COULD_NOT_CONSTITUTE_VALID_SEND_AUTHORITY"
    )


# Material change after authorization:
# epoch advances and SEND no longer exists.
authority_t1 = AuthorityState(
    actor_id=authority_t0.actor_id,
    authority_source=authority_t0.authority_source,
    epoch=authority_t0.epoch + 1,
    permissions=frozenset(),
    status=active_status,
    reason="P2_H01_SEND_REMOVED_AFTER_PREAUTH",
)

if authority_t1.has_authority(PERMISSION):
    raise RuntimeError(
        "HARNESS_CHANGED_STATE_STILL_HAS_SEND_AUTHORITY"
    )


live_state = {
    "authority": authority_t0,
    "change_triggered": False,
    "changed_at_event": None,
}


class PostValidationMutationLedger(WitnessLedger):
    """
    Deterministic adversarial injection.

    The normal PRE_EXECUTION_AUTHORIZED receipt is written first.
    Immediately after that receipt, but before the firewall calls
    the consequence callable, the authoritative test state changes
    from T0 to T1.
    """

    def append(self, *args, **kwargs):
        record = super().append(*args, **kwargs)

        if kwargs.get("event_type") == "PRE_EXECUTION_AUTHORIZED":
            live_state["authority"] = authority_t1
            live_state["change_triggered"] = True
            live_state["changed_at_event"] = (
                "PRE_EXECUTION_AUTHORIZED"
            )

        return record


signing_key = (
    b"P2-H01-DETERMINISTIC-TEST-SIGNING-KEY-00000001"
)

issuer = PermitIssuerV02(
    signing_key=signing_key
)

verifier = PermitVerifierV02(
    signing_key=signing_key
)

ledger = PostValidationMutationLedger(
    LEDGER_PATH
)

firewall = ExecutionFirewallV02(
    verifier=verifier,
    ledger=ledger,
    constitution_path=Path(
        "constitution/constitution.yaml"
    ),
)

messaging_tool = MessagingDemoTool()

broker = ToolBrokerV02(
    firewall=firewall,
    messaging_tool=messaging_tool,
)

objective = (
    "P2-H01 deterministic post-validation "
    "authority-change consequence test"
)

intent_hash = hashlib.sha256(
    objective.encode("utf-8")
).hexdigest().upper()

arguments = {
    "content":
        "P2-H01 consequence payload"
}

permit = issuer.issue(
    authority=authority_t0,
    intent_hash=intent_hash,
    permission=PERMISSION,
    policy_version=POLICY_VERSION,
    target=TARGET,
    tool=TOOL,
    consequence_class=CONSEQUENCE_CLASS,
    arguments=arguments,
    ttl_seconds=300,
)

request = ToolRequestV02(
    permit=permit,
    current_authority=authority_t0,
    intent_hash=intent_hash,
    permission=PERMISSION,
    policy_version=POLICY_VERSION,
    target=TARGET,
    tool_name=TOOL,
    consequence_class=CONSEQUENCE_CLASS,
    arguments=arguments,
)

outbox_before = broker.outbox_size()

result = broker.execute(
    request
)

outbox_after = broker.outbox_size()

live_authority_at_end = live_state["authority"]

live_send_established = (
    live_authority_at_end.has_authority(
        PERMISSION
    )
)

consequence_occurred = (
    outbox_after > outbox_before
)

seam_exposed = (
    live_state["change_triggered"]
    and authority_t0.epoch
        != live_authority_at_end.epoch
    and not live_send_established
    and consequence_occurred
    and result.executed
)

classification = (
    "SEAM_EXPOSED"
    if seam_exposed
    else "SEAM_NOT_EXPOSED"
)

evidence = {
    "test_id": TEST_ID,
    "classification": classification,
    "observed_at_utc": utc_now(),

    "attack":
        "Authority changes after "
        "PRE_EXECUTION_AUTHORIZED and before "
        "the consequence callable.",

    "authority_t0": {
        "epoch": authority_t0.epoch,
        "permission_send":
            authority_t0.has_authority(
                PERMISSION
            ),
        "state_hash":
            authority_t0.state_hash(),
    },

    "authority_at_consequence_boundary": {
        "epoch":
            live_authority_at_end.epoch,
        "permission_send":
            live_send_established,
        "state_hash":
            live_authority_at_end.state_hash(),
    },

    "change_triggered":
        live_state["change_triggered"],

    "changed_at_event":
        live_state["changed_at_event"],

    "permit_id":
        permit.permit_id,

    "permit_authority_epoch":
        permit.authority_epoch,

    "firewall_status":
        result.status,

    "firewall_executed":
        result.executed,

    "firewall_reasons":
        list(result.reasons),

    "outbox_before":
        outbox_before,

    "outbox_after":
        outbox_after,

    "consequence_occurred":
        consequence_occurred,

    "seam_exposed":
        seam_exposed,

    "nonclaim":
        "This deterministic test injects a material "
        "authority change after the firewall's "
        "PRE_EXECUTION_AUTHORIZED receipt. It tests "
        "only whether the present implementation "
        "revalidates authority again before invoking "
        "the consequence callable. It does not by "
        "itself establish real-world concurrent "
        "revocation propagation.",
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
print("P2-H01 CLASSIFICATION:", classification)
print("RESULT:", RESULT_PATH)
print("WITNESS:", LEDGER_PATH)
