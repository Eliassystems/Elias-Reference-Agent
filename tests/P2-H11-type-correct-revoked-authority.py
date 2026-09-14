from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from core.authority import AuthorityState, AuthorityStatus
from core.execution_firewall_v03 import ExecutionFirewallV03
from core.permit_v02 import PermitIssuerV02, PermitVerifierV02
from tools.broker_v031 import ToolBrokerV031, ToolRequestV031
from tools.messaging_demo import MessagingDemoTool
from witness.ledger import WitnessLedger


TEST_ID = "P2-H11"

EVIDENCE_DIR = Path(
    "evidence/phase-ii/p2-h11"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P2-H11-FIRST-OBSERVED-RESULT-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P2-H11-WITNESS-001.jsonl"
)


EVIDENCE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


if RESULT_PATH.exists() or WITNESS_PATH.exists():
    print(
        "P2-H11 FIRST-OBSERVED "
        "ARTIFACT ALREADY EXISTS."
    )
    print("REFUSING RERUN.")
    sys.exit(3)


def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat()


# ============================================================
# T0:
# Valid active authority exists and a valid permit is issued.
#
# Consequence boundary:
# Resolver returns an actual AuthorityState object.
#
# Actor, source, epoch and permission set deliberately remain
# unchanged, but status is REVOKED.
#
# This isolates whether type correctness / permission presence
# can bypass the semantic standing check.
#
# NOTE:
# This adversarial state is constructed directly rather than
# through the normal revoke_all transition, specifically to
# hold epoch and permission text constant for discrimination.
# ============================================================

authority_t0 = AuthorityState.create(
    actor_id="P2-H11-HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)


intent_text = (
    "Send one governed message only while "
    "fresh authority remains semantically active "
    "at the consequence boundary."
)

intent_hash = hashlib.sha256(
    intent_text.encode("utf-8")
).hexdigest().upper()


arguments = {
    "content":
        "P2-H11 APPROVED GOVERNED CONTENT"
}


signing_key = (
    b"P2-H11-TYPE-CORRECT-REVOKED-AUTHORITY-KEY-000001"
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
    authority=authority_t0,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="P2-H11-RECIPIENT",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=arguments,
)


# ------------------------------------------------------------
# Adversarial type-correct state:
#
# SAME actor
# SAME source
# SAME epoch
# SAME permission set
#
# DIFFERENT semantic standing:
# status = REVOKED
#
# Because state_hash includes status/reason, the authority state
# identity must differ even though epoch and permissions remain.
# ------------------------------------------------------------

authority_at_boundary = AuthorityState(
    actor_id=authority_t0.actor_id,
    authority_source=authority_t0.authority_source,
    epoch=authority_t0.epoch,
    permissions=authority_t0.permissions,
    status=AuthorityStatus.REVOKED,
    reason="P2-H11_ADVERSARIAL_REVOKED_STATUS",
)


resolver_state = {
    "calls": 0,
}


def revoked_authority_resolver():
    resolver_state["calls"] += 1
    return authority_at_boundary


request = ToolRequestV031(
    permit=permit,

    current_authority=authority_t0,

    authority_resolver=
        revoked_authority_resolver,

    intent_hash=intent_hash,

    permission="SEND",

    policy_version=
        "ERA-POLICY-001-v0.2.0",

    target="P2-H11-RECIPIENT",

    tool_name="MESSAGING_DEMO",

    consequence_class="C4",

    arguments=arguments,
)


# ------------------------------------------------------------
# Pre-observation discriminators
# ------------------------------------------------------------

resolver_return_is_authority_state = isinstance(
    authority_at_boundary,
    AuthorityState,
)

actor_unchanged = (
    authority_at_boundary.actor_id
    == authority_t0.actor_id
)

authority_source_unchanged = (
    authority_at_boundary.authority_source
    == authority_t0.authority_source
)

epoch_unchanged = (
    authority_at_boundary.epoch
    == authority_t0.epoch
)

permissions_unchanged = (
    authority_at_boundary.permissions
    == authority_t0.permissions
)

send_text_still_present = (
    "SEND"
    in authority_at_boundary.permissions
)

boundary_status_revoked = (
    authority_at_boundary.status
    == AuthorityStatus.REVOKED
)

boundary_has_send_authority = (
    authority_at_boundary.has_authority(
        "SEND"
    )
)

state_hash_changed = (
    authority_at_boundary.state_hash()
    != authority_t0.state_hash()
)


outbox_before = broker.outbox_size()

result = broker.execute(
    request
)

outbox_after = broker.outbox_size()


reasons = list(
    result.reasons
)


expected_reasons = {
    "AUTHORITY_STATE_HASH_CHANGED",
    "CURRENT_PERMISSION_NOT_ESTABLISHED",
}


required_reasons_present = (
    expected_reasons.issubset(
        set(reasons)
    )
)


isolated_semantic_reasons = (
    set(reasons)
    == expected_reasons
)


resolver_called_once = (
    resolver_state["calls"] == 1
)


chain_valid, chain_errors = (
    ledger.verify_chain()
)


p2_h11_pass = (
    resolver_called_once
    and
    resolver_return_is_authority_state
    and
    actor_unchanged
    and
    authority_source_unchanged
    and
    epoch_unchanged
    and
    permissions_unchanged
    and
    send_text_still_present
    and
    boundary_status_revoked
    and
    not boundary_has_send_authority
    and
    state_hash_changed
    and
    not result.executed
    and
    result.status
    == "REFUSED_BEFORE_CONSEQUENCE"
    and
    required_reasons_present
    and
    isolated_semantic_reasons
    and
    outbox_before == 0
    and
    outbox_after == 0
    and
    chain_valid
)


classification = (
    "TYPE_CORRECT_REVOKED_AUTHORITY_REFUSED"
    if p2_h11_pass
    else
    "SEMANTIC_AUTHORITY_STANDING_CONTROL_NOT_ESTABLISHED"
)


evidence = {
    "test_id":
        TEST_ID,

    "classification":
        classification,

    "observed_at_utc":
        utc_now(),

    "predecessor_commit":
        "9605b3c",

    "attack":
        (
            "The consequence-boundary resolver returns "
            "a genuine AuthorityState with unchanged "
            "actor, authority source, epoch and SEND "
            "permission text, but status is REVOKED."
        ),

    "permit_id":
        permit.permit_id,

    "resolver_calls":
        resolver_state["calls"],

    "resolver_called_once":
        resolver_called_once,

    "resolver_return_is_authority_state":
        resolver_return_is_authority_state,

    "actor_unchanged":
        actor_unchanged,

    "authority_source_unchanged":
        authority_source_unchanged,

    "epoch_unchanged":
        epoch_unchanged,

    "permissions_unchanged":
        permissions_unchanged,

    "send_text_still_present":
        send_text_still_present,

    "t0_status":
        authority_t0.status.value,

    "boundary_status":
        authority_at_boundary.status.value,

    "boundary_status_revoked":
        boundary_status_revoked,

    "boundary_has_send_authority":
        boundary_has_send_authority,

    "t0_state_hash":
        authority_t0.state_hash(),

    "boundary_state_hash":
        authority_at_boundary.state_hash(),

    "state_hash_changed":
        state_hash_changed,

    "executed":
        result.executed,

    "status":
        result.status,

    "reasons":
        reasons,

    "required_reasons_present":
        required_reasons_present,

    "isolated_semantic_reasons":
        isolated_semantic_reasons,

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

    "p2_h11_pass":
        p2_h11_pass,

    "bounded_finding":
        (
            "Under frozen deterministic P2-H11, "
            "a type-correct AuthorityState did not "
            "establish execution standing merely "
            "because actor, source, epoch and SEND "
            "permission text remained unchanged when "
            "its semantic status was REVOKED."
        ),

    "nonclaim":
        (
            "This test deliberately constructs an "
            "adversarial AuthorityState directly to "
            "hold epoch and permission text constant. "
            "It establishes only the frozen verifier/"
            "firewall/broker behavior for this tested "
            "semantic-status condition. It does not "
            "establish that such a state can arise "
            "through the normal authority transition "
            "API, nor does it establish external "
            "authority provenance or production-system "
            "assurance."
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
    "P2-H11 CLASSIFICATION:",
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
    if p2_h11_pass
    else 2
)
