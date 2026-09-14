from dataclasses import replace
from pathlib import Path
import hashlib
import secrets
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from core.authority import AuthorityState
from core.permit import PermitIssuer, PermitVerifier


def heading(text):
    print()
    print("=" * 72)
    print(text)
    print("=" * 72)


def show_result(result):
    print("VALID:   ", result.valid)
    print("REASONS: ", list(result.reasons))


heading("ELIAS EXECUTION PERMIT TEST")

# Demo-only key.
# Later this signing authority will be isolated from the agent runtime.
signing_key = secrets.token_bytes(32)

issuer = PermitIssuer(signing_key)
verifier = PermitVerifier(signing_key)

authority_t0 = AuthorityState.create(
    actor_id="HUMAN-001",
    authority_source="HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"READ", "SEND"},
    epoch=1,
)

intent_text = "Send governed summary to RECIPIENT-A"

intent_hash = hashlib.sha256(
    intent_text.encode("utf-8")
).hexdigest().upper()

permit_t0 = issuer.issue(
    authority=authority_t0,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version="ERA-POLICY-001-v0.1.0",
    target="RECIPIENT-A",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    ttl_seconds=300,
)

print("PERMIT ID:       ", permit_t0.permit_id)
print("AUTHORITY EPOCH: ", permit_t0.authority_epoch)
print("TARGET:          ", permit_t0.target)
print("TOOL:            ", permit_t0.tool)
print("CONSEQUENCE:     ", permit_t0.consequence_class)

initial_result = verifier.verify(
    permit=permit_t0,
    current_authority=authority_t0,
    expected_intent_hash=intent_hash,
    expected_permission="SEND",
    expected_policy_version="ERA-POLICY-001-v0.1.0",
    expected_target="RECIPIENT-A",
    expected_tool="MESSAGING_DEMO",
    expected_consequence_class="C4",
)

show_result(initial_result)

assert initial_result.valid

heading("HUMAN REVOKES SEND AFTER PERMIT WAS ISSUED")

authority_t1 = authority_t0.revoke_permission(
    "SEND",
    reason="HUMAN_VETO",
)

print("PERMIT EPOCH:  ", permit_t0.authority_epoch)
print("CURRENT EPOCH: ", authority_t1.epoch)

revoked_result = verifier.verify(
    permit=permit_t0,
    current_authority=authority_t1,
    expected_intent_hash=intent_hash,
    expected_permission="SEND",
    expected_policy_version="ERA-POLICY-001-v0.1.0",
    expected_target="RECIPIENT-A",
    expected_tool="MESSAGING_DEMO",
    expected_consequence_class="C4",
)

show_result(revoked_result)

assert not revoked_result.valid
assert "AUTHORITY_EPOCH_CHANGED" in revoked_result.reasons
assert "AUTHORITY_STATE_HASH_CHANGED" in revoked_result.reasons
assert "CURRENT_PERMISSION_NOT_ESTABLISHED" in revoked_result.reasons

heading("HUMAN RE-AUTHORISES SEND")

authority_t2 = authority_t1.grant(
    "SEND",
    reason="HUMAN_REAUTHORISATION",
)

print("OLD PERMIT EPOCH:", permit_t0.authority_epoch)
print("NEW STATE EPOCH: ", authority_t2.epoch)
print("SEND PRESENT:    ", authority_t2.has_authority("SEND"))

old_permit_after_restore = verifier.verify(
    permit=permit_t0,
    current_authority=authority_t2,
    expected_intent_hash=intent_hash,
    expected_permission="SEND",
    expected_policy_version="ERA-POLICY-001-v0.1.0",
    expected_target="RECIPIENT-A",
    expected_tool="MESSAGING_DEMO",
    expected_consequence_class="C4",
)

show_result(old_permit_after_restore)

assert not old_permit_after_restore.valid
assert "AUTHORITY_EPOCH_CHANGED" in old_permit_after_restore.reasons

print()
print("PASS")
print("Old permit does NOT revive merely because SEND permission exists again.")

heading("ISSUE NEW PERMIT UNDER CURRENT AUTHORITY")

permit_t2 = issuer.issue(
    authority=authority_t2,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version="ERA-POLICY-001-v0.1.0",
    target="RECIPIENT-A",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    ttl_seconds=300,
)

new_result = verifier.verify(
    permit=permit_t2,
    current_authority=authority_t2,
    expected_intent_hash=intent_hash,
    expected_permission="SEND",
    expected_policy_version="ERA-POLICY-001-v0.1.0",
    expected_target="RECIPIENT-A",
    expected_tool="MESSAGING_DEMO",
    expected_consequence_class="C4",
)

show_result(new_result)

assert new_result.valid

heading("ATTEMPT TARGET SUBSTITUTION")

tampered = replace(
    permit_t2,
    target="RECIPIENT-B",
)

tamper_result = verifier.verify(
    permit=tampered,
    current_authority=authority_t2,
    expected_intent_hash=intent_hash,
    expected_permission="SEND",
    expected_policy_version="ERA-POLICY-001-v0.1.0",
    expected_target="RECIPIENT-A",
    expected_tool="MESSAGING_DEMO",
    expected_consequence_class="C4",
)

show_result(tamper_result)

assert not tamper_result.valid
assert "SIGNATURE_INVALID" in tamper_result.reasons
assert "PERMIT_ID_INVALID" in tamper_result.reasons
assert "TARGET_BINDING_MISMATCH" in tamper_result.reasons

heading("FINAL RESULT")

print("PASS: EXECUTION PERMIT CRYPTOGRAPHIC BINDING ESTABLISHED")
print("PASS: PERMIT BOUND TO AUTHORITY EPOCH")
print("PASS: PERMIT BOUND TO AUTHORITY STATE HASH")
print("PASS: PERMIT BOUND TO INTENT")
print("PASS: PERMIT BOUND TO TARGET")
print("PASS: PERMIT BOUND TO TOOL")
print("PASS: PERMIT BOUND TO CONSEQUENCE CLASS")
print("PASS: REVOKED AUTHORITY INVALIDATES HISTORICAL PERMIT")
print("PASS: RESTORED PERMISSION DOES NOT REVIVE OLD PERMIT")
print("PASS: TARGET TAMPERING DETECTED")
