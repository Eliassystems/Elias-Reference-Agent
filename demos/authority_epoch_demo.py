from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from core.authority import AuthorityState, AuthorityStatus


def heading(text):
    print()
    print("=" * 68)
    print(text)
    print("=" * 68)


heading("ELIAS AUTHORITY EPOCH TEST")

initial = AuthorityState.create(
    actor_id="HUMAN-001",
    authority_source="HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"READ", "SEND"},
    epoch=1,
)

print("T0 STATUS:       ", initial.status.value)
print("T0 EPOCH:        ", initial.epoch)
print("T0 PERMISSIONS:  ", sorted(initial.permissions))
print("T0 STATE HASH:   ", initial.state_hash())

assert initial.has_authority("READ")
assert initial.has_authority("SEND")

historical_epoch = initial.epoch
historical_hash = initial.state_hash()

heading("HUMAN REVOKES SEND AUTHORITY")

revoked = initial.revoke_permission(
    "SEND",
    reason="HUMAN_VETO",
)

print("T1 STATUS:       ", revoked.status.value)
print("T1 EPOCH:        ", revoked.epoch)
print("T1 PERMISSIONS:  ", sorted(revoked.permissions))
print("T1 STATE HASH:   ", revoked.state_hash())

assert revoked.epoch == historical_epoch + 1
assert revoked.has_authority("READ")
assert not revoked.has_authority("SEND")
assert revoked.state_hash() != historical_hash

heading("TEST HISTORICAL AUTHORITY")

print("HISTORICAL EPOCH:", historical_epoch)
print("CURRENT EPOCH:   ", revoked.epoch)

assert historical_epoch != revoked.epoch

print()
print("PASS")
print("Historical authority no longer establishes current SEND standing.")

heading("HUMAN RE-AUTHORISES SEND")

restored = revoked.grant(
    "SEND",
    reason="HUMAN_REAUTHORISATION",
)

print("T2 STATUS:       ", restored.status.value)
print("T2 EPOCH:        ", restored.epoch)
print("T2 PERMISSIONS:  ", sorted(restored.permissions))
print("T2 STATE HASH:   ", restored.state_hash())

assert restored.has_authority("SEND")
assert restored.epoch == revoked.epoch + 1
assert restored.epoch != historical_epoch

print()
print("PASS")
print("Restored permission creates NEW standing.")
print("The old epoch does not become valid again.")

heading("EMERGENCY HUMAN VETO")

stopped = restored.revoke_all(
    reason="EMERGENCY_HUMAN_STOP",
)

print("T3 STATUS:       ", stopped.status.value)
print("T3 EPOCH:        ", stopped.epoch)
print("T3 PERMISSIONS:  ", sorted(stopped.permissions))
print("T3 STATE HASH:   ", stopped.state_hash())

assert stopped.status == AuthorityStatus.REVOKED
assert not stopped.has_authority("READ")
assert not stopped.has_authority("SEND")
assert stopped.epoch == restored.epoch + 1

heading("FINAL RESULT")

print("PASS: AUTHORITY EPOCH MECHANISM ESTABLISHED")
print("PASS: HUMAN REVOCATION CHANGES CURRENT STANDING")
print("PASS: HISTORICAL AUTHORITY DOES NOT SURVIVE EPOCH CHANGE")
print("PASS: RE-AUTHORISATION CREATES A NEW EPOCH")
print("PASS: EMERGENCY HUMAN VETO REMOVES EXECUTION AUTHORITY")
