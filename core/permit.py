from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
import hashlib
import hmac
import json
import secrets

from core.authority import AuthorityState


CONSTITUTION_ID = "ERA-CONSTITUTION-001"
CONSTITUTION_VERSION = "0.1.0"
CONSTITUTION_SHA256 = "6FF2C14C67DF4B009F81551AD55ECD4C1EA314B5827D7B039D0E21AD934D302A"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class ExecutionPermit:
    permit_id: str

    intent_hash: str

    actor_id: str
    authority_source: str
    authority_epoch: int
    authority_state_hash: str

    permission: str

    policy_version: str

    constitution_id: str
    constitution_version: str
    constitution_sha256: str

    target: str
    tool: str
    consequence_class: str

    issued_at: str
    expires_at: str
    nonce: str

    signature: str

    def unsigned_payload(self) -> dict:
        return {
            "intent_hash": self.intent_hash,
            "actor_id": self.actor_id,
            "authority_source": self.authority_source,
            "authority_epoch": self.authority_epoch,
            "authority_state_hash": self.authority_state_hash,
            "permission": self.permission,
            "policy_version": self.policy_version,
            "constitution_id": self.constitution_id,
            "constitution_version": self.constitution_version,
            "constitution_sha256": self.constitution_sha256,
            "target": self.target,
            "tool": self.tool,
            "consequence_class": self.consequence_class,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
        }


@dataclass(frozen=True)
class PermitValidation:
    valid: bool
    reasons: Tuple[str, ...]


class PermitIssuer:
    """
    Trusted permit-issuing boundary.

    The agent does NOT get to invent an ExecutionPermit.
    A permit can only be issued from current constituted AuthorityState.
    """

    def __init__(self, signing_key: bytes):
        if not isinstance(signing_key, bytes):
            raise TypeError("signing_key must be bytes")

        if len(signing_key) < 32:
            raise ValueError("signing_key must contain at least 32 bytes")

        self._signing_key = signing_key

    def _signature(self, payload: dict) -> str:
        return hmac.new(
            self._signing_key,
            _canonical_json(payload),
            hashlib.sha256,
        ).hexdigest().upper()

    def issue(
        self,
        *,
        authority: AuthorityState,
        intent_hash: str,
        permission: str,
        policy_version: str,
        target: str,
        tool: str,
        consequence_class: str,
        ttl_seconds: int = 300,
        now: Optional[datetime] = None,
    ) -> ExecutionPermit:

        permission = permission.strip().upper()
        target = target.strip()
        tool = tool.strip()
        consequence_class = consequence_class.strip().upper()
        policy_version = policy_version.strip()

        if not authority.has_authority(permission):
            raise PermissionError(
                f"Current authority does not establish {permission}"
            )

        if not target:
            raise ValueError("target must be constituted")

        if not tool:
            raise ValueError("tool must be constituted")

        if not policy_version:
            raise ValueError("policy_version must be established")

        if ttl_seconds < 1:
            raise ValueError("ttl_seconds must be >= 1")

        current_time = now or _utc_now()
        expiry = current_time + timedelta(seconds=ttl_seconds)

        unsigned = {
            "intent_hash": intent_hash,
            "actor_id": authority.actor_id,
            "authority_source": authority.authority_source,
            "authority_epoch": authority.epoch,
            "authority_state_hash": authority.state_hash(),
            "permission": permission,
            "policy_version": policy_version,
            "constitution_id": CONSTITUTION_ID,
            "constitution_version": CONSTITUTION_VERSION,
            "constitution_sha256": CONSTITUTION_SHA256,
            "target": target,
            "tool": tool,
            "consequence_class": consequence_class,
            "issued_at": _iso(current_time),
            "expires_at": _iso(expiry),
            "nonce": secrets.token_hex(16).upper(),
        }

        permit_id = hashlib.sha256(
            _canonical_json(unsigned)
        ).hexdigest().upper()

        signature = self._signature(unsigned)

        return ExecutionPermit(
            permit_id=permit_id,
            signature=signature,
            **unsigned,
        )


class PermitVerifier:
    """
    Execution-side verification.

    A permit is insufficient merely because it was historically valid.
    It must still match PRESENT authority and the exact requested action.
    """

    def __init__(self, signing_key: bytes):
        if not isinstance(signing_key, bytes):
            raise TypeError("signing_key must be bytes")

        if len(signing_key) < 32:
            raise ValueError("signing_key must contain at least 32 bytes")

        self._signing_key = signing_key

    def _expected_signature(self, permit: ExecutionPermit) -> str:
        return hmac.new(
            self._signing_key,
            _canonical_json(permit.unsigned_payload()),
            hashlib.sha256,
        ).hexdigest().upper()

    def verify(
        self,
        *,
        permit: ExecutionPermit,
        current_authority: AuthorityState,
        expected_intent_hash: str,
        expected_permission: str,
        expected_policy_version: str,
        expected_target: str,
        expected_tool: str,
        expected_consequence_class: str,
        now: Optional[datetime] = None,
    ) -> PermitValidation:

        reasons = []

        expected_permission = expected_permission.strip().upper()
        expected_target = expected_target.strip()
        expected_tool = expected_tool.strip()
        expected_consequence_class = expected_consequence_class.strip().upper()

        expected_signature = self._expected_signature(permit)

        if not hmac.compare_digest(
            permit.signature,
            expected_signature,
        ):
            reasons.append("SIGNATURE_INVALID")

        computed_permit_id = hashlib.sha256(
            _canonical_json(permit.unsigned_payload())
        ).hexdigest().upper()

        if permit.permit_id != computed_permit_id:
            reasons.append("PERMIT_ID_INVALID")

        if permit.constitution_id != CONSTITUTION_ID:
            reasons.append("CONSTITUTION_ID_MISMATCH")

        if permit.constitution_version != CONSTITUTION_VERSION:
            reasons.append("CONSTITUTION_VERSION_MISMATCH")

        if permit.constitution_sha256 != CONSTITUTION_SHA256:
            reasons.append("CONSTITUTION_HASH_MISMATCH")

        if permit.actor_id != current_authority.actor_id:
            reasons.append("ACTOR_ID_CHANGED")

        if permit.authority_source != current_authority.authority_source:
            reasons.append("AUTHORITY_SOURCE_CHANGED")

        if permit.authority_epoch != current_authority.epoch:
            reasons.append("AUTHORITY_EPOCH_CHANGED")

        if permit.authority_state_hash != current_authority.state_hash():
            reasons.append("AUTHORITY_STATE_HASH_CHANGED")

        if not current_authority.has_authority(expected_permission):
            reasons.append("CURRENT_PERMISSION_NOT_ESTABLISHED")

        if permit.permission != expected_permission:
            reasons.append("PERMISSION_BINDING_MISMATCH")

        if permit.intent_hash != expected_intent_hash:
            reasons.append("INTENT_BINDING_MISMATCH")

        if permit.policy_version != expected_policy_version:
            reasons.append("POLICY_VERSION_MISMATCH")

        if permit.target != expected_target:
            reasons.append("TARGET_BINDING_MISMATCH")

        if permit.tool != expected_tool:
            reasons.append("TOOL_BINDING_MISMATCH")

        if permit.consequence_class != expected_consequence_class:
            reasons.append("CONSEQUENCE_BINDING_MISMATCH")

        current_time = now or _utc_now()

        if current_time < _parse_iso(permit.issued_at):
            reasons.append("PERMIT_NOT_YET_VALID")

        if current_time >= _parse_iso(permit.expires_at):
            reasons.append("PERMIT_EXPIRED")

        return PermitValidation(
            valid=len(reasons) == 0,
            reasons=tuple(reasons),
        )
