from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
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
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def build_action_envelope(
    *,
    permission: str,
    target: str,
    tool: str,
    consequence_class: str,
    arguments: Dict[str, Any],
) -> dict:
    return {
        "permission": permission.strip().upper(),
        "target": target.strip(),
        "tool": tool.strip().upper(),
        "consequence_class":
            consequence_class.strip().upper(),
        "arguments": arguments,
    }


def action_hash(envelope: dict) -> str:
    return hashlib.sha256(
        _canonical_json(envelope)
    ).hexdigest().upper()


@dataclass(frozen=True)
class ExecutionPermitV02:
    permit_id: str

    intent_hash: str
    action_hash: str

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
            "action_hash": self.action_hash,
            "actor_id": self.actor_id,
            "authority_source": self.authority_source,
            "authority_epoch": self.authority_epoch,
            "authority_state_hash":
                self.authority_state_hash,
            "permission": self.permission,
            "policy_version": self.policy_version,
            "constitution_id": self.constitution_id,
            "constitution_version":
                self.constitution_version,
            "constitution_sha256":
                self.constitution_sha256,
            "target": self.target,
            "tool": self.tool,
            "consequence_class":
                self.consequence_class,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
        }


@dataclass(frozen=True)
class PermitValidationV02:
    valid: bool
    reasons: Tuple[str, ...]


class PermitIssuerV02:

    def __init__(self, signing_key: bytes):
        if len(signing_key) < 32:
            raise ValueError(
                "signing_key must contain at least 32 bytes"
            )

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
        arguments: Dict[str, Any],
        ttl_seconds: int = 300,
        now: Optional[datetime] = None,
    ) -> ExecutionPermitV02:

        permission = permission.strip().upper()
        target = target.strip()
        tool = tool.strip().upper()
        consequence_class = (
            consequence_class.strip().upper()
        )

        if not authority.has_authority(permission):
            raise PermissionError(
                "CURRENT_AUTHORITY_NOT_ESTABLISHED"
            )

        envelope = build_action_envelope(
            permission=permission,
            target=target,
            tool=tool,
            consequence_class=consequence_class,
            arguments=arguments,
        )

        bound_action_hash = action_hash(envelope)

        current_time = now or _utc_now()
        expiry = current_time + timedelta(
            seconds=ttl_seconds
        )

        unsigned = {
            "intent_hash": intent_hash,
            "action_hash": bound_action_hash,
            "actor_id": authority.actor_id,
            "authority_source":
                authority.authority_source,
            "authority_epoch": authority.epoch,
            "authority_state_hash":
                authority.state_hash(),
            "permission": permission,
            "policy_version":
                policy_version.strip(),
            "constitution_id":
                CONSTITUTION_ID,
            "constitution_version":
                CONSTITUTION_VERSION,
            "constitution_sha256":
                CONSTITUTION_SHA256,
            "target": target,
            "tool": tool,
            "consequence_class":
                consequence_class,
            "issued_at": _iso(current_time),
            "expires_at": _iso(expiry),
            "nonce":
                secrets.token_hex(16).upper(),
        }

        permit_id = hashlib.sha256(
            _canonical_json(unsigned)
        ).hexdigest().upper()

        signature = self._signature(unsigned)

        return ExecutionPermitV02(
            permit_id=permit_id,
            signature=signature,
            **unsigned,
        )


class PermitVerifierV02:

    def __init__(self, signing_key: bytes):
        if len(signing_key) < 32:
            raise ValueError(
                "signing_key must contain at least 32 bytes"
            )

        self._signing_key = signing_key

    def _expected_signature(
        self,
        permit: ExecutionPermitV02,
    ) -> str:

        return hmac.new(
            self._signing_key,
            _canonical_json(
                permit.unsigned_payload()
            ),
            hashlib.sha256,
        ).hexdigest().upper()

    def verify(
        self,
        *,
        permit: ExecutionPermitV02,
        current_authority: AuthorityState,
        expected_intent_hash: str,
        expected_permission: str,
        expected_policy_version: str,
        expected_target: str,
        expected_tool: str,
        expected_consequence_class: str,
        expected_arguments: Dict[str, Any],
        now: Optional[datetime] = None,
    ) -> PermitValidationV02:

        reasons = []

        expected_permission = (
            expected_permission.strip().upper()
        )
        expected_target = expected_target.strip()
        expected_tool = (
            expected_tool.strip().upper()
        )
        expected_consequence_class = (
            expected_consequence_class
            .strip()
            .upper()
        )

        expected_signature = (
            self._expected_signature(permit)
        )

        if not hmac.compare_digest(
            permit.signature,
            expected_signature,
        ):
            reasons.append(
                "SIGNATURE_INVALID"
            )

        computed_permit_id = hashlib.sha256(
            _canonical_json(
                permit.unsigned_payload()
            )
        ).hexdigest().upper()

        if permit.permit_id != computed_permit_id:
            reasons.append(
                "PERMIT_ID_INVALID"
            )

        expected_envelope = build_action_envelope(
            permission=expected_permission,
            target=expected_target,
            tool=expected_tool,
            consequence_class=
                expected_consequence_class,
            arguments=expected_arguments,
        )

        expected_action_hash = action_hash(
            expected_envelope
        )

        if permit.action_hash != expected_action_hash:
            reasons.append(
                "ACTION_BINDING_MISMATCH"
            )

        if permit.actor_id != current_authority.actor_id:
            reasons.append(
                "ACTOR_ID_CHANGED"
            )

        if (
            permit.authority_source
            != current_authority.authority_source
        ):
            reasons.append(
                "AUTHORITY_SOURCE_CHANGED"
            )

        if (
            permit.authority_epoch
            != current_authority.epoch
        ):
            reasons.append(
                "AUTHORITY_EPOCH_CHANGED"
            )

        if (
            permit.authority_state_hash
            != current_authority.state_hash()
        ):
            reasons.append(
                "AUTHORITY_STATE_HASH_CHANGED"
            )

        if not current_authority.has_authority(
            expected_permission
        ):
            reasons.append(
                "CURRENT_PERMISSION_NOT_ESTABLISHED"
            )

        if permit.permission != expected_permission:
            reasons.append(
                "PERMISSION_BINDING_MISMATCH"
            )

        if permit.intent_hash != expected_intent_hash:
            reasons.append(
                "INTENT_BINDING_MISMATCH"
            )

        if (
            permit.policy_version
            != expected_policy_version
        ):
            reasons.append(
                "POLICY_VERSION_MISMATCH"
            )

        if permit.target != expected_target:
            reasons.append(
                "TARGET_BINDING_MISMATCH"
            )

        if permit.tool != expected_tool:
            reasons.append(
                "TOOL_BINDING_MISMATCH"
            )

        if (
            permit.consequence_class
            != expected_consequence_class
        ):
            reasons.append(
                "CONSEQUENCE_BINDING_MISMATCH"
            )

        if (
            permit.constitution_sha256
            != CONSTITUTION_SHA256
        ):
            reasons.append(
                "CONSTITUTION_HASH_MISMATCH"
            )

        current_time = now or _utc_now()

        if current_time >= _parse_iso(
            permit.expires_at
        ):
            reasons.append(
                "PERMIT_EXPIRED"
            )

        return PermitValidationV02(
            valid=len(reasons) == 0,
            reasons=tuple(reasons),
        )
