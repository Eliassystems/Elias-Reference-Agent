from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet, Iterable
import hashlib
import json


class AuthorityStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"


@dataclass(frozen=True)
class AuthorityState:
    """
    Elias Authority State

    Important properties:
    - Authority is external to intelligence.
    - Every material authority change advances the epoch.
    - Old epochs do not regain validity merely because similar
      permissions are later restored.
    - The object is immutable: changes create a new AuthorityState.
    """

    actor_id: str
    authority_source: str
    epoch: int
    permissions: FrozenSet[str]
    status: AuthorityStatus
    reason: str

    @classmethod
    def create(
        cls,
        actor_id: str,
        authority_source: str,
        permissions: Iterable[str],
        epoch: int = 1,
    ) -> "AuthorityState":
        if not actor_id.strip():
            raise ValueError("actor_id must be established")

        if not authority_source.strip():
            raise ValueError("authority_source must be established")

        if epoch < 1:
            raise ValueError("authority epoch must be >= 1")

        normalized = frozenset(cls._normalize_permission(p) for p in permissions)

        return cls(
            actor_id=actor_id.strip(),
            authority_source=authority_source.strip(),
            epoch=epoch,
            permissions=normalized,
            status=AuthorityStatus.ACTIVE,
            reason="INITIAL_AUTHORITY_STATE",
        )

    @staticmethod
    def _normalize_permission(permission: str) -> str:
        value = permission.strip().upper()

        if not value:
            raise ValueError("permission cannot be empty")

        return value

    def has_authority(self, permission: str) -> bool:
        permission = self._normalize_permission(permission)

        return (
            self.status == AuthorityStatus.ACTIVE
            and permission in self.permissions
        )

    def grant(
        self,
        *permissions: str,
        reason: str = "EXTERNAL_AUTHORITY_GRANT",
    ) -> "AuthorityState":
        additions = frozenset(
            self._normalize_permission(p)
            for p in permissions
        )

        new_permissions = self.permissions | additions

        # Re-authorisation after a revoke is a new authority state,
        # even where the permission set looks identical.
        material_change = (
            self.status != AuthorityStatus.ACTIVE
            or new_permissions != self.permissions
        )

        if not material_change:
            return self

        return AuthorityState(
            actor_id=self.actor_id,
            authority_source=self.authority_source,
            epoch=self.epoch + 1,
            permissions=new_permissions,
            status=AuthorityStatus.ACTIVE,
            reason=reason,
        )

    def revoke_permission(
        self,
        permission: str,
        reason: str = "EXTERNAL_AUTHORITY_REVOCATION",
    ) -> "AuthorityState":
        permission = self._normalize_permission(permission)

        if (
            self.status == AuthorityStatus.REVOKED
            or permission not in self.permissions
        ):
            return self

        return AuthorityState(
            actor_id=self.actor_id,
            authority_source=self.authority_source,
            epoch=self.epoch + 1,
            permissions=self.permissions - {permission},
            status=AuthorityStatus.ACTIVE,
            reason=reason,
        )

    def revoke_all(
        self,
        reason: str = "EXTERNAL_AUTHORITY_REVOKED",
    ) -> "AuthorityState":
        if self.status == AuthorityStatus.REVOKED:
            return self

        return AuthorityState(
            actor_id=self.actor_id,
            authority_source=self.authority_source,
            epoch=self.epoch + 1,
            permissions=frozenset(),
            status=AuthorityStatus.REVOKED,
            reason=reason,
        )

    def replace_permissions(
        self,
        permissions: Iterable[str],
        reason: str = "EXTERNAL_AUTHORITY_RECONSTITUTION",
    ) -> "AuthorityState":
        new_permissions = frozenset(
            self._normalize_permission(p)
            for p in permissions
        )

        if (
            self.status == AuthorityStatus.ACTIVE
            and new_permissions == self.permissions
        ):
            return self

        return AuthorityState(
            actor_id=self.actor_id,
            authority_source=self.authority_source,
            epoch=self.epoch + 1,
            permissions=new_permissions,
            status=AuthorityStatus.ACTIVE,
            reason=reason,
        )

    def canonical_payload(self) -> dict:
        return {
            "actor_id": self.actor_id,
            "authority_source": self.authority_source,
            "epoch": self.epoch,
            "permissions": sorted(self.permissions),
            "status": self.status.value,
            "reason": self.reason,
        }

    def state_hash(self) -> str:
        canonical = json.dumps(
            self.canonical_payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

        return hashlib.sha256(canonical).hexdigest().upper()
