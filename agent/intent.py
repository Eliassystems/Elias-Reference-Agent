from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple
import hashlib
import json


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class CanonicalIntent:
    """
    L2 - UNDERSTANDING

    Constituted BEFORE intelligence is invoked.

    The model may reason about how to satisfy this intent.
    It does not get to silently redefine the target,
    consequence class, permission, tool, or policy.
    """

    actor_id: str
    objective: str

    permission: str
    policy_version: str

    target: str
    tool: str
    consequence_class: str

    constraints: Tuple[str, ...]

    @classmethod
    def constitute(
        cls,
        *,
        actor_id: str,
        objective: str,
        permission: str,
        policy_version: str,
        target: str,
        tool: str,
        consequence_class: str,
        constraints: Tuple[str, ...] = (),
    ) -> "CanonicalIntent":

        actor_id = actor_id.strip()
        objective = objective.strip()
        permission = permission.strip().upper()
        policy_version = policy_version.strip()
        target = target.strip()
        tool = tool.strip().upper()
        consequence_class = (
            consequence_class.strip().upper()
        )

        if not actor_id:
            raise ValueError(
                "actor_id must be established"
            )

        if not objective:
            raise ValueError(
                "objective must be established"
            )

        if not permission:
            raise ValueError(
                "permission must be established"
            )

        if not policy_version:
            raise ValueError(
                "policy_version must be established"
            )

        if not target:
            raise ValueError(
                "target must be established"
            )

        if not tool:
            raise ValueError(
                "tool must be established"
            )

        if not consequence_class:
            raise ValueError(
                "consequence_class must be established"
            )

        return cls(
            actor_id=actor_id,
            objective=objective,
            permission=permission,
            policy_version=policy_version,
            target=target,
            tool=tool,
            consequence_class=consequence_class,
            constraints=tuple(constraints),
        )

    def payload(self) -> dict:
        return {
            "actor_id": self.actor_id,
            "objective": self.objective,
            "permission": self.permission,
            "policy_version": self.policy_version,
            "target": self.target,
            "tool": self.tool,
            "consequence_class":
                self.consequence_class,
            "constraints": list(
                self.constraints
            ),
        }

    def intent_hash(self) -> str:
        return hashlib.sha256(
            _canonical_json(self.payload())
        ).hexdigest().upper()
