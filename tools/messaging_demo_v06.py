from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List

from core.authority import AuthorityState


@dataclass
class MessagingDemoToolV06:
    """
    V06 demo side-effect target.

    The commit gate is invoked immediately before the local
    outbox mutation.

    This remains a deterministic local reference primitive.
    It is not a claim of distributed or operating-system
    transaction atomicity.
    """

    outbox: List[dict] = field(
        default_factory=list
    )

    def send(
        self,
        *,
        target: str,
        content: str,
        commit_gate: Callable[
            [],
            AuthorityState,
        ],
    ) -> dict:

        commit_authority = (
            commit_gate()
        )

        record = {
            "target":
                target,

            "content":
                content,

            "delivery_index":
                len(self.outbox) + 1,

            "commit_authority_epoch":
                commit_authority.epoch,

            "commit_authority_state_hash":
                commit_authority.state_hash(),
        }

        self.outbox.append(
            record
        )

        return record
