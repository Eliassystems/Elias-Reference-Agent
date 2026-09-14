from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class MessagingDemoTool:
    """
    Demo side-effect target.

    It does NOT send a real external message.

    The outbox records only calls that actually reached the
    tool after crossing the Elias Execution Firewall.
    """

    outbox: List[dict] = field(
        default_factory=list
    )

    def send(
        self,
        *,
        target: str,
        content: str,
    ) -> dict:

        record = {
            "target": target,
            "content": content,
            "delivery_index":
                len(self.outbox) + 1,
        }

        self.outbox.append(record)

        return record
