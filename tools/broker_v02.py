from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from core.authority import AuthorityState
from core.execution_firewall_v02 import (
    ExecutionFirewallV02,
    FirewallResultV02,
)
from core.permit_v02 import ExecutionPermitV02
from tools.messaging_demo import MessagingDemoTool


@dataclass(frozen=True)
class ToolRequestV02:
    permit: ExecutionPermitV02
    current_authority: AuthorityState
    intent_hash: str
    permission: str
    policy_version: str
    target: str
    tool_name: str
    consequence_class: str
    arguments: Dict[str, Any]


class ToolBrokerV02:

    def __init__(
        self,
        *,
        firewall: ExecutionFirewallV02,
        messaging_tool: MessagingDemoTool,
    ):
        self._firewall = firewall
        self.__messaging_tool = messaging_tool

    def execute(
        self,
        request: ToolRequestV02,
    ) -> FirewallResultV02:

        tool_name = (
            request.tool_name.strip().upper()
        )

        if tool_name != "MESSAGING_DEMO":
            raise ValueError(
                "UNREGISTERED_TOOL"
            )

        if set(request.arguments.keys()) != {
            "content"
        }:
            raise ValueError(
                "INVALID_ARGUMENT_SET"
            )

        content = request.arguments["content"]

        return self._firewall.execute(
            permit=request.permit,
            current_authority=
                request.current_authority,
            expected_intent_hash=
                request.intent_hash,
            expected_permission=
                request.permission,
            expected_policy_version=
                request.policy_version,
            expected_target=
                request.target,
            expected_tool=
                tool_name,
            expected_consequence_class=
                request.consequence_class,
            expected_arguments=
                request.arguments,
            action=lambda:
                self.__messaging_tool.send(
                    target=request.target,
                    content=content,
                ),
        )

    def outbox_size(self) -> int:
        return len(
            self.__messaging_tool.outbox
        )

    def outbox_snapshot(self) -> tuple:
        return tuple(
            dict(item)
            for item
            in self.__messaging_tool.outbox
        )
