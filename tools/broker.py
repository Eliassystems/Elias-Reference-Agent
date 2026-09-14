from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from core.authority import AuthorityState
from core.execution_firewall import (
    ExecutionFirewall,
    FirewallResult,
)
from core.permit import ExecutionPermit
from tools.messaging_demo import MessagingDemoTool


@dataclass(frozen=True)
class ToolRequest:
    permit: ExecutionPermit
    current_authority: AuthorityState
    intent_hash: str
    permission: str
    policy_version: str
    target: str
    tool_name: str
    consequence_class: str
    arguments: Dict[str, Any]


class ToolBroker:
    """
    Elias Tool Broker.

    The agent receives the broker rather than direct access
    to consequence-producing tools.

    All consequential execution is routed through
    the Elias Execution Firewall.
    """

    def __init__(
        self,
        *,
        firewall: ExecutionFirewall,
        messaging_tool: MessagingDemoTool,
    ):
        self._firewall = firewall
        self.__messaging_tool = messaging_tool

    def execute(
        self,
        request: ToolRequest,
    ) -> FirewallResult:

        tool_name = request.tool_name.strip().upper()

        if tool_name != "MESSAGING_DEMO":
            raise ValueError(
                "UNREGISTERED_TOOL: {}".format(tool_name)
            )

        if set(request.arguments.keys()) != {"content"}:
            raise ValueError(
                "MESSAGING_DEMO accepts only: content"
            )

        content = request.arguments["content"]

        if not isinstance(content, str):
            raise TypeError(
                "content must be a string"
            )

        return self._firewall.execute(
            permit=request.permit,
            current_authority=request.current_authority,
            expected_intent_hash=request.intent_hash,
            expected_permission=request.permission,
            expected_policy_version=request.policy_version,
            expected_target=request.target,
            expected_tool=tool_name,
            expected_consequence_class=request.consequence_class,
            action=lambda: self.__messaging_tool.send(
                target=request.target,
                content=content,
            ),
        )

    def outbox_size(self) -> int:
        return len(self.__messaging_tool.outbox)

    def outbox_snapshot(self) -> tuple:
        return tuple(
            dict(item)
            for item in self.__messaging_tool.outbox
        )
