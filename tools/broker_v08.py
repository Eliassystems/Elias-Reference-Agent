from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict

from core.authority import AuthorityState
from core.authority_resolution_attestation import (
    AttestedAuthorityResolution,
)
from core.caller_identity_attestation import (
    CallerIdentityAttestation,
)
from core.execution_firewall_v08 import (
    ExecutionFirewallV08,
    FirewallResultV08,
)
from core.permit_v03 import ExecutionPermitV03
from tools.messaging_demo_v06 import (
    MessagingDemoToolV06,
)


@dataclass(frozen=True)
class ToolRequestV08:
    permit: ExecutionPermitV03
    current_authority: AuthorityState
    presenting_agent_id: str
    caller_identity_attestation: CallerIdentityAttestation
    authority_resolver: Callable[
        [],
        AttestedAuthorityResolution,
    ]
    intent_hash: str
    permission: str
    policy_version: str
    target: str
    tool_name: str
    consequence_class: str
    arguments: Dict[str, Any]


class ToolBrokerV08:

    def __init__(
        self,
        *,
        firewall: ExecutionFirewallV08,
        messaging_tool: MessagingDemoToolV06,
    ):
        self._firewall = firewall
        self.__messaging_tool = (
            messaging_tool
        )

    def execute(
        self,
        request: ToolRequestV08,
    ) -> FirewallResultV08:

        tool_name = (
            request.tool_name
            .strip()
            .upper()
        )

        if tool_name != "MESSAGING_DEMO":
            raise ValueError(
                "UNREGISTERED_TOOL"
            )

        if set(
            request.arguments.keys()
        ) != {
            "content"
        }:
            raise ValueError(
                "INVALID_ARGUMENT_SET"
            )

        content = (
            request.arguments[
                "content"
            ]
        )

        return self._firewall.execute(
            permit=
                request.permit,

            current_authority=
                request.current_authority,
            presenting_agent_id=
                request.presenting_agent_id,

            caller_identity_attestation=
                request.caller_identity_attestation,

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

            authority_resolver=
                request.authority_resolver,

            action=lambda commit_gate:
                self.__messaging_tool.send(
                    target=
                        request.target,

                    content=
                        content,

                    commit_gate=
                        commit_gate,
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
