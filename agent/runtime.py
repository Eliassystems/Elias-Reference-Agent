from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from agent.intent import CanonicalIntent
from agent.model_adapter import ModelAdapter
from core.authority import AuthorityState
from core.permit_v02 import PermitIssuerV02
from tools.broker_v02 import (
    ToolBrokerV02,
    ToolRequestV02,
)
from witness.ledger import WitnessLedger


@dataclass(frozen=True)
class AgentRunResult:
    status: str
    executed: bool

    intent_hash: str
    model_called: bool
    model_id: str

    permit_id: str

    reasons: Tuple[str, ...]
    receipt_hashes: Tuple[str, ...]

    output_content: str = ""


class EliasAgentRuntime:
    """
    Elias Reference Agent Runtime v0.1

    FLOW:

        L0 Identity
            ↓
        L1 Observation / current authority
            ↓
        L2 Canonical Intent
            ↓
        L3 Pre-intelligence governance
            ↓
        L4 Intelligence
            ↓
        Exact action constitution
            ↓
        Permit issuance
            ↓
        Optional changed condition
            ↓
        L5 Execution seam re-check
            ↓
        Broker / Firewall / Consequence
            ↓
        L6 Witness

    Intelligence does not receive unilateral
    execution authority.
    """

    def __init__(
        self,
        *,
        model: ModelAdapter,
        permit_issuer: PermitIssuerV02,
        broker: ToolBrokerV02,
        ledger: WitnessLedger,
    ):
        self.model = model
        self.permit_issuer = permit_issuer
        self.broker = broker
        self.ledger = ledger

    def _witness(
        self,
        *,
        event_type: str,
        authority: AuthorityState,
        intent: CanonicalIntent,
        governance_verdict: str,
        verdict_reason: str,
        execution_result: str,
        permit_id: str,
        details: dict,
    ) -> str:

        record = self.ledger.append(
            event_type=event_type,
            constitution_version="0.1.0",
            actor_identity=authority.actor_id,
            authority_source=
                authority.authority_source,
            authority_epoch=
                authority.epoch,
            intent_hash=
                intent.intent_hash(),
            target=
                intent.target,
            tool=
                intent.tool,
            consequence_class=
                intent.consequence_class,
            governance_verdict=
                governance_verdict,
            verdict_reason=
                verdict_reason,
            execution_result=
                execution_result,
            permit_id=
                permit_id,
            details=
                details,
        )

        return record["receipt_hash"]

    def run(
        self,
        *,
        current_authority: AuthorityState,
        objective: str,
        permission: str,
        policy_version: str,
        target: str,
        tool: str,
        consequence_class: str,
        constraints: Tuple[str, ...] = (),
        before_execute_hook: Optional[
            Callable[
                [AuthorityState],
                AuthorityState,
            ]
        ] = None,
    ) -> AgentRunResult:

        # -----------------------------------------
        # L0 / L2
        # Identity + canonical intent.
        # Intelligence has NOT been called.
        # -----------------------------------------

        intent = CanonicalIntent.constitute(
            actor_id=
                current_authority.actor_id,
            objective=
                objective,
            permission=
                permission,
            policy_version=
                policy_version,
            target=
                target,
            tool=
                tool,
            consequence_class=
                consequence_class,
            constraints=
                constraints,
        )

        intent_hash = intent.intent_hash()

        intent_receipt = self._witness(
            event_type=
                "INTENT_CONSTITUTED",
            authority=
                current_authority,
            intent=
                intent,
            governance_verdict=
                "UNCERTAIN",
            verdict_reason=
                "AWAITING_PRE_INTELLIGENCE_GOVERNANCE",
            execution_result=
                "NO_CONSEQUENCE",
            permit_id=
                "NOT_ISSUED",
            details={
                "objective":
                    intent.objective,
                "constraints":
                    list(intent.constraints),
            },
        )

        # -----------------------------------------
        # L3
        # Governance BEFORE intelligence.
        # -----------------------------------------

        if not current_authority.has_authority(
            intent.permission
        ):

            refusal_receipt = self._witness(
                event_type=
                    "PRE_INTELLIGENCE_REFUSED",
                authority=
                    current_authority,
                intent=
                    intent,
                governance_verdict=
                    "REFUSE",
                verdict_reason=
                    "CURRENT_PERMISSION_NOT_ESTABLISHED",
                execution_result=
                    "INTELLIGENCE_NOT_INVOKED",
                permit_id=
                    "NOT_ISSUED",
                details={
                    "required_permission":
                        intent.permission,
                },
            )

            return AgentRunResult(
                status=
                    "REFUSED_BEFORE_INTELLIGENCE",
                executed=False,
                intent_hash=
                    intent_hash,
                model_called=False,
                model_id="",
                permit_id=
                    "NOT_ISSUED",
                reasons=(
                    "CURRENT_PERMISSION_NOT_ESTABLISHED",
                ),
                receipt_hashes=(
                    intent_receipt,
                    refusal_receipt,
                ),
            )

        admitted_receipt = self._witness(
            event_type=
                "PRE_INTELLIGENCE_ADMITTED",
            authority=
                current_authority,
            intent=
                intent,
            governance_verdict=
                "PERMIT",
            verdict_reason=
                "INTELLIGENCE_ALLOWED_WITHIN_CONSTITUTED_ENVELOPE",
            execution_result=
                "INTELLIGENCE_ONLY",
            permit_id=
                "NOT_ISSUED",
            details={
                "execution_authority":
                    "NOT_YET_ISSUED",
            },
        )

        # -----------------------------------------
        # L4
        # Intelligence operates only now.
        # -----------------------------------------

        model_output = self.model.generate(
            intent
        )

        proposal_receipt = self._witness(
            event_type=
                "INTELLIGENCE_PROPOSAL",
            authority=
                current_authority,
            intent=
                intent,
            governance_verdict=
                "UNCERTAIN",
            verdict_reason=
                "MODEL_OUTPUT_REQUIRES_ACTION_BINDING",
            execution_result=
                "NOT_EXECUTED",
            permit_id=
                "NOT_ISSUED",
            details={
                "model_id":
                    model_output.model_id,
                "model_metadata":
                    model_output.metadata,
                "proposed_content":
                    model_output.content,
            },
        )

        # Exact consequence payload is now known.
        arguments = {
            "content":
                model_output.content
        }

        # -----------------------------------------
        # Permit issued ONLY for exact action.
        # -----------------------------------------

        permit = self.permit_issuer.issue(
            authority=
                current_authority,
            intent_hash=
                intent_hash,
            permission=
                intent.permission,
            policy_version=
                intent.policy_version,
            target=
                intent.target,
            tool=
                intent.tool,
            consequence_class=
                intent.consequence_class,
            arguments=
                arguments,
            ttl_seconds=300,
        )

        permit_receipt = self._witness(
            event_type=
                "EXECUTION_PERMIT_ISSUED",
            authority=
                current_authority,
            intent=
                intent,
            governance_verdict=
                "PERMIT",
            verdict_reason=
                "EXACT_ACTION_BOUND",
            execution_result=
                "NOT_YET_EXECUTED",
            permit_id=
                permit.permit_id,
            details={
                "action_hash":
                    permit.action_hash,
                "model_id":
                    model_output.model_id,
            },
        )

        # -----------------------------------------
        # Changed-condition seam.
        #
        # Used to prove that authority can change
        # AFTER reasoning and AFTER permit issuance.
        # -----------------------------------------

        execution_authority = (
            current_authority
        )

        if before_execute_hook is not None:
            execution_authority = (
                before_execute_hook(
                    current_authority
                )
            )

        # -----------------------------------------
        # L5
        # Exact action reaches Tool Broker.
        # Firewall re-checks PRESENT standing.
        # -----------------------------------------

        request = ToolRequestV02(
            permit=
                permit,
            current_authority=
                execution_authority,
            intent_hash=
                intent_hash,
            permission=
                intent.permission,
            policy_version=
                intent.policy_version,
            target=
                intent.target,
            tool_name=
                intent.tool,
            consequence_class=
                intent.consequence_class,
            arguments=
                arguments,
        )

        firewall_result = self.broker.execute(
            request
        )

        # -----------------------------------------
        # L6
        # Final agent-level witness.
        # -----------------------------------------

        final_receipt = self._witness(
            event_type=
                "AGENT_RUN_COMPLETED",
            authority=
                execution_authority,
            intent=
                intent,
            governance_verdict=
                (
                    "PERMIT"
                    if firewall_result.executed
                    else "REFUSE"
                ),
            verdict_reason=
                (
                    "EXECUTED_WITH_CURRENT_STANDING"
                    if firewall_result.executed
                    else ";".join(
                        firewall_result.reasons
                    )
                ),
            execution_result=
                firewall_result.status,
            permit_id=
                permit.permit_id,
            details={
                "model_id":
                    model_output.model_id,
                "firewall_receipts":
                    list(
                        firewall_result.receipt_hashes
                    ),
                "output_content":
                    model_output.content,
            },
        )

        return AgentRunResult(
            status=
                firewall_result.status,
            executed=
                firewall_result.executed,
            intent_hash=
                intent_hash,
            model_called=True,
            model_id=
                model_output.model_id,
            permit_id=
                permit.permit_id,
            reasons=
                firewall_result.reasons,
            receipt_hashes=(
                intent_receipt,
                admitted_receipt,
                proposal_receipt,
                permit_receipt,
                *firewall_result.receipt_hashes,
                final_receipt,
            ),
            output_content=
                model_output.content,
        )
