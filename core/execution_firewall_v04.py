from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Tuple
import hashlib

from core.authority import AuthorityState
from core.permit_v02 import (
    CONSTITUTION_SHA256,
    ExecutionPermitV02,
    PermitVerifierV02,
)
from witness.ledger import WitnessLedger


@dataclass(frozen=True)
class FirewallResultV04:
    status: str
    executed: bool
    reasons: Tuple[str, ...]
    receipt_hashes: Tuple[str, ...]
    tool_result: Any = None


class ExecutionFirewallV04:

    def __init__(
        self,
        *,
        verifier: PermitVerifierV02,
        ledger: WitnessLedger,
        constitution_path: Path,
    ):
        self.verifier = verifier
        self.ledger = ledger
        self.constitution_path = Path(
            constitution_path
        )

    def _constitution_ok(self) -> bool:
        actual = hashlib.sha256(
            self.constitution_path.read_bytes()
        ).hexdigest().upper()

        return actual == CONSTITUTION_SHA256

    def _refuse(
        self,
        *,
        permit: ExecutionPermitV02,
        authority: AuthorityState,
        reasons: Tuple[str, ...],
        prior_receipt_hashes: Tuple[str, ...] = (),
    ) -> FirewallResultV04:

        receipt = self.ledger.append(
            event_type="EXECUTION_REFUSED",
            constitution_version=
                permit.constitution_version,
            actor_identity=
                authority.actor_id,
            authority_source=
                authority.authority_source,
            authority_epoch=
                authority.epoch,
            intent_hash=
                permit.intent_hash,
            target=
                permit.target,
            tool=
                permit.tool,
            consequence_class=
                permit.consequence_class,
            governance_verdict="REFUSE",
            verdict_reason=
                ";".join(reasons),
            execution_result=
                "NOT_EXECUTED",
            permit_id=
                permit.permit_id,
            details={
                "reasons": list(reasons),
                "action_hash":
                    permit.action_hash,
            },
        )

        return FirewallResultV04(
            status=
                "REFUSED_BEFORE_CONSEQUENCE",
            executed=False,
            reasons=reasons,
            receipt_hashes=(
                *prior_receipt_hashes,
                receipt["receipt_hash"],
            ),
        )

    def execute(
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
        authority_resolver: Callable[[], AuthorityState],
        action: Callable[[], Any],
    ) -> FirewallResultV04:

        if not self._constitution_ok():
            return self._refuse(
                permit=permit,
                authority=current_authority,
                reasons=(
                    "CONSTITUTION_INTEGRITY_FAILED",
                ),
            )

        if self.ledger.has_consumed_permit(
            permit.permit_id
        ):
            return self._refuse(
                permit=permit,
                authority=current_authority,
                reasons=(
                    "PERMIT_ALREADY_CONSUMED",
                ),
            )

        validation = self.verifier.verify(
            permit=permit,
            current_authority=
                current_authority,
            expected_intent_hash=
                expected_intent_hash,
            expected_permission=
                expected_permission,
            expected_policy_version=
                expected_policy_version,
            expected_target=
                expected_target,
            expected_tool=
                expected_tool,
            expected_consequence_class=
                expected_consequence_class,
            expected_arguments=
                expected_arguments,
        )

        if not validation.valid:
            return self._refuse(
                permit=permit,
                authority=current_authority,
                reasons=validation.reasons,
            )

        pre = self.ledger.append(
            event_type=
                "PRE_EXECUTION_AUTHORIZED",
            constitution_version=
                permit.constitution_version,
            actor_identity=
                current_authority.actor_id,
            authority_source=
                current_authority.authority_source,
            authority_epoch=
                current_authority.epoch,
            intent_hash=
                permit.intent_hash,
            target=
                permit.target,
            tool=
                permit.tool,
            consequence_class=
                permit.consequence_class,
            governance_verdict="PERMIT",
            verdict_reason=
                "CURRENT_STANDING_AND_ACTION_BOUND",
            execution_result="PENDING",
            permit_id=
                permit.permit_id,
            details={
                "action_hash":
                    permit.action_hash,
            },
        )

        # -------------------------------------------------
        # P2-H01 REMEDIATION
        #
        # PRE_EXECUTION_AUTHORIZED is not the final word.
        # Resolve authority again at the actual consequence
        # boundary. No resolver means no consequence.
        # -------------------------------------------------

        try:
            execution_authority = (
                authority_resolver()
            )
        except Exception:
            return self._refuse(
                permit=permit,
                authority=current_authority,
                reasons=(
                    "CONSEQUENCE_AUTHORITY_RESOLUTION_FAILED",
                ),
                prior_receipt_hashes=(
                    pre["receipt_hash"],
                ),
            )

        if not isinstance(
            execution_authority,
            AuthorityState,
        ):
            return self._refuse(
                permit=permit,
                authority=current_authority,
                reasons=(
                    "CONSEQUENCE_AUTHORITY_NOT_ESTABLISHED",
                ),
                prior_receipt_hashes=(
                    pre["receipt_hash"],
                ),
            )

        boundary_validation = self.verifier.verify(
            permit=permit,
            current_authority=
                execution_authority,
            expected_intent_hash=
                expected_intent_hash,
            expected_permission=
                expected_permission,
            expected_policy_version=
                expected_policy_version,
            expected_target=
                expected_target,
            expected_tool=
                expected_tool,
            expected_consequence_class=
                expected_consequence_class,
            expected_arguments=
                expected_arguments,
        )

        if not boundary_validation.valid:
            return self._refuse(
                permit=permit,
                authority=
                    execution_authority,
                reasons=
                    boundary_validation.reasons,
                prior_receipt_hashes=(
                    pre["receipt_hash"],
                ),
            )

        boundary = self.ledger.append(
            event_type=
                "CONSEQUENCE_BOUNDARY_REVALIDATED",
            constitution_version=
                permit.constitution_version,
            actor_identity=
                execution_authority.actor_id,
            authority_source=
                execution_authority.authority_source,
            authority_epoch=
                execution_authority.epoch,
            intent_hash=
                permit.intent_hash,
            target=
                permit.target,
            tool=
                permit.tool,
            consequence_class=
                permit.consequence_class,
            governance_verdict="PERMIT",
            verdict_reason=
                "FRESH_AUTHORITY_REVALIDATED",
            execution_result="PENDING",
            permit_id=
                permit.permit_id,
            details={
                "action_hash":
                    permit.action_hash,
                "authority_state_hash":
                    execution_authority.state_hash(),
            },
        )

        try:
            result = action()

        except Exception as exc:
            post = self.ledger.append(
                event_type="EXECUTION_ERROR",
                constitution_version=
                    permit.constitution_version,
                actor_identity=
                    current_authority.actor_id,
                authority_source=
                    current_authority.authority_source,
                authority_epoch=
                    current_authority.epoch,
                intent_hash=
                    permit.intent_hash,
                target=
                    permit.target,
                tool=
                    permit.tool,
                consequence_class=
                    permit.consequence_class,
                governance_verdict="PERMIT",
                verdict_reason=
                    "ACTION_RAISED_EXCEPTION",
                execution_result="ERROR",
                permit_id=
                    permit.permit_id,
                details={
                    "error":
                        str(exc),
                },
            )

            return FirewallResultV04(
                status="EXECUTION_ERROR",
                executed=False,
                reasons=(
                    "ACTION_RAISED_EXCEPTION",
                ),
                receipt_hashes=(
                    pre["receipt_hash"],
                    boundary["receipt_hash"],
                    post["receipt_hash"],
                ),
            )

        try:
            post = self.ledger.append(
                event_type=
                    "EXECUTION_COMPLETED",
                constitution_version=
                    permit.constitution_version,
                actor_identity=
                    current_authority.actor_id,
                authority_source=
                    current_authority.authority_source,
                authority_epoch=
                    current_authority.epoch,
                intent_hash=
                    permit.intent_hash,
                target=
                    permit.target,
                tool=
                    permit.tool,
                consequence_class=
                    permit.consequence_class,
                governance_verdict="PERMIT",
                verdict_reason=
                    "CURRENT_STANDING_AND_ACTION_BOUND",
                execution_result="EXECUTED",
                permit_id=
                    permit.permit_id,
                details={
                    "action_hash":
                        permit.action_hash,
                    "result":
                        repr(result),
                },
            )

        except Exception as completion_exc:

            fallback = self.ledger.append(
                event_type=
                    "EXECUTION_COMPLETION_PERSISTENCE_FAILED",
                constitution_version=
                    permit.constitution_version,
                actor_identity=
                    current_authority.actor_id,
                authority_source=
                    current_authority.authority_source,
                authority_epoch=
                    current_authority.epoch,
                intent_hash=
                    permit.intent_hash,
                target=
                    permit.target,
                tool=
                    permit.tool,
                consequence_class=
                    permit.consequence_class,
                governance_verdict="REVIEW",
                verdict_reason=
                    "EXECUTION_COMPLETION_RECORD_FAILED",
                execution_result=
                    "EXECUTED_EVIDENCE_INCOMPLETE",
                permit_id=
                    permit.permit_id,
                details={
                    "action_hash":
                        permit.action_hash,
                    "result":
                        repr(result),
                    "completion_error":
                        str(completion_exc),
                },
            )

            return FirewallResultV04(
                status=
                    "EXECUTED_EVIDENCE_INCOMPLETE",
                executed=True,
                reasons=(
                    "EXECUTION_COMPLETION_RECORD_FAILED",
                ),
                receipt_hashes=(
                    pre["receipt_hash"],
                    boundary["receipt_hash"],
                    fallback["receipt_hash"],
                ),
                tool_result=result,
            )

        return FirewallResultV04(
            status="EXECUTED",
            executed=True,
            reasons=(),
            receipt_hashes=(
                pre["receipt_hash"],
                boundary["receipt_hash"],
                post["receipt_hash"],
            ),
            tool_result=result,
        )
