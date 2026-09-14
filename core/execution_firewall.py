from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Tuple, Union
import hashlib

from core.authority import AuthorityState
from core.permit import (
    CONSTITUTION_SHA256,
    ExecutionPermit,
    PermitVerifier,
)
from witness.ledger import WitnessLedger


@dataclass(frozen=True)
class FirewallResult:
    status: str
    executed: bool
    reasons: Tuple[str, ...]
    receipt_hashes: Tuple[str, ...]
    tool_result: Any = None


class ExecutionFirewall:
    """
    Elias final pre-consequence enforcement boundary.

    Execution requires:
    1. Frozen constitution integrity.
    2. Permit not previously consumed.
    3. Present authority.
    4. Exact permit/action bindings.
    5. Execution-seam validation.
    6. Durable witness before consequence.
    """

    def __init__(
        self,
        *,
        verifier: PermitVerifier,
        ledger: WitnessLedger,
        constitution_path: Union[str, Path],
    ):
        self.verifier = verifier
        self.ledger = ledger
        self.constitution_path = Path(
            constitution_path
        )

    def _constitution_integrity_valid(self) -> bool:
        actual_hash = hashlib.sha256(
            self.constitution_path.read_bytes()
        ).hexdigest().upper()

        return actual_hash == CONSTITUTION_SHA256

    def _write_refusal(
        self,
        *,
        permit: ExecutionPermit,
        current_authority: AuthorityState,
        reasons: Tuple[str, ...],
    ) -> FirewallResult:

        receipt = self.ledger.append(
            event_type="EXECUTION_REFUSED",
            constitution_version=permit.constitution_version,
            actor_identity=current_authority.actor_id,
            authority_source=current_authority.authority_source,
            authority_epoch=current_authority.epoch,
            intent_hash=permit.intent_hash,
            target=permit.target,
            tool=permit.tool,
            consequence_class=permit.consequence_class,
            governance_verdict="REFUSE",
            verdict_reason=";".join(reasons),
            execution_result="NOT_EXECUTED",
            permit_id=permit.permit_id,
            details={
                "reasons": list(reasons),
            },
        )

        return FirewallResult(
            status="REFUSED_BEFORE_CONSEQUENCE",
            executed=False,
            reasons=reasons,
            receipt_hashes=(
                receipt["receipt_hash"],
            ),
            tool_result=None,
        )

    def execute(
        self,
        *,
        permit: ExecutionPermit,
        current_authority: AuthorityState,
        expected_intent_hash: str,
        expected_permission: str,
        expected_policy_version: str,
        expected_target: str,
        expected_tool: str,
        expected_consequence_class: str,
        action: Callable[[], Any],
    ) -> FirewallResult:

        # Constitutional integrity is checked before consequence.
        if not self._constitution_integrity_valid():
            return self._write_refusal(
                permit=permit,
                current_authority=current_authority,
                reasons=(
                    "CONSTITUTION_INTEGRITY_FAILED",
                ),
            )

        # A permit is single-use once PRE_EXECUTION witness exists.
        if self.ledger.has_consumed_permit(
            permit.permit_id
        ):
            return self._write_refusal(
                permit=permit,
                current_authority=current_authority,
                reasons=(
                    "PERMIT_ALREADY_CONSUMED",
                ),
            )

        # Present standing is checked at the execution seam.
        validation = self.verifier.verify(
            permit=permit,
            current_authority=current_authority,
            expected_intent_hash=expected_intent_hash,
            expected_permission=expected_permission,
            expected_policy_version=expected_policy_version,
            expected_target=expected_target,
            expected_tool=expected_tool,
            expected_consequence_class=
                expected_consequence_class,
        )

        if not validation.valid:
            return self._write_refusal(
                permit=permit,
                current_authority=current_authority,
                reasons=validation.reasons,
            )

        # Write-ahead witness.
        #
        # Once this durable receipt exists, the permit is consumed
        # BEFORE the external side effect is attempted.
        pre = self.ledger.append(
            event_type="PRE_EXECUTION_AUTHORIZED",
            constitution_version=permit.constitution_version,
            actor_identity=current_authority.actor_id,
            authority_source=current_authority.authority_source,
            authority_epoch=current_authority.epoch,
            intent_hash=permit.intent_hash,
            target=permit.target,
            tool=permit.tool,
            consequence_class=permit.consequence_class,
            governance_verdict="PERMIT",
            verdict_reason=
                "CURRENT_STANDING_ESTABLISHED",
            execution_result="PENDING",
            permit_id=permit.permit_id,
            details={
                "authority_state_hash":
                    current_authority.state_hash(),
                "permit_signature":
                    permit.signature,
            },
        )

        try:
            tool_result = action()

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
                intent_hash=permit.intent_hash,
                target=permit.target,
                tool=permit.tool,
                consequence_class=
                    permit.consequence_class,
                governance_verdict="PERMIT",
                verdict_reason=
                    "ACTION_RAISED_EXCEPTION",
                execution_result="ERROR",
                permit_id=permit.permit_id,
                details={
                    "error_type":
                        type(exc).__name__,
                    "error_message":
                        str(exc),
                },
            )

            return FirewallResult(
                status="EXECUTION_ERROR",
                executed=False,
                reasons=(
                    "ACTION_RAISED_EXCEPTION",
                ),
                receipt_hashes=(
                    pre["receipt_hash"],
                    post["receipt_hash"],
                ),
                tool_result=None,
            )

        post = self.ledger.append(
            event_type="EXECUTION_COMPLETED",
            constitution_version=permit.constitution_version,
            actor_identity=current_authority.actor_id,
            authority_source=current_authority.authority_source,
            authority_epoch=current_authority.epoch,
            intent_hash=permit.intent_hash,
            target=permit.target,
            tool=permit.tool,
            consequence_class=permit.consequence_class,
            governance_verdict="PERMIT",
            verdict_reason=
                "CURRENT_STANDING_ESTABLISHED",
            execution_result="EXECUTED",
            permit_id=permit.permit_id,
            details={
                "tool_result":
                    repr(tool_result),
            },
        )

        return FirewallResult(
            status="EXECUTED",
            executed=True,
            reasons=(),
            receipt_hashes=(
                pre["receipt_hash"],
                post["receipt_hash"],
            ),
            tool_result=tool_result,
        )
