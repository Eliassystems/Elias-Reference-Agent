from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Tuple
import hashlib

from core.authority import AuthorityState
from core.authority_resolution import (
    AuthorityResolution,
    AuthorityResolutionStatus,
)
from core.authority_resolution_attestation import (
    AttestedAuthorityResolution,
    AuthorityResolutionAttestationVerifier,
)
from core.permit_v03 import (
    CONSTITUTION_SHA256,
    ExecutionPermitV03,
    PermitVerifierV03,
)
from witness.ledger import WitnessLedger


class CommitGateRefusedV07(Exception):

    def __init__(
        self,
        *,
        authority: AuthorityState,
        reasons: Tuple[str, ...],
        receipt_hashes: Tuple[str, ...] = (),
    ):
        super().__init__(
            ";".join(reasons)
        )

        self.authority = authority
        self.reasons = tuple(reasons)
        self.receipt_hashes = tuple(
            receipt_hashes
        )


@dataclass(frozen=True)
class FirewallResultV07:
    status: str
    executed: bool
    reasons: Tuple[str, ...]
    receipt_hashes: Tuple[str, ...]
    tool_result: Any = None


class ExecutionFirewallV07:

    def __init__(
        self,
        *,
        verifier: PermitVerifierV03,
        resolution_attestation_verifier: AuthorityResolutionAttestationVerifier,
        ledger: WitnessLedger,
        constitution_path: Path,
    ):
        self.verifier = verifier
        self.resolution_attestation_verifier = (
            resolution_attestation_verifier
        )
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
        permit: ExecutionPermitV03,
        authority: AuthorityState,
        presenting_agent_id: str,
        reasons: Tuple[str, ...],
        prior_receipt_hashes: Tuple[str, ...] = (),
    ) -> FirewallResultV07:

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
                "permit_agent_id":
                    permit.agent_id,
                "presenting_agent_id":
                    presenting_agent_id,
                "reasons": list(reasons),
                "action_hash":
                    permit.action_hash,
            },
        )

        return FirewallResultV07(
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
        permit: ExecutionPermitV03,
        current_authority: AuthorityState,
        presenting_agent_id: str,
        expected_intent_hash: str,
        expected_permission: str,
        expected_policy_version: str,
        expected_target: str,
        expected_tool: str,
        expected_consequence_class: str,
        expected_arguments: Dict[str, Any],
        authority_resolver: Callable[
            [],
            AttestedAuthorityResolution,
        ],
        action: Callable[[Callable[[], AuthorityState]], Any],
    ) -> FirewallResultV07:

        presenting_agent_id = presenting_agent_id.strip()

        if not self._constitution_ok():
            return self._refuse(
                permit=permit,
                presenting_agent_id=
                    presenting_agent_id,
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
                presenting_agent_id=
                    presenting_agent_id,
                authority=current_authority,
                reasons=(
                    "PERMIT_ALREADY_CONSUMED",
                ),
            )

        validation = self.verifier.verify(
            permit=permit,
            current_authority=
                current_authority,
            expected_agent_id=
                presenting_agent_id,
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
                presenting_agent_id=
                    presenting_agent_id,
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
                "permit_agent_id":
                    permit.agent_id,
                "presenting_agent_id":
                    presenting_agent_id,
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
            execution_evidence = (
                authority_resolver()
            )
        except Exception:
            return self._refuse(
                permit=permit,
                presenting_agent_id=
                    presenting_agent_id,
                authority=current_authority,
                reasons=(
                    "CONSEQUENCE_AUTHORITY_RESOLUTION_FAILED",
                ),
                prior_receipt_hashes=(
                    pre["receipt_hash"],
                ),
            )

        execution_attestation_validation = (
            self.resolution_attestation_verifier.verify(
                execution_evidence
            )
        )

        if not execution_attestation_validation.valid:
            return self._refuse(
                permit=permit,
                presenting_agent_id=
                    presenting_agent_id,
                authority=current_authority,
                reasons=(
                    "CONSEQUENCE_AUTHORITY_RESOLUTION_ATTESTATION_INVALID",
                    *execution_attestation_validation.reasons,
                ),
                prior_receipt_hashes=(
                    pre["receipt_hash"],
                ),
            )

        execution_resolution = (
            execution_evidence.resolution
        )

        if not isinstance(
            execution_resolution,
            AuthorityResolution,
        ):
            return self._refuse(
                permit=permit,
                presenting_agent_id=
                    presenting_agent_id,
                authority=current_authority,
                reasons=(
                    "CONSEQUENCE_AUTHORITY_RESOLUTION_NOT_ESTABLISHED",
                ),
                prior_receipt_hashes=(
                    pre["receipt_hash"],
                ),
            )

        if (
            execution_resolution.status
            != AuthorityResolutionStatus.ESTABLISHED
        ):
            reason_map = {
                AuthorityResolutionStatus.CONFLICT:
                    "CONSEQUENCE_AUTHORITY_CONFLICT",

                AuthorityResolutionStatus.UNAVAILABLE:
                    "CONSEQUENCE_AUTHORITY_UNAVAILABLE",

                AuthorityResolutionStatus.INDETERMINATE:
                    "CONSEQUENCE_AUTHORITY_INDETERMINATE",
            }

            refusal_reason = reason_map.get(
                execution_resolution.status,
                "CONSEQUENCE_AUTHORITY_RESOLUTION_NOT_ESTABLISHED",
            )

            resolution_record = self.ledger.append(
                event_type=(
                    "AUTHORITY_RESOLUTION_"
                    + execution_resolution.status.value
                ),
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
                governance_verdict="REFUSE",
                verdict_reason=
                    refusal_reason,
                execution_result=
                    "NOT_EXECUTED",
                permit_id=
                    permit.permit_id,
                details={
                    "permit_agent_id":
                        permit.agent_id,
                    "presenting_agent_id":
                        presenting_agent_id,
                    "resolution_status":
                        execution_resolution.status.value,

                    "resolution_reason":
                        execution_resolution.reason,

                    "resolution_hash":
                        execution_resolution.state_hash(),

                    "observations": [
                        observation.canonical_payload()
                        for observation
                        in execution_resolution.observations
                    ],

                    "observation_hashes": [
                        observation.state_hash()
                        for observation
                        in execution_resolution.observations
                    ],
                },
            )

            return self._refuse(
                permit=permit,
                presenting_agent_id=
                    presenting_agent_id,
                authority=current_authority,
                reasons=(
                    refusal_reason,
                ),
                prior_receipt_hashes=(
                    pre["receipt_hash"],
                    resolution_record[
                        "receipt_hash"
                    ],
                ),
            )

        execution_authority = (
            execution_resolution.authority
        )

        if not isinstance(
            execution_authority,
            AuthorityState,
        ):
            return self._refuse(
                permit=permit,
                presenting_agent_id=
                    presenting_agent_id,
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
            expected_agent_id=
                presenting_agent_id,
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
                presenting_agent_id=
                    presenting_agent_id,
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
                "permit_agent_id":
                    permit.agent_id,
                "presenting_agent_id":
                    presenting_agent_id,
                "action_hash":
                    permit.action_hash,
                "authority_state_hash":
                    execution_authority.state_hash(),
            },
        )

        commit_authority = None
        commit_receipt_hashes = ()
        commit_gate_used = False

        def _post_authority() -> AuthorityState:

            if commit_authority is not None:
                return commit_authority

            return execution_authority

        def commit_gate() -> AuthorityState:
            nonlocal commit_authority
            nonlocal commit_receipt_hashes
            nonlocal commit_gate_used

            if commit_gate_used:
                raise CommitGateRefusedV07(
                    authority=
                        _post_authority(),
                    reasons=(
                        "COMMIT_GATE_ALREADY_USED",
                    ),
                )

            commit_gate_used = True

            try:
                commit_evidence = (
                    authority_resolver()
                )

            except Exception:
                raise CommitGateRefusedV07(
                    authority=
                        execution_authority,
                    reasons=(
                        "COMMIT_AUTHORITY_RESOLUTION_FAILED",
                    ),
                )

            commit_attestation_validation = (
                self.resolution_attestation_verifier.verify(
                    commit_evidence
                )
            )

            if not commit_attestation_validation.valid:
                raise CommitGateRefusedV07(
                    authority=
                        execution_authority,
                    reasons=(
                        "COMMIT_AUTHORITY_RESOLUTION_ATTESTATION_INVALID",
                        *commit_attestation_validation.reasons,
                    ),
                )

            commit_resolution = (
                commit_evidence.resolution
            )

            if not isinstance(
                commit_resolution,
                AuthorityResolution,
            ):
                raise CommitGateRefusedV07(
                    authority=
                        execution_authority,
                    reasons=(
                        "COMMIT_AUTHORITY_RESOLUTION_NOT_ESTABLISHED",
                    ),
                )

            if (
                commit_resolution.status
                != AuthorityResolutionStatus.ESTABLISHED
            ):
                reason_map = {
                    AuthorityResolutionStatus.CONFLICT:
                        "COMMIT_AUTHORITY_CONFLICT",

                    AuthorityResolutionStatus.UNAVAILABLE:
                        "COMMIT_AUTHORITY_UNAVAILABLE",

                    AuthorityResolutionStatus.INDETERMINATE:
                        "COMMIT_AUTHORITY_INDETERMINATE",
                }

                refusal_reason = (
                    reason_map.get(
                        commit_resolution.status,
                        "COMMIT_AUTHORITY_RESOLUTION_NOT_ESTABLISHED",
                    )
                )

                resolution_record = (
                    self.ledger.append(
                        event_type=(
                            "COMMIT_AUTHORITY_RESOLUTION_"
                            + commit_resolution.status.value
                        ),
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
                        governance_verdict=
                            "REFUSE",
                        verdict_reason=
                            refusal_reason,
                        execution_result=
                            "NOT_EXECUTED",
                        permit_id=
                            permit.permit_id,
                        details={
                            "permit_agent_id":
                                permit.agent_id,
                            "presenting_agent_id":
                                presenting_agent_id,
                            "resolution_status":
                                commit_resolution.status.value,

                            "resolution_reason":
                                commit_resolution.reason,

                            "resolution_hash":
                                commit_resolution.state_hash(),

                            "observations": [
                                observation.canonical_payload()
                                for observation
                                in commit_resolution.observations
                            ],

                            "observation_hashes": [
                                observation.state_hash()
                                for observation
                                in commit_resolution.observations
                            ],
                        },
                    )
                )

                commit_receipt_hashes = (
                    resolution_record[
                        "receipt_hash"
                    ],
                )

                raise CommitGateRefusedV07(
                    authority=
                        execution_authority,
                    reasons=(
                        refusal_reason,
                    ),
                    receipt_hashes=
                        commit_receipt_hashes,
                )

            candidate_authority = (
                commit_resolution.authority
            )

            if not isinstance(
                candidate_authority,
                AuthorityState,
            ):
                raise CommitGateRefusedV07(
                    authority=
                        execution_authority,
                    reasons=(
                        "COMMIT_AUTHORITY_NOT_ESTABLISHED",
                    ),
                )

            commit_validation = (
                self.verifier.verify(
                    permit=permit,
                    current_authority=
                        candidate_authority,
                    expected_agent_id=
                        presenting_agent_id,
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
            )

            if not commit_validation.valid:

                failure = self.ledger.append(
                    event_type=
                        "CONSEQUENCE_COMMIT_AUTHORITY_REVALIDATION_FAILED",
                    constitution_version=
                        permit.constitution_version,
                    actor_identity=
                        candidate_authority.actor_id,
                    authority_source=
                        candidate_authority.authority_source,
                    authority_epoch=
                        candidate_authority.epoch,
                    intent_hash=
                        permit.intent_hash,
                    target=
                        permit.target,
                    tool=
                        permit.tool,
                    consequence_class=
                        permit.consequence_class,
                    governance_verdict=
                        "REFUSE",
                    verdict_reason=
                        "COMMIT_AUTHORITY_REVALIDATION_FAILED",
                    execution_result=
                        "NOT_EXECUTED",
                    permit_id=
                        permit.permit_id,
                    details={
                        "permit_agent_id":
                            permit.agent_id,
                        "presenting_agent_id":
                            presenting_agent_id,
                        "action_hash":
                            permit.action_hash,

                        "authority_state_hash":
                            candidate_authority.state_hash(),

                        "resolution_hash":
                            commit_resolution.state_hash(),

                        "validation_reasons":
                            list(
                                commit_validation.reasons
                            ),
                    },
                )

                commit_receipt_hashes = (
                    failure[
                        "receipt_hash"
                    ],
                )

                raise CommitGateRefusedV07(
                    authority=
                        candidate_authority,
                    reasons=(
                        "COMMIT_AUTHORITY_REVALIDATION_FAILED",
                        *commit_validation.reasons,
                    ),
                    receipt_hashes=
                        commit_receipt_hashes,
                )

            commit_record = self.ledger.append(
                event_type=
                    "CONSEQUENCE_COMMIT_AUTHORITY_REVALIDATED",
                constitution_version=
                    permit.constitution_version,
                actor_identity=
                    candidate_authority.actor_id,
                authority_source=
                    candidate_authority.authority_source,
                authority_epoch=
                    candidate_authority.epoch,
                intent_hash=
                    permit.intent_hash,
                target=
                    permit.target,
                tool=
                    permit.tool,
                consequence_class=
                    permit.consequence_class,
                governance_verdict=
                    "PERMIT",
                verdict_reason=
                    "COMMIT_AUTHORITY_ESTABLISHED",
                execution_result=
                    "PENDING",
                permit_id=
                    permit.permit_id,
                details={
                    "permit_agent_id":
                        permit.agent_id,
                    "presenting_agent_id":
                        presenting_agent_id,
                    "action_hash":
                        permit.action_hash,

                    "authority_state_hash":
                        candidate_authority.state_hash(),

                    "resolution_hash":
                        commit_resolution.state_hash(),
                },
            )

            commit_receipt_hashes = (
                commit_record[
                    "receipt_hash"
                ],
            )

            commit_authority = (
                candidate_authority
            )

            return commit_authority

        try:
            result = action(
                commit_gate
            )

        except CommitGateRefusedV07 as exc:

            return self._refuse(
                permit=permit,
                presenting_agent_id=
                    presenting_agent_id,
                authority=
                    exc.authority,
                reasons=
                    exc.reasons,
                prior_receipt_hashes=(
                    pre["receipt_hash"],
                    boundary["receipt_hash"],
                    *exc.receipt_hashes,
                ),
            )

        except Exception as exc:
            post = self.ledger.append(
                event_type="EXECUTION_ERROR",
                constitution_version=
                    permit.constitution_version,
                actor_identity=
                    _post_authority().actor_id,
                authority_source=
                    _post_authority().authority_source,
                authority_epoch=
                    _post_authority().epoch,
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
                    "permit_agent_id":
                        permit.agent_id,
                    "presenting_agent_id":
                        presenting_agent_id,
                    "error":
                        str(exc),
                },
            )

            return FirewallResultV07(
                status="EXECUTION_ERROR",
                executed=False,
                reasons=(
                    "ACTION_RAISED_EXCEPTION",
                ),
                receipt_hashes=(
                    pre["receipt_hash"],
                    boundary["receipt_hash"],
                    *commit_receipt_hashes,
                    post["receipt_hash"],
                ),
            )

        if (
            not commit_gate_used
            or commit_authority is None
        ):
            bypass = self.ledger.append(
                event_type=
                    "EXECUTION_COMMIT_GATE_BYPASSED",
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
                governance_verdict=
                    "REVIEW",
                verdict_reason=
                    "COMMIT_GATE_NOT_USED",
                execution_result=
                    "EXECUTED_COMMIT_GATE_NOT_ESTABLISHED",
                permit_id=
                    permit.permit_id,
                details={
                    "permit_agent_id":
                        permit.agent_id,
                    "presenting_agent_id":
                        presenting_agent_id,
                    "action_hash":
                        permit.action_hash,
                    "result":
                        repr(result),

                    "commit_authority_state_hash":
                        (
                            commit_authority.state_hash()
                            if commit_authority is not None
                            else None
                        ),
                },
            )

            return FirewallResultV07(
                status=
                    "EXECUTED_COMMIT_GATE_NOT_ESTABLISHED",
                executed=True,
                reasons=(
                    "COMMIT_GATE_NOT_USED",
                ),
                receipt_hashes=(
                    pre["receipt_hash"],
                    boundary["receipt_hash"],
                    *commit_receipt_hashes,
                    bypass["receipt_hash"],
                ),
                tool_result=result,
            )

        try:
            post = self.ledger.append(
                event_type=
                    "EXECUTION_COMPLETED",
                constitution_version=
                    permit.constitution_version,
                actor_identity=
                    _post_authority().actor_id,
                authority_source=
                    _post_authority().authority_source,
                authority_epoch=
                    _post_authority().epoch,
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
                    "permit_agent_id":
                        permit.agent_id,
                    "presenting_agent_id":
                        presenting_agent_id,
                    "action_hash":
                        permit.action_hash,
                    "result":
                        repr(result),

                    "commit_authority_state_hash":
                        (
                            commit_authority.state_hash()
                            if commit_authority is not None
                            else None
                        ),
                },
            )

        except Exception as completion_exc:

            fallback = self.ledger.append(
                event_type=
                    "EXECUTION_COMPLETION_PERSISTENCE_FAILED",
                constitution_version=
                    permit.constitution_version,
                actor_identity=
                    _post_authority().actor_id,
                authority_source=
                    _post_authority().authority_source,
                authority_epoch=
                    _post_authority().epoch,
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
                    "permit_agent_id":
                        permit.agent_id,
                    "presenting_agent_id":
                        presenting_agent_id,
                    "action_hash":
                        permit.action_hash,
                    "result":
                        repr(result),

                    "commit_authority_state_hash":
                        (
                            commit_authority.state_hash()
                            if commit_authority is not None
                            else None
                        ),
                    "completion_error":
                        str(completion_exc),
                },
            )

            return FirewallResultV07(
                status=
                    "EXECUTED_EVIDENCE_INCOMPLETE",
                executed=True,
                reasons=(
                    "EXECUTION_COMPLETION_RECORD_FAILED",
                ),
                receipt_hashes=(
                    pre["receipt_hash"],
                    boundary["receipt_hash"],
                    *commit_receipt_hashes,
                    fallback["receipt_hash"],
                ),
                tool_result=result,
            )

        return FirewallResultV07(
            status="EXECUTED",
            executed=True,
            reasons=(),
            receipt_hashes=(
                pre["receipt_hash"],
                boundary["receipt_hash"],
                *commit_receipt_hashes,
                post["receipt_hash"],
            ),
            tool_result=result,
        )
