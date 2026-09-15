from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(ROOT),
    )

from core.authority import AuthorityState
from core.authority_resolution import (
    AuthorityResolution,
    AuthorityResolutionStatus,
)
from core.authority_resolution_attestation import (
    AuthorityResolutionAttestationIssuer,
    AuthorityResolutionAttestationVerifier,
    AttestedAuthorityResolution,
)
from core.execution_firewall_v06 import (
    ExecutionFirewallV06,
)
from core.permit_v02 import (
    PermitIssuerV02,
    PermitVerifierV02,
)
from tools.broker_v06 import (
    ToolBrokerV06,
    ToolRequestV06,
)
from tools.messaging_demo_v06 import (
    MessagingDemoToolV06,
)
from witness.ledger import WitnessLedger


TEST_ID = "P3-F08-S01"

BASELINE_COMMIT = (
    "652a3fd147f3fb7ce6f37e25ecd44b752f9940f5"
)

EXPECTED_DEFINITION_HASH = (
    "18D348A6E2405E29B0556151AD991C361A58C0E4BB1EC57AC96F6B6E3D4A5EA7"
)

EXPECTED_GOVERNING_HASHES = {
    "core/authority.py":
        "E949C5C9E75DCB65301701363363AC6D118CD64D3AB38018957DA086EBB6B85C",
    "core/authority_resolution.py":
        "D1B052E1F413ADAFA71C8B7D3E0AB470817E901CBA28D1CF145BF10EA7A585EF",
    "core/authority_resolution_attestation.py":
        "9A40FF86E7F1C84864CB8AAC881F85CBCF5585FA2C5DA8FBF04BA2BA368A0F62",
    "core/execution_firewall_v06.py":
        "5191C0AAE4B9A538C503B28210ACA7AE9D28330DA3898AEFF798A3E8A7A97E2D",
}

EXPECTED_SUPPORT_HASHES = {
    "core/permit_v02.py":
        "1BE9CED135D1C3E0498728B5E9AE0853E46E1925EA90EFF70A573E0F516C70A5",
    "tools/broker_v06.py":
        "F722E4554D6FF300E7036BD1E1C73FD09DA47F2E1053DAA63F1C622FC443F6A6",
    "tools/messaging_demo_v06.py":
        "C976315CB420599ACEC8F2D8E5ED0B4FE4FBB9B1B07CBC8CBBA3CBB3E79A67DE",
    "witness/ledger.py":
        "C940D48351E8F4A06F2008CE720A2187433556E18C49D6378A2FA27E6DCE40E5",
    "constitution/constitution.yaml":
        "6FF2C14C67DF4B009F81551AD55ECD4C1EA314B5827D7B039D0E21AD934D302A",
}

EVIDENCE_DIR = (
    ROOT / "evidence" / "phase-iii" / "p3-f08-s01"
)

DEFINITION_PATH = (
    EVIDENCE_DIR /
    "P3-F08-S01-TEST-DEFINITION-001.json"
)

RESULT_PATH = (
    EVIDENCE_DIR /
    "P3-F08-S01-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR /
    "P3-F08-S01-FIRST-OBSERVED-FREEZE-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR /
    "P3-F08-S01-WITNESS-001.jsonl"
)


SEAM_CLASSIFICATION = (
    "LOCALLY_ASSERTED_DIVERGENT_CONFLICT_ACCEPTED__"
    "CONSEQUENCE_REFUSAL_WITHOUT_NATIVE_PROVENANCE_ESTABLISHMENT"
)

UNEXPECTED_CLASSIFICATION = (
    "P3-F08_UNEXPECTED_RESULT"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest().upper()


def write_json(path: Path, payload) -> None:
    path.write_text(
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def write_sidecar(path: Path) -> None:

    digest = sha256(
        path
    )

    path.with_name(
        path.name + ".sha256"
    ).write_text(
        f"{digest}  {path.name}\n",
        encoding="utf-8",
        newline="\n",
    )


for path in (
    RESULT_PATH,
    FREEZE_PATH,
    WITNESS_PATH,
    RESULT_PATH.with_name(
        RESULT_PATH.name + ".sha256"
    ),
    FREEZE_PATH.with_name(
        FREEZE_PATH.name + ".sha256"
    ),
    WITNESS_PATH.with_name(
        WITNESS_PATH.name + ".sha256"
    ),
):
    if path.exists():
        raise SystemExit(
            "P3-F08 FIRST-OBSERVED ARTIFACT EXISTS - DO NOT RERUN."
        )


definition_identity_preserved = (
    sha256(DEFINITION_PATH)
    == EXPECTED_DEFINITION_HASH
)

source_identity = {}

source_identity_preserved = True

all_expected = {
    **EXPECTED_GOVERNING_HASHES,
    **EXPECTED_SUPPORT_HASHES,
}

for relative, expected in all_expected.items():

    actual = sha256(
        ROOT / relative
    )

    source_identity[relative] = {
        "expected_sha256": expected,
        "actual_sha256": actual,
        "preserved": actual == expected,
    }

    if actual != expected:
        source_identity_preserved = False


# ============================================================
# LEGITIMATE ACTIVE AUTHORITY
# ============================================================

active_authority = AuthorityState.create(
    actor_id="P3-F08-HUMAN-001",
    authority_source="HUMAN_SOVEREIGN_AUTHORITY",
    permissions={
        "SEND"
    },
    epoch=1,
)


# ============================================================
# LOCALLY ASSERTED DIVERGENT OBSERVATION
#
# Native construction requires no signature, issuer receipt,
# registry proof, or attestation input.
# ============================================================

asserted_divergent_authority = None
asserted_construction_error = None

try:

    asserted_divergent_authority = AuthorityState.create(
        actor_id="P3-F08-HUMAN-001",
        authority_source="HUMAN_SOVEREIGN_AUTHORITY",
        permissions={
            "SEND"
        },
        epoch=2,
    )

except Exception as exc:

    asserted_construction_error = {
        "type": type(exc).__name__,
        "message": str(exc),
    }


asserted_authority_locally_constructed = (
    asserted_divergent_authority is not None
    and asserted_construction_error is None
)

asserted_authority_materially_different = (
    asserted_authority_locally_constructed
    and asserted_divergent_authority
        != active_authority
)

native_provenance_proof_supplied = False


# ============================================================
# DIVERGENT CONFLICT REPRESENTATION
# ============================================================

divergent_conflict = None
conflict_construction_error = None

if (
    asserted_authority_locally_constructed
    and asserted_authority_materially_different
):

    try:

        divergent_conflict = AuthorityResolution.conflict(
            (
                active_authority,
                asserted_divergent_authority,
            ),
            reason=(
                "P3-F08-LOCALLY-ASSERTED-"
                "DIVERGENT-CONFLICT"
            ),
        )

    except Exception as exc:

        conflict_construction_error = {
            "type": type(exc).__name__,
            "message": str(exc),
        }


divergent_conflict_constructed = (
    divergent_conflict is not None
    and conflict_construction_error is None
    and divergent_conflict.status
        == AuthorityResolutionStatus.CONFLICT
    and len(
        divergent_conflict.observations
    ) == 2
    and divergent_conflict.observations[0]
        != divergent_conflict.observations[1]
)


# ============================================================
# PROVEN TIMELINE LEDGER
# ============================================================

timeline = []

class TimelineLedger(
    WitnessLedger
):

    def __init__(
        self,
        path,
        timeline_ref,
    ):

        self._timeline_ref = (
            timeline_ref
        )

        super().__init__(
            path
        )

    def append(
        self,
        *args,
        **kwargs,
    ):

        record = super().append(
            *args,
            **kwargs,
        )

        event_type = kwargs.get(
            "event_type"
        )

        if event_type:

            self._timeline_ref.append(
                "WITNESS:"
                + str(
                    event_type
                )
            )

        return record


# ============================================================
# RESOLVER
# ============================================================


# ============================================================
# RESOLVER
# ============================================================

resolver_mode = {
    "mode": "POSITIVE",
}

resolver_state = {
    "calls": 0,
    "modes": [],
    "statuses": [],
    "forms": [],
    "resolution_hashes": [],
}


def authority_resolver():

    resolver_state["calls"] += 1

    mode = resolver_mode["mode"]

    if mode == "POSITIVE":

        resolution = AuthorityResolution.established(
            active_authority,
            reason="P3-F08-S01-POSITIVE-ESTABLISHED",
        )

        output = resolution_issuer.issue(
            resolution
        )

    elif mode == "AUTHENTIC_CONFLICT":

        resolution = divergent_conflict

        output = resolution_issuer.issue(
            resolution
        )

    elif mode == "UNATTESTED_CONFLICT":

        resolution = divergent_conflict

        output = resolution

    elif mode == "COMMIT_UNATTESTED":

        calls_in_mode = (
            resolver_state["modes"].count(
                mode
            )
        )

        if calls_in_mode == 0:

            resolution = AuthorityResolution.established(
                active_authority,
                reason=(
                    "P3-F08-S01-COMMIT-"
                    "BOUNDARY-ESTABLISHED"
                ),
            )

            output = resolution_issuer.issue(
                resolution
            )

        else:

            resolution = divergent_conflict

            output = resolution

    else:

        raise RuntimeError(
            "P3-F08-S01_UNKNOWN_RESOLVER_MODE"
        )

    resolver_state["modes"].append(
        mode
    )

    resolver_state["statuses"].append(
        resolution.status.value
    )

    resolver_state["forms"].append(
        (
            "ATTESTED"
            if isinstance(
                output,
                AttestedAuthorityResolution,
            )
            else "RAW"
        )
    )

    resolver_state["resolution_hashes"].append(
        resolution.state_hash()
    )

    timeline.append(
        "RESOLVER:"
        + mode
        + ":"
        + resolution.status.value
        + ":"
        + resolver_state["forms"][-1]
    )

    return output


# ============================================================
# NORMAL V06 STACK
# ============================================================

permit_signing_key = (
    b"P3-F08-S01-PERMIT-SIGNING-KEY-00000001"
)

resolution_signing_key = (
    b"P3-F08-S01-RESOLUTION-SIGNING-KEY-0001"
)

resolver_id = (
    "P3-F08-S01-AUTHORIZED-RESOLVER-001"
)

issuer = PermitIssuerV02(
    signing_key=permit_signing_key
)

verifier = PermitVerifierV02(
    signing_key=permit_signing_key
)

resolution_issuer = (
    AuthorityResolutionAttestationIssuer(
        resolver_id=resolver_id,
        signing_key=resolution_signing_key,
    )
)

resolution_verifier = (
    AuthorityResolutionAttestationVerifier(
        resolver_id=resolver_id,
        signing_key=resolution_signing_key,
    )
)

ledger = TimelineLedger(
    WITNESS_PATH,
    timeline,
)

messaging_tool = (
    MessagingDemoToolV06()
)

firewall = ExecutionFirewallV06(
    verifier=verifier,
    resolution_attestation_verifier=
        resolution_verifier,
    ledger=ledger,
    constitution_path=(
        ROOT
        / "constitution"
        / "constitution.yaml"
    ),
)

broker = ToolBrokerV06(
    firewall=firewall,
    messaging_tool=messaging_tool,
)


# ============================================================
# S01 CONTROL / ADVERSARIAL CASE RUNNER
# ============================================================

def run_case(
    *,
    case_id: str,
    mode: str,
):

    arguments = {
        "content":
            case_id
    }

    intent_hash = (
        case_id
        + "-INTENT"
    )

    permit = issuer.issue(
        authority=active_authority,
        intent_hash=intent_hash,
        permission="SEND",
        policy_version="ERA-POLICY-001-v0.2.0",
        target=(
            case_id
            + "-RECIPIENT"
        ),
        tool="MESSAGING_DEMO",
        consequence_class="C4",
        arguments=arguments,
    )

    request = ToolRequestV06(
        permit=permit,
        current_authority=
            active_authority,
        authority_resolver=
            authority_resolver,
        intent_hash=intent_hash,
        permission="SEND",
        policy_version="ERA-POLICY-001-v0.2.0",
        target=(
            case_id
            + "-RECIPIENT"
        ),
        tool_name="MESSAGING_DEMO",
        consequence_class="C4",
        arguments=arguments,
    )

    resolver_mode["mode"] = mode

    calls_before = (
        resolver_state["calls"]
    )

    status_index = len(
        resolver_state["statuses"]
    )

    form_index = len(
        resolver_state["forms"]
    )

    outbox_before = (
        broker.outbox_size()
    )

    result = None
    exception = None

    try:

        result = broker.execute(
            request
        )

    except Exception as exc:

        exception = {
            "type":
                type(exc).__name__,

            "message":
                str(exc),
        }

    outbox_after = (
        broker.outbox_size()
    )

    calls = (
        resolver_state["calls"]
        - calls_before
    )

    statuses = list(
        resolver_state["statuses"][
            status_index:
        ]
    )

    forms = list(
        resolver_state["forms"][
            form_index:
        ]
    )

    status = None
    reasons = []

    if result is not None:

        raw_status = getattr(
            result,
            "status",
            None,
        )

        status = getattr(
            raw_status,
            "value",
            raw_status,
        )

        raw_reasons = getattr(
            result,
            "reasons",
            (),
        )

        if raw_reasons is not None:
            reasons = list(
                raw_reasons
            )

    return {
        "mode":
            mode,

        "resolver_calls":
            calls,

        "resolver_statuses":
            statuses,

        "resolver_forms":
            forms,

        "status":
            status,

        "reasons":
            reasons,

        "outbox_before":
            outbox_before,

        "outbox_after":
            outbox_after,

        "consequence_committed":
            outbox_after
            > outbox_before,

        "exception":
            exception,
    }


preconditions_preserved = (
    definition_identity_preserved
    and source_identity_preserved
    and divergent_conflict_constructed
)


positive_control = None
authentic_conflict_control = None
unattested_consequence_case = None
unattested_commit_case = None


if preconditions_preserved:

    positive_control = run_case(
        case_id=(
            "P3-F08-S01-POSITIVE"
        ),
        mode="POSITIVE",
    )

    authentic_conflict_control = run_case(
        case_id=(
            "P3-F08-S01-AUTHENTIC-CONFLICT"
        ),
        mode="AUTHENTIC_CONFLICT",
    )

    unattested_consequence_case = run_case(
        case_id=(
            "P3-F08-S01-UNATTESTED-CONSEQUENCE"
        ),
        mode="UNATTESTED_CONFLICT",
    )

    unattested_commit_case = run_case(
        case_id=(
            "P3-F08-S01-UNATTESTED-COMMIT"
        ),
        mode="COMMIT_UNATTESTED",
    )


positive_control_passed = (
    positive_control is not None
    and positive_control["exception"]
        is None
    and positive_control[
        "consequence_committed"
    ] is True
    and positive_control[
        "resolver_calls"
    ] == 2
    and positive_control[
        "resolver_statuses"
    ] == [
        "ESTABLISHED",
        "ESTABLISHED",
    ]
    and positive_control[
        "resolver_forms"
    ] == [
        "ATTESTED",
        "ATTESTED",
    ]
)


authentic_conflict_preserved = (
    authentic_conflict_control
        is not None
    and authentic_conflict_control[
        "exception"
    ] is None
    and authentic_conflict_control[
        "consequence_committed"
    ] is False
    and authentic_conflict_control[
        "resolver_calls"
    ] == 1
    and authentic_conflict_control[
        "resolver_statuses"
    ] == [
        "CONFLICT"
    ]
    and authentic_conflict_control[
        "resolver_forms"
    ] == [
        "ATTESTED"
    ]
    and (
        "CONSEQUENCE_AUTHORITY_CONFLICT"
        in authentic_conflict_control[
            "reasons"
        ]
    )
)


unattested_consequence_rejected = (
    unattested_consequence_case
        is not None
    and unattested_consequence_case[
        "exception"
    ] is None
    and unattested_consequence_case[
        "consequence_committed"
    ] is False
    and unattested_consequence_case[
        "resolver_calls"
    ] == 1
    and unattested_consequence_case[
        "resolver_statuses"
    ] == [
        "CONFLICT"
    ]
    and unattested_consequence_case[
        "resolver_forms"
    ] == [
        "RAW"
    ]
    and (
        "CONSEQUENCE_AUTHORITY_RESOLUTION_ATTESTATION_INVALID"
        in unattested_consequence_case[
            "reasons"
        ]
    )
    and (
        "AUTHORITY_RESOLUTION_ATTESTATION_MISSING"
        in unattested_consequence_case[
            "reasons"
        ]
    )
    and (
        "CONSEQUENCE_AUTHORITY_CONFLICT"
        not in unattested_consequence_case[
            "reasons"
        ]
    )
)


unattested_commit_rejected = (
    unattested_commit_case
        is not None
    and unattested_commit_case[
        "exception"
    ] is None
    and unattested_commit_case[
        "consequence_committed"
    ] is False
    and unattested_commit_case[
        "resolver_calls"
    ] == 2
    and unattested_commit_case[
        "resolver_statuses"
    ] == [
        "ESTABLISHED",
        "CONFLICT",
    ]
    and unattested_commit_case[
        "resolver_forms"
    ] == [
        "ATTESTED",
        "RAW",
    ]
    and (
        "COMMIT_AUTHORITY_RESOLUTION_ATTESTATION_INVALID"
        in unattested_commit_case[
            "reasons"
        ]
    )
    and (
        "AUTHORITY_RESOLUTION_ATTESTATION_MISSING"
        in unattested_commit_case[
            "reasons"
        ]
    )
    and (
        "COMMIT_AUTHORITY_CONFLICT"
        not in unattested_commit_case[
            "reasons"
        ]
    )
)


control_established = (
    preconditions_preserved
    and positive_control_passed
    and authentic_conflict_preserved
    and unattested_consequence_rejected
    and unattested_commit_rejected
)


if control_established:

    classification = (
        "UNAUTHENTICATED_RESOLUTION_STANDING_REJECTED_AT_"
        "CONSEQUENCE_AND_COMMIT__AUTHENTIC_SEMANTICS_PRESERVED"
    )

else:

    classification = (
        "P3-F08-S01_UNEXPECTED_RESULT"
    )


records = ledger.records()

chain_valid, chain_errors = (
    ledger.verify_chain()
)


result_payload = {
    "test_id":
        TEST_ID,

    "classification":
        classification,

    "repository_baseline_commit":
        BASELINE_COMMIT,

    "definition_identity_preserved":
        definition_identity_preserved,

    "source_identity":
        source_identity,

    "source_identity_preserved":
        source_identity_preserved,

    "divergent_conflict_constructed":
        divergent_conflict_constructed,

    "positive_control":
        positive_control,

    "authentic_conflict_control":
        authentic_conflict_control,

    "unattested_consequence_case":
        unattested_consequence_case,

    "unattested_commit_case":
        unattested_commit_case,

    "positive_control_passed":
        positive_control_passed,

    "authentic_conflict_preserved":
        authentic_conflict_preserved,

    "unattested_consequence_rejected":
        unattested_consequence_rejected,

    "unattested_commit_rejected":
        unattested_commit_rejected,

    "control_established":
        control_established,

    "witness": {
        "record_count":
            len(records),

        "chain_valid":
            chain_valid,

        "chain_errors":
            chain_errors,
    },

    "timeline":
        timeline,

    "bounded_claim": (
        "This deterministic successor test establishes only that "
        "ExecutionFirewallV06 requires the configured native "
        "authority-resolution attestation before a supplied "
        "AuthorityResolution may acquire consequence-affecting "
        "standing at the tested consequence and commit boundaries. "
        "It also checks that correctly attested ESTABLISHED and "
        "materially divergent CONFLICT resolutions retain their "
        "existing bounded semantics. It does not establish external "
        "resolver security, signing-key custody, replay resistance, "
        "attestation freshness, distributed consensus, production "
        "reachability, or protection against compromise of an "
        "authorized resolver or its signing key."
    ),
}


freeze_payload = {
    "test_id":
        TEST_ID,

    "freeze_type":
        "FIRST_OBSERVED_RESULT_FREEZE",

    "classification":
        classification,

    "repository_baseline_commit":
        BASELINE_COMMIT,

    "definition_identity_preserved":
        definition_identity_preserved,

    "source_identity_preserved":
        source_identity_preserved,

    "positive_control_passed":
        positive_control_passed,

    "authentic_conflict_preserved":
        authentic_conflict_preserved,

    "unattested_consequence_rejected":
        unattested_consequence_rejected,

    "unattested_commit_rejected":
        unattested_commit_rejected,

    "control_established":
        control_established,

    "no_retrospective_repair":
        True,
}


write_json(
    RESULT_PATH,
    result_payload,
)

write_json(
    FREEZE_PATH,
    freeze_payload,
)

write_sidecar(
    RESULT_PATH
)

write_sidecar(
    FREEZE_PATH
)

if WITNESS_PATH.exists():
    write_sidecar(
        WITNESS_PATH
    )


print()
print(
    "=== P3-F08-S01 FIRST OBSERVED RESULT ==="
)
print(
    "classification:",
    classification,
)
print(
    "definition_identity_preserved:",
    definition_identity_preserved,
)
print(
    "source_identity_preserved:",
    source_identity_preserved,
)
print(
    "positive_control_passed:",
    positive_control_passed,
)
print(
    "authentic_conflict_preserved:",
    authentic_conflict_preserved,
)
print(
    "unattested_consequence_rejected:",
    unattested_consequence_rejected,
)
print(
    "unattested_commit_rejected:",
    unattested_commit_rejected,
)
print(
    "control_established:",
    control_established,
)
print(
    "witness_chain_valid:",
    chain_valid,
)
print()
print(
    "RESULT:",
    RESULT_PATH.relative_to(ROOT),
)
print(
    "FREEZE:",
    FREEZE_PATH.relative_to(ROOT),
)
print(
    "WITNESS:",
    WITNESS_PATH.relative_to(ROOT),
)
