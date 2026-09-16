from __future__ import annotations

import dataclasses
import hashlib
import inspect
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.authority import AuthorityState
from core.authority_resolution import AuthorityResolution
from core.authority_resolution_attestation import (
    AuthorityResolutionAttestationIssuer,
    AuthorityResolutionAttestationVerifier,
)
from core.execution_firewall_v07 import ExecutionFirewallV07
from core.permit_v03 import PermitIssuerV03, PermitVerifierV03
from tools.broker_v07 import ToolBrokerV07, ToolRequestV07
from tools.messaging_demo_v06 import MessagingDemoToolV06
from witness.ledger import WitnessLedger


TEST_ID = "P4-F02"

DEFINITION_COMMIT = (
    "ba42d618f5abbc92225ffa8b345d894087eb49fb"
)

ANTECEDENT_EVIDENCE_COMMIT = (
    "59a55b6b5b2c090ffc10bdf7bc8c5507a6d29ac2"
)

EXPECTED_DEFINITION_HASH = (
    "709D20662D6B0B8AE69EB2D9C03F8C6E1F9B31B502F7F4F6586E93E718A47FF4"
)

EXPECTED_SOURCE_HASHES = {
    "constitution/constitution.yaml":
        "6FF2C14C67DF4B009F81551AD55ECD4C1EA314B5827D7B039D0E21AD934D302A",
    "core/authority.py":
        "E949C5C9E75DCB65301701363363AC6D118CD64D3AB38018957DA086EBB6B85C",
    "core/authority_resolution.py":
        "D1B052E1F413ADAFA71C8B7D3E0AB470817E901CBA28D1CF145BF10EA7A585EF",
    "core/authority_resolution_attestation.py":
        "9A40FF86E7F1C84864CB8AAC881F85CBCF5585FA2C5DA8FBF04BA2BA368A0F62",
    "core/permit_v03.py":
        "B33702D6E0D9CC397E1B57E54FF5E9FB39A3A40C1E683737DEFB6FFB67D6EE0B",
    "core/execution_firewall_v07.py":
        "A43FEFA0834D405BB0CF07D1D6FE23FE2BF81DF34237574F778AECA2F6E5D948",
    "tools/broker_v07.py":
        "87288780B248260B7F7EE16851198FEFD4B71B9AA25AA361651A460514300340",
    "tools/messaging_demo_v06.py":
        "C976315CB420599ACEC8F2D8E5ED0B4FE4FBB9B1B07CBC8CBBA3CBB3E79A67DE",
    "witness/ledger.py":
        "C940D48351E8F4A06F2008CE720A2187433556E18C49D6378A2FA27E6DCE40E5",
}

EXPECTED_ANTECEDENT_HASHES = {
    "evidence/phase-iv/p4-f01-s01/P4-F01-S01-FIRST-OBSERVED-RESULT-001.json":
        "187CD5C1FDBCFEDAA9A9A8C5DE65514DCD2B97788C53BAE75E647813F3FFD4D1",
    "evidence/phase-iv/p4-f01-s01/P4-F01-S01-FIRST-OBSERVED-FREEZE-001.json":
        "0474E56A5A4FE5688646D86A01B762373158BEFE5E90EB23F67ED83DFD202268",
    "evidence/phase-iv/p4-f01-s01/P4-F01-S01-WITNESS-001.jsonl":
        "9CC228FD69D16F69FD78F5AF6210B0295B08D0156569B9B17DD19B02589370C2",
}

EVIDENCE_DIR = ROOT / "evidence" / "phase-iv" / "p4-f02"

DEFINITION_PATH = (
    EVIDENCE_DIR
    / "P4-F02-TEST-DEFINITION-001.json"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P4-F02-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR
    / "P4-F02-FIRST-OBSERVED-FREEZE-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P4-F02-WITNESS-001.jsonl"
)

AGENT_A = "P4-F01-AGENT-A"
AGENT_B = "P4-F01-AGENT-B"
HUMAN_ACTOR = "P4-F01-HUMAN-001"


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
    digest = sha256(path)

    path.with_name(
        path.name + ".sha256"
    ).write_text(
        f"{digest}  {path.name}\n",
        encoding="utf-8",
        newline="\n",
    )


# ============================================================
# FIRST-OBSERVED ARTIFACT GUARD
# ============================================================

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
            "P4-F02 FIRST-OBSERVED ARTIFACT EXISTS - DO NOT RERUN."
        )


# ============================================================
# DEFINITION / SOURCE / ANTECEDENT IDENTITY
# ============================================================

definition_identity_preserved = (
    sha256(DEFINITION_PATH)
    == EXPECTED_DEFINITION_HASH
)

source_identity = {}
source_identity_preserved = True

for relative, expected in EXPECTED_SOURCE_HASHES.items():
    actual = sha256(ROOT / relative)

    source_identity[relative] = {
        "expected_sha256": expected,
        "actual_sha256": actual,
        "preserved": actual == expected,
    }

    if actual != expected:
        source_identity_preserved = False


antecedent_identity = {}
antecedent_evidence_identity_preserved = True

for relative, expected in EXPECTED_ANTECEDENT_HASHES.items():
    actual = sha256(ROOT / relative)

    antecedent_identity[relative] = {
        "expected_sha256": expected,
        "actual_sha256": actual,
        "preserved": actual == expected,
    }

    if actual != expected:
        antecedent_evidence_identity_preserved = False


# ============================================================
# TESTED CALLER-IDENTITY SURFACE
# ============================================================

request_fields = tuple(
    field.name
    for field in dataclasses.fields(
        ToolRequestV07
    )
)

firewall_execute_parameters = tuple(
    inspect.signature(
        ExecutionFirewallV07.execute
    ).parameters.keys()
)

caller_auth_field_candidates = (
    "actual_caller_agent_id",
    "authenticated_caller_agent_id",
    "caller_agent_id",
    "authenticated_agent_id",
    "verified_agent_id",
    "verified_caller_agent_id",
    "caller_identity",
    "authenticated_caller_identity",
)

request_caller_auth_fields_observed = tuple(
    field
    for field in caller_auth_field_candidates
    if field in request_fields
)

firewall_caller_auth_parameters_observed = tuple(
    field
    for field in caller_auth_field_candidates
    if field in firewall_execute_parameters
)

presenting_agent_field_present = (
    "presenting_agent_id"
    in request_fields
)

presenting_agent_firewall_parameter_present = (
    "presenting_agent_id"
    in firewall_execute_parameters
)

explicit_independent_caller_identity_surface_observed = bool(
    request_caller_auth_fields_observed
    or firewall_caller_auth_parameters_observed
)


# ============================================================
# LEGITIMATE HUMAN AUTHORITY
# ============================================================

active_authority = AuthorityState.create(
    actor_id=HUMAN_ACTOR,
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)


# ============================================================
# TIMELINE / WITNESS
# ============================================================

timeline = []


class TimelineLedger(WitnessLedger):

    def __init__(
        self,
        path,
        timeline_ref,
    ):
        self._timeline_ref = timeline_ref
        super().__init__(path)

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
                + str(event_type)
            )

        return record


ledger = TimelineLedger(
    WITNESS_PATH,
    timeline,
)


# ============================================================
# TRACKING V03 VERIFIER
#
# This does not alter V03. It records which permit agent and
# expected presenter identity V07 supplies to the existing
# verifier at each verification call.
# ============================================================

verifier_call_log = []


class TrackingPermitVerifierV03(
    PermitVerifierV03
):

    def verify(
        self,
        *args,
        **kwargs,
    ):
        permit = kwargs.get(
            "permit"
        )

        if (
            permit is None
            and args
        ):
            permit = args[0]

        verifier_call_log.append({
            "permit_id":
                getattr(
                    permit,
                    "permit_id",
                    None,
                ),
            "permit_agent_id":
                getattr(
                    permit,
                    "agent_id",
                    None,
                ),
            "expected_agent_id":
                kwargs.get(
                    "expected_agent_id"
                ),
        })

        return super().verify(
            *args,
            **kwargs,
        )


# ============================================================
# NORMAL V03 / V07 STACK
# ============================================================

permit_signing_key = (
    b"P4-F02-PERMIT-SIGNING-KEY-00000000000001"
)

resolution_signing_key = (
    b"P4-F02-RESOLUTION-SIGNING-KEY-0000000001"
)

resolver_id = (
    "P4-F02-AUTHORIZED-RESOLVER-001"
)

permit_issuer = PermitIssuerV03(
    signing_key=permit_signing_key
)

permit_verifier = TrackingPermitVerifierV03(
    signing_key=permit_signing_key
)

resolution_issuer = (
    AuthorityResolutionAttestationIssuer(
        resolver_id=resolver_id,
        signing_key=
            resolution_signing_key,
    )
)

resolution_verifier = (
    AuthorityResolutionAttestationVerifier(
        resolver_id=resolver_id,
        signing_key=
            resolution_signing_key,
    )
)

resolver_state = {
    "calls": 0,
    "statuses": [],
}


def authority_resolver():

    resolver_state["calls"] += 1

    resolution = (
        AuthorityResolution.established(
            active_authority,
            reason=
                "P4-F02-ESTABLISHED-AUTHORITY",
        )
    )

    resolver_state[
        "statuses"
    ].append(
        resolution.status.value
    )

    timeline.append(
        "RESOLVER:"
        + resolution.status.value
        + ":ATTESTED"
    )

    return resolution_issuer.issue(
        resolution
    )


messaging_tool = MessagingDemoToolV06()

firewall = ExecutionFirewallV07(
    verifier=permit_verifier,
    resolution_attestation_verifier=
        resolution_verifier,
    ledger=ledger,
    constitution_path=(
        ROOT
        / "constitution"
        / "constitution.yaml"
    ),
)

broker = ToolBrokerV07(
    firewall=firewall,
    messaging_tool=messaging_tool,
)


# ============================================================
# CASE RUNNER
#
# actual_caller_agent_id is harness ground truth only.
# It is deliberately NOT passed to ToolRequestV07 or V07.
# ============================================================

def run_case(
    *,
    case_id: str,
    actual_caller_agent_id: str,
    permit_agent_id: str,
    presenting_agent_id: str,
):

    arguments = {
        "content": case_id
    }

    intent_hash = (
        case_id
        + "-INTENT"
    )

    permit = permit_issuer.issue(
        authority=active_authority,
        agent_id=permit_agent_id,
        intent_hash=intent_hash,
        permission="SEND",
        policy_version=
            "ERA-POLICY-001-v0.2.0",
        target=(
            case_id
            + "-RECIPIENT"
        ),
        tool="MESSAGING_DEMO",
        consequence_class="C4",
        arguments=arguments,
    )

    request = ToolRequestV07(
        permit=permit,
        current_authority=
            active_authority,
        presenting_agent_id=
            presenting_agent_id,
        authority_resolver=
            authority_resolver,
        intent_hash=
            intent_hash,
        permission="SEND",
        policy_version=
            "ERA-POLICY-001-v0.2.0",
        target=(
            case_id
            + "-RECIPIENT"
        ),
        tool_name=
            "MESSAGING_DEMO",
        consequence_class="C4",
        arguments=arguments,
    )

    calls_before = (
        resolver_state["calls"]
    )

    resolver_status_index = len(
        resolver_state[
            "statuses"
        ]
    )

    verifier_start_index = len(
        verifier_call_log
    )

    outbox_before = (
        broker.outbox_size()
    )

    witness_start_index = len(
        ledger.records()
    )

    timeline.append(
        "HARNESS:ACTUAL_CALLER:"
        + actual_caller_agent_id
        + ":PERMIT:"
        + permit_agent_id
        + ":PRESENTER:"
        + presenting_agent_id
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

    witness_end_index = len(
        ledger.records()
    )

    verifier_end_index = len(
        verifier_call_log
    )

    raw_status = (
        getattr(
            result,
            "status",
            None,
        )
        if result is not None
        else None
    )

    status = getattr(
        raw_status,
        "value",
        raw_status,
    )

    raw_reasons = (
        getattr(
            result,
            "reasons",
            (),
        )
        if result is not None
        else ()
    )

    reasons = list(
        raw_reasons or ()
    )

    return {
        "case_id":
            case_id,
        "actual_caller_agent_id_harness_ground_truth":
            actual_caller_agent_id,
        "actual_caller_supplied_to_runtime":
            False,
        "permit_id":
            permit.permit_id,
        "permit_bound_agent_id":
            permit.agent_id,
        "presenting_agent_id":
            presenting_agent_id,
        "human_actor_id":
            active_authority.actor_id,
        "human_authority_state_hash":
            active_authority.state_hash(),
        "resolver_calls":
            resolver_state["calls"]
            - calls_before,
        "resolver_statuses":
            list(
                resolver_state[
                    "statuses"
                ][
                    resolver_status_index:
                ]
            ),
        "verifier_calls":
            list(
                verifier_call_log[
                    verifier_start_index:
                    verifier_end_index
                ]
            ),
        "status":
            status,
        "reasons":
            reasons,
        "exception":
            exception,
        "outbox_before":
            outbox_before,
        "outbox_after":
            outbox_after,
        "consequence_committed":
            outbox_after
            > outbox_before,
        "witness_start_index":
            witness_start_index,
        "witness_end_index":
            witness_end_index,
        "witness_records_added":
            witness_end_index
            - witness_start_index,
    }


# ============================================================
# EXECUTION
# ============================================================

preconditions_preserved = all(
    (
        definition_identity_preserved,
        source_identity_preserved,
        antecedent_evidence_identity_preserved,
        presenting_agent_field_present,
        presenting_agent_firewall_parameter_present,
    )
)

positive_a = None
positive_b = None
negative_assert_a = None

if preconditions_preserved:

    positive_a = run_case(
        case_id=
            "P4-F02-PC-A",
        actual_caller_agent_id=
            AGENT_A,
        permit_agent_id=
            AGENT_A,
        presenting_agent_id=
            AGENT_A,
    )

    positive_b = run_case(
        case_id=
            "P4-F02-PC-B",
        actual_caller_agent_id=
            AGENT_B,
        permit_agent_id=
            AGENT_B,
        presenting_agent_id=
            AGENT_B,
    )

    negative_assert_a = run_case(
        case_id=
            "P4-F02-NEG-ASSERT-A",
        actual_caller_agent_id=
            AGENT_B,
        permit_agent_id=
            AGENT_A,
        presenting_agent_id=
            AGENT_A,
    )


# ============================================================
# DISCRIMINATION
# ============================================================

def verifier_calls_match(
    case_result,
    expected_agent_id: str,
) -> bool:

    if case_result is None:
        return False

    calls = case_result[
        "verifier_calls"
    ]

    return (
        len(calls) == 3
        and all(
            call.get(
                "permit_agent_id"
            ) == expected_agent_id
            and call.get(
                "expected_agent_id"
            ) == expected_agent_id
            for call in calls
        )
    )


positive_a_valid = (
    positive_a is not None
    and positive_a[
        "exception"
    ] is None
    and positive_a[
        "consequence_committed"
    ] is True
    and positive_a[
        "resolver_calls"
    ] >= 2
    and verifier_calls_match(
        positive_a,
        AGENT_A,
    )
)

positive_b_valid = (
    positive_b is not None
    and positive_b[
        "exception"
    ] is None
    and positive_b[
        "consequence_committed"
    ] is True
    and positive_b[
        "resolver_calls"
    ] >= 2
    and verifier_calls_match(
        positive_b,
        AGENT_B,
    )
)

assertion_committed = (
    negative_assert_a is not None
    and negative_assert_a[
        "exception"
    ] is None
    and negative_assert_a[
        "consequence_committed"
    ] is True
)

assertion_full_execution_path = (
    negative_assert_a is not None
    and negative_assert_a[
        "resolver_calls"
    ] >= 2
    and verifier_calls_match(
        negative_assert_a,
        AGENT_A,
    )
)

assertion_refused = (
    negative_assert_a is not None
    and negative_assert_a[
        "consequence_committed"
    ] is False
)

assertion_reasons = (
    negative_assert_a[
        "reasons"
    ]
    if negative_assert_a is not None
    else []
)

caller_auth_specific_refusal = any(
    (
        "CALLER" in str(reason).upper()
        and (
            "AUTH" in str(reason).upper()
            or "IDENTITY" in str(reason).upper()
        )
    )
    or (
        "AGENT_AUTHENTICATION"
        in str(reason).upper()
    )
    for reason in assertion_reasons
)


# ============================================================
# WITNESS OBSERVATION
# ============================================================

records = ledger.records()


def case_records(case_result):

    if case_result is None:
        return []

    return records[
        case_result[
            "witness_start_index"
        ]:
        case_result[
            "witness_end_index"
        ]
    ]


negative_records = (
    case_records(
        negative_assert_a
    )
)


def has_claimed_agent_pair(
    record,
    permit_agent_id: str,
    presenting_agent_id: str,
) -> bool:

    if not isinstance(
        record,
        dict,
    ):
        return False

    details = record.get(
        "details",
        {},
    )

    return (
        isinstance(
            details,
            dict,
        )
        and details.get(
            "permit_agent_id"
        ) == permit_agent_id
        and details.get(
            "presenting_agent_id"
        ) == presenting_agent_id
    )


witness_negative_records_claimed_a_as_a = any(
    has_claimed_agent_pair(
        record,
        AGENT_A,
        AGENT_A,
    )
    for record
    in negative_records
)


def witness_has_native_actual_caller_identity(
    record,
) -> bool:

    if not isinstance(
        record,
        dict,
    ):
        return False

    details = record.get(
        "details",
        {},
    )

    keys = set(
        record.keys()
    )

    if isinstance(
        details,
        dict,
    ):
        keys.update(
            details.keys()
        )

    return any(
        key in keys
        for key in caller_auth_field_candidates
    )


witness_native_actual_caller_identity_observed = any(
    witness_has_native_actual_caller_identity(
        record
    )
    for record
    in negative_records
)

chain_valid, chain_errors = (
    ledger.verify_chain()
)


# ============================================================
# CLASSIFICATION
# ============================================================

seam_observed = all(
    (
        positive_a_valid,
        positive_b_valid,
        assertion_committed,
        assertion_full_execution_path,
        not explicit_independent_caller_identity_surface_observed,
        witness_negative_records_claimed_a_as_a,
        not witness_native_actual_caller_identity_observed,
        chain_valid,
    )
)

if not preconditions_preserved:

    classification = (
        "P4-F02_PRECONDITION_IDENTITY_FAILURE"
    )

elif not positive_a_valid:

    classification = (
        "P4-F02_AGENT_A_POSITIVE_CONTROL_FAILED"
    )

elif not positive_b_valid:

    classification = (
        "P4-F02_AGENT_B_POSITIVE_CONTROL_FAILED"
    )

elif not chain_valid:

    classification = (
        "P4-F02_WITNESS_CHAIN_INVALID"
    )

elif seam_observed:

    classification = (
        "UNAUTHENTICATED_PRESENTER_ASSERTION_ACCEPTED__"
        "CALLER_AUTHENTICITY_NOT_NATIVELY_BOUND"
    )

elif assertion_committed:

    classification = (
        "P4-F02_ASSERTION_COMMITTED__"
        "CALLER_AUTHENTICITY_RESULT_REQUIRES_REVIEW"
    )

elif (
    assertion_refused
    and caller_auth_specific_refusal
):

    classification = (
        "INDEPENDENT_CALLER_AUTHENTICITY_CONTROL_OBSERVED__"
        "FALSE_PRESENTER_ASSERTION_REFUSED"
    )

else:

    classification = (
        "P4-F02_ASSERTION_REFUSED_BY_OTHER_CONTROL__"
        "CALLER_AUTHENTICITY_NOT_ESTABLISHED"
    )


# ============================================================
# RESULT / FREEZE
# ============================================================

result_payload = {
    "test_id":
        TEST_ID,
    "classification":
        classification,
    "definition_commit":
        DEFINITION_COMMIT,
    "antecedent_evidence_commit":
        ANTECEDENT_EVIDENCE_COMMIT,
    "definition_identity_preserved":
        definition_identity_preserved,
    "source_identity":
        source_identity,
    "source_identity_preserved":
        source_identity_preserved,
    "antecedent_identity":
        antecedent_identity,
    "antecedent_evidence_identity_preserved":
        antecedent_evidence_identity_preserved,
    "tested_identity_surface": {
        "tool_request_fields":
            request_fields,
        "firewall_execute_parameters":
            firewall_execute_parameters,
        "presenting_agent_field_present":
            presenting_agent_field_present,
        "presenting_agent_firewall_parameter_present":
            presenting_agent_firewall_parameter_present,
        "request_caller_auth_fields_observed":
            request_caller_auth_fields_observed,
        "firewall_caller_auth_parameters_observed":
            firewall_caller_auth_parameters_observed,
        "explicit_independent_caller_identity_surface_observed":
            explicit_independent_caller_identity_surface_observed,
    },
    "positive_control_agent_a":
        positive_a,
    "positive_control_agent_b":
        positive_b,
    "negative_false_presenter_assertion":
        negative_assert_a,
    "required_observations": {
        "positive_agent_a_valid":
            positive_a_valid,
        "positive_agent_b_valid":
            positive_b_valid,
        "false_presenter_assertion_committed":
            assertion_committed,
        "false_presenter_assertion_refused":
            assertion_refused,
        "adversarial_case_exercised_full_execution_path":
            assertion_full_execution_path,
        "caller_auth_specific_refusal":
            caller_auth_specific_refusal,
        "witness_records_claimed_agent_a_as_presenter_a":
            witness_negative_records_claimed_a_as_a,
        "witness_native_actual_caller_identity_observed":
            witness_native_actual_caller_identity_observed,
        "witness_chain_valid":
            chain_valid,
        "seam_observed":
            seam_observed,
    },
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
        "This test models actual caller identity as harness ground truth "
        "that is deliberately not supplied to the tested V07 execution "
        "path. It asks whether an Agent-B-modeled caller can use an "
        "Agent-A-bound permit while supplying presenting_agent_id as "
        "Agent A, with otherwise-valid authority and execution material. "
        "If accepted, the finding is limited to the tested V07 reference "
        "path and establishes only that matching permit_agent_id to the "
        "caller-supplied presenting_agent_id does not independently "
        "authenticate who supplied that identifier. It does not establish "
        "production exploitability, network spoofing feasibility, credential "
        "theft, swarm compromise, distributed-system compromise, tenant "
        "escape, remote attackability, or compromise of an external "
        "identity provider."
    ),
}

freeze_payload = {
    "test_id":
        TEST_ID,
    "freeze_type":
        "FIRST_OBSERVED_RESULT_FREEZE",
    "classification":
        classification,
    "definition_commit":
        DEFINITION_COMMIT,
    "antecedent_evidence_commit":
        ANTECEDENT_EVIDENCE_COMMIT,
    "definition_identity_preserved":
        definition_identity_preserved,
    "source_identity_preserved":
        source_identity_preserved,
    "antecedent_evidence_identity_preserved":
        antecedent_evidence_identity_preserved,
    "positive_agent_a_valid":
        positive_a_valid,
    "positive_agent_b_valid":
        positive_b_valid,
    "false_presenter_assertion_committed":
        assertion_committed,
    "false_presenter_assertion_refused":
        assertion_refused,
    "explicit_independent_caller_identity_surface_observed":
        explicit_independent_caller_identity_surface_observed,
    "witness_native_actual_caller_identity_observed":
        witness_native_actual_caller_identity_observed,
    "witness_chain_valid":
        chain_valid,
    "seam_observed":
        seam_observed,
    "no_retrospective_repair":
        True,
    "antecedent_test_rerun":
        False,
    "v03_v07_modified_before_observation":
        False,
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
    "=== P4-F02 FIRST OBSERVED RESULT ==="
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
    "antecedent_evidence_identity_preserved:",
    antecedent_evidence_identity_preserved,
)
print(
    "explicit_independent_caller_identity_surface_observed:",
    explicit_independent_caller_identity_surface_observed,
)
print(
    "positive_agent_a_valid:",
    positive_a_valid,
)
print(
    "positive_agent_b_valid:",
    positive_b_valid,
)
print(
    "false_presenter_assertion_committed:",
    assertion_committed,
)
print(
    "false_presenter_assertion_refused:",
    assertion_refused,
)
print(
    "adversarial_case_exercised_full_execution_path:",
    assertion_full_execution_path,
)
print(
    "witness_native_actual_caller_identity_observed:",
    witness_native_actual_caller_identity_observed,
)
print(
    "witness_chain_valid:",
    chain_valid,
)
print(
    "seam_observed:",
    seam_observed,
)
print()
print(
    "RESULT:",
    RESULT_PATH.relative_to(ROOT),
)
print(
    "RESULT_SHA256:",
    sha256(RESULT_PATH),
)
print(
    "FREEZE:",
    FREEZE_PATH.relative_to(ROOT),
)
print(
    "FREEZE_SHA256:",
    sha256(FREEZE_PATH),
)
print(
    "WITNESS:",
    WITNESS_PATH.relative_to(ROOT),
)
print(
    "WITNESS_SHA256:",
    (
        sha256(WITNESS_PATH)
        if WITNESS_PATH.exists()
        else None
    ),
)