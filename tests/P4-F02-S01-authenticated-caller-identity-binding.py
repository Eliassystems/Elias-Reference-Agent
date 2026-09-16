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
from core.caller_identity_attestation import (
    CallerIdentityAttestation,
    CallerIdentityAttestationIssuer,
    CallerIdentityAttestationVerifier,
)
from core.execution_firewall_v08 import ExecutionFirewallV08
from core.permit_v03 import (
    PermitIssuerV03,
    PermitVerifierV03,
)
from tools.broker_v08 import ToolBrokerV08, ToolRequestV08
from tools.messaging_demo_v06 import MessagingDemoToolV06
from witness.ledger import WitnessLedger


TEST_ID = "P4-F02-S01"

DEFINITION_COMMIT = (
    "25a527019f14885ef7b22cc0f113c141e0c356a3"
)

IMPLEMENTATION_COMMIT = (
    "0f6f25e96941adb476a92cd0a65ffa32bf563b55"
)

PREDECESSOR_EVIDENCE_COMMIT = (
    "e245ea362e87e2b050a8d55715e75bab6bd271d4"
)

EXPECTED_DEFINITION_HASH = (
    "BE81F2BFAD7C2B0D4A4B698376C3459040F4C4C7CFBEECC5A75A420A42EA2F5B"
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

    "core/caller_identity_attestation.py":
        "AA0F7960733AF9A82B3D0F02D07CCBFBCAB907B42A5282B010D44B2F8576CFDA",

    "core/execution_firewall_v08.py":
        "F5DA87C150CAACCACCB875F19B1EC51B4E2BA3051E2DB5643005802131B0DCE9",

    "tools/broker_v08.py":
        "542E894D72D57FEF58B945AC4726AF104A3690C77678AF639E51B8E23B16A9BE",
}

EXPECTED_PREDECESSOR_EVIDENCE_HASHES = {
    "evidence/phase-iv/p4-f02/P4-F02-FIRST-OBSERVED-RESULT-001.json":
        "CC10C5B86864290B053D06F345EA05C0E4B17A5C6F13874F6BD7483B6D70D3DB",

    "evidence/phase-iv/p4-f02/P4-F02-FIRST-OBSERVED-FREEZE-001.json":
        "5C62B0C14F46E983CE8A0D2C8A0D08ED2D01B1E525E71590278B93E48BC0438E",

    "evidence/phase-iv/p4-f02/P4-F02-WITNESS-001.jsonl":
        "E89BFBBC7A0858599B348D267449FE23AEAA9FA8D12791A73981D7EA43029F8D",
}


EVIDENCE_DIR = (
    ROOT
    / "evidence"
    / "phase-iv"
    / "p4-f02-s01"
)

DEFINITION_PATH = (
    EVIDENCE_DIR
    / "P4-F02-S01-TEST-DEFINITION-001.json"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P4-F02-S01-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR
    / "P4-F02-S01-FIRST-OBSERVED-FREEZE-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P4-F02-S01-WITNESS-001.jsonl"
)


AGENT_A = "P4-F01-AGENT-A"
AGENT_B = "P4-F01-AGENT-B"
HUMAN_ACTOR = "P4-F01-HUMAN-001"

IDENTITY_AUTHORITY = (
    "P4-F02-S01-IDENTITY-AUTHORITY-001"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest().upper()


def write_json(
    path: Path,
    payload,
) -> None:

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
            "P4-F02-S01 FIRST-OBSERVED ARTIFACT EXISTS - DO NOT RERUN."
        )


# ============================================================
# DEFINITION / SOURCE / PREDECESSOR IDENTITY
# ============================================================

definition_identity_preserved = (
    sha256(DEFINITION_PATH)
    == EXPECTED_DEFINITION_HASH
)

source_identity = {}
source_identity_preserved = True

for relative, expected in EXPECTED_SOURCE_HASHES.items():

    actual = sha256(
        ROOT / relative
    )

    source_identity[relative] = {
        "expected_sha256":
            expected,
        "actual_sha256":
            actual,
        "preserved":
            actual == expected,
    }

    if actual != expected:
        source_identity_preserved = False


predecessor_identity = {}
predecessor_evidence_identity_preserved = True

for (
    relative,
    expected,
) in EXPECTED_PREDECESSOR_EVIDENCE_HASHES.items():

    actual = sha256(
        ROOT / relative
    )

    predecessor_identity[relative] = {
        "expected_sha256":
            expected,
        "actual_sha256":
            actual,
        "preserved":
            actual == expected,
    }

    if actual != expected:
        predecessor_evidence_identity_preserved = False


# ============================================================
# SUCCESSOR SCHEMA OBSERVATION
# ============================================================

request_fields = tuple(
    field.name
    for field
    in dataclasses.fields(
        ToolRequestV08
    )
)

attestation_fields = tuple(
    field.name
    for field
    in dataclasses.fields(
        CallerIdentityAttestation
    )
)

firewall_execute_parameters = tuple(
    inspect.signature(
        ExecutionFirewallV08.execute
    ).parameters.keys()
)

request_has_presenter = (
    "presenting_agent_id"
    in request_fields
)

request_has_caller_attestation = (
    "caller_identity_attestation"
    in request_fields
)

firewall_has_presenter = (
    "presenting_agent_id"
    in firewall_execute_parameters
)

firewall_has_caller_attestation = (
    "caller_identity_attestation"
    in firewall_execute_parameters
)

required_attestation_fields = {
    "attestation_id",
    "subject_agent_id",
    "issuer_id",
    "issued_at",
    "expires_at",
    "nonce",
    "signature",
}

attestation_schema_complete = (
    required_attestation_fields
    .issubset(
        set(attestation_fields)
    )
)

successor_schema_present = all(
    (
        request_has_presenter,
        request_has_caller_attestation,
        firewall_has_presenter,
        firewall_has_caller_attestation,
        attestation_schema_complete,
    )
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
                + str(event_type)
            )

        return record


ledger = TimelineLedger(
    WITNESS_PATH,
    timeline,
)


# ============================================================
# TRACKING PERMIT VERIFIER
# ============================================================

permit_verifier_call_log = []


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

        result = super().verify(
            *args,
            **kwargs,
        )

        permit_verifier_call_log.append({
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

            "valid":
                result.valid,

            "reasons":
                list(
                    result.reasons
                ),
        })

        return result


# ============================================================
# TRACKING CALLER-IDENTITY VERIFIER
# ============================================================

caller_verifier_call_log = []


class TrackingCallerIdentityVerifier(
    CallerIdentityAttestationVerifier
):

    def verify(
        self,
        *args,
        **kwargs,
    ):

        attestation = kwargs.get(
            "attestation"
        )

        if (
            attestation is None
            and args
        ):
            attestation = args[0]

        result = super().verify(
            *args,
            **kwargs,
        )

        caller_verifier_call_log.append({
            "attestation_id":
                getattr(
                    attestation,
                    "attestation_id",
                    None,
                ),

            "subject_agent_id":
                getattr(
                    attestation,
                    "subject_agent_id",
                    None,
                ),

            "issuer_id":
                getattr(
                    attestation,
                    "issuer_id",
                    None,
                ),

            "valid":
                result.valid,

            "reasons":
                list(
                    result.reasons
                ),

            "authenticated_subject_agent_id":
                result.authenticated_subject_agent_id,
        })

        return result


# ============================================================
# V03 / V08 STACK
# ============================================================

permit_signing_key = (
    b"P4-F02-S01-PERMIT-SIGNING-KEY-0000000001"
)

resolution_signing_key = (
    b"P4-F02-S01-RESOLUTION-SIGNING-KEY-00000001"
)

caller_identity_signing_key = (
    b"P4-F02-S01-CALLER-IDENTITY-SIGNING-KEY-0001"
)

resolver_id = (
    "P4-F02-S01-AUTHORIZED-RESOLVER-001"
)

permit_issuer = PermitIssuerV03(
    signing_key=
        permit_signing_key
)

permit_verifier = (
    TrackingPermitVerifierV03(
        signing_key=
            permit_signing_key
    )
)

resolution_issuer = (
    AuthorityResolutionAttestationIssuer(
        resolver_id=
            resolver_id,
        signing_key=
            resolution_signing_key,
    )
)

resolution_verifier = (
    AuthorityResolutionAttestationVerifier(
        resolver_id=
            resolver_id,
        signing_key=
            resolution_signing_key,
    )
)

caller_identity_issuer = (
    CallerIdentityAttestationIssuer(
        issuer_id=
            IDENTITY_AUTHORITY,
        signing_key=
            caller_identity_signing_key,
    )
)

caller_identity_verifier = (
    TrackingCallerIdentityVerifier(
        issuer_id=
            IDENTITY_AUTHORITY,
        signing_key=
            caller_identity_signing_key,
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
                "P4-F02-S01-ESTABLISHED-AUTHORITY",
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

firewall = ExecutionFirewallV08(
    verifier=
        permit_verifier,

    resolution_attestation_verifier=
        resolution_verifier,

    caller_identity_attestation_verifier=
        caller_identity_verifier,

    ledger=
        ledger,

    constitution_path=(
        ROOT
        / "constitution"
        / "constitution.yaml"
    ),
)

broker = ToolBrokerV08(
    firewall=
        firewall,

    messaging_tool=
        messaging_tool,
)


# ============================================================
# CASE RUNNER
# ============================================================

def run_case(
    *,
    case_id: str,
    permit_agent_id: str,
    presenting_agent_id: str,
    caller_attestation_subject_agent_id: str,
    tamper_subject_agent_id: str | None = None,
):

    arguments = {
        "content":
            case_id
    }

    intent_hash = (
        case_id
        + "-INTENT"
    )

    permit = permit_issuer.issue(
        authority=
            active_authority,

        agent_id=
            permit_agent_id,

        intent_hash=
            intent_hash,

        permission=
            "SEND",

        policy_version=
            "ERA-POLICY-001-v0.2.0",

        target=(
            case_id
            + "-RECIPIENT"
        ),

        tool=
            "MESSAGING_DEMO",

        consequence_class=
            "C4",

        arguments=
            arguments,
    )

    original_attestation = (
        caller_identity_issuer.issue(
            subject_agent_id=
                caller_attestation_subject_agent_id,

            ttl_seconds=
                900,

            nonce=(
                case_id
                + "-CALLER-IDENTITY-NONCE"
            ),
        )
    )

    supplied_attestation = (
        original_attestation
    )

    if (
        tamper_subject_agent_id
        is not None
    ):
        supplied_attestation = (
            dataclasses.replace(
                original_attestation,
                subject_agent_id=
                    tamper_subject_agent_id,
            )
        )

    request = ToolRequestV08(
        permit=
            permit,

        current_authority=
            active_authority,

        presenting_agent_id=
            presenting_agent_id,

        caller_identity_attestation=
            supplied_attestation,

        authority_resolver=
            authority_resolver,

        intent_hash=
            intent_hash,

        permission=
            "SEND",

        policy_version=
            "ERA-POLICY-001-v0.2.0",

        target=(
            case_id
            + "-RECIPIENT"
        ),

        tool_name=
            "MESSAGING_DEMO",

        consequence_class=
            "C4",

        arguments=
            arguments,
    )

    resolver_calls_before = (
        resolver_state["calls"]
    )

    resolver_status_index = len(
        resolver_state[
            "statuses"
        ]
    )

    permit_verifier_start = len(
        permit_verifier_call_log
    )

    caller_verifier_start = len(
        caller_verifier_call_log
    )

    witness_start_index = len(
        ledger.records()
    )

    outbox_before = (
        broker.outbox_size()
    )

    timeline.append(
        "HARNESS:"
        + case_id
        + ":PERMIT:"
        + permit_agent_id
        + ":PRESENTER:"
        + presenting_agent_id
        + ":ATTESTED_SUBJECT:"
        + supplied_attestation.subject_agent_id
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

    permit_verifier_end = len(
        permit_verifier_call_log
    )

    caller_verifier_end = len(
        caller_verifier_call_log
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

        "permit_id":
            permit.permit_id,

        "permit_bound_agent_id":
            permit.agent_id,

        "presenting_agent_id":
            presenting_agent_id,

        "original_attestation_subject_agent_id":
            original_attestation.subject_agent_id,

        "supplied_attestation_subject_agent_id":
            supplied_attestation.subject_agent_id,

        "attestation_id":
            supplied_attestation.attestation_id,

        "attestation_issuer_id":
            supplied_attestation.issuer_id,

        "attestation_tampered":
            tamper_subject_agent_id
            is not None,

        "tamper_preserved_attestation_id":
            (
                supplied_attestation.attestation_id
                == original_attestation.attestation_id
            ),

        "tamper_preserved_signature":
            (
                supplied_attestation.signature
                == original_attestation.signature
            ),

        "resolver_calls":
            resolver_state["calls"]
            - resolver_calls_before,

        "resolver_statuses":
            list(
                resolver_state[
                    "statuses"
                ][
                    resolver_status_index:
                ]
            ),

        "permit_verifier_calls":
            list(
                permit_verifier_call_log[
                    permit_verifier_start:
                    permit_verifier_end
                ]
            ),

        "caller_identity_verifier_calls":
            list(
                caller_verifier_call_log[
                    caller_verifier_start:
                    caller_verifier_end
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
# PRECONDITIONS
# ============================================================

preconditions_preserved = all(
    (
        definition_identity_preserved,
        source_identity_preserved,
        predecessor_evidence_identity_preserved,
        successor_schema_present,
    )
)


# ============================================================
# FIRST EXECUTION CASES
# ============================================================

positive_a = None
positive_b = None
negative_caller_mismatch = None
negative_tampered_identity = None

if preconditions_preserved:

    positive_a = run_case(
        case_id=
            "P4-F02-S01-PC-A",

        permit_agent_id=
            AGENT_A,

        presenting_agent_id=
            AGENT_A,

        caller_attestation_subject_agent_id=
            AGENT_A,
    )

    positive_b = run_case(
        case_id=
            "P4-F02-S01-PC-B",

        permit_agent_id=
            AGENT_B,

        presenting_agent_id=
            AGENT_B,

        caller_attestation_subject_agent_id=
            AGENT_B,
    )

    negative_caller_mismatch = run_case(
        case_id=
            "P4-F02-S01-NEG-CALLER-MISMATCH",

        permit_agent_id=
            AGENT_A,

        presenting_agent_id=
            AGENT_A,

        caller_attestation_subject_agent_id=
            AGENT_B,
    )

    negative_tampered_identity = run_case(
        case_id=
            "P4-F02-S01-NEG-TAMPERED-IDENTITY",

        permit_agent_id=
            AGENT_A,

        presenting_agent_id=
            AGENT_A,

        caller_attestation_subject_agent_id=
            AGENT_B,

        tamper_subject_agent_id=
            AGENT_A,
    )


# ============================================================
# DISCRIMINATION HELPERS
# ============================================================

def permit_verifier_calls_match(
    case_result,
    expected_agent_id: str,
    expected_count: int,
) -> bool:

    if case_result is None:
        return False

    calls = case_result[
        "permit_verifier_calls"
    ]

    return (
        len(calls) == expected_count
        and all(
            call.get(
                "permit_agent_id"
            ) == expected_agent_id

            and call.get(
                "expected_agent_id"
            ) == expected_agent_id

            and call.get(
                "valid"
            ) is True

            for call
            in calls
        )
    )


def caller_calls_valid_for_subject(
    case_result,
    expected_subject: str,
    expected_count: int,
) -> bool:

    if case_result is None:
        return False

    calls = case_result[
        "caller_identity_verifier_calls"
    ]

    return (
        len(calls) == expected_count
        and all(
            call.get(
                "subject_agent_id"
            ) == expected_subject

            and call.get(
                "valid"
            ) is True

            and call.get(
                "authenticated_subject_agent_id"
            ) == expected_subject

            for call
            in calls
        )
    )


def caller_call_invalid(
    case_result,
    expected_subject: str,
) -> bool:

    if case_result is None:
        return False

    calls = case_result[
        "caller_identity_verifier_calls"
    ]

    return (
        len(calls) == 1
        and calls[0].get(
            "subject_agent_id"
        ) == expected_subject
        and calls[0].get(
            "valid"
        ) is False
        and calls[0].get(
            "authenticated_subject_agent_id"
        ) is None
    )


# ============================================================
# POSITIVE / NEGATIVE BEHAVIOUR
# ============================================================

positive_a_valid = (
    positive_a is not None
    and positive_a[
        "exception"
    ] is None
    and positive_a[
        "status"
    ] == "EXECUTED"
    and positive_a[
        "consequence_committed"
    ] is True
    and positive_a[
        "resolver_calls"
    ] == 2
    and permit_verifier_calls_match(
        positive_a,
        AGENT_A,
        3,
    )
    and caller_calls_valid_for_subject(
        positive_a,
        AGENT_A,
        3,
    )
)

positive_b_valid = (
    positive_b is not None
    and positive_b[
        "exception"
    ] is None
    and positive_b[
        "status"
    ] == "EXECUTED"
    and positive_b[
        "consequence_committed"
    ] is True
    and positive_b[
        "resolver_calls"
    ] == 2
    and permit_verifier_calls_match(
        positive_b,
        AGENT_B,
        3,
    )
    and caller_calls_valid_for_subject(
        positive_b,
        AGENT_B,
        3,
    )
)

mismatch_refused = (
    negative_caller_mismatch is not None
    and negative_caller_mismatch[
        "exception"
    ] is None
    and negative_caller_mismatch[
        "status"
    ] == "REFUSED_BEFORE_CONSEQUENCE"
    and negative_caller_mismatch[
        "consequence_committed"
    ] is False
    and negative_caller_mismatch[
        "outbox_after"
    ] == negative_caller_mismatch[
        "outbox_before"
    ]
    and negative_caller_mismatch[
        "resolver_calls"
    ] == 0
    and negative_caller_mismatch[
        "reasons"
    ] == [
        "AUTHENTICATED_CALLER_AGENT_MISMATCH"
    ]
    and permit_verifier_calls_match(
        negative_caller_mismatch,
        AGENT_A,
        1,
    )
    and caller_calls_valid_for_subject(
        negative_caller_mismatch,
        AGENT_B,
        1,
    )
)

tampered_identity_refused = (
    negative_tampered_identity is not None
    and negative_tampered_identity[
        "exception"
    ] is None
    and negative_tampered_identity[
        "status"
    ] == "REFUSED_BEFORE_CONSEQUENCE"
    and negative_tampered_identity[
        "consequence_committed"
    ] is False
    and negative_tampered_identity[
        "outbox_after"
    ] == negative_tampered_identity[
        "outbox_before"
    ]
    and negative_tampered_identity[
        "resolver_calls"
    ] == 0
    and len(
        negative_tampered_identity[
            "reasons"
        ]
    ) >= 1
    and negative_tampered_identity[
        "reasons"
    ][0] == "CALLER_IDENTITY_ATTESTATION_INVALID"
    and negative_tampered_identity[
        "tamper_preserved_attestation_id"
    ] is True
    and negative_tampered_identity[
        "tamper_preserved_signature"
    ] is True
    and permit_verifier_calls_match(
        negative_tampered_identity,
        AGENT_A,
        1,
    )
    and caller_call_invalid(
        negative_tampered_identity,
        AGENT_A,
    )
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


def identity_record_matches(
    record,
    *,
    permit_agent_id: str,
    presenting_agent_id: str,
    authenticated_caller_agent_id,
    attestation_id: str,
    issuer_id: str,
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

    if not isinstance(
        details,
        dict,
    ):
        return False

    return (
        details.get(
            "permit_agent_id"
        ) == permit_agent_id

        and details.get(
            "presenting_agent_id"
        ) == presenting_agent_id

        and details.get(
            "authenticated_caller_agent_id"
        ) == authenticated_caller_agent_id

        and details.get(
            "caller_identity_attestation_id"
        ) == attestation_id

        and details.get(
            "caller_identity_issuer_id"
        ) == issuer_id
    )


def case_identity_witness_preserved(
    case_result,
    *,
    permit_agent_id: str,
    presenting_agent_id: str,
    authenticated_caller_agent_id,
) -> bool:

    if case_result is None:
        return False

    case_witness = case_records(
        case_result
    )

    identity_records = []

    for record in case_witness:

        details = (
            record.get(
                "details",
                {},
            )
            if isinstance(
                record,
                dict,
            )
            else {}
        )

        if (
            isinstance(
                details,
                dict,
            )
            and "permit_agent_id"
            in details
        ):
            identity_records.append(
                record
            )

    return (
        bool(
            identity_records
        )
        and all(
            identity_record_matches(
                record,
                permit_agent_id=
                    permit_agent_id,
                presenting_agent_id=
                    presenting_agent_id,
                authenticated_caller_agent_id=
                    authenticated_caller_agent_id,
                attestation_id=
                    case_result[
                        "attestation_id"
                    ],
                issuer_id=
                    case_result[
                        "attestation_issuer_id"
                    ],
            )
            for record
            in identity_records
        )
    )


positive_a_witness_preserved = (
    case_identity_witness_preserved(
        positive_a,
        permit_agent_id=
            AGENT_A,
        presenting_agent_id=
            AGENT_A,
        authenticated_caller_agent_id=
            AGENT_A,
    )
)

positive_b_witness_preserved = (
    case_identity_witness_preserved(
        positive_b,
        permit_agent_id=
            AGENT_B,
        presenting_agent_id=
            AGENT_B,
        authenticated_caller_agent_id=
            AGENT_B,
    )
)

mismatch_witness_preserved = (
    case_identity_witness_preserved(
        negative_caller_mismatch,
        permit_agent_id=
            AGENT_A,
        presenting_agent_id=
            AGENT_A,
        authenticated_caller_agent_id=
            AGENT_B,
    )
)

tampered_witness_preserved = (
    case_identity_witness_preserved(
        negative_tampered_identity,
        permit_agent_id=
            AGENT_A,
        presenting_agent_id=
            AGENT_A,
        authenticated_caller_agent_id=
            None,
    )
)

witness_distinguishes_identities = all(
    (
        positive_a_witness_preserved,
        positive_b_witness_preserved,
        mismatch_witness_preserved,
        tampered_witness_preserved,
    )
)

chain_valid, chain_errors = (
    ledger.verify_chain()
)


# ============================================================
# CLASSIFICATION
# ============================================================

control_established = all(
    (
        preconditions_preserved,
        positive_a_valid,
        positive_b_valid,
        mismatch_refused,
        tampered_identity_refused,
        witness_distinguishes_identities,
        chain_valid,
    )
)

if not preconditions_preserved:

    classification = (
        "P4-F02-S01_PRECONDITION_IDENTITY_FAILURE"
    )

elif not positive_a_valid:

    classification = (
        "P4-F02-S01_AGENT_A_POSITIVE_CONTROL_FAILED"
    )

elif not positive_b_valid:

    classification = (
        "P4-F02-S01_AGENT_B_POSITIVE_CONTROL_FAILED"
    )

elif not mismatch_refused:

    classification = (
        "P4-F02-S01_FALSE_PRESENTER_MISMATCH_CONTROL_FAILED"
    )

elif not tampered_identity_refused:

    classification = (
        "P4-F02-S01_TAMPERED_IDENTITY_CONTROL_FAILED"
    )

elif not witness_distinguishes_identities:

    classification = (
        "P4-F02-S01_WITNESS_IDENTITY_CONTINUITY_FAILED"
    )

elif not chain_valid:

    classification = (
        "P4-F02-S01_WITNESS_CHAIN_INVALID"
    )

else:

    classification = (
        "AUTHENTICATED_CALLER_IDENTITY_BINDING_ESTABLISHED__"
        "FALSE_PRESENTER_ASSERTION_REFUSED_BEFORE_CONSEQUENCE"
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

    "implementation_commit":
        IMPLEMENTATION_COMMIT,

    "predecessor_evidence_commit":
        PREDECESSOR_EVIDENCE_COMMIT,

    "definition_identity_preserved":
        definition_identity_preserved,

    "source_identity":
        source_identity,

    "source_identity_preserved":
        source_identity_preserved,

    "predecessor_identity":
        predecessor_identity,

    "predecessor_evidence_identity_preserved":
        predecessor_evidence_identity_preserved,

    "successor_schema": {
        "tool_request_fields":
            request_fields,

        "caller_identity_attestation_fields":
            attestation_fields,

        "firewall_execute_parameters":
            firewall_execute_parameters,

        "request_has_presenter":
            request_has_presenter,

        "request_has_caller_attestation":
            request_has_caller_attestation,

        "firewall_has_presenter":
            firewall_has_presenter,

        "firewall_has_caller_attestation":
            firewall_has_caller_attestation,

        "attestation_schema_complete":
            attestation_schema_complete,

        "successor_schema_present":
            successor_schema_present,
    },

    "positive_control_agent_a":
        positive_a,

    "positive_control_agent_b":
        positive_b,

    "negative_caller_mismatch":
        negative_caller_mismatch,

    "negative_tampered_identity":
        negative_tampered_identity,

    "required_observations": {
        "positive_agent_a_valid":
            positive_a_valid,

        "positive_agent_b_valid":
            positive_b_valid,

        "false_presenter_mismatch_refused":
            mismatch_refused,

        "tampered_identity_refused":
            tampered_identity_refused,

        "positive_a_witness_identity_preserved":
            positive_a_witness_preserved,

        "positive_b_witness_identity_preserved":
            positive_b_witness_preserved,

        "mismatch_witness_identity_preserved":
            mismatch_witness_preserved,

        "tampered_witness_identity_preserved":
            tampered_witness_preserved,

        "witness_distinguishes_identities":
            witness_distinguishes_identities,

        "witness_chain_valid":
            chain_valid,

        "authenticated_caller_binding_control_established":
            control_established,
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
        "A successful result establishes only that the tested P4-F02-S01 "
        "successor reference path independently verifies a signed caller-"
        "identity attestation and requires its authenticated subject agent "
        "identity to agree with both the supplied presenting_agent_id and "
        "permit-bound agent_id before consequence, while rechecking that "
        "caller identity at the tested consequence and commit boundaries. "
        "It does not establish network-layer authentication, operating-system "
        "process identity, hardware-backed identity, credential isolation, "
        "external identity-provider security, tenant isolation, distributed-"
        "agent security, swarm security, production exploitability resistance, "
        "or protection against compromise of the identity authority, signing "
        "key, authorized agent, human authority, resolver, deployment perimeter "
        "or tool credential."
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

    "implementation_commit":
        IMPLEMENTATION_COMMIT,

    "predecessor_evidence_commit":
        PREDECESSOR_EVIDENCE_COMMIT,

    "definition_identity_preserved":
        definition_identity_preserved,

    "source_identity_preserved":
        source_identity_preserved,

    "predecessor_evidence_identity_preserved":
        predecessor_evidence_identity_preserved,

    "successor_schema_present":
        successor_schema_present,

    "positive_agent_a_valid":
        positive_a_valid,

    "positive_agent_b_valid":
        positive_b_valid,

    "false_presenter_mismatch_refused":
        mismatch_refused,

    "tampered_identity_refused":
        tampered_identity_refused,

    "witness_distinguishes_identities":
        witness_distinguishes_identities,

    "witness_chain_valid":
        chain_valid,

    "authenticated_caller_binding_control_established":
        control_established,

    "no_retrospective_repair":
        True,

    "predecessor_test_rerun":
        False,

    "v03_v07_modified":
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
    "=== P4-F02-S01 FIRST OBSERVED RESULT ==="
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
    "predecessor_evidence_identity_preserved:",
    predecessor_evidence_identity_preserved,
)

print(
    "successor_schema_present:",
    successor_schema_present,
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
    "false_presenter_mismatch_refused:",
    mismatch_refused,
)

print(
    "tampered_identity_refused:",
    tampered_identity_refused,
)

print(
    "witness_distinguishes_identities:",
    witness_distinguishes_identities,
)

print(
    "witness_chain_valid:",
    chain_valid,
)

print(
    "authenticated_caller_binding_control_established:",
    control_established,
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
