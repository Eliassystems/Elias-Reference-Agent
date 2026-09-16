from __future__ import annotations

import dataclasses
import hashlib
import hmac
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
from core.permit_v03 import (
    ExecutionPermitV03,
    PermitIssuerV03,
    PermitVerifierV03,
)
from tools.broker_v07 import ToolBrokerV07, ToolRequestV07
from tools.messaging_demo_v06 import MessagingDemoToolV06
from witness.ledger import WitnessLedger


TEST_ID = "P4-F01-S01"

SUCCESSOR_IMPLEMENTATION_COMMIT = (
    "5d3be3be0f2410aa1dfcf38a387ae686d1286369"
)

PREDECESSOR_COMMIT = (
    "cb37a4269e60f505df5f55d69857019daa522f88"
)

EXPECTED_DEFINITION_HASH = (
    "0778942B276844A24DE360CF885DED08642D552BC0D13052B8D515E86AA96E85"
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

EVIDENCE_DIR = (
    ROOT
    / "evidence"
    / "phase-iv"
    / "p4-f01-s01"
)

DEFINITION_PATH = (
    EVIDENCE_DIR
    / "P4-F01-S01-TEST-DEFINITION-001.json"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P4-F01-S01-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR
    / "P4-F01-S01-FIRST-OBSERVED-FREEZE-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P4-F01-S01-WITNESS-001.jsonl"
)

AGENT_A = "P4-F01-AGENT-A"
AGENT_B = "P4-F01-AGENT-B"
HUMAN_ACTOR = "P4-F01-HUMAN-001"


def sha256(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest().upper()


def canonical_json(payload: dict) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


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
            "P4-F01-S01 FIRST-OBSERVED ARTIFACT EXISTS - DO NOT RERUN."
        )


# ============================================================
# DEFINITION / SOURCE IDENTITY
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
        "expected_sha256": expected,
        "actual_sha256": actual,
        "preserved": actual == expected,
    }

    if actual != expected:
        source_identity_preserved = False


# ============================================================
# SUCCESSOR SCHEMA OBSERVATION
# ============================================================

permit_fields = tuple(
    field.name
    for field in dataclasses.fields(
        ExecutionPermitV03
    )
)

request_fields = tuple(
    field.name
    for field in dataclasses.fields(
        ToolRequestV07
    )
)

permit_agent_binding_field_present = (
    "agent_id" in permit_fields
)

request_presenter_field_present = (
    "presenting_agent_id"
    in request_fields
)

successor_schema_present = (
    permit_agent_binding_field_present
    and request_presenter_field_present
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
# NORMAL V03 / V07 STACK
# ============================================================

permit_signing_key = (
    b"P4-F01-S01-PERMIT-SIGNING-KEY-0000000001"
)

resolution_signing_key = (
    b"P4-F01-S01-RESOLUTION-SIGNING-KEY-000001"
)

resolver_id = (
    "P4-F01-S01-AUTHORIZED-RESOLVER-001"
)

permit_issuer = PermitIssuerV03(
    signing_key=permit_signing_key
)

permit_verifier = PermitVerifierV03(
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
                "P4-F01-S01-ESTABLISHED-AUTHORITY",
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


messaging_tool = (
    MessagingDemoToolV06()
)

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
# ISOLATED CRYPTOGRAPHIC AGENT-BINDING PROOF
#
# A normal pair of independently issued permits would also
# differ in timestamp and random nonce. That would not isolate
# agent identity as the causal cryptographic variable.
#
# Therefore:
#   1. issue one real V03 permit;
#   2. preserve its entire unsigned payload;
#   3. alter ONLY agent_id;
#   4. recompute canonical SHA-256 permit identity and HMAC.
# ============================================================

binding_reference_permit = (
    permit_issuer.issue(
        authority=active_authority,
        agent_id=(
            "  "
            + AGENT_A
            + "  "
        ),
        intent_hash=
            "P4-F01-S01-BINDING-PROOF-INTENT",
        permission="SEND",
        policy_version=
            "ERA-POLICY-001-v0.2.0",
        target=
            "P4-F01-S01-BINDING-PROOF-RECIPIENT",
        tool="MESSAGING_DEMO",
        consequence_class="C4",
        arguments={
            "content":
                "P4-F01-S01-BINDING-PROOF"
        },
    )
)

payload_agent_a = (
    binding_reference_permit
    .unsigned_payload()
)

payload_agent_b = dict(
    payload_agent_a
)

payload_agent_b[
    "agent_id"
] = AGENT_B

changed_fields = tuple(
    sorted(
        key
        for key in payload_agent_a
        if (
            payload_agent_a[key]
            != payload_agent_b[key]
        )
    )
)

recomputed_agent_a_permit_id = (
    hashlib.sha256(
        canonical_json(
            payload_agent_a
        )
    ).hexdigest().upper()
)

recomputed_agent_b_permit_id = (
    hashlib.sha256(
        canonical_json(
            payload_agent_b
        )
    ).hexdigest().upper()
)

recomputed_agent_a_signature = (
    hmac.new(
        permit_signing_key,
        canonical_json(
            payload_agent_a
        ),
        hashlib.sha256,
    ).hexdigest().upper()
)

recomputed_agent_b_signature = (
    hmac.new(
        permit_signing_key,
        canonical_json(
            payload_agent_b
        ),
        hashlib.sha256,
    ).hexdigest().upper()
)

cryptographic_binding_proof = {
    "reference_agent_normalized":
        binding_reference_permit.agent_id
        == AGENT_A,
    "changed_fields":
        changed_fields,
    "only_agent_id_changed":
        changed_fields
        == ("agent_id",),
    "runtime_permit_id_matches_independent_recomputation":
        binding_reference_permit.permit_id
        == recomputed_agent_a_permit_id,
    "runtime_signature_matches_independent_recomputation":
        binding_reference_permit.signature
        == recomputed_agent_a_signature,
    "agent_change_changes_permit_id":
        recomputed_agent_a_permit_id
        != recomputed_agent_b_permit_id,
    "agent_change_changes_signature":
        recomputed_agent_a_signature
        != recomputed_agent_b_signature,
    "agent_a_recomputed_permit_id":
        recomputed_agent_a_permit_id,
    "agent_b_recomputed_permit_id":
        recomputed_agent_b_permit_id,
    "agent_a_recomputed_signature":
        recomputed_agent_a_signature,
    "agent_b_recomputed_signature":
        recomputed_agent_b_signature,
}

cryptographic_agent_binding_established = all(
    (
        cryptographic_binding_proof[
            "reference_agent_normalized"
        ],
        cryptographic_binding_proof[
            "only_agent_id_changed"
        ],
        cryptographic_binding_proof[
            "runtime_permit_id_matches_independent_recomputation"
        ],
        cryptographic_binding_proof[
            "runtime_signature_matches_independent_recomputation"
        ],
        cryptographic_binding_proof[
            "agent_change_changes_permit_id"
        ],
        cryptographic_binding_proof[
            "agent_change_changes_signature"
        ],
    )
)


# ============================================================
# CASE RUNNER
# ============================================================

def run_case(
    *,
    case_id: str,
    bound_agent_id: str,
    presenting_agent_id: str,
):

    arguments = {
        "content": case_id
    }

    intent_hash = (
        case_id
        + "-INTENT"
    )

    permit = (
        permit_issuer.issue(
            authority=
                active_authority,
            agent_id=
                bound_agent_id,
            intent_hash=
                intent_hash,
            permission="SEND",
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
        consequence_class=
            "C4",
        arguments=
            arguments,
    )

    calls_before = (
        resolver_state["calls"]
    )

    status_index = len(
        resolver_state[
            "statuses"
        ]
    )

    outbox_before = (
        broker.outbox_size()
    )

    witness_start_index = len(
        ledger.records()
    )

    timeline.append(
        "HARNESS:BOUND:"
        + bound_agent_id
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
                    status_index:
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
#
# Each case receives a fresh permit. This avoids durable permit
# consumption contaminating the presenter-binding question.
# ============================================================

preconditions_preserved = (
    definition_identity_preserved
    and source_identity_preserved
    and successor_schema_present
)

positive_a = None
positive_b = None
negative_relay = None

if (
    preconditions_preserved
    and cryptographic_agent_binding_established
):

    positive_a = run_case(
        case_id=
            "S01-PC-A",
        bound_agent_id=
            AGENT_A,
        presenting_agent_id=
            AGENT_A,
    )

    positive_b = run_case(
        case_id=
            "S01-PC-B",
        bound_agent_id=
            AGENT_B,
        presenting_agent_id=
            AGENT_B,
    )

    negative_relay = run_case(
        case_id=
            "S01-NEG-RELAY",
        bound_agent_id=
            AGENT_A,
        presenting_agent_id=
            AGENT_B,
    )


# ============================================================
# DISCRIMINATION
# ============================================================

positive_a_committed = (
    positive_a is not None
    and positive_a[
        "exception"
    ] is None
    and positive_a[
        "consequence_committed"
    ] is True
)

positive_b_committed = (
    positive_b is not None
    and positive_b[
        "exception"
    ] is None
    and positive_b[
        "consequence_committed"
    ] is True
)

positive_a_exercised_dynamic_boundaries = (
    positive_a is not None
    and positive_a[
        "resolver_calls"
    ] >= 2
)

positive_b_exercised_dynamic_boundaries = (
    positive_b is not None
    and positive_b[
        "resolver_calls"
    ] >= 2
)

relay_committed = (
    negative_relay is not None
    and negative_relay[
        "consequence_committed"
    ] is True
)

relay_refused = (
    negative_relay is not None
    and negative_relay[
        "consequence_committed"
    ] is False
)

relay_agent_specific_refusal = (
    negative_relay is not None
    and negative_relay[
        "exception"
    ] is None
    and negative_relay[
        "status"
    ] == "REFUSED_BEFORE_CONSEQUENCE"
    and (
        "AGENT_ID_BINDING_MISMATCH"
        in negative_relay[
            "reasons"
        ]
    )
)


# ============================================================
# WITNESS DISTINGUISHABILITY
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


def has_agent_pair(
    record,
    bound_agent_id: str,
    presenting_agent_id: str,
) -> bool:

    details = (
        record.get(
            "details",
            {}
        )
        if isinstance(
            record,
            dict,
        )
        else {}
    )

    return (
        details.get(
            "permit_agent_id"
        )
        == bound_agent_id
        and details.get(
            "presenting_agent_id"
        )
        == presenting_agent_id
    )


positive_a_records = (
    case_records(
        positive_a
    )
)

positive_b_records = (
    case_records(
        positive_b
    )
)

negative_relay_records = (
    case_records(
        negative_relay
    )
)

witness_has_a_bound_a_presented = any(
    has_agent_pair(
        record,
        AGENT_A,
        AGENT_A,
    )
    for record
    in positive_a_records
)

witness_has_b_bound_b_presented = any(
    has_agent_pair(
        record,
        AGENT_B,
        AGENT_B,
    )
    for record
    in positive_b_records
)

witness_has_a_bound_b_presented = any(
    has_agent_pair(
        record,
        AGENT_A,
        AGENT_B,
    )
    for record
    in negative_relay_records
)

witness_negative_refusal_specific = any(
    (
        record.get(
            "event_type"
        )
        == "EXECUTION_REFUSED"
        and has_agent_pair(
            record,
            AGENT_A,
            AGENT_B,
        )
        and (
            "AGENT_ID_BINDING_MISMATCH"
            in (
                record.get(
                    "details",
                    {}
                ).get(
                    "reasons",
                    []
                )
            )
        )
    )
    for record
    in negative_relay_records
    if isinstance(
        record,
        dict,
    )
)

witness_distinguishes_bound_and_presenting_agent = (
    witness_has_a_bound_a_presented
    and witness_has_b_bound_b_presented
    and witness_has_a_bound_b_presented
    and witness_negative_refusal_specific
)

chain_valid, chain_errors = (
    ledger.verify_chain()
)


# ============================================================
# CLASSIFICATION
# ============================================================

required_discrimination_established = all(
    (
        positive_a_committed,
        positive_b_committed,
        not relay_committed,
        relay_refused,
        relay_agent_specific_refusal,
        positive_a_exercised_dynamic_boundaries,
        positive_b_exercised_dynamic_boundaries,
        witness_distinguishes_bound_and_presenting_agent,
        chain_valid,
    )
)

agent_presenter_binding_control_established = (
    preconditions_preserved
    and cryptographic_agent_binding_established
    and required_discrimination_established
)

if not preconditions_preserved:

    classification = (
        "P4-F01-S01_PRECONDITION_IDENTITY_FAILURE"
    )

elif not cryptographic_agent_binding_established:

    classification = (
        "P4-F01-S01_CRYPTOGRAPHIC_AGENT_BINDING_PROOF_FAILED"
    )

elif not positive_a_committed:

    classification = (
        "P4-F01-S01_AGENT_A_POSITIVE_CONTROL_FAILED"
    )

elif not positive_b_committed:

    classification = (
        "P4-F01-S01_AGENT_B_POSITIVE_CONTROL_FAILED"
    )

elif relay_committed:

    classification = (
        "CROSS_AGENT_RELAY_ACCEPTED__"
        "AGENT_PRESENTER_BINDING_NOT_ESTABLISHED"
    )

elif not relay_agent_specific_refusal:

    classification = (
        "CROSS_AGENT_RELAY_REFUSED_BY_OTHER_CONTROL__"
        "AGENT_PRESENTER_BINDING_NOT_ESTABLISHED"
    )

elif not (
    positive_a_exercised_dynamic_boundaries
    and positive_b_exercised_dynamic_boundaries
):

    classification = (
        "P4-F01-S01_DYNAMIC_BOUNDARY_EXERCISE_NOT_ESTABLISHED"
    )

elif not witness_distinguishes_bound_and_presenting_agent:

    classification = (
        "P4-F01-S01_WITNESS_AGENT_DISTINCTION_NOT_ESTABLISHED"
    )

elif not chain_valid:

    classification = (
        "P4-F01-S01_WITNESS_CHAIN_INVALID"
    )

else:

    classification = (
        "AGENT_PRESENTER_BINDING_ESTABLISHED__"
        "CROSS_AGENT_RELAY_REFUSED_BEFORE_CONSEQUENCE"
    )


# ============================================================
# RESULT / FREEZE
# ============================================================

result_payload = {
    "test_id":
        TEST_ID,
    "classification":
        classification,
    "predecessor_commit":
        PREDECESSOR_COMMIT,
    "successor_implementation_commit":
        SUCCESSOR_IMPLEMENTATION_COMMIT,
    "definition_identity_preserved":
        definition_identity_preserved,
    "source_identity":
        source_identity,
    "source_identity_preserved":
        source_identity_preserved,
    "successor_schema_observation": {
        "permit_fields":
            permit_fields,
        "request_fields":
            request_fields,
        "permit_agent_binding_field_present":
            permit_agent_binding_field_present,
        "request_presenter_field_present":
            request_presenter_field_present,
        "successor_schema_present":
            successor_schema_present,
    },
    "cryptographic_binding_proof":
        cryptographic_binding_proof,
    "cryptographic_agent_binding_established":
        cryptographic_agent_binding_established,
    "positive_control_agent_a":
        positive_a,
    "positive_control_agent_b":
        positive_b,
    "negative_cross_agent_relay":
        negative_relay,
    "required_discrimination": {
        "agent_a_bound_presented_by_a_commits":
            positive_a_committed,
        "agent_b_bound_presented_by_b_commits":
            positive_b_committed,
        "agent_a_bound_presented_by_b_commits":
            relay_committed,
        "agent_a_bound_presented_by_b_refused":
            relay_refused,
        "relay_refusal_agent_specific":
            relay_agent_specific_refusal,
        "agent_a_positive_exercised_dynamic_boundaries":
            positive_a_exercised_dynamic_boundaries,
        "agent_b_positive_exercised_dynamic_boundaries":
            positive_b_exercised_dynamic_boundaries,
        "witness_distinguishes_bound_and_presenting_agent":
            witness_distinguishes_bound_and_presenting_agent,
        "witness_chain_valid":
            chain_valid,
    },
    "witness": {
        "record_count":
            len(records),
        "agent_a_bound_a_presented":
            witness_has_a_bound_a_presented,
        "agent_b_bound_b_presented":
            witness_has_b_bound_b_presented,
        "agent_a_bound_b_presented":
            witness_has_a_bound_b_presented,
        "negative_refusal_specific":
            witness_negative_refusal_specific,
        "distinguishes_bound_and_presenting_agent":
            witness_distinguishes_bound_and_presenting_agent,
        "chain_valid":
            chain_valid,
        "chain_errors":
            chain_errors,
    },
    "agent_presenter_binding_control_established":
        agent_presenter_binding_control_established,
    "timeline":
        timeline,
    "bounded_claim": (
        "This successor test examines whether the reference runtime "
        "can bind a permit cryptographically to an upstream agent "
        "identifier supplied to the governed execution path, selectively "
        "distinguish correctly bound Agent A and Agent B presentations, "
        "refuse cross-agent relay, and preserve that distinction in "
        "witness evidence while the underlying legitimate human authority "
        "remains otherwise unchanged. A successful result establishes "
        "this bounded presenter-binding control only. It does not establish "
        "that the supplied agent identity was independently authenticated "
        "by an external identity provider or network boundary, and does "
        "not establish swarm security, distributed-agent security, "
        "credential isolation, concurrency safety, production exploitability "
        "resistance, network identity security, tenant isolation, or "
        "protection against compromise of an authorized human, agent, "
        "resolver, signing key, deployment perimeter or tool credential."
    ),
}

freeze_payload = {
    "test_id":
        TEST_ID,
    "freeze_type":
        "FIRST_OBSERVED_RESULT_FREEZE",
    "classification":
        classification,
    "predecessor_commit":
        PREDECESSOR_COMMIT,
    "successor_implementation_commit":
        SUCCESSOR_IMPLEMENTATION_COMMIT,
    "definition_identity_preserved":
        definition_identity_preserved,
    "source_identity_preserved":
        source_identity_preserved,
    "cryptographic_agent_binding_established":
        cryptographic_agent_binding_established,
    "agent_a_bound_presented_by_a_commits":
        positive_a_committed,
    "agent_b_bound_presented_by_b_commits":
        positive_b_committed,
    "agent_a_bound_presented_by_b_commits":
        relay_committed,
    "relay_refused":
        relay_refused,
    "relay_refusal_agent_specific":
        relay_agent_specific_refusal,
    "witness_distinguishes_bound_and_presenting_agent":
        witness_distinguishes_bound_and_presenting_agent,
    "witness_chain_valid":
        chain_valid,
    "agent_presenter_binding_control_established":
        agent_presenter_binding_control_established,
    "no_retrospective_repair":
        True,
    "predecessor_test_rerun":
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
    "=== P4-F01-S01 FIRST OBSERVED RESULT ==="
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
    "successor_schema_present:",
    successor_schema_present,
)
print(
    "cryptographic_agent_binding_established:",
    cryptographic_agent_binding_established,
)
print(
    "agent_a_bound_presented_by_a_commits:",
    positive_a_committed,
)
print(
    "agent_b_bound_presented_by_b_commits:",
    positive_b_committed,
)
print(
    "agent_a_bound_presented_by_b_commits:",
    relay_committed,
)
print(
    "relay_refused:",
    relay_refused,
)
print(
    "relay_refusal_agent_specific:",
    relay_agent_specific_refusal,
)
print(
    "witness_distinguishes_bound_and_presenting_agent:",
    witness_distinguishes_bound_and_presenting_agent,
)
print(
    "witness_chain_valid:",
    chain_valid,
)
print(
    "agent_presenter_binding_control_established:",
    agent_presenter_binding_control_established,
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