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
from core.execution_firewall_v06 import ExecutionFirewallV06
from core.permit_v02 import (
    ExecutionPermitV02,
    PermitIssuerV02,
    PermitVerifierV02,
)
from tools.broker_v06 import ToolBrokerV06, ToolRequestV06
from tools.messaging_demo_v06 import MessagingDemoToolV06
from witness.ledger import WitnessLedger


TEST_ID = "P4-F01"

BASELINE_COMMIT = (
    "ea1472c5a07cf01d8f20db5fd828a2df67ec0769"
)

EXPECTED_DEFINITION_HASH = (
    "2FEDED4DA6245D265D134877E573D80E1E2C6F331109B601A9059981E206808D"
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
    "core/execution_firewall_v06.py":
        "5191C0AAE4B9A538C503B28210ACA7AE9D28330DA3898AEFF798A3E8A7A97E2D",
    "core/permit_v02.py":
        "1BE9CED135D1C3E0498728B5E9AE0853E46E1925EA90EFF70A573E0F516C70A5",
    "tools/broker_v06.py":
        "F722E4554D6FF300E7036BD1E1C73FD09DA47F2E1053DAA63F1C622FC443F6A6",
    "tools/messaging_demo_v06.py":
        "C976315CB420599ACEC8F2D8E5ED0B4FE4FBB9B1B07CBC8CBBA3CBB3E79A67DE",
    "witness/ledger.py":
        "C940D48351E8F4A06F2008CE720A2187433556E18C49D6378A2FA27E6DCE40E5",
}

EVIDENCE_DIR = ROOT / "evidence" / "phase-iv" / "p4-f01"

DEFINITION_PATH = (
    EVIDENCE_DIR / "P4-F01-TEST-DEFINITION-001.json"
)

RESULT_PATH = (
    EVIDENCE_DIR / "P4-F01-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR / "P4-F01-FIRST-OBSERVED-FREEZE-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR / "P4-F01-WITNESS-001.jsonl"
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
    RESULT_PATH.with_name(RESULT_PATH.name + ".sha256"),
    FREEZE_PATH.with_name(FREEZE_PATH.name + ".sha256"),
    WITNESS_PATH.with_name(WITNESS_PATH.name + ".sha256"),
):
    if path.exists():
        raise SystemExit(
            "P4-F01 FIRST-OBSERVED ARTIFACT EXISTS - DO NOT RERUN."
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
    actual = sha256(ROOT / relative)

    source_identity[relative] = {
        "expected_sha256": expected,
        "actual_sha256": actual,
        "preserved": actual == expected,
    }

    if actual != expected:
        source_identity_preserved = False


# ============================================================
# NATIVE SCHEMA OBSERVATION
# ============================================================

tool_request_fields = tuple(
    field.name
    for field in dataclasses.fields(ToolRequestV06)
)

permit_fields = tuple(
    field.name
    for field in dataclasses.fields(ExecutionPermitV02)
)

agent_identity_field_names = {
    "agent_id",
    "requester_id",
    "caller_id",
    "presenter_id",
    "originating_agent_id",
    "executing_agent_id",
}

request_agent_identity_field_present = any(
    name in agent_identity_field_names
    for name in tool_request_fields
)

permit_agent_identity_field_present = any(
    name in agent_identity_field_names
    for name in permit_fields
)

witness_append_parameters = tuple(
    inspect.signature(
        WitnessLedger.append
    ).parameters.keys()
)

witness_agent_identity_field_present = any(
    name in agent_identity_field_names
    for name in witness_append_parameters
)

native_agent_identity_field_present = (
    request_agent_identity_field_present
    or permit_agent_identity_field_present
    or witness_agent_identity_field_present
)


# ============================================================
# LEGITIMATE HUMAN AUTHORITY
# ============================================================

active_authority = AuthorityState.create(
    actor_id=HUMAN_ACTOR,
    authority_source="HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)


# ============================================================
# TIMELINE / WITNESS
# ============================================================

timeline = []


class TimelineLedger(WitnessLedger):

    def __init__(self, path, timeline_ref):
        self._timeline_ref = timeline_ref
        super().__init__(path)

    def append(self, *args, **kwargs):
        record = super().append(
            *args,
            **kwargs,
        )

        event_type = kwargs.get(
            "event_type"
        )

        if event_type:
            self._timeline_ref.append(
                "WITNESS:" + str(event_type)
            )

        return record


ledger = TimelineLedger(
    WITNESS_PATH,
    timeline,
)


# ============================================================
# NORMAL V06 STACK
# ============================================================

permit_signing_key = (
    b"P4-F01-PERMIT-SIGNING-KEY-0000000001"
)

resolution_signing_key = (
    b"P4-F01-RESOLUTION-SIGNING-KEY-000001"
)

resolver_id = (
    "P4-F01-AUTHORIZED-RESOLVER-001"
)

permit_issuer = PermitIssuerV02(
    signing_key=permit_signing_key
)

permit_verifier = PermitVerifierV02(
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

resolver_state = {
    "calls": 0,
    "statuses": [],
}


def authority_resolver():
    resolver_state["calls"] += 1

    resolution = AuthorityResolution.established(
        active_authority,
        reason="P4-F01-ESTABLISHED-AUTHORITY",
    )

    resolver_state["statuses"].append(
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

firewall = ExecutionFirewallV06(
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

broker = ToolBrokerV06(
    firewall=firewall,
    messaging_tool=messaging_tool,
)


# ============================================================
# CASE RUNNER
#
# originating_agent_id / presenting_agent_id are harness-level
# facts only. They are intentionally NOT injected into the V06
# request unless the baseline natively provides such a field.
# ============================================================

def run_case(
    *,
    case_id: str,
    originating_agent_id: str,
    presenting_agent_id: str,
):

    arguments = {
        "content": case_id
    }

    intent_hash = (
        case_id + "-INTENT"
    )

    permit = permit_issuer.issue(
        authority=active_authority,
        intent_hash=intent_hash,
        permission="SEND",
        policy_version="ERA-POLICY-001-v0.2.0",
        target=case_id + "-RECIPIENT",
        tool="MESSAGING_DEMO",
        consequence_class="C4",
        arguments=arguments,
    )

    request = ToolRequestV06(
        permit=permit,
        current_authority=active_authority,
        authority_resolver=authority_resolver,
        intent_hash=intent_hash,
        permission="SEND",
        policy_version="ERA-POLICY-001-v0.2.0",
        target=case_id + "-RECIPIENT",
        tool_name="MESSAGING_DEMO",
        consequence_class="C4",
        arguments=arguments,
    )

    calls_before = resolver_state["calls"]
    status_index = len(
        resolver_state["statuses"]
    )

    outbox_before = (
        broker.outbox_size()
    )

    timeline.append(
        "HARNESS:ORIGIN:"
        + originating_agent_id
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
            "type": type(exc).__name__,
            "message": str(exc),
        }

    outbox_after = (
        broker.outbox_size()
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
        "case_id": case_id,
        "originating_agent_id":
            originating_agent_id,
        "presenting_agent_id":
            presenting_agent_id,
        "same_agent":
            originating_agent_id
            == presenting_agent_id,
        "permit_id":
            permit.permit_id,
        "human_actor_id":
            active_authority.actor_id,
        "human_authority_state_hash":
            active_authority.state_hash(),
        "resolver_calls":
            resolver_state["calls"]
            - calls_before,
        "resolver_statuses":
            list(
                resolver_state["statuses"][
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
    }


# ============================================================
# EXECUTION
#
# Fresh permit per case avoids PERMIT_ALREADY_CONSUMED
# contaminating the agent-presenter question.
# ============================================================

preconditions_preserved = (
    definition_identity_preserved
    and source_identity_preserved
)

positive_control = None
cross_agent_relay_case = None

if preconditions_preserved:

    positive_control = run_case(
        case_id="P4-F01-POSITIVE-A",
        originating_agent_id=AGENT_A,
        presenting_agent_id=AGENT_A,
    )

    cross_agent_relay_case = run_case(
        case_id="P4-F01-CROSS-AGENT-RELAY",
        originating_agent_id=AGENT_A,
        presenting_agent_id=AGENT_B,
    )


positive_control_passed = (
    positive_control is not None
    and positive_control["exception"]
        is None
    and positive_control[
        "consequence_committed"
    ] is True
)

cross_agent_relay_committed = (
    cross_agent_relay_case is not None
    and cross_agent_relay_case[
        "exception"
    ] is None
    and cross_agent_relay_case[
        "consequence_committed"
    ] is True
)

cross_agent_relay_refused = (
    cross_agent_relay_case is not None
    and cross_agent_relay_case[
        "consequence_committed"
    ] is False
)

relay_text = ""

if cross_agent_relay_case is not None:
    relay_text = " ".join(
        [
            str(
                cross_agent_relay_case.get(
                    "status",
                    "",
                )
            ),
            " ".join(
                str(item)
                for item
                in cross_agent_relay_case.get(
                    "reasons",
                    (),
                )
            ),
            str(
                cross_agent_relay_case.get(
                    "exception",
                    "",
                )
            ),
        ]
    ).upper()

agent_specific_refusal_observed = (
    cross_agent_relay_refused
    and any(
        token in relay_text
        for token in (
            "AGENT",
            "REQUESTER",
            "CALLER",
            "PRESENTER",
        )
    )
)


# ============================================================
# NATIVE WITNESS DISTINGUISHABILITY
# ============================================================

records = ledger.records()


def contains_value(value, target: str) -> bool:

    if isinstance(value, dict):
        return any(
            contains_value(
                item,
                target,
            )
            for item in value.values()
        )

    if isinstance(value, (list, tuple)):
        return any(
            contains_value(
                item,
                target,
            )
            for item in value
        )

    return str(value) == target


witness_contains_agent_a = any(
    contains_value(record, AGENT_A)
    for record in records
)

witness_contains_agent_b = any(
    contains_value(record, AGENT_B)
    for record in records
)

witness_distinguishes_upstream_agents = (
    witness_contains_agent_a
    or witness_contains_agent_b
)

chain_valid, chain_errors = (
    ledger.verify_chain()
)


# ============================================================
# CLASSIFICATION
# ============================================================

if not preconditions_preserved:

    classification = (
        "P4-F01_PRECONDITION_IDENTITY_FAILURE"
    )

elif not positive_control_passed:

    classification = (
        "P4-F01_POSITIVE_CONTROL_FAILED"
    )

elif (
    cross_agent_relay_committed
    and not native_agent_identity_field_present
    and not witness_distinguishes_upstream_agents
):

    classification = (
        "CROSS_AGENT_EXECUTION_MATERIAL_ACCEPTED__"
        "UPSTREAM_AGENT_PRESENTER_STANDING_NOT_NATIVELY_BOUND"
    )

elif (
    cross_agent_relay_refused
    and agent_specific_refusal_observed
):

    classification = (
        "CROSS_AGENT_RELAY_REFUSED__"
        "AGENT_PRESENTER_STANDING_OBSERVED"
    )

elif cross_agent_relay_refused:

    classification = (
        "CROSS_AGENT_RELAY_REFUSED_BY_OTHER_CONTROL__"
        "AGENT_PRESENTER_STANDING_NOT_ESTABLISHED"
    )

else:

    classification = (
        "P4-F01_UNEXPECTED_RESULT"
    )


agent_presenter_control_established = (
    positive_control_passed
    and cross_agent_relay_refused
    and agent_specific_refusal_observed
    and native_agent_identity_field_present
)


# ============================================================
# RESULT / FREEZE
# ============================================================

result_payload = {
    "test_id": TEST_ID,
    "classification": classification,
    "repository_baseline_commit":
        BASELINE_COMMIT,
    "definition_identity_preserved":
        definition_identity_preserved,
    "source_identity":
        source_identity,
    "source_identity_preserved":
        source_identity_preserved,
    "native_schema_observation": {
        "tool_request_fields":
            tool_request_fields,
        "permit_fields":
            permit_fields,
        "witness_append_parameters":
            witness_append_parameters,
        "request_agent_identity_field_present":
            request_agent_identity_field_present,
        "permit_agent_identity_field_present":
            permit_agent_identity_field_present,
        "witness_agent_identity_field_present":
            witness_agent_identity_field_present,
        "native_agent_identity_field_present":
            native_agent_identity_field_present,
    },
    "positive_control":
        positive_control,
    "cross_agent_relay_case":
        cross_agent_relay_case,
    "positive_control_passed":
        positive_control_passed,
    "cross_agent_relay_committed":
        cross_agent_relay_committed,
    "cross_agent_relay_refused":
        cross_agent_relay_refused,
    "agent_specific_refusal_observed":
        agent_specific_refusal_observed,
    "agent_presenter_control_established":
        agent_presenter_control_established,
    "witness": {
        "record_count":
            len(records),
        "contains_agent_a":
            witness_contains_agent_a,
        "contains_agent_b":
            witness_contains_agent_b,
        "distinguishes_upstream_agents":
            witness_distinguishes_upstream_agents,
        "chain_valid":
            chain_valid,
        "chain_errors":
            chain_errors,
    },
    "timeline":
        timeline,
    "bounded_claim": (
        "This deterministic test examines only whether the frozen "
        "ExecutionFirewallV06 / ToolBrokerV06 path natively binds "
        "consequential standing to a distinct upstream agent or "
        "presenter identity when the underlying human authority and "
        "all existing execution-bound material remain otherwise valid. "
        "The positive and relay cases use fresh permits so durable "
        "permit-consumption replay controls do not confound the "
        "agent-presenter question. Harness-level Agent A / Agent B "
        "labels are observations external to the tested runtime and "
        "do not themselves establish a production identity system. "
        "This test does not establish swarm security, production "
        "exploitability, concurrency safety, external authentication, "
        "network identity, credential isolation, distributed-agent "
        "security, or protection against compromise of authorized "
        "humans, agents, resolvers, signing keys, deployment perimeters, "
        "or tool credentials."
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
    "cross_agent_relay_committed":
        cross_agent_relay_committed,
    "cross_agent_relay_refused":
        cross_agent_relay_refused,
    "agent_specific_refusal_observed":
        agent_specific_refusal_observed,
    "native_agent_identity_field_present":
        native_agent_identity_field_present,
    "witness_distinguishes_upstream_agents":
        witness_distinguishes_upstream_agents,
    "agent_presenter_control_established":
        agent_presenter_control_established,
    "witness_chain_valid":
        chain_valid,
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
    "=== P4-F01 FIRST OBSERVED RESULT ==="
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
    "native_agent_identity_field_present:",
    native_agent_identity_field_present,
)
print(
    "cross_agent_relay_committed:",
    cross_agent_relay_committed,
)
print(
    "cross_agent_relay_refused:",
    cross_agent_relay_refused,
)
print(
    "agent_specific_refusal_observed:",
    agent_specific_refusal_observed,
)
print(
    "witness_distinguishes_upstream_agents:",
    witness_distinguishes_upstream_agents,
)
print(
    "agent_presenter_control_established:",
    agent_presenter_control_established,
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
