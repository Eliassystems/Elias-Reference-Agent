from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from core.authority import AuthorityState
from core.authority_resolution import (
    AuthorityResolution,
    AuthorityResolutionStatus,
)
from core.execution_firewall_v05 import ExecutionFirewallV05
from core.permit_v02 import PermitIssuerV02, PermitVerifierV02
from tools.broker_v05 import ToolBrokerV05, ToolRequestV05
from tools.messaging_demo import MessagingDemoTool
from witness.ledger import WitnessLedger


TEST_ID = "P3-F03"

EVIDENCE_DIR = Path(
    "evidence/phase-iii/p3-f03"
)

DEFINITION_PATH = (
    EVIDENCE_DIR
    / "P3-F03-TEST-DEFINITION-001.json"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P3-F03-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR
    / "P3-F03-FIRST-OBSERVED-FREEZE-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P3-F03-WITNESS-001.jsonl"
)


def utc_now():
    return datetime.now(
        timezone.utc
    ).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(65536),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest().upper()


# Secondary execution guard.
if (
    RESULT_PATH.exists()
    or FREEZE_PATH.exists()
    or WITNESS_PATH.exists()
):
    print(
        "P3-F03 FIRST-OBSERVED ARTIFACT ALREADY EXISTS."
    )
    print("REFUSING RERUN.")
    sys.exit(3)


# ------------------------------------------------------------
# AUTHENTIC OBSERVATION EXISTS
# ------------------------------------------------------------

authority_observation = AuthorityState.create(
    actor_id="P3-F03-HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)


# ------------------------------------------------------------
# INFORMATION EXISTS, BUT PRESENT STANDING IS UNRESOLVED
# ------------------------------------------------------------

resolution = AuthorityResolution.indeterminate(
    observations=(
        authority_observation,
    ),
    reason=(
        "AUTHORITY_OBSERVATION_PRESENT_BUT_"
        "CURRENTNESS_NOT_ESTABLISHED"
    ),
)


resolver_state = {
    "calls": 0,
}


def indeterminate_authority_resolver():
    resolver_state["calls"] += 1
    return resolution


arguments = {
    "content":
        "P3-F03 GOVERNED MESSAGE"
}


signing_key = (
    b"P3-F03-AUTHORITY-INDETERMINATE-KEY-000001"
)


issuer = PermitIssuerV02(
    signing_key=signing_key
)


verifier = PermitVerifierV02(
    signing_key=signing_key
)


ledger = WitnessLedger(
    WITNESS_PATH
)


firewall = ExecutionFirewallV05(
    verifier=verifier,
    ledger=ledger,
    constitution_path=(
        ROOT
        / "constitution"
        / "constitution.yaml"
    ),
)


messaging_tool = MessagingDemoTool()


broker = ToolBrokerV05(
    firewall=firewall,
    messaging_tool=messaging_tool,
)


intent_hash = (
    "P3-F03-AUTHORITY-INDETERMINATE-INTENT"
)


permit = issuer.issue(
    authority=authority_observation,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="P3-F03-RECIPIENT",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=arguments,
)


request = ToolRequestV05(
    permit=permit,

    current_authority=
        authority_observation,

    authority_resolver=
        indeterminate_authority_resolver,

    intent_hash=intent_hash,

    permission="SEND",

    policy_version=
        "ERA-POLICY-001-v0.2.0",

    target="P3-F03-RECIPIENT",

    tool_name="MESSAGING_DEMO",

    consequence_class="C4",

    arguments=arguments,
)


outbox_before = broker.outbox_size()


exception_captured = False
exception_type = ""
exception_message = ""
result = None


try:
    result = broker.execute(
        request
    )

except Exception as exc:
    exception_captured = True
    exception_type = type(exc).__name__
    exception_message = str(exc)


outbox_after = broker.outbox_size()


records = ledger.records()

chain_valid, chain_errors = (
    ledger.verify_chain()
)


event_types = [
    record.get("event_type")
    for record in records
]


indeterminate_records = [
    record
    for record in records
    if record.get("event_type")
    == "AUTHORITY_RESOLUTION_INDETERMINATE"
]


indeterminate_record = (
    indeterminate_records[0]
    if len(indeterminate_records) == 1
    else {}
)


indeterminate_details = (
    indeterminate_record.get(
        "details",
        {},
    )
    if indeterminate_record
    else {}
)


expected_observation_hash = (
    authority_observation.state_hash()
)


recorded_observation_hashes = (
    indeterminate_details.get(
        "observation_hashes",
        [],
    )
)


native_resolution_object = isinstance(
    resolution,
    AuthorityResolution,
)


native_indeterminate_status = (
    resolution.status
    == AuthorityResolutionStatus.INDETERMINATE
)


no_executable_authority = (
    resolution.authority is None
)


one_observation_preserved = (
    len(resolution.observations) == 1
    and
    resolution.observations[0].state_hash()
    == expected_observation_hash
)


resolver_called_once = (
    resolver_state["calls"] == 1
)


result_returned = (
    result is not None
)


executed = (
    result.executed
    if result_returned
    else None
)


status = (
    result.status
    if result_returned
    else None
)


reasons = (
    list(result.reasons)
    if result_returned
    else []
)


explicit_indeterminate_reason = (
    reasons
    == [
        "CONSEQUENCE_AUTHORITY_INDETERMINATE"
    ]
)


indeterminate_event_present_once = (
    len(indeterminate_records) == 1
)


observation_hash_preserved = (
    recorded_observation_hashes
    == [
        expected_observation_hash
    ]
)


indeterminate_record_truthful = (
    indeterminate_event_present_once
    and
    indeterminate_record.get(
        "governance_verdict"
    )
    == "REFUSE"
    and
    indeterminate_record.get(
        "verdict_reason"
    )
    == "CONSEQUENCE_AUTHORITY_INDETERMINATE"
    and
    indeterminate_record.get(
        "execution_result"
    )
    == "NOT_EXECUTED"
    and
    indeterminate_details.get(
        "resolution_status"
    )
    == "INDETERMINATE"
    and
    indeterminate_details.get(
        "resolution_reason"
    )
    == resolution.reason
    and
    observation_hash_preserved
)


no_conflict_event = (
    "AUTHORITY_RESOLUTION_CONFLICT"
    not in event_types
)


no_unavailable_event = (
    "AUTHORITY_RESOLUTION_UNAVAILABLE"
    not in event_types
)


consequence_contained = (
    result_returned
    and
    executed is False
    and
    status
    == "REFUSED_BEFORE_CONSEQUENCE"
    and
    outbox_before == 0
    and
    outbox_after == 0
)


native_indeterminate_control_established = (
    not exception_captured
    and
    native_resolution_object
    and
    native_indeterminate_status
    and
    no_executable_authority
    and
    one_observation_preserved
    and
    resolver_called_once
    and
    explicit_indeterminate_reason
    and
    indeterminate_event_present_once
    and
    observation_hash_preserved
    and
    indeterminate_record_truthful
    and
    no_conflict_event
    and
    no_unavailable_event
    and
    consequence_contained
    and
    chain_valid
)


if native_indeterminate_control_established:
    classification = (
        "NATIVE_AUTHORITY_INDETERMINATE_"
        "REPRESENTATION_AND_CONTAINMENT_ESTABLISHED"
    )

elif consequence_contained:
    classification = (
        "CONSEQUENCE_CONTAINED__"
        "INDETERMINATE_CONTROL_NOT_FULLY_ESTABLISHED"
    )

else:
    classification = (
        "CONSEQUENCE_CONTAINMENT_NOT_ESTABLISHED__"
        "INVESTIGATION_REQUIRED"
    )


result_document = {
    "test_id": TEST_ID,

    "observed_at_utc":
        utc_now(),

    "classification":
        classification,

    "authority_observation": {
        "canonical_payload":
            authority_observation.canonical_payload(),

        "state_hash":
            expected_observation_hash,
    },

    "native_resolution": {
        "canonical_payload":
            resolution.canonical_payload(),

        "state_hash":
            resolution.state_hash(),

        "is_authority_resolution":
            native_resolution_object,

        "status_is_indeterminate":
            native_indeterminate_status,

        "executable_authority_absent":
            no_executable_authority,

        "one_observation_preserved":
            one_observation_preserved,
    },

    "execution_observation": {
        "resolver_calls":
            resolver_state["calls"],

        "resolver_called_once":
            resolver_called_once,

        "exception_captured":
            exception_captured,

        "exception_type":
            exception_type,

        "exception_message":
            exception_message,

        "result_returned":
            result_returned,

        "executed":
            executed,

        "status":
            status,

        "reasons":
            reasons,

        "explicit_indeterminate_reason":
            explicit_indeterminate_reason,

        "outbox_before":
            outbox_before,

        "outbox_after":
            outbox_after,

        "consequence_contained":
            consequence_contained,
    },

    "witness_observation": {
        "event_types":
            event_types,

        "indeterminate_event_present_once":
            indeterminate_event_present_once,

        "expected_observation_hash":
            expected_observation_hash,

        "recorded_observation_hashes":
            recorded_observation_hashes,

        "observation_hash_preserved":
            observation_hash_preserved,

        "indeterminate_record_truthful":
            indeterminate_record_truthful,

        "no_conflict_event":
            no_conflict_event,

        "no_unavailable_event":
            no_unavailable_event,

        "chain_valid":
            chain_valid,

        "chain_errors":
            chain_errors,
    },

    "native_indeterminate_control_established":
        native_indeterminate_control_established,

    "bounded_interpretation": (
        "This deterministic local test establishes only whether "
        "V05 natively represents an explicitly supplied "
        "INDETERMINATE authority-resolution state in which "
        "authority information exists but present standing is "
        "not established, preserves the supplied observation, "
        "records that specific governance condition, and "
        "withholds consequence."
    ),
}


with RESULT_PATH.open(
    "w",
    encoding="utf-8",
) as handle:

    json.dump(
        result_document,
        handle,
        indent=2,
        sort_keys=True,
    )

    handle.write("\n")


freeze_document = {
    "test_id": TEST_ID,

    "freeze_type":
        "FIRST_OBSERVED_RESULT_FREEZE",

    "frozen_at_utc":
        utc_now(),

    "classification":
        classification,

    "artifact_hashes_sha256": {
        "test_definition":
            sha256_file(
                DEFINITION_PATH
            ),

        "test_script":
            sha256_file(
                Path(__file__)
            ),

        "result":
            sha256_file(
                RESULT_PATH
            ),

        "witness":
            sha256_file(
                WITNESS_PATH
            ),

        "authority_resolution":
            sha256_file(
                ROOT
                / "core"
                / "authority_resolution.py"
            ),

        "execution_firewall_v05":
            sha256_file(
                ROOT
                / "core"
                / "execution_firewall_v05.py"
            ),

        "broker_v05":
            sha256_file(
                ROOT
                / "tools"
                / "broker_v05.py"
            ),
    },

    "no_retrospective_repair":
        True,
}


with FREEZE_PATH.open(
    "w",
    encoding="utf-8",
) as handle:

    json.dump(
        freeze_document,
        handle,
        indent=2,
        sort_keys=True,
    )

    handle.write("\n")


for path in (
    DEFINITION_PATH,
    Path(__file__),
    RESULT_PATH,
    WITNESS_PATH,
    FREEZE_PATH,
):
    sidecar = Path(
        str(path) + ".sha256"
    )

    sidecar.write_text(
        sha256_file(path)
        + "  "
        + path.name
        + "\n",
        encoding="utf-8",
    )


print()
print("=== P3-F03 FIRST OBSERVED RESULT ===")
print(
    "classification:",
    classification,
)
print(
    "native_resolution_object:",
    native_resolution_object,
)
print(
    "native_indeterminate_status:",
    native_indeterminate_status,
)
print(
    "no_executable_authority:",
    no_executable_authority,
)
print(
    "one_observation_preserved:",
    one_observation_preserved,
)
print(
    "resolver_called_once:",
    resolver_called_once,
)
print(
    "explicit_indeterminate_reason:",
    explicit_indeterminate_reason,
)
print(
    "indeterminate_event_present_once:",
    indeterminate_event_present_once,
)
print(
    "observation_hash_preserved:",
    observation_hash_preserved,
)
print(
    "indeterminate_record_truthful:",
    indeterminate_record_truthful,
)
print(
    "consequence_contained:",
    consequence_contained,
)
print("executed:", executed)
print("status:", status)
print("reasons:", reasons)
print("outbox_before:", outbox_before)
print("outbox_after:", outbox_after)
print(
    "witness_chain_valid:",
    chain_valid,
)
print(
    "native_indeterminate_control_established:",
    native_indeterminate_control_established,
)
print()
print("RESULT:", RESULT_PATH)
print("FREEZE:", FREEZE_PATH)
print("WITNESS:", WITNESS_PATH)
