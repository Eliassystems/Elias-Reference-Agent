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


TEST_ID = "P3-F02"

EVIDENCE_DIR = Path(
    "evidence/phase-iii/p3-f02"
)

DEFINITION_PATH = (
    EVIDENCE_DIR
    / "P3-F02-TEST-DEFINITION-001.json"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P3-F02-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR
    / "P3-F02-FIRST-OBSERVED-FREEZE-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P3-F02-WITNESS-001.jsonl"
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
        "P3-F02 FIRST-OBSERVED ARTIFACT ALREADY EXISTS."
    )
    print("REFUSING RERUN.")
    sys.exit(3)


# ------------------------------------------------------------
# INITIAL VALID STANDING
# ------------------------------------------------------------

authority = AuthorityState.create(
    actor_id="P3-F02-HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)


# ------------------------------------------------------------
# PRESENT-TENSE AUTHORITY CANNOT BE OBTAINED
# ------------------------------------------------------------

resolution = AuthorityResolution.unavailable(
    observations=(),
    reason=(
        "PRESENT_AUTHORITY_INFORMATION_"
        "UNAVAILABLE_AT_CONSEQUENCE_BOUNDARY"
    ),
)


resolver_state = {
    "calls": 0,
}


def unavailable_authority_resolver():
    resolver_state["calls"] += 1
    return resolution


arguments = {
    "content":
        "P3-F02 GOVERNED MESSAGE"
}


signing_key = (
    b"P3-F02-AUTHORITY-UNAVAILABLE-KEY-000001"
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
    "P3-F02-AUTHORITY-UNAVAILABLE-INTENT"
)


permit = issuer.issue(
    authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="P3-F02-RECIPIENT",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=arguments,
)


request = ToolRequestV05(
    permit=permit,

    current_authority=authority,

    authority_resolver=
        unavailable_authority_resolver,

    intent_hash=intent_hash,

    permission="SEND",

    policy_version=
        "ERA-POLICY-001-v0.2.0",

    target="P3-F02-RECIPIENT",

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


unavailable_records = [
    record
    for record in records
    if record.get("event_type")
    == "AUTHORITY_RESOLUTION_UNAVAILABLE"
]


unavailable_record = (
    unavailable_records[0]
    if len(unavailable_records) == 1
    else {}
)


unavailable_details = (
    unavailable_record.get(
        "details",
        {},
    )
    if unavailable_record
    else {}
)


native_resolution_object = isinstance(
    resolution,
    AuthorityResolution,
)


native_unavailable_status = (
    resolution.status
    == AuthorityResolutionStatus.UNAVAILABLE
)


no_executable_authority = (
    resolution.authority is None
)


zero_observations_preserved = (
    resolution.observations == ()
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


explicit_unavailable_reason = (
    reasons
    == [
        "CONSEQUENCE_AUTHORITY_UNAVAILABLE"
    ]
)


unavailable_event_present_once = (
    len(unavailable_records) == 1
)


unavailable_record_truthful = (
    unavailable_event_present_once
    and
    unavailable_record.get(
        "governance_verdict"
    )
    == "REFUSE"
    and
    unavailable_record.get(
        "verdict_reason"
    )
    == "CONSEQUENCE_AUTHORITY_UNAVAILABLE"
    and
    unavailable_record.get(
        "execution_result"
    )
    == "NOT_EXECUTED"
    and
    unavailable_details.get(
        "resolution_status"
    )
    == "UNAVAILABLE"
    and
    unavailable_details.get(
        "resolution_reason"
    )
    == resolution.reason
    and
    unavailable_details.get(
        "observation_hashes"
    )
    == []
)


no_conflict_event = (
    "AUTHORITY_RESOLUTION_CONFLICT"
    not in event_types
)


no_indeterminate_event = (
    "AUTHORITY_RESOLUTION_INDETERMINATE"
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


native_unavailable_control_established = (
    not exception_captured
    and
    native_resolution_object
    and
    native_unavailable_status
    and
    no_executable_authority
    and
    zero_observations_preserved
    and
    resolver_called_once
    and
    explicit_unavailable_reason
    and
    unavailable_event_present_once
    and
    unavailable_record_truthful
    and
    no_conflict_event
    and
    no_indeterminate_event
    and
    consequence_contained
    and
    chain_valid
)


if native_unavailable_control_established:
    classification = (
        "NATIVE_AUTHORITY_UNAVAILABLE_"
        "REPRESENTATION_AND_CONTAINMENT_ESTABLISHED"
    )

elif consequence_contained:
    classification = (
        "CONSEQUENCE_CONTAINED__"
        "UNAVAILABLE_CONTROL_NOT_FULLY_ESTABLISHED"
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

    "native_resolution": {
        "canonical_payload":
            resolution.canonical_payload(),

        "state_hash":
            resolution.state_hash(),

        "is_authority_resolution":
            native_resolution_object,

        "status_is_unavailable":
            native_unavailable_status,

        "executable_authority_absent":
            no_executable_authority,

        "zero_observations_preserved":
            zero_observations_preserved,
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

        "explicit_unavailable_reason":
            explicit_unavailable_reason,

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

        "unavailable_event_present_once":
            unavailable_event_present_once,

        "unavailable_record_truthful":
            unavailable_record_truthful,

        "no_conflict_event":
            no_conflict_event,

        "no_indeterminate_event":
            no_indeterminate_event,

        "chain_valid":
            chain_valid,

        "chain_errors":
            chain_errors,
    },

    "native_unavailable_control_established":
        native_unavailable_control_established,

    "bounded_interpretation": (
        "This deterministic local test establishes only whether "
        "V05 natively represents an explicitly supplied "
        "UNAVAILABLE authority-resolution state, records that "
        "specific governance condition, and withholds consequence. "
        "It does not establish production authority-service "
        "availability, distributed consensus, network freshness, "
        "or external authority provenance."
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
print("=== P3-F02 FIRST OBSERVED RESULT ===")
print(
    "classification:",
    classification,
)
print(
    "native_resolution_object:",
    native_resolution_object,
)
print(
    "native_unavailable_status:",
    native_unavailable_status,
)
print(
    "no_executable_authority:",
    no_executable_authority,
)
print(
    "zero_observations_preserved:",
    zero_observations_preserved,
)
print(
    "resolver_called_once:",
    resolver_called_once,
)
print(
    "explicit_unavailable_reason:",
    explicit_unavailable_reason,
)
print(
    "unavailable_event_present_once:",
    unavailable_event_present_once,
)
print(
    "unavailable_record_truthful:",
    unavailable_record_truthful,
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
    "native_unavailable_control_established:",
    native_unavailable_control_established,
)
print()
print("RESULT:", RESULT_PATH)
print("FREEZE:", FREEZE_PATH)
print("WITNESS:", WITNESS_PATH)
