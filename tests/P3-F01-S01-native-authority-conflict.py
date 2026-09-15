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


TEST_ID = "P3-F01-S01"

EVIDENCE_DIR = Path(
    "evidence/phase-iii/p3-f01-successor"
)

DEFINITION_PATH = (
    EVIDENCE_DIR
    / "P3-F01-S01-TEST-DEFINITION-001.json"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P3-F01-S01-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR
    / "P3-F01-S01-FIRST-OBSERVED-FREEZE-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P3-F01-S01-WITNESS-001.jsonl"
)


EVIDENCE_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


if (
    RESULT_PATH.exists()
    or FREEZE_PATH.exists()
    or WITNESS_PATH.exists()
):
    print(
        "P3-F01-S01 FIRST-OBSERVED ARTIFACT ALREADY EXISTS."
    )
    print("REFUSING RERUN.")
    sys.exit(3)


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


# ------------------------------------------------------------
# TWO AUTHENTIC STATES FROM THE SAME AUTHORITY LINEAGE
# ------------------------------------------------------------

authority_a = AuthorityState.create(
    actor_id="P3-F01-S01-HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)

authority_b = authority_a.revoke_all(
    reason="P3-F01-S01_REPLICA_B_REVOCATION"
)


# ------------------------------------------------------------
# V05 NATIVE CONFLICT REPRESENTATION
# ------------------------------------------------------------

resolution = AuthorityResolution.conflict(
    observations=(
        authority_a,
        authority_b,
    ),
    reason=(
        "AUTHENTIC_AUTHORITY_OBSERVATIONS_"
        "DISAGREE_CURRENT_STANDING_UNRESOLVED"
    ),
)


resolver_state = {
    "calls": 0,
}


def conflict_resolver():
    resolver_state["calls"] += 1
    return resolution


arguments = {
    "content":
        "P3-F01-S01 GOVERNED MESSAGE"
}


signing_key = (
    b"P3-F01-S01-NATIVE-CONFLICT-KEY-000001"
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
    "P3-F01-S01-NATIVE-CONFLICT-INTENT"
)


# Permit is genuinely issued against the earlier ACTIVE state.
permit = issuer.issue(
    authority=authority_a,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="P3-F01-S01-RECIPIENT",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=arguments,
)


request = ToolRequestV05(
    permit=permit,

    current_authority=authority_a,

    authority_resolver=
        conflict_resolver,

    intent_hash=intent_hash,

    permission="SEND",

    policy_version=
        "ERA-POLICY-001-v0.2.0",

    target="P3-F01-S01-RECIPIENT",

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


conflict_records = [
    record
    for record in records
    if record.get("event_type")
    == "AUTHORITY_RESOLUTION_CONFLICT"
]


conflict_record = (
    conflict_records[0]
    if len(conflict_records) == 1
    else {}
)


conflict_details = (
    conflict_record.get(
        "details",
        {},
    )
    if conflict_record
    else {}
)


observation_hashes_expected = [
    authority_a.state_hash(),
    authority_b.state_hash(),
]


observation_hashes_recorded = (
    conflict_details.get(
        "observation_hashes",
        [],
    )
)


native_resolution_object = isinstance(
    resolution,
    AuthorityResolution,
)


native_conflict_status = (
    resolution.status
    == AuthorityResolutionStatus.CONFLICT
)


no_executable_authority = (
    resolution.authority is None
)


two_observations_preserved_in_resolution = (
    len(resolution.observations) == 2
    and
    resolution.observations[0].state_hash()
    == authority_a.state_hash()
    and
    resolution.observations[1].state_hash()
    == authority_b.state_hash()
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


explicit_conflict_reason = (
    reasons
    == [
        "CONSEQUENCE_AUTHORITY_CONFLICT"
    ]
)


conflict_event_present_once = (
    len(conflict_records) == 1
)


conflict_record_truthful = (
    conflict_event_present_once
    and
    conflict_record.get(
        "governance_verdict"
    )
    == "REFUSE"
    and
    conflict_record.get(
        "verdict_reason"
    )
    == "CONSEQUENCE_AUTHORITY_CONFLICT"
    and
    conflict_record.get(
        "execution_result"
    )
    == "NOT_EXECUTED"
    and
    conflict_details.get(
        "resolution_status"
    )
    == "CONFLICT"
    and
    conflict_details.get(
        "resolution_reason"
    )
    == resolution.reason
)


both_observation_hashes_preserved = (
    observation_hashes_recorded
    == observation_hashes_expected
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


native_conflict_control_established = (
    not exception_captured
    and
    native_resolution_object
    and
    native_conflict_status
    and
    no_executable_authority
    and
    two_observations_preserved_in_resolution
    and
    resolver_called_once
    and
    explicit_conflict_reason
    and
    conflict_event_present_once
    and
    conflict_record_truthful
    and
    both_observation_hashes_preserved
    and
    consequence_contained
    and
    chain_valid
)


if native_conflict_control_established:
    classification = (
        "NATIVE_AUTHORITY_CONFLICT_"
        "REPRESENTATION_AND_CONTAINMENT_ESTABLISHED"
    )

elif consequence_contained:
    classification = (
        "CONSEQUENCE_CONTAINED__"
        "NATIVE_CONFLICT_CONTROL_NOT_FULLY_ESTABLISHED"
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

    "antecedent_test":
        "P3-F01",

    "authority_observation_a": {
        "canonical_payload":
            authority_a.canonical_payload(),

        "state_hash":
            authority_a.state_hash(),
    },

    "authority_observation_b": {
        "canonical_payload":
            authority_b.canonical_payload(),

        "state_hash":
            authority_b.state_hash(),
    },

    "native_resolution": {
        "canonical_payload":
            resolution.canonical_payload(),

        "state_hash":
            resolution.state_hash(),

        "is_authority_resolution":
            native_resolution_object,

        "status_is_conflict":
            native_conflict_status,

        "executable_authority_absent":
            no_executable_authority,

        "two_observations_preserved":
            two_observations_preserved_in_resolution,
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

        "explicit_conflict_reason":
            explicit_conflict_reason,

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

        "conflict_event_present_once":
            conflict_event_present_once,

        "conflict_record_truthful":
            conflict_record_truthful,

        "expected_observation_hashes":
            observation_hashes_expected,

        "recorded_observation_hashes":
            observation_hashes_recorded,

        "both_observation_hashes_preserved":
            both_observation_hashes_preserved,

        "chain_valid":
            chain_valid,

        "chain_errors":
            chain_errors,
    },

    "native_conflict_control_established":
        native_conflict_control_established,

    "bounded_interpretation": (
        "This deterministic local successor test establishes "
        "only whether V05 natively represents an explicit "
        "authority conflict, preserves both supplied authentic "
        "authority observations, records the conflict in the "
        "witness chain, and withholds consequence. It does not "
        "establish production distributed consensus, network "
        "freshness, replica authenticity, or external authority "
        "provenance."
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


source_paths = {
    "authority_resolution":
        ROOT / "core" / "authority_resolution.py",

    "execution_firewall_v05":
        ROOT / "core" / "execution_firewall_v05.py",

    "broker_v05":
        ROOT / "tools" / "broker_v05.py",
}


freeze_document = {
    "test_id": TEST_ID,

    "freeze_type":
        "FIRST_OBSERVED_SUCCESSOR_RESULT_FREEZE",

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
                source_paths[
                    "authority_resolution"
                ]
            ),

        "execution_firewall_v05":
            sha256_file(
                source_paths[
                    "execution_firewall_v05"
                ]
            ),

        "broker_v05":
            sha256_file(
                source_paths[
                    "broker_v05"
                ]
            ),
    },

    "antecedent_preserved":
        "P3-F01",

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
print("=== P3-F01-S01 FIRST OBSERVED RESULT ===")
print(
    "classification:",
    classification,
)
print(
    "native_resolution_object:",
    native_resolution_object,
)
print(
    "native_conflict_status:",
    native_conflict_status,
)
print(
    "two_observations_preserved:",
    two_observations_preserved_in_resolution,
)
print(
    "explicit_conflict_reason:",
    explicit_conflict_reason,
)
print(
    "conflict_event_present_once:",
    conflict_event_present_once,
)
print(
    "both_observation_hashes_preserved:",
    both_observation_hashes_preserved,
)
print(
    "consequence_contained:",
    consequence_contained,
)
print(
    "executed:",
    executed,
)
print(
    "status:",
    status,
)
print(
    "reasons:",
    reasons,
)
print(
    "outbox_before:",
    outbox_before,
)
print(
    "outbox_after:",
    outbox_after,
)
print(
    "witness_chain_valid:",
    chain_valid,
)
print(
    "native_conflict_control_established:",
    native_conflict_control_established,
)
print()
print("RESULT:", RESULT_PATH)
print("FREEZE:", FREEZE_PATH)
print("WITNESS:", WITNESS_PATH)
