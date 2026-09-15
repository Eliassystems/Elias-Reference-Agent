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


TEST_ID = "P3-RG01"

EVIDENCE_DIR = Path(
    "evidence/phase-iii/p3-rg01"
)

DEFINITION_PATH = (
    EVIDENCE_DIR
    / "P3-RG01-TEST-DEFINITION-001.json"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P3-RG01-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR
    / "P3-RG01-FIRST-OBSERVED-FREEZE-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P3-RG01-WITNESS-001.jsonl"
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
        "P3-RG01 FIRST-OBSERVED ARTIFACT ALREADY EXISTS."
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


authority = AuthorityState.create(
    actor_id="P3-RG01-HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)


resolution = AuthorityResolution.established(
    authority=authority,
    reason="P3-RG01_CURRENT_AUTHORITY_ESTABLISHED",
)


resolver_state = {
    "calls": 0,
}


def established_authority_resolver():
    resolver_state["calls"] += 1
    return resolution


arguments = {
    "content":
        "P3-RG01 NORMAL GOVERNED MESSAGE"
}


signing_key = (
    b"P3-RG01-ESTABLISHED-AUTHORITY-KEY-000001"
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
    "P3-RG01-ESTABLISHED-AUTHORITY-INTENT"
)


permit = issuer.issue(
    authority=authority,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="P3-RG01-RECIPIENT",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=arguments,
)


request = ToolRequestV05(
    permit=permit,

    current_authority=authority,

    authority_resolver=
        established_authority_resolver,

    intent_hash=intent_hash,

    permission="SEND",

    policy_version=
        "ERA-POLICY-001-v0.2.0",

    target="P3-RG01-RECIPIENT",

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


native_resolution_object = isinstance(
    resolution,
    AuthorityResolution,
)


established_status = (
    resolution.status
    == AuthorityResolutionStatus.ESTABLISHED
)


established_authority_preserved = (
    resolution.authority is not None
    and
    resolution.authority.state_hash()
    == authority.state_hash()
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


pre_execution_present = (
    event_types.count(
        "PRE_EXECUTION_AUTHORIZED"
    )
    == 1
)


boundary_revalidated_present = (
    event_types.count(
        "CONSEQUENCE_BOUNDARY_REVALIDATED"
    )
    == 1
)


execution_completed_present = (
    event_types.count(
        "EXECUTION_COMPLETED"
    )
    == 1
)


no_conflict_event = (
    "AUTHORITY_RESOLUTION_CONFLICT"
    not in event_types
)


no_unavailable_event = (
    "AUTHORITY_RESOLUTION_UNAVAILABLE"
    not in event_types
)


no_indeterminate_event = (
    "AUTHORITY_RESOLUTION_INDETERMINATE"
    not in event_types
)


permit_consumed = (
    ledger.has_consumed_permit(
        permit.permit_id
    )
)


normal_execution_established = (
    not exception_captured
    and
    native_resolution_object
    and
    established_status
    and
    established_authority_preserved
    and
    resolver_called_once
    and
    result_returned
    and
    executed is True
    and
    status == "EXECUTED"
    and
    reasons == []
    and
    outbox_before == 0
    and
    outbox_after == 1
    and
    pre_execution_present
    and
    boundary_revalidated_present
    and
    execution_completed_present
    and
    no_conflict_event
    and
    no_unavailable_event
    and
    no_indeterminate_event
    and
    permit_consumed
    and
    chain_valid
)


if normal_execution_established:
    classification = (
        "V05_ESTABLISHED_AUTHORITY_"
        "NORMAL_EXECUTION_ESTABLISHED"
    )

elif executed is True:
    classification = (
        "EXECUTION_OCCURRED__"
        "REGRESSION_CONTROL_NOT_FULLY_ESTABLISHED"
    )

else:
    classification = (
        "NORMAL_EXECUTION_NOT_ESTABLISHED__"
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

        "status_is_established":
            established_status,

        "authority_preserved":
            established_authority_preserved,
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

        "outbox_before":
            outbox_before,

        "outbox_after":
            outbox_after,

        "permit_consumed":
            permit_consumed,
    },

    "witness_observation": {
        "event_types":
            event_types,

        "pre_execution_present":
            pre_execution_present,

        "boundary_revalidated_present":
            boundary_revalidated_present,

        "execution_completed_present":
            execution_completed_present,

        "no_conflict_event":
            no_conflict_event,

        "no_unavailable_event":
            no_unavailable_event,

        "no_indeterminate_event":
            no_indeterminate_event,

        "chain_valid":
            chain_valid,

        "chain_errors":
            chain_errors,
    },

    "normal_execution_established":
        normal_execution_established,

    "bounded_interpretation": (
        "This deterministic local regression test establishes "
        "only whether V05 preserves normal permitted execution "
        "when the authority resolver explicitly returns an "
        "ESTABLISHED AuthorityResolution carrying the current "
        "valid AuthorityState."
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
        "FIRST_OBSERVED_REGRESSION_RESULT_FREEZE",

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
print("=== P3-RG01 FIRST OBSERVED RESULT ===")
print("classification:", classification)
print(
    "native_resolution_object:",
    native_resolution_object,
)
print(
    "established_status:",
    established_status,
)
print(
    "established_authority_preserved:",
    established_authority_preserved,
)
print(
    "resolver_called_once:",
    resolver_called_once,
)
print("executed:", executed)
print("status:", status)
print("reasons:", reasons)
print("outbox_before:", outbox_before)
print("outbox_after:", outbox_after)
print(
    "boundary_revalidated_present:",
    boundary_revalidated_present,
)
print(
    "execution_completed_present:",
    execution_completed_present,
)
print(
    "permit_consumed:",
    permit_consumed,
)
print(
    "witness_chain_valid:",
    chain_valid,
)
print(
    "normal_execution_established:",
    normal_execution_established,
)
print()
print("RESULT:", RESULT_PATH)
print("FREEZE:", FREEZE_PATH)
print("WITNESS:", WITNESS_PATH)
