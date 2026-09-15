from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import sys


ROOT = Path(__file__).resolve().parents[1]

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from core.authority import AuthorityState
from core.execution_firewall_v04 import ExecutionFirewallV04
from core.permit_v02 import PermitIssuerV02, PermitVerifierV02
from tools.broker_v04 import ToolBrokerV04, ToolRequestV04
from tools.messaging_demo import MessagingDemoTool
from witness.ledger import WitnessLedger


TEST_ID = "P3-F01"

EVIDENCE_DIR = Path(
    "evidence/phase-iii/p3-f01"
)

RESULT_PATH = (
    EVIDENCE_DIR
    / "P3-F01-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR
    / "P3-F01-FIRST-OBSERVED-FREEZE-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR
    / "P3-F01-WITNESS-001.jsonl"
)

TEST_DEFINITION_PATH = (
    EVIDENCE_DIR
    / "P3-F01-TEST-DEFINITION-001.json"
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
        "P3-F01 FIRST-OBSERVED ARTIFACT ALREADY EXISTS."
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


@dataclass(frozen=True)
class AuthorityConflictObservation:
    """
    Test-harness representation only.

    This object deliberately preserves two legitimate,
    type-correct AuthorityState observations rather than
    selecting one as authoritative.

    It is NOT part of the production Elias authority model.
    """

    observation_a: AuthorityState
    observation_b: AuthorityState
    reason: str


# ------------------------------------------------------------
# Same legitimate authority lineage.
#
# A = previously valid ACTIVE state.
# B = later REVOKED state produced through the ordinary
#     AuthorityState transition mechanism.
# ------------------------------------------------------------

authority_a = AuthorityState.create(
    actor_id="P3-F01-HUMAN-001",
    authority_source=
        "HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)

authority_b = authority_a.revoke_all(
    reason="P3-F01_REPLICA_B_REVOCATION"
)


# ------------------------------------------------------------
# Preserve disagreement instead of choosing a winner.
# ------------------------------------------------------------

conflict_observation = AuthorityConflictObservation(
    observation_a=authority_a,
    observation_b=authority_b,
    reason=(
        "TWO_AUTHENTIC_AUTHORITY_OBSERVATIONS_"
        "CURRENT_STANDING_UNRESOLVED"
    ),
)


resolver_state = {
    "calls": 0,
}


def conflicting_authority_resolver():
    resolver_state["calls"] += 1

    # Deliberately do not collapse the two observations
    # into one AuthorityState.
    return conflict_observation


arguments = {
    "content":
        "P3-F01 GOVERNED MESSAGE"
}


signing_key = (
    b"P3-F01-CONFLICTING-AUTHORITY-KEY-000001"
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


firewall = ExecutionFirewallV04(
    verifier=verifier,
    ledger=ledger,
    constitution_path=(
        ROOT
        / "constitution"
        / "constitution.yaml"
    ),
)


messaging_tool = MessagingDemoTool()


broker = ToolBrokerV04(
    firewall=firewall,
    messaging_tool=messaging_tool,
)


intent_hash = (
    "P3-F01-CONFLICTING-AUTHORITY-INTENT"
)


# Permit is genuinely issued while authority A is active.
permit = issuer.issue(
    authority=authority_a,
    intent_hash=intent_hash,
    permission="SEND",
    policy_version=
        "ERA-POLICY-001-v0.2.0",
    target="P3-F01-RECIPIENT",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=arguments,
)


request = ToolRequestV04(
    permit=permit,

    current_authority=authority_a,

    authority_resolver=
        conflicting_authority_resolver,

    intent_hash=intent_hash,

    permission="SEND",

    policy_version=
        "ERA-POLICY-001-v0.2.0",

    target="P3-F01-RECIPIENT",

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


consequence_containment_observed = (
    result_returned
    and
    result.executed is False
    and
    result.status
    == "REFUSED_BEFORE_CONSEQUENCE"
    and
    "CONSEQUENCE_AUTHORITY_NOT_ESTABLISHED"
    in reasons
    and
    outbox_before == 0
    and
    outbox_after == 0
)


# The current V04 contract requires a single AuthorityState.
# The test-harness conflict object is intentionally not one.
resolver_return_is_authority_state = isinstance(
    conflict_observation,
    AuthorityState,
)


native_conflict_representation_established = (
    resolver_return_is_authority_state
)


if (
    consequence_containment_observed
    and
    not native_conflict_representation_established
):
    classification = (
        "CONTAINMENT_OBSERVED__"
        "CONFLICT_NATIVE_REPRESENTATION_NOT_ESTABLISHED"
    )

elif consequence_containment_observed:
    classification = (
        "CONTAINMENT_OBSERVED__"
        "CONFLICT_REPRESENTATION_REQUIRES_REVIEW"
    )

else:
    classification = (
        "CONTAINMENT_NOT_ESTABLISHED__"
        "INVESTIGATION_REQUIRED"
    )


result_document = {
    "test_id": TEST_ID,
    "observed_at_utc": utc_now(),

    "classification":
        classification,

    "test_harness_only_conflict_object": True,

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

    "observations": {
        "resolver_calls":
            resolver_state["calls"],

        "resolver_called_once":
            resolver_called_once,

        "resolver_return_type":
            type(conflict_observation).__name__,

        "resolver_return_is_authority_state":
            resolver_return_is_authority_state,

        "result_returned":
            result_returned,

        "exception_captured":
            exception_captured,

        "exception_type":
            exception_type,

        "exception_message":
            exception_message,

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

        "witness_chain_valid":
            chain_valid,

        "witness_chain_errors":
            chain_errors,

        "witness_event_types": [
            record.get("event_type")
            for record in records
        ],
    },

    "consequence_containment_observed":
        consequence_containment_observed,

    "native_conflict_representation_established":
        native_conflict_representation_established,

    "bounded_interpretation": (
        "This test distinguishes consequence containment "
        "from native representation of conflicting legitimate "
        "authority observations. Refusal caused by the existing "
        "single-AuthorityState interface does not establish that "
        "V04 semantically understands split-brain authority."
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
                TEST_DEFINITION_PATH
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
    },

    "no_retrospective_repair": True,
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
    TEST_DEFINITION_PATH,
    Path(__file__),
    RESULT_PATH,
    WITNESS_PATH,
    FREEZE_PATH,
):
    sha_path = Path(
        str(path) + ".sha256"
    )

    sha_path.write_text(
        sha256_file(path)
        + "  "
        + path.name
        + "\n",
        encoding="utf-8",
    )


print()
print("=== P3-F01 FIRST OBSERVED RESULT ===")
print("classification:", classification)
print(
    "consequence_containment_observed:",
    consequence_containment_observed,
)
print(
    "native_conflict_representation_established:",
    native_conflict_representation_established,
)
print("resolver_calls:", resolver_state["calls"])
print("executed:", executed)
print("status:", status)
print("reasons:", reasons)
print("outbox_before:", outbox_before)
print("outbox_after:", outbox_after)
print("witness_chain_valid:", chain_valid)
print()
print("RESULT:", RESULT_PATH)
print("FREEZE:", FREEZE_PATH)
print("WITNESS:", WITNESS_PATH)
