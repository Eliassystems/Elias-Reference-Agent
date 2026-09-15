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


TEST_ID = "P3-F08"

BASELINE_COMMIT = (
    "3b2a43110bb209d2c121ed8655f7a62e1e7f2d76"
)

EXPECTED_DEFINITION_HASH = (
    "55DA576FEC65A0AA6A2DB1944AAE986AC2B0A6AC0617192BE6683534D54ED451"
)

EXPECTED_GOVERNING_HASHES = {'core/authority.py': 'E949C5C9E75DCB65301701363363AC6D118CD64D3AB38018957DA086EBB6B85C', 'core/authority_resolution.py': 'D1B052E1F413ADAFA71C8B7D3E0AB470817E901CBA28D1CF145BF10EA7A585EF', 'core/execution_firewall_v06.py': '688BCA67810747A053A4251974281AC2D5C435C0CEAC36CBFEF85A65A0D9DEBD'}

EXPECTED_SUPPORT_HASHES = {'core/permit_v02.py': '1BE9CED135D1C3E0498728B5E9AE0853E46E1925EA90EFF70A573E0F516C70A5', 'tools/broker_v06.py': 'B220643B322356345E79EA37359D48BCDE004DCE09727B01F8BEC5E6DFCBE26F', 'tools/messaging_demo_v06.py': 'C976315CB420599ACEC8F2D8E5ED0B4FE4FBB9B1B07CBC8CBBA3CBB3E79A67DE', 'witness/ledger.py': 'C940D48351E8F4A06F2008CE720A2187433556E18C49D6378A2FA27E6DCE40E5', 'constitution/constitution.yaml': '6FF2C14C67DF4B009F81551AD55ECD4C1EA314B5827D7B039D0E21AD934D302A'}

EVIDENCE_DIR = (
    ROOT / "evidence" / "phase-iii" / "p3-f08"
)

DEFINITION_PATH = (
    EVIDENCE_DIR /
    "P3-F08-TEST-DEFINITION-001.json"
)

RESULT_PATH = (
    EVIDENCE_DIR /
    "P3-F08-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR /
    "P3-F08-FIRST-OBSERVED-FREEZE-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR /
    "P3-F08-WITNESS-001.jsonl"
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
    "resolution_hashes": [],
    "observation_counts": [],
    "observation_hashes": [],
}


def authority_resolver():

    resolver_state["calls"] += 1

    mode = resolver_mode["mode"]

    if mode == "POSITIVE":

        resolution = AuthorityResolution.established(
            active_authority,
            reason="P3-F08-POSITIVE-ESTABLISHED",
        )

    elif mode == "ADVERSARIAL":

        if divergent_conflict is None:
            raise RuntimeError(
                "P3-F08_DIVERGENT_CONFLICT_NOT_CONSTRUCTED"
            )

        resolution = divergent_conflict

    else:

        raise RuntimeError(
            "P3-F08_UNKNOWN_RESOLVER_MODE"
        )

    resolver_state["modes"].append(
        mode
    )

    resolver_state["statuses"].append(
        resolution.status.value
    )

    resolver_state["resolution_hashes"].append(
        resolution.state_hash()
    )

    resolver_state["observation_counts"].append(
        len(
            resolution.observations
        )
    )

    resolver_state["observation_hashes"].append(
        [
            observation.state_hash()
            for observation
            in resolution.observations
        ]
    )

    timeline.append(
        "RESOLVER:"
        + mode
        + ":"
        + resolution.status.value
    )

    return resolution


# ============================================================
# NORMAL V06 STACK
# ============================================================

signing_key = (
    b"P3-F08-DIVERGENT-CONFLICT-KEY-0001"
)

issuer = PermitIssuerV02(
    signing_key=signing_key
)

verifier = PermitVerifierV02(
    signing_key=signing_key
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
# POSITIVE CONTROL
# Normal established authority must execute.
# ============================================================

positive_arguments = {
    "content":
        "P3-F08 POSITIVE ESTABLISHED CONTROL"
}

positive_intent_hash = (
    "P3-F08-POSITIVE-INTENT"
)

positive_permit = issuer.issue(
    authority=active_authority,
    intent_hash=positive_intent_hash,
    permission="SEND",
    policy_version="ERA-POLICY-001-v0.2.0",
    target="P3-F08-POSITIVE-RECIPIENT",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=positive_arguments,
)

positive_request = ToolRequestV06(
    permit=positive_permit,
    current_authority=active_authority,
    authority_resolver=authority_resolver,
    intent_hash=positive_intent_hash,
    permission="SEND",
    policy_version="ERA-POLICY-001-v0.2.0",
    target="P3-F08-POSITIVE-RECIPIENT",
    tool_name="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=positive_arguments,
)

resolver_mode["mode"] = "POSITIVE"

positive_calls_before = (
    resolver_state["calls"]
)

positive_outbox_before = (
    broker.outbox_size()
)

positive_result = None
positive_exception = None

try:

    positive_result = broker.execute(
        positive_request
    )

except Exception as exc:

    positive_exception = {
        "type": type(exc).__name__,
        "message": str(exc),
    }

positive_outbox_after = (
    broker.outbox_size()
)

positive_calls = (
    resolver_state["calls"]
    - positive_calls_before
)

positive_status = None
positive_reasons = []

if positive_result is not None:

    raw_status = getattr(
        positive_result,
        "status",
        None,
    )

    positive_status = getattr(
        raw_status,
        "value",
        raw_status,
    )

    raw_reasons = getattr(
        positive_result,
        "reasons",
        (),
    )

    if raw_reasons is not None:
        positive_reasons = list(
            raw_reasons
        )


positive_control_passed = (
    positive_exception is None
    and positive_result is not None
    and positive_outbox_after
        == positive_outbox_before + 1
    and positive_calls == 2
)


# ============================================================
# ADVERSARIAL CONDITION
# Same legitimate permit/current authority.
# Resolver supplies native CONFLICT containing one locally
# asserted divergent AuthorityState.
# ============================================================

adversarial_arguments = {
    "content":
        "P3-F08 DIVERGENT ASSERTED CONFLICT TEST"
}

adversarial_intent_hash = (
    "P3-F08-ADVERSARIAL-INTENT"
)

adversarial_permit = issuer.issue(
    authority=active_authority,
    intent_hash=adversarial_intent_hash,
    permission="SEND",
    policy_version="ERA-POLICY-001-v0.2.0",
    target="P3-F08-ADVERSARIAL-RECIPIENT",
    tool="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=adversarial_arguments,
)

adversarial_request = ToolRequestV06(
    permit=adversarial_permit,
    current_authority=active_authority,
    authority_resolver=authority_resolver,
    intent_hash=adversarial_intent_hash,
    permission="SEND",
    policy_version="ERA-POLICY-001-v0.2.0",
    target="P3-F08-ADVERSARIAL-RECIPIENT",
    tool_name="MESSAGING_DEMO",
    consequence_class="C4",
    arguments=adversarial_arguments,
)

resolver_mode["mode"] = "ADVERSARIAL"

adversarial_calls_before = (
    resolver_state["calls"]
)

adversarial_status_index = len(
    resolver_state["statuses"]
)

adversarial_outbox_before = (
    broker.outbox_size()
)

adversarial_result = None
adversarial_exception = None

if (
    definition_identity_preserved
    and source_identity_preserved
    and positive_control_passed
    and asserted_authority_locally_constructed
    and asserted_authority_materially_different
    and divergent_conflict_constructed
):

    try:

        adversarial_result = broker.execute(
            adversarial_request
        )

    except Exception as exc:

        adversarial_exception = {
            "type": type(exc).__name__,
            "message": str(exc),
        }


adversarial_outbox_after = (
    broker.outbox_size()
)

adversarial_calls = (
    resolver_state["calls"]
    - adversarial_calls_before
)

adversarial_resolver_statuses = (
    resolver_state["statuses"][
        adversarial_status_index:
    ]
)

adversarial_status = None
adversarial_reasons = []

if adversarial_result is not None:

    raw_status = getattr(
        adversarial_result,
        "status",
        None,
    )

    adversarial_status = getattr(
        raw_status,
        "value",
        raw_status,
    )

    raw_reasons = getattr(
        adversarial_result,
        "reasons",
        (),
    )

    if raw_reasons is not None:
        adversarial_reasons = list(
            raw_reasons
        )


consequence_committed = (
    adversarial_outbox_after
    > adversarial_outbox_before
)


seam_observed = (
    definition_identity_preserved
    and source_identity_preserved
    and positive_control_passed
    and asserted_authority_locally_constructed
    and asserted_authority_materially_different
    and native_provenance_proof_supplied is False
    and divergent_conflict_constructed
    and adversarial_exception is None
    and adversarial_result is not None
    and "CONSEQUENCE_AUTHORITY_CONFLICT"
        in adversarial_reasons
    and consequence_committed is False
    and adversarial_calls == 1
    and adversarial_resolver_statuses
        == ["CONFLICT"]
)


if seam_observed:

    classification = (
        SEAM_CLASSIFICATION
    )

else:

    classification = (
        UNEXPECTED_CLASSIFICATION
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

    "positive_control": {
        "passed":
            positive_control_passed,

        "resolver_calls":
            positive_calls,

        "status":
            positive_status,

        "reasons":
            positive_reasons,

        "outbox_before":
            positive_outbox_before,

        "outbox_after":
            positive_outbox_after,

        "exception":
            positive_exception,
    },

    "asserted_divergent_observation": {
        "locally_constructed":
            asserted_authority_locally_constructed,

        "materially_different":
            asserted_authority_materially_different,

        "native_provenance_proof_supplied":
            native_provenance_proof_supplied,

        "construction_error":
            asserted_construction_error,

        "state_hash":
            (
                asserted_divergent_authority.state_hash()
                if asserted_divergent_authority
                is not None
                else None
            ),

        "canonical_payload":
            (
                asserted_divergent_authority.canonical_payload()
                if asserted_divergent_authority
                is not None
                else None
            ),
    },

    "divergent_conflict": {
        "constructed":
            divergent_conflict_constructed,

        "construction_error":
            conflict_construction_error,

        "observation_count":
            (
                len(
                    divergent_conflict.observations
                )
                if divergent_conflict
                is not None
                else None
            ),

        "resolution_hash":
            (
                divergent_conflict.state_hash()
                if divergent_conflict
                is not None
                else None
            ),
    },

    "adversarial_execution": {
        "resolver_calls":
            adversarial_calls,

        "resolver_statuses":
            adversarial_resolver_statuses,

        "status":
            adversarial_status,

        "reasons":
            adversarial_reasons,

        "outbox_before":
            adversarial_outbox_before,

        "outbox_after":
            adversarial_outbox_after,

        "consequence_committed":
            consequence_committed,

        "exception":
            adversarial_exception,
    },

    "witness": {
        "record_count":
            len(records),

        "chain_valid":
            chain_valid,

        "chain_errors":
            chain_errors,
    },

    "seam_observed":
        seam_observed,

    "bounded_claim": (
        "This deterministic test examines only whether two materially "
        "different locally constructible AuthorityState assertions can "
        "form a native CONFLICT without native provenance establishment "
        "and whether ExecutionFirewallV06 then treats that supplied "
        "CONFLICT as sufficient to refuse an otherwise-authorized "
        "consequence. It does not establish that an external attacker "
        "can reach or control the resolver in production, does not "
        "establish cryptographic forgery, and does not assess external "
        "registries, signatures, issuer attestations, deployment access "
        "controls, or distributed consensus."
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

    "asserted_authority_locally_constructed":
        asserted_authority_locally_constructed,

    "divergent_conflict_constructed":
        divergent_conflict_constructed,

    "seam_observed":
        seam_observed,

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
print("=== P3-F08 FIRST OBSERVED RESULT ===")
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
    "asserted_authority_locally_constructed:",
    asserted_authority_locally_constructed,
)
print(
    "asserted_authority_materially_different:",
    asserted_authority_materially_different,
)
print(
    "native_provenance_proof_supplied:",
    native_provenance_proof_supplied,
)
print(
    "divergent_conflict_constructed:",
    divergent_conflict_constructed,
)
print(
    "adversarial_resolver_calls:",
    adversarial_calls,
)
print(
    "adversarial_resolver_statuses:",
    adversarial_resolver_statuses,
)
print(
    "execution_status:",
    adversarial_status,
)
print(
    "execution_reasons:",
    adversarial_reasons,
)
print(
    "consequence_committed:",
    consequence_committed,
)
print(
    "seam_observed:",
    seam_observed,
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
