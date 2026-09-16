from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1]),
)

from core.authority import AuthorityState
from core.authority_resolution import AuthorityResolution
from core.authority_resolution_attestation import (
    AuthorityResolutionAttestationIssuer,
    AuthorityResolutionAttestationVerifier,
)
from core.caller_identity_attestation import (
    CallerIdentityAttestationIssuer,
    CallerIdentityAttestationVerifier,
)
from core.execution_firewall_v09 import ExecutionFirewallV09
from core.permit_v03 import PermitIssuerV03, PermitVerifierV03
from tools.broker_v09 import ToolBrokerV09, ToolRequestV09
from tools.messaging_demo_v06 import MessagingDemoToolV06
from witness.ledger import WitnessLedger


ROOT = Path(__file__).resolve().parents[1]

TEST_ID = "P4-F03-S01"
ATTEMPT_ID = "P4-F03-S01-ATTEMPT-01"

DEFINITION_COMMIT = (
    "bd2d7aa64ca479e893aa3e9e1ea2e0366db0ef7c"
)

IMPLEMENTATION_COMMIT = (
    "d6c7fa9c60d744138c8f2c79b9a7e155cd6773c5"
)

PREDECESSOR_EVIDENCE_COMMIT = (
    "f06e191356cf740b175e43f8c19f942f21115a23"
)

EXPECTED_DEFINITION_HASH = (
    "DD6C8F5D5243761AD27D27830B8849DACCB78605B69443F6091E01D86DEEAED7"
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
    "core/caller_identity_attestation.py":
        "AA0F7960733AF9A82B3D0F02D07CCBFBCAB907B42A5282B010D44B2F8576CFDA",
    "core/execution_firewall_v09.py":
        "8113089EEEA159BE63158C9701ED24C5E152B3D29EDF97B10816D4FFDA629124",
    "tools/broker_v09.py":
        "A1B80CA2AFA85152FE7010E6D12C5EF8E6CF873B9613D2FCD57FAEEE0869211C",
    "tools/messaging_demo_v06.py":
        "C976315CB420599ACEC8F2D8E5ED0B4FE4FBB9B1B07CBC8CBBA3CBB3E79A67DE",
    "witness/ledger.py":
        "C940D48351E8F4A06F2008CE720A2187433556E18C49D6378A2FA27E6DCE40E5",
}

EXPECTED_PREDECESSOR_HASHES = {
    "evidence/phase-iv/p4-f03/P4-F03-FIRST-OBSERVED-RESULT-001.json":
        "52B6AE11BA93C097291DB6C02BD60957E008EBF55287D2AF1BFEDAE0BCE11A3D",
    "evidence/phase-iv/p4-f03/P4-F03-FIRST-OBSERVED-FREEZE-001.json":
        "6164A4F98E3DF5C090C19AE07AFFEDD84262D0EAB804CF68398D179D0C47598E",
    "evidence/phase-iv/p4-f03/P4-F03-WITNESS-001.jsonl":
        "94F01504D41C0938F741C5F4A4270774B3E9750AC92B2F35F50F5B81970AFB21",
}

EVIDENCE_DIR = ROOT / "evidence" / "phase-iv" / "p4-f03-s01"

DEFINITION_PATH = (
    EVIDENCE_DIR / "P4-F03-S01-TEST-DEFINITION-001.json"
)

RESULT_PATH = (
    EVIDENCE_DIR / "P4-F03-S01-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR / "P4-F03-S01-FIRST-OBSERVED-FREEZE-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR / "P4-F03-S01-WITNESS-001.jsonl"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


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
            "P4-F03-S01 FIRST-OBSERVED ARTIFACT EXISTS - DO NOT RERUN."
        )


# ============================================================
# FROZEN IDENTITY CHECKS
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


predecessor_identity = {}
predecessor_evidence_identity_preserved = True

for relative, expected in EXPECTED_PREDECESSOR_HASHES.items():
    actual = sha256(ROOT / relative)

    predecessor_identity[relative] = {
        "expected_sha256": expected,
        "actual_sha256": actual,
        "preserved": actual == expected,
    }

    if actual != expected:
        predecessor_evidence_identity_preserved = False


# ============================================================
# TEST IDENTITIES / LEGITIMATE AUTHORITY
# ============================================================

AGENT = "P4-F01-AGENT-A"
HUMAN_ACTOR = "P4-F01-HUMAN-001"

IDENTITY_AUTHORITY = (
    "P4-F02-S01-IDENTITY-AUTHORITY-001"
)

RESOLVER_ID = (
    "P4-F03-S01-AUTHORIZED-RESOLVER-001"
)

active_authority = AuthorityState.create(
    actor_id=HUMAN_ACTOR,
    authority_source="HUMAN_SOVEREIGN_AUTHORITY",
    permissions={"SEND"},
    epoch=1,
)


# ============================================================
# LOCAL QA SIGNING MATERIAL
# ============================================================

permit_signing_key = (
    b"P4-F03-S01-PERMIT-SIGNING-KEY-00000000000001"
)

resolution_signing_key = (
    b"P4-F03-S01-RESOLUTION-SIGNING-KEY-0000000001"
)

caller_identity_signing_key = (
    b"P4-F03-S01-CALLER-IDENTITY-SIGNING-KEY-00001"
)


# ============================================================
# TRACKING / WITNESS STACK
# ============================================================

permit_verifier_call_log = []
caller_verifier_call_log = []


class TrackingPermitVerifierV03(PermitVerifierV03):

    def verify(self, *args, **kwargs):
        permit = kwargs.get("permit")

        if permit is None and args:
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


class TrackingCallerIdentityVerifier(
    CallerIdentityAttestationVerifier
):

    def verify(self, *args, **kwargs):
        attestation = kwargs.get(
            "attestation"
        )

        if attestation is None and args:
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
            "nonce":
                getattr(
                    attestation,
                    "nonce",
                    None,
                ),
            "signature":
                getattr(
                    attestation,
                    "signature",
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


ledger = WitnessLedger(
    WITNESS_PATH
)


permit_issuer = PermitIssuerV03(
    signing_key=
        permit_signing_key
)

permit_verifier = TrackingPermitVerifierV03(
    signing_key=
        permit_signing_key
)

resolution_issuer = (
    AuthorityResolutionAttestationIssuer(
        resolver_id=
            RESOLVER_ID,
        signing_key=
            resolution_signing_key,
    )
)

resolution_verifier = (
    AuthorityResolutionAttestationVerifier(
        resolver_id=
            RESOLVER_ID,
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
                "P4-F03-S01-ESTABLISHED-AUTHORITY",
        )
    )

    resolver_state[
        "statuses"
    ].append(
        resolution.status.value
    )

    return resolution_issuer.issue(
        resolution
    )


messaging_tool = MessagingDemoToolV06()

firewall = ExecutionFirewallV09(
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

broker = ToolBrokerV09(
    firewall=
        firewall,
    messaging_tool=
        messaging_tool,
)


# ============================================================
# EXECUTION HELPERS
# ============================================================

def issue_fresh_permit(
    *,
    case_id: str,
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
            AGENT,
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

    return (
        permit,
        intent_hash,
        arguments,
    )


def issue_caller_attestation(
    *,
    nonce: str,
):
    return caller_identity_issuer.issue(
        subject_agent_id=
            AGENT,
        ttl_seconds=
            900,
        nonce=
            nonce,
    )


def attestation_identity(
    attestation,
):
    return {
        "attestation_id":
            attestation.attestation_id,
        "subject_agent_id":
            attestation.subject_agent_id,
        "issuer_id":
            attestation.issuer_id,
        "issued_at":
            attestation.issued_at,
        "expires_at":
            attestation.expires_at,
        "nonce":
            attestation.nonce,
        "signature":
            attestation.signature,
    }


def run_execution(
    *,
    case_id: str,
    caller_attestation,
):
    (
        permit,
        intent_hash,
        arguments,
    ) = issue_fresh_permit(
        case_id=
            case_id
    )

    resolver_calls_before = (
        resolver_state["calls"]
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

    request = ToolRequestV09(
        permit=
            permit,
        current_authority=
            active_authority,
        presenting_agent_id=
            AGENT,
        caller_identity_attestation=
            caller_attestation,
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

    return {
        "case_id":
            case_id,
        "permit_id":
            permit.permit_id,
        "permit_agent_id":
            permit.agent_id,
        "caller_attestation":
            attestation_identity(
                caller_attestation
            ),
        "status":
            status,
        "reasons":
            list(
                raw_reasons or ()
            ),
        "exception":
            exception,
        "resolver_calls":
            (
                resolver_state["calls"]
                - resolver_calls_before
            ),
        "permit_verifier_calls":
            list(
                permit_verifier_call_log[
                    permit_verifier_start:
                ]
            ),
        "caller_identity_verifier_calls":
            list(
                caller_verifier_call_log[
                    caller_verifier_start:
                ]
            ),
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
# FIRST-OBSERVED TEST LOGIC
# ============================================================

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


def write_sidecar(
    path: Path,
) -> None:
    digest = sha256(path)

    path.with_name(
        path.name + ".sha256"
    ).write_text(
        f"{digest}  {path.name}\n",
        encoding="utf-8",
        newline="\n",
    )


preconditions_preserved = all(
    (
        definition_identity_preserved,
        source_identity_preserved,
        predecessor_evidence_identity_preserved,
    )
)


positive_first = None
positive_second = None
reuse_first = None
reuse_second = None


if preconditions_preserved:

    positive_attestation_one = (
        issue_caller_attestation(
            nonce=
                "P4-F03-S01-PC-ATTESTATION-001"
        )
    )

    positive_attestation_two = (
        issue_caller_attestation(
            nonce=
                "P4-F03-S01-PC-ATTESTATION-002"
        )
    )

    positive_first = run_execution(
        case_id=
            "P4-F03-S01-PC-01",
        caller_attestation=
            positive_attestation_one,
    )

    positive_second = run_execution(
        case_id=
            "P4-F03-S01-PC-02",
        caller_attestation=
            positive_attestation_two,
    )

    reused_attestation = (
        issue_caller_attestation(
            nonce=
                "P4-F03-S01-REUSED-ATTESTATION-001"
        )
    )

    reuse_first = run_execution(
        case_id=
            "P4-F03-S01-REUSE-FIRST",
        caller_attestation=
            reused_attestation,
    )

    reuse_second = run_execution(
        case_id=
            "P4-F03-S01-REUSE-SECOND",
        caller_attestation=
            reused_attestation,
    )


# ============================================================
# OBSERVATION HELPERS
# ============================================================

def executed_and_committed(
    case_result,
) -> bool:
    return (
        case_result is not None
        and case_result[
            "exception"
        ] is None
        and case_result[
            "status"
        ] == "EXECUTED"
        and case_result[
            "consequence_committed"
        ] is True
    )


positive_control_valid = (
    executed_and_committed(
        positive_first
    )
    and executed_and_committed(
        positive_second
    )
    and positive_first[
        "permit_id"
    ] != positive_second[
        "permit_id"
    ]
    and positive_first[
        "caller_attestation"
    ][
        "attestation_id"
    ] != positive_second[
        "caller_attestation"
    ][
        "attestation_id"
    ]
    and positive_first[
        "caller_attestation"
    ][
        "nonce"
    ] != positive_second[
        "caller_attestation"
    ][
        "nonce"
    ]
)


fresh_permits_confirmed = (
    reuse_first is not None
    and reuse_second is not None
    and reuse_first[
        "permit_id"
    ] != reuse_second[
        "permit_id"
    ]
)


same_attestation_reused = (
    reuse_first is not None
    and reuse_second is not None
    and reuse_first[
        "caller_attestation"
    ] == reuse_second[
        "caller_attestation"
    ]
)


reuse_first_valid = (
    executed_and_committed(
        reuse_first
    )
)


second_caller_verifications = (
    reuse_second[
        "caller_identity_verifier_calls"
    ]
    if reuse_second is not None
    else []
)


replayed_attestation_still_valid = (
    bool(
        second_caller_verifications
    )
    and all(
        call.get(
            "valid"
        ) is True
        for call
        in second_caller_verifications
    )
)


reuse_second_committed = (
    executed_and_committed(
        reuse_second
    )
)


reuse_second_refused_before_consequence = (
    reuse_second is not None
    and reuse_second[
        "exception"
    ] is None
    and reuse_second[
        "status"
    ] == "REFUSED_BEFORE_CONSEQUENCE"
    and reuse_second[
        "consequence_committed"
    ] is False
)


reuse_second_reasons = (
    tuple(
        reuse_second[
            "reasons"
        ]
    )
    if reuse_second is not None
    else ()
)


native_replay_refusal_confirmed = (
    reuse_second_refused_before_consequence
    and reuse_second_reasons
    == (
        "CALLER_IDENTITY_ATTESTATION_ALREADY_USED",
    )
)


records = ledger.records()

chain_valid, chain_errors = (
    ledger.verify_chain()
)


# ============================================================
# CLASSIFICATION
# ============================================================

if not preconditions_preserved:

    classification = (
        "P4-F03-S01_PRECONDITION_IDENTITY_FAILURE"
    )

elif not positive_control_valid:

    classification = (
        "P4-F03-S01_POSITIVE_CONTROL_FAILED"
    )

elif not (
    fresh_permits_confirmed
    and same_attestation_reused
    and reuse_first_valid
    and replayed_attestation_still_valid
):

    classification = (
        "P4-F03-S01_NON_DISCRIMINATING_RESULT"
    )

elif reuse_second_committed:

    classification = (
        "CALLER_ATTESTATION_COMMITTED_USE_REPLAY_ACCEPTED_"
        "ACROSS_FRESH_PERMITS__"
        "SEQUENTIAL_SINGLE_USE_CONTROL_NOT_ESTABLISHED"
    )

elif native_replay_refusal_confirmed:

    classification = (
        "CALLER_ATTESTATION_COMMITTED_USE_REPLAY_REFUSED_"
        "ACROSS_FRESH_PERMITS__"
        "SEQUENTIAL_SINGLE_USE_CONTROL_ESTABLISHED"
    )

elif reuse_second_refused_before_consequence:

    classification = (
        "P4-F03-S01_NON_DISCRIMINATING_UNRELATED_REFUSAL"
    )

else:

    classification = (
        "P4-F03-S01_NON_DISCRIMINATING_RESULT"
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
    "positive_control_first":
        positive_first,
    "positive_control_second":
        positive_second,
    "reuse_first":
        reuse_first,
    "reuse_second":
        reuse_second,
    "required_observations": {
        "positive_control_valid":
            positive_control_valid,
        "fresh_permits_confirmed":
            fresh_permits_confirmed,
        "same_attestation_reused":
            same_attestation_reused,
        "reuse_first_valid":
            reuse_first_valid,
        "replayed_attestation_still_valid":
            replayed_attestation_still_valid,
        "reuse_second_committed":
            reuse_second_committed,
        "reuse_second_refused_before_consequence":
            reuse_second_refused_before_consequence,
        "reuse_second_reasons":
            list(
                reuse_second_reasons
            ),
        "native_replay_refusal_confirmed":
            native_replay_refusal_confirmed,
        "witness_chain_valid":
            chain_valid,
    },
    "witness": {
        "record_count":
            len(records),
        "chain_valid":
            chain_valid,
        "chain_errors":
            chain_errors,
    },
    "bounded_claim": (
        "P4-F03-S01 evaluates only sequential committed-use reuse of the "
        "same still-valid authenticated caller-identity attestation in the "
        "frozen V09 local reference path across separate fresh execution "
        "permits. It does not establish simultaneous or concurrent replay "
        "protection, distributed replay protection, network or transport "
        "security, process or hardware identity, operating-system security, "
        "external identity-provider or credential-compromise resistance, "
        "tenant isolation, general swarm security, or production "
        "exploitability resistance."
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
    "positive_control_valid":
        positive_control_valid,
    "fresh_permits_confirmed":
        fresh_permits_confirmed,
    "same_attestation_reused":
        same_attestation_reused,
    "reuse_first_valid":
        reuse_first_valid,
    "replayed_attestation_still_valid":
        replayed_attestation_still_valid,
    "reuse_second_committed":
        reuse_second_committed,
    "reuse_second_refused_before_consequence":
        reuse_second_refused_before_consequence,
    "reuse_second_reasons":
        list(
            reuse_second_reasons
        ),
    "native_replay_refusal_confirmed":
        native_replay_refusal_confirmed,
    "witness_chain_valid":
        chain_valid,
    "no_retrospective_repair":
        True,
    "predecessor_test_rerun":
        False,
    "v09_modified":
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
    "=== P4-F03-S01 FIRST OBSERVED RESULT ==="
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
    "positive_control_valid:",
    positive_control_valid,
)

print(
    "fresh_permits_confirmed:",
    fresh_permits_confirmed,
)

print(
    "same_attestation_reused:",
    same_attestation_reused,
)

print(
    "reuse_first_valid:",
    reuse_first_valid,
)

print(
    "replayed_attestation_still_valid:",
    replayed_attestation_still_valid,
)

print(
    "reuse_second_committed:",
    reuse_second_committed,
)

print(
    "reuse_second_refused_before_consequence:",
    reuse_second_refused_before_consequence,
)

print(
    "witness_chain_valid:",
    chain_valid,
)

print()

print(
    "RESULT_SHA256:",
    sha256(
        RESULT_PATH
    ),
)

print(
    "FREEZE_SHA256:",
    sha256(
        FREEZE_PATH
    ),
)

print(
    "WITNESS_SHA256:",
    (
        sha256(
            WITNESS_PATH
        )
        if WITNESS_PATH.exists()
        else None
    ),
)
