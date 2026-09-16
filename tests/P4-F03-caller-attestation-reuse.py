from __future__ import annotations

import hashlib
import json
from pathlib import Path

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
from core.execution_firewall_v08 import ExecutionFirewallV08
from core.permit_v03 import PermitIssuerV03, PermitVerifierV03
from tools.broker_v08 import ToolBrokerV08, ToolRequestV08
from tools.messaging_demo_v06 import MessagingDemoToolV06
from witness.ledger import WitnessLedger


ROOT = Path(__file__).resolve().parents[1]

TEST_ID = "P4-F03"

DEFINITION_COMMIT = (
    "3a6c3db2dc954bc89296559b0b7ee0a498906458"
)

PREDECESSOR_EVIDENCE_COMMIT = (
    "15aa88dca989cc1694f99352db2d7d1191b93d75"
)

EXPECTED_DEFINITION_HASH = (
    "D07DC914CBBC7DDEBD48B364216A0A06C83CE73505CB2F4D2ADA41E7615FE34D"
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
    "core/execution_firewall_v08.py":
        "F5DA87C150CAACCACCB875F19B1EC51B4E2BA3051E2DB5643005802131B0DCE9",
    "tools/broker_v08.py":
        "542E894D72D57FEF58B945AC4726AF104A3690C77678AF639E51B8E23B16A9BE",
    "tools/messaging_demo_v06.py":
        "C976315CB420599ACEC8F2D8E5ED0B4FE4FBB9B1B07CBC8CBBA3CBB3E79A67DE",
    "witness/ledger.py":
        "C940D48351E8F4A06F2008CE720A2187433556E18C49D6378A2FA27E6DCE40E5",
}

EXPECTED_PREDECESSOR_HASHES = {
    "evidence/phase-iv/p4-f02-s01/P4-F02-S01-FIRST-OBSERVED-RESULT-001.json":
        "2FB4B6893852D0AAC7A7D5940E4F79FC2CE24A574EE7CA1B4909913546AFBBC9",
    "evidence/phase-iv/p4-f02-s01/P4-F02-S01-FIRST-OBSERVED-FREEZE-001.json":
        "55DDB7A9AF7C784F7B74732F3A6955D3BF27F33D2EBC2B506127AE6ED702D4DA",
    "evidence/phase-iv/p4-f02-s01/P4-F02-S01-WITNESS-001.jsonl":
        "5ACFA70BB4EA216F19611F8CB181F62BFF4861447884AE7A3B82EA14E39D5B9B",
}

EVIDENCE_DIR = ROOT / "evidence" / "phase-iv" / "p4-f03"

DEFINITION_PATH = (
    EVIDENCE_DIR / "P4-F03-TEST-DEFINITION-001.json"
)

RESULT_PATH = (
    EVIDENCE_DIR / "P4-F03-FIRST-OBSERVED-RESULT-001.json"
)

FREEZE_PATH = (
    EVIDENCE_DIR / "P4-F03-FIRST-OBSERVED-FREEZE-001.json"
)

WITNESS_PATH = (
    EVIDENCE_DIR / "P4-F03-WITNESS-001.jsonl"
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
            "P4-F03 FIRST-OBSERVED ARTIFACT EXISTS - DO NOT RERUN."
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
    "P4-F03-AUTHORIZED-RESOLVER-001"
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
    b"P4-F03-PERMIT-SIGNING-KEY-00000000000001"
)

resolution_signing_key = (
    b"P4-F03-RESOLUTION-SIGNING-KEY-0000000001"
)

caller_identity_signing_key = (
    b"P4-F03-CALLER-IDENTITY-SIGNING-KEY-00001"
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
                "P4-F03-ESTABLISHED-AUTHORITY",
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

    request = ToolRequestV08(
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
                "P4-F03-PC-ATTESTATION-001"
        )
    )

    positive_attestation_two = (
        issue_caller_attestation(
            nonce=
                "P4-F03-PC-ATTESTATION-002"
        )
    )

    positive_first = run_execution(
        case_id=
            "P4-F03-PC-01",
        caller_attestation=
            positive_attestation_one,
    )

    positive_second = run_execution(
        case_id=
            "P4-F03-PC-02",
        caller_attestation=
            positive_attestation_two,
    )

    reused_attestation = (
        issue_caller_attestation(
            nonce=
                "P4-F03-REUSED-ATTESTATION-001"
        )
    )

    reuse_first = run_execution(
        case_id=
            "P4-F03-REUSE-FIRST",
        caller_attestation=
            reused_attestation,
    )

    reuse_second = run_execution(
        case_id=
            "P4-F03-REUSE-SECOND",
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


records = ledger.records()

chain_valid, chain_errors = (
    ledger.verify_chain()
)


# ============================================================
# CLASSIFICATION
# ============================================================

if not preconditions_preserved:

    classification = (
        "P4-F03_PRECONDITION_IDENTITY_FAILURE"
    )

elif not positive_control_valid:

    classification = (
        "P4-F03_POSITIVE_CONTROL_FAILED"
    )

elif not (
    fresh_permits_confirmed
    and same_attestation_reused
    and reuse_first_valid
    and replayed_attestation_still_valid
):

    classification = (
        "P4-F03_NON_DISCRIMINATING_RESULT"
    )

elif reuse_second_committed:

    classification = (
        "AUTHENTICATED_CALLER_ATTESTATION_REPLAY_ACCEPTED_"
        "ACROSS_FRESH_PERMITS__SINGLE_USE_CONTROL_NOT_ESTABLISHED"
    )

elif reuse_second_refused_before_consequence:

    classification = (
        "AUTHENTICATED_CALLER_ATTESTATION_REPLAY_REFUSED_"
        "ACROSS_FRESH_PERMITS__SINGLE_USE_CONTROL_ESTABLISHED"
    )

else:

    classification = (
        "P4-F03_NON_DISCRIMINATING_RESULT"
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
            (
                reuse_second[
                    "reasons"
                ]
                if reuse_second is not None
                else []
            ),
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
        "P4-F03 observes only whether the frozen V08 reference path "
        "permits reuse of the same still-valid authenticated caller-identity "
        "attestation across separate executions carrying fresh execution "
        "permits. It does not establish distributed replay behavior, stolen-"
        "credential resistance, network authentication, external identity-"
        "provider security, process or hardware identity, tenant isolation, "
        "swarm security, or production exploitability resistance."
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
    "witness_chain_valid":
        chain_valid,
    "no_retrospective_repair":
        True,
    "predecessor_test_rerun":
        False,
    "v08_modified":
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
    "=== P4-F03 FIRST OBSERVED RESULT ==="
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
