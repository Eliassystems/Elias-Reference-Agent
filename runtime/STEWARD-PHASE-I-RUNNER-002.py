from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import secrets
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest().upper()


def write_json(path: Path, payload: dict) -> None:
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def nonempty_line_count(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(
        1
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    )


def load_adapter(path: Path):
    spec = importlib.util.spec_from_file_location(
        "steward_phase_i_blind_adapter_001",
        str(path),
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("ADAPTER_IMPORT_SPEC_NOT_ESTABLISHED")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worktree", required=True)
    parser.add_argument("--attempt", required=True)
    parser.add_argument("--freeze", required=True)
    parser.add_argument("--expected-runner-hash", required=True)
    parser.add_argument("--expected-freeze-hash", required=True)
    parser.add_argument("--admission", required=True)
    parser.add_argument("--expected-admission-hash", required=True)
    args = parser.parse_args()

    runner_path = Path(__file__).resolve()
    worktree = Path(args.worktree).resolve()
    attempt = Path(args.attempt).resolve()
    freeze_path = Path(args.freeze).resolve()
    admission_path = Path(args.admission).resolve()

    if sha256_file(runner_path) != args.expected_runner_hash.upper():
        print("STOP: RUNNER IDENTITY CHANGED")
        return 40

    if sha256_file(freeze_path) != args.expected_freeze_hash.upper():
        print("STOP: EXECUTION FREEZE IDENTITY CHANGED")
        return 41

    freeze = json.loads(freeze_path.read_text(encoding="utf-8-sig"))

    frozen_admission_path = Path(freeze["admission"]["path"]).resolve()

    if admission_path != frozen_admission_path:
        print("STOP: ADMISSION PATH DOES NOT MATCH FREEZE")
        return 57

    if not admission_path.exists():
        print("STOP: REQUIRED PREEXECUTION ADMISSION DOES NOT EXIST")
        return 58

    actual_admission_hash = sha256_file(admission_path)

    if actual_admission_hash != args.expected_admission_hash.upper():
        print("STOP: PREEXECUTION ADMISSION HASH CHANGED")
        return 59

    admission = json.loads(
        admission_path.read_text(encoding="utf-8-sig")
    )

    if admission.get("schema") != freeze["admission"]["schema"]:
        print("STOP: ADMISSION SCHEMA DOES NOT MATCH FREEZE")
        return 60

    if admission.get("admission_id") != freeze["admission"]["admission_id"]:
        print("STOP: ADMISSION ID DOES NOT MATCH FREEZE")
        return 61

    if admission.get("status") != "ACTIVE":
        print("STOP: PREEXECUTION ADMISSION IS NOT ACTIVE")
        return 62

    bound = admission.get("bound_objects", {})

    if str(bound.get("runner_sha256", "")).upper() != args.expected_runner_hash.upper():
        print("STOP: ADMISSION NOT BOUND TO EXACT RUNNER")
        return 63

    if str(bound.get("execution_freeze_sha256", "")).upper() != args.expected_freeze_hash.upper():
        print("STOP: ADMISSION NOT BOUND TO EXACT EXECUTION FREEZE")
        return 64

    if str(bound.get("admission_enforcement_adjudication_sha256", "")).upper() != freeze["admission"]["enforcement_adjudication_sha256"]:
        print("STOP: ADMISSION NOT BOUND TO ENFORCEMENT ADJUDICATION")
        return 65

    scope = admission.get("execution_scope", {})

    if scope.get("attempt_id") != freeze["execution"]["attempt_id"]:
        print("STOP: ADMISSION ATTEMPT ID DOES NOT MATCH FREEZE")
        return 66

    admitted_attempt = Path(scope.get("attempt_directory", "")).resolve()

    if admitted_attempt != attempt:
        print("STOP: ADMISSION ATTEMPT DIRECTORY DOES NOT MATCH")
        return 67

    if int(scope.get("parent_process_id", -1)) != os.getppid():
        print("STOP: ADMISSION PROCESS BINDING DOES NOT MATCH")
        return 68

    if scope.get("model_id") != freeze["model"]["id"]:
        print("STOP: ADMISSION MODEL ID DOES NOT MATCH FREEZE")
        return 69

    if int(scope.get("scenario_count", -1)) != 5:
        print("STOP: ADMISSION SCENARIO COUNT DOES NOT MATCH")
        return 70

    if scope.get("exact_execution_authorised") is not True:
        print("STOP: EXACT PHASE I EXECUTION NOT AUTHORISED")
        return 71

    if scope.get("real_world_external_messaging") is not False:
        print("STOP: ADMISSION EXTERNAL-MESSAGING BOUNDARY CHANGED")
        return 72

    if attempt.exists():
        print("STOP: PHASE I LIVE ATTEMPT 001 ALREADY EXISTS - NO RERUN")
        return 42

    frozen_attempt = Path(freeze["execution"]["attempt_directory"]).resolve()
    if frozen_attempt != attempt:
        print("STOP: ATTEMPT DIRECTORY DOES NOT MATCH FREEZE")
        return 43

    frozen_worktree = Path(freeze["worktree"]["path"]).resolve()
    if frozen_worktree != worktree:
        print("STOP: WORKTREE DOES NOT MATCH FREEZE")
        return 44

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key or not api_key.strip():
        print("STOP: OPENAI_API_KEY NOT PRESENT")
        return 45

    for relative, expected in freeze["component_hashes"].items():
        component = worktree / Path(relative)
        if not component.exists():
            print(f"STOP: COMPONENT MISSING: {relative}")
            return 46
        if sha256_file(component) != str(expected).upper():
            print(f"STOP: COMPONENT HASH CHANGED: {relative}")
            return 47

    adapter_path = Path(freeze["adapter"]["path"]).resolve()
    prompts_path = Path(freeze["blind_prompts"]["path"]).resolve()

    if sha256_file(adapter_path) != freeze["adapter"]["sha256"]:
        print("STOP: ADAPTER HASH CHANGED")
        return 48

    if sha256_file(prompts_path) != freeze["blind_prompts"]["sha256"]:
        print("STOP: BLIND PROMPTS HASH CHANGED")
        return 49

    adapter = load_adapter(adapter_path)
    bindings = adapter.load_blind_scenarios(prompts_path)

    if len(bindings) != 5:
        print("STOP: FIVE BLIND SCENARIOS NOT ESTABLISHED")
        return 50

    frozen_bindings = {
        item["scenario_id"]: item
        for item in freeze["scenario_bindings"]
    }

    for binding in bindings:
        if binding.scenario_id not in frozen_bindings:
            print("STOP: SCENARIO ATTRIBUTION CHANGED")
            return 51
        expected = frozen_bindings[binding.scenario_id]
        if binding.prompt != binding.prompt.strip():
            print("STOP: BLIND PROMPT HAS EDGE WHITESPACE")
            return 52
        if sha256_text(binding.prompt) != expected["prompt_utf8_sha256"]:
            print("STOP: BLIND PROMPT CONTENT CHANGED")
            return 53
        if binding.subject_or_question_key != expected["subject_or_question_key"]:
            print("STOP: NEUTRAL SUBJECT BINDING CHANGED")
            return 54
        if binding.session_id != expected["session_id"]:
            print("STOP: NEUTRAL SESSION BINDING CHANGED")
            return 55
        runtime_kwargs = binding.runtime_kwargs()
        if runtime_kwargs["objective"] != binding.prompt:
            print("STOP: PROMPT NOT PRESERVED AS OBJECTIVE")
            return 56

    attempt.mkdir(parents=True, exist_ok=False)

    start_record = {
        "schema": "elias.stewards-test.phase-i.execution-start.v1",
        "attempt_id": freeze["execution"]["attempt_id"],
        "started_at_utc": utc_now(),
        "runner_sha256": args.expected_runner_hash.upper(),
        "freeze_sha256": args.expected_freeze_hash.upper(),
        "adapter_sha256": freeze["adapter"]["sha256"],
        "blind_prompts_sha256": freeze["blind_prompts"]["sha256"],
        "model_id": freeze["model"]["id"],
        "scenario_count": 5,
        "api_key_present": True,
        "api_key_value_recorded": False,
        "semantic_adjudication_started": False,
    }

    write_json(attempt / "PHASE-I-EXECUTION-STARTED.json", start_record)

    results = []
    total_model_calls = 0
    current_position = None
    current_scenario_id = None
    current_model = None

    try:
        sys.path.insert(0, str(worktree))

        from agent.openai_adapter_v02 import OpenAIModelAdapterV02
        from agent.runtime_v03 import EliasAgentRuntimeV03
        from core.authority import AuthorityState
        from core.execution_firewall_v02 import ExecutionFirewallV02
        from core.permit_v02 import PermitIssuerV02, PermitVerifierV02
        from core.temporal_standing_v03 import TemporalStandingResolverV03
        from epistemic.continuity import EpistemicContinuityStore
        from tools.broker_v03 import ToolBrokerV03
        from tools.messaging_demo import MessagingDemoTool
        from witness.ledger import WitnessLedger

        for position, binding in enumerate(bindings, start=1):
            current_position = position
            current_scenario_id = binding.scenario_id
            current_model = None

            scenario_dir = attempt / f"SCENARIO-{position:02d}"
            scenario_dir.mkdir(parents=False, exist_ok=False)

            ledger_path = scenario_dir / "witness.jsonl"
            continuity_path = scenario_dir / "continuity.jsonl"

            signing_key = secrets.token_bytes(32)
            issuer = PermitIssuerV02(signing_key)
            verifier = PermitVerifierV02(signing_key)

            ledger = WitnessLedger(ledger_path)

            firewall = ExecutionFirewallV02(
                verifier=verifier,
                ledger=ledger,
                constitution_path=worktree / "constitution" / "constitution.yaml",
            )

            resolver = TemporalStandingResolverV03(
                signing_key=signing_key,
                issuer=issuer,
            )

            messaging = MessagingDemoTool()

            broker = ToolBrokerV03(
                firewall=firewall,
                messaging_tool=messaging,
                temporal_resolver=resolver,
            )

            continuity = EpistemicContinuityStore(continuity_path)

            current_model = OpenAIModelAdapterV02(
                model=freeze["model"]["id"]
            )

            runtime = EliasAgentRuntimeV03(
                model=current_model,
                permit_issuer=issuer,
                broker=broker,
                ledger=ledger,
                continuity=continuity,
            )

            runtime_kwargs = binding.runtime_kwargs()

            authority = AuthorityState.create(
                actor_id=freeze["runtime_fixture"]["actor_id"],
                authority_source=freeze["runtime_fixture"]["authority_source"],
                permissions=(runtime_kwargs["permission"],),
                epoch=1,
            )

            result = runtime.run(
                current_authority=authority,
                **runtime_kwargs,
            )

            model_calls = int(current_model.calls)
            total_model_calls += model_calls

            outbox = list(broker.outbox_snapshot())

            scenario_result = {
                "schema": "elias.stewards-test.phase-i.scenario-first-result.v1",
                "scenario_position": position,
                "scenario_id": binding.scenario_id,
                "prompt_utf8_sha256": sha256_text(binding.prompt),
                "session_id": binding.session_id,
                "subject_or_question_key": binding.subject_or_question_key,
                "model_id": getattr(result, "model_id", ""),
                "model_calls": model_calls,
                "runtime_status": getattr(result, "status", ""),
                "runtime_executed": bool(getattr(result, "executed", False)),
                "runtime_model_called": bool(getattr(result, "model_called", False)),
                "continuity_recovered": bool(getattr(result, "continuity_recovered", False)),
                "continuity_subject_record_count_before": int(getattr(result, "continuity_subject_record_count", 0)),
                "continuity_record_id": getattr(result, "continuity_record_id", ""),
                "continuity_record_hash": getattr(result, "continuity_record_hash", ""),
                "output_content": getattr(result, "output_content", ""),
                "outbox": outbox,
                "outbox_count": len(outbox),
                "witness_record_count": nonempty_line_count(ledger_path),
                "continuity_file_record_count": nonempty_line_count(continuity_path),
                "witness_sha256": sha256_file(ledger_path) if ledger_path.exists() else "",
                "continuity_sha256": sha256_file(continuity_path) if continuity_path.exists() else "",
                "semantic_adjudication": "NOT_PERFORMED_BY_EXECUTION_RUNNER",
            }

            scenario_result_path = scenario_dir / "SCENARIO-FIRST-RESULT.json"
            write_json(scenario_result_path, scenario_result)

            results.append({
                "scenario_position": position,
                "scenario_id": binding.scenario_id,
                "prompt_utf8_sha256": sha256_text(binding.prompt),
                "scenario_result_file": str(scenario_result_path.name),
                "scenario_result_sha256": sha256_file(scenario_result_path),
                "witness_sha256": scenario_result["witness_sha256"],
                "continuity_sha256": scenario_result["continuity_sha256"],
            })

        phase_result = {
            "schema": "elias.stewards-test.phase-i.first-observed-execution-result.v1",
            "attempt_id": freeze["execution"]["attempt_id"],
            "completed_at_utc": utc_now(),
            "scenario_count_expected": 5,
            "scenario_count_completed": len(results),
            "model_calls_total": total_model_calls,
            "technical_execution_completed": len(results) == 5,
            "scenario_results": results,
            "semantic_adjudication": "NOT_PERFORMED_BY_EXECUTION_RUNNER",
            "semantic_phase_result": "NOT_YET_ADJUDICATED",
            "assessment_criteria_loaded_by_execution_runner": False,
            "test_disclosure_supplied_to_model": False,
            "expected_answers_supplied_to_model": False,
            "external_real_world_messaging": False,
            "rerun_authorised": False,
        }

        write_json(
            attempt / "PHASE-I-FIRST-OBSERVED-RESULT.json",
            phase_result,
        )

        print(json.dumps({
            "attempt_id": phase_result["attempt_id"],
            "scenario_count_completed": phase_result["scenario_count_completed"],
            "model_calls_total": phase_result["model_calls_total"],
            "technical_execution_completed": phase_result["technical_execution_completed"],
            "semantic_phase_result": phase_result["semantic_phase_result"],
            "rerun_authorised": False,
        }, indent=2))

        return 0

    except Exception as exc:
        current_calls = 0
        if current_model is not None:
            current_calls = int(getattr(current_model, "calls", 0))

        error_record = {
            "schema": "elias.stewards-test.phase-i.execution-error.v1",
            "attempt_id": freeze["execution"]["attempt_id"],
            "observed_at_utc": utc_now(),
            "failed_scenario_position": current_position,
            "failed_scenario_id": current_scenario_id,
            "completed_scenarios_before_error": len(results),
            "model_calls_before_current_scenario": total_model_calls,
            "current_scenario_model_calls": current_calls,
            "exception_type": type(exc).__name__,
            "exception_message": str(exc),
            "traceback": traceback.format_exc(),
            "semantic_adjudication": "NOT_PERFORMED",
            "phase_result": "NOT_ESTABLISHED_TECHNICAL_EXECUTION_ERROR",
            "rerun_authorised": False,
        }

        write_json(
            attempt / "PHASE-I-ATTEMPT-ERROR.json",
            error_record,
        )

        print(json.dumps(error_record, indent=2))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
