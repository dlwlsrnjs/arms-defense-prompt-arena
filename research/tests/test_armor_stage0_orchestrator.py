from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from defense_arena.armor_judge import ARMOR_JUDGE_PROTOCOL
from defense_arena.armor_stage0 import (
    ARM_IDS,
    SHA256_EMPTY,
    audit_results,
    build_plan,
    load_results,
    prepare,
)
from defense_arena.armor_stage0_orchestrator import (
    ResolvedBehavior,
    ResolvedPrompt,
    Stage0LiveOrchestrator,
    Stage0OrchestrationError,
)


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_text(value: str) -> str:
    return _sha_bytes(value.encode())


def _fixture(tmp_path: Path):
    memory = b'{"entries": []}\n'
    asset = b"offline fixture asset"
    prompts = {
        ARM_IDS[0]: "",
        ARM_IDS[1]: "generic defense",
        ARM_IDS[2]: "matched defense",
        ARM_IDS[3]: "mismatched defense",
    }
    memory_hash = _sha_bytes(memory)
    spec = {
        "schema_version": 1,
        "experiment_id": "live-orchestrator-fixture",
        "target_call_budget": 2,
        "randomization_seed": 31,
        "prompt_token_budget": 8,
        "max_censoring_rate": 0.01,
        "arms": {
            ARM_IDS[0]: {
                "prompt_sha256": SHA256_EMPTY,
                "prompt_token_count": 0,
                "memory_relation": "none",
                "compiler_memory_sha256": None,
            },
            ARM_IDS[1]: {
                "prompt_sha256": _sha_text(prompts[ARM_IDS[1]]),
                "prompt_token_count": 2,
                "memory_relation": "none",
                "compiler_memory_sha256": None,
            },
            ARM_IDS[2]: {
                "prompt_sha256": _sha_text(prompts[ARM_IDS[2]]),
                "prompt_token_count": 2,
                "memory_relation": "matched",
                "compiler_memory_sha256": memory_hash,
            },
            ARM_IDS[3]: {
                "prompt_sha256": _sha_text(prompts[ARM_IDS[3]]),
                "prompt_token_count": 2,
                "memory_relation": "mismatched",
                "compiler_memory_sha256": "9" * 64,
            },
        },
        "pairs": [
            {
                "pair_id": "live-pair-001",
                "behavior_id": "live-behavior-001",
                "attacker_seed": 7101,
                "initial_memory_sha256": memory_hash,
                "initial_retrieval_sha256": "2" * 64,
                "first_action_sha256": _sha_text("first request"),
                "fallback_policy_sha256": _sha_text("fallback policy"),
                "fallback_action_sha256": _sha_text("fallback action"),
                "fallback_request_sha256": _sha_text("fallback request"),
                "asset_hashes": {"fixture_asset": _sha_bytes(asset)},
                "decoding_config": {"temperature": 0.0, "top_p": 1.0, "max_tokens": 64},
            }
        ],
    }
    plan = build_plan(spec)
    root = prepare(plan, tmp_path / "prepared")

    def behavior_resolver(behavior_id: str) -> ResolvedBehavior:
        return ResolvedBehavior(
            behavior_id=behavior_id,
            value={"id": behavior_id, "ephemeral_text": "never persisted by orchestrator"},
            assets={"fixture_asset": asset},
        )

    def prompt_resolver(arm: str) -> ResolvedPrompt:
        return ResolvedPrompt(text=prompts[arm], token_count=0 if arm == ARM_IDS[0] else 2)

    def memory_resolver(requested_hash: str):
        assert requested_hash == memory_hash
        return memory

    return plan, root, prompts, behavior_resolver, prompt_resolver, memory_resolver


def _axis(name: str, value: int, maximum: int) -> dict:
    return {
        "axis": name,
        "value": value,
        "observed_value": value,
        "minimum": 0 if name != "benchmark_completion" else 1,
        "maximum": maximum,
        "status": "ok",
        "fail_closed_applied": False,
        "error_code": None,
        "judge_output_sha256": _sha_text(f"{name}-judge"),
        "judge_output_chars": 8,
        "reason_sha256": _sha_text(f"{name}-reason"),
        "reason_chars": 8,
        "seed": 17,
    }


def _axis_artifact(request: str, response: str) -> dict:
    return {
        "protocol_version": ARMOR_JUDGE_PROTOCOL,
        "complete": True,
        "is_censored": False,
        "strict_success": False,
        "fail_closed_strict_upper_bound": False,
        "error_codes": [],
        "attack_validity": _axis("attack_validity", 1, 1),
        "benchmark_completion": _axis("benchmark_completion", 2, 5),
        "capability_harm": _axis("capability_harm", 1, 5),
        "input_provenance": {
            "behavior_sha256": _sha_text("behavior"),
            "category_sha256": _sha_text("category"),
            "request_sha256": _sha_text(request),
            "response_sha256": _sha_text(response),
            "behavior_chars": 8,
            "category_chars": 8,
            "request_chars": len(request),
            "response_chars": len(response),
            "raw_text_included": False,
            "response_independent_validity": True,
            "validity_payload_sha256": _sha_text(f"validity:{request}"),
            "validity_multimodal_bundle_sha256": _sha_text(
                f"validity-bundle:{request}"
            ),
        },
    }


def _instrumented_row(context, *, legacy: bool = False, provenance_overrides=None):
    requests = ["first request", "second request"]
    responses = ["first response", "second response"]
    asset_hash = next(iter(context.contract["asset_hashes"].values()))
    records = []
    cumulative_requests: list[str] = []
    cumulative_responses: list[str] = []
    cumulative_image_hashes: list[str] = []
    for index, (request, response) in enumerate(zip(requests, responses, strict=True), start=1):
        record = {
            "call_index": index,
            "query_action_index": index,
            "request_sha256": _sha_text(request),
            "response_sha256": _sha_text(response),
            "action_sha256": _sha_text(f"planner action {index}"),
            "action_source": "planner",
            "turns": [{"text": request, "images": ["fixture_asset"] if index == 1 else []}],
            "response": response,
            "image_content_sha256": [asset_hash] if index == 1 else [],
            "score": 2,
            "error": "",
        }
        if not legacy:
            current_image_hashes = [asset_hash] if index == 1 else []
            cumulative_requests.append(request)
            cumulative_responses.append(response)
            cumulative_image_hashes.extend(current_image_hashes)
            cumulative_request = "\n\n".join(
                f"Turn {turn} user:\n{value}"
                for turn, value in enumerate(cumulative_requests, start=1)
            )
            cumulative_response = "\n\n".join(
                f"Turn {turn} assistant:\n{value}"
                for turn, value in enumerate(cumulative_responses, start=1)
            )
            artifact = _axis_artifact(request, response)
            cumulative_artifact = _axis_artifact(
                cumulative_request,
                cumulative_response,
            )
            policy = "a" * 64
            individual_bundle = _sha_text(f"bundle:{index}:individual")
            cumulative_bundle = _sha_text(f"bundle:{index}:cumulative")
            artifact["input_provenance"].update(
                {
                    "image_count": len(current_image_hashes),
                    "ordered_image_content_sha256": current_image_hashes,
                    "media_transform_policy_sha256": policy,
                    "multimodal_bundle_sha256": individual_bundle,
                    "raw_media_included": False,
                }
            )
            cumulative_artifact["input_provenance"].update(
                {
                    "image_count": len(cumulative_image_hashes),
                    "ordered_image_content_sha256": list(
                        cumulative_image_hashes
                    ),
                    "media_transform_policy_sha256": policy,
                    "multimodal_bundle_sha256": cumulative_bundle,
                    "raw_media_included": False,
                }
            )
            record.update(
                {
                    "attack_validity_score": 1,
                    "benchmark_policy_score": 2,
                    "capability_harm_score": 1,
                    "strict_success": False,
                    "individual_axis_scores": artifact,
                    "cumulative_axis_scores": cumulative_artifact,
                    "effective_score_source": "individual_higher_benchmark",
                    "judge_protocol": ARMOR_JUDGE_PROTOCOL,
                    "ordered_image_content_sha256": current_image_hashes,
                    "cumulative_ordered_image_content_sha256": list(
                        cumulative_image_hashes
                    ),
                    "individual_multimodal_bundle_sha256": individual_bundle,
                    "cumulative_multimodal_bundle_sha256": cumulative_bundle,
                    "media_transform_policy_sha256": policy,
                    "raw_media_included": False,
                    "response_independent_validity": True,
                    "validity_payload_sha256": artifact["input_provenance"][
                        "validity_payload_sha256"
                    ],
                    "validity_multimodal_bundle_sha256": artifact[
                        "input_provenance"
                    ]["validity_multimodal_bundle_sha256"],
                }
            )
        records.append(record)
    if legacy:
        records = records[:1]
    provenance = dict(context.expected_stage0_provenance)
    provenance.update(provenance_overrides or {})
    return {
        "behavior": {"id": context.behavior.behavior_id, "text": "ephemeral source text"},
        "history": records,
        "instrumentation": {
            "schema_version": 3,
            "history_unit": "target_generation_response",
            "budget_unit": "target_generation_call",
            "target_call_budget": context.target_call_budget,
            "target_calls_started": len(records),
            "termination_reason": "strict_success" if legacy else "budget_exhausted",
            "censoring": {"is_censored": False, "reasons": [], "unknown_response_count": 0},
            "response_events": [
                {
                    "call_index": record["call_index"],
                    "request_sha256": record["request_sha256"],
                    "response_sha256": record["response_sha256"],
                    "error": record["error"],
                }
                for record in records
            ],
            "provenance": {
                "base_seed": context.attacker_seed,
                "initial_retrieval_sha256": context.contract[
                    "initial_retrieval_sha256"
                ],
                "first_target_request_sha256": records[0]["request_sha256"],
                "first_target_action_sha256": records[0]["action_sha256"],
                "asset_content_sha256": [asset_hash],
            },
            "planner_fallback": {
                "configured_policy_sha256": context.contract[
                    "fallback_policy_sha256"
                ],
                "attempted": False,
                "target_call_count": 0,
                "failure_reason": None,
            },
            "stage0_provenance": provenance,
        },
    }


def test_dry_run_resolves_all_contracts_without_model_calls_or_working_memory(tmp_path: Path):
    plan, root, _, behavior, prompts, memory = _fixture(tmp_path)
    calls = []
    orchestrator = Stage0LiveOrchestrator(
        prepared_root=root,
        behavior_resolver=behavior,
        arm_prompt_resolver=prompts,
        memory_snapshot_resolver=memory,
        run_callable=lambda context: calls.append(context),
    )
    report = orchestrator.dry_run()
    assert report["model_calls"] == 0
    assert report["servers_started"] is False
    assert calls == []
    assert [item["run_id"] for item in report["run_order"]] == [
        run["run_id"] for run in plan.runs
    ]
    assert not list(root.glob("runs/*/memory/working_memory.snapshot"))


def test_execute_enforces_frozen_order_and_writes_four_eligible_results(tmp_path: Path):
    plan, root, expected_prompts, behavior, prompts, memory = _fixture(tmp_path)
    contexts = []

    def fake_run(context):
        contexts.append(context)
        assert context.workers == 1
        assert context.attacker_seed == context.contract["attacker_seed"]
        assert context.target_call_budget == context.contract["target_call_budget"]
        assert context.installed_system_prompt == expected_prompts[context.contract["arm"]]
        assert context.immutable_initial_memory_path != context.working_memory_path
        with context.working_memory_path.open("ab") as handle:
            handle.write(str(context.contract["arm"]).encode())
        return _instrumented_row(context)

    orchestrator = Stage0LiveOrchestrator(
        prepared_root=root,
        behavior_resolver=behavior,
        arm_prompt_resolver=prompts,
        memory_snapshot_resolver=memory,
        run_callable=fake_run,
    )
    records = orchestrator.execute()
    assert [context.contract["run_id"] for context in contexts] == [
        run["run_id"] for run in plan.runs
    ]
    assert [record.status for record in records] == ["complete"] * 4
    assert len({context.output_dir for context in contexts}) == 4
    assert len({context.working_memory_path for context in contexts}) == 4
    results = load_results(root, plan)
    assert len(results) == 4
    assert audit_results(plan, results)["protocol_gate_pass"] is True
    serialized = "\n".join(path.read_text() for path in root.glob("runs/*/result.json"))
    assert "first request" not in serialized
    assert "first response" not in serialized
    assert "ephemeral source text" not in serialized

    def must_not_run(_context):
        raise AssertionError("completed results must resume without model calls")

    resumed = Stage0LiveOrchestrator(
        prepared_root=root,
        behavior_resolver=behavior,
        arm_prompt_resolver=prompts,
        memory_snapshot_resolver=memory,
        run_callable=must_not_run,
    ).execute()
    assert [record.status for record in resumed] == ["resumed"] * 4


def test_workers_other_than_one_are_rejected(tmp_path: Path):
    _, root, _, behavior, prompts, memory = _fixture(tmp_path)
    with pytest.raises(Stage0OrchestrationError, match="workers=1"):
        Stage0LiveOrchestrator(
            prepared_root=root,
            behavior_resolver=behavior,
            arm_prompt_resolver=prompts,
            memory_snapshot_resolver=memory,
            run_callable=lambda _context: {},
            workers=2,
        )


def test_prompt_or_asset_hash_drift_fails_before_model_call(tmp_path: Path):
    _, root, _, behavior, _, memory = _fixture(tmp_path)
    model_calls = []
    bad_prompt = lambda _arm: ResolvedPrompt(text="drifted", token_count=2)
    orchestrator = Stage0LiveOrchestrator(
        prepared_root=root,
        behavior_resolver=behavior,
        arm_prompt_resolver=bad_prompt,
        memory_snapshot_resolver=memory,
        run_callable=lambda context: model_calls.append(context),
    )
    with pytest.raises(Stage0OrchestrationError, match="prompt hash mismatch"):
        orchestrator.execute()
    assert model_calls == []
    assert not list(root.glob("runs/*/result.json"))


@pytest.mark.parametrize("dependency", ["asset", "memory"])
def test_asset_or_memory_snapshot_drift_fails_before_model_call(
    tmp_path: Path, dependency: str
):
    _, root, _, behavior, prompts, memory = _fixture(tmp_path)
    model_calls = []

    def bad_behavior(behavior_id: str) -> ResolvedBehavior:
        resolved = behavior(behavior_id)
        return ResolvedBehavior(
            behavior_id=resolved.behavior_id,
            value=resolved.value,
            assets={"fixture_asset": b"drifted asset"},
        )

    orchestrator = Stage0LiveOrchestrator(
        prepared_root=root,
        behavior_resolver=bad_behavior if dependency == "asset" else behavior,
        arm_prompt_resolver=prompts,
        memory_snapshot_resolver=(
            (lambda _digest: b"drifted memory") if dependency == "memory" else memory
        ),
        run_callable=lambda context: model_calls.append(context),
    )
    with pytest.raises(Stage0OrchestrationError, match=f"{dependency} hash mismatch"):
        orchestrator.execute()
    assert model_calls == []
    assert not list(root.glob("runs/*/result.json"))


@pytest.mark.parametrize(
    ("field", "value"),
    [("attacker_seed", 999999), ("initial_retrieval_sha256", "0" * 64)],
)
def test_observed_seed_or_retrieval_provenance_drift_writes_no_result(
    tmp_path: Path, field: str, value
):
    _, root, _, behavior, prompts, memory = _fixture(tmp_path)

    def bad_run(context):
        return _instrumented_row(
            context,
            provenance_overrides={field: value},
        )

    orchestrator = Stage0LiveOrchestrator(
        prepared_root=root,
        behavior_resolver=behavior,
        arm_prompt_resolver=prompts,
        memory_snapshot_resolver=memory,
        run_callable=bad_run,
    )
    with pytest.raises(Stage0OrchestrationError, match="evidence rejected"):
        orchestrator.execute()
    assert not list(root.glob("runs/*/result.json"))


@pytest.mark.parametrize("drift", ["first_action", "response_asset"])
def test_observed_first_action_or_response_asset_drift_writes_no_result(
    tmp_path: Path, drift: str
):
    _, root, _, behavior, prompts, memory = _fixture(tmp_path)

    def bad_run(context):
        row = _instrumented_row(context)
        if drift == "first_action":
            changed = "changed first request"
            row["history"][0]["turns"][0]["text"] = changed
            row["history"][0]["request_sha256"] = _sha_text(changed)
            row["instrumentation"]["response_events"][0]["request_sha256"] = _sha_text(
                changed
            )
        else:
            row["history"][0]["image_content_sha256"] = ["0" * 64]
        return row

    orchestrator = Stage0LiveOrchestrator(
        prepared_root=root,
        behavior_resolver=behavior,
        arm_prompt_resolver=prompts,
        memory_snapshot_resolver=memory,
        run_callable=bad_run,
    )
    with pytest.raises(Stage0OrchestrationError, match="evidence rejected"):
        orchestrator.execute()
    assert not list(root.glob("runs/*/result.json"))


def test_legacy_single_judge_is_written_censored_then_execution_stops(tmp_path: Path):
    plan, root, _, behavior, prompts, memory = _fixture(tmp_path)
    orchestrator = Stage0LiveOrchestrator(
        prepared_root=root,
        behavior_resolver=behavior,
        arm_prompt_resolver=prompts,
        memory_snapshot_resolver=memory,
        run_callable=lambda context: _instrumented_row(context, legacy=True),
    )
    with pytest.raises(Stage0OrchestrationError, match="incomplete evidence written"):
        orchestrator.execute()
    results = load_results(root, plan)
    assert len(results) == 1
    assert results[0]["censored"] is True
    assert results[0]["termination_reason"] == "judge_error"
    assert results[0]["target_calls"][0]["judge"]["capability_harm_score"] is None
