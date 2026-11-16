from __future__ import annotations

import json
from collections import Counter

from scripts.build_memory_explorer_data import (
    DEFAULT_OUTPUT,
    DEFAULT_SOURCE,
    build_memory_explorer_data,
    check_output,
    render_memory_explorer_data,
)


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {
            key for child in value.values() for key in _all_keys(child)
        }
    if isinstance(value, list):
        return {key for child in value for key in _all_keys(child)}
    return set()


def test_memory_explorer_projection_is_complete_and_payload_free() -> None:
    data = build_memory_explorer_data(DEFAULT_SOURCE)

    assert data["schema_version"] == "memory-explorer-v1"
    assert data["payload_policy"] == {
        "raw_attack_payload_included": False,
        "raw_target_response_included": False,
        "raw_judge_reason_included": False,
        "behavior_identifier_included": False,
        "dataset_instance_index_included": False,
        "local_path_included": False,
        "projection_rule": "explicit_field_allowlist_only",
    }
    assert data["counts"] == {
        "final_slots": 101,
        "episode_decisions": 220,
        "transitions": 307,
        "retrieval_records": 555,
        "target_query_records": 520,
        "event_ledger_records": 2042,
        "strict_success_episodes": 80,
        "episodes_without_trajectory": 7,
    }
    assert len(data["slots"]) == 101
    assert len(data["episodes"]) == 220
    assert len(data["transitions"]) == 307
    assert len({row["slot_id"] for row in data["slots"]}) == 101
    assert len({row["episode_id"] for row in data["episodes"]}) == 220
    assert len({row["transition_id"] for row in data["transitions"]}) == 307

    assert data["pack_id"] == data["source"]["pack_id"]
    assert data["summary"]["pack_id"] == data["source"]["pack_id"]
    assert data["summary"]["counts"] == {
        "slots": 101,
        "episodes": 220,
        "transitions": 307,
        "review_items": 7,
    }
    assert data["compatibility_aliases"] == {
        "pack_id": "Exact alias of source.pack_id for simple browser clients.",
        "summary": "Small projection of canonical source, counts, metrics, and review_queue metadata; it contains no record arrays.",
        "tasks": "Field-renamed projection of review_queue.items; review_queue remains canonical.",
    }

    assert Counter(row["memory_decision"] for row in data["episodes"]) == {
        "insert_new_slot": 101,
        "replace_strictly_higher_score": 15,
        "reject_equal_score_first_writer_kept": 53,
        "reject_lower_score": 44,
        "no_trajectory": 7,
    }
    assert Counter(row["family"] for row in data["slots"]) == {
        "adaptive_trajectory": 37,
        "structured_transformation": 26,
        "social_document_framing": 22,
        "cross_modal_obfuscation": 12,
        "fragmentation_and_many_shot": 4,
    }

    forbidden_keys = {
        "behavior",
        "behavior_id",
        "behavior_text",
        "instance_index",
        "prompt",
        "raw_prompt",
        "target_response",
        "response",
        "judge_reason",
        "reason",
        "reflection",
        "turns",
        "steps",
        "image_path",
        "local_path",
    }
    assert not (_all_keys(data) & forbidden_keys)

    rendered = render_memory_explorer_data(data).decode("utf-8")
    for forbidden_path in ("/home/", "/data1/", "/tmp/", "file://"):
        assert forbidden_path not in rendered


def test_review_queue_is_evidence_driven_and_filterable() -> None:
    data = build_memory_explorer_data(DEFAULT_SOURCE)
    queue = {item["id"]: item for item in data["review_queue"]["items"]}

    assert queue["review-missing-trajectories"]["affected_count"] == 7
    assert queue["review-retrieval-lineage"]["affected_count"] == 186
    assert queue["review-retrieval-lineage"]["affected_event_count"] == 555
    assert queue["review-transition-causality"]["affected_count"] == 307
    assert queue["review-feedback-exposure"]["affected_count"] == 307
    assert queue["review-survivor-bias"]["affected_count"] == 101
    assert queue["review-family-coverage"]["affected_count"] == 4
    assert queue["review-family-coverage"]["family_labels"] == [
        "fragmentation_and_many_shot"
    ]

    assert sum(
        "missing_trajectory_evidence" in row["review_flags"]
        for row in data["episodes"]
    ) == 7
    assert sum(
        "retrieval_lineage_not_attested" in row["review_flags"]
        for row in data["episodes"]
    ) == 186
    assert all(
        "transition_dependency_inferred" in row["review_flags"]
        and "feedback_exposure_inferred" in row["review_flags"]
        for row in data["transitions"]
    )

    assert len(data["tasks"]) == len(data["review_queue"]["items"])
    for task, item in zip(data["tasks"], data["review_queue"]["items"]):
        assert task["task_id"] == item["id"]
        assert task["canonical_review_id"] == item["id"]
        assert task["gap"] == item["evidence_gap"]
        assert task["recommended_action"] == item["recommended_next_action"]
        assert task["affected_count"] == item["affected_count"]


def test_committed_memory_explorer_data_is_deterministic_and_in_sync() -> None:
    first = render_memory_explorer_data(build_memory_explorer_data(DEFAULT_SOURCE))
    second = render_memory_explorer_data(build_memory_explorer_data(DEFAULT_SOURCE))

    assert first == second
    assert check_output(DEFAULT_OUTPUT, first)
    parsed = json.loads(DEFAULT_OUTPUT.read_text(encoding="utf-8"))
    assert parsed["source"]["pack_id"] == (
        "qwen2.5-vl-3b-public-v2-round1-payload-free"
    )
