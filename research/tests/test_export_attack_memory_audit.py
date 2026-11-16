from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest

from scripts.export_attack_memory_audit import export_pack
from scripts.verify_attack_memory_audit import verify_pack


def _query(
    step: int,
    strategy: str,
    score: int,
    marker: str,
    *,
    error: str = "",
) -> dict[str, object]:
    return {
        "step": step,
        "strategy": strategy,
        "turns": [{"text": f"private turn {marker}", "images": []}],
        "response": f"private target response {marker}",
        "score": score,
        "reason": f"private judge rationale {marker}",
        "error": error,
    }


def _trajectory(behavior_id: str, score: int, queries: int, marker: str) -> dict[str, object]:
    return {
        "behavior_id": behavior_id,
        "behavior": f"private behavior {marker}",
        "risk_category": "General Harm",
        "strategy": "scenario_playing",
        "best_score": score,
        "queries": queries,
        "steps": [f"private step {marker}"] * queries,
        "reflection": f"private reflection {marker} that must never be public",
        "success": score >= 5,
    }


def _write_fixture(root: Path) -> tuple[Path, Path, Path]:
    root.mkdir(parents=True, exist_ok=True)
    first_query = _query(1, "scenario_playing", 1, "first")
    second_a = _query(
        1,
        "news_report",
        1,
        "second-a",
        error="private backend exception that must never be public",
    )
    second_b = _query(2, "scenario_playing", 5, "second-b")
    first_trajectory = _trajectory("advbench:private:first", 1, 1, "first")
    final_trajectory = _trajectory("salad:private:second", 5, 2, "second")
    rows = [
        {
            "behavior": {
                "id": "advbench:private:first",
                "text": "private source behavior first",
                "risk_category": "General Harm",
                "sector": "test",
            },
            "best_query": first_query,
            "best_score": 1,
            "epsilon": 1.0,
            "history": [first_query],
            "instance_index": 0,
            "queries": 1,
            "retrieved": [],
            "steps": 1,
            "success": False,
            "trajectory": first_trajectory,
            "used_memory": False,
        },
        {
            "behavior": {
                "id": "salad:private:second",
                "text": "private source behavior second",
                "risk_category": "General Harm",
                "sector": "test",
            },
            "best_query": second_b,
            "best_score": 5,
            "epsilon": 0.5,
            "history": [second_a, second_b],
            "instance_index": 1,
            "queries": 2,
            "retrieved": ["General Harm/scenario_playing"],
            "steps": 2,
            "success": True,
            "trajectory": final_trajectory,
            "used_memory": True,
        },
        {
            "behavior": {
                "id": "harmbench:private:third",
                "text": "private source behavior third",
                "risk_category": "Cyber Harm",
                "sector": "test",
            },
            "best_query": None,
            "best_score": 0,
            "epsilon": 0.1,
            "history": [],
            "instance_index": 2,
            "queries": 0,
            "retrieved": [],
            "steps": 0,
            "success": False,
            "trajectory": None,
            "used_memory": False,
        },
    ]
    memory_path = root / "memory.json"
    results_path = root / "results.jsonl"
    manifest_path = root / "memory_manifest.json"
    memory_path.write_text(
        json.dumps([final_trajectory], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    results_path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    memory_sha = hashlib.sha256(memory_path.read_bytes()).hexdigest()
    manifest_path.write_text(
        json.dumps(
            {
                "memory_sha256": memory_sha,
                "target": "fixture-target",
                "model_id": "fixture-model",
                "model_revision": "fixture-revision",
                "promoted_at": "2026-01-01T00:00:00Z",
                "warmup": {
                    "seed": 7,
                    "workers": 1,
                    "memory_mode": "epsilon_greedy",
                    "memory_in": None,
                    "embedder_model": "fixture-embedder",
                    "embedder_revision": "fixture-embedder-revision",
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return memory_path, results_path, manifest_path


def _files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_export_is_payload_free_replayable_and_deterministic(tmp_path: Path) -> None:
    memory, results, manifest = _write_fixture(tmp_path / "source")
    first = tmp_path / "first"
    second = tmp_path / "second"

    export_pack(
        memory_path=memory,
        results_path=results,
        manifest_path=manifest,
        output=first,
    )
    export_pack(
        memory_path=memory,
        results_path=results,
        manifest_path=manifest,
        output=second,
    )

    assert _files(first) == _files(second)
    verification = verify_pack(first)
    assert verification["artifacts_verified"] == 11
    assert verification["event_hash_chain_valid"] is True
    assert verification["cross_format_counts_valid"] is True
    summary = json.loads((first / "json/collection_summary.json").read_text())
    assert summary["counts"] == {
        "actual_attack_success_rate": 0.33333333,
        "actual_strict_successes": 1,
        "episodes": 3,
        "episodes_using_memory": 1,
        "episodes_without_trajectory": 1,
        "event_ledger_records": 14,
        "final_memory_slots": 1,
        "final_success_slot_fraction_not_asr": 1.0,
        "final_success_slots": 1,
        "query_to_query_transitions": 1,
        "retrieval_label_records": 1,
        "target_query_records": 3,
        "trajectory_candidates": 2,
        "unique_behaviors": 3,
    }
    assert summary["verification"]["payload_leakage_gate"] == "passed"

    with (first / "csv/memory_updates.csv").open(newline="", encoding="utf-8") as handle:
        updates = list(csv.DictReader(handle))
    assert [row["memory_decision"] for row in updates] == [
        "insert_new_slot",
        "replace_strictly_higher_score",
        "no_trajectory",
    ]

    with (first / "csv/queries.csv").open(newline="", encoding="utf-8") as handle:
        queries = list(csv.DictReader(handle))
    assert [row["has_error"] for row in queries] == ["False", "True", "False"]
    assert [row["error_class"] for row in queries] == [
        "none",
        "legacy_error_present",
        "none",
    ]
    assert {
        row["feedback_exposure_evidence"] for row in queries
    } == {"implementation_inferred_unversioned_not_runtime_attested"}

    with (first / "csv/transitions.csv").open(newline="", encoding="utf-8") as handle:
        transitions = list(csv.DictReader(handle))
    assert len(transitions) == 1
    assert transitions[0]["episode_id"] == "episode-000002"
    assert transitions[0]["feedback_exposure_evidence"] == (
        "implementation_inferred_unversioned_not_runtime_attested"
    )

    public_blob = b"\n".join(_files(first).values()).decode("utf-8")
    for forbidden in (
        "advbench:private:first",
        "salad:private:second",
        "harmbench:private:third",
        "private target response",
        "private judge rationale",
        "private reflection",
        "private source behavior",
        "private backend exception",
    ):
        assert forbidden not in public_blob


def test_export_rejects_unexpected_preexisting_files(tmp_path: Path) -> None:
    memory, results, manifest = _write_fixture(tmp_path / "source")
    output = tmp_path / "output"
    output.mkdir()
    (output / "stale-private-payload.json").write_text("do not keep me")

    with pytest.raises(ValueError, match="unexpected files"):
        export_pack(
            memory_path=memory,
            results_path=results,
            manifest_path=manifest,
            output=output,
        )
