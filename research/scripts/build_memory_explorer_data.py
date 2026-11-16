#!/usr/bin/env python3
"""Build the deterministic, payload-free data projection used by the site.

The public attack-memory audit pack is already payload-free.  This builder
applies a second, narrower allowlist for browser publication: it keeps only
aggregate provenance, controlled labels, scores, occurrence IDs, insertion
decisions, and evidence-status flags.  It never copies behavior identifiers,
dataset row indices, prompts, turns, model responses, judge reasons,
reflections, media paths, or local filesystem paths.

The output is descriptive evidence for human review.  It is not an official
ARMS reproduction, a defense prompt, or evidence that an inferred transition
is causal.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "memory-explorer-v1"
BUILDER_VERSION = "1.0.0"

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = PROJECT_ROOT / "research" / "artifacts" / "attack-memory-v1"
DEFAULT_OUTPUT = PROJECT_ROOT / "dist" / "data" / "memory-explorer-v1.json"

SOURCE_FILES = (
    "manifest.json",
    "json/collection_summary.json",
    "csv/episodes.csv",
    "csv/final_slots.csv",
    "csv/retrievals.csv",
    "csv/transitions.csv",
)

FORBIDDEN_OUTPUT_KEYS = {
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

EPISODE_REQUIRED_FIELDS = {
    "episode_ordinal",
    "episode_id",
    "source_dataset",
    "risk_category",
    "epsilon",
    "used_memory",
    "retrieval_count",
    "query_count",
    "total_user_turns",
    "has_multi_turn_candidate",
    "strategy_sequence",
    "family_sequence",
    "score_sequence",
    "score_delta_sequence",
    "strategy_switches",
    "family_switches",
    "best_score",
    "strict_success",
    "trajectory_present",
    "candidate_strategy",
    "candidate_family",
    "memory_slot_id",
    "memory_decision",
    "memory_accepted",
    "previous_slot_score",
    "candidate_finally_retained",
}

SLOT_REQUIRED_FIELDS = {
    "slot_id",
    "risk_category",
    "strategy",
    "family",
    "source_dataset",
    "best_score",
    "success",
    "queries",
    "step_count",
    "final_entry_id",
    "slot_version",
    "candidate_count",
    "accepted_write_count",
    "replacement_count",
    "rejected_equal_count",
    "rejected_lower_count",
    "final_selected_episode_id",
    "source_trace_matched",
}

TRANSITION_REQUIRED_FIELDS = {
    "transition_id",
    "episode_id",
    "transition_ordinal",
    "from_query_id",
    "to_query_id",
    "from_strategy",
    "to_strategy",
    "from_family",
    "to_family",
    "operator",
    "from_score",
    "to_score",
    "score_delta",
    "reached_strict_success",
    "target_response_exposed",
    "judge_score_exposed",
    "judge_reason_exposed",
    "response_prefix_limit_chars",
    "feedback_exposure_evidence",
    "dependency_evidence",
}

RETRIEVAL_REQUIRED_FIELDS = {
    "episode_id",
    "retrieved_item_id",
    "retrieval_score",
    "lineage_status",
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{path.name}: expected a JSON object")
    return value


def _read_csv(path: Path, required_fields: set[str]) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or ())
        missing = sorted(required_fields - fields)
        if missing:
            raise ValueError(f"{path.name}: missing required fields: {missing}")
        return list(reader)


def _boolean(value: str, *, field: str) -> bool:
    if value == "True":
        return True
    if value == "False":
        return False
    raise ValueError(f"{field}: expected True or False, got {value!r}")


def _optional_text(value: str) -> str | None:
    return value or None


def _optional_int(value: str, *, field: str) -> int | None:
    return int(value) if value else None


def _text_sequence(value: str) -> list[str]:
    return value.split("|") if value else []


def _int_sequence(value: str) -> list[int]:
    return [int(item) for item in value.split("|")] if value else []


def _verify_source_files(source: Path, manifest: Mapping[str, Any]) -> None:
    if manifest.get("raw_attack_payload_included") is not False:
        raise ValueError("source manifest must explicitly exclude raw attack payloads")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping):
        raise ValueError("source manifest is missing the artifact table")

    for relative in SOURCE_FILES:
        path = source / relative
        if not path.is_file():
            raise FileNotFoundError(path)
        if relative == "manifest.json":
            continue
        record = artifacts.get(relative)
        if not isinstance(record, Mapping):
            raise ValueError(f"source manifest has no record for {relative}")
        expected = record.get("sha256")
        actual = _sha256_file(path)
        if actual != expected:
            raise ValueError(
                f"source hash mismatch for {relative}: expected {expected}, got {actual}"
            )


def _assert_unique(rows: Iterable[Mapping[str, Any]], field: str) -> None:
    values = [row[field] for row in rows]
    duplicates = sorted(value for value, count in Counter(values).items() if count > 1)
    if duplicates:
        raise ValueError(f"duplicate {field} values: {duplicates[:5]}")


def _validate_counts(
    summary: Mapping[str, Any],
    episodes: list[dict[str, str]],
    slots: list[dict[str, str]],
    retrievals: list[dict[str, str]],
    transitions: list[dict[str, str]],
) -> None:
    counts = summary.get("counts")
    if not isinstance(counts, Mapping):
        raise ValueError("collection summary is missing counts")

    observed = {
        "episodes": len(episodes),
        "final_memory_slots": len(slots),
        "retrieval_label_records": len(retrievals),
        "query_to_query_transitions": len(transitions),
        "target_query_records": sum(int(row["query_count"]) for row in episodes),
        "episodes_using_memory": sum(
            _boolean(row["used_memory"], field="used_memory") for row in episodes
        ),
        "episodes_without_trajectory": sum(
            not _boolean(row["trajectory_present"], field="trajectory_present")
            for row in episodes
        ),
        "trajectory_candidates": sum(
            _boolean(row["trajectory_present"], field="trajectory_present")
            for row in episodes
        ),
        "actual_strict_successes": sum(
            _boolean(row["strict_success"], field="strict_success") for row in episodes
        ),
        "final_success_slots": sum(
            _boolean(row["success"], field="success") for row in slots
        ),
    }
    for key, value in observed.items():
        if counts.get(key) != value:
            raise ValueError(
                f"count mismatch for {key}: summary={counts.get(key)!r}, observed={value}"
            )

    expected_transitions = sum(max(int(row["query_count"]) - 1, 0) for row in episodes)
    if expected_transitions != len(transitions):
        raise ValueError(
            "transition count does not equal the sum of per-episode ordered query edges"
        )
    if sum(int(row["retrieval_count"]) for row in episodes) != len(retrievals):
        raise ValueError("retrieval count does not equal the per-episode retrieval total")

    _assert_unique(episodes, "episode_id")
    _assert_unique(slots, "slot_id")
    _assert_unique(transitions, "transition_id")


def _episode_projection(row: Mapping[str, str]) -> dict[str, Any]:
    flags: list[str] = []
    trajectory_present = _boolean(
        row["trajectory_present"], field="trajectory_present"
    )
    retrieval_count = int(row["retrieval_count"])
    if not trajectory_present:
        flags.append("missing_trajectory_evidence")
    if retrieval_count:
        flags.append("retrieval_lineage_not_attested")

    return {
        "episode_ordinal": int(row["episode_ordinal"]),
        "episode_id": row["episode_id"],
        "source_dataset": row["source_dataset"],
        "risk_category": row["risk_category"],
        "epsilon": float(row["epsilon"]),
        "used_memory": _boolean(row["used_memory"], field="used_memory"),
        "retrieval_count": retrieval_count,
        "query_count": int(row["query_count"]),
        "total_user_turns": int(row["total_user_turns"]),
        "has_multi_turn_candidate": _boolean(
            row["has_multi_turn_candidate"], field="has_multi_turn_candidate"
        ),
        "strategy_sequence": _text_sequence(row["strategy_sequence"]),
        "family_sequence": _text_sequence(row["family_sequence"]),
        "score_sequence": _int_sequence(row["score_sequence"]),
        "score_delta_sequence": _int_sequence(row["score_delta_sequence"]),
        "strategy_switches": int(row["strategy_switches"]),
        "family_switches": int(row["family_switches"]),
        "best_score": int(row["best_score"]),
        "strict_success": _boolean(row["strict_success"], field="strict_success"),
        "trajectory_present": trajectory_present,
        "candidate_strategy": _optional_text(row["candidate_strategy"]),
        "candidate_family": _optional_text(row["candidate_family"]),
        "memory_slot_id": _optional_text(row["memory_slot_id"]),
        "memory_decision": row["memory_decision"],
        "memory_accepted": _boolean(row["memory_accepted"], field="memory_accepted"),
        "previous_slot_score": _optional_int(
            row["previous_slot_score"], field="previous_slot_score"
        ),
        "candidate_finally_retained": _boolean(
            row["candidate_finally_retained"], field="candidate_finally_retained"
        ),
        "review_flags": flags,
    }


def _slot_projection(
    row: Mapping[str, str], *, least_represented_families: set[str]
) -> dict[str, Any]:
    flags = (
        ["family_coverage_review"]
        if row["family"] in least_represented_families
        else []
    )
    return {
        "slot_id": row["slot_id"],
        "risk_category": row["risk_category"],
        "strategy": row["strategy"],
        "family": row["family"],
        "source_dataset": row["source_dataset"],
        "best_score": int(row["best_score"]),
        "success": _boolean(row["success"], field="success"),
        "queries": int(row["queries"]),
        "step_count": int(row["step_count"]),
        "final_entry_id": row["final_entry_id"],
        "slot_version": int(row["slot_version"]),
        "candidate_count": int(row["candidate_count"]),
        "accepted_write_count": int(row["accepted_write_count"]),
        "replacement_count": int(row["replacement_count"]),
        "rejected_equal_count": int(row["rejected_equal_count"]),
        "rejected_lower_count": int(row["rejected_lower_count"]),
        "final_selected_episode_id": row["final_selected_episode_id"],
        "source_trace_matched": _boolean(
            row["source_trace_matched"], field="source_trace_matched"
        ),
        "review_flags": flags,
    }


def _transition_projection(row: Mapping[str, str]) -> dict[str, Any]:
    flags: list[str] = []
    if row["dependency_evidence"] == "program_order_inferred_not_explicit_edge":
        flags.append("transition_dependency_inferred")
    if row["feedback_exposure_evidence"].endswith("not_runtime_attested"):
        flags.append("feedback_exposure_inferred")
    return {
        "transition_id": row["transition_id"],
        "episode_id": row["episode_id"],
        "transition_ordinal": int(row["transition_ordinal"]),
        "from_query_id": row["from_query_id"],
        "to_query_id": row["to_query_id"],
        "from_strategy": row["from_strategy"],
        "to_strategy": row["to_strategy"],
        "from_family": row["from_family"],
        "to_family": row["to_family"],
        "operator": row["operator"],
        "from_score": int(row["from_score"]),
        "to_score": int(row["to_score"]),
        "score_delta": int(row["score_delta"]),
        "reached_strict_success": _boolean(
            row["reached_strict_success"], field="reached_strict_success"
        ),
        "target_response_exposed": _boolean(
            row["target_response_exposed"], field="target_response_exposed"
        ),
        "judge_score_exposed": _boolean(
            row["judge_score_exposed"], field="judge_score_exposed"
        ),
        "judge_reason_exposed": _boolean(
            row["judge_reason_exposed"], field="judge_reason_exposed"
        ),
        "response_prefix_limit_chars": int(row["response_prefix_limit_chars"]),
        "feedback_exposure_evidence": row["feedback_exposure_evidence"],
        "dependency_evidence": row["dependency_evidence"],
        "review_flags": flags,
    }


def _sorted_counter(values: Iterable[str], *, label: str) -> list[dict[str, Any]]:
    return [
        {label: value, "count": count}
        for value, count in sorted(Counter(values).items(), key=lambda pair: pair[0])
    ]


def _review_queue(
    *,
    episodes: list[dict[str, Any]],
    slots: list[dict[str, Any]],
    retrievals: list[dict[str, str]],
    transitions: list[dict[str, Any]],
    least_represented_families: set[str],
) -> dict[str, Any]:
    no_trajectory = sum(
        "missing_trajectory_evidence" in row["review_flags"] for row in episodes
    )
    retrieval_episode_count = sum(
        "retrieval_lineage_not_attested" in row["review_flags"] for row in episodes
    )
    missing_retrieval_receipts = sum(
        not row["retrieved_item_id"] or not row["retrieval_score"]
        for row in retrievals
    )
    inferred_edges = sum(
        "transition_dependency_inferred" in row["review_flags"] for row in transitions
    )
    inferred_feedback = sum(
        "feedback_exposure_inferred" in row["review_flags"] for row in transitions
    )
    low_coverage_slots = sum(
        "family_coverage_review" in row["review_flags"] for row in slots
    )

    items = [
        {
            "id": "review-missing-trajectories",
            "priority": "high",
            "title": "Resolve episodes without a trajectory candidate",
            "record_type": "episode",
            "affected_count": no_trajectory,
            "filter": {"review_flag": "missing_trajectory_evidence"},
            "evidence_gap": "The public ledger records no selected trajectory for these episodes but does not attest why.",
            "recommended_next_action": "Audit the access-controlled runtime record and assign a pre-registered failure class without copying payload text into this public projection.",
            "completion_evidence": "A versioned, payload-free failure label plus annotator and policy manifest.",
        },
        {
            "id": "review-retrieval-lineage",
            "priority": "high",
            "title": "Attest retrieval item identity and similarity receipts",
            "record_type": "episode",
            "affected_count": retrieval_episode_count,
            "affected_event_count": missing_retrieval_receipts,
            "filter": {"review_flag": "retrieval_lineage_not_attested"},
            "evidence_gap": "Legacy retrieval rows preserve rank and controlled labels but not item IDs, similarity values, snapshots, or consumption receipts.",
            "recommended_next_action": "Add immutable retrieval receipts to a new run; do not retrofit identities into the sealed legacy artifact.",
            "completion_evidence": "A new-run retrieval ledger linking snapshot hash, item ID, score, rank, and consumer event.",
        },
        {
            "id": "review-transition-causality",
            "priority": "high",
            "title": "Replace program-order transition proxies with explicit edges",
            "record_type": "transition",
            "affected_count": inferred_edges,
            "filter": {"review_flag": "transition_dependency_inferred"},
            "evidence_gap": "Query order is preserved, but the legacy record has no explicit receipt proving that one response caused the next planner action.",
            "recommended_next_action": "Instrument a new run with response hash, planner-input receipt, parent event ID, and adaptation operation before testing causal claims.",
            "completion_evidence": "A versioned event schema with explicit parent IDs validated end to end.",
        },
        {
            "id": "review-feedback-exposure",
            "priority": "high",
            "title": "Attest exactly what feedback reached the attacker",
            "record_type": "transition",
            "affected_count": inferred_feedback,
            "filter": {"review_flag": "feedback_exposure_inferred"},
            "evidence_gap": "Feedback-exposure booleans come from an unversioned implementation inference rather than runtime receipts.",
            "recommended_next_action": "Record response, score, and rationale exposure as separate hashed receipts under pre-registered feedback policies.",
            "completion_evidence": "Per-turn runtime exposure receipts and a pinned producer commit.",
        },
        {
            "id": "review-producer-provenance",
            "priority": "high",
            "title": "Pin the producer implementation",
            "record_type": "global",
            "affected_count": 1,
            "filter": {"scope": "provenance"},
            "evidence_gap": "The sealed legacy manifest has no producer code commit.",
            "recommended_next_action": "Use a new run profile with a pinned commit and container or environment digest; never rewrite the sealed artifact.",
            "completion_evidence": "Run manifest containing code, configuration, model, and environment digests.",
        },
        {
            "id": "review-survivor-bias",
            "priority": "medium",
            "title": "Keep final-slot prevalence separate from episode attack success",
            "record_type": "slot",
            "affected_count": len(slots),
            "filter": {"scope": "all_slots"},
            "evidence_gap": "The final grid keeps per-slot winners and is therefore survivor-biased.",
            "recommended_next_action": "Report episode-level ASR from all episodes and label final-slot success only as a selected-memory composition statistic.",
            "completion_evidence": "Tables and figures that preserve both denominators and never relabel the slot fraction as ASR.",
        },
        {
            "id": "review-family-coverage",
            "priority": "medium",
            "title": "Review the least represented strategy family",
            "record_type": "slot",
            "affected_count": low_coverage_slots,
            "filter": {"review_flag": "family_coverage_review"},
            "evidence_gap": "The least represented family has limited final-slot coverage; this is a sampling flag, not an effectiveness conclusion.",
            "recommended_next_action": "Pre-register coverage quotas or a power-based sampling rule before collecting a new universal memory.",
            "completion_evidence": "A frozen sampling manifest with family quotas and inclusion rules.",
            "family_labels": sorted(least_represented_families),
        },
    ]
    return {
        "policy": "Queue items are derived from evidence gaps or denominator risks only; they are not attack or defense conclusions.",
        "annotation_storage": "browser_local_only",
        "annotation_statuses": [
            "unreviewed",
            "actionable",
            "needs_evidence",
            "reject",
            "reviewed",
        ],
        "annotation_fields": [
            "status",
            "defense_invariant",
            "predicted_adaptation",
            "benign_exception",
            "evaluation_task",
            "note",
        ],
        "counts_by_priority": [
            {"priority": priority, "count": count}
            for priority, count in sorted(
                Counter(item["priority"] for item in items).items()
            )
        ],
        "items": items,
    }


def _task_aliases(review_queue: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return the small, UI-compatible projection of canonical queue items."""

    tasks: list[dict[str, Any]] = []
    for item in review_queue["items"]:
        task = {
            "task_id": item["id"],
            "priority": item["priority"],
            "scope": item["record_type"],
            "gap": item["evidence_gap"],
            "affected_count": item["affected_count"],
            "recommended_action": item["recommended_next_action"],
            "canonical_review_id": item["id"],
        }
        if item.get("family_labels"):
            task["family"] = ", ".join(item["family_labels"])
        tasks.append(task)
    return tasks


def _assert_payload_free(value: Any, *, key_path: tuple[str, ...] = ()) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if key in FORBIDDEN_OUTPUT_KEYS:
                raise ValueError(
                    f"forbidden output key at {'.'.join((*key_path, key))}"
                )
            _assert_payload_free(child, key_path=(*key_path, key))
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _assert_payload_free(child, key_path=(*key_path, str(index)))
        return
    if isinstance(value, str):
        lowered = value.casefold()
        forbidden_fragments = ("/home/", "/data1/", "/tmp/", "file://")
        if any(fragment in lowered for fragment in forbidden_fragments):
            raise ValueError(
                f"local absolute path leaked at {'.'.join(key_path)}: {value!r}"
            )


def build_memory_explorer_data(source: Path = DEFAULT_SOURCE) -> dict[str, Any]:
    source = source.resolve()
    manifest = _read_json(source / "manifest.json")
    _verify_source_files(source, manifest)

    summary = _read_json(source / "json" / "collection_summary.json")
    if summary.get("raw_attack_payload_included") is not False:
        raise ValueError("collection summary must exclude raw attack payloads")

    episode_rows = _read_csv(source / "csv" / "episodes.csv", EPISODE_REQUIRED_FIELDS)
    slot_rows = _read_csv(source / "csv" / "final_slots.csv", SLOT_REQUIRED_FIELDS)
    retrieval_rows = _read_csv(
        source / "csv" / "retrievals.csv", RETRIEVAL_REQUIRED_FIELDS
    )
    transition_rows = _read_csv(
        source / "csv" / "transitions.csv", TRANSITION_REQUIRED_FIELDS
    )
    _validate_counts(summary, episode_rows, slot_rows, retrieval_rows, transition_rows)

    family_counts = Counter(row["family"] for row in slot_rows)
    minimum_family_count = min(family_counts.values())
    least_represented_families = {
        family for family, count in family_counts.items() if count == minimum_family_count
    }

    episodes = [_episode_projection(row) for row in episode_rows]
    slots = [
        _slot_projection(row, least_represented_families=least_represented_families)
        for row in slot_rows
    ]
    transitions = [_transition_projection(row) for row in transition_rows]

    counts = summary["counts"]
    source_artifacts = {
        relative: {
            "sha256": manifest["artifacts"][relative]["sha256"],
            "records": manifest["artifacts"][relative]["records"],
        }
        for relative in SOURCE_FILES
        if relative != "manifest.json"
    }
    source_artifacts["manifest.json"] = {
        "sha256": _sha256_file(source / "manifest.json"),
        "records": 1,
    }

    public_counts = {
        "final_slots": len(slots),
        "episode_decisions": len(episodes),
        "transitions": len(transitions),
        "retrieval_records": len(retrieval_rows),
        "target_query_records": counts["target_query_records"],
        "event_ledger_records": counts["event_ledger_records"],
        "strict_success_episodes": counts["actual_strict_successes"],
        "episodes_without_trajectory": counts["episodes_without_trajectory"],
    }
    public_metrics = {
        "episode_attack_success_rate": counts["actual_attack_success_rate"],
        "final_success_slots": counts["final_success_slots"],
        "final_success_slot_fraction_not_asr": counts[
            "final_success_slot_fraction_not_asr"
        ],
        "metric_boundary": "The final-slot fraction is survivor-biased and must not be reported as episode ASR.",
    }
    review_queue = _review_queue(
        episodes=episodes,
        slots=slots,
        retrievals=retrieval_rows,
        transitions=transitions,
        least_represented_families=least_represented_families,
    )

    data: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "builder_version": BUILDER_VERSION,
        "pack_id": summary["pack_id"],
        "purpose": "human_audit_and_review_workbench",
        "payload_policy": {
            "raw_attack_payload_included": False,
            "raw_target_response_included": False,
            "raw_judge_reason_included": False,
            "behavior_identifier_included": False,
            "dataset_instance_index_included": False,
            "local_path_included": False,
            "projection_rule": "explicit_field_allowlist_only",
        },
        "compatibility_aliases": {
            "pack_id": "Exact alias of source.pack_id for simple browser clients.",
            "summary": "Small projection of canonical source, counts, metrics, and review_queue metadata; it contains no record arrays.",
            "tasks": "Field-renamed projection of review_queue.items; review_queue remains canonical.",
        },
        "source": {
            "pack_id": summary["pack_id"],
            "schema_version": summary["schema_version"],
            "exporter_version": summary["exporter_version"],
            "purpose": summary["purpose"],
            "source_artifacts": source_artifacts,
            "source_sha256": manifest["source_sha256"],
            "verification": manifest["verification"],
        },
        "counts": public_counts,
        "metrics": public_metrics,
        "summary": {
            "pack_id": summary["pack_id"],
            "counts": {
                "slots": public_counts["final_slots"],
                "episodes": public_counts["episode_decisions"],
                "transitions": public_counts["transitions"],
                "review_items": len(review_queue["items"]),
            },
            "metrics": public_metrics,
            "review_policy": review_queue["policy"],
        },
        "filter_catalog": {
            "source_datasets": sorted({row["source_dataset"] for row in episodes}),
            "risk_categories": sorted({row["risk_category"] for row in episodes}),
            "strategies": sorted(
                {
                    strategy
                    for row in episodes
                    for strategy in row["strategy_sequence"]
                }
                | {row["strategy"] for row in slots}
            ),
            "families": sorted(family_counts),
            "memory_decisions": sorted({row["memory_decision"] for row in episodes}),
            "transition_operators": sorted({row["operator"] for row in transitions}),
            "review_flags": sorted(
                {
                    flag
                    for row in [*episodes, *slots, *transitions]
                    for flag in row["review_flags"]
                }
            ),
        },
        "distributions": {
            "episodes_by_dataset": _sorted_counter(
                (row["source_dataset"] for row in episodes), label="source_dataset"
            ),
            "episodes_by_risk_category": _sorted_counter(
                (row["risk_category"] for row in episodes), label="risk_category"
            ),
            "episodes_by_memory_decision": _sorted_counter(
                (row["memory_decision"] for row in episodes), label="memory_decision"
            ),
            "slots_by_family": [
                {
                    "family": family,
                    "slots": sum(row["family"] == family for row in slots),
                    "successful_slots": sum(
                        row["family"] == family and row["success"] for row in slots
                    ),
                }
                for family in sorted(family_counts)
            ],
        },
        "collection_contract": summary["collection_contract"],
        "collection_flow": summary["collection_flow"],
        "provenance": {
            "run": summary["run_provenance"],
            "verification": summary["verification"],
            "downstream_evaluation_contract": summary[
                "downstream_evaluation_contract"
            ],
            "claim_boundaries": [
                "This is a clean-room memory-adaptive attack audit projection, not an official ARMS implementation or reproduction.",
                "The source is one legacy Qwen2.5-VL-3B warm-up and is not cross-model evidence.",
                "Append order is a replay proxy, not attested wall-clock insertion order.",
                "Transition and feedback exposure fields are inferred unless explicitly marked otherwise.",
                "The payload-free browser projection cannot regenerate the private defense-prompt compiler input.",
            ],
        },
        "limitations": [
            *summary["known_limitations"],
            "This browser projection deliberately omits dataset row indices in addition to all raw payload fields.",
            "The source is a single 3B legacy run; generalization to other target sizes, models, or unseen attacks remains untested here.",
            "This is not an official ARMS code path and must not be described as an ARMS reproduction.",
        ],
        "review_queue": review_queue,
        "tasks": _task_aliases(review_queue),
        "slots": slots,
        "episodes": episodes,
        "transitions": transitions,
    }
    _assert_payload_free(data)
    return data


def render_memory_explorer_data(data: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def check_output(output: Path, expected: bytes) -> bool:
    return output.is_file() and output.read_bytes() == expected


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=DEFAULT_SOURCE,
        help="payload-free attack-memory audit pack",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="generated site JSON",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero instead of writing if the generated file is stale",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    data = build_memory_explorer_data(args.source)
    rendered = render_memory_explorer_data(data)
    if args.check:
        if check_output(args.out, rendered):
            print(
                f"memory explorer data is in sync: {args.out} "
                f"({len(data['slots'])} slots, {len(data['episodes'])} episodes, "
                f"{len(data['transitions'])} transitions)"
            )
            return 0
        expected = hashlib.sha256(rendered).hexdigest()
        actual = _sha256_file(args.out) if args.out.is_file() else "missing"
        print(
            f"memory explorer data is stale: {args.out} "
            f"(expected sha256={expected}, actual={actual})",
            file=sys.stderr,
        )
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(rendered)
    print(
        f"wrote {args.out} ({len(data['slots'])} slots, "
        f"{len(data['episodes'])} episodes, {len(data['transitions'])} transitions)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
