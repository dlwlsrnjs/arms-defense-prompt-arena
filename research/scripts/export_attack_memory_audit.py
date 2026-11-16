#!/usr/bin/env python3
"""Export a deterministic, payload-free audit pack for legacy attack memory.

The exporter replays the legacy ``(risk_category, strategy)`` winner grid from
the raw episode log.  It emits only hashes, controlled labels, counts, scores,
and insertion decisions; attack text, target responses, judge rationales,
reflections, media paths, and local source paths are never copied.

This is an audit/research export, not a replacement for the private source
artifacts and not sufficient by itself to regenerate a defense prompt.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "attack-memory-public-v1"
EXPORTER_VERSION = "1.0.0"

STRATEGY_FAMILIES: dict[str, str] = {
    "actor_attack": "adaptive_trajectory",
    "crescendo": "adaptive_trajectory",
    "narrative": "adaptive_trajectory",
    "scenario_playing": "adaptive_trajectory",
    "email_thread": "social_document_framing",
    "news_report": "social_document_framing",
    "slack_conversation": "social_document_framing",
    "flowchart": "structured_transformation",
    "numbered_list": "structured_transformation",
    "rule_based": "structured_transformation",
    "simulated_function_call": "structured_transformation",
    "acronym": "fragmentation_and_many_shot",
    "jigsaw_scramble": "fragmentation_and_many_shot",
    "many_shot_mixup": "fragmentation_and_many_shot",
    "multimodal_shuffling": "cross_modal_obfuscation",
    "multimodal_trigger_backdoor": "cross_modal_obfuscation",
    "photographic": "cross_modal_obfuscation",
}

EPISODE_FIELDS = (
    "episode_ordinal",
    "episode_id",
    "source_dataset",
    "risk_category",
    "instance_index",
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
)

SLOT_FIELDS = (
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
)

RETRIEVAL_FIELDS = (
    "retrieval_id",
    "episode_id",
    "retrieval_rank",
    "retrieved_risk_category",
    "retrieved_strategy",
    "retrieved_family",
    "retrieved_slot_id",
    "retrieved_item_id",
    "retrieval_score",
    "lineage_status",
)

QUERY_FIELDS = (
    "query_id",
    "episode_id",
    "query_ordinal",
    "recorded_step",
    "strategy",
    "family",
    "score",
    "strict_success",
    "user_turn_count",
    "image_reference_count",
    "has_error",
    "error_class",
    "selected_for_trajectory",
    "target_response_exposed",
    "judge_score_exposed",
    "judge_reason_exposed",
    "response_prefix_limit_chars",
    "feedback_exposure_evidence",
    "exposure_label",
)

TRANSITION_FIELDS = (
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
)

MEMORY_UPDATE_FIELDS = (
    "episode_id",
    "episode_ordinal",
    "insert_attempted",
    "memory_decision",
    "memory_accepted",
    "memory_slot_id",
    "candidate_entry_id",
    "previous_entry_id",
    "current_entry_id",
    "slot_version_before",
    "slot_version_after",
    "previous_slot_score",
    "candidate_score",
    "current_slot_score",
    "memory_size_before",
    "memory_size_after",
    "memory_head_before_sha256",
    "memory_head_after_sha256",
    "decision_evidence",
)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value))


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise TypeError(f"{path}:{line_number}: expected a JSON object")
            rows.append(value)
    return rows


def source_dataset(behavior_id: str) -> str:
    prefix = behavior_id.partition(":")[0].casefold()
    aliases = {
        "advbench": "AdvBench",
        "harmbench": "HarmBench",
        "salad": "SALAD-Bench",
    }
    return aliases.get(prefix, "UNKNOWN")


def family_for(strategy: str) -> str:
    return STRATEGY_FAMILIES.get(strategy, "unknown_strategy")


def slot_id(risk_category: str, strategy: str) -> str:
    value = {"risk_category": risk_category, "strategy": strategy}
    return "slot-" + sha256_json(value)[:16]


def episode_id(ordinal: int) -> str:
    return f"episode-{ordinal + 1:06d}"


def memory_state_sha256(
    slots: Mapping[tuple[str, str], Mapping[str, Any]],
    entry_ids: Mapping[tuple[str, str], str],
    slot_versions: Mapping[tuple[str, str], int],
) -> str:
    members = [
        {
            "slot_id": slot_id(category, strategy),
            "slot_version": slot_versions[(category, strategy)],
            "entry_id": entry_ids[(category, strategy)],
            "risk_category": category,
            "strategy": strategy,
            "family": family_for(strategy),
            "best_score": int(trajectory.get("best_score", 0)),
            "queries": int(trajectory.get("queries", 0)),
            "success": bool(trajectory.get("success", False)),
        }
        for (category, strategy), trajectory in sorted(slots.items())
    ]
    return sha256_json(members)


def transition_operator(
    previous_strategy: str,
    next_strategy: str,
) -> str:
    if previous_strategy == next_strategy:
        return "persist_or_refine_same_strategy"
    previous_family = family_for(previous_strategy)
    next_family = family_for(next_strategy)
    if previous_family == next_family:
        return "refine_within_family"
    if next_family == "adaptive_trajectory":
        return "switch_to_adaptive_trajectory"
    if next_family == "social_document_framing":
        return "reframe_as_social_document"
    if next_family == "structured_transformation":
        return "switch_to_structured_transformation"
    if next_family == "fragmentation_and_many_shot":
        return "fragment_or_many_shot"
    if next_family == "cross_modal_obfuscation":
        return "switch_to_cross_modal"
    return "switch_to_unknown_family"


def safe_query_record(
    query: Mapping[str, Any],
    *,
    episode_identifier: str,
    query_ordinal: int,
    vmax: int,
) -> dict[str, Any]:
    turns = query.get("turns") or []
    if not isinstance(turns, list):
        raise TypeError("history.turns must be a list")
    image_references = 0
    for turn in turns:
        if isinstance(turn, Mapping):
            images = turn.get("images") or []
            if isinstance(images, list):
                image_references += len(images)
    error = str(query.get("error", ""))
    strategy = str(query.get("strategy", ""))
    score = int(query.get("score", 0))
    return {
        "query_id": f"{episode_identifier}-q{query_ordinal + 1:02d}",
        "episode_id": episode_identifier,
        "query_ordinal": query_ordinal,
        "recorded_step": int(query.get("step", query_ordinal + 1)),
        "strategy": strategy,
        "family": family_for(strategy),
        "score": score,
        "strict_success": score >= vmax,
        "user_turn_count": len(turns),
        "image_reference_count": image_references,
        "has_error": bool(error),
        "error_class": "legacy_error_present" if error else "none",
        "target_response_exposed": True,
        "judge_score_exposed": True,
        "judge_reason_exposed": True,
        "response_prefix_limit_chars": 1200,
        "feedback_exposure_evidence": (
            "implementation_inferred_unversioned_not_runtime_attested"
        ),
        "exposure_label": "unlabeled_legacy",
        "selected_for_trajectory": False,
    }


def _counter_rows(counter: Counter[str]) -> list[dict[str, Any]]:
    return [
        {"label": label, "count": count}
        for label, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    ]


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]], fields: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
            writer.writeheader()
            for row in rows:
                writer.writerow({field: row.get(field, "") for field in fields})
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _append_event(
    events: list[dict[str, Any]],
    *,
    event_type: str,
    episode_identifier: str,
    payload: Mapping[str, Any],
) -> None:
    previous = events[-1]["event_sha256"] if events else None
    base = {
        "schema_version": SCHEMA_VERSION,
        "event_index": len(events),
        "event_type": event_type,
        "episode_id": episode_identifier,
        "previous_event_sha256": previous,
        **payload,
    }
    events.append({**base, "event_sha256": sha256_json(base)})


def _validate_event_chain(events: Sequence[Mapping[str, Any]]) -> None:
    previous: str | None = None
    for index, event in enumerate(events):
        if event.get("event_index") != index:
            raise ValueError(f"event index mismatch at {index}")
        if event.get("previous_event_sha256") != previous:
            raise ValueError(f"event predecessor mismatch at {index}")
        base = dict(event)
        claimed = str(base.pop("event_sha256"))
        actual = sha256_json(base)
        if claimed != actual:
            raise ValueError(f"event hash mismatch at {index}")
        previous = claimed


def _raw_payload_values(
    episodes: Iterable[Mapping[str, Any]],
    memory_rows: Iterable[Mapping[str, Any]],
) -> set[str]:
    values: set[str] = set()
    for episode in episodes:
        behavior = episode.get("behavior")
        if isinstance(behavior, Mapping):
            values.add(str(behavior.get("text", "")))
        for query in episode.get("history") or []:
            if not isinstance(query, Mapping):
                continue
            values.add(str(query.get("response", "")))
            values.add(str(query.get("reason", "")))
            for turn in query.get("turns") or []:
                if isinstance(turn, Mapping):
                    values.add(str(turn.get("text", "")))
        trajectory = episode.get("trajectory")
        if isinstance(trajectory, Mapping):
            values.add(str(trajectory.get("behavior", "")))
            values.add(str(trajectory.get("reflection", "")))
            values.update(str(step) for step in trajectory.get("steps") or [])
    for row in memory_rows:
        values.add(str(row.get("behavior", "")))
        values.add(str(row.get("reflection", "")))
        values.update(str(step) for step in row.get("steps") or [])
    return {value for value in values if len(value) >= 32}


def _assert_no_payload_leak(
    output_paths: Iterable[Path],
    episodes: Sequence[Mapping[str, Any]],
    memory_rows: Sequence[Mapping[str, Any]],
) -> None:
    public_text = "\n".join(
        path.read_text(encoding="utf-8", errors="strict") for path in output_paths
    )
    leaked = [value for value in _raw_payload_values(episodes, memory_rows) if value in public_text]
    if leaked:
        raise ValueError(f"payload leakage gate failed for {len(leaked)} raw strings")
    behavior_ids = {
        str(row.get("behavior", {}).get("id", ""))
        for row in episodes
        if isinstance(row.get("behavior"), Mapping)
    }
    leaked_ids = [value for value in behavior_ids if value and value in public_text]
    if leaked_ids:
        raise ValueError(
            f"behavior identifier leakage gate failed for {len(leaked_ids)} identifiers"
        )


def export_pack(
    *,
    memory_path: Path,
    results_path: Path,
    manifest_path: Path,
    output: Path,
    vmax: int = 5,
) -> dict[str, Any]:
    allowed_existing_files = {
        "README.md",
        "manifest.json",
        "csv/episodes.csv",
        "csv/retrievals.csv",
        "csv/queries.csv",
        "csv/transitions.csv",
        "csv/memory_updates.csv",
        "csv/final_slots.csv",
        "json/collection_summary.json",
        "json/memory_flow.json",
        "jsonl/memory_flow.jsonl",
        "schemas/episode.schema.json",
        "schemas/flow-event.schema.json",
    }
    if output.exists():
        unexpected = sorted(
            path.relative_to(output).as_posix()
            for path in output.rglob("*")
            if path.is_file()
            and path.relative_to(output).as_posix() not in allowed_existing_files
        )
        if unexpected:
            raise ValueError(
                "output directory contains unexpected files; use a clean destination: "
                + ", ".join(unexpected)
            )

    memory_rows = json.loads(memory_path.read_text(encoding="utf-8"))
    source_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    episodes = read_jsonl(results_path)
    if not isinstance(memory_rows, list) or not all(isinstance(row, dict) for row in memory_rows):
        raise TypeError("memory must contain a JSON array of objects")
    if not isinstance(source_manifest, dict):
        raise TypeError("memory manifest must contain a JSON object")

    expected_memory_sha = source_manifest.get("memory_sha256")
    actual_memory_sha = sha256_file(memory_path)
    if expected_memory_sha != actual_memory_sha:
        raise ValueError("memory SHA-256 does not match the promotion manifest")

    slots: dict[tuple[str, str], dict[str, Any]] = {}
    slot_entry_ids: dict[tuple[str, str], str] = {}
    slot_versions: dict[tuple[str, str], int] = {}
    slot_statistics: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    accepted_episode_by_hash: dict[str, str] = {}
    episode_records: list[dict[str, Any]] = []

    for ordinal, row in enumerate(episodes):
        behavior = row.get("behavior")
        if not isinstance(behavior, Mapping):
            raise TypeError(f"episode {ordinal}: behavior must be an object")
        behavior_identifier = str(behavior.get("id", ""))
        risk_category = str(behavior.get("risk_category", ""))
        identifier = episode_id(ordinal)
        history = row.get("history") or []
        if not isinstance(history, list):
            raise TypeError(f"episode {ordinal}: history must be a list")
        queries = [
            safe_query_record(
                query,
                episode_identifier=identifier,
                query_ordinal=query_ordinal,
                vmax=vmax,
            )
            for query_ordinal, query in enumerate(history)
            if isinstance(query, Mapping)
        ]
        if len(queries) != len(history):
            raise TypeError(f"episode {ordinal}: every history item must be an object")
        best_query = row.get("best_query")
        if best_query is not None:
            selected_indexes = [
                index for index, query in enumerate(history) if query == best_query
            ]
            if len(selected_indexes) != 1:
                raise ValueError(
                    f"episode {ordinal}: best_query must match exactly one history item"
                )
            queries[selected_indexes[0]]["selected_for_trajectory"] = True

        before_head = memory_state_sha256(slots, slot_entry_ids, slot_versions)
        memory_size_before = len(slots)
        trajectory = row.get("trajectory")
        decision = "no_trajectory"
        accepted = False
        previous: dict[str, Any] | None = None
        candidate_hash: str | None = None
        candidate_entry_id: str | None = None
        previous_entry_id: str | None = None
        slot_version_before = 0
        slot_version_after = 0
        key: tuple[str, str] | None = None
        if trajectory is not None:
            if not isinstance(trajectory, dict):
                raise TypeError(f"episode {ordinal}: trajectory must be an object or null")
            category = str(trajectory.get("risk_category", ""))
            strategy = str(trajectory.get("strategy", ""))
            key = (category, strategy)
            statistics = slot_statistics[key]
            statistics["candidate_count"] += 1
            previous = slots.get(key)
            previous_entry_id = slot_entry_ids.get(key)
            slot_version_before = slot_versions.get(key, 0)
            slot_version_after = slot_version_before
            candidate_score = int(trajectory.get("best_score", 0))
            candidate_hash = sha256_json(trajectory)
            candidate_entry_id = f"entry-{ordinal + 1:06d}"
            if previous is None:
                decision = "insert_new_slot"
                accepted = True
            else:
                previous_score = int(previous.get("best_score", 0))
                if candidate_score > previous_score:
                    decision = "replace_strictly_higher_score"
                    accepted = True
                    statistics["replacement_count"] += 1
                elif candidate_score == previous_score:
                    decision = "reject_equal_score_first_writer_kept"
                    statistics["rejected_equal_count"] += 1
                else:
                    decision = "reject_lower_score"
                    statistics["rejected_lower_count"] += 1
            if accepted:
                slots[key] = trajectory
                slot_entry_ids[key] = candidate_entry_id
                slot_versions[key] = slot_version_before + 1
                slot_version_after = slot_versions[key]
                statistics["accepted_write_count"] += 1
                accepted_episode_by_hash[candidate_hash] = identifier
        after_head = memory_state_sha256(slots, slot_entry_ids, slot_versions)
        memory_size_after = len(slots)

        strategy_sequence = [query["strategy"] for query in queries]
        family_sequence = [query["family"] for query in queries]
        score_sequence = [int(query["score"]) for query in queries]
        transitions = []
        for transition_ordinal in range(1, len(queries)):
            previous_query = queries[transition_ordinal - 1]
            next_query = queries[transition_ordinal]
            transitions.append(
                {
                    "transition_id": (
                        f"{identifier}-t{transition_ordinal:02d}"
                    ),
                    "episode_id": identifier,
                    "transition_ordinal": transition_ordinal - 1,
                    "from_query_id": previous_query["query_id"],
                    "to_query_id": next_query["query_id"],
                    "from_strategy": previous_query["strategy"],
                    "to_strategy": next_query["strategy"],
                    "from_family": previous_query["family"],
                    "to_family": next_query["family"],
                    "operator": transition_operator(
                        str(previous_query["strategy"]),
                        str(next_query["strategy"]),
                    ),
                    "from_score": previous_query["score"],
                    "to_score": next_query["score"],
                    "score_delta": int(next_query["score"]) - int(previous_query["score"]),
                    "reached_strict_success": bool(next_query["strict_success"]),
                    "target_response_exposed": True,
                    "judge_score_exposed": True,
                    "judge_reason_exposed": True,
                    "response_prefix_limit_chars": 1200,
                    "feedback_exposure_evidence": (
                        "implementation_inferred_unversioned_not_runtime_attested"
                    ),
                    "dependency_evidence": "program_order_inferred_not_explicit_edge",
                }
            )

        retrieved = row.get("retrieved") or []
        if not isinstance(retrieved, list):
            raise TypeError(f"episode {ordinal}: retrieved must be a list")
        retrievals: list[dict[str, Any]] = []
        for rank, item in enumerate(retrieved, start=1):
            label = str(item)
            retrieved_category, separator, retrieved_strategy = label.rpartition("/")
            if not separator:
                retrieved_category = "UNKNOWN"
                retrieved_strategy = "unknown_strategy"
            retrievals.append(
                {
                    "retrieval_id": f"{identifier}-r{rank:02d}",
                    "episode_id": identifier,
                    "retrieval_rank": rank,
                    "retrieved_risk_category": retrieved_category,
                    "retrieved_strategy": retrieved_strategy,
                    "retrieved_family": family_for(retrieved_strategy),
                    "retrieved_slot_id": slot_id(retrieved_category, retrieved_strategy),
                    "retrieved_item_id": None,
                    "retrieval_score": None,
                    "lineage_status": "label_only_not_attested",
                }
            )
        episode_records.append(
            {
                "episode_ordinal": ordinal,
                "episode_id": identifier,
                "source_dataset": source_dataset(behavior_identifier),
                "risk_category": risk_category,
                "instance_index": int(row.get("instance_index", ordinal)),
                "epsilon": float(row.get("epsilon", 0.0)),
                "used_memory": bool(row.get("used_memory", False)),
                "retrieval_count": len(retrieved),
                "retrievals": retrievals,
                "query_count": len(queries),
                "queries": queries,
                "transitions": transitions,
                "strategy_sequence": strategy_sequence,
                "family_sequence": family_sequence,
                "score_sequence": score_sequence,
                "total_user_turns": sum(int(query["user_turn_count"]) for query in queries),
                "has_multi_turn_candidate": any(
                    int(query["user_turn_count"]) > 1 for query in queries
                ),
                "best_score": int(row.get("best_score", 0)),
                "strict_success": bool(row.get("success", False)),
                "trajectory_present": trajectory is not None,
                "trajectory_sha256": candidate_hash,
                "candidate_entry_id": candidate_entry_id,
                "candidate_strategy": (
                    str(trajectory.get("strategy", ""))
                    if isinstance(trajectory, Mapping)
                    else None
                ),
                "candidate_family": (
                    family_for(str(trajectory.get("strategy", "")))
                    if isinstance(trajectory, Mapping)
                    else None
                ),
                "memory_slot_id": slot_id(*key) if key is not None else None,
                "memory_decision": decision,
                "memory_accepted": accepted,
                "previous_entry_id": previous_entry_id,
                "previous_slot_score": (
                    int(previous.get("best_score", 0)) if previous is not None else None
                ),
                "memory_head_before_sha256": before_head,
                "memory_head_after_sha256": after_head,
                "slot_version_before": slot_version_before,
                "slot_version_after": slot_version_after,
                "memory_size_before": memory_size_before,
                "memory_size_after": memory_size_after,
            }
        )

    final_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for row in memory_rows:
        key = (str(row.get("risk_category", "")), str(row.get("strategy", "")))
        if key in final_by_key:
            raise ValueError(f"duplicate canonical memory slot: {key}")
        final_by_key[key] = row
    if slots != final_by_key:
        replay_only = sorted(set(slots) - set(final_by_key))
        canonical_only = sorted(set(final_by_key) - set(slots))
        mismatched = sorted(
            key for key in set(slots) & set(final_by_key) if slots[key] != final_by_key[key]
        )
        raise ValueError(
            "replayed grid does not match canonical memory: "
            f"replay_only={replay_only}, canonical_only={canonical_only}, "
            f"mismatched={mismatched}"
        )

    final_hashes = {sha256_json(row) for row in memory_rows}
    for record in episode_records:
        candidate_hash = record["trajectory_sha256"]
        record["candidate_finally_retained"] = bool(
            candidate_hash and candidate_hash in final_hashes
        )

    slot_rows: list[dict[str, Any]] = []
    for (category, strategy), row in sorted(final_by_key.items()):
        trajectory_hash = sha256_json(row)
        statistics = slot_statistics[(category, strategy)]
        selected_behavior_id = str(row.get("behavior_id", ""))
        selected_episode = accepted_episode_by_hash.get(trajectory_hash)
        if selected_episode is None:
            raise ValueError(f"final trajectory lacks an accepted source episode: {(category, strategy)}")
        slot_rows.append(
            {
                "slot_id": slot_id(category, strategy),
                "risk_category": category,
                "strategy": strategy,
                "family": family_for(strategy),
                "source_dataset": source_dataset(selected_behavior_id),
                "best_score": int(row.get("best_score", 0)),
                "success": bool(row.get("success", False)),
                "queries": int(row.get("queries", 0)),
                "step_count": len(row.get("steps") or []),
                "final_entry_id": slot_entry_ids[(category, strategy)],
                "slot_version": slot_versions[(category, strategy)],
                "candidate_count": statistics["candidate_count"],
                "accepted_write_count": statistics["accepted_write_count"],
                "replacement_count": statistics["replacement_count"],
                "rejected_equal_count": statistics["rejected_equal_count"],
                "rejected_lower_count": statistics["rejected_lower_count"],
                "final_selected_episode_id": selected_episode,
                "source_trace_matched": True,
            }
        )

    episode_csv_rows: list[dict[str, Any]] = []
    retrieval_csv_rows: list[dict[str, Any]] = []
    query_csv_rows: list[dict[str, Any]] = []
    transition_csv_rows: list[dict[str, Any]] = []
    memory_update_rows: list[dict[str, Any]] = []
    for record in episode_records:
        scores = [int(value) for value in record["score_sequence"]]
        score_deltas = [scores[index] - scores[index - 1] for index in range(1, len(scores))]
        strategies = [str(value) for value in record["strategy_sequence"]]
        families = [str(value) for value in record["family_sequence"]]
        episode_csv_rows.append(
            {
                **record,
                "strategy_sequence": "|".join(strategies),
                "family_sequence": "|".join(families),
                "score_sequence": "|".join(str(score) for score in scores),
                "score_delta_sequence": "|".join(str(delta) for delta in score_deltas),
                "strategy_switches": sum(
                    strategies[index] != strategies[index - 1]
                    for index in range(1, len(strategies))
                ),
                "family_switches": sum(
                    families[index] != families[index - 1]
                    for index in range(1, len(families))
                ),
            }
        )
        retrieval_csv_rows.extend(record["retrievals"])
        query_csv_rows.extend(record["queries"])
        transition_csv_rows.extend(record["transitions"])
        current_entry_id = (
            record["candidate_entry_id"]
            if record["memory_accepted"]
            else record["previous_entry_id"]
        )
        current_score = (
            record["best_score"]
            if record["memory_accepted"]
            else record["previous_slot_score"]
        )
        memory_update_rows.append(
            {
                "episode_id": record["episode_id"],
                "episode_ordinal": record["episode_ordinal"],
                "insert_attempted": record["trajectory_present"],
                "memory_decision": record["memory_decision"],
                "memory_accepted": record["memory_accepted"],
                "memory_slot_id": record["memory_slot_id"],
                "candidate_entry_id": record["candidate_entry_id"],
                "previous_entry_id": record["previous_entry_id"],
                "current_entry_id": current_entry_id,
                "slot_version_before": record["slot_version_before"],
                "slot_version_after": record["slot_version_after"],
                "previous_slot_score": record["previous_slot_score"],
                "candidate_score": (
                    record["best_score"] if record["trajectory_present"] else None
                ),
                "current_slot_score": current_score,
                "memory_size_before": record["memory_size_before"],
                "memory_size_after": record["memory_size_after"],
                "memory_head_before_sha256": record["memory_head_before_sha256"],
                "memory_head_after_sha256": record["memory_head_after_sha256"],
                "decision_evidence": "deterministic_strict_score_replay",
            }
        )

    events: list[dict[str, Any]] = []
    for record, update in zip(episode_records, memory_update_rows, strict=True):
        identifier = str(record["episode_id"])
        _append_event(
            events,
            event_type="episode_started",
            episode_identifier=identifier,
            payload={
                key: record[key]
                for key in (
                    "episode_ordinal",
                    "source_dataset",
                    "risk_category",
                    "instance_index",
                    "epsilon",
                    "used_memory",
                    "retrieval_count",
                    "query_count",
                )
            },
        )
        for retrieval in record["retrievals"]:
            _append_event(
                events,
                event_type="retrieval_observed",
                episode_identifier=identifier,
                payload=retrieval,
            )
        for query_ordinal, query in enumerate(record["queries"]):
            if query_ordinal:
                _append_event(
                    events,
                    event_type="strategy_transition_observed",
                    episode_identifier=identifier,
                    payload=record["transitions"][query_ordinal - 1],
                )
            _append_event(
                events,
                event_type="query_observed",
                episode_identifier=identifier,
                payload=query,
            )
        _append_event(
            events,
            event_type="memory_update_decided",
            episode_identifier=identifier,
            payload=update,
        )
        _append_event(
            events,
            event_type="episode_ended",
            episode_identifier=identifier,
            payload={
                "best_score": record["best_score"],
                "strict_success": record["strict_success"],
                "trajectory_present": record["trajectory_present"],
                "candidate_entry_id": record["candidate_entry_id"],
                "candidate_strategy": record["candidate_strategy"],
                "candidate_family": record["candidate_family"],
                "candidate_finally_retained": record["candidate_finally_retained"],
            },
        )
    _validate_event_chain(events)

    source_counts = Counter(str(row["source_dataset"]) for row in episode_records)
    risk_counts = Counter(str(row["risk_category"]) for row in episode_records)
    strategy_counts = Counter(
        str(query["strategy"])
        for row in episode_records
        for query in row["queries"]
    )
    family_counts = Counter(
        str(query["family"])
        for row in episode_records
        for query in row["queries"]
    )
    decision_counts = Counter(str(row["memory_decision"]) for row in episode_records)
    score_counts = Counter(
        str(query["score"])
        for row in episode_records
        for query in row["queries"]
    )
    final_family_counts = Counter(str(row["family"]) for row in slot_rows)
    final_family_successes = Counter(
        str(row["family"]) for row in slot_rows if bool(row["success"])
    )
    transition_pairs = Counter(
        f"{transition['from_family']} -> {transition['to_family']}"
        for row in episode_records
        for transition in row["transitions"]
    )

    warmup = source_manifest.get("warmup") or {}
    runtime_profile = source_manifest.get("runtime_profile") or {}
    target_precisions = runtime_profile.get("target_precision") or {}
    if not isinstance(target_precisions, Mapping):
        target_precisions = {}
    summary = {
        "schema_version": SCHEMA_VERSION,
        "exporter_version": EXPORTER_VERSION,
        "pack_id": "qwen2.5-vl-3b-public-v2-round1-payload-free",
        "purpose": "audit_and_descriptive_analysis_only",
        "raw_attack_payload_included": False,
        "source_artifacts": {
            "memory": {
                "logical_name": "public-v2/qwen2.5-vl-3b/memory.json",
                "sha256": actual_memory_sha,
            },
            "results": {
                "logical_name": "public-v2/qwen2.5-vl-3b/round-1/results.jsonl",
                "sha256": sha256_file(results_path),
            },
            "promotion_manifest": {
                "logical_name": "public-v2/qwen2.5-vl-3b/memory_manifest.json",
                "sha256": sha256_file(manifest_path),
            },
            "behavior_shard": {
                "logical_name": "public-v2/qwen2.5-vl-3b/warm-behavior-shard.jsonl",
                "sha256": warmup.get("behavior_sha256"),
                "verification_status": "attested_by_promotion_manifest_not_rehashed",
            },
            "runtime_config": {
                "logical_name": "open-models-public-warm-gate.yaml",
                "sha256": warmup.get("runtime_config_sha256"),
                "verification_status": "attested_by_promotion_manifest_not_rehashed",
            },
        },
        "run_provenance": {
            "target": source_manifest.get("target"),
            "model_id": source_manifest.get("model_id"),
            "model_revision": source_manifest.get("model_revision"),
            "source_promoted_at": source_manifest.get("promoted_at"),
            "seed": warmup.get("seed"),
            "workers": warmup.get("workers"),
            "memory_mode": warmup.get("memory_mode"),
            "embedder_model": warmup.get("embedder_model"),
            "embedder_revision": warmup.get("embedder_revision"),
            "attacker_model": runtime_profile.get("attacker_model"),
            "attacker_precision": runtime_profile.get("attacker_precision"),
            "judge_model": runtime_profile.get("judge_model"),
            "judge_precision": runtime_profile.get("judge_precision"),
            "target_precision": target_precisions.get(source_manifest.get("target")),
            "producer_code_commit": None,
            "producer_code_commit_status": "missing_from_legacy_manifest",
            "initial_memory_present": warmup.get("memory_in") is not None,
            "ordering_basis": "results_jsonl_line_order",
            "replay_order_attested": False,
            "replay_order_basis": "results_jsonl_append_order_proxy",
            "concurrency_warning": (
                "workers=4; replay reproduces the final grid, but the legacy log does not "
                "prove wall-clock insertion order or explicit response-dependency edges"
            ),
        },
        "collection_contract": {
            "slot_key": ["risk_category", "strategy"],
            "online_insert_rule": "insert empty slot; replace only on strictly higher best_score",
            "equal_score_rule": "keep first writer",
            "retrieval_rule": "top-k semantic similarity over risk category and behavior",
            "retrieval_formula": "cos(category) + 1.2 * cos(behavior)",
            "default_top_k": 3,
        },
        "downstream_evaluation_contract": {
            "scope": "not_part_of_the_legacy_warmup_collection",
            "memory_mode": "frozen_retrieval_only",
            "description": "D1/Stage-0 resets to the same snapshot and blocks writes",
        },
        "collection_flow": [
            "start episode with behavior and optional top-k memory retrieval",
            "issue one or more target queries and observe target/judge feedback",
            "select the episode's highest-scoring query as a trajectory candidate",
            "map the candidate to a (risk_category, strategy) slot",
            "insert, strictly-higher replace, equal reject, or lower reject",
            "persist the mutable winner grid and append the full episode result",
            "promote and deterministically reserialize the verified canonical snapshot",
        ],
        "counts": {
            "episodes": len(episode_records),
            "unique_behaviors": len(
                {
                    str(row.get("behavior", {}).get("id", ""))
                    for row in episodes
                    if isinstance(row.get("behavior"), Mapping)
                }
            ),
            "trajectory_candidates": sum(
                bool(row["trajectory_present"]) for row in episode_records
            ),
            "episodes_without_trajectory": sum(
                not bool(row["trajectory_present"]) for row in episode_records
            ),
            "target_query_records": sum(int(row["query_count"]) for row in episode_records),
            "retrieval_label_records": len(retrieval_csv_rows),
            "query_to_query_transitions": sum(
                len(row["transitions"]) for row in episode_records
            ),
            "episodes_using_memory": sum(
                bool(row["used_memory"]) for row in episode_records
            ),
            "actual_strict_successes": sum(
                bool(row["strict_success"]) for row in episode_records
            ),
            "actual_attack_success_rate": round(
                sum(bool(row["strict_success"]) for row in episode_records)
                / max(1, len(episode_records)),
                8,
            ),
            "final_memory_slots": len(slot_rows),
            "final_success_slots": sum(bool(row["success"]) for row in slot_rows),
            "final_success_slot_fraction_not_asr": round(
                sum(bool(row["success"]) for row in slot_rows) / max(1, len(slot_rows)),
                8,
            ),
            "event_ledger_records": len(events),
        },
        "distributions": {
            "source_dataset_by_episode": _counter_rows(source_counts),
            "risk_category_by_episode": _counter_rows(risk_counts),
            "strategy_by_query": _counter_rows(strategy_counts),
            "family_by_query": _counter_rows(family_counts),
            "score_by_query": _counter_rows(score_counts),
            "memory_decision_by_episode": _counter_rows(decision_counts),
            "top_family_transitions": _counter_rows(transition_pairs),
            "final_slot_family": [
                {
                    "family": family,
                    "slots": final_family_counts[family],
                    "successful_slots": final_family_successes[family],
                }
                for family in sorted(final_family_counts)
            ],
        },
        "verification": {
            "source_memory_sha256_matches_manifest": True,
            "replayed_grid_exactly_matches_canonical_memory": True,
            "canonical_duplicate_slots": 0,
            "event_hash_chain_valid": True,
            "source_trace_match_count": len(slot_rows),
            "payload_leakage_gate": "evaluated_after_write",
        },
        "known_limitations": [
            "The final grid is survivor-biased and must not be reported as episode ASR.",
            "Legacy strategy is a dominant tool/provenance label, not a complete adaptation mechanism.",
            "The log preserves all user turns in a candidate but only its final target response.",
            "Query ordering suggests response conditioning but does not encode an explicit causal edge.",
            "Feedback exposure fields are inferred from an unversioned implementation, not runtime receipts.",
            "Legacy workers=4 makes exact wall-clock acquisition ordering scheduler-dependent.",
            "Reflections are self-reports and are excluded from all public labels.",
            "Exposure labels remain unlabeled until a frozen payload-private annotator is registered.",
        ],
    }

    public_episode_json = []
    for record, update in zip(episode_records, memory_update_rows, strict=True):
        public_episode_json.append(
            {
                "episode": {
                    key: record[key]
                    for key in (
                        "episode_ordinal",
                        "episode_id",
                        "source_dataset",
                        "risk_category",
                        "instance_index",
                        "epsilon",
                        "used_memory",
                        "retrieval_count",
                        "query_count",
                        "total_user_turns",
                        "has_multi_turn_candidate",
                        "best_score",
                        "strict_success",
                        "trajectory_present",
                        "candidate_entry_id",
                        "candidate_strategy",
                        "candidate_family",
                        "candidate_finally_retained",
                    )
                },
                "retrievals": record["retrievals"],
                "queries": record["queries"],
                "transitions": record["transitions"],
                "memory_update": update,
            }
        )
    memory_flow = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "legacy_adaptive_memory_flow_public_v1",
        "summary": summary,
        "episodes": public_episode_json,
        "final_slots": slot_rows,
    }
    episode_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://example.invalid/schemas/legacy-memory-episode-v1.json",
        "title": "Payload-free legacy memory episode",
        "type": "object",
        "required": ["episode", "retrievals", "queries", "transitions", "memory_update"],
        "properties": {
            "episode": {"type": "object"},
            "retrievals": {"type": "array", "items": {"type": "object"}},
            "queries": {"type": "array", "items": {"type": "object"}},
            "transitions": {"type": "array", "items": {"type": "object"}},
            "memory_update": {"type": "object"},
        },
        "additionalProperties": False,
    }
    event_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://example.invalid/schemas/legacy-reconstruction-event-v1.json",
        "title": "Payload-free legacy reconstruction event",
        "type": "object",
        "required": [
            "schema_version",
            "event_index",
            "event_type",
            "episode_id",
            "previous_event_sha256",
            "event_sha256",
        ],
        "properties": {
            "schema_version": {"const": SCHEMA_VERSION},
            "event_index": {"type": "integer", "minimum": 0},
            "event_type": {
                "enum": [
                    "episode_started",
                    "retrieval_observed",
                    "query_observed",
                    "strategy_transition_observed",
                    "memory_update_decided",
                    "episode_ended",
                ]
            },
            "episode_id": {"type": "string"},
            "previous_event_sha256": {"type": ["string", "null"]},
            "event_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
        "additionalProperties": True,
    }

    output.mkdir(parents=True, exist_ok=True)
    episode_csv = output / "csv" / "episodes.csv"
    retrieval_csv = output / "csv" / "retrievals.csv"
    query_csv = output / "csv" / "queries.csv"
    transition_csv = output / "csv" / "transitions.csv"
    memory_update_csv = output / "csv" / "memory_updates.csv"
    slot_csv = output / "csv" / "final_slots.csv"
    summary_json = output / "json" / "collection_summary.json"
    flow_json = output / "json" / "memory_flow.json"
    event_jsonl = output / "jsonl" / "memory_flow.jsonl"
    episode_schema_json = output / "schemas" / "episode.schema.json"
    event_schema_json = output / "schemas" / "flow-event.schema.json"
    _write_csv(episode_csv, episode_csv_rows, EPISODE_FIELDS)
    _write_csv(retrieval_csv, retrieval_csv_rows, RETRIEVAL_FIELDS)
    _write_csv(query_csv, query_csv_rows, QUERY_FIELDS)
    _write_csv(transition_csv, transition_csv_rows, TRANSITION_FIELDS)
    _write_csv(memory_update_csv, memory_update_rows, MEMORY_UPDATE_FIELDS)
    _write_csv(slot_csv, slot_rows, SLOT_FIELDS)
    atomic_write(
        summary_json,
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        + b"\n",
    )
    atomic_write(
        flow_json,
        json.dumps(memory_flow, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        + b"\n",
    )
    atomic_write(
        event_jsonl,
        b"".join(canonical_json(event) + b"\n" for event in events),
    )
    atomic_write(
        episode_schema_json,
        json.dumps(episode_schema, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        + b"\n",
    )
    atomic_write(
        event_schema_json,
        json.dumps(event_schema, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        + b"\n",
    )

    public_paths = (
        episode_csv,
        retrieval_csv,
        query_csv,
        transition_csv,
        memory_update_csv,
        slot_csv,
        summary_json,
        flow_json,
        event_jsonl,
        episode_schema_json,
        event_schema_json,
    )
    _assert_no_payload_leak(public_paths, episodes, memory_rows)
    summary["verification"]["payload_leakage_gate"] = "passed"
    memory_flow["summary"] = summary
    atomic_write(
        summary_json,
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        + b"\n",
    )
    atomic_write(
        flow_json,
        json.dumps(memory_flow, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        + b"\n",
    )
    _assert_no_payload_leak(public_paths, episodes, memory_rows)

    artifact_rows = {
        episode_csv.relative_to(output).as_posix(): len(episode_csv_rows),
        retrieval_csv.relative_to(output).as_posix(): len(retrieval_csv_rows),
        query_csv.relative_to(output).as_posix(): len(query_csv_rows),
        transition_csv.relative_to(output).as_posix(): len(transition_csv_rows),
        memory_update_csv.relative_to(output).as_posix(): len(memory_update_rows),
        slot_csv.relative_to(output).as_posix(): len(slot_rows),
        summary_json.relative_to(output).as_posix(): 1,
        flow_json.relative_to(output).as_posix(): len(public_episode_json),
        event_jsonl.relative_to(output).as_posix(): len(events),
        episode_schema_json.relative_to(output).as_posix(): 1,
        event_schema_json.relative_to(output).as_posix(): 1,
    }
    artifact_manifest = {
        "schema_version": SCHEMA_VERSION,
        "exporter_version": EXPORTER_VERSION,
        "pack_id": summary["pack_id"],
        "raw_attack_payload_included": False,
        "artifacts": {
            path.relative_to(output).as_posix(): {
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
                "records": artifact_rows[path.relative_to(output).as_posix()],
            }
            for path in public_paths
        },
        "source_sha256": {
            "memory": actual_memory_sha,
            "results": sha256_file(results_path),
            "promotion_manifest": sha256_file(manifest_path),
            "behavior_shard_attested_by_promotion_manifest": warmup.get(
                "behavior_sha256"
            ),
            "runtime_config_attested_by_promotion_manifest": warmup.get(
                "runtime_config_sha256"
            ),
        },
        "verification": summary["verification"],
    }
    manifest_output = output / "manifest.json"
    atomic_write(
        manifest_output,
        json.dumps(
            artifact_manifest,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        + b"\n",
    )
    _assert_no_payload_leak(
        tuple(path for path in output.rglob("*") if path.is_file()),
        episodes,
        memory_rows,
    )
    return artifact_manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--memory", required=True, type=Path)
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--vmax", type=int, default=5)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    for path in (args.memory, args.results, args.manifest):
        if not path.is_file():
            raise FileNotFoundError(path)
    result = export_pack(
        memory_path=args.memory.resolve(),
        results_path=args.results.resolve(),
        manifest_path=args.manifest.resolve(),
        output=args.out.resolve(),
        vmax=args.vmax,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
