"""Promote unanimously reviewed D1 candidates across pending cohorts.

This module is offline and outcome-blind.  It validates every pending cohort,
private behavior row, blinded packet, and reviewer decision artifact before it
selects exactly two candidates from each canonical D1 category.  Raw behavior
rows are written only to a mode-0600 JSONL artifact; the public promotion
manifest contains hashes and aggregates, never raw text, reviewer identities,
or individual decisions.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import armor_challenge_review as review

PROMOTION_PROTOCOL = "armor-d1-reviewed-candidate-promotion-v1"
PROMOTION_STATUS = "reviewed_candidates_promoted"
PRIVATE_ROWS_ARTIFACT_TYPE = "armor-d1-promoted-private-rows-jsonl-v1"
PER_CATEGORY = 2
CANONICAL_CATEGORIES = (
    "Cyber Harm",
    "Fraud/Deception",
    "Hate/Harassment",
    "Non-violent Crime",
    "Privacy Violations",
    "Self-Harm",
    "Sexual/Adult Content",
    "Violence",
)
RANKING_POLICY = (
    "sha256(protocol\\0seed\\0category\\0behavior_id\\0row_sha256"
    "\\0challenge_entry_sha256), then behavior_id"
)

_PUBLIC_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "protocol",
        "status",
        "target_outcomes_used",
        "selection_policy",
        "source_cohorts",
        "aggregate",
        "selected_candidates",
        "selected_candidates_sha256",
        "private_rows_artifact",
        "manifest_sha256",
    }
)
_SELECTION_POLICY_FIELDS = frozenset(
    {
        "canonical_categories",
        "per_category",
        "ranking_seed",
        "ranking",
        "review_requirement",
        "target_outcomes_used",
    }
)
_SOURCE_COHORT_FIELDS = frozenset(
    {
        "challenge_manifest_sha256",
        "private_rows_file_sha256",
        "reviewer_packet_sha256",
        "reviewer_decision_artifact_sha256",
        "reviewer_kind_counts",
        "candidate_count",
        "unanimously_approved_count",
    }
)
_AGGREGATE_FIELDS = frozenset(
    {
        "source_cohort_count",
        "candidate_count",
        "unanimously_approved_count",
        "selected_count",
        "category_unanimously_approved_counts",
        "category_selected_counts",
        "reviewer_kind_counts",
    }
)
_SELECTED_CANDIDATE_FIELDS = frozenset(
    {
        "category",
        "category_rank",
        "selection_rank_sha256",
        "behavior_id",
        "source_pair_id",
        "row_sha256",
        "content_sha256",
        "normalized_query_sha256",
        "decontamination_sha256",
        "source_challenge_manifest_sha256",
        "source_challenge_entry_sha256",
    }
)
_PRIVATE_ARTIFACT_FIELDS = frozenset(
    {
        "artifact_type",
        "row_count",
        "file_sha256",
        "file_mode",
        "contains_raw_text",
        "publish",
    }
)
_PUBLIC_FORBIDDEN_KEYS = frozenset(
    {
        "attack",
        "attack_text",
        "behavior",
        "behavior_text",
        "completion",
        "decision",
        "decisions",
        "prompt",
        "query",
        "request_text",
        "response",
        "response_text",
        "reviewer_id",
        "reviewer_ids",
        "target_outcome",
        "target_outcomes",
        "target_response",
        "text",
    }
)
_TARGET_OUTCOME_KEYS = frozenset(
    {
        "attack_success",
        "target_completion",
        "target_outcome",
        "target_outcomes",
        "target_response",
        "target_success",
    }
)
_CROSS_COHORT_UNIQUE_FIELDS = (
    "pair_id",
    "behavior_id",
    "challenge_entry_sha256",
    "row_sha256",
    "content_sha256",
    "normalized_query_sha256",
    "decontamination_sha256",
)


class D1ReviewPromotionError(ValueError):
    """Raised when review evidence cannot support a safe D1 promotion."""


@dataclass(frozen=True)
class PendingReviewCohortArtifacts:
    """Paths for one pending cohort and its two independent reviews."""

    pending_manifest_path: str | Path
    private_rows_path: str | Path
    reviewer_packet_paths: tuple[str | Path, str | Path]
    reviewer_decision_paths: tuple[str | Path, str | Path]


@dataclass(frozen=True)
class D1ReviewPromotion:
    """Validated private rows and their raw-free public manifest."""

    private_rows: tuple[dict[str, Any], ...]
    manifest: dict[str, Any]


@dataclass(frozen=True)
class _Candidate:
    entry: dict[str, Any]
    row: dict[str, Any]
    challenge_manifest_sha256: str
    unanimously_approved: bool


@dataclass(frozen=True)
class _VerifiedCohort:
    challenge_manifest_sha256: str
    private_rows_file_sha256: str
    packet_sha256: tuple[str, str]
    decision_sha256: tuple[str, str]
    reviewer_kind_counts: dict[str, int]
    candidates: tuple[_Candidate, ...]


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise D1ReviewPromotionError(f"{label} must be an object")
    return value


def _require_exact_fields(
    value: Mapping[str, Any], expected: frozenset[str], label: str
) -> None:
    if set(value) != expected:
        missing = sorted(expected.difference(value))
        extra = sorted(set(value).difference(expected))
        raise D1ReviewPromotionError(
            f"{label} fields mismatch; missing={missing}, extra={extra}"
        )


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise D1ReviewPromotionError(f"{label} must be a non-empty string")
    return value.strip()


def _require_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise D1ReviewPromotionError(f"{label} must be an integer >= {minimum}")
    return value


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        raise D1ReviewPromotionError(f"{label} must be a lowercase SHA-256 digest")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise D1ReviewPromotionError(
            f"{label} must be a lowercase SHA-256 digest"
        ) from exc
    return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _reject_public_private_fields(value: Any, label: str) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).casefold() in _PUBLIC_FORBIDDEN_KEYS:
                raise D1ReviewPromotionError(
                    f"{label} contains forbidden private field: {key}"
                )
            _reject_public_private_fields(child, f"{label}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_public_private_fields(child, f"{label}[{index}]")


def _reject_target_outcome_fields(value: Any, label: str) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).casefold() in _TARGET_OUTCOME_KEYS:
                raise D1ReviewPromotionError(
                    f"{label} contains forbidden target-outcome field: {key}"
                )
            _reject_target_outcome_fields(child, f"{label}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_target_outcome_fields(child, f"{label}[{index}]")


def _load_private_json(path: str | Path, label: str) -> Mapping[str, Any]:
    resolved, value = review._load_json(path, label)
    review._require_private_file(resolved, label)
    return value


def _review_item_id(
    *, reviewer_slot: str, manifest_sha256: str, entry_sha256: str
) -> str:
    return review._review_item_id(reviewer_slot, manifest_sha256, entry_sha256)


def _verify_cohort(
    artifacts: PendingReviewCohortArtifacts,
    *,
    cohort_index: int,
) -> _VerifiedCohort:
    label = f"cohorts[{cohort_index}]"
    if not isinstance(artifacts, PendingReviewCohortArtifacts):
        raise D1ReviewPromotionError(f"{label} must be PendingReviewCohortArtifacts")
    if len(artifacts.reviewer_packet_paths) != 2:
        raise D1ReviewPromotionError(f"{label} must provide exactly two packets")
    if len(artifacts.reviewer_decision_paths) != 2:
        raise D1ReviewPromotionError(f"{label} must provide exactly two decisions")

    try:
        manifest, manifest_sha256, entries, rows = review._verify_pending_inputs(
            artifacts.pending_manifest_path,
            artifacts.private_rows_path,
        )
        selection = _require_mapping(
            manifest.get("selection_policy"), f"{label}.selection_policy"
        )
        if (
            selection.get("no_target_outcome_used") is not True
            or selection.get("sealed_track_used") is not False
        ):
            raise D1ReviewPromotionError(
                f"{label} selection is not outcome-blind and unsealed"
            )
        source = _require_mapping(manifest.get("source"), f"{label}.source")
        if source.get("track") != "defender_train":
            raise D1ReviewPromotionError(f"{label} source must be defender_train")

        packets = tuple(
            _load_private_json(path, f"{label}.reviewer_packets[{index}]")
            for index, path in enumerate(artifacts.reviewer_packet_paths)
        )
        packet_hashes = tuple(
            review._validate_packet(packet, f"{label}.reviewer_packets[{index}]")
            for index, packet in enumerate(packets)
        )
        if len(set(packet_hashes)) != 2:
            raise D1ReviewPromotionError(f"{label} packet hashes must be distinct")
        slots = tuple(str(packet["reviewer_slot"]) for packet in packets)
        if len(set(slots)) != 2:
            raise D1ReviewPromotionError(f"{label} reviewer slots must be distinct")
        if any(
            packet.get("challenge_manifest_sha256") != manifest_sha256
            for packet in packets
        ):
            raise D1ReviewPromotionError(
                f"{label} packet challenge manifest binding mismatch"
            )
        expected_packets = review._expected_packets(
            manifest_sha256=manifest_sha256,
            entries=entries,
            rows=rows,
            reviewer_slots=slots,
        )
        if tuple(dict(packet) for packet in packets) != expected_packets:
            raise D1ReviewPromotionError(
                f"{label} packets do not exactly match the pending cohort"
            )

        decisions = tuple(
            _load_private_json(path, f"{label}.reviewer_decisions[{index}]")
            for index, path in enumerate(artifacts.reviewer_decision_paths)
        )
        decisions_by_packet: dict[str, Mapping[str, Any]] = {}
        for index, artifact in enumerate(decisions):
            packet_sha256 = _require_sha256(
                artifact.get("packet_sha256"),
                f"{label}.reviewer_decisions[{index}].packet_sha256",
            )
            if packet_sha256 in decisions_by_packet:
                raise D1ReviewPromotionError(
                    f"{label} duplicate decision packet binding"
                )
            decisions_by_packet[packet_sha256] = artifact
        if set(decisions_by_packet) != set(packet_hashes):
            raise D1ReviewPromotionError(
                f"{label} decisions do not exactly cover both packets"
            )

        decision_hashes: list[str] = []
        reviewer_ids: set[str] = set()
        reviewer_kinds: Counter[str] = Counter()
        decision_maps: list[dict[str, Mapping[str, Any]]] = []
        for index, (packet, packet_sha256) in enumerate(
            zip(packets, packet_hashes, strict=True)
        ):
            artifact = decisions_by_packet[packet_sha256]
            artifact_sha256, reviewer_kind, decision_map = (
                review._validate_decision_for_packet(
                    artifact,
                    packet,
                    f"{label}.reviewer_decisions[{index}]",
                )
            )
            reviewer_id = str(artifact["reviewer_id"])
            if reviewer_id in reviewer_ids:
                raise D1ReviewPromotionError(
                    f"{label} reviewer identities must be distinct"
                )
            reviewer_ids.add(reviewer_id)
            reviewer_kinds[reviewer_kind] += 1
            decision_hashes.append(artifact_sha256)
            decision_maps.append(decision_map)
        if len(reviewer_ids) != 2:
            raise D1ReviewPromotionError(
                f"{label} must contain two distinct reviewer identities"
            )

        candidates: list[_Candidate] = []
        for entry_index, raw_entry in enumerate(entries):
            entry = dict(raw_entry)
            behavior_id = str(entry["behavior_id"])
            category = str(entry["category"])
            if category not in CANONICAL_CATEGORIES:
                raise D1ReviewPromotionError(
                    f"{label}.pairs[{entry_index}] has noncanonical category {category!r}"
                )
            row = dict(rows[behavior_id])
            _reject_target_outcome_fields(row, f"{label}.private_rows.{behavior_id}")
            if row.get("safety_label") != "harmful":
                raise D1ReviewPromotionError(
                    f"{label}.pairs[{entry_index}] is not harmful-labeled"
                )
            if row.get("track", "defender_train") != "defender_train":
                raise D1ReviewPromotionError(
                    f"{label}.pairs[{entry_index}] is not defender_train"
                )
            decisions_for_entry: list[str] = []
            for packet, decision_map in zip(packets, decision_maps, strict=True):
                item_id = _review_item_id(
                    reviewer_slot=str(packet["reviewer_slot"]),
                    manifest_sha256=manifest_sha256,
                    entry_sha256=str(entry["challenge_entry_sha256"]),
                )
                try:
                    decision = decision_map[item_id]
                except KeyError as exc:
                    raise D1ReviewPromotionError(
                        f"{label} decision mapping is missing an entry"
                    ) from exc
                decisions_for_entry.append(str(decision["decision"]))
            candidates.append(
                _Candidate(
                    entry=copy.deepcopy(entry),
                    row=copy.deepcopy(row),
                    challenge_manifest_sha256=manifest_sha256,
                    unanimously_approved=all(
                        decision == "approve" for decision in decisions_for_entry
                    ),
                )
            )

        private_metadata = _require_mapping(
            manifest.get("private_behavior_file"),
            f"{label}.private_behavior_file",
        )
        return _VerifiedCohort(
            challenge_manifest_sha256=manifest_sha256,
            private_rows_file_sha256=_require_sha256(
                private_metadata.get("sha256"),
                f"{label}.private_behavior_file.sha256",
            ),
            packet_sha256=(str(packet_hashes[0]), str(packet_hashes[1])),
            decision_sha256=(str(decision_hashes[0]), str(decision_hashes[1])),
            reviewer_kind_counts=dict(sorted(reviewer_kinds.items())),
            candidates=tuple(candidates),
        )
    except review.ChallengeReviewError as exc:
        raise D1ReviewPromotionError(f"{label}: {exc}") from exc


def _rank_sha256(candidate: _Candidate, seed: int) -> str:
    entry = candidate.entry
    material = "\0".join(
        (
            PROMOTION_PROTOCOL,
            str(seed),
            str(entry["category"]),
            str(entry["behavior_id"]),
            str(entry["row_sha256"]),
            str(entry["challenge_entry_sha256"]),
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _private_jsonl_bytes(rows: Sequence[Mapping[str, Any]]) -> bytes:
    text = "".join(
        json.dumps(
            dict(row),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
        for row in rows
    )
    return text.encode("utf-8")


def build_d1_review_promotion(
    cohorts: Sequence[PendingReviewCohortArtifacts],
    *,
    ranking_seed: int,
) -> D1ReviewPromotion:
    """Validate review artifacts and return a deterministic 8x2 promotion."""

    if (
        not isinstance(cohorts, Sequence)
        or isinstance(cohorts, (str, bytes))
        or not cohorts
    ):
        raise D1ReviewPromotionError("cohorts must be a non-empty sequence")
    seed = _require_int(ranking_seed, "ranking_seed")
    verified = [
        _verify_cohort(cohort, cohort_index=index)
        for index, cohort in enumerate(cohorts)
    ]

    seen_manifest_hashes: set[str] = set()
    seen_private_file_hashes: set[str] = set()
    seen_packet_hashes: set[str] = set()
    seen_decision_hashes: set[str] = set()
    seen_candidate_fields: dict[str, set[str]] = {
        field: set() for field in _CROSS_COHORT_UNIQUE_FIELDS
    }
    all_candidates: list[_Candidate] = []
    reviewer_kind_counts: Counter[str] = Counter()
    for cohort_index, cohort in enumerate(verified):
        if cohort.challenge_manifest_sha256 in seen_manifest_hashes:
            raise D1ReviewPromotionError("duplicate source challenge manifest hash")
        seen_manifest_hashes.add(cohort.challenge_manifest_sha256)
        if cohort.private_rows_file_sha256 in seen_private_file_hashes:
            raise D1ReviewPromotionError("duplicate private rows artifact hash")
        seen_private_file_hashes.add(cohort.private_rows_file_sha256)
        for packet_sha256 in cohort.packet_sha256:
            if packet_sha256 in seen_packet_hashes:
                raise D1ReviewPromotionError("duplicate reviewer packet hash")
            seen_packet_hashes.add(packet_sha256)
        for decision_sha256 in cohort.decision_sha256:
            if decision_sha256 in seen_decision_hashes:
                raise D1ReviewPromotionError(
                    "duplicate reviewer decision artifact hash"
                )
            seen_decision_hashes.add(decision_sha256)
        reviewer_kind_counts.update(cohort.reviewer_kind_counts)
        for candidate in cohort.candidates:
            for field in _CROSS_COHORT_UNIQUE_FIELDS:
                value = str(candidate.entry[field])
                if value in seen_candidate_fields[field]:
                    raise D1ReviewPromotionError(
                        f"duplicate candidate {field} across cohorts: {value}"
                    )
                seen_candidate_fields[field].add(value)
            all_candidates.append(candidate)

    approved_by_category: dict[str, list[_Candidate]] = defaultdict(list)
    for candidate in all_candidates:
        if candidate.unanimously_approved:
            approved_by_category[str(candidate.entry["category"])].append(candidate)

    selected_rows: list[dict[str, Any]] = []
    selected_public: list[dict[str, Any]] = []
    approved_counts: dict[str, int] = {}
    selected_counts: dict[str, int] = {}
    for category in CANONICAL_CATEGORIES:
        ranked = sorted(
            approved_by_category.get(category, []),
            key=lambda candidate: (
                _rank_sha256(candidate, seed),
                str(candidate.entry["behavior_id"]),
            ),
        )
        approved_counts[category] = len(ranked)
        if len(ranked) < PER_CATEGORY:
            raise D1ReviewPromotionError(
                f"insufficient unanimous approvals for {category}: "
                f"required={PER_CATEGORY}, available={len(ranked)}"
            )
        selected_counts[category] = PER_CATEGORY
        for category_rank, candidate in enumerate(ranked[:PER_CATEGORY], start=1):
            entry = candidate.entry
            rank_sha256 = _rank_sha256(candidate, seed)
            selected_rows.append(copy.deepcopy(candidate.row))
            selected_public.append(
                {
                    "category": category,
                    "category_rank": category_rank,
                    "selection_rank_sha256": rank_sha256,
                    "behavior_id": entry["behavior_id"],
                    "source_pair_id": entry["pair_id"],
                    "row_sha256": entry["row_sha256"],
                    "content_sha256": entry["content_sha256"],
                    "normalized_query_sha256": entry["normalized_query_sha256"],
                    "decontamination_sha256": entry["decontamination_sha256"],
                    "source_challenge_manifest_sha256": candidate.challenge_manifest_sha256,
                    "source_challenge_entry_sha256": entry["challenge_entry_sha256"],
                }
            )

    private_payload = _private_jsonl_bytes(selected_rows)
    source_cohorts = []
    for cohort in sorted(verified, key=lambda item: item.challenge_manifest_sha256):
        source_cohorts.append(
            {
                "challenge_manifest_sha256": cohort.challenge_manifest_sha256,
                "private_rows_file_sha256": cohort.private_rows_file_sha256,
                "reviewer_packet_sha256": sorted(cohort.packet_sha256),
                "reviewer_decision_artifact_sha256": sorted(cohort.decision_sha256),
                "reviewer_kind_counts": dict(
                    sorted(cohort.reviewer_kind_counts.items())
                ),
                "candidate_count": len(cohort.candidates),
                "unanimously_approved_count": sum(
                    candidate.unanimously_approved for candidate in cohort.candidates
                ),
            }
        )
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "protocol": PROMOTION_PROTOCOL,
        "status": PROMOTION_STATUS,
        "target_outcomes_used": False,
        "selection_policy": {
            "canonical_categories": list(CANONICAL_CATEGORIES),
            "per_category": PER_CATEGORY,
            "ranking_seed": seed,
            "ranking": RANKING_POLICY,
            "review_requirement": "two_distinct_reviewers_unanimous_approve",
            "target_outcomes_used": False,
        },
        "source_cohorts": source_cohorts,
        "aggregate": {
            "source_cohort_count": len(verified),
            "candidate_count": len(all_candidates),
            "unanimously_approved_count": sum(
                candidate.unanimously_approved for candidate in all_candidates
            ),
            "selected_count": len(selected_rows),
            "category_unanimously_approved_counts": approved_counts,
            "category_selected_counts": selected_counts,
            "reviewer_kind_counts": dict(sorted(reviewer_kind_counts.items())),
        },
        "selected_candidates": selected_public,
        "selected_candidates_sha256": review.canonical_sha256(selected_public),
        "private_rows_artifact": {
            "artifact_type": PRIVATE_ROWS_ARTIFACT_TYPE,
            "row_count": len(selected_rows),
            "file_sha256": _sha256_bytes(private_payload),
            "file_mode": "0600",
            "contains_raw_text": True,
            "publish": False,
        },
    }
    _reject_public_private_fields(manifest, "promotion manifest")
    manifest["manifest_sha256"] = review.canonical_sha256(manifest)
    _validate_public_manifest(manifest)
    return D1ReviewPromotion(
        private_rows=tuple(copy.deepcopy(selected_rows)),
        manifest=copy.deepcopy(manifest),
    )


def _validate_public_manifest(value: Mapping[str, Any]) -> None:
    manifest = _require_mapping(value, "promotion manifest")
    _require_exact_fields(manifest, _PUBLIC_MANIFEST_FIELDS, "promotion manifest")
    _reject_public_private_fields(manifest, "promotion manifest")
    stored_sha256 = _require_sha256(
        manifest.get("manifest_sha256"), "promotion manifest.manifest_sha256"
    )
    unhashed = dict(manifest)
    unhashed.pop("manifest_sha256", None)
    if review.canonical_sha256(unhashed) != stored_sha256:
        raise D1ReviewPromotionError("promotion manifest self-hash mismatch")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("protocol") != PROMOTION_PROTOCOL
        or manifest.get("status") != PROMOTION_STATUS
        or manifest.get("target_outcomes_used") is not False
    ):
        raise D1ReviewPromotionError("promotion manifest header is invalid")
    selection = _require_mapping(
        manifest.get("selection_policy"), "promotion manifest.selection_policy"
    )
    _require_exact_fields(
        selection, _SELECTION_POLICY_FIELDS, "promotion manifest.selection_policy"
    )
    if (
        selection.get("canonical_categories") != list(CANONICAL_CATEGORIES)
        or selection.get("per_category") != PER_CATEGORY
        or selection.get("ranking") != RANKING_POLICY
        or selection.get("review_requirement")
        != "two_distinct_reviewers_unanimous_approve"
        or selection.get("target_outcomes_used") is not False
    ):
        raise D1ReviewPromotionError("promotion selection policy is invalid")
    _require_int(selection.get("ranking_seed"), "selection_policy.ranking_seed")

    source_cohorts = manifest.get("source_cohorts")
    if not isinstance(source_cohorts, list) or not source_cohorts:
        raise D1ReviewPromotionError("promotion source_cohorts must not be empty")
    observed_manifest_hashes: set[str] = set()
    observed_packet_hashes: set[str] = set()
    observed_decision_hashes: set[str] = set()
    source_candidate_total = 0
    source_approved_total = 0
    source_reviewer_kinds: Counter[str] = Counter()
    for index, source in enumerate(source_cohorts):
        source = _require_mapping(source, f"source_cohorts[{index}]")
        _require_exact_fields(source, _SOURCE_COHORT_FIELDS, f"source_cohorts[{index}]")
        source_manifest_sha256 = _require_sha256(
            source.get("challenge_manifest_sha256"),
            f"source_cohorts[{index}].challenge_manifest_sha256",
        )
        if source_manifest_sha256 in observed_manifest_hashes:
            raise D1ReviewPromotionError("duplicate public source cohort hash")
        observed_manifest_hashes.add(source_manifest_sha256)
        _require_sha256(
            source.get("private_rows_file_sha256"),
            f"source_cohorts[{index}].private_rows_file_sha256",
        )
        for field in (
            "reviewer_packet_sha256",
            "reviewer_decision_artifact_sha256",
        ):
            hashes = source.get(field)
            if (
                not isinstance(hashes, list)
                or len(hashes) != 2
                or len(set(hashes)) != 2
            ):
                raise D1ReviewPromotionError(
                    f"source_cohorts[{index}].{field} must contain two distinct hashes"
                )
            for hash_index, digest in enumerate(hashes):
                digest = _require_sha256(
                    digest, f"source_cohorts[{index}].{field}[{hash_index}]"
                )
                observed = (
                    observed_packet_hashes
                    if field == "reviewer_packet_sha256"
                    else observed_decision_hashes
                )
                if digest in observed:
                    raise D1ReviewPromotionError(
                        f"duplicate public review artifact hash: {digest}"
                    )
                observed.add(digest)
        kinds = _require_mapping(
            source.get("reviewer_kind_counts"),
            f"source_cohorts[{index}].reviewer_kind_counts",
        )
        if set(kinds).difference({"human", "model"}) or not kinds:
            raise D1ReviewPromotionError(
                f"source_cohorts[{index}] reviewer kind counts are invalid"
            )
        kind_total = 0
        for kind, count in kinds.items():
            normalized_count = _require_int(
                count,
                f"source_cohorts[{index}].reviewer_kind_counts.{kind}",
                minimum=1,
            )
            kind_total += normalized_count
            source_reviewer_kinds[kind] += normalized_count
        if kind_total != 2:
            raise D1ReviewPromotionError(
                f"source_cohorts[{index}] reviewer kind counts are invalid"
            )
        candidate_count = _require_int(
            source.get("candidate_count"), f"source_cohorts[{index}].candidate_count"
        )
        approved_count = _require_int(
            source.get("unanimously_approved_count"),
            f"source_cohorts[{index}].unanimously_approved_count",
        )
        if (
            candidate_count != review.EXPECTED_PAIR_COUNT
            or approved_count > candidate_count
        ):
            raise D1ReviewPromotionError(
                f"source_cohorts[{index}] candidate counts are invalid"
            )
        source_candidate_total += candidate_count
        source_approved_total += approved_count
    if [source["challenge_manifest_sha256"] for source in source_cohorts] != sorted(
        observed_manifest_hashes
    ):
        raise D1ReviewPromotionError("promotion source cohorts are not canonical")

    aggregate = _require_mapping(
        manifest.get("aggregate"), "promotion manifest.aggregate"
    )
    _require_exact_fields(aggregate, _AGGREGATE_FIELDS, "promotion manifest.aggregate")
    if aggregate.get("source_cohort_count") != len(source_cohorts):
        raise D1ReviewPromotionError("promotion source cohort count mismatch")
    if aggregate.get("candidate_count") != source_candidate_total:
        raise D1ReviewPromotionError("promotion candidate count mismatch")
    if aggregate.get("unanimously_approved_count") != source_approved_total:
        raise D1ReviewPromotionError("promotion approved count mismatch")
    if aggregate.get("selected_count") != len(CANONICAL_CATEGORIES) * PER_CATEGORY:
        raise D1ReviewPromotionError("promotion selected count mismatch")
    if aggregate.get("category_selected_counts") != {
        category: PER_CATEGORY for category in CANONICAL_CATEGORIES
    }:
        raise D1ReviewPromotionError("promotion category selected counts mismatch")
    approved_counts = _require_mapping(
        aggregate.get("category_unanimously_approved_counts"),
        "aggregate.category_unanimously_approved_counts",
    )
    if set(approved_counts) != set(CANONICAL_CATEGORIES):
        raise D1ReviewPromotionError("promotion category approved counts mismatch")
    approved_category_total = 0
    for category in CANONICAL_CATEGORIES:
        approved_category_total += _require_int(
            approved_counts.get(category),
            f"aggregate.category_unanimously_approved_counts.{category}",
            minimum=PER_CATEGORY,
        )
    if approved_category_total != source_approved_total:
        raise D1ReviewPromotionError("promotion category approved total mismatch")
    aggregate_reviewer_kinds = _require_mapping(
        aggregate.get("reviewer_kind_counts"), "aggregate.reviewer_kind_counts"
    )
    if dict(aggregate_reviewer_kinds) != dict(sorted(source_reviewer_kinds.items())):
        raise D1ReviewPromotionError("promotion reviewer kind aggregate mismatch")

    selected = manifest.get("selected_candidates")
    if (
        not isinstance(selected, list)
        or len(selected) != len(CANONICAL_CATEGORIES) * PER_CATEGORY
    ):
        raise D1ReviewPromotionError("promotion selected_candidates count mismatch")
    if manifest.get("selected_candidates_sha256") != review.canonical_sha256(selected):
        raise D1ReviewPromotionError("promotion selected_candidates hash mismatch")
    expected_positions = [
        (category, rank)
        for category in CANONICAL_CATEGORIES
        for rank in range(1, PER_CATEGORY + 1)
    ]
    observed_positions: list[tuple[str, int]] = []
    observed_behavior_ids: set[str] = set()
    observed_pair_ids: set[str] = set()
    observed_row_hashes: set[str] = set()
    for index, raw_candidate in enumerate(selected):
        candidate = _require_mapping(raw_candidate, f"selected_candidates[{index}]")
        _require_exact_fields(
            candidate,
            _SELECTED_CANDIDATE_FIELDS,
            f"selected_candidates[{index}]",
        )
        observed_positions.append(
            (str(candidate.get("category")), candidate.get("category_rank"))
        )
        behavior_id = _require_string(
            candidate.get("behavior_id"), f"selected_candidates[{index}].behavior_id"
        )
        pair_id = _require_string(
            candidate.get("source_pair_id"),
            f"selected_candidates[{index}].source_pair_id",
        )
        if behavior_id in observed_behavior_ids or pair_id in observed_pair_ids:
            raise D1ReviewPromotionError("duplicate public selected candidate id")
        observed_behavior_ids.add(behavior_id)
        observed_pair_ids.add(pair_id)
        for field in (
            "selection_rank_sha256",
            "row_sha256",
            "content_sha256",
            "normalized_query_sha256",
            "decontamination_sha256",
            "source_challenge_manifest_sha256",
            "source_challenge_entry_sha256",
        ):
            _require_sha256(
                candidate.get(field), f"selected_candidates[{index}].{field}"
            )
        row_sha256 = str(candidate["row_sha256"])
        if row_sha256 in observed_row_hashes:
            raise D1ReviewPromotionError("duplicate public selected row hash")
        observed_row_hashes.add(row_sha256)
        if (
            candidate["source_challenge_manifest_sha256"]
            not in observed_manifest_hashes
        ):
            raise D1ReviewPromotionError(
                "selected candidate references an unknown source cohort"
            )
        rank_material = "\0".join(
            (
                PROMOTION_PROTOCOL,
                str(selection["ranking_seed"]),
                str(candidate["category"]),
                behavior_id,
                row_sha256,
                str(candidate["source_challenge_entry_sha256"]),
            )
        )
        if (
            candidate["selection_rank_sha256"]
            != hashlib.sha256(rank_material.encode("utf-8")).hexdigest()
        ):
            raise D1ReviewPromotionError("selected candidate ranking hash mismatch")
    if observed_positions != expected_positions:
        raise D1ReviewPromotionError("promotion selected candidate order is invalid")
    for category_index, category in enumerate(CANONICAL_CATEGORIES):
        start = category_index * PER_CATEGORY
        category_rows = selected[start : start + PER_CATEGORY]
        observed_order = [
            (row["selection_rank_sha256"], row["behavior_id"]) for row in category_rows
        ]
        if observed_order != sorted(observed_order):
            raise D1ReviewPromotionError(
                f"promotion deterministic rank order is invalid: {category}"
            )

    private_artifact = _require_mapping(
        manifest.get("private_rows_artifact"),
        "promotion manifest.private_rows_artifact",
    )
    _require_exact_fields(
        private_artifact,
        _PRIVATE_ARTIFACT_FIELDS,
        "promotion manifest.private_rows_artifact",
    )
    if private_artifact != {
        "artifact_type": PRIVATE_ROWS_ARTIFACT_TYPE,
        "row_count": len(CANONICAL_CATEGORIES) * PER_CATEGORY,
        "file_sha256": private_artifact.get("file_sha256"),
        "file_mode": "0600",
        "contains_raw_text": True,
        "publish": False,
    }:
        raise D1ReviewPromotionError("promotion private artifact policy mismatch")
    _require_sha256(
        private_artifact.get("file_sha256"),
        "promotion manifest.private_rows_artifact.file_sha256",
    )


def _destination(path: str | Path) -> Path:
    raw = Path(path).expanduser()
    if not raw.is_absolute():
        raw = Path.cwd() / raw
    raw.parent.mkdir(parents=True, exist_ok=True)
    return raw.parent.resolve() / raw.name


def _stage_payload(destination: Path, payload: bytes, *, mode: int) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(mode)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return temporary


def write_d1_review_promotion(
    promotion: D1ReviewPromotion,
    *,
    private_rows_output_path: str | Path,
    promotion_manifest_output_path: str | Path,
) -> tuple[Path, Path]:
    """Atomically publish private rows and public manifest without overwrite."""

    if not isinstance(promotion, D1ReviewPromotion):
        raise D1ReviewPromotionError("promotion must be D1ReviewPromotion")
    _validate_public_manifest(promotion.manifest)
    private_payload = _private_jsonl_bytes(promotion.private_rows)
    private_metadata = promotion.manifest["private_rows_artifact"]
    if private_metadata["file_sha256"] != _sha256_bytes(private_payload):
        raise D1ReviewPromotionError("private rows payload hash mismatch")
    selected = promotion.manifest["selected_candidates"]
    if len(selected) != len(promotion.private_rows):
        raise D1ReviewPromotionError("private/public selected row count mismatch")
    for index, (row, candidate) in enumerate(
        zip(promotion.private_rows, selected, strict=True)
    ):
        if review.canonical_sha256(row) != candidate["row_sha256"]:
            raise D1ReviewPromotionError(
                f"private/public row hash mismatch at index {index}"
            )

    private_destination = _destination(private_rows_output_path)
    manifest_destination = _destination(promotion_manifest_output_path)
    if private_destination == manifest_destination:
        raise D1ReviewPromotionError("private and public output paths must differ")
    for destination in (private_destination, manifest_destination):
        if destination.exists() or destination.is_symlink():
            raise D1ReviewPromotionError(
                f"refusing to overwrite existing artifact: {destination}"
            )
    public_payload = (
        json.dumps(
            promotion.manifest,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    staged_private = _stage_payload(private_destination, private_payload, mode=0o600)
    try:
        staged_manifest = _stage_payload(
            manifest_destination, public_payload, mode=0o644
        )
    except Exception:
        staged_private.unlink(missing_ok=True)
        raise

    published: list[Path] = []
    try:
        for temporary, destination in (
            (staged_private, private_destination),
            (staged_manifest, manifest_destination),
        ):
            try:
                os.link(temporary, destination)
            except FileExistsError as exc:
                raise D1ReviewPromotionError(
                    f"refusing to overwrite existing artifact: {destination}"
                ) from exc
            published.append(destination)
        for parent in {path.parent for path in published}:
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except Exception:
        for path in reversed(published):
            path.unlink(missing_ok=True)
        raise
    finally:
        staged_private.unlink(missing_ok=True)
        staged_manifest.unlink(missing_ok=True)
    return private_destination, manifest_destination


def promote_d1_reviewed_candidates(
    cohorts: Sequence[PendingReviewCohortArtifacts],
    *,
    ranking_seed: int,
    private_rows_output_path: str | Path,
    promotion_manifest_output_path: str | Path,
) -> dict[str, Any]:
    """Validate, select, and publish one offline D1 promotion."""

    promotion = build_d1_review_promotion(cohorts, ranking_seed=ranking_seed)
    write_d1_review_promotion(
        promotion,
        private_rows_output_path=private_rows_output_path,
        promotion_manifest_output_path=promotion_manifest_output_path,
    )
    return copy.deepcopy(promotion.manifest)


__all__ = [
    "CANONICAL_CATEGORIES",
    "PER_CATEGORY",
    "PRIVATE_ROWS_ARTIFACT_TYPE",
    "PROMOTION_PROTOCOL",
    "PROMOTION_STATUS",
    "D1ReviewPromotion",
    "D1ReviewPromotionError",
    "PendingReviewCohortArtifacts",
    "build_d1_review_promotion",
    "promote_d1_reviewed_candidates",
    "write_d1_review_promotion",
]
