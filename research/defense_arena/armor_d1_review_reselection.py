"""Outcome-blind seed reselection after review of a prior D1 final cohort.

The helper validates the original reviewed candidate pool and a separately
reviewed prior-final pending challenge.  It then finds the first promotion
ranking seed whose selected behavior IDs exclude every prior-final candidate
that did not receive two approvals.  Public output contains only aggregate
counts and artifact hashes; raw rows remain in the mode-0600 promotion file.
"""

from __future__ import annotations

import copy
import json
import os
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import armor_d1_review_promotion as promotion
from .armor_challenge_review import canonical_sha256

RESELECTION_PROTOCOL = "armor-d1-outcome-blind-review-reselection-v1"
RESELECTION_ARTIFACT_TYPE = "armor-d1-review-reselection-attestation-v1"
RESELECTION_STATUS = "prior_review_rejections_excluded"
SEED_SEARCH_POLICY = "ascending_integer_first_match"
DEFAULT_MAX_SEED_ATTEMPTS = 1_000_000

_ATTESTATION_FIELDS = frozenset(
    {
        "schema_version",
        "protocol",
        "artifact_type",
        "status",
        "target_outcomes_used",
        "prior_final_review",
        "rejection_summary",
        "seed_search",
        "new_promotion_manifest_sha256",
        "attestation_sha256",
    }
)
_PRIOR_REVIEW_FIELDS = frozenset(
    {
        "challenge_manifest_sha256",
        "private_rows_file_sha256",
        "reviewer_packet_sha256",
        "reviewer_decision_artifact_sha256",
    }
)
_REJECTION_SUMMARY_FIELDS = frozenset(
    {
        "rejected_count",
        "category_rejected_counts",
    }
)
_SEED_SEARCH_FIELDS = frozenset(
    {
        "policy",
        "start_seed",
        "chosen_seed",
        "examined_seed_count",
    }
)
_SOURCE_IDENTITY_FIELDS = (
    "category",
    "row_sha256",
    "content_sha256",
    "normalized_query_sha256",
    "decontamination_sha256",
)


class D1ReviewReselectionError(ValueError):
    """Raised when prior reviews cannot support a safe reselection."""


@dataclass(frozen=True)
class D1ReviewReselection:
    """A new promotion and its raw-free reselection attestation."""

    promotion: promotion.D1ReviewPromotion
    attestation: dict[str, Any]
    _rejected_candidates: tuple[tuple[str, str], ...] = field(repr=False)


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise D1ReviewReselectionError(f"{label} must be an object")
    return value


def _require_exact_fields(
    value: Mapping[str, Any], expected: frozenset[str], label: str
) -> None:
    if set(value) != expected:
        missing = sorted(expected.difference(value))
        extra = sorted(set(value).difference(expected))
        raise D1ReviewReselectionError(
            f"{label} fields mismatch; missing={missing}, extra={extra}"
        )


def _require_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise D1ReviewReselectionError(f"{label} must be an integer >= {minimum}")
    return value


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        raise D1ReviewReselectionError(f"{label} must be a lowercase SHA-256")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise D1ReviewReselectionError(
            f"{label} must be a lowercase SHA-256"
        ) from exc
    return value


def _normalize_original_cohorts(
    value: promotion.PendingReviewCohortArtifacts
    | Sequence[promotion.PendingReviewCohortArtifacts],
) -> tuple[promotion.PendingReviewCohortArtifacts, ...]:
    if isinstance(value, promotion.PendingReviewCohortArtifacts):
        return (value,)
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or not value:
        raise D1ReviewReselectionError(
            "original_cohorts must be a non-empty sequence"
        )
    cohorts = tuple(value)
    if any(
        not isinstance(item, promotion.PendingReviewCohortArtifacts)
        for item in cohorts
    ):
        raise D1ReviewReselectionError(
            "original_cohorts must contain PendingReviewCohortArtifacts"
        )
    return cohorts


def _source_fingerprints_from_manifest(
    manifest: Mapping[str, Any],
) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        sorted(
            (
                source["challenge_manifest_sha256"],
                source["private_rows_file_sha256"],
                tuple(source["reviewer_packet_sha256"]),
                tuple(source["reviewer_decision_artifact_sha256"]),
            )
            for source in manifest["source_cohorts"]
        )
    )


def _source_fingerprints_from_verified(
    verified: Sequence[promotion._VerifiedCohort],
) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        sorted(
            (
                cohort.challenge_manifest_sha256,
                cohort.private_rows_file_sha256,
                tuple(sorted(cohort.packet_sha256)),
                tuple(sorted(cohort.decision_sha256)),
            )
            for cohort in verified
        )
    )


def _selected_behavior_ids(
    value: promotion.D1ReviewPromotion,
) -> tuple[str, ...]:
    return tuple(
        str(candidate["behavior_id"])
        for candidate in value.manifest["selected_candidates"]
    )


def _validate_verified_candidate_identities(
    cohorts: Sequence[promotion._VerifiedCohort],
    *,
    label: str,
) -> None:
    seen_ids: set[str] = set()
    seen_row_hashes: set[str] = set()
    seen_entry_hashes: set[str] = set()
    seen_identity_hashes: set[str] = set()
    for cohort in cohorts:
        for candidate in cohort.candidates:
            entry = candidate.entry
            behavior_id = str(entry["behavior_id"])
            if behavior_id in seen_ids:
                raise D1ReviewReselectionError(
                    f"{label} contains a duplicate behavior ID"
                )
            seen_ids.add(behavior_id)
            row_sha256 = _require_sha256(
                entry.get("row_sha256"), f"{label}.{behavior_id}.row_sha256"
            )
            entry_sha256 = _require_sha256(
                entry.get("challenge_entry_sha256"),
                f"{label}.{behavior_id}.challenge_entry_sha256",
            )
            if row_sha256 in seen_row_hashes or entry_sha256 in seen_entry_hashes:
                raise D1ReviewReselectionError(
                    f"{label} contains a duplicate row or challenge-entry hash"
                )
            seen_row_hashes.add(row_sha256)
            seen_entry_hashes.add(entry_sha256)

            identity_hashes = {
                _require_sha256(
                    entry.get(field_name), f"{label}.{behavior_id}.{field_name}"
                )
                for field_name in (
                    "content_sha256",
                    "normalized_query_sha256",
                    "decontamination_sha256",
                )
            }
            row_hashes = candidate.row.get("hashes")
            if not isinstance(row_hashes, Mapping):
                raise D1ReviewReselectionError(
                    f"{label}.{behavior_id}.hashes must be an object"
                )
            query_sha256 = row_hashes.get("query_sha256")
            if query_sha256 is not None:
                identity_hashes.add(
                    _require_sha256(
                        query_sha256, f"{label}.{behavior_id}.query_sha256"
                    )
                )
            if identity_hashes & seen_identity_hashes:
                raise D1ReviewReselectionError(
                    f"{label} contains a duplicate candidate identity hash"
                )
            seen_identity_hashes.update(identity_hashes)


def _ranked_behavior_ids(
    approved_by_category: Mapping[str, Sequence[promotion._Candidate]],
    seed: int,
) -> tuple[str, ...]:
    selected: list[str] = []
    for category in promotion.CANONICAL_CATEGORIES:
        ranked = sorted(
            approved_by_category[category],
            key=lambda candidate: (
                promotion._rank_sha256(candidate, seed),
                str(candidate.entry["behavior_id"]),
            ),
        )
        selected.extend(
            str(candidate.entry["behavior_id"])
            for candidate in ranked[: promotion.PER_CATEGORY]
        )
    return tuple(selected)


def _build_attestation(
    *,
    prior: promotion._VerifiedCohort,
    rejected: tuple[tuple[str, str], ...],
    start_seed: int,
    chosen_seed: int,
    new_promotion: promotion.D1ReviewPromotion,
) -> dict[str, Any]:
    rejected_counts = Counter(category for _behavior_id, category in rejected)
    attestation: dict[str, Any] = {
        "schema_version": 1,
        "protocol": RESELECTION_PROTOCOL,
        "artifact_type": RESELECTION_ARTIFACT_TYPE,
        "status": RESELECTION_STATUS,
        "target_outcomes_used": False,
        "prior_final_review": {
            "challenge_manifest_sha256": prior.challenge_manifest_sha256,
            "private_rows_file_sha256": prior.private_rows_file_sha256,
            "reviewer_packet_sha256": sorted(prior.packet_sha256),
            "reviewer_decision_artifact_sha256": sorted(prior.decision_sha256),
        },
        "rejection_summary": {
            "rejected_count": len(rejected),
            "category_rejected_counts": {
                category: rejected_counts[category]
                for category in promotion.CANONICAL_CATEGORIES
            },
        },
        "seed_search": {
            "policy": SEED_SEARCH_POLICY,
            "start_seed": start_seed,
            "chosen_seed": chosen_seed,
            "examined_seed_count": chosen_seed - start_seed + 1,
        },
        "new_promotion_manifest_sha256": new_promotion.manifest["manifest_sha256"],
    }
    promotion._reject_public_private_fields(attestation, "reselection attestation")
    attestation["attestation_sha256"] = canonical_sha256(attestation)
    return attestation


def build_d1_review_reselection(
    original_cohorts: promotion.PendingReviewCohortArtifacts
    | Sequence[promotion.PendingReviewCohortArtifacts],
    *,
    prior_pending_manifest_path: str | Path,
    prior_private_rows_path: str | Path,
    prior_reviewer_packet_paths: tuple[str | Path, str | Path],
    prior_reviewer_decision_paths: tuple[str | Path, str | Path],
    ranking_seed_start: int,
    max_seed_attempts: int = DEFAULT_MAX_SEED_ATTEMPTS,
) -> D1ReviewReselection:
    """Return the first promotion that excludes all prior non-approvals."""

    cohorts = _normalize_original_cohorts(original_cohorts)
    start_seed = _require_int(ranking_seed_start, "ranking_seed_start")
    attempt_limit = _require_int(
        max_seed_attempts, "max_seed_attempts", minimum=1
    )
    try:
        initial_promotion = promotion.build_d1_review_promotion(
            cohorts,
            ranking_seed=start_seed,
        )
        verified_sources = tuple(
            promotion._verify_cohort(cohort, cohort_index=index)
            for index, cohort in enumerate(cohorts)
        )
        prior = promotion._verify_cohort(
            promotion.PendingReviewCohortArtifacts(
                pending_manifest_path=prior_pending_manifest_path,
                private_rows_path=prior_private_rows_path,
                reviewer_packet_paths=prior_reviewer_packet_paths,
                reviewer_decision_paths=prior_reviewer_decision_paths,
            ),
            cohort_index=0,
        )
    except promotion.D1ReviewPromotionError as exc:
        raise D1ReviewReselectionError(str(exc)) from exc

    source_fingerprints = _source_fingerprints_from_manifest(
        initial_promotion.manifest
    )
    _validate_verified_candidate_identities(
        verified_sources, label="original reviewed pool"
    )
    _validate_verified_candidate_identities((prior,), label="prior final cohort")
    if _source_fingerprints_from_verified(verified_sources) != source_fingerprints:
        raise D1ReviewReselectionError(
            "original cohort artifacts changed during validation"
        )

    prior_category_counts = Counter(
        str(candidate.entry["category"]) for candidate in prior.candidates
    )
    expected_category_counts = {
        category: promotion.PER_CATEGORY
        for category in promotion.CANONICAL_CATEGORIES
    }
    if dict(prior_category_counts) != expected_category_counts:
        raise D1ReviewReselectionError(
            "prior final cohort must contain exactly two candidates per category"
        )

    original_by_id: dict[str, promotion._Candidate] = {}
    approved_by_category: dict[str, list[promotion._Candidate]] = defaultdict(list)
    for cohort in verified_sources:
        for candidate in cohort.candidates:
            behavior_id = str(candidate.entry["behavior_id"])
            if behavior_id in original_by_id:
                raise D1ReviewReselectionError(
                    f"duplicate original candidate behavior_id: {behavior_id}"
                )
            original_by_id[behavior_id] = candidate
            if candidate.unanimously_approved:
                approved_by_category[str(candidate.entry["category"])].append(
                    candidate
                )

    rejected: list[tuple[str, str]] = []
    for candidate in prior.candidates:
        behavior_id = str(candidate.entry["behavior_id"])
        try:
            original = original_by_id[behavior_id]
        except KeyError as exc:
            raise D1ReviewReselectionError(
                "prior final candidate is absent from the original reviewed pool"
            ) from exc
        if not original.unanimously_approved:
            raise D1ReviewReselectionError(
                "prior final candidate lacked unanimous approval in the original pool"
            )
        for field_name in _SOURCE_IDENTITY_FIELDS:
            if candidate.entry[field_name] != original.entry[field_name]:
                raise D1ReviewReselectionError(
                    "prior final candidate identity does not match the original pool"
                )
        if not candidate.unanimously_approved:
            rejected.append((behavior_id, str(candidate.entry["category"])))

    rejected_tuple = tuple(sorted(rejected))
    rejected_ids = {behavior_id for behavior_id, _category in rejected_tuple}
    for category in promotion.CANONICAL_CATEGORIES:
        available = sum(
            str(candidate.entry["behavior_id"]) not in rejected_ids
            for candidate in approved_by_category[category]
        )
        if available < promotion.PER_CATEGORY:
            raise D1ReviewReselectionError(
                f"no feasible rejection-free promotion for {category}: "
                f"required={promotion.PER_CATEGORY}, available={available}"
            )

    expected_initial_ids = _ranked_behavior_ids(approved_by_category, start_seed)
    if _selected_behavior_ids(initial_promotion) != expected_initial_ids:
        raise D1ReviewReselectionError("promotion ranking implementation mismatch")

    chosen_seed: int | None = None
    expected_chosen_ids: tuple[str, ...] | None = None
    for offset in range(attempt_limit):
        candidate_seed = start_seed + offset
        selected_ids = _ranked_behavior_ids(approved_by_category, candidate_seed)
        if rejected_ids.isdisjoint(selected_ids):
            chosen_seed = candidate_seed
            expected_chosen_ids = selected_ids
            break
    if chosen_seed is None or expected_chosen_ids is None:
        raise D1ReviewReselectionError(
            "seed search exhausted before finding a rejection-free promotion"
        )

    try:
        new_promotion = (
            initial_promotion
            if chosen_seed == start_seed
            else promotion.build_d1_review_promotion(
                cohorts,
                ranking_seed=chosen_seed,
            )
        )
    except promotion.D1ReviewPromotionError as exc:
        raise D1ReviewReselectionError(str(exc)) from exc
    if (
        _source_fingerprints_from_manifest(new_promotion.manifest)
        != source_fingerprints
    ):
        raise D1ReviewReselectionError(
            "original cohort artifacts changed during seed search"
        )
    if _selected_behavior_ids(new_promotion) != expected_chosen_ids:
        raise D1ReviewReselectionError("chosen promotion does not match seed search")
    if not rejected_ids.isdisjoint(_selected_behavior_ids(new_promotion)):
        raise D1ReviewReselectionError("chosen promotion still contains a rejection")

    attestation = _build_attestation(
        prior=prior,
        rejected=rejected_tuple,
        start_seed=start_seed,
        chosen_seed=chosen_seed,
        new_promotion=new_promotion,
    )
    result = D1ReviewReselection(
        promotion=copy.deepcopy(new_promotion),
        attestation=copy.deepcopy(attestation),
        _rejected_candidates=rejected_tuple,
    )
    _validate_reselection(result)
    return result


def _validate_attestation(value: Mapping[str, Any]) -> None:
    attestation = _require_mapping(value, "reselection attestation")
    _require_exact_fields(
        attestation, _ATTESTATION_FIELDS, "reselection attestation"
    )
    promotion._reject_public_private_fields(attestation, "reselection attestation")
    if (
        attestation.get("schema_version") != 1
        or attestation.get("protocol") != RESELECTION_PROTOCOL
        or attestation.get("artifact_type") != RESELECTION_ARTIFACT_TYPE
        or attestation.get("status") != RESELECTION_STATUS
        or attestation.get("target_outcomes_used") is not False
    ):
        raise D1ReviewReselectionError("reselection attestation header is invalid")
    stored_hash = _require_sha256(
        attestation.get("attestation_sha256"),
        "reselection attestation.attestation_sha256",
    )
    unhashed = dict(attestation)
    unhashed.pop("attestation_sha256", None)
    if canonical_sha256(unhashed) != stored_hash:
        raise D1ReviewReselectionError("reselection attestation self-hash mismatch")

    prior = _require_mapping(
        attestation.get("prior_final_review"), "prior_final_review"
    )
    _require_exact_fields(prior, _PRIOR_REVIEW_FIELDS, "prior_final_review")
    _require_sha256(
        prior.get("challenge_manifest_sha256"),
        "prior_final_review.challenge_manifest_sha256",
    )
    _require_sha256(
        prior.get("private_rows_file_sha256"),
        "prior_final_review.private_rows_file_sha256",
    )
    for field_name in (
        "reviewer_packet_sha256",
        "reviewer_decision_artifact_sha256",
    ):
        hashes = prior.get(field_name)
        if (
            not isinstance(hashes, list)
            or len(hashes) != 2
            or hashes != sorted(hashes)
            or len(set(hashes)) != 2
        ):
            raise D1ReviewReselectionError(
                f"prior_final_review.{field_name} must contain two sorted hashes"
            )
        for index, digest in enumerate(hashes):
            _require_sha256(
                digest, f"prior_final_review.{field_name}[{index}]"
            )

    rejection = _require_mapping(
        attestation.get("rejection_summary"), "rejection_summary"
    )
    _require_exact_fields(
        rejection, _REJECTION_SUMMARY_FIELDS, "rejection_summary"
    )
    rejected_count = _require_int(
        rejection.get("rejected_count"), "rejection_summary.rejected_count"
    )
    counts = _require_mapping(
        rejection.get("category_rejected_counts"),
        "rejection_summary.category_rejected_counts",
    )
    if set(counts) != set(promotion.CANONICAL_CATEGORIES):
        raise D1ReviewReselectionError("rejection category counts are incomplete")
    count_total = sum(
        _require_int(counts[category], f"category_rejected_counts.{category}")
        for category in promotion.CANONICAL_CATEGORIES
    )
    if count_total != rejected_count:
        raise D1ReviewReselectionError("rejection category count total mismatch")

    search = _require_mapping(attestation.get("seed_search"), "seed_search")
    _require_exact_fields(search, _SEED_SEARCH_FIELDS, "seed_search")
    if search.get("policy") != SEED_SEARCH_POLICY:
        raise D1ReviewReselectionError("seed search policy mismatch")
    start_seed = _require_int(search.get("start_seed"), "seed_search.start_seed")
    chosen_seed = _require_int(search.get("chosen_seed"), "seed_search.chosen_seed")
    examined = _require_int(
        search.get("examined_seed_count"),
        "seed_search.examined_seed_count",
        minimum=1,
    )
    if chosen_seed < start_seed or examined != chosen_seed - start_seed + 1:
        raise D1ReviewReselectionError("seed search range is inconsistent")
    _require_sha256(
        attestation.get("new_promotion_manifest_sha256"),
        "new_promotion_manifest_sha256",
    )


def _validate_reselection(value: D1ReviewReselection) -> None:
    if not isinstance(value, D1ReviewReselection):
        raise D1ReviewReselectionError("reselection must be D1ReviewReselection")
    try:
        promotion._validate_public_manifest(value.promotion.manifest)
    except promotion.D1ReviewPromotionError as exc:
        raise D1ReviewReselectionError(str(exc)) from exc
    _validate_attestation(value.attestation)

    private_payload = promotion._private_jsonl_bytes(value.promotion.private_rows)
    private_metadata = value.promotion.manifest["private_rows_artifact"]
    if private_metadata["file_sha256"] != promotion._sha256_bytes(private_payload):
        raise D1ReviewReselectionError("promotion private rows hash mismatch")
    selected = value.promotion.manifest["selected_candidates"]
    if len(selected) != len(value.promotion.private_rows):
        raise D1ReviewReselectionError("promotion private/public count mismatch")
    for index, (row, candidate) in enumerate(
        zip(value.promotion.private_rows, selected, strict=True)
    ):
        if canonical_sha256(row) != candidate["row_sha256"]:
            raise D1ReviewReselectionError(
                f"promotion private/public row mismatch at index {index}"
            )
        if row.get("id") != candidate["behavior_id"]:
            raise D1ReviewReselectionError(
                f"promotion behavior ID mismatch at index {index}"
            )
        hashes = row.get("hashes")
        if not isinstance(hashes, Mapping):
            raise D1ReviewReselectionError(
                f"promotion private row hashes missing at index {index}"
            )
        for field_name in (
            "content_sha256",
            "normalized_query_sha256",
            "decontamination_sha256",
        ):
            if hashes.get(field_name) != candidate[field_name]:
                raise D1ReviewReselectionError(
                    f"promotion identity hash mismatch at index {index}"
                )

    rejected = value._rejected_candidates
    rejected_ids = [behavior_id for behavior_id, _category in rejected]
    if (
        len(rejected_ids) != len(set(rejected_ids))
        or tuple(sorted(rejected)) != rejected
    ):
        raise D1ReviewReselectionError("internal rejected candidates are not canonical")
    if any(
        category not in promotion.CANONICAL_CATEGORIES
        for _behavior_id, category in rejected
    ):
        raise D1ReviewReselectionError("internal rejected candidate category is invalid")
    rejection = value.attestation["rejection_summary"]
    expected_counts = Counter(category for _behavior_id, category in rejected)
    if rejection["rejected_count"] != len(rejected_ids) or rejection[
        "category_rejected_counts"
    ] != {
        category: expected_counts[category]
        for category in promotion.CANONICAL_CATEGORIES
    }:
        raise D1ReviewReselectionError("internal rejection aggregate mismatch")
    selected_ids = {str(candidate["behavior_id"]) for candidate in selected}
    if selected_ids.intersection(rejected_ids):
        raise D1ReviewReselectionError("promotion contains a rejected candidate")
    search = value.attestation["seed_search"]
    if (
        value.promotion.manifest["selection_policy"]["ranking_seed"]
        != search["chosen_seed"]
    ):
        raise D1ReviewReselectionError("promotion seed does not match attestation")
    if (
        value.attestation["new_promotion_manifest_sha256"]
        != value.promotion.manifest["manifest_sha256"]
    ):
        raise D1ReviewReselectionError("promotion hash does not match attestation")


def write_d1_review_reselection(
    reselection: D1ReviewReselection,
    *,
    private_rows_output_path: str | Path,
    promotion_manifest_output_path: str | Path,
    reselection_attestation_output_path: str | Path,
) -> tuple[Path, Path, Path]:
    """Atomically publish the private promotion and two public artifacts."""

    _validate_reselection(reselection)
    destinations = (
        promotion._destination(private_rows_output_path),
        promotion._destination(promotion_manifest_output_path),
        promotion._destination(reselection_attestation_output_path),
    )
    if len(set(destinations)) != 3:
        raise D1ReviewReselectionError("reselection output paths must be distinct")
    for destination in destinations:
        if destination.exists() or destination.is_symlink():
            raise D1ReviewReselectionError(
                f"refusing to overwrite existing artifact: {destination}"
            )

    payloads = (
        promotion._private_jsonl_bytes(reselection.promotion.private_rows),
        (
            json.dumps(
                reselection.promotion.manifest,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8"),
        (
            json.dumps(
                reselection.attestation,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8"),
    )
    modes = (0o600, 0o644, 0o644)
    staged: list[Path] = []
    try:
        for destination, payload, mode in zip(
            destinations, payloads, modes, strict=True
        ):
            staged.append(promotion._stage_payload(destination, payload, mode=mode))
    except Exception:
        for temporary in staged:
            temporary.unlink(missing_ok=True)
        raise

    published: list[Path] = []
    try:
        for temporary, destination in zip(staged, destinations, strict=True):
            try:
                os.link(temporary, destination)
            except FileExistsError as exc:
                raise D1ReviewReselectionError(
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
        for temporary in staged:
            temporary.unlink(missing_ok=True)
    return destinations


__all__ = [
    "DEFAULT_MAX_SEED_ATTEMPTS",
    "RESELECTION_ARTIFACT_TYPE",
    "RESELECTION_PROTOCOL",
    "RESELECTION_STATUS",
    "SEED_SEARCH_POLICY",
    "D1ReviewReselection",
    "D1ReviewReselectionError",
    "build_d1_review_reselection",
    "write_d1_review_reselection",
]
