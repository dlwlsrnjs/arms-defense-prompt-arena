"""Outcome-blind candidate screening for the D1-v2 native calibration cohort.

The screener only uses frozen behavior metadata and aggregate reviewer reason
codes.  It never accepts target outcomes.  Raw candidate rows are written to a
private JSONL artifact, while the public screening manifest contains only
criteria, counts, and cryptographic file attestations.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
PROTOCOL = "armor-d1-v2-outcome-blind-screening-v1"
SCREENED_ARTIFACT_TYPE = "armor-d1-v2-private-screened-candidates-v1"
MANIFEST_ARTIFACT_TYPE = "armor-d1-v2-screening-manifest-v1"
DEFAULT_MIN_QUERY_CHARS = 80
DEFAULT_MAX_QUERY_CHARS = 800

D1_V2_CATEGORY_LEAF_WHITELIST: dict[str, tuple[str, ...]] = {
    "Cyber Harm": ("Malware Generation", "Cyber Attack"),
    "Fraud/Deception": ("Financial Fraud", "Scams"),
    "Hate/Harassment": (
        "Hate Speech",
        "Harass Threaten or Bully An Individual",
    ),
    "Non-violent Crime": ("Drug-related Crimes", "Financial Crimes"),
    "Privacy Violations": ("Illegitimate Surveillance",),
    "Self-Harm": ("Self-Harm",),
    "Sexual/Adult Content": ("Sexual Offenses",),
    "Violence": ("Weapon Generation and Transportation", "Terrorism"),
}

REVIEW_REASON_CODES = frozenset(
    {
        "ambiguous_or_fragmentary",
        "depends_on_missing_context",
        "not_clearly_harmful",
        "real_personal_data_risk",
        "not_vlm_attack_compatible",
        "benchmark_scope_mismatch",
        "other",
    }
)

_EXCLUSION_HASH_FIELDS = (
    "query_sha256",
    "normalized_query_sha256",
    "decontamination_sha256",
    "content_sha256",
)
_RAW_TEXT_KEYS = frozenset({"behavior", "context", "query", "text"})
_ORDERED_FILTER_REASONS = (
    "category_not_allowed",
    "not_harmful",
    "not_defender_train",
    "not_text_modality",
    "query_not_text",
    "query_too_short",
    "query_too_long",
    "leaf_not_allowed",
    "excluded_prior_id_or_hash",
    "duplicate_candidate_identity",
)
_LEAF_PREFIX = re.compile(r"^O[0-9]+: ")
_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "protocol",
        "artifact_type",
        "stage",
        "input",
        "exclusion_files",
        "exclusion_identity_counts",
        "criteria",
        "counts",
        "outcome_blindness",
        "screened_private_file",
        "raw_text_included",
        "manifest_sha256",
    }
)


class D1ScreeningError(ValueError):
    """Raised when screening inputs or frozen artifacts are invalid."""


def canonical_sha256(value: Any) -> str:
    text = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _jsonl_rows(path: Path, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise D1ScreeningError(f"unable to read {label}") from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise D1ScreeningError(
                f"invalid JSON in {label} at line {line_number}"
            ) from exc
        if not isinstance(value, dict):
            raise D1ScreeningError(f"{label} line {line_number} must be a JSON object")
        rows.append(value)
    return rows


def _normalized_whitelist(
    value: Mapping[str, Sequence[str]] | None,
) -> dict[str, tuple[str, ...]]:
    raw = D1_V2_CATEGORY_LEAF_WHITELIST if value is None else value
    if not isinstance(raw, Mapping) or not raw:
        raise D1ScreeningError("category_leaf_whitelist must be a non-empty mapping")
    normalized: dict[str, tuple[str, ...]] = {}
    for category, leaves in raw.items():
        if not isinstance(category, str) or not category:
            raise D1ScreeningError("whitelist categories must be non-empty strings")
        if isinstance(leaves, (str, bytes)) or not isinstance(leaves, Sequence):
            raise D1ScreeningError(
                f"whitelist leaves for {category!r} must be a non-empty sequence"
            )
        leaf_values = tuple(leaves)
        if (
            not leaf_values
            or any(not isinstance(leaf, str) or not leaf for leaf in leaf_values)
            or len(set(leaf_values)) != len(leaf_values)
        ):
            raise D1ScreeningError(
                f"whitelist leaves for {category!r} must be unique non-empty strings"
            )
        normalized[category] = tuple(sorted(leaf_values))
    return dict(sorted(normalized.items()))


def _normalized_reason_counts(value: Mapping[str, int] | None) -> dict[str, int]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise D1ScreeningError("reviewer_reason_counts must be a mapping")
    normalized: dict[str, int] = {}
    for reason, count in value.items():
        if reason not in REVIEW_REASON_CODES:
            raise D1ScreeningError(f"unknown reviewer reason code: {reason!r}")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise D1ScreeningError(
                f"reviewer reason count for {reason!r} must be an integer >= 0"
            )
        normalized[str(reason)] = count
    return dict(sorted(normalized.items()))


def _identity(row: Mapping[str, Any]) -> tuple[str | None, set[str]]:
    row_id = row.get("id")
    normalized_id = row_id if isinstance(row_id, str) and row_id else None
    hashes = row.get("hashes")
    values: set[str] = set()
    if isinstance(hashes, Mapping):
        for field in _EXCLUSION_HASH_FIELDS:
            value = hashes.get(field)
            if isinstance(value, str) and value:
                values.add(value)
    return normalized_id, values


def _source_leaf(row: Mapping[str, Any]) -> str | None:
    path = row.get("source_category_path")
    if (
        isinstance(path, (str, bytes))
        or not isinstance(path, Sequence)
        or not path
        or not isinstance(path[-1], str)
        or not path[-1]
    ):
        return None
    return _LEAF_PREFIX.sub("", path[-1])


def _jsonl_bytes(rows: Sequence[Mapping[str, Any]]) -> bytes:
    return "".join(
        json.dumps(
            dict(row),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
        for row in rows
    ).encode("utf-8")


def _reject_raw_manifest_fields(value: Any, label: str = "manifest") -> None:
    if isinstance(value, Mapping):
        forbidden = sorted(str(key) for key in value if str(key) in _RAW_TEXT_KEYS)
        if forbidden:
            raise D1ScreeningError(f"{label} contains raw-text fields: {forbidden}")
        for key, child in value.items():
            _reject_raw_manifest_fields(child, f"{label}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_raw_manifest_fields(child, f"{label}[{index}]")


def _validate_manifest_self_hash(manifest: Mapping[str, Any]) -> None:
    if set(manifest) != _MANIFEST_FIELDS:
        raise D1ScreeningError("screening manifest fields do not match the schema")
    if (
        manifest.get("schema_version") != SCHEMA_VERSION
        or manifest.get("protocol") != PROTOCOL
        or manifest.get("artifact_type") != MANIFEST_ARTIFACT_TYPE
        or manifest.get("stage") != "D1-v2-screening"
        or manifest.get("raw_text_included") is not False
    ):
        raise D1ScreeningError("screening manifest header is invalid")
    observed = manifest.get("manifest_sha256")
    if (
        not isinstance(observed, str)
        or len(observed) != 64
        or observed != observed.lower()
    ):
        raise D1ScreeningError("screening manifest has no valid self-hash")
    try:
        bytes.fromhex(observed)
    except ValueError as exc:
        raise D1ScreeningError("screening manifest has no valid self-hash") from exc
    unhashed = dict(manifest)
    unhashed.pop("manifest_sha256", None)
    if canonical_sha256(unhashed) != observed:
        raise D1ScreeningError("screening manifest self-hash mismatch")
    _reject_raw_manifest_fields(manifest)
    outcome_blindness = manifest.get("outcome_blindness")
    if not isinstance(outcome_blindness, Mapping) or (
        outcome_blindness.get("target_outcomes_used") is not False
        or outcome_blindness.get("reviewer_feedback_usage")
        != "aggregate_reason_codes_only"
        or outcome_blindness.get("raw_reviewer_items_used") is not False
        or outcome_blindness.get("individual_reviewer_decisions_used") is not False
    ):
        raise D1ScreeningError("screening manifest is not outcome-blind")
    _normalized_reason_counts(outcome_blindness.get("reviewer_reason_code_counts"))


def screen_d1_v2_candidates(
    defender_train_jsonl: str | Path,
    *,
    category_leaf_whitelist: Mapping[str, Sequence[str]] | None = None,
    min_query_chars: int = DEFAULT_MIN_QUERY_CHARS,
    max_query_chars: int = DEFAULT_MAX_QUERY_CHARS,
    exclusion_jsonl_paths: Sequence[str | Path] = (),
    reviewer_reason_counts: Mapping[str, int] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return qualifying raw rows and a raw-free, self-hashed manifest.

    Matching is exact.  The only normalization is removal of an ``Oxx: ``
    prefix from the final ``source_category_path`` label.
    """

    if (
        isinstance(min_query_chars, bool)
        or not isinstance(min_query_chars, int)
        or min_query_chars < 0
        or isinstance(max_query_chars, bool)
        or not isinstance(max_query_chars, int)
        or max_query_chars < min_query_chars
    ):
        raise D1ScreeningError(
            "query character bounds must be integers with 0 <= min <= max"
        )
    whitelist = _normalized_whitelist(category_leaf_whitelist)
    reason_counts = _normalized_reason_counts(reviewer_reason_counts)

    source_path = Path(defender_train_jsonl).expanduser().resolve()
    source_rows = _jsonl_rows(source_path, "defender_train JSONL")
    exclusion_paths = tuple(
        Path(path).expanduser().resolve() for path in exclusion_jsonl_paths
    )
    if len(set(exclusion_paths)) != len(exclusion_paths):
        raise D1ScreeningError("exclusion JSONL paths must be unique")

    excluded_ids: set[str] = set()
    excluded_hashes: set[str] = set()
    exclusion_files: list[dict[str, Any]] = []
    for index, exclusion_path in enumerate(exclusion_paths, start=1):
        rows = _jsonl_rows(exclusion_path, f"exclusion JSONL {index}")
        for row in rows:
            row_id, hashes = _identity(row)
            if row_id is not None:
                excluded_ids.add(row_id)
            excluded_hashes.update(hashes)
        exclusion_files.append(
            {
                "file_sha256": _sha256_file(exclusion_path),
                "row_count": len(rows),
            }
        )

    category_counts = {category: {"before": 0, "after": 0} for category in whitelist}
    for row in source_rows:
        category = row.get("canonical_category")
        if category in category_counts:
            category_counts[str(category)]["before"] += 1

    filter_counts: Counter[str] = Counter()
    selected: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    selected_hashes: set[str] = set()
    for row in source_rows:
        category = row.get("canonical_category")
        if category not in whitelist:
            filter_counts["category_not_allowed"] += 1
            continue
        if row.get("safety_label") != "harmful":
            filter_counts["not_harmful"] += 1
            continue
        if row.get("track") != "defender_train":
            filter_counts["not_defender_train"] += 1
            continue
        if row.get("modality") != "text":
            filter_counts["not_text_modality"] += 1
            continue
        query = row.get("query")
        if not isinstance(query, str):
            filter_counts["query_not_text"] += 1
            continue
        if len(query) < min_query_chars:
            filter_counts["query_too_short"] += 1
            continue
        if len(query) > max_query_chars:
            filter_counts["query_too_long"] += 1
            continue
        if _source_leaf(row) not in whitelist[str(category)]:
            filter_counts["leaf_not_allowed"] += 1
            continue
        row_id, hashes = _identity(row)
        if (row_id is not None and row_id in excluded_ids) or bool(
            hashes & excluded_hashes
        ):
            filter_counts["excluded_prior_id_or_hash"] += 1
            continue
        if (row_id is not None and row_id in selected_ids) or bool(
            hashes & selected_hashes
        ):
            filter_counts["duplicate_candidate_identity"] += 1
            continue
        selected.append(dict(row))
        if row_id is not None:
            selected_ids.add(row_id)
        selected_hashes.update(hashes)
        category_counts[str(category)]["after"] += 1

    screened_bytes = _jsonl_bytes(selected)
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "protocol": PROTOCOL,
        "artifact_type": MANIFEST_ARTIFACT_TYPE,
        "stage": "D1-v2-screening",
        "input": {
            "file_sha256": _sha256_file(source_path),
            "row_count": len(source_rows),
        },
        "exclusion_files": exclusion_files,
        "exclusion_identity_counts": {
            "unique_ids": len(excluded_ids),
            "unique_hashes": len(excluded_hashes),
        },
        "criteria": {
            "safety_label": "harmful",
            "track": "defender_train",
            "modality": "text",
            "min_query_chars": min_query_chars,
            "max_query_chars": max_query_chars,
            "query_bounds_inclusive": True,
            "category_leaf_match": "exact_after_Oxx_prefix_removal",
            "category_leaf_whitelist": {
                category: list(leaves) for category, leaves in whitelist.items()
            },
            "exclude_prior_ids_and_hashes": True,
        },
        "counts": {
            "input_rows": len(source_rows),
            "selected_rows": len(selected),
            "excluded_rows": len(source_rows) - len(selected),
            "filter_exclusion_counts": {
                reason: filter_counts[reason] for reason in _ORDERED_FILTER_REASONS
            },
            "by_category": category_counts,
        },
        "outcome_blindness": {
            "target_outcomes_used": False,
            "reviewer_feedback_usage": "aggregate_reason_codes_only",
            "reviewer_reason_code_counts": reason_counts,
            "raw_reviewer_items_used": False,
            "individual_reviewer_decisions_used": False,
        },
        "screened_private_file": {
            "artifact_type": SCREENED_ARTIFACT_TYPE,
            "file_sha256": hashlib.sha256(screened_bytes).hexdigest(),
            "row_count": len(selected),
            "mode": "0600",
            "contains_raw_text": True,
            "publish": False,
        },
        "raw_text_included": False,
    }
    _reject_raw_manifest_fields(manifest)
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    return selected, manifest


def _atomic_exclusive_write(path: Path, payload: bytes, *, mode: int) -> Path:
    destination = path.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(destination):
        raise D1ScreeningError(
            f"refusing to overwrite existing screening artifact: {destination}"
        )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise D1ScreeningError(
                f"refusing to overwrite existing screening artifact: {destination}"
            ) from exc
        directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return destination
    finally:
        if temporary.exists():
            temporary.unlink()


def write_d1_v2_screening(
    screened_jsonl_path: str | Path,
    manifest_path: str | Path,
    screened_rows: Sequence[Mapping[str, Any]],
    manifest: Mapping[str, Any],
) -> tuple[Path, Path]:
    """Atomically publish private rows and then the raw-free commit manifest."""

    screened_destination = Path(screened_jsonl_path).expanduser().resolve()
    manifest_destination = Path(manifest_path).expanduser().resolve()
    if screened_destination == manifest_destination:
        raise D1ScreeningError("screened JSONL and manifest paths must differ")
    if os.path.lexists(screened_destination) or os.path.lexists(manifest_destination):
        raise D1ScreeningError("refusing to overwrite an existing screening artifact")

    _validate_manifest_self_hash(manifest)
    screened_bytes = _jsonl_bytes(screened_rows)
    private_contract = manifest.get("screened_private_file")
    if not isinstance(private_contract, Mapping):
        raise D1ScreeningError("screening manifest lacks the private-file contract")
    if (
        private_contract.get("file_sha256")
        != hashlib.sha256(screened_bytes).hexdigest()
        or private_contract.get("row_count") != len(screened_rows)
        or private_contract.get("mode") != "0600"
        or private_contract.get("contains_raw_text") is not True
        or private_contract.get("publish") is not False
    ):
        raise D1ScreeningError("screened rows do not match the manifest contract")
    counts = manifest.get("counts")
    if not isinstance(counts, Mapping) or counts.get("selected_rows") != len(
        screened_rows
    ):
        raise D1ScreeningError("screening count does not match screened rows")

    manifest_bytes = (
        json.dumps(
            dict(manifest),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    private_path = _atomic_exclusive_write(
        screened_destination,
        screened_bytes,
        mode=0o600,
    )
    public_path = _atomic_exclusive_write(
        manifest_destination,
        manifest_bytes,
        mode=0o644,
    )
    return private_path, public_path


__all__ = [
    "D1_V2_CATEGORY_LEAF_WHITELIST",
    "DEFAULT_MAX_QUERY_CHARS",
    "DEFAULT_MIN_QUERY_CHARS",
    "MANIFEST_ARTIFACT_TYPE",
    "PROTOCOL",
    "REVIEW_REASON_CODES",
    "SCREENED_ARTIFACT_TYPE",
    "D1ScreeningError",
    "canonical_sha256",
    "screen_d1_v2_candidates",
    "write_d1_v2_screening",
]
