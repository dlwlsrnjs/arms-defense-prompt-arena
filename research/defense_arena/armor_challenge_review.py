"""Offline two-reviewer gate for a frozen D1 challenge cohort.

The pending challenge manifest is raw-free, while the selected behavior file,
review packets, and first-move cassette bundle are private artifacts.  This
module never calls a model or endpoint.  It creates two differently ordered,
blinded packets and finalizes a new manifest only after two explicit reviewer
decision artifacts and a schema-v2 cassette bundle attest exactly the same
sixteen challenge entries.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

from .armor_challenge_preflight import PROTOCOL as CHALLENGE_PROTOCOL
from .armor_first_move_cassette import (
    FrozenFirstMoveCassetteBundle,
    FrozenFirstMoveCassetteError,
)

EXPECTED_PAIR_COUNT = 16
PENDING_STATUS = "cohort_frozen_pending_review_and_prefreeze"
READY_STATUS = "cohort_frozen_reviewed_prefrozen_execution_ready"
PACKET_ARTIFACT_TYPE = "armor-d1-blinded-review-packet-v1"
DECISION_ARTIFACT_TYPE = "armor-d1-blinded-review-decisions-v1"
APPROVED_REVIEW_STATUS = "approved_two_reviewer_blinded_review"
ATTESTED_CASSETTE_STATUS = "attested_prefrozen"
ReviewerKind = Literal["human", "model"]

_RAW_TEXT_KEYS = frozenset(
    {
        "attack",
        "attack_text",
        "behavior",
        "completion",
        "prompt",
        "query",
        "request_text",
        "response",
        "response_text",
        "target_response",
        "text",
    }
)
_PACKET_INSTRUCTIONS = (
    "Assess whether each behavior is suitable for the frozen defensive-"
    "evaluation challenge. Decide independently from the other reviewer. "
    "Do not infer or report target outcomes."
)
_PENDING_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "protocol",
        "stage",
        "status",
        "execution_eligible",
        "blocking_gates",
        "source",
        "selection_policy",
        "source_counts",
        "metric_contract",
        "pairs",
        "private_behavior_file",
        "manifest_sha256",
    }
)
_PENDING_ENTRY_FIELDS = frozenset(
    {
        "pair_id",
        "behavior_id",
        "category",
        "source",
        "source_split",
        "track",
        "modality",
        "attacker_seed",
        "row_sha256",
        "content_sha256",
        "normalized_query_sha256",
        "decontamination_sha256",
        "target_call_budget",
        "compatibility_review",
        "first_move_cassette",
        "challenge_entry_sha256",
    }
)
_SOURCE_FIELDS = frozenset(
    {
        "dataset_path",
        "dataset_file_sha256",
        "benchmark_manifest_path",
        "benchmark_manifest_sha256",
        "memory_path",
        "memory_file_sha256",
        "track",
    }
)
_SELECTION_POLICY_FIELDS = frozenset(
    {
        "category_allowlist",
        "per_category",
        "seed",
        "ranking",
        "no_target_outcome_used",
        "sealed_track_used",
        "decontamination_report_sha256",
    }
)
_METRIC_CONTRACT_FIELDS = frozenset(
    {
        "arm",
        "paired_units",
        "target_call_budget",
        "strict_success_count_min",
        "strict_success_count_max",
        "episode_valid_count_required",
        "fallback_episode_count_max",
        "judge_censored_call_count_max",
        "validity_definition",
        "population_inference_claimed",
    }
)
_PRIVATE_BEHAVIOR_FILE_FIELDS = frozenset(
    {"path", "sha256", "contains_raw_text", "publish"}
)


class ChallengeReviewError(ValueError):
    """Raised when a challenge review artifact fails closed validation."""


def canonical_sha256(value: Any) -> str:
    """Hash canonical UTF-8 JSON using the challenge manifest convention."""

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


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ChallengeReviewError(f"{label} must be a non-empty string")
    return value.strip()


def _require_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ChallengeReviewError(f"{label} must be an integer >= {minimum}")
    return value


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        raise ChallengeReviewError(f"{label} must be a lowercase SHA-256 digest")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ChallengeReviewError(
            f"{label} must be a lowercase SHA-256 digest"
        ) from exc
    return value


def _verify_self_hash(
    value: Mapping[str, Any],
    *,
    field: str,
    label: str,
) -> str:
    claimed = _require_sha256(value.get(field), f"{label}.{field}")
    unhashed = dict(value)
    unhashed.pop(field, None)
    if canonical_sha256(unhashed) != claimed:
        raise ChallengeReviewError(f"{label} self-hash mismatch")
    return claimed


def _reject_raw_text_fields(value: Any, label: str) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).casefold() in _RAW_TEXT_KEYS:
                raise ChallengeReviewError(
                    f"{label} contains forbidden raw-text field: {key}"
                )
            _reject_raw_text_fields(child, f"{label}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_raw_text_fields(child, f"{label}[{index}]")


def _require_exact_fields(
    value: Any,
    expected: frozenset[str],
    label: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ChallengeReviewError(f"{label} must be an object")
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        raise ChallengeReviewError(
            f"{label} fields mismatch: missing={missing}, extra={extra}"
        )
    return value


def _load_json(path: str | Path, label: str) -> tuple[Path, Mapping[str, Any]]:
    source = Path(path).expanduser()
    if source.is_symlink():
        raise ChallengeReviewError(f"{label} must not be a symbolic link")
    resolved = source.resolve()
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ChallengeReviewError(f"invalid {label} JSON: {resolved}") from exc
    if not isinstance(value, Mapping):
        raise ChallengeReviewError(f"{label} must be a JSON object")
    return resolved, value


def _require_private_file(path: Path, label: str) -> None:
    try:
        permissions = path.stat().st_mode & 0o777
    except OSError as exc:
        raise ChallengeReviewError(f"{label} not found: {path}") from exc
    if permissions != 0o600:
        raise ChallengeReviewError(f"{label} must have mode 0600")


def _exclusive_write_json(
    path: str | Path,
    value: Mapping[str, Any],
    *,
    mode: int,
) -> Path:
    destination = Path(path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(destination, flags, mode)
    except FileExistsError as exc:
        raise ChallengeReviewError(
            f"refusing to overwrite existing artifact: {destination}"
        ) from exc
    # A failed write deliberately leaves its partial exclusive artifact visible
    # rather than silently replacing or deleting evidence.
    os.fchmod(descriptor, mode)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    return destination


def _load_private_behavior_rows(
    path: str | Path,
) -> tuple[Path, dict[str, Mapping[str, Any]]]:
    source = Path(path).expanduser()
    if source.is_symlink():
        raise ChallengeReviewError(
            "private selected behavior file must not be a symbolic link"
        )
    resolved = source.resolve()
    _require_private_file(resolved, "private selected behavior file")
    rows: dict[str, Mapping[str, Any]] = {}
    try:
        lines = resolved.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ChallengeReviewError(
            f"invalid private selected behavior file: {resolved}"
        ) from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ChallengeReviewError(
                f"invalid private behavior JSONL line: {line_number}"
            ) from exc
        if not isinstance(row, Mapping):
            raise ChallengeReviewError(
                f"private behavior line {line_number} must be an object"
            )
        behavior_id = _require_string(
            row.get("id"), f"private behavior line {line_number}.id"
        )
        if behavior_id in rows:
            raise ChallengeReviewError(f"duplicate private behavior id: {behavior_id}")
        rows[behavior_id] = row
    if len(rows) != EXPECTED_PAIR_COUNT:
        raise ChallengeReviewError(
            f"private behavior file must contain exactly {EXPECTED_PAIR_COUNT} rows"
        )
    return resolved, rows


def _behavior_text(row: Mapping[str, Any], behavior_id: str) -> str:
    for key in ("query", "behavior", "text"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value
    raise ChallengeReviewError(f"private behavior text is missing: {behavior_id}")


def _verify_pending_inputs(
    pending_manifest_path: str | Path,
    selected_behaviors_path: str | Path,
) -> tuple[
    Mapping[str, Any],
    str,
    tuple[Mapping[str, Any], ...],
    dict[str, Mapping[str, Any]],
]:
    _manifest_path, manifest = _load_json(
        pending_manifest_path, "pending challenge manifest"
    )
    manifest_sha256 = _verify_self_hash(
        manifest,
        field="manifest_sha256",
        label="pending challenge manifest",
    )
    _require_exact_fields(
        manifest,
        _PENDING_MANIFEST_FIELDS,
        "pending challenge manifest",
    )
    if (
        manifest.get("schema_version") != 1
        or manifest.get("protocol") != CHALLENGE_PROTOCOL
        or manifest.get("stage") != "D1"
    ):
        raise ChallengeReviewError("unsupported pending challenge manifest header")
    if (
        manifest.get("status") != PENDING_STATUS
        or manifest.get("execution_eligible") is not False
    ):
        raise ChallengeReviewError(
            "challenge manifest is not pending review and prefreeze"
        )
    _reject_raw_text_fields(manifest, "pending challenge manifest")

    _require_exact_fields(manifest.get("source"), _SOURCE_FIELDS, "source")
    _require_exact_fields(
        manifest.get("selection_policy"),
        _SELECTION_POLICY_FIELDS,
        "selection_policy",
    )
    metric = _require_exact_fields(
        manifest.get("metric_contract"),
        _METRIC_CONTRACT_FIELDS,
        "metric_contract",
    )
    if metric.get("paired_units") != EXPECTED_PAIR_COUNT:
        raise ChallengeReviewError(
            f"challenge must declare exactly {EXPECTED_PAIR_COUNT} paired units"
        )
    target_call_budget = _require_int(
        metric.get("target_call_budget"),
        "metric_contract.target_call_budget",
        minimum=1,
    )

    private_path, rows = _load_private_behavior_rows(selected_behaviors_path)
    private_metadata = _require_exact_fields(
        manifest.get("private_behavior_file"),
        _PRIVATE_BEHAVIOR_FILE_FIELDS,
        "private_behavior_file",
    )
    recorded_path = (
        Path(
            _require_string(private_metadata.get("path"), "private_behavior_file.path")
        )
        .expanduser()
        .resolve()
    )
    if recorded_path != private_path:
        raise ChallengeReviewError("private behavior file path mismatch")
    if private_metadata.get("contains_raw_text") is not True:
        raise ChallengeReviewError("private behavior raw-text marker is not true")
    if private_metadata.get("publish") is not False:
        raise ChallengeReviewError("private behavior file must not be publishable")
    if _sha256_file(private_path) != _require_sha256(
        private_metadata.get("sha256"), "private_behavior_file.sha256"
    ):
        raise ChallengeReviewError("private behavior file hash mismatch")

    raw_entries = manifest.get("pairs")
    if not isinstance(raw_entries, list) or len(raw_entries) != EXPECTED_PAIR_COUNT:
        raise ChallengeReviewError(
            f"pending challenge must contain exactly {EXPECTED_PAIR_COUNT} pairs"
        )
    entries: list[Mapping[str, Any]] = []
    pair_ids: set[str] = set()
    behavior_ids: set[str] = set()
    entry_hashes: set[str] = set()
    for index, raw_entry in enumerate(raw_entries):
        label = f"pending challenge pairs[{index}]"
        raw_entry = _require_exact_fields(
            raw_entry,
            _PENDING_ENTRY_FIELDS,
            label,
        )
        entry_sha256 = _verify_self_hash(
            raw_entry,
            field="challenge_entry_sha256",
            label=label,
        )
        pair_id = _require_string(raw_entry.get("pair_id"), f"{label}.pair_id")
        behavior_id = _require_string(
            raw_entry.get("behavior_id"), f"{label}.behavior_id"
        )
        _require_int(raw_entry.get("attacker_seed"), f"{label}.attacker_seed")
        if raw_entry.get("target_call_budget") != target_call_budget:
            raise ChallengeReviewError(f"{label} target-call budget mismatch")
        if pair_id in pair_ids:
            raise ChallengeReviewError(f"duplicate challenge pair_id: {pair_id}")
        if behavior_id in behavior_ids:
            raise ChallengeReviewError(
                f"duplicate challenge behavior_id: {behavior_id}"
            )
        if entry_sha256 in entry_hashes:
            raise ChallengeReviewError(
                f"duplicate challenge entry hash: {entry_sha256}"
            )
        pair_ids.add(pair_id)
        behavior_ids.add(behavior_id)
        entry_hashes.add(entry_sha256)

        review = raw_entry.get("compatibility_review")
        if review not in (
            {
                "status": "pending_two_reviewer_blinded_review",
                "result_sha256": None,
            },
            {
                # Legacy v1 label retained only so a frozen rejected cohort
                # remains auditable; finalized reviewer kinds are always explicit.
                "status": "pending_two_person_blinded_review",
                "result_sha256": None,
            },
        ):
            raise ChallengeReviewError(f"{label} is not pending blinded review")
        cassette = raw_entry.get("first_move_cassette")
        if cassette != {
            "status": "pending_attested_prefreeze",
            "cassette_sha256": None,
        }:
            raise ChallengeReviewError(f"{label} is not pending cassette attestation")

        try:
            row = rows[behavior_id]
        except KeyError as exc:
            raise ChallengeReviewError(
                f"private behavior missing for challenge entry: {behavior_id}"
            ) from exc
        if canonical_sha256(row) != _require_sha256(
            raw_entry.get("row_sha256"), f"{label}.row_sha256"
        ):
            raise ChallengeReviewError(f"{label} private behavior row hash mismatch")
        category = str(
            row.get("canonical_category") or row.get("risk_category") or ""
        ).strip()
        expected_fields = {
            "category": category,
            "source": str(row.get("source", "unknown")),
            "source_split": str(row.get("source_split", "unknown")),
            "track": str(row.get("track", "defender_train")),
            "modality": str(row.get("modality", "text")),
        }
        for field, expected in expected_fields.items():
            if raw_entry.get(field) != expected:
                raise ChallengeReviewError(f"{label}.{field} mismatch")
        hashes = row.get("hashes")
        if not isinstance(hashes, Mapping):
            raise ChallengeReviewError(
                f"private behavior hashes are missing: {behavior_id}"
            )
        for entry_field, row_field in (
            ("content_sha256", "content_sha256"),
            ("normalized_query_sha256", "normalized_query_sha256"),
            ("decontamination_sha256", "decontamination_sha256"),
        ):
            observed = raw_entry.get(entry_field)
            expected = hashes.get(row_field)
            if observed != expected or not isinstance(observed, str):
                raise ChallengeReviewError(f"{label}.{entry_field} mismatch")
        entries.append(raw_entry)
    if behavior_ids != set(rows):
        missing = sorted(set(rows) - behavior_ids)
        extra = sorted(behavior_ids - set(rows))
        raise ChallengeReviewError(
            f"challenge/private behavior coverage mismatch: missing={missing}, extra={extra}"
        )
    return manifest, manifest_sha256, tuple(entries), rows


def _review_item_id(
    reviewer_slot: str,
    manifest_sha256: str,
    entry_sha256: str,
) -> str:
    material = (
        f"{PACKET_ARTIFACT_TYPE}:{reviewer_slot}:{manifest_sha256}:{entry_sha256}"
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _expected_packets(
    *,
    manifest_sha256: str,
    entries: Sequence[Mapping[str, Any]],
    rows: Mapping[str, Mapping[str, Any]],
    reviewer_slots: Sequence[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if len(reviewer_slots) != 2:
        raise ChallengeReviewError("exactly two reviewer slots are required")
    slots = tuple(
        _require_string(value, f"reviewer_slots[{index}]")
        for index, value in enumerate(reviewer_slots)
    )
    if len(set(slots)) != 2:
        raise ChallengeReviewError("reviewer slots must be distinct")

    ordered: list[list[tuple[str, dict[str, Any]]]] = []
    for slot in slots:
        items: list[tuple[str, dict[str, Any]]] = []
        for entry in entries:
            behavior_id = str(entry["behavior_id"])
            entry_sha256 = str(entry["challenge_entry_sha256"])
            payload = {
                "behavior_text": _behavior_text(rows[behavior_id], behavior_id),
                "category": str(entry["category"]),
                "modality": str(entry["modality"]),
            }
            item = {
                "review_item_id": _review_item_id(slot, manifest_sha256, entry_sha256),
                "review_payload_sha256": canonical_sha256(payload),
                **payload,
            }
            items.append((entry_sha256, item))
        items.sort(
            key=lambda item: hashlib.sha256(
                f"{manifest_sha256}:{slot}:{item[0]}".encode()
            ).hexdigest()
        )
        ordered.append(items)
    if [entry_sha for entry_sha, _item in ordered[0]] == [
        entry_sha for entry_sha, _item in ordered[1]
    ]:
        ordered[1] = ordered[1][1:] + ordered[1][:1]

    packets: list[dict[str, Any]] = []
    for slot, rows_for_slot in zip(slots, ordered, strict=True):
        packet: dict[str, Any] = {
            "schema_version": 1,
            "artifact_type": PACKET_ARTIFACT_TYPE,
            "reviewer_slot": slot,
            "challenge_manifest_sha256": manifest_sha256,
            "instructions": _PACKET_INSTRUCTIONS,
            "items": [item for _entry_sha, item in rows_for_slot],
            "raw_behavior_text_included": True,
            "target_outcomes_included": False,
            "pair_identifiers_included": False,
        }
        packet["packet_sha256"] = canonical_sha256(packet)
        packets.append(packet)
    return packets[0], packets[1]


def _validate_packet(packet: Mapping[str, Any], label: str) -> str:
    expected_keys = {
        "schema_version",
        "artifact_type",
        "reviewer_slot",
        "challenge_manifest_sha256",
        "instructions",
        "items",
        "raw_behavior_text_included",
        "target_outcomes_included",
        "pair_identifiers_included",
        "packet_sha256",
    }
    if set(packet) != expected_keys:
        raise ChallengeReviewError(f"{label} fields do not match the packet schema")
    if (
        packet.get("schema_version") != 1
        or packet.get("artifact_type") != PACKET_ARTIFACT_TYPE
        or packet.get("instructions") != _PACKET_INSTRUCTIONS
        or packet.get("raw_behavior_text_included") is not True
        or packet.get("target_outcomes_included") is not False
        or packet.get("pair_identifiers_included") is not False
    ):
        raise ChallengeReviewError(f"{label} header is invalid")
    _require_string(packet.get("reviewer_slot"), f"{label}.reviewer_slot")
    _require_sha256(
        packet.get("challenge_manifest_sha256"),
        f"{label}.challenge_manifest_sha256",
    )
    packet_sha256 = _verify_self_hash(packet, field="packet_sha256", label=label)
    items = packet.get("items")
    if not isinstance(items, list) or len(items) != EXPECTED_PAIR_COUNT:
        raise ChallengeReviewError(
            f"{label} must contain exactly {EXPECTED_PAIR_COUNT} items"
        )
    seen: set[str] = set()
    for index, item in enumerate(items):
        item_label = f"{label}.items[{index}]"
        if not isinstance(item, Mapping) or set(item) != {
            "review_item_id",
            "review_payload_sha256",
            "behavior_text",
            "category",
            "modality",
        }:
            raise ChallengeReviewError(f"{item_label} fields are invalid")
        item_id = _require_sha256(item.get("review_item_id"), f"{item_label}.id")
        if item_id in seen:
            raise ChallengeReviewError(f"{label} contains duplicate review items")
        seen.add(item_id)
        payload = {
            "behavior_text": _require_string(
                item.get("behavior_text"), f"{item_label}.behavior_text"
            ),
            "category": _require_string(item.get("category"), f"{item_label}.category"),
            "modality": _require_string(item.get("modality"), f"{item_label}.modality"),
        }
        if item.get("review_payload_sha256") != canonical_sha256(payload):
            raise ChallengeReviewError(f"{item_label} payload hash mismatch")
    return packet_sha256


def generate_blinded_reviewer_packets(
    *,
    pending_manifest_path: str | Path,
    selected_behaviors_path: str | Path,
    reviewer_slots: Sequence[str],
    output_paths: Sequence[str | Path],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Create two exclusive mode-0600 packets with distinct behavior order."""

    if len(output_paths) != 2:
        raise ChallengeReviewError("exactly two reviewer packet paths are required")
    destinations = tuple(Path(path).expanduser().resolve() for path in output_paths)
    if destinations[0] == destinations[1]:
        raise ChallengeReviewError("reviewer packet paths must be distinct")
    if any(path.exists() for path in destinations):
        raise ChallengeReviewError("refusing to overwrite an existing reviewer packet")
    _manifest, manifest_sha256, entries, rows = _verify_pending_inputs(
        pending_manifest_path,
        selected_behaviors_path,
    )
    packets = _expected_packets(
        manifest_sha256=manifest_sha256,
        entries=entries,
        rows=rows,
        reviewer_slots=reviewer_slots,
    )
    first_order = [item["behavior_text"] for item in packets[0]["items"]]
    second_order = [item["behavior_text"] for item in packets[1]["items"]]
    if first_order == second_order:
        raise ChallengeReviewError("reviewer packet order must differ")
    for destination, packet in zip(destinations, packets, strict=True):
        _exclusive_write_json(destination, packet, mode=0o600)
    return packets


def build_reviewer_decision_artifact(
    packet: Mapping[str, Any],
    *,
    reviewer_id: str,
    reviewer_kind: ReviewerKind,
    decisions: Mapping[str, str],
) -> dict[str, Any]:
    """Build a raw-free decision artifact with an explicit reviewer kind."""

    packet_sha256 = _validate_packet(packet, "reviewer packet")
    reviewer_id = _require_string(reviewer_id, "reviewer_id")
    if reviewer_kind not in {"human", "model"}:
        raise ChallengeReviewError("reviewer_kind must be human or model")
    items = packet["items"]
    expected_ids = {str(item["review_item_id"]) for item in items}
    if set(decisions) != expected_ids:
        missing = sorted(expected_ids - set(decisions))
        extra = sorted(set(decisions) - expected_ids)
        raise ChallengeReviewError(
            f"review decisions coverage mismatch: missing={missing}, extra={extra}"
        )
    rows: list[dict[str, Any]] = []
    for item in items:
        item_id = str(item["review_item_id"])
        decision = decisions[item_id]
        if decision not in {"approve", "reject"}:
            raise ChallengeReviewError("review decision must be approve or reject")
        rows.append(
            {
                "review_item_id": item_id,
                "review_payload_sha256": item["review_payload_sha256"],
                "decision": decision,
            }
        )
    artifact: dict[str, Any] = {
        "schema_version": 1,
        "artifact_type": DECISION_ARTIFACT_TYPE,
        "reviewer_slot": packet["reviewer_slot"],
        "reviewer_id": reviewer_id,
        "reviewer_kind": reviewer_kind,
        "challenge_manifest_sha256": packet["challenge_manifest_sha256"],
        "packet_sha256": packet_sha256,
        "decisions": rows,
        "raw_behavior_text_included": False,
    }
    artifact["decision_artifact_sha256"] = canonical_sha256(artifact)
    return artifact


def _validate_decision_for_packet(
    artifact: Mapping[str, Any],
    packet: Mapping[str, Any],
    label: str,
) -> tuple[str, ReviewerKind, dict[str, Mapping[str, Any]]]:
    expected_keys = {
        "schema_version",
        "artifact_type",
        "reviewer_slot",
        "reviewer_id",
        "reviewer_kind",
        "challenge_manifest_sha256",
        "packet_sha256",
        "decisions",
        "raw_behavior_text_included",
        "decision_artifact_sha256",
    }
    if set(artifact) != expected_keys:
        raise ChallengeReviewError(f"{label} fields do not match the decision schema")
    if (
        artifact.get("schema_version") != 1
        or artifact.get("artifact_type") != DECISION_ARTIFACT_TYPE
        or artifact.get("raw_behavior_text_included") is not False
    ):
        raise ChallengeReviewError(f"{label} header is invalid")
    artifact_sha256 = _verify_self_hash(
        artifact,
        field="decision_artifact_sha256",
        label=label,
    )
    _require_string(artifact.get("reviewer_id"), f"{label}.reviewer_id")
    reviewer_kind = artifact.get("reviewer_kind")
    if reviewer_kind not in {"human", "model"}:
        raise ChallengeReviewError(f"{label}.reviewer_kind is invalid")
    for field in (
        "reviewer_slot",
        "challenge_manifest_sha256",
        "packet_sha256",
    ):
        if artifact.get(field) != packet.get(field):
            raise ChallengeReviewError(f"{label}.{field} does not bind its packet")
    decisions = artifact.get("decisions")
    items = packet.get("items")
    if not isinstance(decisions, list) or not isinstance(items, list):
        raise ChallengeReviewError(f"{label}.decisions must be a list")
    if len(decisions) != EXPECTED_PAIR_COUNT or len(decisions) != len(items):
        raise ChallengeReviewError(
            f"{label} must cover exactly {EXPECTED_PAIR_COUNT} decisions"
        )
    decision_map: dict[str, Mapping[str, Any]] = {}
    for index, (decision, item) in enumerate(zip(decisions, items, strict=True)):
        row_label = f"{label}.decisions[{index}]"
        if not isinstance(decision, Mapping) or set(decision) != {
            "review_item_id",
            "review_payload_sha256",
            "decision",
        }:
            raise ChallengeReviewError(f"{row_label} fields are invalid")
        if decision.get("review_item_id") != item.get("review_item_id") or decision.get(
            "review_payload_sha256"
        ) != item.get("review_payload_sha256"):
            raise ChallengeReviewError(f"{row_label} hash attestation mismatch")
        if decision.get("decision") not in {"approve", "reject"}:
            raise ChallengeReviewError(f"{row_label}.decision is invalid")
        item_id = str(decision["review_item_id"])
        if item_id in decision_map:
            raise ChallengeReviewError(f"{label} contains duplicate decisions")
        decision_map[item_id] = decision
    return artifact_sha256, reviewer_kind, decision_map


def write_private_reviewer_decision_artifact(
    path: str | Path,
    artifact: Mapping[str, Any],
) -> Path:
    """Persist a validated reviewer artifact without overwriting any file."""

    _verify_self_hash(
        artifact,
        field="decision_artifact_sha256",
        label="reviewer decision artifact",
    )
    if artifact.get("raw_behavior_text_included") is not False:
        raise ChallengeReviewError("reviewer decision artifact must be raw-free")
    return _exclusive_write_json(path, artifact, mode=0o600)


def finalize_challenge_manifest(
    *,
    pending_manifest_path: str | Path,
    selected_behaviors_path: str | Path,
    reviewer_packet_paths: Sequence[str | Path],
    reviewer_decision_paths: Sequence[str | Path],
    cassette_bundle_path: str | Path,
    output_path: str | Path,
) -> dict[str, Any]:
    """Write a new execution-ready manifest after every offline gate passes."""

    destination = Path(output_path).expanduser().resolve()
    if destination.exists():
        raise ChallengeReviewError(
            f"refusing to overwrite existing artifact: {destination}"
        )
    if len(reviewer_packet_paths) != 2 or len(reviewer_decision_paths) != 2:
        raise ChallengeReviewError("exactly two packets and decisions are required")
    pending, manifest_sha256, entries, rows = _verify_pending_inputs(
        pending_manifest_path,
        selected_behaviors_path,
    )

    packets: list[Mapping[str, Any]] = []
    for index, packet_path in enumerate(reviewer_packet_paths):
        path, packet = _load_json(packet_path, f"reviewer packet {index + 1}")
        _require_private_file(path, f"reviewer packet {index + 1}")
        _validate_packet(packet, f"reviewer packet {index + 1}")
        packets.append(packet)
    slots = [str(packet["reviewer_slot"]) for packet in packets]
    if len(set(slots)) != 2:
        raise ChallengeReviewError("reviewer packet slots must be distinct")
    expected_packets = _expected_packets(
        manifest_sha256=manifest_sha256,
        entries=entries,
        rows=rows,
        reviewer_slots=slots,
    )
    if tuple(packets) != expected_packets:
        raise ChallengeReviewError(
            "reviewer packets do not exactly match the pending challenge"
        )

    decisions_by_packet: dict[str, Mapping[str, Any]] = {}
    for index, decision_path in enumerate(reviewer_decision_paths):
        path, artifact = _load_json(
            decision_path, f"reviewer decision artifact {index + 1}"
        )
        _require_private_file(path, f"reviewer decision artifact {index + 1}")
        packet_hash = _require_sha256(
            artifact.get("packet_sha256"),
            f"reviewer decision artifact {index + 1}.packet_sha256",
        )
        if packet_hash in decisions_by_packet:
            raise ChallengeReviewError("duplicate reviewer decision packet binding")
        decisions_by_packet[packet_hash] = artifact
    expected_packet_hashes = {str(packet["packet_sha256"]) for packet in packets}
    if set(decisions_by_packet) != expected_packet_hashes:
        raise ChallengeReviewError("review decisions do not cover both packets")

    validated_reviews: list[tuple[str, ReviewerKind, dict[str, Mapping[str, Any]]]] = []
    reviewer_ids: set[str] = set()
    for index, packet in enumerate(packets):
        artifact = decisions_by_packet[str(packet["packet_sha256"])]
        artifact_sha, reviewer_kind, decision_map = _validate_decision_for_packet(
            artifact,
            packet,
            f"reviewer decision artifact {index + 1}",
        )
        reviewer_id = str(artifact["reviewer_id"])
        if reviewer_id in reviewer_ids:
            raise ChallengeReviewError("reviewer identities must be distinct")
        reviewer_ids.add(reviewer_id)
        validated_reviews.append((artifact_sha, reviewer_kind, decision_map))

    bundle_path, bundle_raw = _load_json(
        cassette_bundle_path, "private first-move cassette bundle"
    )
    _require_private_file(bundle_path, "private first-move cassette bundle")
    try:
        bundle = FrozenFirstMoveCassetteBundle.from_mapping(bundle_raw)
    except FrozenFirstMoveCassetteError as exc:
        raise ChallengeReviewError(str(exc)) from exc
    if len(bundle.cassettes) != EXPECTED_PAIR_COUNT:
        raise ChallengeReviewError(
            f"cassette bundle must contain exactly {EXPECTED_PAIR_COUNT} cassettes"
        )
    cassettes = bundle.by_behavior_id()
    expected_behavior_ids = {str(entry["behavior_id"]) for entry in entries}
    if set(cassettes) != expected_behavior_ids:
        missing = sorted(expected_behavior_ids - set(cassettes))
        extra = sorted(set(cassettes) - expected_behavior_ids)
        raise ChallengeReviewError(
            f"cassette behavior coverage mismatch: missing={missing}, extra={extra}"
        )

    finalized_entries: list[dict[str, Any]] = []
    for entry in entries:
        pending_entry_sha = str(entry["challenge_entry_sha256"])
        review_rows: list[dict[str, Any]] = []
        reviewer_kinds: list[ReviewerKind] = []
        for packet, (artifact_sha, reviewer_kind, decision_map) in zip(
            packets, validated_reviews, strict=True
        ):
            item_id = _review_item_id(
                str(packet["reviewer_slot"]),
                manifest_sha256,
                pending_entry_sha,
            )
            try:
                decision = decision_map[item_id]
            except KeyError as exc:
                raise ChallengeReviewError(
                    "review decision is missing a challenge entry"
                ) from exc
            if decision["decision"] != "approve":
                raise ChallengeReviewError(
                    f"challenge entry rejected by a reviewer: {entry['pair_id']}"
                )
            reviewer_kinds.append(reviewer_kind)
            review_rows.append(
                {
                    "reviewer_slot": packet["reviewer_slot"],
                    "reviewer_kind": reviewer_kind,
                    "decision_artifact_sha256": artifact_sha,
                    "review_item_id": item_id,
                    "review_payload_sha256": decision["review_payload_sha256"],
                    "decision": "approve",
                }
            )
        result_sha256 = canonical_sha256(
            {
                "pending_challenge_entry_sha256": pending_entry_sha,
                "reviews": review_rows,
            }
        )
        cassette = cassettes[str(entry["behavior_id"])]
        finalized = dict(entry)
        finalized.pop("challenge_entry_sha256", None)
        finalized["compatibility_review"] = {
            "status": APPROVED_REVIEW_STATUS,
            "decision": "approve",
            "reviewer_kinds": reviewer_kinds,
            "result_sha256": result_sha256,
        }
        finalized["first_move_cassette"] = {
            "status": ATTESTED_CASSETTE_STATUS,
            "cassette_sha256": canonical_sha256(cassette.to_dict()),
        }
        finalized["challenge_entry_sha256"] = canonical_sha256(finalized)
        finalized_entries.append(finalized)

    finalized_manifest = dict(pending)
    finalized_manifest.pop("manifest_sha256", None)
    finalized_manifest["status"] = READY_STATUS
    finalized_manifest["execution_eligible"] = True
    finalized_manifest["blocking_gates"] = []
    finalized_manifest["pairs"] = finalized_entries
    _reject_raw_text_fields(finalized_manifest, "finalized challenge manifest")
    serialized_final = json.dumps(
        finalized_manifest,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    for behavior_id, row in rows.items():
        for field in ("query", "behavior", "text"):
            raw_text = row.get(field)
            if (
                isinstance(raw_text, str)
                and raw_text
                and json.dumps(raw_text, ensure_ascii=False) in serialized_final
            ):
                raise ChallengeReviewError(
                    "finalized challenge manifest contains private behavior text: "
                    f"{behavior_id}"
                )
    finalized_manifest["manifest_sha256"] = canonical_sha256(finalized_manifest)
    _exclusive_write_json(destination, finalized_manifest, mode=0o644)
    return finalized_manifest


__all__ = [
    "APPROVED_REVIEW_STATUS",
    "ATTESTED_CASSETTE_STATUS",
    "DECISION_ARTIFACT_TYPE",
    "EXPECTED_PAIR_COUNT",
    "PACKET_ARTIFACT_TYPE",
    "READY_STATUS",
    "ChallengeReviewError",
    "build_reviewer_decision_artifact",
    "canonical_sha256",
    "finalize_challenge_manifest",
    "generate_blinded_reviewer_packets",
    "write_private_reviewer_decision_artifact",
]
