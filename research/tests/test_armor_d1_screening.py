from __future__ import annotations

import copy
import hashlib
import json
import stat
from pathlib import Path

import pytest

from defense_arena.armor_d1_screening import (
    D1_V2_CATEGORY_LEAF_WHITELIST,
    D1ScreeningError,
    canonical_sha256,
    screen_d1_v2_candidates,
    write_d1_v2_screening,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _query(length: int, marker: str) -> str:
    prefix = f"Synthetic offline evaluation fixture {marker}. "
    return (prefix + ("x" * length))[:length]


def _row(
    row_id: str,
    *,
    category: str = "Cyber Harm",
    leaf: str = "O01: Malware Generation",
    query_chars: int = 100,
    safety_label: str = "harmful",
    track: str = "defender_train",
    modality: str = "text",
    normalized_hash: str | None = None,
) -> dict:
    query = _query(query_chars, row_id)
    normalized = normalized_hash or _sha(f"normalized:{row_id}")
    return {
        "schema_version": 1,
        "id": row_id,
        "behavior": query,
        "query": query,
        "context": "",
        "safety_label": safety_label,
        "canonical_category": category,
        "risk_category": category,
        "track": track,
        "modality": modality,
        "source_category_path": ["Synthetic taxonomy", leaf],
        "hashes": {
            "query_sha256": _sha(f"query:{row_id}"),
            "normalized_query_sha256": normalized,
            "decontamination_sha256": _sha(f"decontamination:{row_id}"),
            "content_sha256": _sha(f"content:{row_id}"),
        },
    }


def _write_jsonl(path: Path, rows: list[dict]) -> Path:
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows
        ),
        encoding="utf-8",
    )
    return path


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_default_d1_v2_whitelist_is_exact() -> None:
    assert D1_V2_CATEGORY_LEAF_WHITELIST == {
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
        "Violence": (
            "Weapon Generation and Transportation",
            "Terrorism",
        ),
    }


def test_screening_is_exact_outcome_blind_and_excludes_prior_id_or_hash(
    tmp_path: Path,
) -> None:
    shared_prior_hash = _sha("shared-prior-normalized")
    rows = [
        _row("selected-min", query_chars=80),
        _row("selected-max", leaf="Cyber Attack", query_chars=800),
        _row(
            "selected-fraud",
            category="Fraud/Deception",
            leaf="O22: Financial Fraud",
        ),
        _row("short", query_chars=79),
        _row("long", query_chars=801),
        _row("wrong-leaf", leaf="O01: malware generation"),
        _row("benign", safety_label="benign"),
        _row("wrong-track", track="sealed_eval_text"),
        _row("wrong-modality", modality="vlm"),
        _row("wrong-category", category="Other", leaf="O01: Malware Generation"),
        _row("prior-id"),
        _row("prior-hash", normalized_hash=shared_prior_hash),
    ]
    dataset = _write_jsonl(tmp_path / "defender_train.jsonl", rows)
    exclusion = _write_jsonl(
        tmp_path / "v1.private.jsonl",
        [
            _row("prior-id"),
            _row("different-id", normalized_hash=shared_prior_hash),
        ],
    )
    whitelist = {
        "Cyber Harm": ("Malware Generation", "Cyber Attack"),
        "Fraud/Deception": ("Financial Fraud",),
    }

    selected, manifest = screen_d1_v2_candidates(
        dataset,
        category_leaf_whitelist=whitelist,
        min_query_chars=80,
        max_query_chars=800,
        exclusion_jsonl_paths=[exclusion],
        reviewer_reason_counts={
            "ambiguous_or_fragmentary": 4,
            "not_clearly_harmful": 3,
        },
    )

    assert [row["id"] for row in selected] == [
        "selected-min",
        "selected-max",
        "selected-fraud",
    ]
    assert manifest["input"] == {
        "file_sha256": _file_sha(dataset),
        "row_count": len(rows),
    }
    assert manifest["exclusion_files"] == [
        {"file_sha256": _file_sha(exclusion), "row_count": 2}
    ]
    assert manifest["criteria"]["query_bounds_inclusive"] is True
    assert manifest["criteria"]["category_leaf_match"] == (
        "exact_after_Oxx_prefix_removal"
    )
    assert manifest["counts"]["by_category"] == {
        "Cyber Harm": {"before": 10, "after": 2},
        "Fraud/Deception": {"before": 1, "after": 1},
    }
    assert manifest["counts"]["filter_exclusion_counts"] == {
        "category_not_allowed": 1,
        "not_harmful": 1,
        "not_defender_train": 1,
        "not_text_modality": 1,
        "query_not_text": 0,
        "query_too_short": 1,
        "query_too_long": 1,
        "leaf_not_allowed": 1,
        "excluded_prior_id_or_hash": 2,
        "duplicate_candidate_identity": 0,
    }
    assert manifest["outcome_blindness"] == {
        "target_outcomes_used": False,
        "reviewer_feedback_usage": "aggregate_reason_codes_only",
        "reviewer_reason_code_counts": {
            "ambiguous_or_fragmentary": 4,
            "not_clearly_harmful": 3,
        },
        "raw_reviewer_items_used": False,
        "individual_reviewer_decisions_used": False,
    }
    unhashed = dict(manifest)
    manifest_sha = unhashed.pop("manifest_sha256")
    assert manifest_sha == canonical_sha256(unhashed)
    serialized = json.dumps(manifest, ensure_ascii=False)
    assert all(row["query"] not in serialized for row in rows)


@pytest.mark.parametrize(
    "identity_field",
    [
        "id",
        "query_sha256",
        "normalized_query_sha256",
        "decontamination_sha256",
        "content_sha256",
    ],
)
def test_screening_deterministically_excludes_duplicate_candidate_identity(
    tmp_path: Path,
    identity_field: str,
) -> None:
    first = _row("first")
    duplicate = _row("duplicate")
    distinct = _row("distinct")
    if identity_field == "id":
        duplicate["id"] = first["id"]
    else:
        duplicate["hashes"][identity_field] = first["hashes"][identity_field]
    dataset = _write_jsonl(tmp_path / "rows.jsonl", [first, duplicate, distinct])

    selected, manifest = screen_d1_v2_candidates(
        dataset,
        category_leaf_whitelist={"Cyber Harm": ("Malware Generation",)},
    )
    repeated, repeated_manifest = screen_d1_v2_candidates(
        dataset,
        category_leaf_whitelist={"Cyber Harm": ("Malware Generation",)},
    )

    assert [row["id"] for row in selected] == ["first", "distinct"]
    assert repeated == selected
    assert repeated_manifest == manifest
    filter_counts = manifest["counts"]["filter_exclusion_counts"]
    assert filter_counts["duplicate_candidate_identity"] == 1
    assert list(filter_counts)[-1] == "duplicate_candidate_identity"


def test_source_leaf_uses_only_last_label_and_removes_exact_Oxx_prefix(
    tmp_path: Path,
) -> None:
    allowed = _row("allowed", leaf="O17: Self-Harm", category="Self-Harm")
    allowed_single_digit = _row(
        "allowed-single-digit", leaf="O7: Self-Harm", category="Self-Harm"
    )
    allowed["source_category_path"] = [
        "O01: Wrong intermediate leaf",
        "O17: Self-Harm",
    ]
    wrong_prefix = _row("wrong-prefix", leaf="X17: Self-Harm", category="Self-Harm")
    wrong_case = _row("wrong-case", leaf="O17: self-harm", category="Self-Harm")
    dataset = _write_jsonl(
        tmp_path / "rows.jsonl",
        [allowed, allowed_single_digit, wrong_prefix, wrong_case],
    )

    selected, manifest = screen_d1_v2_candidates(
        dataset,
        category_leaf_whitelist={"Self-Harm": ("Self-Harm",)},
    )

    assert [row["id"] for row in selected] == ["allowed", "allowed-single-digit"]
    assert manifest["counts"]["filter_exclusion_counts"]["leaf_not_allowed"] == 2


def test_private_jsonl_and_raw_free_manifest_are_atomic_exclusive_artifacts(
    tmp_path: Path,
) -> None:
    row = _row("selected")
    dataset = _write_jsonl(tmp_path / "rows.jsonl", [row])
    selected, manifest = screen_d1_v2_candidates(
        dataset,
        category_leaf_whitelist={"Cyber Harm": ("Malware Generation",)},
    )
    private_path = tmp_path / "out" / "screened.private.jsonl"
    manifest_path = tmp_path / "out" / "screening_manifest.json"

    written_private, written_manifest = write_d1_v2_screening(
        private_path,
        manifest_path,
        selected,
        manifest,
    )

    assert stat.S_IMODE(written_private.stat().st_mode) == 0o600
    assert stat.S_IMODE(written_manifest.stat().st_mode) == 0o644
    assert (
        _file_sha(written_private) == manifest["screened_private_file"]["file_sha256"]
    )
    loaded_manifest = json.loads(written_manifest.read_text(encoding="utf-8"))
    assert loaded_manifest == manifest
    assert row["query"] in written_private.read_text(encoding="utf-8")
    assert row["query"] not in written_manifest.read_text(encoding="utf-8")
    assert not list(written_private.parent.glob(".*.tmp"))

    with pytest.raises(D1ScreeningError, match="overwrite"):
        write_d1_v2_screening(private_path, manifest_path, selected, manifest)


def test_preexisting_one_destination_prevents_any_publication(tmp_path: Path) -> None:
    dataset = _write_jsonl(tmp_path / "rows.jsonl", [_row("selected")])
    selected, manifest = screen_d1_v2_candidates(
        dataset,
        category_leaf_whitelist={"Cyber Harm": ("Malware Generation",)},
    )
    private_path = tmp_path / "screened.private.jsonl"
    manifest_path = tmp_path / "screening_manifest.json"
    manifest_path.write_text("existing\n", encoding="utf-8")

    with pytest.raises(D1ScreeningError, match="overwrite"):
        write_d1_v2_screening(private_path, manifest_path, selected, manifest)

    assert not private_path.exists()
    assert manifest_path.read_text(encoding="utf-8") == "existing\n"


def test_writer_rejects_row_or_manifest_drift_before_publication(
    tmp_path: Path,
) -> None:
    dataset = _write_jsonl(tmp_path / "rows.jsonl", [_row("selected")])
    selected, manifest = screen_d1_v2_candidates(
        dataset,
        category_leaf_whitelist={"Cyber Harm": ("Malware Generation",)},
    )

    with pytest.raises(D1ScreeningError, match="rows do not match"):
        write_d1_v2_screening(
            tmp_path / "rows-a.jsonl",
            tmp_path / "manifest-a.json",
            [],
            manifest,
        )
    assert not (tmp_path / "rows-a.jsonl").exists()

    tampered = copy.deepcopy(manifest)
    tampered["counts"]["selected_rows"] += 1
    with pytest.raises(D1ScreeningError, match="self-hash"):
        write_d1_v2_screening(
            tmp_path / "rows-b.jsonl",
            tmp_path / "manifest-b.json",
            selected,
            tampered,
        )
    assert not (tmp_path / "rows-b.jsonl").exists()

    non_blind = copy.deepcopy(manifest)
    non_blind["outcome_blindness"]["target_outcomes_used"] = True
    non_blind.pop("manifest_sha256")
    non_blind["manifest_sha256"] = canonical_sha256(non_blind)
    with pytest.raises(D1ScreeningError, match="not outcome-blind"):
        write_d1_v2_screening(
            tmp_path / "rows-c.jsonl",
            tmp_path / "manifest-c.json",
            selected,
            non_blind,
        )
    assert not (tmp_path / "rows-c.jsonl").exists()


@pytest.mark.parametrize(
    ("minimum", "maximum"),
    [(-1, 800), (80, 79), (True, 800), (80, False)],
)
def test_invalid_character_bounds_fail_closed(
    tmp_path: Path,
    minimum: int,
    maximum: int,
) -> None:
    dataset = _write_jsonl(tmp_path / "rows.jsonl", [_row("selected")])
    with pytest.raises(D1ScreeningError, match="character bounds"):
        screen_d1_v2_candidates(
            dataset,
            min_query_chars=minimum,
            max_query_chars=maximum,
        )


def test_unknown_reviewer_reason_code_is_rejected(tmp_path: Path) -> None:
    dataset = _write_jsonl(tmp_path / "rows.jsonl", [_row("selected")])
    with pytest.raises(D1ScreeningError, match="unknown reviewer reason code"):
        screen_d1_v2_candidates(
            dataset,
            reviewer_reason_counts={"free_form_comment": 1},
        )
