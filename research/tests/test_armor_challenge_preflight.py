from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from defense_arena import armor_challenge_preflight
from defense_arena.armor_challenge_preflight import (
    PROTOCOL,
    build_d1_challenge_cohort,
    write_d1_challenge_cohort,
)
from defense_arena.memory_compiler import normalized_behavior_sha256, sha256_file


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _row(row_id: str, text: str, category: str) -> dict:
    normalized = normalized_behavior_sha256(text)
    return {
        "schema_version": 1,
        "id": row_id,
        "behavior": text,
        "query": text,
        "safety_label": "harmful",
        "canonical_category": category,
        "risk_category": category,
        "source": "public-fixture",
        "source_split": "train",
        "track": "defender_train",
        "modality": "text",
        "hashes": {
            "content_sha256": _sha(f"content:{row_id}"),
            "normalized_query_sha256": normalized,
            "decontamination_sha256": normalized,
        },
    }


def _write_jsonl(path: Path, rows: list[dict]) -> Path:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    return path


def test_d1_cohort_is_outcome_blind_hash_only_and_not_execution_eligible(
    tmp_path: Path,
):
    rows = [
        _row("a-1", "Harmless synthetic fixture A1", "A"),
        _row("a-2", "Harmless synthetic fixture A2", "A"),
        _row("b-1", "Harmless synthetic fixture B1", "B"),
        _row("b-2", "Harmless synthetic fixture B2", "B"),
        _row("c-1", "Excluded synthetic fixture C1", "C"),
    ]
    dataset = _write_jsonl(tmp_path / "defender_train.jsonl", rows)
    memory = tmp_path / "memory.json"
    memory.write_text("[]", encoding="utf-8")
    benchmark_manifest = tmp_path / "manifest.json"
    benchmark_manifest.write_text('{"schema_version":1}\n', encoding="utf-8")

    selected, manifest = build_d1_challenge_cohort(
        dataset,
        benchmark_manifest_path=benchmark_manifest,
        memory_path=memory,
        category_allowlist=["B", "A"],
        per_category=2,
        seed=31,
        target_call_budget=4,
    )

    assert len(selected) == 4
    assert manifest["protocol"] == PROTOCOL
    assert manifest["execution_eligible"] is False
    assert manifest["selection_policy"]["category_allowlist"] == ["A", "B"]
    assert manifest["metric_contract"]["strict_success_count_min"] == 4
    assert manifest["metric_contract"]["strict_success_count_max"] == 9
    serialized = json.dumps(manifest, ensure_ascii=False)
    assert "Harmless synthetic fixture" not in serialized
    assert all(len(pair["challenge_entry_sha256"]) == 64 for pair in manifest["pairs"])
    assert all(pair["compatibility_review"]["status"].startswith("pending") for pair in manifest["pairs"])

    finalized = write_d1_challenge_cohort(tmp_path / "cohort", selected, manifest)
    behavior_file = Path(finalized["private_behavior_file"]["path"])
    assert behavior_file.stat().st_mode & 0o777 == 0o600
    assert finalized["private_behavior_file"]["publish"] is False
    assert finalized["private_behavior_file"]["sha256"] == sha256_file(behavior_file)
    assert json.loads((tmp_path / "cohort" / "challenge_manifest.json").read_text()) == finalized

    repeated = write_d1_challenge_cohort(tmp_path / "cohort", selected, manifest)
    assert repeated == finalized


def test_builder_rechecks_unique_identity_at_challenge_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _row("a-1", "Harmless synthetic fixture A1", "A")
    second = _row("a-2", "Harmless synthetic fixture A2", "A")
    second["hashes"]["content_sha256"] = first["hashes"]["content_sha256"]

    def duplicate_selector(*args: object, **kwargs: object) -> tuple[list[dict], dict]:
        del args, kwargs
        return [first, second], {}

    monkeypatch.setattr(
        armor_challenge_preflight,
        "select_decontaminated_harmful_pilot",
        duplicate_selector,
    )

    with pytest.raises(ValueError, match="duplicate candidate identity"):
        build_d1_challenge_cohort(
            tmp_path / "unused.jsonl",
            benchmark_manifest_path=tmp_path / "unused-manifest.json",
            memory_path=tmp_path / "unused-memory.json",
            category_allowlist=["A"],
            per_category=2,
            seed=31,
        )
