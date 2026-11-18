from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts import build_aamd_rcat7_pilot_source as builder
from scripts.generate_aamd_taxonomy_proposals import (
    build_taxonomy_contract,
    validate_source_bundle,
)


RESEARCH_ROOT = Path(__file__).resolve().parents[1]
TAXONOMY_PATH = RESEARCH_ROOT / "configs/aamd_rcat7_taxonomy_v1_1.json"
PROMPT_PATH = RESEARCH_ROOT / "prompts/aamd_llm_first_labeler_32b_v3.txt"
CONFIG_PATH = RESEARCH_ROOT / "configs/aamd_llm_first_labeler_32b_v3.json"


def _generator_contract() -> Any:
    taxonomy = json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    prompt = PROMPT_PATH.read_bytes()
    return build_taxonomy_contract(taxonomy, config, prompt)


def _build(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Any]:
    monkeypatch.setattr(builder, "RUNTIME_ROOT", tmp_path)
    output_dir = tmp_path / "source-v2"
    manifest = builder.build_bundles(
        memory_flow_path=builder.DEFAULT_INPUT,
        artifact_manifest_path=builder.DEFAULT_ARTIFACT_MANIFEST,
        output_dir=output_dir,
        bundle_prefix="attack-memory-v1-rcat7-pilot-source",
        chunk_size=24,
    )
    return output_dir, manifest


def test_frozen_source_builds_exact_v3_commitments_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_dir, manifest = _build(tmp_path, monkeypatch)

    assert manifest["builder_version"] == builder.BUILDER_VERSION
    assert manifest["claim_bearing"] is False
    assert manifest["source"]["artifact_manifest_sha256"] == (
        builder.PINNED_ARTIFACT_MANIFEST_SHA256
    )
    assert manifest["source"]["memory_flow_sha256"] == (
        builder.PINNED_MEMORY_FLOW_SHA256
    )
    assert manifest["source"]["pack_id"] == builder.PINNED_SOURCE_PACK_ID
    assert manifest["projection"]["task_count"] == 307
    assert manifest["projection"]["bundle_count"] == 13
    assert manifest["projection"]["visibility_mask_hash"] == (
        "dbc3df1c573217c17873853aa8d4df45e6e63d1c5cd8c777272cbadf738c5892"
    )

    paths = sorted(output_dir.glob("source-bundle-*.json"))
    assert len(paths) == 13
    assert json.loads(paths[-1].read_text(encoding="utf-8"))["tasks"]
    assert len(json.loads(paths[-1].read_text(encoding="utf-8"))["tasks"]) == 19
    assert not list(tmp_path.glob(".source-v2.staging-*"))

    contract = _generator_contract()
    all_tasks: list[dict[str, Any]] = []
    for index, path in enumerate(paths):
        bundle = json.loads(path.read_text(encoding="utf-8"))
        assert path.stat().st_size < 1024 * 1024
        assert bundle["claim_bearing"] is False
        assert bundle["visibility_mask_hash"] == builder.canonical_hash(
            builder.V3_VISIBILITY_MASK
        )
        assert bundle["queue_hash"] == builder.canonical_hash(
            builder.ordered_queue_projection(bundle["tasks"])
        )
        if len(bundle["tasks"]) > 1:
            assert bundle["queue_hash"] != builder.canonical_hash(
                builder.ordered_queue_projection(list(reversed(bundle["tasks"])))
            )
        for task in bundle["tasks"]:
            assert task["record_hash"] == builder.canonical_hash(
                builder.public_record_projection(task)
            )
        validate_source_bundle(
            bundle,
            contract,
            output_bundle_id=f"validated-review-bundle-{index:03d}",
        )
        all_tasks.extend(bundle["tasks"])

    assert all_tasks[0]["task_id"] == "task-e000002t01"
    assert all_tasks[0]["record_hash"] == (
        "cd6e4981b037417e448b4551c7147fdf52e935ffd77dbc2c771a97090d540406"
    )
    assert all_tasks[-1]["task_id"] == "task-e000220t02"
    assert all_tasks[-1]["record_hash"] == (
        "a3c27c0837916aedfa2182f0461cdff350a3e7badbc03f05ab4a445227816ef1"
    )


def test_source_commitments_reject_forged_manifest_and_memory_flow(
    tmp_path: Path,
) -> None:
    forged_manifest = tmp_path / "manifest.json"
    manifest = json.loads(builder.DEFAULT_ARTIFACT_MANIFEST.read_text(encoding="utf-8"))
    manifest["verification"]["event_hash_chain_valid"] = False
    forged_manifest.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(builder.BuildError, match="pinned frozen source"):
        builder.verify_source(
            memory_flow_path=builder.DEFAULT_INPUT,
            artifact_manifest_path=forged_manifest,
        )

    forged_memory = tmp_path / "memory-flow.json"
    memory = json.loads(builder.DEFAULT_INPUT.read_text(encoding="utf-8"))
    memory["episodes"][0]["episode"]["best_score"] = -1
    forged_memory.write_text(json.dumps(memory), encoding="utf-8")
    with pytest.raises(builder.BuildError, match="pinned frozen source"):
        builder.verify_source(
            memory_flow_path=forged_memory,
            artifact_manifest_path=builder.DEFAULT_ARTIFACT_MANIFEST,
        )


def test_strict_json_rejects_duplicate_keys_and_nonfinite_values(
    tmp_path: Path,
) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"pack_id":"first","pack_id":"second"}', encoding="utf-8")
    with pytest.raises(builder.BuildError, match="duplicate JSON key"):
        builder.load_json(duplicate, name="duplicate fixture")

    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text('{"epsilon":NaN}', encoding="utf-8")
    with pytest.raises(builder.BuildError, match="non-finite"):
        builder.load_json(nonfinite, name="nonfinite fixture")


def test_build_tasks_rejects_memory_receipt_mismatch() -> None:
    memory = builder.load_json(builder.DEFAULT_INPUT, name="memory flow")
    memory["episodes"][0]["episode"]["used_memory"] = True
    with pytest.raises(builder.BuildError, match="used_memory"):
        builder.build_tasks(memory, builder.PINNED_MEMORY_FLOW_SHA256)


def test_staged_publish_removes_partial_outputs_on_write_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(builder, "RUNTIME_ROOT", tmp_path)
    output_dir = tmp_path / "faulted-source"
    original = builder.atomic_write_new
    calls = 0

    def fail_second_write(path: Path, value: Any) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise builder.BuildError("injected write failure")
        original(path, value)

    monkeypatch.setattr(builder, "atomic_write_new", fail_second_write)
    with pytest.raises(builder.BuildError, match="injected write failure"):
        builder.build_bundles(
            memory_flow_path=builder.DEFAULT_INPUT,
            artifact_manifest_path=builder.DEFAULT_ARTIFACT_MANIFEST,
            output_dir=output_dir,
            bundle_prefix="attack-memory-v1-rcat7-pilot-source",
            chunk_size=24,
        )
    assert not output_dir.exists()
    assert not list(tmp_path.glob(".faulted-source.staging-*"))


def test_output_and_bundle_prefix_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(builder, "RUNTIME_ROOT", tmp_path)
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    with pytest.raises(builder.BuildError, match="unused"):
        builder.build_bundles(
            memory_flow_path=builder.DEFAULT_INPUT,
            artifact_manifest_path=builder.DEFAULT_ARTIFACT_MANIFEST,
            output_dir=occupied,
            bundle_prefix="attack-memory-v1-rcat7-pilot-source",
            chunk_size=24,
        )

    with pytest.raises(builder.BuildError, match="bundle_prefix"):
        builder.build_bundles(
            memory_flow_path=builder.DEFAULT_INPUT,
            artifact_manifest_path=builder.DEFAULT_ARTIFACT_MANIFEST,
            output_dir=tmp_path / "invalid-prefix",
            bundle_prefix="invalid prefix",
            chunk_size=24,
        )
