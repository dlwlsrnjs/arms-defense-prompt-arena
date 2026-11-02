from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from PIL import Image

from defense_arena.armor_challenge_preflight import (
    build_d1_challenge_cohort,
    write_d1_challenge_cohort,
)
from defense_arena.armor_challenge_review import (
    APPROVED_REVIEW_STATUS,
    ATTESTED_CASSETTE_STATUS,
    READY_STATUS,
)
from defense_arena.armor_first_move_cassette import FrozenFirstMoveCassette
from defense_arena.armor_prefreeze_batch import (
    BATCH_FINAL_ARTIFACT,
    BATCH_PLAN_ARTIFACT,
    PrefreezeBatchError,
    consolidate_prefreeze_batches,
    finalize_prefreeze_batch,
    prepare_prefreeze_batch,
)
from defense_arena.armor_stage0 import canonical_sha256
from defense_arena.asset_hashing import asset_file_sha256
from defense_arena.instrumentation import FALLBACK_POLICY_SHA256
from defense_arena.memory_compiler import normalized_behavior_sha256, sha256_file


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _write_json(path: Path, value: object, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(mode)


def _row(index: int) -> dict:
    category = "A" if index < 8 else "B"
    behavior_id = f"batch-behavior-{index:02d}"
    text = f"Private batch behavior sentinel {index:02d}"
    normalized = normalized_behavior_sha256(text)
    return {
        "schema_version": 1,
        "id": behavior_id,
        "behavior": text,
        "query": text,
        "safety_label": "harmful",
        "canonical_category": category,
        "risk_category": category,
        "source": "batch-fixture",
        "source_split": "train",
        "track": "defender_train",
        "modality": "text",
        "hashes": {
            "content_sha256": _sha(f"content:{behavior_id}"),
            "normalized_query_sha256": normalized,
            "decontamination_sha256": normalized,
        },
    }


def _fixture(tmp_path: Path) -> dict:
    rows = [_row(index) for index in range(16)]
    dataset = tmp_path / "defender-train.jsonl"
    dataset.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )
    memory = tmp_path / "warm-memory.json"
    memory.write_text("[]\n", encoding="utf-8")
    benchmark = tmp_path / "benchmark-manifest.json"
    benchmark.write_text('{"schema_version":1}\n', encoding="utf-8")
    selected, pending = build_d1_challenge_cohort(
        dataset,
        benchmark_manifest_path=benchmark,
        memory_path=memory,
        category_allowlist=["A", "B"],
        per_category=8,
        seed=177,
        target_call_budget=4,
    )
    cohort = tmp_path / "cohort"
    manifest = write_d1_challenge_cohort(cohort, selected, pending)
    behaviors = Path(manifest["private_behavior_file"]["path"])
    behaviors.chmod(0o600)
    arena = tmp_path / "arena.yaml"
    arena.write_text("targets: {}\n", encoding="utf-8")
    base = tmp_path / "base.yaml"
    base.write_text("base: fixture\n", encoding="utf-8")
    return {
        "rows": rows,
        "manifest": manifest,
        "manifest_path": cohort / "challenge_manifest.json",
        "behaviors": behaviors,
        "arena": arena,
        "base": base,
        "memory": memory,
    }


def _prepare(
    tmp_path: Path,
    fixture: dict,
    *,
    name: str = "prefreeze-batch",
    decoding_config: dict | None = None,
) -> tuple[dict, Path]:
    root = tmp_path / name
    kwargs = {}
    if decoding_config is not None:
        kwargs["decoding_config"] = decoding_config
    plan = prepare_prefreeze_batch(
        challenge_manifest_path=fixture["manifest_path"],
        selected_behaviors_path=fixture["behaviors"],
        arena_config_path=fixture["arena"],
        base_config_path=fixture["base"],
        target_id="qwen2.5-vl-3b",
        memory_path=fixture["memory"],
        output_dir=root,
        **kwargs,
    )
    return plan, root


def _populate_completed_pair_outputs(
    plan: dict,
    *,
    pair_indices: set[int] | None = None,
    attempt_label: str = "",
) -> None:
    memory_hash = plan["inputs"]["memory_sha256"]
    decoding = plan["decoding_config"]
    for index, pair_plan in enumerate(plan["pairs"], start=1):
        if pair_indices is not None and index not in pair_indices:
            continue
        behavior_id = pair_plan["behavior_id"]
        request = f"Captured private first move {attempt_label}{behavior_id}"
        request_hash = _sha(request)
        action_hash = _sha(f"action:{behavior_id}")
        work_dir = Path(pair_plan["work_dir"])
        image_path = work_dir / "runtime" / "artifacts" / "00001" / "img_1.bmp"
        image_path.parent.mkdir(parents=True, exist_ok=True)
        with Image.new("RGB", (2, 2), (index, 20, 30)) as image:
            image.save(image_path)
        image_hash = asset_file_sha256(image_path)
        assets = {"first-action-image-001": image_hash}
        pair = {
            "pair_id": pair_plan["pair_id"],
            "behavior_id": behavior_id,
            "attacker_seed": pair_plan["attacker_seed"],
            "initial_memory_sha256": memory_hash,
            "initial_retrieval_sha256": _sha(f"retrieval:{behavior_id}"),
            "first_action_sha256": request_hash,
            "fallback_policy_sha256": FALLBACK_POLICY_SHA256,
            "fallback_action_sha256": action_hash,
            "fallback_request_sha256": request_hash,
            "asset_hashes": assets,
            "decoding_config": decoding,
        }
        wrapper = {
            "schema_version": 1,
            "artifact_type": "armor-stage0-prefreeze-pair-v1",
            "target_call_budget": 4,
            "pair": pair,
            "pair_sha256": canonical_sha256(pair),
            "prefreeze_spec_sha256": pair_plan["prefreeze_spec_sha256"],
            "decoding_config_sha256": canonical_sha256(decoding),
            "raw_attack_or_response_text_included": False,
        }
        _write_json(Path(pair_plan["wrapper_result_path"]), wrapper)
        _write_json(
            Path(pair_plan["asset_result_path"]),
            {
                "behaviors": {
                    behavior_id: {
                        "first-action-image-001": {
                            "path": str(image_path),
                            "sha256": image_hash,
                        }
                    }
                }
            },
        )
        cassette = FrozenFirstMoveCassette(
            behavior_id=behavior_id,
            request_text=request,
            request_sha256=request_hash,
            action_sha256=action_hash,
            image_assets=tuple(assets.items()),
        )
        _write_json(
            Path(pair_plan["cassette_result_path"]),
            cassette.to_dict(),
            mode=0o600,
        )


def test_prepare_is_offline_argv_only_private_and_no_overwrite(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    plan, root = _prepare(tmp_path, fixture)

    assert plan["artifact_type"] == BATCH_PLAN_ARTIFACT
    assert plan["pair_count"] == 16
    assert len(plan["pairs"]) == 16
    assert plan["execution_policy"] == {
        "preparation_invokes_endpoints": False,
        "prefreeze_requires_existing_endpoints": True,
        "prefreeze_target_is_capture_stub": True,
        "model_servers_started": False,
        "model_servers_stopped": False,
        "accelerator_allocation_performed": False,
    }
    serialized = json.dumps(plan, ensure_ascii=False)
    assert "Private batch behavior sentinel" not in serialized
    plan_path = root / "prefreeze_batch_plan.private.json"
    assert plan_path.stat().st_mode & 0o777 == 0o600
    for row in plan["pairs"]:
        assert Path(row["prefreeze_spec_path"]).stat().st_mode & 0o777 == 0o600
        argv = row["invocation_argv"]
        assert argv[2] == "prefreeze"
        assert "--behavior-id" in argv
        assert row["behavior_id"] in argv

    with pytest.raises(PrefreezeBatchError, match="refusing to overwrite"):
        _prepare(tmp_path, fixture)


def test_prepare_accepts_an_execution_ready_manifest(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    ready = dict(fixture["manifest"])
    ready_pairs = []
    for entry in ready["pairs"]:
        finalized = dict(entry)
        finalized.pop("challenge_entry_sha256")
        finalized["compatibility_review"] = {
            "status": APPROVED_REVIEW_STATUS,
            "decision": "approve",
            "reviewer_kinds": ["model", "human"],
            "result_sha256": _sha(f"review:{entry['pair_id']}"),
        }
        finalized["first_move_cassette"] = {
            "status": ATTESTED_CASSETTE_STATUS,
            "cassette_sha256": _sha(f"cassette:{entry['pair_id']}"),
        }
        finalized["challenge_entry_sha256"] = canonical_sha256(finalized)
        ready_pairs.append(finalized)
    ready.pop("manifest_sha256")
    ready["status"] = READY_STATUS
    ready["execution_eligible"] = True
    ready["blocking_gates"] = []
    ready["pairs"] = ready_pairs
    ready["manifest_sha256"] = canonical_sha256(ready)
    ready_path = tmp_path / "ready-challenge.json"
    _write_json(ready_path, ready)

    plan = prepare_prefreeze_batch(
        challenge_manifest_path=ready_path,
        selected_behaviors_path=fixture["behaviors"],
        arena_config_path=fixture["arena"],
        base_config_path=fixture["base"],
        target_id="qwen2.5-vl-3b",
        memory_path=fixture["memory"],
        output_dir=tmp_path / "ready-prefreeze-batch",
    )
    assert plan["challenge_manifest"]["status"] == READY_STATUS
    assert len(plan["pairs"]) == 16


def test_prepare_preserves_symlinked_virtualenv_interpreter_path(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    interpreter_target = tmp_path / "system-python-fixture"
    interpreter_target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    interpreter_target.chmod(0o755)
    virtualenv_bin = tmp_path / "fake-venv" / "bin"
    virtualenv_bin.mkdir(parents=True)
    virtualenv_python = virtualenv_bin / "python"
    virtualenv_python.symlink_to(interpreter_target)

    plan = prepare_prefreeze_batch(
        challenge_manifest_path=fixture["manifest_path"],
        selected_behaviors_path=fixture["behaviors"],
        arena_config_path=fixture["arena"],
        base_config_path=fixture["base"],
        target_id="qwen2.5-vl-3b",
        memory_path=fixture["memory"],
        output_dir=tmp_path / "symlink-interpreter-batch",
        python_executable=virtualenv_python,
    )

    assert plan["inputs"]["python_executable"] == str(virtualenv_python)
    assert plan["pairs"][0]["invocation_argv"][0] == str(virtualenv_python)
    assert virtualenv_python.resolve() == interpreter_target


def test_finalize_attests_16_and_copies_private_assets(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    plan, root = _prepare(tmp_path, fixture)
    _populate_completed_pair_outputs(plan)

    output = tmp_path / "combined"
    attestation = finalize_prefreeze_batch(
        plan_path=root / "prefreeze_batch_plan.private.json",
        output_dir=output,
    )

    assert attestation["artifact_type"] == BATCH_FINAL_ARTIFACT
    assert attestation["pair_count"] == 16
    bundle_path = Path(attestation["cassette_bundle"]["path"])
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    assert bundle["schema_version"] == 2
    assert len(bundle["cassettes"]) == 16
    assert bundle["target_response_included"] is False
    assert bundle_path.stat().st_mode & 0o777 == 0o600

    assets_path = Path(attestation["asset_manifest"]["path"])
    assets = json.loads(assets_path.read_text(encoding="utf-8"))["behaviors"]
    assert len(assets) == 16
    assert assets_path.stat().st_mode & 0o777 == 0o600
    for behavior_assets in assets.values():
        for row in behavior_assets.values():
            copied = Path(row["path"])
            assert copied.is_relative_to(output / "assets")
            assert copied.stat().st_mode & 0o777 == 0o600
            assert asset_file_sha256(copied) == row["sha256"]
    assert sha256_file(bundle_path) == attestation["cassette_bundle"]["file_sha256"]

    with pytest.raises(PrefreezeBatchError, match="refusing to overwrite"):
        finalize_prefreeze_batch(
            plan_path=root / "prefreeze_batch_plan.private.json",
            output_dir=output,
        )


def test_finalize_rejects_tamper_before_creating_destination(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    plan, root = _prepare(tmp_path, fixture)
    _populate_completed_pair_outputs(plan)
    first = plan["pairs"][0]
    cassette_path = Path(first["cassette_result_path"])
    cassette = json.loads(cassette_path.read_text(encoding="utf-8"))
    cassette["request_text"] += " tampered"
    _write_json(cassette_path, cassette, mode=0o600)

    output = tmp_path / "must-not-exist"
    with pytest.raises(PrefreezeBatchError, match="request text hash mismatch"):
        finalize_prefreeze_batch(
            plan_path=root / "prefreeze_batch_plan.private.json",
            output_dir=output,
        )
    assert not output.exists()


def test_consolidate_uses_complementary_valid_captures(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    first, first_root = _prepare(tmp_path, fixture, name="attempt-one")
    second, second_root = _prepare(tmp_path, fixture, name="attempt-two")
    _populate_completed_pair_outputs(
        first,
        pair_indices=set(range(1, 9)),
        attempt_label="attempt-one:",
    )
    _populate_completed_pair_outputs(
        second,
        pair_indices=set(range(9, 17)),
        attempt_label="attempt-two:",
    )

    attestation = consolidate_prefreeze_batches(
        plan_paths=[
            first_root / "prefreeze_batch_plan.private.json",
            second_root / "prefreeze_batch_plan.private.json",
        ],
        output_dir=tmp_path / "consolidated",
    )

    assert [row["source_attempt_ordinal"] for row in attestation["pairs"]] == [
        *([1] * 8),
        *([2] * 8),
    ]
    attempts = attestation["consolidation"]["attempts"]
    assert attempts[0]["pair_outcome_counts"] == {
        "selected_valid": 8,
        "valid_not_selected": 0,
        "partial": 8,
        "invalid_completed": 0,
    }
    assert attempts[1]["pair_outcome_counts"] == {
        "selected_valid": 8,
        "valid_not_selected": 0,
        "partial": 8,
        "invalid_completed": 0,
    }
    serialized = json.dumps(attestation, ensure_ascii=False)
    assert "Captured private first move" not in serialized
    bundle = json.loads(
        Path(attestation["cassette_bundle"]["path"]).read_text(encoding="utf-8")
    )
    assert len(bundle["cassettes"]) == 16


def test_consolidate_skips_tampered_earlier_capture_and_is_caller_ordered(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    first, first_root = _prepare(tmp_path, fixture, name="attempt-one")
    second, second_root = _prepare(tmp_path, fixture, name="attempt-two")
    _populate_completed_pair_outputs(first, attempt_label="attempt-one:")
    _populate_completed_pair_outputs(second, attempt_label="attempt-two:")
    first_cassette_path = Path(first["pairs"][0]["cassette_result_path"])
    first_cassette = json.loads(first_cassette_path.read_text(encoding="utf-8"))
    first_cassette["request_text"] += " tampered"
    _write_json(first_cassette_path, first_cassette, mode=0o600)

    forward = consolidate_prefreeze_batches(
        plan_paths=[
            first_root / "prefreeze_batch_plan.private.json",
            second_root / "prefreeze_batch_plan.private.json",
        ],
        output_dir=tmp_path / "forward-consolidated",
    )
    assert forward["pairs"][0]["source_attempt_ordinal"] == 2
    assert all(row["source_attempt_ordinal"] == 1 for row in forward["pairs"][1:])
    assert forward["consolidation"]["attempts"][0]["pair_outcome_counts"] == {
        "selected_valid": 15,
        "valid_not_selected": 0,
        "partial": 0,
        "invalid_completed": 1,
    }
    assert forward["consolidation"]["attempts"][1]["pair_outcome_counts"] == {
        "selected_valid": 1,
        "valid_not_selected": 15,
        "partial": 0,
        "invalid_completed": 0,
    }

    reverse = consolidate_prefreeze_batches(
        plan_paths=[
            second_root / "prefreeze_batch_plan.private.json",
            first_root / "prefreeze_batch_plan.private.json",
        ],
        output_dir=tmp_path / "reverse-consolidated",
    )
    assert all(row["source_attempt_ordinal"] == 1 for row in reverse["pairs"])
    assert all(
        row["source_plan_sha256"] == second["plan_sha256"] for row in reverse["pairs"]
    )


def test_consolidate_rejects_incompatible_plan_semantics(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _first, first_root = _prepare(tmp_path, fixture, name="attempt-one")
    _second, second_root = _prepare(
        tmp_path,
        fixture,
        name="attempt-two",
        decoding_config={"temperature": 0.0, "top_p": 1.0, "max_tokens": 2048},
    )

    output = tmp_path / "must-not-exist-consolidated"
    with pytest.raises(PrefreezeBatchError, match="incompatible.*ordinal 2"):
        consolidate_prefreeze_batches(
            plan_paths=[
                first_root / "prefreeze_batch_plan.private.json",
                second_root / "prefreeze_batch_plan.private.json",
            ],
            output_dir=output,
        )
    assert not output.exists()


def test_batch_source_has_no_execution_or_resource_lifecycle_calls() -> None:
    from defense_arena import armor_prefreeze_batch

    source = Path(armor_prefreeze_batch.__file__).read_text(encoding="utf-8")
    assert "import subprocess" not in source
    assert "os.kill" not in source
    assert "nvidia-smi" not in source
    assert "CUDA_VISIBLE_DEVICES" not in source
