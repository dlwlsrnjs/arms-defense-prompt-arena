from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from defense_arena.armor_challenge_review import READY_STATUS
from defense_arena.armor_d1_stage0_spec import (
    D1Stage0SpecBuildError,
    build_d1_stage0_spec,
    freeze_d1_prefreeze_binding,
    write_d1_stage0_spec,
)
from defense_arena.armor_first_move_cassette import FrozenFirstMoveCassette
from defense_arena.armor_judge import ARMOR_JUDGE_PROTOCOL
from defense_arena.armor_stage0 import (
    ARM_IDS,
    CHALLENGE_PROTOCOL,
    CONTROL_SUBTYPES,
    RAW_TEXT_KEYS,
    SHA256_EMPTY,
    build_plan,
    canonical_sha256,
    freeze_evaluator_provenance,
)
from defense_arena.instrumentation import FALLBACK_POLICY_SHA256
from scripts.build_armor_d1_stage0_spec import main as cli_main


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _evaluator() -> dict:
    return freeze_evaluator_provenance(
        attacker_base_url="http://127.0.0.1:18101/v1",
        attacker_served_model_name="fixture-attacker",
        evaluated_target_base_url="http://127.0.0.1:18203/v1",
        evaluated_target_served_model_name="fixture-target",
        visual_evaluator={
            "protocol_version": ARMOR_JUDGE_PROTOCOL,
            "role": "independent_multimodal_attack_validity_judge",
            "model_id": "fixture/evaluator",
            "model_revision": "fixture-revision",
            "base_url": "http://127.0.0.1:18103/v1",
            "served_model_name": "fixture-evaluator",
            "max_side": 640,
        },
    )


def _template(evaluator: dict | None = None) -> dict:
    matched_memory = _sha("matched-memory")
    arms = {
        ARM_IDS[0]: {
            "prompt_sha256": SHA256_EMPTY,
            "prompt_token_count": 0,
            "memory_relation": "none",
            "compiler_memory_sha256": None,
            "control_subtype": CONTROL_SUBTYPES[ARM_IDS[0]],
        },
        ARM_IDS[1]: {
            "prompt_sha256": _sha("generic-prompt"),
            "prompt_token_count": 32,
            "memory_relation": "none",
            "compiler_memory_sha256": None,
            "control_subtype": CONTROL_SUBTYPES[ARM_IDS[1]],
        },
        ARM_IDS[2]: {
            "prompt_sha256": _sha("matched-prompt"),
            "prompt_token_count": 32,
            "memory_relation": "matched",
            "compiler_memory_sha256": matched_memory,
            "control_subtype": CONTROL_SUBTYPES[ARM_IDS[2]],
        },
        ARM_IDS[3]: {
            "prompt_sha256": _sha("shuffled-prompt"),
            "prompt_token_count": 32,
            "memory_relation": "mismatched",
            "compiler_memory_sha256": _sha("shuffled-memory"),
            "control_subtype": CONTROL_SUBTYPES[ARM_IDS[3]],
        },
    }
    request_sha256 = _sha("template request")
    pair = {
        "pair_id": "template-pair",
        "behavior_id": "template-behavior",
        "attacker_seed": 7,
        "initial_memory_sha256": matched_memory,
        "initial_retrieval_sha256": _sha("template retrieval"),
        "first_action_sha256": request_sha256,
        "fallback_policy_sha256": FALLBACK_POLICY_SHA256,
        "fallback_action_sha256": _sha("template action"),
        "fallback_request_sha256": request_sha256,
        "asset_hashes": {"first-action-image-001": _sha("template image")},
        "decoding_config": {"temperature": 0.0, "max_tokens": 32, "seed": 7},
    }
    value = {
        "schema_version": 1,
        "experiment_id": "four-arm-template",
        "target_call_budget": 2,
        "randomization_seed": 117,
        "prompt_token_budget": 64,
        "max_censoring_rate": 0.01,
        "evaluator_provenance": evaluator or _evaluator(),
        "arms": arms,
        "pairs": [pair],
    }
    if value["evaluator_provenance"]["protocol_version"] == ARMOR_JUDGE_PROTOCOL:
        build_plan(value)
    return value


def _wrapper(pair: dict) -> dict:
    return {
        "schema_version": 1,
        "artifact_type": "armor-stage0-prefreeze-pair-v1",
        "target_call_budget": 4,
        "pair": pair,
        "pair_sha256": canonical_sha256(pair),
        "prefreeze_spec_sha256": _sha(f"prefreeze-spec:{pair['pair_id']}"),
        "decoding_config_sha256": canonical_sha256(pair["decoding_config"]),
        "raw_attack_or_response_text_included": False,
    }


def _fixture() -> dict:
    template = _template()
    matched_memory = template["arms"][ARM_IDS[2]]["compiler_memory_sha256"]
    entries: list[dict] = []
    wrappers: list[dict] = []
    cassettes: list[dict] = []
    for index in range(16):
        pair_id = f"d1-pair-{index:02d}"
        behavior_id = f"public-behavior-{index:02d}"
        request_text = f"PRIVATE-REQUEST-SENTINEL-{index:02d}"
        request_sha256 = _sha(request_text)
        action_sha256 = _sha(f"action:{index}")
        asset_sha256 = _sha(f"image:{index}")
        cassette = FrozenFirstMoveCassette(
            behavior_id=behavior_id,
            request_text=request_text,
            request_sha256=request_sha256,
            action_sha256=action_sha256,
            image_assets=(("first-action-image-001", asset_sha256),),
        ).to_dict()
        cassette_sha256 = canonical_sha256(cassette)
        cassettes.append(cassette)
        pair = {
            "pair_id": pair_id,
            "behavior_id": behavior_id,
            "attacker_seed": 10_000 + index,
            "initial_memory_sha256": matched_memory,
            "initial_retrieval_sha256": _sha(f"retrieval:{index}"),
            "first_action_sha256": request_sha256,
            "fallback_policy_sha256": FALLBACK_POLICY_SHA256,
            "fallback_action_sha256": action_sha256,
            "fallback_request_sha256": request_sha256,
            "asset_hashes": {"first-action-image-001": asset_sha256},
            "decoding_config": {
                "temperature": 0.0,
                "max_tokens": 64,
                "seed": index,
            },
        }
        wrappers.append(_wrapper(pair))
        entry = {
            "pair_id": pair_id,
            "behavior_id": behavior_id,
            "category": f"category-{index // 2}",
            "source": "fixture-source",
            "source_split": "fixture-split",
            "track": "defender_train",
            "modality": "vision",
            "attacker_seed": 10_000 + index,
            "row_sha256": _sha(f"row:{index}"),
            "content_sha256": _sha(f"content:{index}"),
            "normalized_query_sha256": _sha(f"normalized:{index}"),
            "decontamination_sha256": _sha(f"decontamination:{index}"),
            "target_call_budget": 4,
            "compatibility_review": {
                "status": "approved_two_reviewer_blinded_review",
                "decision": "approve",
                "reviewer_kinds": ["human", "model"],
                "result_sha256": _sha(f"review:{index}"),
            },
            "first_move_cassette": {
                "status": "attested_prefrozen",
                "cassette_sha256": cassette_sha256,
            },
        }
        entry["challenge_entry_sha256"] = canonical_sha256(entry)
        entries.append(entry)

    manifest = {
        "schema_version": 1,
        "protocol": CHALLENGE_PROTOCOL,
        "stage": "D1",
        "status": READY_STATUS,
        "execution_eligible": True,
        "blocking_gates": [],
        "source": {
            "dataset_path": "/private/fixture.jsonl",
            "dataset_file_sha256": _sha("dataset"),
            "benchmark_manifest_path": "/public/manifest.json",
            "benchmark_manifest_sha256": _sha("benchmark manifest"),
            "memory_path": "/public/memory.json",
            "memory_file_sha256": matched_memory,
            "track": "defender_train",
        },
        "selection_policy": {
            "category_allowlist": [f"category-{index}" for index in range(8)],
            "per_category": 2,
            "seed": 20261101,
            "ranking": "fixture deterministic ranking",
            "no_target_outcome_used": True,
            "sealed_track_used": False,
            "decontamination_report_sha256": _sha("selection report"),
        },
        "source_counts": {"fixture-source": 16},
        "metric_contract": {
            "arm": ARM_IDS[0],
            "paired_units": 16,
            "target_call_budget": 4,
            "strict_success_count_min": 4,
            "strict_success_count_max": 9,
            "episode_valid_count_required": 16,
            "fallback_episode_count_max": 0,
            "judge_censored_call_count_max": 0,
            "validity_definition": (
                "all measured current-request individual validity scores equal 1"
            ),
            "population_inference_claimed": False,
        },
        "pairs": entries,
        "private_behavior_file": {
            "path": "/private/fixture.jsonl",
            "sha256": _sha("private behavior file"),
            "contains_raw_text": True,
            "publish": False,
        },
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    records = [
        freeze_d1_prefreeze_binding(
            prefreeze_wrapper=wrapper,
            challenge_manifest_sha256=manifest["manifest_sha256"],
            challenge_entry_sha256=entry["challenge_entry_sha256"],
            first_move_cassette_sha256=entry["first_move_cassette"]["cassette_sha256"],
        )
        for wrapper, entry in zip(wrappers, entries, strict=True)
    ]
    bundle = {
        "schema_version": 2,
        "artifact_type": "armor-stage0-frozen-first-move-bundle-v2",
        "cassettes": cassettes,
        "raw_attack_or_response_text_included": True,
        "target_response_included": False,
    }
    return {
        "manifest": manifest,
        "records": records,
        "bundle": bundle,
        "template": template,
        "evaluator": template["evaluator_provenance"],
    }


def _build(fixture: dict, **overrides: object) -> dict:
    arguments = {
        "challenge_manifest": fixture["manifest"],
        "prefreeze_records": fixture["records"],
        "cassette_bundle": fixture["bundle"],
        "template_spec": fixture["template"],
        "experiment_id": "d1-native-fixture",
    }
    arguments.update(overrides)
    return build_d1_stage0_spec(**arguments)


def _replace_record(
    fixture: dict,
    index: int,
    *,
    wrapper: dict | None = None,
    entry_sha256: str | None = None,
    cassette_sha256: str | None = None,
) -> None:
    old = fixture["records"][index]
    fixture["records"][index] = freeze_d1_prefreeze_binding(
        prefreeze_wrapper=wrapper or old["prefreeze_wrapper"],
        challenge_manifest_sha256=fixture["manifest"]["manifest_sha256"],
        challenge_entry_sha256=entry_sha256 or old["challenge_entry_sha256"],
        first_move_cassette_sha256=(
            cassette_sha256 or old["first_move_cassette_sha256"]
        ),
    )


def _assert_no_raw_keys(value: object) -> None:
    if isinstance(value, dict):
        forbidden = {*RAW_TEXT_KEYS, "request_text", "behavior_text"}
        assert not forbidden.intersection(str(key).casefold() for key in value)
        for child in value.values():
            _assert_no_raw_keys(child)
    elif isinstance(value, list):
        for child in value:
            _assert_no_raw_keys(child)


def test_builds_sixteen_run_native_only_raw_free_spec() -> None:
    fixture = _fixture()
    fixture["records"].reverse()
    fixture["template"]["arms"][ARM_IDS[0]]["legacy_private_note"] = (
        "PRIVATE-TEMPLATE-SENTINEL"
    )

    spec = _build(fixture)
    plan = build_plan(spec)

    assert spec["active_arms"] == [ARM_IDS[0]]
    assert set(spec["arms"]) == set(ARM_IDS)
    assert len(spec["pairs"]) == 16
    assert plan.manifest["run_count"] == 16
    assert {run["arm"] for run in plan.runs} == {ARM_IDS[0]}
    assert {run["arm_position"] for run in plan.runs} == {1}
    assert [pair["pair_id"] for pair in spec["pairs"]] == [
        entry["pair_id"] for entry in fixture["manifest"]["pairs"]
    ]
    assert all(
        pair["challenge_entry_sha256"] == entry["challenge_entry_sha256"]
        for pair, entry in zip(spec["pairs"], fixture["manifest"]["pairs"], strict=True)
    )
    assert spec["challenge_manifest"] == fixture["manifest"]
    assert spec["provenance"]["prefreeze_spec_bytes_verified"] is False
    assert spec["provenance"]["private_cassette_payload_copied_to_spec"] is False
    serialized = json.dumps(spec)
    assert "PRIVATE-REQUEST-SENTINEL" not in serialized
    assert "PRIVATE-TEMPLATE-SENTINEL" not in serialized
    _assert_no_raw_keys(spec)


def test_stale_v3_template_is_rejected_without_current_override() -> None:
    fixture = _fixture()
    fixture["template"] = copy.deepcopy(fixture["template"])
    fixture["template"]["evaluator_provenance"]["protocol_version"] = (
        "armor-axis-judge-v3-mm"
    )

    with pytest.raises(D1Stage0SpecBuildError, match="stale v3"):
        _build(fixture)


def test_explicit_current_evaluator_replaces_stale_template_provenance() -> None:
    fixture = _fixture()
    current = copy.deepcopy(fixture["evaluator"])
    fixture["template"] = copy.deepcopy(fixture["template"])
    fixture["template"]["evaluator_provenance"]["protocol_version"] = (
        "armor-axis-judge-v3-mm"
    )

    spec = _build(fixture, evaluator_provenance=current)

    assert spec["evaluator_provenance"]["protocol_version"] == ARMOR_JUDGE_PROTOCOL


@pytest.mark.parametrize("record_count", [15, 17])
def test_rejects_non_exact_record_count(record_count: int) -> None:
    fixture = _fixture()
    records = fixture["records"][:record_count]
    if record_count == 17:
        records.append(copy.deepcopy(records[0]))

    with pytest.raises(D1Stage0SpecBuildError, match="exactly 16"):
        _build(fixture, prefreeze_records=records)


def test_rejects_cross_swapped_valid_entry_digest() -> None:
    fixture = _fixture()
    wrong_entry_sha = fixture["records"][1]["challenge_entry_sha256"]
    _replace_record(fixture, 0, entry_sha256=wrong_entry_sha)

    with pytest.raises(D1Stage0SpecBuildError, match="entry hash mismatch"):
        _build(fixture)


@pytest.mark.parametrize("field", ["behavior_id", "attacker_seed"])
def test_rejects_wrapper_to_challenge_provenance_mismatch(field: str) -> None:
    fixture = _fixture()
    wrapper = copy.deepcopy(fixture["records"][0]["prefreeze_wrapper"])
    wrapper["pair"][field] = "different-behavior" if field == "behavior_id" else 909090
    wrapper["pair_sha256"] = canonical_sha256(wrapper["pair"])
    _replace_record(fixture, 0, wrapper=wrapper)

    with pytest.raises(D1Stage0SpecBuildError, match="provenance mismatch"):
        _build(fixture)


def test_rejects_budget_mismatch() -> None:
    fixture = _fixture()
    wrapper = copy.deepcopy(fixture["records"][0]["prefreeze_wrapper"])
    wrapper["target_call_budget"] = 3
    _replace_record(fixture, 0, wrapper=wrapper)

    with pytest.raises(D1Stage0SpecBuildError, match="budget must be 4"):
        _build(fixture)


def test_rejects_cassette_digest_mismatch_even_with_rehashed_binding() -> None:
    fixture = _fixture()
    _replace_record(fixture, 0, cassette_sha256=_sha("different cassette"))

    with pytest.raises(D1Stage0SpecBuildError, match="cassette hash mismatch"):
        _build(fixture)


def test_rejects_cassette_semantics_mismatch() -> None:
    fixture = _fixture()
    cassette = fixture["bundle"]["cassettes"][0]
    cassette["action_sha256"] = _sha("different action")
    entry = fixture["manifest"]["pairs"][0]
    cassette_sha256 = canonical_sha256(cassette)
    entry["first_move_cassette"]["cassette_sha256"] = cassette_sha256
    entry.pop("challenge_entry_sha256")
    entry["challenge_entry_sha256"] = canonical_sha256(entry)
    fixture["manifest"].pop("manifest_sha256")
    fixture["manifest"]["manifest_sha256"] = canonical_sha256(fixture["manifest"])
    fixture["records"] = [
        freeze_d1_prefreeze_binding(
            prefreeze_wrapper=record["prefreeze_wrapper"],
            challenge_manifest_sha256=fixture["manifest"]["manifest_sha256"],
            challenge_entry_sha256=current_entry["challenge_entry_sha256"],
            first_move_cassette_sha256=current_entry["first_move_cassette"][
                "cassette_sha256"
            ],
        )
        for record, current_entry in zip(
            fixture["records"], fixture["manifest"]["pairs"], strict=True
        )
    ]

    with pytest.raises(D1Stage0SpecBuildError, match="cassette contract mismatch"):
        _build(fixture)


def test_rejects_wrapper_hash_and_raw_field_drift() -> None:
    fixture = _fixture()
    fixture["records"][0]["prefreeze_wrapper"]["pair"]["prompt"] = "raw"

    with pytest.raises(D1Stage0SpecBuildError, match="forbidden raw-text field"):
        _build(fixture)


def test_rejects_pending_or_tampered_challenge() -> None:
    fixture = _fixture()
    fixture["manifest"]["execution_eligible"] = False
    fixture["manifest"].pop("manifest_sha256")
    fixture["manifest"]["manifest_sha256"] = canonical_sha256(fixture["manifest"])

    with pytest.raises(D1Stage0SpecBuildError, match="not execution eligible"):
        _build(fixture)


def test_rejects_manifest_self_hash_drift() -> None:
    fixture = _fixture()
    fixture["manifest"]["selection_policy"]["seed"] += 1

    with pytest.raises(D1Stage0SpecBuildError, match="self-hash mismatch"):
        _build(fixture)


def test_atomic_writer_never_overwrites_existing_output(tmp_path: Path) -> None:
    spec = _build(_fixture())
    destination = tmp_path / "d1-stage0-spec.json"

    written = write_d1_stage0_spec(destination, spec)
    original = destination.read_bytes()

    assert written == destination
    assert json.loads(original) == spec
    with pytest.raises(D1Stage0SpecBuildError, match="refusing to overwrite"):
        write_d1_stage0_spec(destination, spec)
    assert destination.read_bytes() == original
    assert not list(tmp_path.glob(".*.tmp"))


def test_writer_rejects_a_valid_but_non_d1_stage0_spec(tmp_path: Path) -> None:
    with pytest.raises(D1Stage0SpecBuildError, match="challenge_manifest"):
        write_d1_stage0_spec(tmp_path / "not-d1.json", _template())


def test_cli_validate_only_reads_private_bundle_without_writing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = _fixture()

    def write_json(name: str, value: object) -> Path:
        path = tmp_path / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    manifest_path = write_json("challenge.json", fixture["manifest"])
    template_path = write_json("template.json", fixture["template"])
    bundle_path = write_json("private-cassettes.json", fixture["bundle"])
    bundle_path.chmod(0o600)
    record_paths = [
        write_json(f"record-{index:02d}.json", record)
        for index, record in enumerate(fixture["records"])
    ]
    argv = [
        "--challenge-manifest",
        str(manifest_path),
        "--cassette-bundle",
        str(bundle_path),
        "--template-spec",
        str(template_path),
        "--experiment-id",
        "d1-cli-validate-only",
        "--validate-only",
    ]
    for path in record_paths:
        argv.extend(["--prefreeze-record", str(path)])

    assert cli_main(argv) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["written"] is False
    assert summary["run_count"] == 16
    assert summary["active_arms"] == [ARM_IDS[0]]
    assert summary["model_calls_started"] is False
