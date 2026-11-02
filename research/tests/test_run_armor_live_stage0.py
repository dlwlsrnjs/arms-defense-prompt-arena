from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from PIL import Image

from defense_arena.armor_first_move_cassette import (
    FrozenFirstMoveCassette,
    FrozenFirstMoveCassetteBundle,
)
from defense_arena.armor_stage0 import ARM_IDS, SHA256_EMPTY, build_plan, prepare
from defense_arena.armor_stage0_orchestrator import (
    LiveRunContext,
    LiveRunRecord,
    ResolvedBehavior,
    Stage0OrchestrationError,
)
from defense_arena.asset_hashing import image_content_sha256
from defense_arena.instrumentation import FALLBACK_POLICY_SHA256
from scripts import run_armor_live_stage0 as cli


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha_text(value: str) -> str:
    return _sha_bytes(value.encode())


def _write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def _fixture(tmp_path: Path):
    memory = tmp_path / "memory.json"
    memory.write_text("[]\n", encoding="utf-8")
    memory_hash = _sha_bytes(memory.read_bytes())
    asset = tmp_path / "asset.bmp"
    with Image.new("RGB", (2, 1), (7, 8, 9)) as image:
        asset_hash = image_content_sha256(image)
        image.save(asset)
    behavior = tmp_path / "behaviors.jsonl"
    behavior.write_text(
        json.dumps(
            {
                "id": "behavior-one",
                "query": "synthetic behavior",
                "risk_category": "Synthetic",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    with behavior.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                {
                    "id": "behavior-unused",
                    "query": "another synthetic behavior",
                    "risk_category": "Synthetic",
                }
            )
            + "\n"
        )
    base = tmp_path / "base.yaml"
    base.write_text("seed: 0\n", encoding="utf-8")
    arena = tmp_path / "arena.yaml"
    arena.write_text(
        """project_root: .
source_root: external-arms
base_config: base.yaml
behaviors: behaviors.jsonl
memory_mode: required
targets:
  target-a:
    label: Target A
    parameters: fixture
    model_id: unused
    base_url: http://existing-target/v1
    served_model_name: served-target
    memory_source: memory.json
    min_memory_entries: 0
    min_successful_entries: 0
    min_category_coverage: 0
""",
        encoding="utf-8",
    )

    prompt_values = {
        ARM_IDS[0]: "",
        ARM_IDS[1]: "generic defense",
        ARM_IDS[2]: "matched defense",
        ARM_IDS[3]: "mismatched defense",
    }
    prompt_manifest = tmp_path / "prompt_manifest.json"
    arm_to_condition = {
        ARM_IDS[0]: "native",
        ARM_IDS[1]: "generic",
        ARM_IDS[2]: "matched_memory",
        ARM_IDS[3]: "label_shuffled",
    }
    prompt_rows = {}
    for index, (arm, text) in enumerate(prompt_values.items()):
        prompt_path = tmp_path / "prompts" / f"{index}.txt"
        prompt_path.parent.mkdir(parents=True, exist_ok=True)
        prompt_path.write_text(text, encoding="utf-8")
        prompt_rows[arm_to_condition[arm]] = {
            "prompt_path": prompt_path.relative_to(tmp_path).as_posix(),
            "prompt_file_sha256": _sha_bytes(prompt_path.read_bytes()),
            "text_sha256": _sha_text(text),
            "tokens": len(text.split()),
        }
    _write_json(prompt_manifest, {"conditions": prompt_rows})
    asset_manifest = tmp_path / "asset_manifest.json"
    _write_json(
        asset_manifest,
        {
            "behaviors": {
                "behavior-one": {
                    "asset-one": {"path": "asset.bmp", "sha256": asset_hash}
                }
            }
        },
    )
    first_request = "fixture first request"
    first_action_hash = _sha_text("fixture first action")
    first_move_cassette = tmp_path / "first-move-cassette.json"
    _write_json(
        first_move_cassette,
        FrozenFirstMoveCassette(
            behavior_id="behavior-one",
            request_text=first_request,
            request_sha256=_sha_text(first_request),
            action_sha256=first_action_hash,
            image_assets=(("asset-one", asset_hash),),
        ).to_dict(),
    )
    first_move_cassette.chmod(0o600)

    spec = {
        "schema_version": 1,
        "experiment_id": "live-cli-fixture",
        "target_call_budget": 2,
        "randomization_seed": 17,
        "prompt_token_budget": 8,
        "max_censoring_rate": 0.01,
        "arms": {
            ARM_IDS[0]: {
                "prompt_sha256": SHA256_EMPTY,
                "prompt_token_count": 0,
                "memory_relation": "none",
                "compiler_memory_sha256": None,
            },
            ARM_IDS[1]: {
                "prompt_sha256": _sha_text(prompt_values[ARM_IDS[1]]),
                "prompt_token_count": 2,
                "memory_relation": "none",
                "compiler_memory_sha256": None,
            },
            ARM_IDS[2]: {
                "prompt_sha256": _sha_text(prompt_values[ARM_IDS[2]]),
                "prompt_token_count": 2,
                "memory_relation": "matched",
                "compiler_memory_sha256": memory_hash,
            },
            ARM_IDS[3]: {
                "prompt_sha256": _sha_text(prompt_values[ARM_IDS[3]]),
                "prompt_token_count": 2,
                "memory_relation": "mismatched",
                "compiler_memory_sha256": "9" * 64,
            },
        },
        "pairs": [
            {
                "pair_id": "pair-one",
                "behavior_id": "behavior-one",
                "attacker_seed": 7101,
                "initial_memory_sha256": memory_hash,
                "initial_retrieval_sha256": "1" * 64,
                "first_action_sha256": _sha_text(first_request),
                "fallback_policy_sha256": FALLBACK_POLICY_SHA256,
                "fallback_action_sha256": first_action_hash,
                "fallback_request_sha256": _sha_text(first_request),
                "asset_hashes": {"asset-one": asset_hash},
                "decoding_config": {
                    "temperature": 0.0,
                    "top_p": 1.0,
                    "max_tokens": 64,
                },
            }
        ],
    }
    prepared = prepare(build_plan(spec), tmp_path / "prepared")
    return SimpleNamespace(
        memory=memory,
        memory_hash=memory_hash,
        asset=asset,
        behavior=behavior,
        base=base,
        arena=arena,
        prompts=prompt_manifest,
        assets=asset_manifest,
        first_move_cassette=first_move_cassette,
        prepared=prepared,
        spec=spec,
    )


def _multi_pair_fixture(tmp_path: Path):
    paths = _fixture(tmp_path)
    second_asset = tmp_path / "asset-two.bmp"
    with Image.new("RGB", (2, 1), (17, 18, 19)) as image:
        second_asset_hash = image_content_sha256(image)
        image.save(second_asset)

    asset_manifest = json.loads(paths.assets.read_text(encoding="utf-8"))
    asset_manifest["behaviors"]["behavior-unused"] = {
        "asset-two": {
            "path": second_asset.name,
            "sha256": second_asset_hash,
        }
    }
    _write_json(paths.assets, asset_manifest)

    first = FrozenFirstMoveCassette.from_mapping(
        json.loads(paths.first_move_cassette.read_text(encoding="utf-8"))
    )
    second_request = "fixture second first request"
    second_action_hash = _sha_text("fixture second first action")
    second = FrozenFirstMoveCassette(
        behavior_id="behavior-unused",
        request_text=second_request,
        request_sha256=_sha_text(second_request),
        action_sha256=second_action_hash,
        image_assets=(("asset-two", second_asset_hash),),
    )
    _write_json(
        paths.first_move_cassette,
        FrozenFirstMoveCassetteBundle((first, second)).to_dict(),
    )
    paths.first_move_cassette.chmod(0o600)

    spec = copy.deepcopy(paths.spec)
    spec["pairs"].append(
        {
            "pair_id": "pair-two",
            "behavior_id": "behavior-unused",
            "attacker_seed": 7102,
            "initial_memory_sha256": paths.memory_hash,
            "initial_retrieval_sha256": "2" * 64,
            "first_action_sha256": _sha_text(second_request),
            "fallback_policy_sha256": FALLBACK_POLICY_SHA256,
            "fallback_action_sha256": second_action_hash,
            "fallback_request_sha256": _sha_text(second_request),
            "asset_hashes": {"asset-two": second_asset_hash},
            "decoding_config": {
                "temperature": 0.0,
                "top_p": 1.0,
                "max_tokens": 64,
            },
        }
    )
    paths.prepared = prepare(build_plan(spec), tmp_path / "prepared-multi")
    paths.second_asset = second_asset
    paths.second_request = second_request
    return paths


def _prepared_args(
    paths, result: Path, *, shutdown_completion: Path | None = None
) -> list[str]:
    args = [
        "--prepared",
        str(paths.prepared),
        "--arena-config",
        str(paths.arena),
        "--base-config",
        str(paths.base),
        "--target-id",
        "target-a",
        "--behaviors",
        str(paths.behavior),
        "--prompts",
        str(paths.prompts),
        "--assets",
        str(paths.assets),
        "--first-move-cassette",
        str(paths.first_move_cassette),
        "--memory",
        str(paths.memory),
        "--result",
        str(result),
    ]
    if shutdown_completion is not None:
        args.extend(["--shutdown-completion", str(shutdown_completion)])
    return args


def test_dry_run_resolves_explicit_artifacts_without_building_agent(tmp_path: Path):
    paths = _fixture(tmp_path)
    result = tmp_path / "dry-run.json"

    assert cli.main(["dry-run", *_prepared_args(paths, result)]) == 0

    report = json.loads(result.read_text(encoding="utf-8"))
    assert report["mode"] == "dry-run"
    assert report["run_count"] == 4
    assert report["model_calls"] == 0
    assert report["servers_started"] is False
    assert report["servers_stopped"] is False
    assert report["gpu_allocation_performed"] is False
    assert report["behavior_file"] == str(paths.behavior.resolve())


def test_multi_pair_dry_run_attests_complete_v2_bundle(tmp_path: Path):
    paths = _multi_pair_fixture(tmp_path)
    result = tmp_path / "multi-pair-dry-run.json"

    assert cli.main(["dry-run", *_prepared_args(paths, result)]) == 0

    report = json.loads(result.read_text(encoding="utf-8"))
    assert report["run_count"] == 8
    assert {row["pair_id"] for row in report["run_order"]} == {
        "pair-one",
        "pair-two",
    }
    assert report["model_calls"] == 0
    assert report["gpu_allocation_performed"] is False


def test_multi_pair_run_callable_routes_cassette_and_assets_by_contract_behavior(
    tmp_path: Path,
    monkeypatch,
):
    paths = _multi_pair_fixture(tmp_path)
    captured: list[tuple[str, str, tuple[str, ...], tuple[tuple[int, ...], ...]]] = []

    class _Runner:
        def __init__(self, **_kwargs):
            pass

        def __call__(self, context):
            move = context.frozen_first_move
            captured.append(
                (
                    str(context.contract["behavior_id"]),
                    move.request_text,
                    tuple(image.image_id for image in move.images),
                    tuple(
                        tuple(image.decoded_image.getpixel((0, 0)))
                        for image in move.images
                    ),
                )
            )
            return {}

    monkeypatch.setattr(cli, "ArmorLiveRunner", _Runner)
    result = tmp_path / "unused-report.json"
    args = cli.build_parser().parse_args(
        ["dry-run", *_prepared_args(paths, result)]
    )
    orchestrator = cli._build_orchestrator(args)

    for behavior_id in ("behavior-one", "behavior-unused"):
        context = LiveRunContext(
            contract={"behavior_id": behavior_id},
            behavior=ResolvedBehavior(behavior_id, object(), {}),
            installed_system_prompt="",
            output_dir=tmp_path,
            immutable_initial_memory_path=paths.memory,
            working_memory_path=paths.memory,
            attacker_seed=0,
            target_call_budget=1,
            decoding_config={},
            expected_stage0_provenance={},
        )
        assert orchestrator.run_callable(context) == {}

    assert captured == [
        (
            "behavior-one",
            "fixture first request",
            ("asset-one",),
            ((7, 8, 9),),
        ),
        (
            "behavior-unused",
            paths.second_request,
            ("asset-two",),
            ((17, 18, 19),),
        ),
    ]


@pytest.mark.parametrize("case", ["missing", "extra", "mismatch"])
def test_multi_pair_bundle_coverage_and_contract_mismatch_fail_closed(
    tmp_path: Path,
    case: str,
):
    paths = _multi_pair_fixture(tmp_path)
    raw = json.loads(paths.first_move_cassette.read_text(encoding="utf-8"))
    if case == "missing":
        raw["cassettes"].pop()
        expected = "cassette behavior coverage mismatch"
    elif case == "extra":
        extra_request = "extra private request"
        raw["cassettes"].append(
            FrozenFirstMoveCassette(
                behavior_id="behavior-extra",
                request_text=extra_request,
                request_sha256=_sha_text(extra_request),
                action_sha256=_sha_text("extra action"),
                image_assets=(("asset-extra", _sha_text("extra pixels")),),
            ).to_dict()
        )
        expected = "cassette behavior coverage mismatch"
    else:
        mismatched_request = "mismatched private request"
        raw["cassettes"][1]["request_text"] = mismatched_request
        raw["cassettes"][1]["request_sha256"] = _sha_text(mismatched_request)
        expected = "cassette contract mismatch"
    _write_json(paths.first_move_cassette, raw)
    paths.first_move_cassette.chmod(0o600)
    args = cli.build_parser().parse_args(
        ["dry-run", *_prepared_args(paths, tmp_path / "unused.json")]
    )

    with pytest.raises(cli.LiveStage0CLIError, match=expected):
        cli._build_orchestrator(args)


def test_v2_bundle_keeps_private_permission_requirement(tmp_path: Path):
    paths = _multi_pair_fixture(tmp_path)
    paths.first_move_cassette.chmod(0o640)
    args = cli.build_parser().parse_args(
        ["dry-run", *_prepared_args(paths, tmp_path / "unused.json")]
    )

    with pytest.raises(cli.LiveStage0CLIError, match="group/world accessible"):
        cli._build_orchestrator(args)


def test_live_mode_wires_runner_and_orchestrator_without_lifecycle_calls(
    tmp_path: Path, monkeypatch
):
    paths = _fixture(tmp_path)
    result = tmp_path / "live-report.json"
    shutdown_completion = tmp_path / "target-shutdown-request.json"
    captured = SimpleNamespace(runner=None, orchestrator=None)

    class _Runner:
        def __init__(self, **kwargs):
            captured.runner = kwargs

    class _Orchestrator:
        def __init__(self, **kwargs):
            captured.orchestrator = kwargs
            self.plan = SimpleNamespace(
                manifest={"protocol": "fixture-protocol", "experiment_id": "fixture"}
            )

        def execute(self):
            return (
                LiveRunRecord(
                    run_id="run-one",
                    pair_id="pair-one",
                    arm="native_no_added_prompt",
                    arm_position=1,
                    status="complete",
                    result_path="result.json",
                ),
            )

    monkeypatch.setattr(cli, "ArmorLiveRunner", _Runner)
    monkeypatch.setattr(cli, "Stage0LiveOrchestrator", _Orchestrator)

    assert (
        cli.main(
            [
                "live",
                *_prepared_args(
                    paths,
                    result,
                    shutdown_completion=shutdown_completion,
                ),
            ]
        )
        == 0
    )

    report = json.loads(result.read_text(encoding="utf-8"))
    assert captured.runner["freeze_memory"] is True
    assert captured.runner["base_config"] == paths.base
    assert captured.orchestrator["workers"] == 1
    assert report["records"][0]["status"] == "complete"
    assert report["servers_started"] is False
    assert report["gpu_allocation_performed"] is False
    shutdown = json.loads(shutdown_completion.read_text(encoding="utf-8"))
    assert shutdown["completed"] is True
    assert shutdown["execution_status"] == "complete"
    assert shutdown["lane_b_target_shutdown_requested"] is True
    assert shutdown["raw_attack_or_response_text_included"] is False


def test_live_failure_still_requests_external_target_shutdown(tmp_path: Path, monkeypatch):
    paths = _fixture(tmp_path)
    result = tmp_path / "failed-live-report.json"
    shutdown_completion = tmp_path / "failed-shutdown-request.json"

    class _Runner:
        def __init__(self, **_kwargs):
            pass

    class _Orchestrator:
        def __init__(self, **_kwargs):
            self.plan = SimpleNamespace(manifest={})

        def execute(self):
            raise Stage0OrchestrationError("fixture failure")

    monkeypatch.setattr(cli, "ArmorLiveRunner", _Runner)
    monkeypatch.setattr(cli, "Stage0LiveOrchestrator", _Orchestrator)

    with pytest.raises(SystemExit):
        cli.main(
            [
                "live",
                *_prepared_args(
                    paths,
                    result,
                    shutdown_completion=shutdown_completion,
                ),
            ]
        )

    shutdown = json.loads(shutdown_completion.read_text(encoding="utf-8"))
    assert shutdown["completed"] is True
    assert shutdown["execution_status"] == "failed"
    assert shutdown["lane_b_target_shutdown_requested"] is True


def _capture_row(context) -> dict:
    request = "captured first request"
    request_hash = _sha_text(request)
    action_hash = _sha_text("query action")
    with Image.new("RGB", (2, 1), (12, 34, 56)) as image:
        image_hash = image_content_sha256(image)
    return {
        "behavior": {"id": context.behavior.behavior_id, "text": "ephemeral"},
        "history": [
            {
                "call_index": 1,
                "error": "target_error",
                "turns": [{"text": request, "images": ["img_1"]}],
                "response": "",
                "request_sha256": request_hash,
                "response_sha256": _sha_text(""),
                "action_sha256": action_hash,
                "image_content_sha256": [image_hash],
            }
        ],
        "instrumentation": {
            "schema_version": 3,
            "target_call_budget": context.target_call_budget,
            "target_calls_started": 1,
            "target_responses_received": 0,
            "judge_invocations": 0,
            "termination_reason": "target_error",
            "provenance": {
                "base_seed": context.attacker_seed,
                "initial_retrieval_sha256": _sha_text("retrieval"),
                "first_target_request_sha256": request_hash,
                "first_target_action_sha256": action_hash,
                "asset_content_sha256": [image_hash],
            },
            "planner_fallback": {
                "configured_policy_sha256": FALLBACK_POLICY_SHA256
            },
        },
    }


def test_prefreeze_writes_metadata_pair_only_with_fake_capture_runner(
    tmp_path: Path, monkeypatch
):
    paths = _fixture(tmp_path)
    prefreeze_spec = tmp_path / "prefreeze.json"
    _write_json(
        prefreeze_spec,
        {
            "schema_version": 1,
            "pair_id": "pair-prefrozen",
            "attacker_seed": 7201,
            "target_call_budget": 2,
            "decoding_config": {"temperature": 0.0, "top_p": 1.0},
        },
    )
    result = tmp_path / "pair.json"
    assets_result = tmp_path / "prefrozen-assets.json"
    cassette_result = tmp_path / "private-first-move.json"
    work_dir = tmp_path / "prefreeze-work"
    captured = SimpleNamespace(init=None, context=None)

    class _Runner:
        def __init__(self, **kwargs):
            captured.init = kwargs

        def prefreeze(self, context):
            captured.context = context
            artifact = context.output_dir / "artifacts" / "00001" / "img_1.bmp"
            artifact.parent.mkdir(parents=True, exist_ok=True)
            with Image.new("RGB", (2, 1), (12, 34, 56)) as image:
                image.save(artifact)
            return _capture_row(context)

    monkeypatch.setattr(cli, "ArmorLiveRunner", _Runner)

    assert (
        cli.main(
            [
                "prefreeze",
                "--arena-config",
                str(paths.arena),
                "--base-config",
                str(paths.base),
                "--target-id",
                "target-a",
                "--behavior",
                str(paths.behavior),
                "--behavior-id",
                "behavior-one",
                "--memory",
                str(paths.memory),
                "--spec",
                str(prefreeze_spec),
                "--work-dir",
                str(work_dir),
                "--result",
                str(result),
                "--assets-result",
                str(assets_result),
                "--cassette-result",
                str(cassette_result),
            ]
        )
        == 0
    )

    wrapper = json.loads(result.read_text(encoding="utf-8"))
    pair = wrapper["pair"]
    assert captured.init["freeze_memory"] is True
    assert captured.context.workers == 1
    assert set(wrapper) == {
        "schema_version",
        "artifact_type",
        "target_call_budget",
        "pair",
        "pair_sha256",
        "prefreeze_spec_sha256",
        "decoding_config_sha256",
        "raw_attack_or_response_text_included",
    }
    assert wrapper["schema_version"] == 1
    assert wrapper["artifact_type"] == "armor-stage0-prefreeze-pair-v1"
    assert wrapper["target_call_budget"] == 2
    assert wrapper["pair_sha256"] == cli.canonical_sha256(pair)
    assert wrapper["prefreeze_spec_sha256"] == _sha_bytes(prefreeze_spec.read_bytes())
    assert wrapper["decoding_config_sha256"] == cli.canonical_sha256(
        pair["decoding_config"]
    )
    assert wrapper["raw_attack_or_response_text_included"] is False
    assert pair["pair_id"] == "pair-prefrozen"
    assert pair["behavior_id"] == "behavior-one"
    assert pair["first_action_sha256"] == _sha_text("captured first request")
    assert pair["fallback_policy_sha256"] == FALLBACK_POLICY_SHA256
    serialized = result.read_text(encoding="utf-8")
    assert "captured first request" not in serialized
    assert "ephemeral" not in serialized
    assets = json.loads(assets_result.read_text(encoding="utf-8"))
    asset_row = assets["behaviors"]["behavior-one"]["first-action-image-001"]
    assert Path(asset_row["path"]).suffix == ".bmp"
    with Image.open(asset_row["path"]) as image:
        image.load()
        assert asset_row["sha256"] == image_content_sha256(image)
    private = json.loads(cassette_result.read_text(encoding="utf-8"))
    assert private["request_text"] == "captured first request"
    assert private["target_response_included"] is False
    assert cassette_result.stat().st_mode & 0o777 == 0o600


def test_prefreeze_rejects_runtime_budget_attestation_drift(tmp_path: Path, monkeypatch):
    paths = _fixture(tmp_path)
    prefreeze_spec = tmp_path / "prefreeze-budget.json"
    _write_json(
        prefreeze_spec,
        {
            "schema_version": 1,
            "pair_id": "pair-budget-drift",
            "attacker_seed": 7202,
            "target_call_budget": 2,
            "decoding_config": {"temperature": 0.0, "top_p": 1.0},
        },
    )

    class _Runner:
        def __init__(self, **_kwargs):
            pass

        def prefreeze(self, context):
            row = _capture_row(context)
            row["instrumentation"]["target_call_budget"] = 3
            return row

    monkeypatch.setattr(cli, "ArmorLiveRunner", _Runner)
    result = tmp_path / "must-not-exist.json"
    with pytest.raises(SystemExit):
        cli.main(
            [
                "prefreeze",
                "--arena-config",
                str(paths.arena),
                "--base-config",
                str(paths.base),
                "--target-id",
                "target-a",
                "--behavior",
                str(paths.behavior),
                "--behavior-id",
                "behavior-one",
                "--memory",
                str(paths.memory),
                "--spec",
                str(prefreeze_spec),
                "--work-dir",
                str(tmp_path / "prefreeze-drift-work"),
                "--result",
                str(result),
                "--assets-result",
                str(tmp_path / "must-not-exist-assets.json"),
                "--cassette-result",
                str(tmp_path / "must-not-exist-cassette.json"),
            ]
        )
    assert not result.exists()


def test_cli_source_contains_no_server_or_gpu_lifecycle_operations():
    source = Path(cli.__file__).read_text(encoding="utf-8")
    assert "subprocess" not in source
    assert "CUDA_VISIBLE_DEVICES" not in source
    assert "nvidia-smi" not in source
    assert "kill(" not in source
