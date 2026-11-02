from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

from defense_arena import armor_live_runner as live_runner
from defense_arena.armor_judge import ARMOR_JUDGE_PROTOCOL, ArmorJudge
from defense_arena.armor_live_runner import (
    MEMORY_PREWARM_POLICY_SHA256,
    ArmorLiveRunner,
    ArmorLiveRunnerError,
    ARMsRuntimeBindings,
)
from defense_arena.armor_stage0 import (
    canonical_sha256,
    freeze_evaluator_provenance,
)
from defense_arena.armor_stage0_adapter import provenance_fields
from defense_arena.armor_stage0_orchestrator import LiveRunContext, ResolvedBehavior
from defense_arena.asset_hashing import image_content_sha256
from defense_arena.config import ArenaConfig, TargetProfile
from defense_arena.instrumentation import (
    FALLBACK_POLICY_SHA256,
    FrozenFirstMove,
    FrozenFirstMoveImage,
)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def test_source_pythonpath_is_child_visible_and_restores_absent_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "external-arms"
    source_root.mkdir()
    monkeypatch.delenv("PYTHONPATH", raising=False)

    with live_runner._temporary_source_pythonpath(source_root):
        child_environment = os.environ.copy()
        assert child_environment["PYTHONPATH"] == str(source_root.resolve())

    assert "PYTHONPATH" not in os.environ


def test_source_pythonpath_prepends_and_deduplicates_without_reordering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "external-arms"
    source_root.mkdir()
    source_text = str(source_root.resolve())
    original = os.pathsep.join(
        ["relative-one", source_text, "relative-two", "relative-one", ""]
    )
    monkeypatch.setenv("PYTHONPATH", original)

    with live_runner._temporary_source_pythonpath(source_root):
        child_environment = os.environ.copy()
        assert child_environment["PYTHONPATH"] == os.pathsep.join(
            [source_text, "relative-one", "relative-two", ""]
        )

    assert os.environ["PYTHONPATH"] == original


def test_source_pythonpath_restores_exact_value_after_exception(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "external-arms"
    source_root.mkdir()
    original = f"alpha{os.pathsep}{os.pathsep}beta{os.pathsep}alpha"
    monkeypatch.setenv("PYTHONPATH", original)

    with (
        pytest.raises(RuntimeError, match="fixture failure"),
        live_runner._temporary_source_pythonpath(source_root),
    ):
        assert os.environ["PYTHONPATH"].startswith(
            f"{source_root.resolve()}{os.pathsep}"
        )
        raise RuntimeError("fixture failure")

    assert os.environ["PYTHONPATH"] == original


@dataclass
class _Endpoint:
    base_url: str
    model: str
    temperature: float = 0.7
    max_tokens: int = 512


class _Config:
    def __init__(self):
        self.seed = 0
        self.max_queries = 30
        self.max_steps = 5
        self.min_queries_before_finish = 10
        self.eps_max = 1.0
        self.eps_min = 0.1
        self.attacker = _Endpoint("http://existing-attacker/v1", "served-attacker")
        self.target = _Endpoint("http://old-target/v1", "old-target")


class _Memory:
    def __init__(self, path: Path):
        self.path = path
        self.insert_calls = 0

    def __len__(self):
        return 1

    def retrieve(self, *_args, **_kwargs):
        return []

    def insert(self, _trajectory):
        self.insert_calls += 1
        self.path.write_bytes(self.path.read_bytes() + b"\nupdated")
        return True


class _BatchEmbedder:
    def __init__(self, failure: str | None = None):
        self.failure = failure
        self.calls: list[list[str]] = []

    def embed(self, texts):
        batch = list(texts)
        self.calls.append(batch)
        if self.failure == "count":
            return np.zeros((max(0, len(batch) - 1), 4), dtype=np.float32)
        if self.failure == "shape":
            return np.zeros((len(batch),), dtype=np.float32)
        rows = np.zeros((len(batch), 4), dtype=np.float32)
        for index, text in enumerate(batch):
            rows[index, index % 4] = float(len(text) + 1)
        return rows


class _BatchMemory(_Memory):
    def __init__(self, path: Path, *, failure: str | None = None):
        super().__init__(path)
        self.embedder = _BatchEmbedder(failure)
        self._emb_cache = {}
        self.grid = {
            (f"category-{index:02d}", f"strategy-{index:02d}"): SimpleNamespace(
                risk_category=f"category-{index:02d}",
                behavior=f"memory behavior {index:02d}",
            )
            for index in range(17)
        }


class _Target:
    def __init__(self):
        self.calls = []

    def chat(self, messages, **overrides):
        self.calls.append((messages, overrides))
        return "target response"


class _Image:
    mode = "RGB"
    size = (1, 1)

    def __init__(self, data: bytes):
        self.data = data

    def tobytes(self) -> bytes:
        return self.data


class _JudgeClient:
    def __init__(self):
        self.extra_body = {}

    def chat(self, _messages, **_overrides):
        raise AssertionError("offline bridge test must not call the judge endpoint")


class _Tools:
    def __init__(self):
        self.close_calls = 0

    def close(self):
        self.close_calls += 1


class _Result:
    def __init__(self, row):
        self.row = row

    def to_dict(self):
        return self.row


def _fixture(tmp_path: Path):
    initial_bytes = b"[]\n"
    initial_hash = _sha(initial_bytes)
    initial = tmp_path / "initial.snapshot"
    working = tmp_path / "working.snapshot"
    initial.write_bytes(initial_bytes)
    working.write_bytes(initial_bytes)
    base_config = tmp_path / "base.yaml"
    base_config.write_text("seed: 0\n", encoding="utf-8")
    arena_path = tmp_path / "arena.yaml"
    arena_path.write_text("fixture: true\n", encoding="utf-8")
    unused_memory = tmp_path / "must-not-be-used.json"
    unused_memory.write_text("[]\n", encoding="utf-8")
    behaviors = tmp_path / "behaviors.jsonl"
    behaviors.write_text("", encoding="utf-8")
    target = TargetProfile(
        id="target-a",
        label="Target A",
        parameters="fixture",
        model_id="unused-checkpoint",
        base_url="http://existing-target/v1",
        served_model_name="served-target",
        memory_source=unused_memory,
        min_memory_entries=0,
        min_successful_entries=0,
        min_category_coverage=0,
    )
    arena = ArenaConfig(
        path=arena_path,
        project_root=tmp_path,
        source_root=tmp_path / "external-source-not-imported",
        base_config=base_config,
        behaviors=behaviors,
        memory_mode="required",
        targets={target.id: target},
        warm_gate={},
        runtime_profile={
            "visual_judge": {
                "protocol_version": ARMOR_JUDGE_PROTOCOL,
                "role": "independent_multimodal_attack_validity_judge",
                "reuse_existing_endpoint": True,
                "model_id": "fixture/visual-evaluator",
                "model_revision": "fixture-visual-revision",
                "base_url": "http://existing-vision-judge/v1",
                "served_model_name": "served-vision-judge",
                "api_key": "EMPTY",
                "temperature": 0.0,
                "max_tokens": 4096,
                "timeout": 600.0,
                "max_retries": 4,
                "max_side": 640,
            }
        },
    )
    decoding = {"temperature": 0.0, "top_p": 1.0, "max_tokens": 64}
    contract = {
        "run_id": "run-one",
        "pair_id": "pair-one",
        "behavior_id": "behavior-one",
        "arm": "matched_memory_defense",
        "arm_position": 1,
        "arm_prompt_sha256": _sha(b"protect target"),
        "attacker_seed": 7101,
        "target_call_budget": 2,
        "initial_memory_sha256": initial_hash,
        "initial_retrieval_sha256": "1" * 64,
        "first_action_sha256": "2" * 64,
        "fallback_policy_sha256": FALLBACK_POLICY_SHA256,
        "fallback_action_sha256": "3" * 64,
        "fallback_request_sha256": "4" * 64,
        "asset_bundle_sha256": "5" * 64,
        "decoding_config_sha256": canonical_sha256(decoding),
        "run_memory_namespace": "run-memory/run-one",
    }
    expected = {field: contract[field] for field in provenance_fields(contract)}
    context = LiveRunContext(
        contract=contract,
        behavior=ResolvedBehavior(
            behavior_id="behavior-one",
            value=SimpleNamespace(
                id="behavior-one", text="synthetic behavior", risk_category="Synthetic"
            ),
            assets={},
        ),
        installed_system_prompt="protect target",
        output_dir=tmp_path / "runtime",
        immutable_initial_memory_path=initial,
        working_memory_path=working,
        attacker_seed=7101,
        target_call_budget=2,
        decoding_config=decoding,
        expected_stage0_provenance=expected,
        workers=1,
    )
    return arena, target, context, initial_bytes


def _context_with_frozen_move(
    context: LiveRunContext,
    images: tuple[tuple[str, _Image], ...],
) -> tuple[LiveRunContext, FrozenFirstMove]:
    request = "attested first request"
    request_hash = _sha(request.encode())
    action_hash = _sha(b"attested first action")
    contract = dict(context.contract)
    contract.update(
        {
            "first_action_sha256": request_hash,
            "fallback_action_sha256": action_hash,
            "fallback_request_sha256": request_hash,
            "asset_hashes": {
                image_id: image_content_sha256(image) for image_id, image in images
            },
        }
    )
    move = FrozenFirstMove(
        request_text=request,
        request_sha256=request_hash,
        action_sha256=action_hash,
        images=tuple(
            FrozenFirstMoveImage(
                image_id=image_id,
                decoded_image=image,
                content_sha256=image_content_sha256(image),
            )
            for image_id, image in images
        ),
    )
    expected = {field: contract[field] for field in provenance_fields(contract)}
    return (
        replace(
            context,
            contract=contract,
            expected_stage0_provenance=expected,
            frozen_first_move=move,
        ),
        move,
    )


def _modern_context(
    arena: ArenaConfig,
    target: TargetProfile,
    context: LiveRunContext,
) -> LiveRunContext:
    evaluator = freeze_evaluator_provenance(
        attacker_base_url="http://existing-attacker/v1",
        attacker_served_model_name="served-attacker",
        evaluated_target_base_url=target.base_url,
        evaluated_target_served_model_name=target.served_model_name,
        visual_evaluator=arena.runtime_profile["visual_judge"],
    )
    contract = {**context.contract, "evaluator_provenance": evaluator}
    return replace(
        context,
        contract=contract,
        expected_stage0_provenance={
            field: contract[field] for field in provenance_fields(contract)
        },
    )


def _bindings(
    *,
    adaptive_write: bool = False,
    attack_error: Exception | None = None,
    capture_prefreeze: bool = False,
    memory_factory=None,
):
    state = SimpleNamespace(
        config_paths=[],
        configs=[],
        build_calls=0,
        instrument_calls=0,
        attacks=0,
        agents=[],
        hooks=[],
        raw_targets=[],
        memories=[],
        frozen_moves=[],
        vision_client_settings=[],
        vision_clients=[],
        multimodal_messages=[],
    )

    def load_config(path: Path):
        state.config_paths.append(path)
        config = _Config()
        state.configs.append(config)
        return config

    def build_agent(cfg, out_dir: Path):
        state.build_calls += 1
        assert (out_dir / "memory.json").is_file()
        raw_target = _Target()
        state.raw_targets.append(raw_target)
        memory = (
            memory_factory(out_dir / "memory.json")
            if memory_factory is not None
            else _Memory(out_dir / "memory.json")
        )
        state.memories.append(memory)
        agent = SimpleNamespace(
            cfg=cfg,
            target=raw_target,
            judge=SimpleNamespace(client=_JudgeClient()),
            memory=memory,
            tools=_Tools(),
        )
        state.agents.append(agent)
        return agent

    def instrument_agent(
        agent,
        *,
        target_call_budget,
        provenance_hook,
        frozen_first_move=None,
    ):
        state.instrument_calls += 1
        state.frozen_moves.append(frozen_first_move)
        assert target_call_budget == 2

        class _Instrumented:
            def attack(self, behavior, index, workdir):
                state.attacks += 1
                assert index == 1
                assert workdir.name == "00001"
                assert isinstance(agent.judge, ArmorJudge)
                hook = provenance_hook(agent, behavior, index)
                state.hooks.append(hook)
                try:
                    response = agent.target.chat(
                        [{"role": "user", "content": "request"}], seed=12345
                    )
                except ArmorLiveRunnerError:
                    if not capture_prefreeze:
                        raise
                    request = "captured first request"
                    action_hash = _sha(b"captured query action")
                    image_hash = _sha(b"captured image")
                    return _Result(
                        {
                            "behavior": {"id": behavior.id, "text": behavior.text},
                            "history": [
                                {
                                    "call_index": 1,
                                    "error": "target_error",
                                    "turns": [{"text": request, "images": ["img_1"]}],
                                    "response": "",
                                    "request_sha256": _sha(request.encode()),
                                    "response_sha256": _sha(b""),
                                    "action_sha256": action_hash,
                                    "image_content_sha256": [image_hash],
                                }
                            ],
                            "instrumentation": {
                                "schema_version": 3,
                                "target_call_budget": agent.cfg.max_queries,
                                "target_calls_started": 1,
                                "target_responses_received": 0,
                                "judge_invocations": 0,
                                "termination_reason": "target_error",
                                "provenance": {
                                    "base_seed": agent.cfg.seed,
                                    "initial_retrieval_sha256": "1" * 64,
                                    "first_target_request_sha256": _sha(
                                        request.encode()
                                    ),
                                    "first_target_action_sha256": action_hash,
                                    "asset_content_sha256": [image_hash],
                                },
                                "planner_fallback": {
                                    "configured_policy_sha256": FALLBACK_POLICY_SHA256
                                },
                            },
                        }
                    )
                if adaptive_write:
                    agent.memory.insert(SimpleNamespace(best_score=1))
                if attack_error is not None:
                    raise attack_error
                return _Result(
                    {
                        "behavior": {"id": behavior.id},
                        "response": response,
                        "hook": hook,
                    }
                )

        return _Instrumented()

    def vision_client_factory(settings):
        state.vision_client_settings.append(dict(settings))
        client = _JudgeClient()
        state.vision_clients.append(client)
        return client

    def multimodal_make_message(role, text, images, max_side):
        state.multimodal_messages.append((role, text, tuple(images), max_side))
        return {"role": role, "content": text}

    return (
        ARMsRuntimeBindings(
            load_config=load_config,
            build_agent=build_agent,
            instrument_agent=instrument_agent,
            vision_client_factory=vision_client_factory,
            multimodal_make_message=multimodal_make_message,
        ),
        state,
    )


def test_live_bridge_builds_one_frozen_agent_and_applies_prompt_decoding_and_provenance(
    tmp_path: Path,
):
    arena, target, context, initial_bytes = _fixture(tmp_path)
    bindings, state = _bindings(adaptive_write=True)
    runner = ArmorLiveRunner(
        arena_config=arena,
        target_profile=target,
        bindings=bindings,
    )

    row = runner(context)

    assert runner.freeze_memory is True
    assert row["behavior"] == {"id": "behavior-one"}
    assert state.build_calls == state.instrument_calls == state.attacks == 1
    config = state.configs[0]
    assert config.seed == context.attacker_seed
    assert config.max_queries == context.target_call_budget
    assert config.eps_max == config.eps_min == 0.0
    assert config.max_steps >= 2 * context.target_call_budget
    assert config.target.base_url == target.base_url
    assert config.target.model == target.served_model_name
    assert config.target.temperature == 0.0
    assert config.target.max_tokens == 64

    agent = state.agents[0]
    assert agent.tools.close_calls == 1
    assert agent.memory.base.insert_calls == 0
    messages, overrides = agent.target.target.target.calls[0]
    assert messages == [
        {"role": "system", "content": "protect target"},
        {"role": "user", "content": "request"},
    ]
    assert overrides == {
        "seed": 12345,
        "temperature": 0.0,
        "top_p": 1.0,
        "max_tokens": 64,
    }
    assert state.hooks[0]["stage0_provenance"] == dict(
        context.expected_stage0_provenance
    )
    assert state.hooks[0]["live_runner"]["freeze_memory"] is True
    assert state.hooks[0]["live_runner"]["visual_judge"]["configured"] is True
    assert state.hooks[0]["live_runner"]["visual_judge"]["max_side"] == 640
    assert len(state.vision_clients) == 1
    assert state.vision_clients[0] is not state.agents[0].judge.client
    assert state.hooks[0]["live_runner"]["memory_prewarm"] == {
        "supported": False,
        "text_count": 0,
        "cache_hit_count": 0,
        "embedded_count": 0,
        "batch_size": 32,
        "batch_count": 0,
        "embedding_dimension": None,
        "policy_sha256": MEMORY_PREWARM_POLICY_SHA256,
    }
    assert context.immutable_initial_memory_path.read_bytes() == initial_bytes
    assert context.working_memory_path.read_bytes() == initial_bytes
    assert not target.memory_source.samefile(context.working_memory_path)


def test_live_bridge_validates_and_passes_ordered_frozen_first_move(tmp_path: Path):
    arena, target, base_context, _initial_bytes = _fixture(tmp_path)
    first = _Image(b"\x01\x02\x03")
    second = _Image(b"\x04\x05\x06")
    context, move = _context_with_frozen_move(
        base_context,
        (
            ("first-action-image-001", first),
            ("first-action-image-002", second),
        ),
    )
    bindings, state = _bindings()
    runner = ArmorLiveRunner(
        arena_config=arena,
        target_profile=target,
        bindings=bindings,
    )

    runner(context)

    assert state.frozen_moves == [move]
    assert state.build_calls == state.instrument_calls == state.attacks == 1
    messages = state.agents[0].judge.multimodal_message_builder(
        "rubric",
        "payload",
        (first, second, first),
    )
    assert messages == [
        {"role": "system", "content": "rubric"},
        {"role": "user", "content": "payload"},
    ]
    assert state.multimodal_messages[-1] == (
        "user",
        "payload",
        (first, second, first),
        640,
    )
    assert state.vision_client_settings == [
        {
            "base_url": "http://existing-vision-judge/v1",
            "model": "served-vision-judge",
            "api_key": "EMPTY",
            "temperature": 0.0,
            "max_tokens": 4096,
            "timeout": 600.0,
            "max_retries": 4,
            "image_max_side": 640,
        }
    ]


def test_live_bridge_rejects_multimodal_run_without_visual_config_or_factory(
    tmp_path: Path,
):
    arena, target, base_context, _initial_bytes = _fixture(tmp_path)
    context, _move = _context_with_frozen_move(
        base_context,
        (("first-action-image-001", _Image(b"\x01\x02\x03")),),
    )
    bindings, state = _bindings()
    runner = ArmorLiveRunner(
        arena_config=replace(arena, runtime_profile={}),
        target_profile=target,
        bindings=bindings,
    )

    with pytest.raises(ArmorLiveRunnerError, match="visual_judge"):
        runner(context)
    assert state.build_calls == 0


@pytest.mark.parametrize(
    "colliding_base_url",
    ["http://existing-attacker/v1/", "http://existing-target/v1"],
)
def test_live_bridge_rejects_visual_endpoint_collision_before_client_or_agent_build(
    tmp_path: Path,
    colliding_base_url: str,
):
    arena, target, context, _initial_bytes = _fixture(tmp_path)
    visual = {
        **arena.runtime_profile["visual_judge"],
        "base_url": colliding_base_url,
    }
    arena = replace(
        arena,
        runtime_profile={"visual_judge": visual},
    )
    bindings, state = _bindings()
    runner = ArmorLiveRunner(
        arena_config=arena,
        target_profile=target,
        bindings=bindings,
    )

    with pytest.raises(ArmorLiveRunnerError, match="must be distinct"):
        runner(context)

    assert state.vision_client_settings == []
    assert state.build_calls == 0


def test_live_bridge_rejects_runtime_evaluator_drift_from_frozen_contract(
    tmp_path: Path,
):
    arena, target, legacy_context, _initial_bytes = _fixture(tmp_path)
    context = _modern_context(arena, target, legacy_context)
    drifted_visual = {
        **arena.runtime_profile["visual_judge"],
        "model_revision": "different-revision",
    }
    arena = replace(
        arena,
        runtime_profile={"visual_judge": drifted_visual},
    )
    bindings, state = _bindings()
    runner = ArmorLiveRunner(
        arena_config=arena,
        target_profile=target,
        bindings=bindings,
    )

    with pytest.raises(ArmorLiveRunnerError, match="frozen Stage-0 contract"):
        runner(context)

    assert state.vision_client_settings == []
    assert state.build_calls == 0

    missing_factory = replace(bindings, vision_client_factory=None)
    second_runner = ArmorLiveRunner(
        arena_config=arena,
        target_profile=target,
        bindings=missing_factory,
    )
    with pytest.raises(ArmorLiveRunnerError, match="vision_client_factory"):
        second_runner(context)
    assert state.build_calls == 0


def test_live_bridge_preserves_duplicate_hashes_but_rejects_order_drift(
    tmp_path: Path,
):
    arena, target, base_context, _initial_bytes = _fixture(tmp_path)
    duplicate_a = _Image(b"\x01\x02\x03")
    duplicate_b = _Image(b"\x01\x02\x03")
    duplicate_context, duplicate_move = _context_with_frozen_move(
        base_context,
        (
            ("first-action-image-001", duplicate_a),
            ("first-action-image-002", duplicate_b),
        ),
    )
    bindings, state = _bindings()
    runner = ArmorLiveRunner(
        arena_config=arena,
        target_profile=target,
        bindings=bindings,
    )

    runner(duplicate_context)

    assert [item.content_sha256 for item in state.frozen_moves[0].images] == [
        duplicate_move.images[0].content_sha256,
        duplicate_move.images[1].content_sha256,
    ]

    first = _Image(b"\x07\x08\x09")
    second = _Image(b"\x0a\x0b\x0c")
    ordered_context, _move = _context_with_frozen_move(
        base_context,
        (
            ("first-action-image-001", first),
            ("first-action-image-002", second),
        ),
    )
    swapped = FrozenFirstMove(
        request_text=ordered_context.frozen_first_move.request_text,
        request_sha256=ordered_context.frozen_first_move.request_sha256,
        action_sha256=ordered_context.frozen_first_move.action_sha256,
        images=tuple(reversed(ordered_context.frozen_first_move.images)),
    )
    bad_context = replace(ordered_context, frozen_first_move=swapped)
    bad_bindings, bad_state = _bindings()
    bad_runner = ArmorLiveRunner(
        arena_config=arena,
        target_profile=target,
        bindings=bad_bindings,
    )

    with pytest.raises(ArmorLiveRunnerError, match="ordered image hashes"):
        bad_runner(bad_context)

    assert bad_state.build_calls == 0


def test_live_bridge_rejects_mutated_frozen_image_before_agent_build(tmp_path: Path):
    arena, target, base_context, _initial_bytes = _fixture(tmp_path)
    image = _Image(b"\x01\x02\x03")
    context, _move = _context_with_frozen_move(
        base_context,
        (("first-action-image-001", image),),
    )
    bindings, state = _bindings()
    runner = ArmorLiveRunner(
        arena_config=arena,
        target_profile=target,
        bindings=bindings,
    )
    image.data = b"\x09\x09\x09"

    with pytest.raises(ArmorLiveRunnerError, match="decoded image hash mismatch"):
        runner(context)

    assert state.build_calls == 0


def test_live_bridge_adaptive_mode_syncs_only_run_local_memory_atomically(
    tmp_path: Path,
):
    arena, target, context, initial_bytes = _fixture(tmp_path)
    bindings, state = _bindings(adaptive_write=True)
    before_inode = context.working_memory_path.stat().st_ino
    runner = ArmorLiveRunner(
        arena_config=arena,
        target_profile=target,
        freeze_memory=False,
        bindings=bindings,
    )

    runner(context)

    assert state.agents[0].memory.insert_calls == 1
    assert state.agents[0].tools.close_calls == 1
    assert context.immutable_initial_memory_path.read_bytes() == initial_bytes
    assert context.working_memory_path.read_bytes() == initial_bytes + b"\nupdated"
    assert context.working_memory_path.stat().st_ino != before_inode
    assert target.memory_source.read_text(encoding="utf-8") == "[]\n"


def test_live_bridge_closes_tools_and_does_not_sync_on_attack_failure(tmp_path: Path):
    arena, target, context, initial_bytes = _fixture(tmp_path)
    bindings, state = _bindings(
        adaptive_write=True, attack_error=RuntimeError("synthetic failure")
    )
    runner = ArmorLiveRunner(
        arena_config=arena,
        target_profile=target,
        freeze_memory=False,
        bindings=bindings,
    )

    with pytest.raises(RuntimeError, match="synthetic failure"):
        runner(context)

    assert state.agents[0].tools.close_calls == 1
    assert context.immutable_initial_memory_path.read_bytes() == initial_bytes
    assert context.working_memory_path.read_bytes() == initial_bytes


def test_live_bridge_rejects_contract_drift_before_build(tmp_path: Path):
    arena, target, context, _initial_bytes = _fixture(tmp_path)
    bindings, state = _bindings()
    context.contract["fallback_policy_sha256"] = "0" * 64
    context.expected_stage0_provenance["fallback_policy_sha256"] = "0" * 64
    runner = ArmorLiveRunner(
        arena_config=arena,
        target_profile=target,
        bindings=bindings,
    )

    with pytest.raises(ArmorLiveRunnerError, match="fallback policy"):
        runner(context)

    assert state.build_calls == 0


def test_prefreeze_uses_capture_stub_before_target_http_and_returns_valid_row(
    tmp_path: Path,
):
    arena, target, context, initial_bytes = _fixture(tmp_path)
    bindings, state = _bindings(capture_prefreeze=True)
    runner = ArmorLiveRunner(
        arena_config=arena,
        target_profile=target,
        freeze_memory=False,
        bindings=bindings,
    )

    row = runner.prefreeze(context)

    assert row["instrumentation"]["termination_reason"] == "target_error"
    assert row["instrumentation"]["target_responses_received"] == 0
    assert row["instrumentation"]["judge_invocations"] == 0
    assert state.raw_targets[0].calls == []
    assert state.hooks[0]["live_runner"] == {
        "freeze_memory": True,
        "prefreeze_capture": True,
        "decoding_config_sha256": context.contract["decoding_config_sha256"],
        "initial_memory_sha256": context.contract["initial_memory_sha256"],
        "memory_prewarm": {
            "supported": False,
            "text_count": 0,
            "cache_hit_count": 0,
            "embedded_count": 0,
            "batch_size": 32,
            "batch_count": 0,
            "embedding_dimension": None,
            "policy_sha256": MEMORY_PREWARM_POLICY_SHA256,
        },
        "visual_judge": {
            "configured": False,
            "role": None,
            "protocol_version": None,
            "model_id": None,
            "model_revision": None,
            "endpoint": None,
            "max_side": None,
            "media_transform_policy_sha256": None,
            "raw_media_included": False,
        },
        "workers": 1,
    }
    assert state.agents[0].tools.close_calls == 1
    assert context.immutable_initial_memory_path.read_bytes() == initial_bytes
    assert context.working_memory_path.read_bytes() == initial_bytes


@pytest.mark.parametrize("prefreeze", [False, True])
def test_live_and_prefreeze_path_prewarm_memory_in_deterministic_batches(
    tmp_path: Path,
    prefreeze: bool,
):
    arena, target, context, _initial_bytes = _fixture(tmp_path)
    bindings, state = _bindings(
        capture_prefreeze=prefreeze,
        memory_factory=_BatchMemory,
    )
    runner = ArmorLiveRunner(
        arena_config=arena,
        target_profile=target,
        bindings=bindings,
    )

    if prefreeze:
        runner.prefreeze(context)
    else:
        runner(context)

    memory = state.memories[0]
    expected = sorted(
        {
            "Synthetic",
            "synthetic behavior",
            *(f"category-{index:02d}" for index in range(17)),
            *(f"memory behavior {index:02d}" for index in range(17)),
        }
    )
    assert [len(batch) for batch in memory.embedder.calls] == [32, 4]
    assert [text for batch in memory.embedder.calls for text in batch] == expected
    assert sorted(memory._emb_cache) == expected
    assert state.hooks[0]["live_runner"]["memory_prewarm"] == {
        "supported": True,
        "text_count": 36,
        "cache_hit_count": 0,
        "embedded_count": 36,
        "batch_size": 32,
        "batch_count": 2,
        "embedding_dimension": 4,
        "policy_sha256": MEMORY_PREWARM_POLICY_SHA256,
    }


@pytest.mark.parametrize("failure", ["count", "shape"])
def test_memory_prewarm_fails_closed_on_invalid_embedding_output(
    tmp_path: Path,
    failure: str,
):
    arena, target, context, initial_bytes = _fixture(tmp_path)
    bindings, state = _bindings(
        memory_factory=lambda path: _BatchMemory(path, failure=failure)
    )
    runner = ArmorLiveRunner(
        arena_config=arena,
        target_profile=target,
        bindings=bindings,
    )

    with pytest.raises(ArmorLiveRunnerError, match="memory prewarm batch"):
        runner(context)

    assert state.instrument_calls == 0
    assert state.agents[0].tools.close_calls == 1
    assert state.memories[0]._emb_cache == {}
    assert context.immutable_initial_memory_path.read_bytes() == initial_bytes
    assert context.working_memory_path.read_bytes() == initial_bytes
