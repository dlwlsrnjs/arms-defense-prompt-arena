"""Pure run-callable bridge from Stage-0 contexts to one instrumented ARMS episode.

This module connects :class:`Stage0LiveOrchestrator` to an already-running set
of attacker, target, and judge endpoints.  It constructs clients and one ARMS
agent, but it deliberately has no server/device start, stop, allocation, or
cleanup logic.  Endpoint lifecycle remains the launcher's responsibility.
"""

from __future__ import annotations

import hashlib
import importlib
import os
import shutil
import sys
import tempfile
from collections.abc import Callable, Iterator, Mapping, MutableMapping
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .armor_judge import ArmorJudge
from .armor_prefreeze import extract_prefreeze_evidence
from .armor_stage0 import (
    VISUAL_EVALUATOR_ROLE,
    Stage0ValidationError,
    canonical_sha256,
    freeze_evaluator_provenance,
    media_transform_policy,
)
from .armor_stage0_adapter import provenance_fields
from .armor_stage0_orchestrator import LiveRunContext
from .config import ArenaConfig, TargetProfile
from .instrumentation import (
    FALLBACK_POLICY_SHA256,
    instrument_arms_agent,
    validate_frozen_first_move,
)
from .memory import sha256_file
from .prompting import SystemPromptTarget

MEMORY_PREWARM_POLICY = {
    "name": "arms_layered_memory_batch_prewarm_v1",
    "batch_size": 32,
    "ordering": "unique_unicode_lexicographic",
    "text_sources": [
        "memory.grid[*].risk_category",
        "memory.grid[*].behavior",
        "current_behavior.risk_category",
        "current_behavior.text",
    ],
    "cache_target": "memory._emb_cache",
    "validation": "exact_row_count_positive_1d_consistent_dimension",
}
MEMORY_PREWARM_POLICY_SHA256 = canonical_sha256(MEMORY_PREWARM_POLICY)


class ArmorLiveRunnerError(RuntimeError):
    """Raised when a live run would violate its frozen Stage-0 contract."""


@dataclass(frozen=True)
class ARMsRuntimeBindings:
    """Small dependency seam used by the real loader and offline tests."""

    load_config: Callable[[Path], Any]
    build_agent: Callable[[Any, Path], Any]
    instrument_agent: Callable[..., Any] = instrument_arms_agent
    behavior_factory: Callable[[Any, str], Any] | None = None
    vision_client_factory: Callable[[Mapping[str, Any]], Any] | None = None
    multimodal_make_message: Callable[..., dict[str, Any]] | None = None


@dataclass(frozen=True)
class _VisualJudgeRuntime:
    """Independent VLM judge path plus its immutable image transform."""

    client: Any
    message_builder: Callable[[str, str, tuple[Any, ...]], list[dict[str, Any]]]
    role: str
    media_transform_policy_sha256: str
    max_side: int
    evaluator_provenance: Mapping[str, Any]


class _FrozenMemory:
    """Permit retrieval from the run-local snapshot while blocking adaptation."""

    def __init__(self, base: Any):
        self.base = base
        self.path = getattr(base, "path", None)

    def __len__(self) -> int:
        return len(self.base)

    def retrieve(self, *args: Any, **kwargs: Any) -> Any:
        return self.base.retrieve(*args, **kwargs)

    def insert(self, _trajectory: Any) -> bool:
        return False


class _FixedDecodingTarget:
    """Apply the frozen target decoding mapping to every target generation."""

    def __init__(self, target: Any, decoding_config: Mapping[str, Any]):
        self.target = target
        self.decoding_config = dict(decoding_config)

    def chat(self, messages: list[dict], **overrides: Any) -> str:
        merged = dict(overrides)
        for key, value in self.decoding_config.items():
            if key in merged and merged[key] != value:
                raise ArmorLiveRunnerError(
                    f"target decoding override conflicts with frozen {key}"
                )
            merged[key] = value
        return self.target.chat(messages, **merged)


class _PrefreezeCaptureTarget:
    """Abort before any target endpoint can receive the frozen first request."""

    def chat(self, _messages: list[dict], **_overrides: Any) -> str:
        raise ArmorLiveRunnerError("armor_prefreeze_target_capture")


@dataclass(frozen=True)
class _MemoryPrewarmReport:
    supported: bool
    text_count: int
    cache_hit_count: int
    embedded_count: int
    batch_size: int
    batch_count: int
    embedding_dimension: int | None
    policy_sha256: str = MEMORY_PREWARM_POLICY_SHA256

    def to_dict(self) -> dict[str, Any]:
        return {
            "supported": self.supported,
            "text_count": self.text_count,
            "cache_hit_count": self.cache_hit_count,
            "embedded_count": self.embedded_count,
            "batch_size": self.batch_size,
            "batch_count": self.batch_count,
            "embedding_dimension": self.embedding_dimension,
            "policy_sha256": self.policy_sha256,
        }


def _vector_dimension(value: Any, label: str) -> int:
    shape = getattr(value, "shape", None)
    if shape is not None:
        try:
            dimensions = tuple(int(item) for item in shape)
        except (TypeError, ValueError) as exc:
            raise ArmorLiveRunnerError(f"{label} has an invalid shape") from exc
        if len(dimensions) != 1 or dimensions[0] < 1:
            raise ArmorLiveRunnerError(f"{label} must be a non-empty 1-D vector")
        return dimensions[0]
    if isinstance(value, (str, bytes, bytearray)):
        raise ArmorLiveRunnerError(f"{label} must be a numeric vector")
    try:
        dimension = len(value)
    except TypeError as exc:
        raise ArmorLiveRunnerError(f"{label} must be a vector") from exc
    if dimension < 1:
        raise ArmorLiveRunnerError(f"{label} must be a non-empty vector")
    return int(dimension)


def _embedding_rows(value: Any, expected_count: int, label: str) -> list[Any]:
    shape = getattr(value, "shape", None)
    if shape is not None:
        try:
            dimensions = tuple(int(item) for item in shape)
        except (TypeError, ValueError) as exc:
            raise ArmorLiveRunnerError(f"{label} has an invalid shape") from exc
        if len(dimensions) != 2 or dimensions[0] != expected_count or dimensions[1] < 1:
            raise ArmorLiveRunnerError(
                f"{label} must have shape ({expected_count}, positive_dimension)"
            )
    if isinstance(value, (str, bytes, bytearray)):
        raise ArmorLiveRunnerError(f"{label} must be a sequence of vectors")
    try:
        rows = list(value)
    except TypeError as exc:
        raise ArmorLiveRunnerError(f"{label} must be a sequence of vectors") from exc
    if len(rows) != expected_count:
        raise ArmorLiveRunnerError(
            f"{label} returned {len(rows)} rows for {expected_count} texts"
        )
    return rows


def _prewarm_memory_embeddings(
    memory: Any,
    behavior: Any,
) -> _MemoryPrewarmReport:
    """Populate LayeredMemory's private cache in deterministic small batches."""

    batch_size = int(MEMORY_PREWARM_POLICY["batch_size"])
    required = ("grid", "embedder", "_emb_cache")
    if not all(hasattr(memory, name) for name in required):
        return _MemoryPrewarmReport(False, 0, 0, 0, batch_size, 0, None)

    grid = memory.grid
    cache = memory._emb_cache
    embed = getattr(memory.embedder, "embed", None)
    if not isinstance(grid, Mapping):
        raise ArmorLiveRunnerError("memory prewarm grid must be a mapping")
    if not isinstance(cache, MutableMapping):
        raise ArmorLiveRunnerError("memory prewarm cache must be mutable")
    if not callable(embed):
        raise ArmorLiveRunnerError("memory prewarm embedder must expose embed")

    texts = {behavior.risk_category, behavior.text}
    for index, trajectory in enumerate(grid.values()):
        category = getattr(trajectory, "risk_category", None)
        trajectory_behavior = getattr(trajectory, "behavior", None)
        if not isinstance(category, str) or not isinstance(trajectory_behavior, str):
            raise ArmorLiveRunnerError(
                f"memory prewarm trajectory {index} lacks string category/behavior"
            )
        texts.add(category)
        texts.add(trajectory_behavior)
    if not all(isinstance(text, str) for text in texts):
        raise ArmorLiveRunnerError("memory prewarm texts must all be strings")
    ordered = sorted(texts)

    dimension: int | None = None
    cache_hits = 0
    missing: list[str] = []
    for text in ordered:
        if text not in cache:
            missing.append(text)
            continue
        cache_hits += 1
        observed = _vector_dimension(cache[text], f"memory cache entry {text!r}")
        if dimension is None:
            dimension = observed
        elif dimension != observed:
            raise ArmorLiveRunnerError("memory cache embedding dimensions disagree")

    pending: dict[str, Any] = {}
    batch_count = 0
    for offset in range(0, len(missing), batch_size):
        batch = missing[offset : offset + batch_size]
        batch_count += 1
        try:
            encoded = embed(batch)
        except Exception as exc:
            raise ArmorLiveRunnerError(
                f"memory prewarm embedder failed at batch {batch_count}"
            ) from exc
        rows = _embedding_rows(
            encoded,
            len(batch),
            f"memory prewarm batch {batch_count}",
        )
        for text, row in zip(batch, rows, strict=True):
            observed = _vector_dimension(row, f"memory embedding for {text!r}")
            if dimension is None:
                dimension = observed
            elif dimension != observed:
                raise ArmorLiveRunnerError(
                    "memory prewarm embedding dimensions disagree"
                )
            pending[text] = row

    cache.update(pending)
    if any(text not in cache for text in ordered):
        raise ArmorLiveRunnerError("memory prewarm cache population was incomplete")
    return _MemoryPrewarmReport(
        supported=True,
        text_count=len(ordered),
        cache_hit_count=cache_hits,
        embedded_count=len(pending),
        batch_size=batch_size,
        batch_count=batch_count,
        embedding_dimension=dimension,
    )


def _atomic_copy(source: Path, destination: Path) -> None:
    """Copy one file via same-directory replace so readers never see a partial."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        shutil.copyfile(source, temporary)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def _module_is_under(module: Any, root: Path) -> bool:
    module_file = getattr(module, "__file__", None)
    if not module_file:
        return False
    try:
        Path(module_file).resolve().relative_to(root)
    except ValueError:
        return False
    return True


@contextmanager
def _temporary_source_pythonpath(source_root: Path) -> Iterator[None]:
    """Expose the configured ARMS tree to child Python processes.

    ARMS' MCP backend launches ``sys.executable -m arms.mcp.server`` with a
    copy of the current environment.  Updating only the parent's ``sys.path``
    therefore leaves that child unable to import ``arms``.  Keep the resolved
    source root first, retain the order of all other distinct entries (empty
    entries included), and restore the exact prior environment state.
    """

    source_text = str(source_root.resolve())
    existed = "PYTHONPATH" in os.environ
    original = os.environ.get("PYTHONPATH")
    existing_entries = [] if original is None else original.split(os.pathsep)
    ordered = [source_text]
    seen = {source_text}
    for entry in existing_entries:
        if entry in seen:
            continue
        seen.add(entry)
        ordered.append(entry)
    os.environ["PYTHONPATH"] = os.pathsep.join(ordered)
    try:
        yield
    finally:
        if existed:
            # ``original`` is necessarily a string when the key existed, but
            # retain this branch to make restoration explicit and fail closed.
            os.environ["PYTHONPATH"] = "" if original is None else original
        else:
            os.environ.pop("PYTHONPATH", None)


def _default_behavior_factory(behavior_type: type) -> Callable[[Any, str], Any]:
    def factory(value: Any, expected_id: str) -> Any:
        if isinstance(value, behavior_type):
            return value
        if isinstance(value, Mapping):
            text = value.get("text", value.get("behavior"))
            category = value.get("risk_category")
            if not isinstance(text, str) or not isinstance(category, str):
                raise ArmorLiveRunnerError(
                    "mapping behavior values require text/behavior and risk_category"
                )
            return behavior_type(
                id=str(value.get("id", expected_id)),
                text=text,
                risk_category=category,
                sector=str(value.get("sector", "")),
            )
        return value

    return factory


def _default_vision_client_factory(
    chat_client_type: type,
) -> Callable[[Mapping[str, Any]], Any]:
    """Bind the external ARMS ChatClient without sharing another endpoint object."""

    def factory(settings: Mapping[str, Any]) -> Any:
        return chat_client_type(**dict(settings))

    return factory


def _requires_multimodal_judge(context: LiveRunContext) -> bool:
    assets = context.contract.get("asset_hashes")
    contract_has_assets = isinstance(assets, Mapping) and bool(assets)
    cassette_has_images = bool(
        context.frozen_first_move is not None and context.frozen_first_move.images
    )
    return contract_has_assets or cassette_has_images


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ArmorLiveRunnerError(f"{label} must be a positive integer")
    return value


def _visual_judge_runtime(
    *,
    arena_config: ArenaConfig,
    bindings: ARMsRuntimeBindings,
    required: bool,
    attacker_endpoint: Any,
    target_profile: TargetProfile,
    expected_provenance: Mapping[str, Any] | None,
) -> _VisualJudgeRuntime | None:
    """Build a separately configured VLM validity judge without endpoint I/O.

    The configuration deliberately lives in ``runtime_profile`` rather than
    borrowing the target or text judge client.  Constructing ARMS ChatClient
    does not make a model call; failures here therefore happen before any live
    target/judge request.
    """

    raw = arena_config.runtime_profile.get("visual_judge")
    if raw is None:
        if required:
            raise ArmorLiveRunnerError(
                "multimodal run requires runtime_profile.visual_judge"
            )
        return None
    if not isinstance(raw, Mapping):
        raise ArmorLiveRunnerError("runtime_profile.visual_judge must be a mapping")
    if bindings.vision_client_factory is None:
        raise ArmorLiveRunnerError(
            "multimodal run requires an independent vision_client_factory"
        )
    if bindings.multimodal_make_message is None:
        raise ArmorLiveRunnerError(
            "multimodal run requires the ARMS make_message transform"
        )

    role = raw.get("role")
    if role != VISUAL_EVALUATOR_ROLE:
        raise ArmorLiveRunnerError(
            f"visual_judge.role must be {VISUAL_EVALUATOR_ROLE!r}"
        )
    if raw.get("reuse_existing_endpoint") is not True:
        raise ArmorLiveRunnerError(
            "visual_judge must explicitly reuse an existing endpoint"
        )
    base_url = raw.get("base_url")
    model = raw.get("served_model_name")
    api_key = raw.get("api_key", "EMPTY")
    if not isinstance(base_url, str) or not base_url.strip():
        raise ArmorLiveRunnerError("visual_judge.base_url must be non-empty")
    if not isinstance(model, str) or not model.strip():
        raise ArmorLiveRunnerError("visual_judge.served_model_name must be non-empty")
    if not isinstance(api_key, str) or not api_key:
        raise ArmorLiveRunnerError("visual_judge.api_key must be non-empty")
    max_side = _positive_int(raw.get("max_side"), "visual_judge.max_side")
    max_tokens = _positive_int(raw.get("max_tokens", 4096), "visual_judge.max_tokens")
    max_retries = _positive_int(raw.get("max_retries", 4), "visual_judge.max_retries")
    timeout = raw.get("timeout", 600.0)
    temperature = raw.get("temperature", 0.0)
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or timeout <= 0
    ):
        raise ArmorLiveRunnerError("visual_judge.timeout must be positive")
    if (
        isinstance(temperature, bool)
        or not isinstance(temperature, (int, float))
        or not 0 <= float(temperature) <= 2
    ):
        raise ArmorLiveRunnerError("visual_judge.temperature must be in [0, 2]")

    try:
        evaluator_provenance = freeze_evaluator_provenance(
            attacker_base_url=getattr(attacker_endpoint, "base_url", None),
            attacker_served_model_name=getattr(attacker_endpoint, "model", None),
            evaluated_target_base_url=target_profile.base_url,
            evaluated_target_served_model_name=target_profile.served_model_name,
            visual_evaluator=raw,
        )
    except Stage0ValidationError as exc:
        raise ArmorLiveRunnerError(str(exc)) from exc
    if (
        expected_provenance is not None
        and dict(expected_provenance) != evaluator_provenance
    ):
        raise ArmorLiveRunnerError(
            "runtime evaluator provenance differs from the frozen Stage-0 contract"
        )

    client_settings = {
        "base_url": base_url.strip(),
        "model": model.strip(),
        "api_key": api_key,
        "temperature": float(temperature),
        "max_tokens": max_tokens,
        "timeout": float(timeout),
        "max_retries": max_retries,
        "image_max_side": max_side,
    }
    try:
        client = bindings.vision_client_factory(client_settings)
    except Exception as exc:
        raise ArmorLiveRunnerError(
            f"visual judge client factory failed: {type(exc).__name__}"
        ) from exc
    if not callable(getattr(client, "chat", None)):
        raise ArmorLiveRunnerError(
            "visual judge client factory returned an incompatible object"
        )

    policy_sha256 = canonical_sha256(media_transform_policy(max_side))
    make_message = bindings.multimodal_make_message

    def builder(
        rubric: str,
        payload: str,
        ordered_images: tuple[Any, ...],
    ) -> list[dict[str, Any]]:
        return [
            make_message("system", rubric, (), max_side),
            make_message("user", payload, ordered_images, max_side),
        ]

    return _VisualJudgeRuntime(
        client=client,
        message_builder=builder,
        role=str(role),
        media_transform_policy_sha256=policy_sha256,
        max_side=max_side,
        evaluator_provenance=evaluator_provenance,
    )


@contextmanager
def _load_default_bindings(arena_config: ArenaConfig) -> Iterator[ARMsRuntimeBindings]:
    """Import the configured source tree and temporarily install local prompt fixes."""

    source_root = arena_config.source_root.resolve()
    if not (source_root / "arms" / "runner.py").is_file():
        raise ArmorLiveRunnerError(f"ARMS source tree not found: {source_root}")
    source_text = str(source_root)
    inserted = source_text not in sys.path
    if inserted:
        sys.path.insert(0, source_text)
    importlib.invalidate_caches()
    try:
        with _temporary_source_pythonpath(source_root):
            agent_module = importlib.import_module("arms.agent")
            config_module = importlib.import_module("arms.config")
            llm_module = importlib.import_module("arms.llm")
            prompt_module = importlib.import_module("arms.prompts")
            runner_module = importlib.import_module("arms.runner")
            types_module = importlib.import_module("arms.types")
            for module in (
                agent_module,
                config_module,
                llm_module,
                prompt_module,
                runner_module,
                types_module,
            ):
                if not _module_is_under(module, source_root):
                    raise ArmorLiveRunnerError(
                        "imported ARMS module is outside configured source root: "
                        f"{module.__name__}"
                    )

            from scripts import run_open_arms as local_protocol

            original_prompt = prompt_module.PLANNER_SYSTEM
            original_first_user = agent_module.FIRST_USER
            original_compact = agent_module._compact
            prompt_module.PLANNER_SYSTEM = local_protocol.PLANNER_SYSTEM
            agent_module.FIRST_USER = local_protocol.FIRST_USER
            agent_module._compact = local_protocol.compact_planner_context
            try:
                yield ARMsRuntimeBindings(
                    load_config=config_module.ARMsConfig.load,
                    build_agent=runner_module.build_agent,
                    behavior_factory=_default_behavior_factory(types_module.Behavior),
                    vision_client_factory=_default_vision_client_factory(
                        llm_module.ChatClient
                    ),
                    multimodal_make_message=llm_module.make_message,
                )
            finally:
                prompt_module.PLANNER_SYSTEM = original_prompt
                agent_module.FIRST_USER = original_first_user
                agent_module._compact = original_compact
    finally:
        if inserted:
            try:
                sys.path.remove(source_text)
            except ValueError:
                pass


def _validate_behavior(value: Any, expected_id: str) -> None:
    if getattr(value, "id", None) != expected_id:
        raise ArmorLiveRunnerError("resolved behavior id does not match live context")
    if not isinstance(getattr(value, "text", None), str):
        raise ArmorLiveRunnerError("resolved behavior must expose text")
    if not isinstance(getattr(value, "risk_category", None), str):
        raise ArmorLiveRunnerError("resolved behavior must expose risk_category")


def _validate_context(context: LiveRunContext) -> None:
    if context.workers != 1:
        raise ArmorLiveRunnerError("Stage-0 live ARMS runs require workers=1")
    if context.attacker_seed != context.contract.get("attacker_seed"):
        raise ArmorLiveRunnerError("attacker seed differs from frozen contract")
    if context.target_call_budget != context.contract.get("target_call_budget"):
        raise ArmorLiveRunnerError("target-call budget differs from frozen contract")
    expected = {
        field: context.contract.get(field)
        for field in provenance_fields(context.contract)
    }
    if dict(context.expected_stage0_provenance) != expected:
        raise ArmorLiveRunnerError("expected Stage-0 provenance differs from contract")
    if canonical_sha256(dict(context.decoding_config)) != context.contract.get(
        "decoding_config_sha256"
    ):
        raise ArmorLiveRunnerError("decoding config differs from frozen contract")
    reserved_decoding_keys = {
        "extra_body",
        "messages",
        "model",
        "response_format",
        "seed",
    }
    conflicts = sorted(reserved_decoding_keys.intersection(context.decoding_config))
    if conflicts:
        raise ArmorLiveRunnerError(
            f"decoding config contains runner-reserved keys: {conflicts}"
        )
    if FALLBACK_POLICY_SHA256 != context.contract.get("fallback_policy_sha256"):
        raise ArmorLiveRunnerError("fallback policy differs from instrumented policy")
    if (
        context.immutable_initial_memory_path.resolve()
        == context.working_memory_path.resolve()
    ):
        raise ArmorLiveRunnerError("immutable and working memory paths must differ")
    if context.installed_system_prompt != context.installed_system_prompt.strip():
        raise ArmorLiveRunnerError("installed system prompt must already be normalized")
    prompt_hash = hashlib.sha256(
        context.installed_system_prompt.encode("utf-8")
    ).hexdigest()
    if prompt_hash != context.contract.get("arm_prompt_sha256"):
        raise ArmorLiveRunnerError(
            "installed system prompt differs from frozen contract"
        )
    if context.frozen_first_move is not None:
        asset_hashes = context.contract.get("asset_hashes")
        if not isinstance(asset_hashes, Mapping):
            raise ArmorLiveRunnerError(
                "frozen first move requires contract asset_hashes"
            )
        ordered_asset_ids = tuple(sorted(str(key) for key in asset_hashes))
        ordered_asset_hashes = tuple(
            str(asset_hashes[key]) for key in ordered_asset_ids
        )
        try:
            validate_frozen_first_move(
                context.frozen_first_move,
                expected_request_sha256=str(context.contract["first_action_sha256"]),
                expected_action_sha256=str(context.contract["fallback_action_sha256"]),
                expected_image_content_sha256=ordered_asset_hashes,
            )
        except (TypeError, ValueError) as exc:
            raise ArmorLiveRunnerError(
                f"frozen first move differs from contract: {exc}"
            ) from exc
        if context.frozen_first_move.request_sha256 != context.contract.get(
            "fallback_request_sha256"
        ):
            raise ArmorLiveRunnerError(
                "frozen first-move request differs from fallback contract"
            )
        if (
            tuple(item.image_id for item in context.frozen_first_move.images)
            != ordered_asset_ids
        ):
            raise ArmorLiveRunnerError(
                "frozen first-move ordered image ids differ from contract"
            )


def _configure_runtime(
    cfg: Any,
    context: LiveRunContext,
    target_profile: TargetProfile,
) -> None:
    cfg.seed = context.attacker_seed
    cfg.max_queries = context.target_call_budget
    cfg.eps_max = 0.0
    cfg.eps_min = 0.0
    cfg.min_queries_before_finish = min(
        int(getattr(cfg, "min_queries_before_finish", context.target_call_budget)),
        context.target_call_budget,
    )
    cfg.max_steps = max(
        int(getattr(cfg, "max_steps", 0)), 2 * context.target_call_budget
    )
    cfg.target.base_url = target_profile.base_url
    cfg.target.model = target_profile.served_model_name
    if "temperature" in context.decoding_config:
        cfg.target.temperature = context.decoding_config["temperature"]
    if "max_tokens" in context.decoding_config:
        cfg.target.max_tokens = context.decoding_config["max_tokens"]


def _coerce_row(result: Any) -> Mapping[str, Any]:
    row = result.to_dict() if callable(getattr(result, "to_dict", None)) else result
    if not isinstance(row, Mapping):
        raise ArmorLiveRunnerError("instrumented ARMS attack must return a mapping")
    return row


class ArmorLiveRunner:
    """Callable bridge for exactly one Stage-0 behavior and one ARMS agent.

    ``freeze_memory=True`` is the default causal-evaluation mode. Retrieval
    still uses the run-local working snapshot, while insertion is disabled.
    Setting it false permits within-run adaptation; writes remain isolated to
    the run-local agent file and are atomically synchronized back only after a
    successful episode.
    """

    def __init__(
        self,
        *,
        arena_config: ArenaConfig,
        target_profile: TargetProfile,
        base_config: str | Path | None = None,
        freeze_memory: bool = True,
        bindings: ARMsRuntimeBindings | None = None,
    ):
        configured_target = arena_config.targets.get(target_profile.id)
        if configured_target != target_profile:
            raise ArmorLiveRunnerError(
                "target profile must be the exact profile registered in arena config"
            )
        if not isinstance(freeze_memory, bool):
            raise TypeError("freeze_memory must be a boolean")
        self.arena_config = arena_config
        self.target_profile = target_profile
        selected_config = Path(base_config or arena_config.base_config).expanduser()
        if not selected_config.is_absolute():
            selected_config = arena_config.project_root / selected_config
        self.base_config = selected_config.resolve()
        self.freeze_memory = freeze_memory
        self.bindings = bindings

    def __call__(self, context: LiveRunContext) -> Mapping[str, Any]:
        return self._run(context, prefreeze=False)

    def prefreeze(self, context: LiveRunContext) -> Mapping[str, Any]:
        """Capture the first resolved target request without target HTTP I/O.

        The attacker, memory retrieval, and tools are real. The target is
        replaced before instrumentation with a stub that raises on its first
        invocation. The returned schema-v3 row can be reduced with
        :func:`extract_prefreeze_evidence` to prepare a paired Stage-0 spec.
        """

        return self._run(context, prefreeze=True)

    def _run(self, context: LiveRunContext, *, prefreeze: bool) -> Mapping[str, Any]:
        if prefreeze and context.frozen_first_move is not None:
            raise ArmorLiveRunnerError(
                "prefreeze capture cannot consume a frozen first-move cassette"
            )
        _validate_context(context)
        if not self.base_config.is_file():
            raise ArmorLiveRunnerError(
                f"base ARMS config not found: {self.base_config}"
            )
        initial_path = context.immutable_initial_memory_path.resolve()
        working_path = context.working_memory_path.resolve()
        if not initial_path.is_file() or not working_path.is_file():
            raise ArmorLiveRunnerError(
                "initial and working memory snapshots must exist"
            )
        expected_memory_hash = str(context.contract["initial_memory_sha256"])
        if sha256_file(initial_path) != expected_memory_hash:
            raise ArmorLiveRunnerError("immutable initial memory hash mismatch")
        working_start_hash = sha256_file(working_path)
        if working_start_hash != expected_memory_hash:
            raise ArmorLiveRunnerError(
                "working memory did not start from frozen snapshot"
            )

        manager = (
            nullcontext(self.bindings)
            if self.bindings is not None
            else _load_default_bindings(self.arena_config)
        )
        with manager as bindings:
            assert bindings is not None
            cfg = bindings.load_config(self.base_config)
            _configure_runtime(cfg, context, self.target_profile)
            visual_judge = (
                None
                if prefreeze
                else _visual_judge_runtime(
                    arena_config=self.arena_config,
                    bindings=bindings,
                    required=_requires_multimodal_judge(context),
                    attacker_endpoint=getattr(cfg, "attacker", None),
                    target_profile=self.target_profile,
                    expected_provenance=context.contract.get("evaluator_provenance"),
                )
            )

            agent_root = context.output_dir.resolve() / "arms_agent"
            runtime_memory = agent_root / "memory.json"
            if runtime_memory.exists():
                if sha256_file(runtime_memory) != working_start_hash:
                    raise ArmorLiveRunnerError(
                        "stale run-local agent memory differs from working snapshot"
                    )
            else:
                _atomic_copy(working_path, runtime_memory)
            if sha256_file(runtime_memory) != working_start_hash:
                raise ArmorLiveRunnerError(
                    "run-local memory installation hash mismatch"
                )

            agent: Any | None = None
            try:
                agent = bindings.build_agent(cfg, agent_root)
                memory = getattr(agent, "memory", None)
                memory_path = getattr(memory, "path", None)
                if (
                    memory_path is None
                    or Path(memory_path).resolve() != runtime_memory.resolve()
                ):
                    raise ArmorLiveRunnerError(
                        "ARMS agent memory path is not the installed run-local snapshot"
                    )
                if sha256_file(runtime_memory) != working_start_hash:
                    raise ArmorLiveRunnerError("agent build modified run-local memory")

                behavior = (
                    bindings.behavior_factory(
                        context.behavior.value, context.behavior.behavior_id
                    )
                    if bindings.behavior_factory is not None
                    else context.behavior.value
                )
                _validate_behavior(behavior, context.behavior.behavior_id)
                memory_prewarm = _prewarm_memory_embeddings(memory, behavior)

                if prefreeze:
                    # Do not retain or wrap the endpoint client: no path from
                    # the capture call reaches target HTTP.
                    agent.target = _PrefreezeCaptureTarget()
                else:
                    agent.target = SystemPromptTarget(
                        _FixedDecodingTarget(agent.target, context.decoding_config),
                        context.installed_system_prompt,
                    )
                text_judge_client = getattr(agent.judge, "client", agent.judge)
                if visual_judge is not None and (
                    visual_judge.client is agent.judge
                    or visual_judge.client is text_judge_client
                ):
                    raise ArmorLiveRunnerError(
                        "visual judge client must be independent from the text judge"
                    )
                agent.judge = ArmorJudge(
                    agent.judge,
                    vision_client=(
                        visual_judge.client if visual_judge is not None else None
                    ),
                    multimodal_message_builder=(
                        visual_judge.message_builder
                        if visual_judge is not None
                        else None
                    ),
                    media_transform_policy_sha256=(
                        visual_judge.media_transform_policy_sha256
                        if visual_judge is not None
                        else None
                    ),
                )
                effective_freeze = self.freeze_memory or prefreeze
                if effective_freeze:
                    agent.memory = _FrozenMemory(memory)

                expected_provenance = dict(context.expected_stage0_provenance)

                def provenance_hook(
                    _agent: Any, _behavior: Any, _index: int
                ) -> dict[str, Any]:
                    return {
                        "stage0_provenance": expected_provenance,
                        "live_runner": {
                            "freeze_memory": effective_freeze,
                            "prefreeze_capture": prefreeze,
                            "decoding_config_sha256": canonical_sha256(
                                dict(context.decoding_config)
                            ),
                            "initial_memory_sha256": working_start_hash,
                            "memory_prewarm": memory_prewarm.to_dict(),
                            "visual_judge": {
                                "configured": visual_judge is not None,
                                "role": (
                                    visual_judge.role
                                    if visual_judge is not None
                                    else None
                                ),
                                "protocol_version": (
                                    visual_judge.evaluator_provenance[
                                        "protocol_version"
                                    ]
                                    if visual_judge is not None
                                    else None
                                ),
                                "model_id": (
                                    visual_judge.evaluator_provenance[
                                        "visual_evaluator"
                                    ]["model_id"]
                                    if visual_judge is not None
                                    else None
                                ),
                                "model_revision": (
                                    visual_judge.evaluator_provenance[
                                        "visual_evaluator"
                                    ]["model_revision"]
                                    if visual_judge is not None
                                    else None
                                ),
                                "endpoint": (
                                    visual_judge.evaluator_provenance[
                                        "visual_evaluator"
                                    ]["endpoint"]
                                    if visual_judge is not None
                                    else None
                                ),
                                "max_side": (
                                    visual_judge.max_side
                                    if visual_judge is not None
                                    else None
                                ),
                                "media_transform_policy_sha256": (
                                    visual_judge.media_transform_policy_sha256
                                    if visual_judge is not None
                                    else None
                                ),
                                "raw_media_included": False,
                            },
                            "workers": 1,
                        },
                    }

                instrument_kwargs: dict[str, Any] = {
                    "target_call_budget": context.target_call_budget,
                    "provenance_hook": provenance_hook,
                }
                if context.frozen_first_move is not None:
                    instrument_kwargs["frozen_first_move"] = context.frozen_first_move
                instrumented = bindings.instrument_agent(agent, **instrument_kwargs)
                result = instrumented.attack(
                    behavior,
                    1,
                    context.output_dir.resolve() / "artifacts" / "00001",
                )
                row = _coerce_row(result)
                if prefreeze:
                    # Validate the no-target/no-judge proof before exposing the
                    # capture row to a manifest-preparation caller.
                    extract_prefreeze_evidence(
                        row,
                        initial_memory_sha256=expected_memory_hash,
                    )

                if sha256_file(initial_path) != expected_memory_hash:
                    raise ArmorLiveRunnerError(
                        "live run modified immutable initial memory"
                    )
                if sha256_file(working_path) != working_start_hash:
                    raise ArmorLiveRunnerError(
                        "working memory changed outside the isolated agent path"
                    )
                runtime_final_hash = sha256_file(runtime_memory)
                if effective_freeze and runtime_final_hash != working_start_hash:
                    raise ArmorLiveRunnerError("frozen run modified its agent memory")
                _atomic_copy(runtime_memory, working_path)
                if sha256_file(working_path) != runtime_final_hash:
                    raise ArmorLiveRunnerError(
                        "atomic working-memory sync hash mismatch"
                    )
                if sha256_file(initial_path) != expected_memory_hash:
                    raise ArmorLiveRunnerError(
                        "immutable initial memory drift after sync"
                    )
                return row
            finally:
                if agent is not None:
                    tools = getattr(agent, "tools", None)
                    close = getattr(tools, "close", None)
                    if callable(close):
                        close()


def make_armor_live_run_callable(
    *,
    arena_config: ArenaConfig,
    target_profile: TargetProfile,
    base_config: str | Path | None = None,
    freeze_memory: bool = True,
    bindings: ARMsRuntimeBindings | None = None,
) -> ArmorLiveRunner:
    """Build the callable injected into :class:`Stage0LiveOrchestrator`."""

    return ArmorLiveRunner(
        arena_config=arena_config,
        target_profile=target_profile,
        base_config=base_config,
        freeze_memory=freeze_memory,
        bindings=bindings,
    )
