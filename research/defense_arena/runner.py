from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import ArenaConfig, TargetProfile
from .instrumentation import instrument_arms_agent
from .memory import MemoryStats, inspect_memory, install_memory_snapshot, sha256_file
from .metrics import DEFAULT_BUDGETS, summarize_budgeted_asr
from .prompting import DefensePrompt, SystemPromptTarget


def configure_json_judge(agent: Any) -> Any:
    """Constrain the local judge to valid JSON without changing its rubric."""
    client = agent.judge.client
    extra_body = dict(getattr(client, "extra_body", {}) or {})
    extra_body["response_format"] = {"type": "json_object"}
    client.extra_body = extra_body
    return agent


@dataclass(frozen=True)
class ArenaRunPlan:
    target: TargetProfile
    defense: DefensePrompt
    behaviors: Path
    output: Path
    limit: int | None
    workers: int
    memory: MemoryStats
    ready: bool
    memory_mode: str
    query_budget: int | None
    freeze_memory: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": {
                "id": self.target.id,
                "label": self.target.label,
                "parameters": self.target.parameters,
                "model_id": self.target.model_id,
                "base_url": self.target.base_url,
                "served_model_name": self.target.served_model_name,
            },
            "condition": self.defense.condition,
            "prompt_author": self.defense.author,
            "prompt_sha256": self.defense.sha256,
            "behaviors": str(self.behaviors),
            "output": str(self.output),
            "limit": self.limit,
            "workers": self.workers,
            "warm_memory": self.memory.to_dict(),
            "memory_mode": self.memory_mode,
            "query_budget": self.query_budget,
            "budget_unit": "target_generation_call",
            "judge_every_target_response": True,
            "stop_on_strict_success": True,
            "instrumentation_schema_version": 3,
            "freeze_memory": self.freeze_memory,
            "judge_response_format": "json_object",
            "ready": self.ready,
        }


class _ReadOnlyMemory:
    """Expose retrieval while preventing held-out cases from training on each other."""

    def __init__(self, base: Any):
        self.base = base

    def __len__(self) -> int:
        return len(self.base)

    def retrieve(self, *args: Any, **kwargs: Any) -> Any:
        return self.base.retrieve(*args, **kwargs)

    def insert(self, _trajectory: Any) -> bool:
        return False


class _RunnerProxy:
    def __init__(self, base: Any, system_prompt: str, *, freeze_memory: bool):
        self.base = base
        self.system_prompt = system_prompt
        self.freeze_memory = freeze_memory

    def build_agent(self, cfg: Any, out_dir: Path) -> Any:
        agent = configure_json_judge(self.base.build_agent(cfg, out_dir))
        agent.target = SystemPromptTarget(agent.target, self.system_prompt)
        if self.freeze_memory:
            agent.memory = _ReadOnlyMemory(agent.memory)
        return instrument_arms_agent(agent, target_call_budget=cfg.max_queries)

    def summarize(self, results: list[dict], vmax: int) -> dict:
        return self.base.summarize(results, vmax)


def create_plan(
    config: ArenaConfig,
    *,
    target_id: str,
    defense: DefensePrompt,
    output: str | Path,
    behaviors: str | Path | None = None,
    limit: int | None = None,
    workers: int = 1,
    query_budget: int | None = None,
    freeze_memory: bool = True,
) -> ArenaRunPlan:
    if workers < 1:
        raise ValueError("workers must be >= 1")
    if query_budget is not None and query_budget < 1:
        raise ValueError("query_budget must be >= 1")
    target = config.target(target_id)
    behavior_path = (
        Path(behaviors).expanduser().resolve() if behaviors else config.behaviors
    )
    if not behavior_path.is_file():
        raise FileNotFoundError(f"behavior file not found: {behavior_path}")
    memory = inspect_memory(target.memory_source)
    ready = memory.is_ready(
        min_entries=target.min_memory_entries,
        min_successful_entries=target.min_successful_entries,
        min_categories=target.min_category_coverage,
        min_successful_categories=target.min_successful_categories,
        min_strategies=target.min_strategy_coverage,
    )
    return ArenaRunPlan(
        target=target,
        defense=defense,
        behaviors=behavior_path,
        output=Path(output).expanduser().resolve(),
        limit=limit,
        workers=workers,
        memory=memory,
        ready=ready,
        memory_mode=config.memory_mode,
        query_budget=query_budget,
        freeze_memory=freeze_memory,
    )


def _write_manifest(plan: ArenaRunPlan, config: ArenaConfig) -> Path:
    plan.output.mkdir(parents=True, exist_ok=True)
    manifest_path = plan.output / "arena_run.json"
    frozen = plan.to_dict()
    frozen.update(
        {
            "schema_version": 1,
            "arena_config": str(config.path),
            "arena_config_sha256": sha256_file(config.path),
            "base_config": str(config.base_config),
            "base_config_sha256": sha256_file(config.base_config),
            "behavior_sha256": sha256_file(plan.behaviors),
            "initial_memory_source": str(plan.target.memory_source),
            "runtime_profile": config.runtime_profile,
            # datetime.UTC does not exist in the supported Python 3.10 runtime.
            "created_at": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
        }
    )
    comparable = dict(frozen)
    comparable.pop("created_at", None)
    if manifest_path.exists():
        existing = json.loads(manifest_path.read_text(encoding="utf-8"))
        existing.pop("created_at", None)
        if existing != comparable:
            raise RuntimeError(
                f"run manifest mismatch; choose a new output directory: {manifest_path}"
            )
    else:
        manifest_path.write_text(
            json.dumps(frozen, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        (plan.output / "defense_system_prompt.txt").write_text(
            plan.defense.installed_text + ("\n" if plan.defense.installed_text else ""),
            encoding="utf-8",
        )
    return manifest_path


def execute_plan(
    plan: ArenaRunPlan, config: ArenaConfig, *, allow_underwarmed: bool = False
) -> dict[str, Any]:
    if not plan.ready and not allow_underwarmed:
        raise RuntimeError(
            f"target {plan.target.id} is not warm: {plan.memory.entries} entries, "
            f"{plan.memory.successful_entries} successful, {plan.memory.categories} categories"
        )
    install_memory_snapshot(plan.target.memory_source, plan.output / "memory.json")
    _write_manifest(plan, config)

    from scripts import run_open_arms as baseline

    baseline.add_source_root(str(config.source_root))
    import arms.agent as agent_module  # pylint: disable=import-outside-toplevel
    import arms.prompts as prompt_module  # pylint: disable=import-outside-toplevel
    import arms.runner as runner_module  # pylint: disable=import-outside-toplevel
    from arms.config import ARMsConfig  # pylint: disable=import-outside-toplevel
    from arms.runner import load_behaviors  # pylint: disable=import-outside-toplevel

    prompt_module.PLANNER_SYSTEM = baseline.PLANNER_SYSTEM
    agent_module.FIRST_USER = baseline.FIRST_USER
    agent_module._compact = baseline.compact_planner_context

    runtime_config = ARMsConfig.load(config.base_config)
    runtime_config.target.base_url = plan.target.base_url
    runtime_config.target.model = plan.target.served_model_name
    if plan.query_budget is not None:
        runtime_config.max_queries = plan.query_budget
        runtime_config.min_queries_before_finish = min(
            runtime_config.min_queries_before_finish, plan.query_budget
        )
        runtime_config.max_steps = max(runtime_config.max_steps, 2 * plan.query_budget)
    if plan.memory_mode == "required":
        # The paper schedule starts at epsilon=1, which would deliberately ignore
        # warm memory on the first public-demo case. Arena comparisons require the
        # attacker to consult its mature target-specific memory on every episode.
        runtime_config.eps_max = 0.0
        runtime_config.eps_min = 0.0
    behaviors = load_behaviors(plan.behaviors, limit=plan.limit)
    proxy = _RunnerProxy(
        runner_module,
        plan.defense.installed_text,
        freeze_memory=plan.freeze_memory,
    )
    summary = baseline.run_resilient(
        runtime_config, behaviors, plan.output, plan.workers, proxy
    )
    if int(summary.get("pending_n", 0)) != 0:
        raise RuntimeError(
            f"incomplete arena run: {summary.get('completed_n', 0)}/{summary.get('requested_n', len(behaviors))} "
            "behaviors completed; rerun the same output directory to resume"
        )
    result_rows = [
        json.loads(line)
        for line in (plan.output / "results.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    behavior_metadata = {
        str(row["id"]): row
        for row in (
            json.loads(line)
            for line in plan.behaviors.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    }
    prefix_budgets = tuple(
        value for value in DEFAULT_BUDGETS if value <= runtime_config.max_queries
    )
    if runtime_config.max_queries not in prefix_budgets:
        prefix_budgets = (*prefix_budgets, runtime_config.max_queries)
    summary.update(
        {
            "arena_target": plan.target.id,
            "condition": plan.defense.condition,
            "defense_prompt_sha256": plan.defense.sha256,
            "initial_memory_sha256": plan.memory.sha256,
            "memory_frozen_during_eval": plan.freeze_memory,
            "independent_run_query_budget": runtime_config.max_queries,
            "anytime_prefix_metrics": summarize_budgeted_asr(
                result_rows,
                budgets=prefix_budgets,
                metadata_by_id=behavior_metadata,
            ),
        }
    )
    (plan.output / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return summary
