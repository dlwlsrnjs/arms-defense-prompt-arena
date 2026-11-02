from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


def _resolve(root: Path, value: str) -> Path:
    path = Path(value).expanduser()
    return path if path.is_absolute() else (root / path).resolve()


@dataclass(frozen=True)
class TargetProfile:
    id: str
    label: str
    parameters: str
    model_id: str
    base_url: str
    served_model_name: str
    memory_source: Path
    min_memory_entries: int
    min_successful_entries: int
    min_category_coverage: int
    min_successful_categories: int = 0
    min_strategy_coverage: int = 0
    checkpoint: Path | None = None
    checkpoint_revision: str | None = None
    baseline_summary: Path | None = None

    @classmethod
    def from_mapping(cls, target_id: str, raw: dict[str, Any], root: Path) -> TargetProfile:
        required = {
            "label",
            "parameters",
            "model_id",
            "base_url",
            "served_model_name",
            "memory_source",
            "min_memory_entries",
            "min_successful_entries",
            "min_category_coverage",
        }
        missing = sorted(required - set(raw))
        if missing:
            raise ValueError(f"target {target_id!r} is missing fields: {missing}")
        checkpoint = raw.get("checkpoint")
        baseline_summary = raw.get("baseline_summary")
        return cls(
            id=target_id,
            label=str(raw["label"]),
            parameters=str(raw["parameters"]),
            model_id=str(raw["model_id"]),
            base_url=str(raw["base_url"]),
            served_model_name=str(raw["served_model_name"]),
            memory_source=_resolve(root, str(raw["memory_source"])),
            min_memory_entries=int(raw["min_memory_entries"]),
            min_successful_entries=int(raw["min_successful_entries"]),
            min_category_coverage=int(raw["min_category_coverage"]),
            min_successful_categories=int(raw.get("min_successful_categories", 0)),
            min_strategy_coverage=int(raw.get("min_strategy_coverage", 0)),
            checkpoint=_resolve(root, str(checkpoint)) if checkpoint else None,
            checkpoint_revision=str(raw["checkpoint_revision"]) if raw.get("checkpoint_revision") else None,
            baseline_summary=_resolve(root, str(baseline_summary)) if baseline_summary else None,
        )


@dataclass(frozen=True)
class ArenaConfig:
    path: Path
    project_root: Path
    source_root: Path
    base_config: Path
    behaviors: Path
    memory_mode: str
    targets: dict[str, TargetProfile]
    warm_gate: dict[str, Any]
    runtime_profile: dict[str, Any]

    @classmethod
    def load(cls, path: str | Path) -> ArenaConfig:
        config_path = Path(path).expanduser().resolve()
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise TypeError("arena config must be a YAML mapping")
        project_root = _resolve(config_path.parent, str(raw.get("project_root", "..")))
        targets_raw = raw.get("targets")
        if not isinstance(targets_raw, dict) or not targets_raw:
            raise ValueError("arena config must define at least one target")
        targets = {
            str(target_id): TargetProfile.from_mapping(str(target_id), values, project_root)
            for target_id, values in targets_raw.items()
        }
        memory_mode = str(raw.get("memory_mode", "required"))
        if memory_mode not in {"required", "epsilon_greedy"}:
            raise ValueError("memory_mode must be required or epsilon_greedy")
        warm_gate = raw.get("warm_gate") or {}
        if not isinstance(warm_gate, dict):
            raise TypeError("warm_gate must be a mapping")
        runtime_profile = raw.get("runtime_profile") or {}
        if not isinstance(runtime_profile, dict):
            raise TypeError("runtime_profile must be a mapping")
        return cls(
            path=config_path,
            project_root=project_root,
            source_root=_resolve(project_root, str(raw["source_root"])),
            base_config=_resolve(project_root, str(raw["base_config"])),
            behaviors=_resolve(project_root, str(raw["behaviors"])),
            memory_mode=memory_mode,
            targets=targets,
            warm_gate={str(key): value for key, value in warm_gate.items()},
            runtime_profile={str(key): value for key, value in runtime_profile.items()},
        )

    def target(self, target_id: str) -> TargetProfile:
        try:
            return self.targets[target_id]
        except KeyError as exc:
            raise KeyError(f"unknown target {target_id!r}; choose from {sorted(self.targets)}") from exc
