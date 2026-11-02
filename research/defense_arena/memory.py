from __future__ import annotations

import hashlib
import json
import os
import shutil
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class MemoryStats:
    exists: bool
    entries: int = 0
    successful_entries: int = 0
    categories: int = 0
    strategies: int = 0
    successful_categories: int = 0
    successful_strategies: int = 0
    mean_best_score: float = 0.0
    sha256: str | None = None

    def is_ready(
        self,
        *,
        min_entries: int,
        min_successful_entries: int,
        min_categories: int,
        min_successful_categories: int = 0,
        min_strategies: int = 0,
    ) -> bool:
        return (
            self.exists
            and self.entries >= min_entries
            and self.successful_entries >= min_successful_entries
            and self.categories >= min_categories
            and self.successful_categories >= min_successful_categories
            and self.strategies >= min_strategies
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def inspect_memory(path: str | Path) -> MemoryStats:
    memory_path = Path(path)
    if not memory_path.is_file():
        return MemoryStats(exists=False)
    raw = json.loads(memory_path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise TypeError(f"ARMS memory must be a JSON list: {memory_path}")
    if not raw:
        return MemoryStats(exists=True, sha256=sha256_file(memory_path))
    required = {"risk_category", "strategy", "best_score"}
    for index, row in enumerate(raw):
        if not isinstance(row, dict) or not required.issubset(row):
            raise ValueError(f"invalid ARMS memory entry {index} in {memory_path}")
    successful_rows = [
        row for row in raw if bool(row.get("success")) or int(row.get("best_score", 0)) >= 5
    ]
    return MemoryStats(
        exists=True,
        entries=len(raw),
        successful_entries=len(successful_rows),
        categories=len({str(row["risk_category"]) for row in raw}),
        strategies=len({str(row["strategy"]) for row in raw}),
        successful_categories=len({str(row["risk_category"]) for row in successful_rows}),
        successful_strategies=len({str(row["strategy"]) for row in successful_rows}),
        mean_best_score=sum(float(row["best_score"]) for row in raw) / len(raw),
        sha256=sha256_file(memory_path),
    )


def install_memory_snapshot(source: str | Path, destination: str | Path) -> MemoryStats:
    source_path, destination_path = Path(source), Path(destination)
    source_stats = inspect_memory(source_path)
    if not source_stats.exists:
        raise FileNotFoundError(f"warm ARMS memory not found: {source_path}")
    if destination_path.exists():
        return inspect_memory(destination_path)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination_path.with_name(f".{destination_path.name}.{os.getpid()}.tmp")
    shutil.copyfile(source_path, temporary)
    os.replace(temporary, destination_path)
    installed = inspect_memory(destination_path)
    if installed.sha256 != source_stats.sha256:
        raise RuntimeError("installed ARMS memory hash does not match the source snapshot")
    return installed


def merge_memory_snapshots(sources: Iterable[str | Path], destination: str | Path) -> MemoryStats:
    """Merge immutable seed memories by keeping the strongest trajectory per ARMS slot."""
    source_paths = [Path(path) for path in sources]
    if not source_paths:
        raise ValueError("at least one memory source is required")
    best: dict[tuple[str, str], dict[str, Any]] = {}
    for source_path in source_paths:
        stats = inspect_memory(source_path)
        if not stats.exists:
            raise FileNotFoundError(f"ARMS memory not found: {source_path}")
        rows = json.loads(source_path.read_text(encoding="utf-8"))
        for row in rows:
            key = (str(row["risk_category"]), str(row["strategy"]))
            current = best.get(key)
            candidate_rank = (
                int(row.get("best_score", 0)),
                int(bool(row.get("success"))),
                -int(row.get("queries", 10**9)),
            )
            current_rank = (
                int(current.get("best_score", 0)),
                int(bool(current.get("success"))),
                -int(current.get("queries", 10**9)),
            ) if current else None
            if current is None or candidate_rank > current_rank:
                best[key] = row
    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination_path.with_name(f".{destination_path.name}.{os.getpid()}.tmp")
    ordered = [best[key] for key in sorted(best)]
    temporary.write_text(json.dumps(ordered, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    os.replace(temporary, destination_path)
    return inspect_memory(destination_path)
