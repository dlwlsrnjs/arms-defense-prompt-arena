"""Build or validate a metadata-only, one-pair ARMOR Stage-0 spec.

This command performs no model calls and contains no GPU or server lifecycle
code. The two compiler manifests are passed explicitly so provenance is bound
to their exact file bytes rather than to paths copied from another manifest.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defense_arena.armor_stage0 import (
    ARM_IDS,
    build_plan,
    freeze_evaluator_provenance,
)
from defense_arena.armor_stage0_spec import build_one_pair_stage0_spec
from defense_arena.config import ArenaConfig


def _json_object(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = path.expanduser().resolve().read_bytes()
    value = json.loads(raw)
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must contain a JSON object: {path}")
    return dict(value), raw


def _write_atomic(path: Path, value: Mapping[str, Any]) -> None:
    destination = path.expanduser().resolve()
    if destination.exists():
        existing = json.loads(destination.read_text(encoding="utf-8"))
        if existing != value:
            raise RuntimeError(f"refusing to replace a different frozen spec: {destination}")
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefreeze-wrapper", type=Path, required=True)
    parser.add_argument("--prefreeze-spec", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--matched-compiler", type=Path, required=True)
    parser.add_argument("--shuffled-compiler", type=Path, required=True)
    parser.add_argument("--arena-config", type=Path, required=True)
    parser.add_argument("--base-config", type=Path)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--target-call-budget", type=int, required=True)
    parser.add_argument("--randomization-seed", type=int, required=True)
    parser.add_argument("--max-censoring-rate", type=float, default=0.01)
    parser.add_argument(
        "--out",
        type=Path,
        help="Destination JSON. Required unless --validate-only is used.",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate and print a metadata-only summary without writing a spec.",
    )
    return parser


def _frozen_evaluator(args: argparse.Namespace) -> dict[str, Any]:
    arena = ArenaConfig.load(args.arena_config)
    target = arena.target(args.target_id)
    base_path = args.base_config or arena.base_config
    base_path = base_path.expanduser()
    if not base_path.is_absolute():
        base_path = arena.project_root / base_path
    base_raw = yaml.safe_load(base_path.resolve().read_text(encoding="utf-8"))
    if not isinstance(base_raw, Mapping) or not isinstance(
        base_raw.get("attacker"), Mapping
    ):
        raise TypeError("base config must contain an attacker mapping")
    attacker = base_raw["attacker"]
    visual = arena.runtime_profile.get("visual_judge")
    if not isinstance(visual, Mapping):
        raise TypeError("arena runtime_profile must contain a visual_judge mapping")
    return freeze_evaluator_provenance(
        attacker_base_url=attacker.get("base_url"),
        attacker_served_model_name=attacker.get("model"),
        evaluated_target_base_url=target.base_url,
        evaluated_target_served_model_name=target.served_model_name,
        visual_evaluator=visual,
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.validate_only and args.out is None:
        raise SystemExit("--out is required unless --validate-only is used")

    wrapper, _wrapper_bytes = _json_object(
        args.prefreeze_wrapper, "prefreeze wrapper"
    )
    prefreeze_spec_bytes = args.prefreeze_spec.expanduser().resolve().read_bytes()
    selection, _selection_bytes = _json_object(args.selection, "selection manifest")
    matched, matched_bytes = _json_object(args.matched_compiler, "matched compiler")
    shuffled, shuffled_bytes = _json_object(
        args.shuffled_compiler, "label-shuffled compiler"
    )
    evaluator_provenance = _frozen_evaluator(args)
    spec = build_one_pair_stage0_spec(
        prefreeze_wrapper=wrapper,
        prefreeze_spec_bytes=prefreeze_spec_bytes,
        selection_manifest=selection,
        selection_root=args.selection.expanduser().resolve().parent,
        matched_compiler_manifest=matched,
        matched_compiler_bytes=matched_bytes,
        shuffled_compiler_manifest=shuffled,
        shuffled_compiler_bytes=shuffled_bytes,
        evaluator_provenance=evaluator_provenance,
        experiment_id=args.experiment_id,
        target_call_budget=args.target_call_budget,
        randomization_seed=args.randomization_seed,
        max_censoring_rate=args.max_censoring_rate,
    )
    plan = build_plan(spec)
    if not args.validate_only:
        assert args.out is not None
        _write_atomic(args.out, spec)

    arms = {row["id"]: row for row in plan.manifest["arms"]}
    summary = {
        "status": "valid",
        "written": not args.validate_only,
        "output": str(args.out.expanduser().resolve()) if args.out else None,
        "experiment_id": plan.manifest["experiment_id"],
        "pair_id": plan.manifest["pairs"][0]["pair_id"],
        "run_count": plan.manifest["run_count"],
        "prompt_token_budget": plan.manifest["prompt_token_budget"],
        "arm_prompt_token_counts": {
            arm: arms[arm]["prompt_token_count"] for arm in ARM_IDS
        },
        "source_spec_sha256": plan.manifest["source_spec_sha256"],
        "evaluator_protocol_version": evaluator_provenance["protocol_version"],
        "visual_evaluator_endpoint_identity_sha256": evaluator_provenance[
            "visual_evaluator"
        ]["endpoint"]["identity_sha256"],
        "raw_prompt_or_behavior_text_included": False,
        "model_calls_started": False,
        "servers_started": False,
        "gpu_allocation_performed": False,
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
