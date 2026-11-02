#!/usr/bin/env python3
"""Prepare or finalize an offline D1 first-move prefreeze batch.

``prepare`` writes sixteen argv entries but does not execute them.  Each entry
uses the existing capture-only prefreeze command and therefore expects the
configured attacker endpoint to be running already.  ``finalize`` validates
one plan's resulting files.  ``consolidate`` selects the earliest valid result
per pair across compatible plans and creates the same private cassette/asset
bundle.  No command manages model servers or accelerator resources.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defense_arena.armor_prefreeze_batch import (
    DEFAULT_DECODING_CONFIG,
    PrefreezeBatchError,
    consolidate_prefreeze_batches,
    finalize_prefreeze_batch,
    prepare_prefreeze_batch,
)


def _decoding_config(path: Path | None) -> Mapping[str, Any]:
    if path is None:
        return DEFAULT_DECODING_CONFIG
    resolved = path.expanduser().resolve()
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PrefreezeBatchError(f"invalid decoding config JSON: {resolved}") from exc
    if not isinstance(value, Mapping) or not value:
        raise PrefreezeBatchError("decoding config must be a non-empty object")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser("prepare")
    prepare.add_argument("--challenge-manifest", required=True, type=Path)
    prepare.add_argument("--selected-behaviors", required=True, type=Path)
    prepare.add_argument("--arena-config", required=True, type=Path)
    prepare.add_argument("--base-config", required=True, type=Path)
    prepare.add_argument("--target-id", required=True)
    prepare.add_argument("--memory", required=True, type=Path)
    prepare.add_argument("--output-dir", required=True, type=Path)
    prepare.add_argument("--decoding-config", type=Path)
    prepare.add_argument(
        "--runner",
        type=Path,
        default=PROJECT_ROOT / "scripts" / "run_armor_live_stage0.py",
    )
    prepare.add_argument("--python-executable", type=Path)

    finalize = commands.add_parser("finalize")
    finalize.add_argument("--plan", required=True, type=Path)
    finalize.add_argument("--output-dir", required=True, type=Path)

    consolidate = commands.add_parser("consolidate")
    consolidate.add_argument(
        "--plan",
        required=True,
        action="append",
        type=Path,
        help="private batch plan in deterministic attempt order; repeat as needed",
    )
    consolidate.add_argument("--output-dir", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare_prefreeze_batch(
                challenge_manifest_path=args.challenge_manifest,
                selected_behaviors_path=args.selected_behaviors,
                arena_config_path=args.arena_config,
                base_config_path=args.base_config,
                target_id=args.target_id,
                memory_path=args.memory,
                output_dir=args.output_dir,
                decoding_config=_decoding_config(args.decoding_config),
                runner_path=args.runner,
                python_executable=args.python_executable,
            )
        elif args.command == "finalize":
            result = finalize_prefreeze_batch(
                plan_path=args.plan,
                output_dir=args.output_dir,
            )
        else:
            result = consolidate_prefreeze_batches(
                plan_paths=args.plan,
                output_dir=args.output_dir,
            )
    except (OSError, PrefreezeBatchError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
