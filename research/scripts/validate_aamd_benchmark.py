#!/usr/bin/env python3
"""Validate the offline AAMD-v1 benchmark and human-workspace contract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defense_arena.aamd_benchmark import validate_benchmark_file
from defense_arena.adaptive_attack_memory_dataset import DatasetValidationError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=PROJECT_ROOT / "configs" / "aamd_benchmark_v1.json",
        help="AAMD-v1 benchmark config",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = validate_benchmark_file(args.config)
    except DatasetValidationError as exc:
        print(f"AAMD benchmark validation failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
