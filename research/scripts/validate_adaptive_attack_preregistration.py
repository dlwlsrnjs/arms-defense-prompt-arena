#!/usr/bin/env python3
"""Validate the payload-free adaptive-attack preregistration bundle."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defense_arena.adaptive_attack_preregistration import (
    PreregistrationValidationError,
    validate_bundle,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--attack-universe",
        type=Path,
        default=PROJECT_ROOT / "configs" / "adaptive_attack_universe_v1.json",
    )
    parser.add_argument(
        "--behavior-registry",
        type=Path,
        default=PROJECT_ROOT / "configs" / "behavior_registry_v1.json",
    )
    parser.add_argument(
        "--behavior-schema",
        type=Path,
        default=PROJECT_ROOT / "schemas" / "behavior-registry-v1.schema.json",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        summary = validate_bundle(
            args.attack_universe,
            args.behavior_registry,
            args.behavior_schema,
        )
    except PreregistrationValidationError as exc:
        print(f"preregistration validation failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
