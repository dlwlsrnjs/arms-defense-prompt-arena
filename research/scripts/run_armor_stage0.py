#!/usr/bin/env python3
"""Prepare or validate the metadata-only ARMS VS ARMOR Stage-0 protocol.

This command never starts model servers and never selects a GPU.  ``prepare``
only freezes run contracts; ``validate`` only reads completed result records.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defense_arena.armor_stage0 import (
    audit_results,
    load_prepared,
    load_results,
    load_spec,
    prepare,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    prepare_parser = commands.add_parser("prepare", help="freeze a Stage-0 manifest and run plan")
    prepare_parser.add_argument("--spec", required=True, type=Path)
    prepare_parser.add_argument("--out", required=True, type=Path)

    validate_parser = commands.add_parser("validate", help="validate result files against a frozen plan")
    validate_parser.add_argument("--out", required=True, type=Path)
    validate_parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="report missing results instead of failing validation",
    )
    validate_parser.add_argument(
        "--report",
        type=Path,
        help="optional JSON report path (defaults to <out>/stage0_audit.json)",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.command == "prepare":
        plan = load_spec(args.spec)
        root = prepare(plan, args.out)
        summary = {
            "output_root": str(root),
            "experiment_id": plan.manifest["experiment_id"],
            "pair_count": plan.manifest["pair_count"],
            "run_count": plan.manifest["run_count"],
            "target_call_budget": plan.manifest["target_call_budget"],
            "servers_started": False,
        }
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return 0

    plan = load_prepared(args.out)
    results = load_results(args.out, plan)
    report = audit_results(plan, results, require_complete=not args.allow_incomplete)
    report_path = args.report or (args.out / "stage0_audit.json")
    report_path = report_path.expanduser().resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["protocol_gate_pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
