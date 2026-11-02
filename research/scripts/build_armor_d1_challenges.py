"""Freeze the outcome-blind D1 cohort without contacting model endpoints."""

from __future__ import annotations

import argparse
import json

from defense_arena.armor_challenge_preflight import (
    build_d1_challenge_cohort,
    write_d1_challenge_cohort,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--benchmark-manifest", required=True)
    parser.add_argument("--memory", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--category", action="append", required=True)
    parser.add_argument("--per-category", type=int, default=2)
    parser.add_argument("--seed", type=int, default=20261101)
    parser.add_argument("--target-call-budget", type=int, default=4)
    parser.add_argument("--exclude-behaviors", action="append", default=[])
    args = parser.parse_args()

    selected, manifest = build_d1_challenge_cohort(
        args.dataset,
        benchmark_manifest_path=args.benchmark_manifest,
        memory_path=args.memory,
        category_allowlist=args.category,
        per_category=args.per_category,
        seed=args.seed,
        exclude_behavior_paths=args.exclude_behaviors,
        target_call_budget=args.target_call_budget,
    )
    finalized = write_d1_challenge_cohort(args.output, selected, manifest)
    print(
        json.dumps(
            {
                "protocol": finalized["protocol"],
                "stage": finalized["stage"],
                "selected": len(finalized["pairs"]),
                "categories": finalized["selection_policy"]["category_allowlist"],
                "execution_eligible": finalized["execution_eligible"],
                "manifest_sha256": finalized["manifest_sha256"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
