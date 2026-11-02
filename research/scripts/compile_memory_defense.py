#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defense_arena.memory_compiler import (
    METHOD_NAME,
    SCHEMA_VERSION,
    build_defense_atoms,
    compile_prompt_candidates,
    prompt_memory_overlap,
    sha256_file,
    verify_memory,
)


def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def _write_json(path: Path, value: object) -> None:
    _write_atomic(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def _token_counter(path: Path) -> tuple[Callable[[str], int], str]:
    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(
        str(path),
        local_files_only=True,
        trust_remote_code=True,
    )

    def count(value: str) -> int:
        return len(tokenizer.encode(value, add_special_tokens=False))

    return count, f"{type(tokenizer).__name__}:{path.resolve()}"


def _memory_admission_report(
    verification: dict[str, object],
    *,
    require_source_traces: bool,
) -> dict[str, object]:
    entries = int(verification.get("entries", 0))
    expected: dict[str, int] = {
        "verified_entries": entries,
        "outcome_flag_mismatches": 0,
        "trace_score_mismatches": 0,
        "trace_query_mismatches": 0,
        "duplicate_slots": 0,
    }
    if require_source_traces:
        expected["source_trace_matches"] = entries
    checks = {
        name: {
            "actual": int(verification.get(name, 0)),
            "expected": wanted,
            "passed": int(verification.get(name, 0)) == wanted,
        }
        for name, wanted in expected.items()
    }
    failures = [name for name, check in checks.items() if not check["passed"]]
    return {
        "passed": not failures,
        "source_traces_required": require_source_traces,
        "checks": checks,
        "failures": failures,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Compile verified ARMS attacker memory into token-budgeted, payload-free Mem2Guard-X system prompts."
        )
    )
    parser.add_argument("--memory", required=True, type=Path)
    parser.add_argument("--results", type=Path, help="Optional warm-run results.jsonl for trajectory verification.")
    parser.add_argument("--tokenizer", required=True, type=Path)
    parser.add_argument("--budgets", nargs="+", type=int, default=(64, 128, 256))
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--vmax", type=int, default=5)
    parser.add_argument(
        "--max-memory-overlap",
        type=int,
        default=8,
        help="Reject a prompt sharing more than this many consecutive normalized words with raw memory.",
    )
    args = parser.parse_args()

    memory = args.memory.expanduser().resolve()
    results = args.results.expanduser().resolve() if args.results else None
    tokenizer = args.tokenizer.expanduser().resolve()
    output = args.out.expanduser().resolve()
    for required in (memory, tokenizer):
        if not required.exists():
            parser.error(f"path not found: {required}")
    if results is not None and not results.is_file():
        parser.error(f"results not found: {results}")

    verified, verification = verify_memory(memory, results_path=results, vmax=args.vmax)
    admission = _memory_admission_report(
        verification,
        require_source_traces=results is not None,
    )
    verification["admission_gate"] = admission
    if not admission["passed"]:
        checks = admission["checks"]
        raise SystemExit(
            "memory admission gate failed: "
            + ", ".join(
                f"{name}={checks[name]['actual']} (expected {checks[name]['expected']})"
                for name in admission["failures"]
            )
        )
    atoms = build_defense_atoms(verified)
    count_tokens, counter_name = _token_counter(tokenizer)
    candidates = compile_prompt_candidates(
        atoms,
        budgets=args.budgets,
        count_tokens=count_tokens,
        token_counter_name=counter_name,
        memory_semantic_hash=verification["memory_semantic_sha256"],
    )
    overlap = {
        str(candidate.budget): prompt_memory_overlap(memory, candidate.text)
        for candidate in candidates
    }
    failures = {
        budget: report
        for budget, report in overlap.items()
        if int(report["longest_consecutive_word_overlap"]) > args.max_memory_overlap
    }
    if failures:
        raise SystemExit(
            "raw-memory overlap gate failed: "
            + ", ".join(
                f"B{budget}={report['longest_consecutive_word_overlap']}"
                for budget, report in failures.items()
            )
        )

    output.mkdir(parents=True, exist_ok=True)
    _write_json(output / "verified_memory_report.json", verification)
    _write_json(output / "defense_atoms.json", [atom.to_dict() for atom in atoms])
    for candidate in candidates:
        _write_atomic(output / f"prompt-B{candidate.budget}.txt", candidate.text + "\n")

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "method": METHOD_NAME,
        "created_at": datetime.now(timezone.utc).isoformat(),  # noqa: UP017
        "memory_path": str(memory),
        "memory_sha256": sha256_file(memory),
        "memory_semantic_sha256": verification["memory_semantic_sha256"],
        "source_results_path": str(results) if results else None,
        "source_results_sha256": sha256_file(results) if results else None,
        "tokenizer": str(tokenizer),
        "token_counter": counter_name,
        "budgets": [candidate.to_dict() for candidate in candidates],
        "overlap_gate": {
            "maximum_allowed_consecutive_words": args.max_memory_overlap,
            "reports": overlap,
        },
        "deployment_contract": {
            "target_weights_frozen": True,
            "raw_behavior_copied": False,
            "raw_reflection_copied": False,
            "raw_steps_copied": False,
            "system_prompt_only": True,
            "public_explanation": "high-level boundary only",
            "private_provenance": "defense_atoms.json evidence_ids",
        },
    }
    _write_json(output / "compiler_manifest.json", manifest)
    print(json.dumps(manifest, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
