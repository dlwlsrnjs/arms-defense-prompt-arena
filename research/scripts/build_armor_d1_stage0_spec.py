"""Build or validate a native-only sixteen-pair ARMOR D1 Stage-0 spec.

This command only reads frozen artifacts and writes metadata.  It contains no
model, endpoint, server, process, or GPU lifecycle operations.
"""

from __future__ import annotations

import argparse
import json
import stat
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defense_arena.armor_d1_stage0_spec import (
    D1Stage0SpecBuildError,
    build_d1_stage0_spec,
    write_d1_stage0_spec,
)
from defense_arena.armor_stage0 import ARM_IDS, build_plan


def _json_object(path: Path, label: str) -> dict[str, Any]:
    source = path.expanduser().resolve()
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise D1Stage0SpecBuildError(f"invalid {label} JSON: {source}") from exc
    if not isinstance(value, Mapping):
        raise D1Stage0SpecBuildError(f"{label} must contain a JSON object: {source}")
    return dict(value)


def _private_cassette_bundle(path: Path) -> dict[str, Any]:
    source = path.expanduser()
    if source.is_symlink():
        raise D1Stage0SpecBuildError(
            "private cassette bundle must not be a symbolic link"
        )
    resolved = source.resolve()
    try:
        mode = stat.S_IMODE(resolved.stat().st_mode)
    except OSError as exc:
        raise D1Stage0SpecBuildError(
            f"private cassette bundle not found: {resolved}"
        ) from exc
    if mode != 0o600:
        raise D1Stage0SpecBuildError("private cassette bundle must have mode 0600")
    return _json_object(resolved, "private cassette bundle")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--challenge-manifest", type=Path, required=True)
    parser.add_argument(
        "--prefreeze-record",
        type=Path,
        action="append",
        required=True,
        help="One metadata-only binding record; provide exactly sixteen.",
    )
    parser.add_argument("--cassette-bundle", type=Path, required=True)
    parser.add_argument("--template-spec", type=Path, required=True)
    parser.add_argument(
        "--evaluator-provenance",
        type=Path,
        help=(
            "Explicit current evaluator provenance. Required when the template "
            "contains stale v3 provenance."
        ),
    )
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument(
        "--out",
        type=Path,
        help="Destination JSON. Required unless --validate-only is used.",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate and print a metadata-only summary without writing.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.validate_only and args.out is None:
        raise SystemExit("--out is required unless --validate-only is used")
    if len(args.prefreeze_record) != 16:
        raise SystemExit("exactly sixteen --prefreeze-record values are required")

    challenge_manifest = _json_object(args.challenge_manifest, "challenge manifest")
    records = [
        _json_object(path, f"prefreeze record {index}")
        for index, path in enumerate(args.prefreeze_record, start=1)
    ]
    cassette_bundle = _private_cassette_bundle(args.cassette_bundle)
    template_spec = _json_object(args.template_spec, "four-arm template spec")
    evaluator_provenance = (
        None
        if args.evaluator_provenance is None
        else _json_object(args.evaluator_provenance, "evaluator provenance")
    )
    spec = build_d1_stage0_spec(
        challenge_manifest=challenge_manifest,
        prefreeze_records=records,
        cassette_bundle=cassette_bundle,
        template_spec=template_spec,
        evaluator_provenance=evaluator_provenance,
        experiment_id=args.experiment_id,
    )
    plan = build_plan(spec)
    output: Path | None = None
    if not args.validate_only:
        assert args.out is not None
        output = write_d1_stage0_spec(args.out, spec)

    summary = {
        "status": "valid",
        "written": output is not None,
        "output": str(output) if output is not None else None,
        "experiment_id": plan.manifest["experiment_id"],
        "pair_count": plan.manifest["pair_count"],
        "run_count": plan.manifest["run_count"],
        "active_arms": plan.manifest["active_arms"],
        "expected_native_arm": ARM_IDS[0],
        "challenge_manifest_sha256": plan.manifest["challenge_manifest_sha256"],
        "source_spec_sha256": plan.manifest["source_spec_sha256"],
        "evaluator_protocol_version": plan.manifest["evaluator_provenance"][
            "protocol_version"
        ],
        "prefreeze_spec_bytes_verified": False,
        "raw_attack_or_response_text_included": False,
        "model_calls_started": False,
        "servers_started": False,
        "gpu_allocation_performed": False,
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
