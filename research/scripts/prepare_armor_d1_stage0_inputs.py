#!/usr/bin/env python3
"""Freeze metadata-only D1 Stage-0 binding and evaluator inputs.

This command performs no endpoint calls, process lifecycle operations, or GPU
allocation.  It upgrades consolidated prefreeze evidence to the hashes of the
independently reviewed execution-ready challenge manifest.
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

from defense_arena.armor_d1_stage0_spec import freeze_d1_prefreeze_binding
from defense_arena.armor_stage0 import canonical_sha256, freeze_evaluator_provenance
from defense_arena.config import ArenaConfig


class InputPreparationError(ValueError):
    """Raised when frozen sources do not describe one exact D1 cohort."""


def _object(path: Path, label: str) -> dict[str, Any]:
    source = path.expanduser().resolve()
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InputPreparationError(f"invalid {label}: {source}") from exc
    if not isinstance(value, Mapping):
        raise InputPreparationError(f"{label} must be a JSON object: {source}")
    return dict(value)


def _write_atomic(path: Path, value: Mapping[str, Any]) -> Path:
    destination = path.expanduser().resolve()
    if destination.exists():
        if _object(destination, "existing output") != value:
            raise InputPreparationError(
                f"refusing to replace different frozen output: {destination}"
            )
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
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
    return destination


def _evaluator_provenance(
    *, arena_config: Path, base_config: Path | None, target_id: str
) -> dict[str, Any]:
    arena = ArenaConfig.load(arena_config)
    target = arena.target(target_id)
    base_path = (base_config or arena.base_config).expanduser()
    if not base_path.is_absolute():
        base_path = arena.project_root / base_path
    raw = yaml.safe_load(base_path.resolve().read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping) or not isinstance(raw.get("attacker"), Mapping):
        raise InputPreparationError("base config must contain an attacker mapping")
    visual = arena.runtime_profile.get("visual_judge")
    if not isinstance(visual, Mapping):
        raise InputPreparationError(
            "arena runtime_profile must contain a visual_judge mapping"
        )
    attacker = raw["attacker"]
    return freeze_evaluator_provenance(
        attacker_base_url=attacker.get("base_url"),
        attacker_served_model_name=attacker.get("model"),
        evaluated_target_base_url=target.base_url,
        evaluated_target_served_model_name=target.served_model_name,
        visual_evaluator=visual,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--challenge-manifest", required=True, type=Path)
    parser.add_argument("--prefreeze-attestation", required=True, type=Path)
    parser.add_argument("--arena-config", required=True, type=Path)
    parser.add_argument("--base-config", type=Path)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--out", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    challenge = _object(args.challenge_manifest, "challenge manifest")
    attestation = _object(args.prefreeze_attestation, "prefreeze attestation")
    manifest_sha256 = str(challenge.get("manifest_sha256", ""))
    unhashed = dict(challenge)
    unhashed.pop("manifest_sha256", None)
    if canonical_sha256(unhashed) != manifest_sha256:
        raise InputPreparationError("challenge manifest self-hash mismatch")
    if challenge.get("execution_eligible") is not True:
        raise InputPreparationError("challenge manifest is not execution eligible")
    challenge_pairs = challenge.get("pairs")
    attested_pairs = attestation.get("pairs")
    if not isinstance(challenge_pairs, list) or len(challenge_pairs) != 16:
        raise InputPreparationError("challenge manifest must contain 16 pairs")
    if not isinstance(attested_pairs, list) or len(attested_pairs) != 16:
        raise InputPreparationError("prefreeze attestation must contain 16 pairs")
    attested_by_pair = {
        str(row.get("pair_id", "")): row
        for row in attested_pairs
        if isinstance(row, Mapping)
    }
    if len(attested_by_pair) != 16:
        raise InputPreparationError("prefreeze attestation pair ids are not unique")

    output_root = args.out.expanduser().resolve()
    binding_paths: list[Path] = []
    for order, entry_value in enumerate(challenge_pairs, start=1):
        if not isinstance(entry_value, Mapping):
            raise InputPreparationError("challenge pair must be an object")
        entry = dict(entry_value)
        pair_id = str(entry.get("pair_id", ""))
        try:
            attested = attested_by_pair[pair_id]
        except KeyError as exc:
            raise InputPreparationError(f"missing prefreeze pair: {pair_id}") from exc
        if attested.get("behavior_id") != entry.get("behavior_id"):
            raise InputPreparationError(f"behavior mismatch: {pair_id}")
        cassette = entry.get("first_move_cassette")
        if not isinstance(cassette, Mapping):
            raise InputPreparationError(f"missing cassette attestation: {pair_id}")
        cassette_sha256 = str(cassette.get("cassette_sha256", ""))
        if attested.get("first_move_cassette_sha256") != cassette_sha256:
            raise InputPreparationError(f"cassette mismatch: {pair_id}")
        wrapper = _object(
            Path(str(attested.get("prefreeze_wrapper_path", ""))),
            f"prefreeze wrapper for {pair_id}",
        )
        if canonical_sha256(wrapper) != attested.get(
            "prefreeze_wrapper_canonical_sha256"
        ):
            raise InputPreparationError(f"wrapper hash mismatch: {pair_id}")
        binding = freeze_d1_prefreeze_binding(
            prefreeze_wrapper=wrapper,
            challenge_manifest_sha256=manifest_sha256,
            challenge_entry_sha256=str(entry.get("challenge_entry_sha256", "")),
            first_move_cassette_sha256=cassette_sha256,
        )
        binding_paths.append(
            _write_atomic(
                output_root / "bindings" / f"{order:02d}-{pair_id}.json", binding
            )
        )

    evaluator = _evaluator_provenance(
        arena_config=args.arena_config,
        base_config=args.base_config,
        target_id=args.target_id,
    )
    evaluator_path = _write_atomic(output_root / "evaluator_provenance.json", evaluator)
    summary = {
        "status": "ready",
        "challenge_manifest_sha256": manifest_sha256,
        "binding_count": len(binding_paths),
        "binding_paths": [str(path) for path in binding_paths],
        "evaluator_provenance_path": str(evaluator_path),
        "evaluator_protocol_version": evaluator["protocol_version"],
        "raw_attack_or_response_text_included": False,
        "model_calls_started": False,
        "servers_started": False,
        "gpu_allocation_performed": False,
    }
    _write_atomic(output_root / "input_manifest.json", summary)
    print(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
