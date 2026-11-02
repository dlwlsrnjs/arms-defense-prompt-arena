#!/usr/bin/env python3
"""Run ARMOR Stage-0 preparation or execution against existing endpoints.

This command has no model-server or GPU lifecycle operations. ``dry-run`` only
resolves and hashes inputs. ``prefreeze`` runs the attacker/tools with a target
capture stub and writes a metadata-only pair record. ``live`` uses endpoints
already declared in the arena/base configs and writes Stage-0 results beneath
the prepared root.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from PIL import Image

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defense_arena.armor_first_move_cassette import (
    FrozenFirstMoveCassette,
    FrozenFirstMoveCassetteBundle,
    FrozenFirstMoveCassetteError,
    cassette_from_prefreeze_row,
)
from defense_arena.armor_live_runner import ArmorLiveRunner, ArmorLiveRunnerError
from defense_arena.armor_prefreeze import (
    PrefreezeValidationError,
    extract_prefreeze_evidence,
)
from defense_arena.armor_stage0 import (
    ARM_IDS,
    SHA256_EMPTY,
    canonical_sha256,
    load_prepared,
)
from defense_arena.armor_stage0_adapter import PROVENANCE_FIELDS
from defense_arena.armor_stage0_orchestrator import (
    LiveRunContext,
    ResolvedBehavior,
    ResolvedPrompt,
    Stage0LiveOrchestrator,
    Stage0OrchestrationError,
)
from defense_arena.asset_hashing import asset_file_sha256
from defense_arena.config import ArenaConfig
from defense_arena.instrumentation import (
    FALLBACK_POLICY_SHA256,
    FrozenFirstMove,
    FrozenFirstMoveImage,
)
from defense_arena.memory import sha256_file


class LiveStage0CLIError(RuntimeError):
    """Raised when explicit CLI artifacts are incomplete or inconsistent."""


SELECTOR_CONDITION_TO_ARM = {
    "native": "native_no_added_prompt",
    "generic": "generic_token_matched_prompt",
    "matched_memory": "matched_target_memory_prompt",
    "label_shuffled": "mismatched_or_label_shuffled_memory_prompt",
}


def _atomic_write_json(path: Path, value: Any, *, mode: int = 0o644) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _atomic_write_private_json(path: Path, value: Any) -> None:
    _atomic_write_json(path, value, mode=0o600)


def _load_json(path: Path, label: str) -> Any:
    resolved = path.expanduser().resolve()
    try:
        return json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LiveStage0CLIError(f"invalid {label} JSON: {resolved}") from exc


def _resolve_relative(root: Path, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise LiveStage0CLIError(f"{label} must be a non-empty path")
    path = Path(value).expanduser()
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def _load_behaviors(path: Path) -> dict[str, dict[str, Any]]:
    resolved = path.expanduser().resolve()
    rows: dict[str, dict[str, Any]] = {}
    try:
        lines = resolved.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise LiveStage0CLIError(f"behavior file not found: {resolved}") from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise LiveStage0CLIError(
                f"invalid behavior JSONL at line {line_number}"
            ) from exc
        if not isinstance(row, dict):
            raise LiveStage0CLIError(f"behavior line {line_number} must be an object")
        behavior_id = str(row.get("id", "")).strip()
        text = row.get("query", row.get("behavior", row.get("text")))
        category = row.get("risk_category")
        if not behavior_id or not isinstance(text, str) or not isinstance(category, str):
            raise LiveStage0CLIError(
                f"behavior line {line_number} requires id, query/behavior/text, and risk_category"
            )
        if behavior_id in rows:
            raise LiveStage0CLIError(f"duplicate behavior id: {behavior_id}")
        rows[behavior_id] = {
            "id": behavior_id,
            "text": text,
            "risk_category": category,
            "sector": str(row.get("sector", "")),
        }
    if not rows:
        raise LiveStage0CLIError("behavior file is empty")
    return rows


def _load_prompt_manifest(path: Path) -> dict[str, ResolvedPrompt]:
    resolved = path.expanduser().resolve()
    raw = _load_json(resolved, "prompt manifest")
    if not isinstance(raw, Mapping):
        raise LiveStage0CLIError("prompt manifest must be an object")
    conditions = raw.get("conditions")
    legacy_arms = raw.get("arms")
    if conditions is not None and legacy_arms is not None:
        raise LiveStage0CLIError("prompt manifest cannot contain both conditions and arms")
    if conditions is not None:
        if not isinstance(conditions, Mapping) or set(conditions) != set(
            SELECTOR_CONDITION_TO_ARM
        ):
            raise LiveStage0CLIError(
                "selector conditions must contain exactly "
                f"{list(SELECTOR_CONDITION_TO_ARM)}"
            )
        rows = {
            SELECTOR_CONDITION_TO_ARM[str(condition)]: (
                value,
                "prompt_path",
                "tokens",
            )
            for condition, value in conditions.items()
        }
    else:
        if not isinstance(legacy_arms, Mapping) or set(legacy_arms) != set(ARM_IDS):
            raise LiveStage0CLIError(
                f"legacy prompt arms must contain exactly {list(ARM_IDS)}"
            )
        rows = {
            str(arm): (value, "path", "token_count")
            for arm, value in legacy_arms.items()
        }
    prompts: dict[str, ResolvedPrompt] = {}
    for arm, (value, path_field, token_field) in rows.items():
        if not isinstance(value, Mapping):
            raise LiveStage0CLIError(f"prompt manifest arm {arm!r} must be an object")
        token_count = value.get(token_field)
        if isinstance(token_count, bool) or not isinstance(token_count, int) or token_count < 0:
            raise LiveStage0CLIError(f"prompt manifest arm {arm!r} has invalid token count")
        prompt_path = value.get(path_field)
        if prompt_path is None:
            text = ""
        else:
            source = _resolve_relative(resolved.parent, prompt_path, f"prompt {arm}")
            try:
                text = source.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise LiveStage0CLIError(f"prompt file not found: {source}") from exc
            expected_file_hash = value.get("prompt_file_sha256")
            if expected_file_hash is not None and sha256_file(source) != expected_file_hash:
                raise LiveStage0CLIError(f"prompt file hash mismatch: {arm}")
        expected_text_hash = value.get("text_sha256")
        observed_text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if expected_text_hash is not None and observed_text_hash != expected_text_hash:
            raise LiveStage0CLIError(f"prompt text hash mismatch: {arm}")
        prompts[str(arm)] = ResolvedPrompt(text=text, token_count=token_count)
    if set(prompts) != set(ARM_IDS):
        raise LiveStage0CLIError("prompt manifest did not resolve all Stage-0 arms")
    return prompts


def _load_asset_manifest(path: Path) -> dict[str, dict[str, Path]]:
    resolved = path.expanduser().resolve()
    raw = _load_json(resolved, "asset manifest")
    behaviors = raw.get("behaviors") if isinstance(raw, Mapping) else None
    if not isinstance(behaviors, Mapping):
        raise LiveStage0CLIError("asset manifest requires a behaviors mapping")
    result: dict[str, dict[str, Path]] = {}
    for behavior_id, assets in behaviors.items():
        if not isinstance(assets, Mapping):
            raise LiveStage0CLIError(
                f"asset manifest behavior {behavior_id!r} must be an object"
            )
        resolved_assets: dict[str, Path] = {}
        for asset_id, source in assets.items():
            raw_path = source.get("path") if isinstance(source, Mapping) else source
            asset_path = _resolve_relative(
                resolved.parent, raw_path, f"asset {behavior_id}/{asset_id}"
            )
            if not asset_path.is_file():
                raise LiveStage0CLIError(f"asset file not found: {asset_path}")
            if (
                isinstance(source, Mapping)
                and source.get("sha256") is not None
                and asset_file_sha256(asset_path) != source["sha256"]
            ):
                raise LiveStage0CLIError(
                    f"asset content hash mismatch: {behavior_id}/{asset_id}"
                )
            resolved_assets[str(asset_id)] = asset_path
        result[str(behavior_id)] = resolved_assets
    return result


def _load_first_move_cassettes(
    path: Path,
    *,
    plan: Any,
    assets: Mapping[str, Mapping[str, Path]],
) -> dict[str, FrozenFirstMoveCassette]:
    resolved_path = path.expanduser().resolve()
    try:
        permissions = resolved_path.stat().st_mode & 0o777
    except OSError as exc:
        raise LiveStage0CLIError(
            f"private first-move cassette not found: {resolved_path}"
        ) from exc
    if permissions & 0o077:
        raise LiveStage0CLIError(
            "private first-move cassette must not be group/world accessible"
        )
    raw = _load_json(path, "private frozen first-move cassette")
    if not isinstance(raw, Mapping):
        raise LiveStage0CLIError("private first-move cassette must be an object")
    try:
        if raw.get("schema_version") == 1:
            parsed = (FrozenFirstMoveCassette.from_mapping(raw),)
        elif raw.get("schema_version") == 2:
            parsed = FrozenFirstMoveCassetteBundle.from_mapping(raw).cassettes
        else:
            raise FrozenFirstMoveCassetteError(
                "private first-move cassette schema_version must be 1 or 2"
            )
    except FrozenFirstMoveCassetteError as exc:
        raise LiveStage0CLIError(str(exc)) from exc
    cassettes = {cassette.behavior_id: cassette for cassette in parsed}
    pairs = plan.manifest.get("pairs")
    if (
        not isinstance(pairs, list)
        or not pairs
        or not all(isinstance(pair, Mapping) for pair in pairs)
    ):
        raise LiveStage0CLIError("prepared plan must contain pair contracts")
    contract_behavior_ids = {str(pair.get("behavior_id", "")) for pair in pairs}
    missing = sorted(contract_behavior_ids - set(cassettes))
    extra = sorted(set(cassettes) - contract_behavior_ids)
    if missing or extra:
        raise LiveStage0CLIError(
            "cassette behavior coverage mismatch: "
            f"missing={missing}, extra={extra}"
        )
    for pair in pairs:
        behavior_id = str(pair.get("behavior_id", ""))
        cassette = cassettes[behavior_id]
        contract_assets = pair.get("asset_hashes")
        if not isinstance(contract_assets, Mapping):
            raise LiveStage0CLIError(
                f"prepared pair is missing asset hashes: {behavior_id}"
            )
        try:
            cassette.attest_contract(
                behavior_id=behavior_id,
                request_sha256=str(pair.get("first_action_sha256", "")),
                action_sha256=str(pair.get("fallback_action_sha256", "")),
                asset_hashes={
                    str(key): str(value)
                    for key, value in contract_assets.items()
                },
            )
        except FrozenFirstMoveCassetteError as exc:
            raise LiveStage0CLIError(str(exc)) from exc
        if cassette.request_sha256 != pair.get("fallback_request_sha256"):
            raise LiveStage0CLIError(
                "cassette request hash differs from the prefrozen fallback "
                f"contract: {behavior_id}"
            )
        behavior_assets = assets.get(behavior_id)
        if not isinstance(behavior_assets, Mapping):
            raise LiveStage0CLIError(
                f"asset manifest lacks cassette behavior: {behavior_id}"
            )
        if tuple(behavior_assets) != tuple(
            name for name, _ in cassette.image_assets
        ):
            raise LiveStage0CLIError(
                "asset manifest order differs from the cassette image order: "
                f"{behavior_id}"
            )
        # Decode and attest once during CLI construction so dry-run is a true
        # no-model preflight. Live execution materializes a fresh copy per arm.
        move = _materialize_first_move(cassette, behavior_assets)
        _close_first_move(move)
    return cassettes


def _materialize_first_move(
    cassette: FrozenFirstMoveCassette,
    assets: Mapping[str, Path],
) -> FrozenFirstMove:
    images: list[FrozenFirstMoveImage] = []
    try:
        for asset_id, digest in cassette.image_assets:
            try:
                source = assets[asset_id]
            except KeyError as exc:
                raise LiveStage0CLIError(
                    f"cassette asset is missing: {asset_id}"
                ) from exc
            with Image.open(source) as decoded:
                decoded.load()
                image = decoded.copy()
            images.append(
                FrozenFirstMoveImage(
                    image_id=asset_id,
                    decoded_image=image,
                    content_sha256=digest,
                )
            )
        return FrozenFirstMove(
            request_text=cassette.request_text,
            request_sha256=cassette.request_sha256,
            action_sha256=cassette.action_sha256,
            images=tuple(images),
        )
    except Exception:
        for item in images:
            close = getattr(item.decoded_image, "close", None)
            if callable(close):
                close()
        raise


def _close_first_move(move: FrozenFirstMove) -> None:
    for item in move.images:
        close = getattr(item.decoded_image, "close", None)
        if callable(close):
            close()


def _prepared_plan(prepared: Path):
    return load_prepared(prepared)


def _build_orchestrator(args: argparse.Namespace) -> Stage0LiveOrchestrator:
    plan = _prepared_plan(args.prepared)
    arena = ArenaConfig.load(args.arena_config)
    target = arena.target(args.target_id)
    behaviors = _load_behaviors(args.behaviors)
    prompts = _load_prompt_manifest(args.prompts)
    assets = _load_asset_manifest(args.assets)
    cassettes = _load_first_move_cassettes(
        args.first_move_cassette,
        plan=plan,
        assets=assets,
    )
    memory = args.memory.expanduser().resolve()
    if not memory.is_file():
        raise LiveStage0CLIError(f"memory snapshot not found: {memory}")

    def behavior_resolver(behavior_id: str) -> ResolvedBehavior:
        try:
            row = behaviors[behavior_id]
        except KeyError as exc:
            raise LiveStage0CLIError(f"missing behavior: {behavior_id}") from exc
        return ResolvedBehavior(
            behavior_id=behavior_id,
            value=SimpleNamespace(**row),
            assets=assets.get(behavior_id, {}),
        )

    def prompt_resolver(arm: str) -> ResolvedPrompt:
        try:
            return prompts[arm]
        except KeyError as exc:
            raise LiveStage0CLIError(f"missing prompt manifest arm: {arm}") from exc

    def memory_resolver(_requested_hash: str) -> Path:
        return memory

    runner = ArmorLiveRunner(
        arena_config=arena,
        target_profile=target,
        base_config=args.base_config,
        freeze_memory=not args.adaptive_memory,
    )

    def run_callable(context: LiveRunContext) -> Mapping[str, Any]:
        behavior_id = str(context.contract.get("behavior_id", ""))
        try:
            cassette = cassettes[behavior_id]
            behavior_assets = assets[behavior_id]
        except KeyError as exc:
            raise LiveStage0CLIError(
                f"no attested first-move cassette route for behavior: {behavior_id}"
            ) from exc
        move = _materialize_first_move(cassette, behavior_assets)
        try:
            return runner(replace(context, frozen_first_move=move))
        finally:
            _close_first_move(move)

    return Stage0LiveOrchestrator(
        prepared_root=args.prepared,
        behavior_resolver=behavior_resolver,
        arm_prompt_resolver=prompt_resolver,
        memory_snapshot_resolver=memory_resolver,
        run_callable=run_callable,
        workers=1,
    )


def _run_prepared(args: argparse.Namespace) -> dict[str, Any]:
    execution_status = "failed"
    try:
        orchestrator = _build_orchestrator(args)
        if args.command == "dry-run":
            report = orchestrator.dry_run()
        else:
            records = orchestrator.execute()
            report = {
                "protocol": orchestrator.plan.manifest["protocol"],
                "experiment_id": orchestrator.plan.manifest["experiment_id"],
                "workers": 1,
                "run_count": len(records),
                "records": [asdict(record) for record in records],
            }
        report.update(
            {
                "mode": args.command,
                "prepared_root": str(args.prepared.expanduser().resolve()),
                "arena_config": str(args.arena_config.expanduser().resolve()),
                "base_config": str(args.base_config.expanduser().resolve()),
                "behavior_file": str(args.behaviors.expanduser().resolve()),
                "memory_snapshot": str(args.memory.expanduser().resolve()),
                "private_first_move_cassette": str(
                    args.first_move_cassette.expanduser().resolve()
                ),
                "first_move_policy": (
                    "frozen_first_move_then_response_conditioned_restart_v1"
                ),
                "servers_started": False,
                "servers_stopped": False,
                "gpu_allocation_performed": False,
            }
        )
        _atomic_write_json(args.result, report)
        execution_status = "complete"
        return report
    finally:
        if args.command == "live":
            _atomic_write_json(
                args.shutdown_completion,
                {
                    "schema_version": 1,
                    "completed": True,
                    "mode": "live",
                    "execution_status": execution_status,
                    "lane_b_target_shutdown_requested": True,
                    "target_id": args.target_id,
                    "result_path": str(args.result.expanduser().resolve()),
                    "raw_attack_or_response_text_included": False,
                },
            )


def _copy_prefreeze_memory(source: Path, work_dir: Path) -> tuple[Path, Path, str]:
    source = source.expanduser().resolve()
    if not source.is_file():
        raise LiveStage0CLIError(f"memory snapshot not found: {source}")
    memory_hash = sha256_file(source)
    memory_root = work_dir.expanduser().resolve() / "memory"
    initial = memory_root / "initial.snapshot"
    working = memory_root / "working.snapshot"
    if initial.exists() or working.exists():
        raise LiveStage0CLIError("prefreeze work directory already contains memory state")
    memory_root.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, initial)
    initial.chmod(0o444)
    shutil.copyfile(source, working)
    working.chmod(0o600)
    if sha256_file(initial) != memory_hash or sha256_file(working) != memory_hash:
        raise LiveStage0CLIError("prefreeze memory copy hash mismatch")
    return initial, working, memory_hash


def _run_prefreeze(args: argparse.Namespace) -> dict[str, Any]:
    spec = _load_json(args.spec, "prefreeze spec")
    if not isinstance(spec, Mapping) or spec.get("schema_version") != 1:
        raise LiveStage0CLIError("prefreeze spec schema_version must be 1")
    pair_id = str(spec.get("pair_id", "")).strip()
    seed = spec.get("attacker_seed")
    budget = spec.get("target_call_budget")
    decoding = spec.get("decoding_config")
    if not pair_id:
        raise LiveStage0CLIError("prefreeze spec requires pair_id")
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise LiveStage0CLIError("prefreeze attacker_seed must be non-negative")
    if isinstance(budget, bool) or not isinstance(budget, int) or budget < 1:
        raise LiveStage0CLIError("prefreeze target_call_budget must be positive")
    if not isinstance(decoding, Mapping) or not decoding:
        raise LiveStage0CLIError("prefreeze decoding_config must be non-empty")
    behaviors = _load_behaviors(args.behavior)
    behavior_id = args.behavior_id.strip()
    if not behavior_id:
        raise LiveStage0CLIError("prefreeze behavior id cannot be empty")
    try:
        behavior = behaviors[behavior_id]
    except KeyError as exc:
        raise LiveStage0CLIError(
            f"prefreeze behavior id not found: {behavior_id}"
        ) from exc
    initial, working, memory_hash = _copy_prefreeze_memory(args.memory, args.work_dir)

    arena = ArenaConfig.load(args.arena_config)
    target = arena.target(args.target_id)
    run_id = f"prefreeze-{hashlib.sha256(pair_id.encode()).hexdigest()[:20]}"
    contract = {
        "run_id": run_id,
        "pair_id": pair_id,
        "behavior_id": behavior_id,
        "arm": "prefreeze_capture",
        "arm_position": 1,
        "arm_prompt_sha256": SHA256_EMPTY,
        "attacker_seed": seed,
        "target_call_budget": budget,
        "initial_memory_sha256": memory_hash,
        "initial_retrieval_sha256": "0" * 64,
        "first_action_sha256": "0" * 64,
        "fallback_policy_sha256": FALLBACK_POLICY_SHA256,
        "fallback_action_sha256": "0" * 64,
        "fallback_request_sha256": "0" * 64,
        "asset_bundle_sha256": "0" * 64,
        "decoding_config_sha256": canonical_sha256(dict(decoding)),
        "run_memory_namespace": f"prefreeze/{run_id}",
    }
    expected = {field: contract[field] for field in PROVENANCE_FIELDS}
    context = LiveRunContext(
        contract=contract,
        behavior=ResolvedBehavior(
            behavior_id=behavior_id,
            value=SimpleNamespace(**behavior),
            assets={},
        ),
        installed_system_prompt="",
        output_dir=args.work_dir.expanduser().resolve() / "runtime",
        immutable_initial_memory_path=initial,
        working_memory_path=working,
        attacker_seed=seed,
        target_call_budget=budget,
        decoding_config=dict(decoding),
        expected_stage0_provenance=expected,
        workers=1,
    )
    runner = ArmorLiveRunner(
        arena_config=arena,
        target_profile=target,
        base_config=args.base_config,
        freeze_memory=True,
    )
    row = runner.prefreeze(context)
    evidence = extract_prefreeze_evidence(row, initial_memory_sha256=memory_hash)
    if evidence.target_call_budget != budget:
        raise LiveStage0CLIError(
            "prefreeze runtime target_call_budget does not match requested budget"
        )
    pair = evidence.to_pair_record(pair_id=pair_id, decoding_config=decoding)
    history = row.get("history") if isinstance(row, Mapping) else None
    record = history[0] if isinstance(history, list) and history else None
    turns = record.get("turns") if isinstance(record, Mapping) else None
    image_ids = (
        turns[0].get("images")
        if isinstance(turns, list) and turns and isinstance(turns[0], Mapping)
        else None
    )
    if not isinstance(image_ids, list) or len(image_ids) != len(evidence.asset_hashes):
        raise LiveStage0CLIError("prefreeze asset ids do not match captured hashes")
    artifact_root = (context.output_dir / "artifacts" / "00001").resolve()
    asset_rows: dict[str, dict[str, str]] = {}
    for image_id, (asset_name, expected_hash) in zip(
        image_ids, evidence.asset_hashes, strict=True
    ):
        if not isinstance(image_id, str) or Path(image_id).name != image_id:
            raise LiveStage0CLIError("prefreeze image id is not a safe filename")
        candidates = []
        if artifact_root.is_dir():
            for candidate in artifact_root.iterdir():
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                source = candidate.resolve()
                if source.parent != artifact_root:
                    continue
                if source.name != image_id and source.stem != image_id:
                    continue
                if asset_file_sha256(source) == expected_hash:
                    candidates.append(source)
        if len(candidates) != 1:
            raise LiveStage0CLIError(
                "prefreeze artifact content hash did not resolve uniquely"
            )
        source = candidates[0]
        asset_rows[asset_name] = {"path": str(source), "sha256": expected_hash}
    asset_manifest = {"behaviors": {behavior_id: asset_rows}}
    cassette = cassette_from_prefreeze_row(
        row,
        behavior_id=behavior_id,
        request_sha256=evidence.first_target_request_sha256,
        action_sha256=evidence.first_target_action_sha256,
        image_assets=evidence.asset_hashes,
    )
    wrapper = {
        "schema_version": 1,
        "artifact_type": "armor-stage0-prefreeze-pair-v1",
        "target_call_budget": evidence.target_call_budget,
        "pair": pair,
        "pair_sha256": canonical_sha256(pair),
        # Raw-file digest binds the wrapper to the exact CLI input bytes. The
        # builder separately validates semantic fields and canonical hashes.
        "prefreeze_spec_sha256": sha256_file(args.spec.expanduser().resolve()),
        "decoding_config_sha256": canonical_sha256(dict(decoding)),
        "raw_attack_or_response_text_included": False,
    }
    _atomic_write_json(args.assets_result, asset_manifest)
    _atomic_write_private_json(args.cassette_result, cassette.to_dict())
    _atomic_write_json(args.result, wrapper)
    return {
        "mode": "prefreeze",
        "pair_id": pair_id,
        "behavior_id": behavior_id,
        "result": str(args.result.expanduser().resolve()),
        "assets_result": str(args.assets_result.expanduser().resolve()),
        "private_first_move_cassette": str(
            args.cassette_result.expanduser().resolve()
        ),
        "work_dir": str(args.work_dir.expanduser().resolve()),
        "public_raw_attack_or_response_text_written": False,
        "private_raw_attack_text_written": True,
        "private_target_response_written": False,
        "servers_started": False,
        "servers_stopped": False,
        "gpu_allocation_performed": False,
    }


def _add_shared_live_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--prepared", required=True, type=Path)
    parser.add_argument("--arena-config", required=True, type=Path)
    parser.add_argument("--base-config", required=True, type=Path)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--behaviors", required=True, type=Path)
    parser.add_argument("--prompts", required=True, type=Path)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument(
        "--first-move-cassette",
        required=True,
        type=Path,
        help=(
            "private mode-0600 v1 first-move cassette or v2 behavior bundle; "
            "validated before any target call and never copied into Stage-0 results"
        ),
    )
    parser.add_argument("--memory", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument(
        "--adaptive-memory",
        action="store_true",
        help="allow within-run memory writes (default: frozen memory)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    dry_run = commands.add_parser("dry-run")
    _add_shared_live_arguments(dry_run)
    live = commands.add_parser("live")
    _add_shared_live_arguments(live)
    live.add_argument(
        "--shutdown-completion",
        required=True,
        type=Path,
        help="atomically written completion request for the external lane-b watchdog",
    )
    prefreeze = commands.add_parser("prefreeze")
    prefreeze.add_argument("--arena-config", required=True, type=Path)
    prefreeze.add_argument("--base-config", required=True, type=Path)
    prefreeze.add_argument("--target-id", required=True)
    prefreeze.add_argument("--behavior", required=True, type=Path)
    prefreeze.add_argument("--behavior-id", required=True)
    prefreeze.add_argument("--memory", required=True, type=Path)
    prefreeze.add_argument("--spec", required=True, type=Path)
    prefreeze.add_argument("--work-dir", required=True, type=Path)
    prefreeze.add_argument("--result", required=True, type=Path)
    prefreeze.add_argument("--assets-result", required=True, type=Path)
    prefreeze.add_argument(
        "--cassette-result",
        required=True,
        type=Path,
        help="private mode-0600 raw first-move cassette (contains no target response)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        report = _run_prefreeze(args) if args.command == "prefreeze" else _run_prepared(args)
    except (
        ArmorLiveRunnerError,
        FrozenFirstMoveCassetteError,
        KeyError,
        LiveStage0CLIError,
        OSError,
        PrefreezeValidationError,
        Stage0OrchestrationError,
        TypeError,
        ValueError,
    ) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
