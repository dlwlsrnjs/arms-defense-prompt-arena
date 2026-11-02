"""Offline orchestration for a sixteen-pair D1 first-move prefreeze.

The batch has two deliberately separate phases:

``prepare_prefreeze_batch``
    Validates a frozen challenge and writes one schema-v1 prefreeze spec plus
    an argv-only invocation plan per pair.  The plan points at
    :mod:`scripts.run_armor_live_stage0`, whose prefreeze mode uses configured,
    already-running endpoints and a target capture stub.  Preparation never
    invokes an endpoint.

``finalize_prefreeze_batch``
    Runs only after those argv entries have been executed elsewhere.  It
    validates every wrapper, cassette, and captured image against the frozen
    specs and challenge, then creates a private schema-v2 cassette bundle and
    a self-contained private asset manifest.

This module intentionally contains no process, model-server, accelerator, or
endpoint lifecycle operations.  All artifacts that reveal raw first moves or
captured images are written mode 0600 without overwriting existing files.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .armor_challenge_review import (
    EXPECTED_PAIR_COUNT,
    PENDING_STATUS,
    READY_STATUS,
    ChallengeReviewError,
    _verify_pending_inputs,
)
from .armor_d1_stage0_spec import (
    D1_TARGET_CALL_BUDGET,
    D1Stage0SpecBuildError,
    _verify_challenge_manifest,
    _verify_wrapper,
)
from .armor_first_move_cassette import (
    FrozenFirstMoveCassette,
    FrozenFirstMoveCassetteBundle,
    FrozenFirstMoveCassetteError,
)
from .armor_stage0 import canonical_sha256
from .asset_hashing import asset_file_sha256
from .memory_compiler import sha256_file

BATCH_PLAN_ARTIFACT = "armor-d1-prefreeze-batch-plan-v1"
BATCH_FINAL_ARTIFACT = "armor-d1-prefreeze-batch-final-v1"
DEFAULT_DECODING_CONFIG: Mapping[str, Any] = {
    "temperature": 0.0,
    "top_p": 1.0,
    "max_tokens": 1024,
}

_PLAN_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "challenge_manifest",
        "private_behavior_file",
        "inputs",
        "pair_count",
        "decoding_config",
        "decoding_config_sha256",
        "execution_policy",
        "pairs",
        "raw_attack_or_response_text_included",
        "plan_sha256",
    }
)
_PLAN_PAIR_FIELDS = frozenset(
    {
        "order",
        "pair_id",
        "behavior_id",
        "challenge_entry_sha256",
        "attacker_seed",
        "target_call_budget",
        "prefreeze_spec_path",
        "prefreeze_spec_sha256",
        "work_dir",
        "wrapper_result_path",
        "asset_result_path",
        "cassette_result_path",
        "invocation_argv",
    }
)
_SPEC_FIELDS = frozenset(
    {
        "schema_version",
        "pair_id",
        "attacker_seed",
        "target_call_budget",
        "decoding_config",
    }
)
_INPUT_FIELDS = frozenset(
    {
        "arena_config_path",
        "arena_config_sha256",
        "base_config_path",
        "base_config_sha256",
        "target_id",
        "memory_path",
        "memory_sha256",
        "runner_path",
        "runner_sha256",
        "python_executable",
    }
)
_EXECUTION_POLICY = {
    "preparation_invokes_endpoints": False,
    "prefreeze_requires_existing_endpoints": True,
    "prefreeze_target_is_capture_stub": True,
    "model_servers_started": False,
    "model_servers_stopped": False,
    "accelerator_allocation_performed": False,
}


class PrefreezeBatchError(ValueError):
    """Raised when an offline prefreeze batch fails closed."""


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PrefreezeBatchError(f"{label} must be an object")
    return value


def _require_exact_fields(
    value: Mapping[str, Any], expected: frozenset[str], label: str
) -> None:
    if set(value) != expected:
        missing = sorted(expected.difference(value))
        extra = sorted(set(value).difference(expected))
        raise PrefreezeBatchError(
            f"{label} fields mismatch; missing={missing}, extra={extra}"
        )


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PrefreezeBatchError(f"{label} must be a non-empty string")
    return value.strip()


def _require_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise PrefreezeBatchError(f"{label} must be an integer >= {minimum}")
    return value


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        raise PrefreezeBatchError(f"{label} must be a lowercase SHA-256 digest")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise PrefreezeBatchError(
            f"{label} must be a lowercase SHA-256 digest"
        ) from exc
    return value


def _load_json(path: str | Path, label: str) -> tuple[Path, Mapping[str, Any]]:
    source = Path(path).expanduser()
    if source.is_symlink():
        raise PrefreezeBatchError(f"{label} must not be a symbolic link")
    resolved = source.resolve()
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PrefreezeBatchError(f"invalid {label}: {resolved}") from exc
    if not isinstance(value, Mapping):
        raise PrefreezeBatchError(f"{label} must be a JSON object")
    return resolved, value


def _private_file(path: str | Path, label: str) -> Path:
    source = Path(path).expanduser()
    if source.is_symlink():
        raise PrefreezeBatchError(f"{label} must not be a symbolic link")
    resolved = source.resolve()
    try:
        mode = resolved.stat().st_mode & 0o777
    except OSError as exc:
        raise PrefreezeBatchError(f"{label} not found: {resolved}") from exc
    if not resolved.is_file() or mode != 0o600:
        raise PrefreezeBatchError(f"{label} must be a regular mode-0600 file")
    return resolved


def _ordinary_file(path: str | Path, label: str) -> Path:
    source = Path(path).expanduser()
    if source.is_symlink():
        raise PrefreezeBatchError(f"{label} must not be a symbolic link")
    resolved = source.resolve()
    if not resolved.is_file():
        raise PrefreezeBatchError(f"{label} not found: {resolved}")
    return resolved


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _exclusive_write_bytes(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    destination = path.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise PrefreezeBatchError(
                f"refusing to overwrite existing artifact: {destination}"
            ) from exc
        directory_descriptor = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def _exclusive_write_json(path: Path, value: Any, *, mode: int = 0o600) -> None:
    _exclusive_write_bytes(path, _json_bytes(value), mode=mode)


def _load_private_rows(path: str | Path) -> tuple[Path, dict[str, Mapping[str, Any]]]:
    resolved = _private_file(path, "private selected behavior file")
    rows: dict[str, Mapping[str, Any]] = {}
    try:
        lines = resolved.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise PrefreezeBatchError(
            f"invalid private selected behavior file: {resolved}"
        ) from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise PrefreezeBatchError(
                f"invalid private behavior JSONL line: {line_number}"
            ) from exc
        if not isinstance(row, Mapping):
            raise PrefreezeBatchError(
                f"private behavior line {line_number} must be an object"
            )
        behavior_id = _require_string(
            row.get("id"), f"private behavior line {line_number}.id"
        )
        if behavior_id in rows:
            raise PrefreezeBatchError(f"duplicate private behavior id: {behavior_id}")
        rows[behavior_id] = row
    if len(rows) != EXPECTED_PAIR_COUNT:
        raise PrefreezeBatchError(
            f"private behavior file must contain exactly {EXPECTED_PAIR_COUNT} rows"
        )
    return resolved, rows


def _validated_challenge(
    manifest_path: str | Path,
    selected_behaviors_path: str | Path,
) -> tuple[Path, Mapping[str, Any], str, list[dict[str, Any]], Path]:
    resolved_manifest, manifest = _load_json(manifest_path, "challenge manifest")
    status = manifest.get("status")
    try:
        if status == PENDING_STATUS:
            _, manifest_sha256, entries, _ = _verify_pending_inputs(
                resolved_manifest, selected_behaviors_path
            )
            normalized_entries = [dict(entry) for entry in entries]
        elif status == READY_STATUS:
            manifest_sha256, normalized_entries = _verify_challenge_manifest(manifest)
        else:
            raise PrefreezeBatchError(
                "challenge manifest must be a frozen pending or execution-ready D1 cohort"
            )
    except (ChallengeReviewError, D1Stage0SpecBuildError) as exc:
        raise PrefreezeBatchError(str(exc)) from exc

    private_path, rows = _load_private_rows(selected_behaviors_path)
    private_metadata = _require_mapping(
        manifest.get("private_behavior_file"), "private_behavior_file"
    )
    recorded_path = (
        Path(
            _require_string(private_metadata.get("path"), "private_behavior_file.path")
        )
        .expanduser()
        .resolve()
    )
    if private_path != recorded_path:
        raise PrefreezeBatchError("private behavior file path mismatch")
    recorded_hash = _require_sha256(
        private_metadata.get("sha256"), "private_behavior_file.sha256"
    )
    if sha256_file(private_path) != recorded_hash:
        raise PrefreezeBatchError("private behavior file hash mismatch")
    if (
        private_metadata.get("contains_raw_text") is not True
        or private_metadata.get("publish") is not False
    ):
        raise PrefreezeBatchError("private behavior publication policy mismatch")

    expected_ids = {str(entry["behavior_id"]) for entry in normalized_entries}
    if set(rows) != expected_ids:
        raise PrefreezeBatchError("challenge/private behavior coverage mismatch")
    for entry in normalized_entries:
        behavior_id = str(entry["behavior_id"])
        if canonical_sha256(rows[behavior_id]) != entry.get("row_sha256"):
            raise PrefreezeBatchError(
                f"private behavior row hash mismatch: {behavior_id}"
            )
    return (
        resolved_manifest,
        manifest,
        manifest_sha256,
        normalized_entries,
        private_path,
    )


def _source_attestation(path: str | Path, label: str) -> tuple[Path, str]:
    resolved = _ordinary_file(path, label)
    return resolved, sha256_file(resolved)


def _python_executable_path(value: str | Path) -> str:
    """Validate an interpreter without collapsing a virtualenv symlink.

    Resolving ``venv/bin/python`` commonly produces the system interpreter and
    silently loses the virtualenv's site-packages.  The invocation plan must
    therefore retain the caller's absolute path spelling while still checking
    that its resolved target is a regular executable file.
    """

    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    candidate = Path(os.path.abspath(candidate))
    try:
        resolved_target = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PrefreezeBatchError(f"python executable not found: {candidate}") from exc
    if not resolved_target.is_file() or not os.access(candidate, os.X_OK):
        raise PrefreezeBatchError(
            f"python executable is not a regular executable file: {candidate}"
        )
    return str(candidate)


def _safe_pair_dir(index: int, pair_id: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", pair_id.casefold()).strip("-")[:48]
    if not slug:
        slug = hashlib.sha256(pair_id.encode("utf-8")).hexdigest()[:16]
    return f"{index:02d}-{slug}"


def prepare_prefreeze_batch(
    *,
    challenge_manifest_path: str | Path,
    selected_behaviors_path: str | Path,
    arena_config_path: str | Path,
    base_config_path: str | Path,
    target_id: str,
    memory_path: str | Path,
    output_dir: str | Path,
    decoding_config: Mapping[str, Any] = DEFAULT_DECODING_CONFIG,
    runner_path: str | Path | None = None,
    python_executable: str | Path | None = None,
) -> dict[str, Any]:
    """Write an offline, argv-only plan for exactly sixteen prefreeze calls.

    The function performs no invocation.  Every argv entry uses the existing
    ``prefreeze`` command, which has no server lifecycle behavior and captures
    before a target response exists.
    """

    (
        resolved_manifest,
        manifest,
        manifest_sha256,
        entries,
        private_path,
    ) = _validated_challenge(challenge_manifest_path, selected_behaviors_path)
    if len(entries) != EXPECTED_PAIR_COUNT:
        raise PrefreezeBatchError(
            f"challenge must contain exactly {EXPECTED_PAIR_COUNT} pairs"
        )
    decoding = dict(_require_mapping(decoding_config, "decoding_config"))
    if not decoding:
        raise PrefreezeBatchError("decoding_config must not be empty")
    target = _require_string(target_id, "target_id")

    arena_path, arena_sha = _source_attestation(arena_config_path, "arena config")
    base_path, base_sha = _source_attestation(base_config_path, "base config")
    memory_source, memory_sha = _source_attestation(memory_path, "memory snapshot")
    if runner_path is None:
        runner_path = (
            Path(__file__).resolve().parents[1] / "scripts" / "run_armor_live_stage0.py"
        )
    runner, runner_sha = _source_attestation(runner_path, "prefreeze runner")
    executable = _python_executable_path(python_executable or sys.executable)

    root = Path(output_dir).expanduser().resolve()
    try:
        root.mkdir(parents=True, mode=0o700, exist_ok=False)
    except FileExistsError as exc:
        raise PrefreezeBatchError(
            f"refusing to overwrite existing batch directory: {root}"
        ) from exc
    root.chmod(0o700)

    plan_pairs: list[dict[str, Any]] = []
    pairs_root = root / "pairs"
    pairs_root.mkdir(mode=0o700)
    for index, entry in enumerate(entries, start=1):
        pair_id = _require_string(entry.get("pair_id"), f"pairs[{index}].pair_id")
        behavior_id = _require_string(
            entry.get("behavior_id"), f"pairs[{index}].behavior_id"
        )
        seed = _require_int(entry.get("attacker_seed"), f"pairs[{index}].attacker_seed")
        budget = _require_int(
            entry.get("target_call_budget"),
            f"pairs[{index}].target_call_budget",
            minimum=1,
        )
        if budget != D1_TARGET_CALL_BUDGET:
            raise PrefreezeBatchError("D1 prefreeze target-call budget must be 4")
        pair_root = pairs_root / _safe_pair_dir(index, pair_id)
        pair_root.mkdir(mode=0o700)
        spec_path = pair_root / "prefreeze_spec.json"
        work_dir = pair_root / "work"
        wrapper_path = pair_root / "prefreeze_wrapper.json"
        asset_path = pair_root / "captured_assets.private.json"
        cassette_path = pair_root / "first_move.private.json"
        spec = {
            "schema_version": 1,
            "pair_id": pair_id,
            "attacker_seed": seed,
            "target_call_budget": budget,
            "decoding_config": decoding,
        }
        spec_bytes = _json_bytes(spec)
        _exclusive_write_bytes(spec_path, spec_bytes)
        argv = [
            executable,
            str(runner),
            "prefreeze",
            "--arena-config",
            str(arena_path),
            "--base-config",
            str(base_path),
            "--target-id",
            target,
            "--behavior",
            str(private_path),
            "--behavior-id",
            behavior_id,
            "--memory",
            str(memory_source),
            "--spec",
            str(spec_path),
            "--work-dir",
            str(work_dir),
            "--result",
            str(wrapper_path),
            "--assets-result",
            str(asset_path),
            "--cassette-result",
            str(cassette_path),
        ]
        plan_pairs.append(
            {
                "order": index,
                "pair_id": pair_id,
                "behavior_id": behavior_id,
                "challenge_entry_sha256": _require_sha256(
                    entry.get("challenge_entry_sha256"),
                    f"pairs[{index}].challenge_entry_sha256",
                ),
                "attacker_seed": seed,
                "target_call_budget": budget,
                "prefreeze_spec_path": str(spec_path),
                "prefreeze_spec_sha256": hashlib.sha256(spec_bytes).hexdigest(),
                "work_dir": str(work_dir),
                "wrapper_result_path": str(wrapper_path),
                "asset_result_path": str(asset_path),
                "cassette_result_path": str(cassette_path),
                "invocation_argv": argv,
            }
        )

    plan: dict[str, Any] = {
        "schema_version": 1,
        "artifact_type": BATCH_PLAN_ARTIFACT,
        "challenge_manifest": {
            "path": str(resolved_manifest),
            "sha256": manifest_sha256,
            "status": manifest["status"],
        },
        "private_behavior_file": {
            "path": str(private_path),
            "sha256": sha256_file(private_path),
            "contains_raw_text": True,
            "publish": False,
        },
        "inputs": {
            "arena_config_path": str(arena_path),
            "arena_config_sha256": arena_sha,
            "base_config_path": str(base_path),
            "base_config_sha256": base_sha,
            "target_id": target,
            "memory_path": str(memory_source),
            "memory_sha256": memory_sha,
            "runner_path": str(runner),
            "runner_sha256": runner_sha,
            "python_executable": executable,
        },
        "pair_count": EXPECTED_PAIR_COUNT,
        "decoding_config": decoding,
        "decoding_config_sha256": canonical_sha256(decoding),
        "execution_policy": dict(_EXECUTION_POLICY),
        "pairs": plan_pairs,
        "raw_attack_or_response_text_included": False,
    }
    plan["plan_sha256"] = canonical_sha256(plan)
    _exclusive_write_json(root / "prefreeze_batch_plan.private.json", plan)
    return plan


def _verify_plan(plan_path: str | Path) -> tuple[Path, Mapping[str, Any]]:
    resolved = _private_file(plan_path, "prefreeze batch plan")
    _, plan = _load_json(resolved, "prefreeze batch plan")
    _require_exact_fields(plan, _PLAN_FIELDS, "prefreeze batch plan")
    if (
        plan.get("schema_version") != 1
        or plan.get("artifact_type") != BATCH_PLAN_ARTIFACT
    ):
        raise PrefreezeBatchError("unsupported prefreeze batch plan")
    claimed = _require_sha256(plan.get("plan_sha256"), "plan_sha256")
    unhashed = dict(plan)
    unhashed.pop("plan_sha256", None)
    if canonical_sha256(unhashed) != claimed:
        raise PrefreezeBatchError("prefreeze batch plan self-hash mismatch")
    if plan.get("pair_count") != EXPECTED_PAIR_COUNT:
        raise PrefreezeBatchError("prefreeze batch plan must contain 16 pairs")
    if plan.get("execution_policy") != _EXECUTION_POLICY:
        raise PrefreezeBatchError("prefreeze execution policy mismatch")
    if plan.get("raw_attack_or_response_text_included") is not False:
        raise PrefreezeBatchError("prefreeze plan violates raw-text policy")
    pairs = plan.get("pairs")
    if not isinstance(pairs, list) or len(pairs) != EXPECTED_PAIR_COUNT:
        raise PrefreezeBatchError("prefreeze batch plan must contain 16 pair rows")
    return resolved, plan


def _verify_source_hash(path: Any, expected: Any, label: str) -> Path:
    source = _ordinary_file(_require_string(path, f"{label}.path"), label)
    digest = _require_sha256(expected, f"{label}.sha256")
    if sha256_file(source) != digest:
        raise PrefreezeBatchError(f"{label} hash mismatch")
    return source


def _load_asset_rows(
    path: Any,
    *,
    behavior_id: str,
    expected_hashes: Mapping[str, Any],
    work_dir: Path,
) -> dict[str, Path]:
    _resolved, manifest = _load_json(path, "per-pair asset manifest")
    if set(manifest) != {"behaviors"}:
        raise PrefreezeBatchError("per-pair asset manifest fields mismatch")
    behaviors = _require_mapping(manifest.get("behaviors"), "asset behaviors")
    if set(behaviors) != {behavior_id}:
        raise PrefreezeBatchError("per-pair asset behavior coverage mismatch")
    assets = _require_mapping(behaviors[behavior_id], "behavior assets")
    if list(assets) != list(expected_hashes):
        raise PrefreezeBatchError("per-pair ordered asset coverage mismatch")
    resolved_assets: dict[str, Path] = {}
    for asset_id, expected_digest in expected_hashes.items():
        if Path(str(asset_id)).name != str(asset_id):
            raise PrefreezeBatchError("asset id is not a safe filename")
        row = _require_mapping(assets[asset_id], f"asset {asset_id}")
        if set(row) != {"path", "sha256"}:
            raise PrefreezeBatchError(f"asset fields mismatch: {asset_id}")
        digest = _require_sha256(row.get("sha256"), f"asset {asset_id}.sha256")
        if digest != expected_digest:
            raise PrefreezeBatchError(f"asset contract hash mismatch: {asset_id}")
        source = Path(_require_string(row.get("path"), f"asset {asset_id}.path"))
        if source.expanduser().is_symlink():
            raise PrefreezeBatchError(f"asset must not be a symbolic link: {asset_id}")
        source = source.expanduser().resolve()
        try:
            source.relative_to(work_dir.resolve())
        except ValueError as exc:
            raise PrefreezeBatchError(
                f"asset escapes its prefreeze work directory: {asset_id}"
            ) from exc
        if not source.is_file() or asset_file_sha256(source) != digest:
            raise PrefreezeBatchError(f"captured asset hash mismatch: {asset_id}")
        resolved_assets[str(asset_id)] = source
    return resolved_assets


def _copy_private_asset(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        shutil.copyfile(source, temporary)
        temporary.chmod(0o600)
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise PrefreezeBatchError(
                f"refusing to overwrite captured asset: {destination}"
            ) from exc
    finally:
        temporary.unlink(missing_ok=True)


@dataclass(frozen=True)
class _PreparedPair:
    plan: Mapping[str, Any]
    entry: Mapping[str, Any]
    spec_bytes: bytes
    spec: Mapping[str, Any]


@dataclass(frozen=True)
class _PlanContext:
    resolved_plan: Path
    plan: Mapping[str, Any]
    challenge: Mapping[str, Any]
    challenge_sha256: str
    inputs: Mapping[str, Any]
    memory_sha256: str
    decoding: Mapping[str, Any]
    pairs: tuple[_PreparedPair, ...]
    compatibility_sha256: str


@dataclass(frozen=True)
class _PairCapture:
    behavior_id: str
    cassette: FrozenFirstMoveCassette
    assets: Mapping[str, Path]
    expected_asset_hashes: Mapping[str, Any]
    attestation: Mapping[str, Any]


def _validate_plan_context(plan_path: str | Path) -> _PlanContext:
    resolved_plan, plan = _verify_plan(plan_path)
    challenge_meta = _require_mapping(
        plan.get("challenge_manifest"), "challenge_manifest"
    )
    challenge_path = _ordinary_file(
        _require_string(challenge_meta.get("path"), "challenge_manifest.path"),
        "challenge manifest",
    )
    private_meta = _require_mapping(
        plan.get("private_behavior_file"), "private_behavior_file"
    )
    private_path = _private_file(
        _require_string(private_meta.get("path"), "private_behavior_file.path"),
        "private behavior file",
    )
    private_sha = _require_sha256(
        private_meta.get("sha256"), "private_behavior_file.sha256"
    )
    if sha256_file(private_path) != private_sha:
        raise PrefreezeBatchError("private behavior file hash mismatch")
    _, challenge, challenge_sha, challenge_entries, _ = _validated_challenge(
        challenge_path, private_path
    )
    if challenge_sha != challenge_meta.get("sha256"):
        raise PrefreezeBatchError("challenge manifest hash drift")
    if challenge.get("status") != challenge_meta.get("status"):
        raise PrefreezeBatchError("challenge manifest status drift")

    inputs = _require_mapping(plan.get("inputs"), "inputs")
    _require_exact_fields(inputs, _INPUT_FIELDS, "inputs")
    for path_key, hash_key, label in (
        ("arena_config_path", "arena_config_sha256", "arena config"),
        ("base_config_path", "base_config_sha256", "base config"),
        ("memory_path", "memory_sha256", "memory snapshot"),
        ("runner_path", "runner_sha256", "prefreeze runner"),
    ):
        _verify_source_hash(inputs[path_key], inputs[hash_key], label)
    memory_sha = str(inputs["memory_sha256"])
    decoding = dict(_require_mapping(plan.get("decoding_config"), "decoding_config"))
    if canonical_sha256(decoding) != _require_sha256(
        plan.get("decoding_config_sha256"), "decoding_config_sha256"
    ):
        raise PrefreezeBatchError("decoding config hash mismatch")

    entries_by_pair = {str(entry["pair_id"]): entry for entry in challenge_entries}
    prepared: list[_PreparedPair] = []
    seen_pairs: set[str] = set()
    seen_behaviors: set[str] = set()
    semantic_pairs: list[dict[str, Any]] = []
    for index, raw_pair in enumerate(plan["pairs"], start=1):
        pair_plan = _require_mapping(raw_pair, f"plan pairs[{index}]")
        _require_exact_fields(pair_plan, _PLAN_PAIR_FIELDS, f"plan pairs[{index}]")
        if pair_plan.get("order") != index:
            raise PrefreezeBatchError("prefreeze plan order mismatch")
        pair_id = _require_string(pair_plan.get("pair_id"), "pair_id")
        behavior_id = _require_string(pair_plan.get("behavior_id"), "behavior_id")
        if pair_id in seen_pairs or behavior_id in seen_behaviors:
            raise PrefreezeBatchError("duplicate pair or behavior in prefreeze plan")
        seen_pairs.add(pair_id)
        seen_behaviors.add(behavior_id)
        try:
            entry = entries_by_pair[pair_id]
        except KeyError as exc:
            raise PrefreezeBatchError(f"pair is not in challenge: {pair_id}") from exc
        for field in ("behavior_id", "attacker_seed", "target_call_budget"):
            if pair_plan.get(field) != entry.get(field):
                raise PrefreezeBatchError(f"challenge/plan mismatch: {pair_id}.{field}")
        if pair_plan.get("challenge_entry_sha256") != entry.get(
            "challenge_entry_sha256"
        ):
            raise PrefreezeBatchError(f"challenge entry hash mismatch: {pair_id}")

        spec_path = _private_file(
            _require_string(pair_plan.get("prefreeze_spec_path"), "spec path"),
            "prefreeze spec",
        )
        spec_bytes = spec_path.read_bytes()
        if hashlib.sha256(spec_bytes).hexdigest() != _require_sha256(
            pair_plan.get("prefreeze_spec_sha256"), "prefreeze_spec_sha256"
        ):
            raise PrefreezeBatchError(f"prefreeze spec hash mismatch: {pair_id}")
        try:
            spec_value = json.loads(spec_bytes)
        except json.JSONDecodeError as exc:
            raise PrefreezeBatchError(f"invalid prefreeze spec: {pair_id}") from exc
        spec = _require_mapping(spec_value, "prefreeze spec")
        _require_exact_fields(spec, _SPEC_FIELDS, "prefreeze spec")
        expected_spec = {
            "schema_version": 1,
            "pair_id": pair_id,
            "attacker_seed": entry["attacker_seed"],
            "target_call_budget": entry["target_call_budget"],
            "decoding_config": decoding,
        }
        if dict(spec) != expected_spec:
            raise PrefreezeBatchError(f"prefreeze spec semantic mismatch: {pair_id}")
        prepared.append(_PreparedPair(pair_plan, entry, spec_bytes, dict(spec)))
        semantic_pairs.append(
            {
                "order": index,
                "pair_id": pair_id,
                "behavior_id": behavior_id,
                "challenge_entry_sha256": entry["challenge_entry_sha256"],
                "spec": dict(spec),
            }
        )
    if set(entries_by_pair) != seen_pairs:
        raise PrefreezeBatchError("prefreeze plan/challenge coverage mismatch")

    compatibility = {
        "challenge_manifest_sha256": challenge_sha,
        "challenge_status": challenge["status"],
        "private_behavior_file_sha256": private_sha,
        "input_identity": {
            "arena_config_sha256": inputs["arena_config_sha256"],
            "base_config_sha256": inputs["base_config_sha256"],
            "memory_sha256": inputs["memory_sha256"],
            "runner_sha256": inputs["runner_sha256"],
            "target_id": inputs["target_id"],
            "python_executable": inputs["python_executable"],
        },
        "decoding_config": decoding,
        "pairs": semantic_pairs,
    }
    return _PlanContext(
        resolved_plan=resolved_plan,
        plan=plan,
        challenge=challenge,
        challenge_sha256=challenge_sha,
        inputs=inputs,
        memory_sha256=memory_sha,
        decoding=decoding,
        pairs=tuple(prepared),
        compatibility_sha256=canonical_sha256(compatibility),
    )


def _capture_outputs_complete(pair_plan: Mapping[str, Any]) -> bool:
    fields = (
        "wrapper_result_path",
        "asset_result_path",
        "cassette_result_path",
    )
    return all(
        Path(_require_string(pair_plan.get(field), field)).expanduser().exists()
        for field in fields
    )


def _validate_pair_capture(
    context: _PlanContext,
    prepared: _PreparedPair,
) -> _PairCapture:
    pair_plan = prepared.plan
    entry = prepared.entry
    pair_id = str(entry["pair_id"])
    behavior_id = str(entry["behavior_id"])
    wrapper_path, wrapper = _load_json(
        pair_plan.get("wrapper_result_path"), "prefreeze wrapper"
    )
    try:
        pair, _wrapper_metadata = _verify_wrapper(wrapper)
    except D1Stage0SpecBuildError as exc:
        raise PrefreezeBatchError(str(exc)) from exc
    if (
        wrapper.get("prefreeze_spec_sha256")
        != hashlib.sha256(prepared.spec_bytes).hexdigest()
    ):
        raise PrefreezeBatchError(f"wrapper/spec hash mismatch: {pair_id}")
    for field in ("pair_id", "behavior_id", "attacker_seed"):
        if pair.get(field) != entry.get(field):
            raise PrefreezeBatchError(f"wrapper/challenge mismatch: {pair_id}.{field}")
    if pair.get("initial_memory_sha256") != context.memory_sha256:
        raise PrefreezeBatchError(f"wrapper memory mismatch: {pair_id}")
    if pair.get("decoding_config") != context.decoding:
        raise PrefreezeBatchError(f"wrapper decoding mismatch: {pair_id}")

    cassette_path = _private_file(
        _require_string(pair_plan.get("cassette_result_path"), "cassette path"),
        "per-pair first-move cassette",
    )
    _, cassette_raw = _load_json(cassette_path, "per-pair first-move cassette")
    try:
        cassette = FrozenFirstMoveCassette.from_mapping(cassette_raw)
        cassette.attest_contract(
            behavior_id=behavior_id,
            request_sha256=str(pair["first_action_sha256"]),
            action_sha256=str(pair["fallback_action_sha256"]),
            asset_hashes=pair["asset_hashes"],
        )
    except FrozenFirstMoveCassetteError as exc:
        raise PrefreezeBatchError(str(exc)) from exc
    if cassette.request_sha256 != pair["fallback_request_sha256"]:
        raise PrefreezeBatchError(f"cassette request mismatch: {pair_id}")
    cassette_sha = canonical_sha256(cassette.to_dict())
    if context.challenge.get("status") == READY_STATUS:
        declared = _require_mapping(
            entry.get("first_move_cassette"), "first_move_cassette"
        ).get("cassette_sha256")
        if declared != cassette_sha:
            raise PrefreezeBatchError(
                f"ready challenge cassette hash mismatch: {pair_id}"
            )

    work_dir = (
        Path(_require_string(pair_plan.get("work_dir"), "prefreeze work_dir"))
        .expanduser()
        .resolve()
    )
    assets = _load_asset_rows(
        pair_plan.get("asset_result_path"),
        behavior_id=behavior_id,
        expected_hashes=pair["asset_hashes"],
        work_dir=work_dir,
    )
    return _PairCapture(
        behavior_id=behavior_id,
        cassette=cassette,
        assets=assets,
        expected_asset_hashes=dict(pair["asset_hashes"]),
        attestation={
            "order": pair_plan["order"],
            "pair_id": pair_id,
            "behavior_id": behavior_id,
            "challenge_entry_sha256": entry["challenge_entry_sha256"],
            "prefreeze_wrapper_path": str(wrapper_path),
            "prefreeze_wrapper_canonical_sha256": canonical_sha256(wrapper),
            "prefreeze_spec_sha256": pair_plan["prefreeze_spec_sha256"],
            "first_move_cassette_sha256": cassette_sha,
            "ordered_asset_sha256": dict(pair["asset_hashes"]),
        },
    )


def _emit_prefreeze_results(
    *,
    primary: _PlanContext,
    selected: Sequence[tuple[_PairCapture, _PlanContext, int]],
    attempt_summaries: Sequence[Mapping[str, Any]],
    output_dir: str | Path,
) -> dict[str, Any]:
    destination = Path(output_dir).expanduser().resolve()
    if destination.exists() or destination.is_symlink():
        raise PrefreezeBatchError(
            f"refusing to overwrite existing finalization directory: {destination}"
        )
    if len(selected) != EXPECTED_PAIR_COUNT:
        raise PrefreezeBatchError("prefreeze result coverage mismatch")
    bundle = FrozenFirstMoveCassetteBundle(
        tuple(capture.cassette for capture, _context, _ordinal in selected)
    )

    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        destination.mkdir(mode=0o700, exist_ok=False)
    except FileExistsError as exc:
        raise PrefreezeBatchError(
            f"refusing to overwrite existing finalization directory: {destination}"
        ) from exc
    destination.chmod(0o700)
    bundle_path = destination / "first_move_cassettes.private.json"
    assets_path = destination / "captured_assets.private.json"
    attestation_path = destination / "prefreeze_batch_attestation.private.json"

    combined_behaviors: dict[str, dict[str, dict[str, str]]] = {}
    attestations: list[dict[str, Any]] = []
    for index, (capture, source_context, attempt_ordinal) in enumerate(
        selected, start=1
    ):
        output_rows: dict[str, dict[str, str]] = {}
        for asset_id, source in capture.assets.items():
            suffix = source.suffix.lower()
            if not re.fullmatch(r"\.[a-z0-9]{1,10}", suffix):
                suffix = ".asset"
            copied = destination / "assets" / f"{index:02d}" / f"{asset_id}{suffix}"
            _copy_private_asset(source, copied)
            if asset_file_sha256(copied) != capture.expected_asset_hashes[asset_id]:
                raise PrefreezeBatchError(
                    "private copied asset hash mismatch: "
                    f"{capture.behavior_id}/{asset_id}"
                )
            output_rows[asset_id] = {
                "path": str(copied),
                "sha256": str(capture.expected_asset_hashes[asset_id]),
            }
        combined_behaviors[capture.behavior_id] = output_rows
        row = dict(capture.attestation)
        row["source_plan_sha256"] = source_context.plan["plan_sha256"]
        row["source_attempt_ordinal"] = attempt_ordinal
        attestations.append(row)

    bundle_value = bundle.to_dict()
    assets_value = {"behaviors": combined_behaviors}
    _exclusive_write_json(bundle_path, bundle_value)
    _exclusive_write_json(assets_path, assets_value)
    source_plan_hashes = [str(row["source_plan_sha256"]) for row in attempt_summaries]
    aggregate_plan_sha = (
        source_plan_hashes[0]
        if len(source_plan_hashes) == 1
        else canonical_sha256(
            {
                "selection_policy": "earliest_caller_order_fully_valid_capture",
                "source_plan_sha256": source_plan_hashes,
            }
        )
    )
    attestation: dict[str, Any] = {
        "schema_version": 1,
        "artifact_type": BATCH_FINAL_ARTIFACT,
        "plan_sha256": aggregate_plan_sha,
        "challenge_manifest_sha256": primary.challenge_sha256,
        "challenge_status": primary.challenge["status"],
        "pair_count": EXPECTED_PAIR_COUNT,
        "cassette_bundle": {
            "path": str(bundle_path),
            "canonical_sha256": canonical_sha256(bundle_value),
            "file_sha256": sha256_file(bundle_path),
            "mode": "0600",
            "target_response_included": False,
        },
        "asset_manifest": {
            "path": str(assets_path),
            "canonical_sha256": canonical_sha256(assets_value),
            "file_sha256": sha256_file(assets_path),
            "mode": "0600",
        },
        "pairs": attestations,
        "consolidation": {
            "selection_policy": "earliest_caller_order_fully_valid_capture",
            "invalid_completed_attempt_policy": "skip_and_count",
            "attempt_count": len(attempt_summaries),
            "attempts": [dict(row) for row in attempt_summaries],
        },
        "raw_attack_or_response_text_included": False,
        "model_servers_started": False,
        "model_servers_stopped": False,
        "accelerator_allocation_performed": False,
        "source_plan_path": str(primary.resolved_plan),
        "source_plan_paths": [
            str(row["source_plan_path"]) for row in attempt_summaries
        ],
    }
    attestation["attestation_sha256"] = canonical_sha256(attestation)
    _exclusive_write_json(attestation_path, attestation)
    return attestation


def finalize_prefreeze_batch(
    *,
    plan_path: str | Path,
    output_dir: str | Path,
) -> dict[str, Any]:
    """Strictly finalize one plan; any incomplete or invalid pair fails closed."""

    context = _validate_plan_context(plan_path)
    selected = [
        (_validate_pair_capture(context, prepared), context, 1)
        for prepared in context.pairs
    ]
    summary = {
        "attempt_ordinal": 1,
        "source_plan_path": str(context.resolved_plan),
        "source_plan_sha256": context.plan["plan_sha256"],
        "pair_outcome_counts": {
            "selected_valid": EXPECTED_PAIR_COUNT,
            "valid_not_selected": 0,
            "partial": 0,
            "invalid_completed": 0,
        },
    }
    return _emit_prefreeze_results(
        primary=context,
        selected=selected,
        attempt_summaries=[summary],
        output_dir=output_dir,
    )


def consolidate_prefreeze_batches(
    *,
    plan_paths: Sequence[str | Path],
    output_dir: str | Path,
) -> dict[str, Any]:
    """Select each pair's earliest fully valid capture across compatible plans.

    Completed but invalid captures are skipped and counted.  Consolidation
    still fails closed if no fully valid capture remains for any pair.
    """

    if (
        isinstance(plan_paths, (str, bytes))
        or not isinstance(plan_paths, Sequence)
        or not plan_paths
    ):
        raise PrefreezeBatchError("consolidation requires at least one batch plan")
    contexts = [_validate_plan_context(path) for path in plan_paths]
    expected_compatibility = contexts[0].compatibility_sha256
    for ordinal, context in enumerate(contexts[1:], start=2):
        if context.compatibility_sha256 != expected_compatibility:
            raise PrefreezeBatchError(
                f"incompatible prefreeze batch plan at attempt ordinal {ordinal}"
            )

    outcomes = [
        {
            "selected_valid": 0,
            "valid_not_selected": 0,
            "partial": 0,
            "invalid_completed": 0,
        }
        for _context in contexts
    ]
    selected: list[tuple[_PairCapture, _PlanContext, int]] = []
    for pair_index in range(EXPECTED_PAIR_COUNT):
        valid: list[tuple[int, _PairCapture]] = []
        for context_index, context in enumerate(contexts):
            prepared = context.pairs[pair_index]
            if not _capture_outputs_complete(prepared.plan):
                outcomes[context_index]["partial"] += 1
                continue
            try:
                capture = _validate_pair_capture(context, prepared)
            except (OSError, PrefreezeBatchError):
                outcomes[context_index]["invalid_completed"] += 1
                continue
            valid.append((context_index, capture))
        if not valid:
            pair_id = contexts[0].pairs[pair_index].entry["pair_id"]
            partial_count = sum(row["partial"] for row in outcomes)
            invalid_count = sum(row["invalid_completed"] for row in outcomes)
            raise PrefreezeBatchError(
                "no fully valid completed capture for pair "
                f"{pair_id}; partial={partial_count}, invalid_completed={invalid_count}"
            )
        chosen_index, chosen_capture = valid[0]
        outcomes[chosen_index]["selected_valid"] += 1
        for later_index, _capture in valid[1:]:
            outcomes[later_index]["valid_not_selected"] += 1
        selected.append((chosen_capture, contexts[chosen_index], chosen_index + 1))

    summaries = [
        {
            "attempt_ordinal": ordinal,
            "source_plan_path": str(context.resolved_plan),
            "source_plan_sha256": context.plan["plan_sha256"],
            "pair_outcome_counts": outcomes[ordinal - 1],
        }
        for ordinal, context in enumerate(contexts, start=1)
    ]
    return _emit_prefreeze_results(
        primary=contexts[0],
        selected=selected,
        attempt_summaries=summaries,
        output_dir=output_dir,
    )


__all__ = [
    "BATCH_FINAL_ARTIFACT",
    "BATCH_PLAN_ARTIFACT",
    "DEFAULT_DECODING_CONFIG",
    "PrefreezeBatchError",
    "consolidate_prefreeze_batches",
    "finalize_prefreeze_batch",
    "prepare_prefreeze_batch",
]
