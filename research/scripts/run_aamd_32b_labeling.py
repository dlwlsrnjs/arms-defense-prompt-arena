#!/usr/bin/env python3
"""Wait for one designated GPU, run frozen 32B RCAT-7 labeling, then stop it.

This orchestrator never co-locates with another compute process.  It waits for the
requested physical GPU, launches the run-bound ephemeral service through
``manage_aamd_vllm.py``, generates every deterministic source chunk, writes a
completion receipt, and explicitly stops the captured service in ``finally``.
The independent service watchdog remains the hard-deadline fallback.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Mapping, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_ROOT = Path("/data1/users/ljk98/Amrs-runtime")
MANAGER = REPOSITORY_ROOT / "research/scripts/manage_aamd_vllm.py"
GENERATOR = REPOSITORY_ROOT / "research/scripts/generate_aamd_taxonomy_proposals.py"
MODEL_ID = "Qwen/Qwen2.5-VL-32B-Instruct"
MODEL_REVISION = "7cfb30d71a1f4f49a57592323337a4a4727301da"
RUNTIME_ATTESTATION_TYPE = "aamd-managed-vllm-runtime-v1"
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
BUNDLE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,159}$")
TRAILING_BUNDLE_ORDINAL_RE = re.compile(
    r"^(?P<stem>[A-Za-z0-9][A-Za-z0-9._:@+\-]*)-(?P<ordinal>[0-9]+)$"
)
EXPECTED_MEMORY_FLOW_SHA256 = "4209aa264955815f17afce5309ad49f411a65bfdce937c89b60ebce4d711332e"
EXPECTED_ARTIFACT_MANIFEST_SHA256 = "0efa74bd5a7ce36698566749e4e2c71bafdfb100b6e52658557cb06939bd4424"
EXPECTED_PACK_ID = "qwen2.5-vl-3b-public-v2-round1-payload-free"
PUBLIC_RECORD_FIELDS = (
    "benchmark",
    "record_handle",
    "title",
    "question",
    "instructions",
    "evidence",
    "taxonomy_id",
    "taxonomy_version",
    "taxonomy_hash",
    "locked_axes",
    "locked_axes_hash",
)
EXPECTED_VISIBILITY_MASK = {
    "schema_version": 3,
    "strategy": "abstract-evidence-plus-frozen-taxonomy-proposal",
    "forbidden": [
        "raw_payload",
        "raw_prompt",
        "attack_text",
        "harmful_request",
        "target_response",
        "attack_method",
        "outcome",
        "ground_truth",
        "system_prompt",
    ],
    "visible": [*PUBLIC_RECORD_FIELDS, "llm_proposal"],
}


class OrchestratorError(RuntimeError):
    """Raised on a terminal orchestration failure."""


def derive_review_bundle_id(source_bundle_id: Any) -> str:
    """Derive an injective, human-readable review ID from one source ID.

    Frozen pilot sources use a terminal numeric bundle ordinal, for example
    ``attack-memory-v1-rcat7-pilot-000``.  Insert the review marker immediately
    before that ordinal instead of relying on a ``-source-`` token that is not
    present in the real frozen IDs.  IDs without a terminal ordinal receive a
    suffix.  Both transformations preserve the complete source identifier, so
    distinct valid source IDs cannot collapse to the same review ID.
    """

    if not isinstance(source_bundle_id, str) or not BUNDLE_ID_RE.fullmatch(
        source_bundle_id
    ):
        raise OrchestratorError("source bundle ID is outside the generator contract")
    terminal = TRAILING_BUNDLE_ORDINAL_RE.fullmatch(source_bundle_id)
    if terminal is None:
        candidate = f"{source_bundle_id}-review"
    else:
        candidate = (
            f"{terminal.group('stem')}-review-{terminal.group('ordinal')}"
        )
    if not BUNDLE_ID_RE.fullmatch(candidate):
        raise OrchestratorError(
            "derived review bundle ID is outside the generator contract"
        )
    if candidate == source_bundle_id:
        raise OrchestratorError("derived review bundle ID equals its source ID")
    return candidate


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise OrchestratorError("source value is not canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def strict_json_bytes(raw: bytes, *, name: str) -> Any:
    def pairs(values: Sequence[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise OrchestratorError(f"{name} has duplicate key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise OrchestratorError(f"{name} has non-finite number: {value}")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=reject_constant)
    except UnicodeDecodeError as exc:
        raise OrchestratorError(f"{name} is not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise OrchestratorError(f"{name} is not strict JSON") from exc


def verify_source_directory(source_dir: Path) -> list[Path]:
    """Verify every frozen input before waiting for or allocating a GPU."""

    manifest_path = source_dir / "source-manifest.json"
    try:
        manifest_raw = manifest_path.read_bytes()
    except OSError as exc:
        raise OrchestratorError("source-manifest.json is unavailable") from exc
    manifest = strict_json_bytes(manifest_raw, name="source manifest")
    if not isinstance(manifest, dict):
        raise OrchestratorError("source manifest must be an object")
    if manifest.get("status") != "pilot_only" or manifest.get("claim_bearing") is not False:
        raise OrchestratorError("source must remain non-claim-bearing pilot data")
    source = manifest.get("source")
    if not isinstance(source, dict) or (
        source.get("memory_flow_sha256") != EXPECTED_MEMORY_FLOW_SHA256
        or source.get("artifact_manifest_sha256")
        != EXPECTED_ARTIFACT_MANIFEST_SHA256
        or source.get("pack_id") != EXPECTED_PACK_ID
    ):
        raise OrchestratorError("source artifact commitments do not match the frozen pack")
    projection = manifest.get("projection")
    entries = manifest.get("bundles")
    if not isinstance(projection, dict) or not isinstance(entries, list) or not entries:
        raise OrchestratorError("source manifest has no bundle projection")
    if projection.get("visibility_mask") != EXPECTED_VISIBILITY_MASK:
        raise OrchestratorError("source visibility mask drifted")
    expected_visibility_hash = canonical_sha256(EXPECTED_VISIBILITY_MASK)
    if projection.get("visibility_mask_hash") != expected_visibility_hash:
        raise OrchestratorError("source visibility-mask hash drifted")

    discovered = sorted(source_dir.glob("source-bundle-*.json"))
    if len(discovered) != len(entries) or projection.get("bundle_count") != len(entries):
        raise OrchestratorError("source bundle count does not match its manifest")
    ordered: list[Path] = []
    total_tasks = 0
    for ordinal, (entry, path) in enumerate(zip(entries, discovered)):
        if not isinstance(entry, dict):
            raise OrchestratorError("source bundle manifest entry must be an object")
        recorded_path = Path(str(entry.get("path", "")))
        if not recorded_path.is_absolute():
            recorded_path = source_dir / recorded_path
        recorded_path = recorded_path.resolve(strict=False)
        if recorded_path != path.resolve(strict=False):
            raise OrchestratorError(f"source bundle path mismatch at ordinal {ordinal}")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry.get("file_sha256"):
            raise OrchestratorError(f"source bundle file hash mismatch: {path.name}")
        bundle = strict_json_bytes(raw, name=path.name)
        if not isinstance(bundle, dict):
            raise OrchestratorError(f"source bundle must be an object: {path.name}")
        if canonical_sha256(bundle) != entry.get("canonical_sha256"):
            raise OrchestratorError(f"source canonical hash mismatch: {path.name}")
        if bundle.get("bundle_id") != entry.get("bundle_id"):
            raise OrchestratorError(f"source bundle ID mismatch: {path.name}")
        if bundle.get("visibility_mask_hash") != expected_visibility_hash:
            raise OrchestratorError(f"source visibility hash mismatch: {path.name}")
        tasks = bundle.get("tasks")
        if not isinstance(tasks, list) or len(tasks) != entry.get("task_count"):
            raise OrchestratorError(f"source task count mismatch: {path.name}")
        queue: list[dict[str, Any]] = []
        for task_ordinal, task in enumerate(tasks):
            if not isinstance(task, dict):
                raise OrchestratorError(f"source task is not an object: {path.name}")
            try:
                record = {field: task[field] for field in PUBLIC_RECORD_FIELDS}
            except KeyError as exc:
                raise OrchestratorError(
                    f"source public record is incomplete: {path.name}"
                ) from exc
            if canonical_sha256(record) != task.get("record_hash"):
                raise OrchestratorError(f"source record hash mismatch: {path.name}")
            queue.append(
                {
                    "ordinal": task_ordinal,
                    "task_id": task.get("task_id"),
                    "record_handle": task.get("record_handle"),
                    "record_hash": task.get("record_hash"),
                }
            )
        queue_hash = canonical_sha256(queue)
        if queue_hash != bundle.get("queue_hash") or queue_hash != entry.get("queue_hash"):
            raise OrchestratorError(f"source queue hash mismatch: {path.name}")
        total_tasks += len(tasks)
        ordered.append(path)
    if total_tasks != projection.get("task_count"):
        raise OrchestratorError("source total task count does not match its manifest")
    return ordered


def runtime_path(value: str | Path, *, name: str) -> Path:
    path = Path(value).expanduser().resolve(strict=False)
    runtime = RUNTIME_ROOT.resolve(strict=False)
    try:
        path.relative_to(runtime)
    except ValueError as exc:
        raise OrchestratorError(f"{name} must resolve below {runtime}") from exc
    if path == runtime:
        raise OrchestratorError(f"{name} must be below {runtime}")
    return path


def atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    )
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def build_runtime_attestation(
    *,
    launch_result: Mapping[str, Any],
    identity_path: Path,
    run_id: str,
    gpu: int,
    port: int,
) -> dict[str, Any]:
    """Bind the exact persisted manager identity to a conservative provenance claim."""

    try:
        identity_raw = identity_path.read_bytes()
    except OSError as exc:
        raise OrchestratorError("manager service identity is unavailable") from exc
    identity = strict_json_bytes(identity_raw, name="manager service identity")
    if not isinstance(identity, dict) or launch_result.get("identity") != identity:
        raise OrchestratorError("manager launch response and service identity differ")
    if (
        identity.get("run_id") != run_id
        or identity.get("gpu_index") != gpu
        or identity.get("cuda_visible_devices") != str(gpu)
        or identity.get("port") != port
        or identity.get("model_id") != MODEL_ID
    ):
        raise OrchestratorError("manager service identity does not match the run")
    if identity.get("pid") != identity.get("process_group_id") or identity.get(
        "pid"
    ) != identity.get("session_id"):
        raise OrchestratorError("manager service is not a captured session leader")
    provenance = identity.get("runtime_provenance")
    if not isinstance(provenance, dict) or (
        provenance.get("model_id") != MODEL_ID
        or provenance.get("model_revision") != MODEL_REVISION
    ):
        raise OrchestratorError("manager runtime provenance is not the frozen model")
    attestation_method = provenance.get("model_tree_attestation")
    if not isinstance(attestation_method, str) or not attestation_method:
        raise OrchestratorError("manager runtime provenance lacks its method")
    for field in (
        "pid",
        "process_start_ticks",
        "process_group_id",
        "session_id",
        "hard_deadline_seconds",
    ):
        if not isinstance(identity.get(field), int):
            raise OrchestratorError(f"manager identity field is invalid: {field}")
    record = {
        "schema_version": 1,
        "attestation_type": RUNTIME_ATTESTATION_TYPE,
        "run_id": run_id,
        "manager_script_file_sha256": hashlib.sha256(MANAGER.read_bytes()).hexdigest(),
        "service_identity": identity,
        "service_identity_file_sha256": hashlib.sha256(identity_raw).hexdigest(),
        "service_identity_canonical_sha256": canonical_sha256(identity),
        "runtime_provenance": provenance,
        "runtime_provenance_canonical_sha256": canonical_sha256(provenance),
        "lifecycle": {
            "model_server_lifecycle_managed": True,
            "gpu_lifecycle_managed": True,
            "identity_captured_before_service_release": True,
            "watchdog_identity_captured_before_service_release": True,
            "hard_deadline_watchdog_armed": True,
            "cleanup_verification_state": "pending_at_generation",
        },
        "weights": {
            "provenance_attested": True,
            "snapshot_content_hashed": False,
            "attestation_method": attestation_method,
            "model_revision": MODEL_REVISION,
        },
    }
    return record


def persist_runtime_attestation(
    path: Path, record: Mapping[str, Any]
) -> dict[str, Any]:
    if path.exists() or path.is_symlink():
        raise OrchestratorError("runtime attestation path must be unused")
    atomic_json(path, record)
    raw = path.read_bytes()
    persisted = strict_json_bytes(raw, name="runtime attestation")
    if persisted != record:
        raise OrchestratorError("persisted runtime attestation differs from memory")
    return {
        "schema_version": 1,
        "file_sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": canonical_sha256(record),
        "attestation": dict(record),
    }


def run_json(command: Sequence[str], *, env: Mapping[str, str]) -> Mapping[str, Any]:
    completed = subprocess.run(
        list(command),
        cwd=REPOSITORY_ROOT,
        env=dict(env),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    if completed.returncode != 0:
        raise OrchestratorError(
            f"command failed ({completed.returncode}): {' '.join(command)}\n"
            f"{completed.stderr[-4000:]}"
        )
    try:
        value = json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise OrchestratorError("command did not return JSON") from exc
    if not isinstance(value, dict):
        raise OrchestratorError("command JSON must be an object")
    return value


def gpu_is_empty(index: int) -> tuple[bool, str]:
    command = [
        "nvidia-smi",
        "--query-gpu=index,uuid,memory.used",
        "--format=csv,noheader,nounits",
    ]
    gpu = subprocess.run(
        command,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    matches = []
    for line in gpu.stdout.splitlines():
        parts = [part.strip() for part in line.split(",")]
        if len(parts) == 3 and int(parts[0]) == index:
            matches.append((parts[1], int(parts[2])))
    if len(matches) != 1:
        raise OrchestratorError(f"GPU {index} could not be resolved exactly once")
    uuid, used = matches[0]
    apps = subprocess.run(
        [
            "nvidia-smi",
            "--query-compute-apps=gpu_uuid,pid,process_name,used_memory",
            "--format=csv,noheader,nounits",
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    matches_apps = [
        line.strip()
        for line in apps.stdout.splitlines()
        if line.strip().startswith(uuid + ",")
    ]
    return not matches_apps and used <= 512, (
        f"gpu={index} uuid={uuid} memory_used_mib={used} processes={len(matches_apps)}"
    )


def endpoint_ready(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            payload = json.loads(response.read())
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return False
    values = payload.get("data") if isinstance(payload, dict) else None
    return isinstance(values, list) and any(
        isinstance(item, dict) and item.get("id") == MODEL_ID for item in values
    )


def run_monitored_generator(
    command: Sequence[str],
    *,
    env: Mapping[str, str],
    identity_path: Path,
    deadline_monotonic: float,
) -> subprocess.CompletedProcess[str]:
    """Run one chunk while continuously enforcing the captured service identity."""

    process = subprocess.Popen(
        list(command),
        cwd=REPOSITORY_ROOT,
        env=dict(env),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    def stop_generator() -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    try:
        while process.poll() is None:
            if time.monotonic() >= deadline_monotonic:
                stop_generator()
                raise OrchestratorError("generator exceeded the service hard deadline")
            service_status = run_json(
                [
                    sys.executable,
                    str(MANAGER),
                    "status",
                    "--identity",
                    str(identity_path),
                ],
                env=env,
            )
            if not service_status.get("ok"):
                stop_generator()
                raise OrchestratorError(
                    "service ownership drifted during generation: "
                    f"{service_status.get('identity_error')}"
                )
            if not service_status.get("live") or not service_status.get("port_open"):
                stop_generator()
                raise OrchestratorError("vLLM service died during generation")
            time.sleep(10)
        stdout, stderr = process.communicate(timeout=10)
    except Exception:
        stop_generator()
        raise
    return subprocess.CompletedProcess(
        args=list(command),
        returncode=int(process.returncode or 0),
        stdout=stdout,
        stderr=stderr,
    )


def validate_generated_pair(
    output_path: Path,
    manifest_path: Path,
    *,
    expected_bundle_id: str,
    expected_runtime_attestation: Mapping[str, Any],
) -> dict[str, Any]:
    output_raw = output_path.read_bytes()
    if len(output_raw) >= 1024 * 1024:
        raise OrchestratorError(f"generated bundle exceeds the Site limit: {output_path}")
    output = strict_json_bytes(output_raw, name=output_path.name)
    manifest_raw = manifest_path.read_bytes()
    manifest = strict_json_bytes(manifest_raw, name=manifest_path.name)
    if not isinstance(output, dict) or not isinstance(manifest, dict):
        raise OrchestratorError("generated output pair must contain JSON objects")
    if output.get("bundle_id") != expected_bundle_id or manifest.get("status") != "complete":
        raise OrchestratorError("generated output identity/status mismatch")
    artifacts = manifest.get("artifacts")
    artifact = artifacts.get("output_bundle") if isinstance(artifacts, dict) else None
    if not isinstance(artifact, dict):
        raise OrchestratorError("generation manifest lacks output commitment")
    if manifest.get("runtime_attestation") != expected_runtime_attestation:
        raise OrchestratorError("generation manifest runtime attestation mismatch")
    generator = manifest.get("generator")
    contract = manifest.get("contract")
    if not isinstance(generator, dict) or not isinstance(contract, dict) or (
        generator.get("model_server_lifecycle_managed") is not True
        or generator.get("gpu_lifecycle_managed") is not True
        or contract.get("weights_provenance_attested") is not True
        or contract.get("weights_snapshot_attested") is not False
        or contract.get("weights_snapshot_content_hashed") is not False
    ):
        raise OrchestratorError("generation manifest overstates or omits provenance")
    canonical_hash = canonical_sha256(output)
    if (
        artifact.get("file_sha256") != hashlib.sha256(output_raw).hexdigest()
        or artifact.get("canonical_sha256") != canonical_hash
    ):
        raise OrchestratorError("generated output commitment mismatch")
    declared_output = manifest.get("output")
    if not isinstance(declared_output, dict) or (
        declared_output.get("bundle_id") != expected_bundle_id
        or declared_output.get("bundle_canonical_sha256") != canonical_hash
        or declared_output.get("task_count") != len(output.get("tasks", []))
    ):
        raise OrchestratorError("generation manifest output projection mismatch")
    attestation_hash = expected_runtime_attestation.get("canonical_sha256")
    attestation_file_hash = expected_runtime_attestation.get("file_sha256")
    tasks = output.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        raise OrchestratorError("generated output has no tasks")
    for task in tasks:
        proposal = task.get("llm_proposal") if isinstance(task, dict) else None
        provenance = proposal.get("provenance") if isinstance(proposal, dict) else None
        if not isinstance(provenance, dict) or provenance.get("model_id") != MODEL_ID:
            raise OrchestratorError("generated proposal model provenance is invalid")
    return {
        "bundle_id": expected_bundle_id,
        "task_count": len(output.get("tasks", [])),
        "bundle_canonical_sha256": canonical_hash,
        "bundle_file_sha256": hashlib.sha256(output_raw).hexdigest(),
        "manifest_file_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "manifest_canonical_sha256": canonical_sha256(manifest),
        "runtime_attestation_file_sha256": attestation_file_hash,
        "runtime_attestation_canonical_sha256": attestation_hash,
        "source_bundle_projection_canonical_sha256": manifest.get("inputs", {}).get(
            "source_bundle_projection_canonical_sha256"
        ),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source-dir", required=True)
    parser.add_argument("--gpu", type=int, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--wait-seconds", type=int, default=21600)
    parser.add_argument("--service-deadline-seconds", type=int, default=28800)
    parser.add_argument("--poll-seconds", type=int, default=20)
    parser.add_argument("--startup-seconds", type=int, default=1800)
    args = parser.parse_args(argv)

    if not RUN_ID_RE.fullmatch(args.run_id):
        raise OrchestratorError("invalid run ID")
    if args.gpu not in range(8):
        raise OrchestratorError("GPU index must be in [0, 7]")
    if not 1024 <= args.port <= 65535:
        raise OrchestratorError("invalid port")
    if min(
        args.wait_seconds,
        args.service_deadline_seconds,
        args.poll_seconds,
        args.startup_seconds,
    ) <= 0:
        raise OrchestratorError("timing arguments must be positive")

    run_root = runtime_path(args.run_root, name="run_root")
    source_dir = runtime_path(args.source_dir, name="source_dir")
    generated_dir = run_root / "generated"
    if generated_dir.is_symlink():
        raise OrchestratorError("generated_dir must not be a symlink")
    generated_dir.mkdir(parents=True, exist_ok=True)
    if generated_dir.resolve() != generated_dir or not generated_dir.is_dir():
        raise OrchestratorError("generated_dir must be a real runtime directory")
    status_path = run_root / "orchestrator-status.json"
    service_identity = run_root / "service/identity.json"
    completion_path = run_root / "service/completion.json"
    watchdog_identity = run_root / "service/watchdog-identity.json"
    runtime_attestation_path = run_root / "runtime-attestation.json"
    if any(
        path.exists() or path.is_symlink()
        for path in (
            service_identity,
            completion_path,
            watchdog_identity,
            runtime_attestation_path,
        )
    ):
        raise OrchestratorError(
            "service/attestation paths must be unused; choose a fresh run root"
        )
    env = os.environ.copy()
    env.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "TMPDIR": str(run_root / "tmp"),
            "PYTHONPYCACHEPREFIX": str(run_root / "cache/pycache"),
        }
    )

    source_bundles = verify_source_directory(source_dir)
    source_manifest_initial_raw = (source_dir / "source-manifest.json").read_bytes()
    source_manifest_initial_sha256 = hashlib.sha256(
        source_manifest_initial_raw
    ).hexdigest()
    source_bundle_file_sha256 = {
        path: hashlib.sha256(path.read_bytes()).hexdigest() for path in source_bundles
    }
    review_bundle_ids: dict[Path, str] = {}
    for path in source_bundles:
        source = strict_json_bytes(path.read_bytes(), name=path.name)
        if not isinstance(source, dict):
            raise OrchestratorError(f"source bundle must be an object: {path.name}")
        review_bundle_ids[path] = derive_review_bundle_id(source.get("bundle_id"))
    if len(set(review_bundle_ids.values())) != len(review_bundle_ids):
        raise OrchestratorError("derived review bundle IDs are not unique")
    generator_revision = f"sha256:{hashlib.sha256(GENERATOR.read_bytes()).hexdigest()}"
    wait_started = time.monotonic()
    last_observation = "not_checked"
    while time.monotonic() - wait_started < args.wait_seconds:
        empty, last_observation = gpu_is_empty(args.gpu)
        atomic_json(
            status_path,
            {
                "run_id": args.run_id,
                "status": "waiting_for_gpu" if not empty else "gpu_available",
                "gpu_observation": last_observation,
                "source_bundle_count": len(source_bundles),
            },
        )
        if empty:
            break
        print(last_observation, flush=True)
        time.sleep(args.poll_seconds)
    else:
        raise OrchestratorError(
            f"GPU did not become empty before wait deadline: {last_observation}"
        )

    failures: list[dict[str, Any]] = []
    successes: list[dict[str, Any]] = []
    runtime_attestation: dict[str, Any] | None = None
    try:
        launch = run_json(
            [
                sys.executable,
                str(MANAGER),
                "launch",
                "--run-root",
                str(run_root),
                "--run-id",
                args.run_id,
                "--gpu",
                str(args.gpu),
                "--port",
                str(args.port),
                "--deadline-seconds",
                str(args.service_deadline_seconds),
                "--gpu-memory-utilization",
                "0.94",
                "--max-model-len",
                "16384",
                "--max-num-seqs",
                "1",
            ],
            env=env,
        )
        print(json.dumps({"event": "launched", **launch}, sort_keys=True), flush=True)
        runtime_attestation = persist_runtime_attestation(
            runtime_attestation_path,
            build_runtime_attestation(
                launch_result=launch,
                identity_path=service_identity,
                run_id=args.run_id,
                gpu=args.gpu,
                port=args.port,
            ),
        )
        generation_deadline = (
            time.monotonic() + args.service_deadline_seconds - 300
        )
        atomic_json(
            status_path,
            {
                "run_id": args.run_id,
                "status": "starting_model",
                "gpu": args.gpu,
                "port": args.port,
                "source_bundle_count": len(source_bundles),
            },
        )

        ready_url = f"http://127.0.0.1:{args.port}/v1/models"
        startup_started = time.monotonic()
        while time.monotonic() - startup_started < args.startup_seconds:
            if endpoint_ready(ready_url):
                break
            service_status = run_json(
                [
                    sys.executable,
                    str(MANAGER),
                    "status",
                    "--identity",
                    str(service_identity),
                ],
                env=env,
            )
            if not service_status.get("ok"):
                raise OrchestratorError(
                    f"vLLM allocation identity failed: {service_status.get('identity_error')}"
                )
            if not service_status.get("live"):
                raise OrchestratorError("vLLM exited before endpoint readiness")
            time.sleep(10)
        else:
            raise OrchestratorError("vLLM endpoint readiness timed out")

        for index, source_path in enumerate(source_bundles):
            freshly_verified = verify_source_directory(source_dir)
            if freshly_verified != source_bundles:
                raise OrchestratorError("source bundle set changed during generation")
            source_raw = source_path.read_bytes()
            if hashlib.sha256(source_raw).hexdigest() != source_bundle_file_sha256[
                source_path
            ]:
                raise OrchestratorError("source bundle changed after preflight")
            source = strict_json_bytes(source_raw, name=source_path.name)
            if not isinstance(source, dict):
                raise OrchestratorError("source bundle changed after verification")
            output_id = review_bundle_ids[source_path]
            output_path = generated_dir / f"review-bundle-{index:03d}.json"
            manifest_path = generated_dir / f"generation-manifest-{index:03d}.json"
            atomic_json(
                status_path,
                {
                    "run_id": args.run_id,
                    "status": "generating",
                    "current_bundle_index": index,
                    "source_bundle_count": len(source_bundles),
                    "completed_bundles": len(successes),
                    "failed_bundles": len(failures),
                },
            )
            command = [
                sys.executable,
                str(GENERATOR),
                "--input-bundle",
                str(source_path),
                "--endpoint",
                f"http://127.0.0.1:{args.port}/v1",
                "--output-bundle-id",
                output_id,
                "--generator-code-revision",
                generator_revision,
                "--runtime-attestation",
                str(runtime_attestation_path),
                "--runtime-attestation-file-sha256",
                str(runtime_attestation["file_sha256"]),
                "--runtime-attestation-canonical-sha256",
                str(runtime_attestation["canonical_sha256"]),
                "--output",
                str(output_path),
                "--manifest",
                str(manifest_path),
                "--timeout-seconds",
                "600",
            ]
            print(
                json.dumps(
                    {"event": "generation_start", "index": index, "id": output_id},
                    sort_keys=True,
                ),
                flush=True,
            )
            completed = run_monitored_generator(
                command,
                env=env,
                identity_path=service_identity,
                deadline_monotonic=generation_deadline,
            )
            if completed.returncode == 0:
                receipt = strict_json_bytes(
                    completed.stdout.strip().splitlines()[-1].encode("utf-8"),
                    name=f"generator receipt {index}",
                )
                if not isinstance(receipt, dict):
                    raise OrchestratorError("generator receipt must be an object")
                verified = validate_generated_pair(
                    output_path,
                    manifest_path,
                    expected_bundle_id=output_id,
                    expected_runtime_attestation=runtime_attestation,
                )
                if receipt.get("bundle_canonical_sha256") != verified.get(
                    "bundle_canonical_sha256"
                ):
                    raise OrchestratorError("generator receipt hash mismatch")
                successes.append({**dict(receipt), **verified})
                print(
                    json.dumps(
                        {
                            "event": "generation_complete",
                            "index": index,
                            **successes[-1],
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
            else:
                failure = {
                    "index": index,
                    "source": str(source_path),
                    "manifest": str(manifest_path),
                    "returncode": completed.returncode,
                    "stderr_tail": completed.stderr[-4000:],
                }
                failures.append(failure)
                print(
                    json.dumps({"event": "generation_failed", **failure}, sort_keys=True),
                    flush=True,
                )

        result = {
            "run_id": args.run_id,
            "status": "complete" if not failures else "partial_failure",
            "gpu": args.gpu,
            "port": args.port,
            "source_bundle_count": len(source_bundles),
            "successful_bundle_count": len(successes),
            "failed_bundle_count": len(failures),
            "successes": successes,
            "failures": failures,
        }
        if not failures:
            if verify_source_directory(source_dir) != source_bundles:
                raise OrchestratorError("source bundle set changed before publication")
            source_manifest_raw = (source_dir / "source-manifest.json").read_bytes()
            if hashlib.sha256(source_manifest_raw).hexdigest() != (
                source_manifest_initial_sha256
            ):
                raise OrchestratorError("source manifest changed during generation")
            import_manifest = {
                "schema_version": 2,
                "run_id": args.run_id,
                "status": "validated_for_pilot_import",
                "claim_bearing": False,
                "source_manifest_file_sha256": source_manifest_initial_sha256,
                "generator_code_revision": generator_revision,
                "runtime_attestation_path": str(runtime_attestation_path),
                "runtime_attestation": runtime_attestation,
                "bundle_count": len(successes),
                "task_count": sum(int(item["task_count"]) for item in successes),
                "bundles": successes,
            }
            atomic_json(generated_dir / "review-bundle-manifest.json", import_manifest)
            result["import_manifest"] = str(
                generated_dir / "review-bundle-manifest.json"
            )
        atomic_json(run_root / "labeling-result.json", result)
        atomic_json(
            completion_path,
            {
                "run_id": args.run_id,
                "status": result["status"],
                "successful_bundle_count": len(successes),
                "failed_bundle_count": len(failures),
            },
        )
        atomic_json(status_path, result)
        print(json.dumps(result, sort_keys=True), flush=True)
        return 0 if not failures else 3
    finally:
        # The manager may have durably captured an identity and then failed
        # before returning JSON. If so, this run still owns the identity path
        # because it was required to be unused above, so always attempt cleanup.
        if service_identity.exists():
            completion_error: Exception | None = None
            if not completion_path.exists():
                try:
                    atomic_json(
                        completion_path,
                        {
                            "run_id": args.run_id,
                            "status": "aborted",
                            "successful_bundle_count": len(successes),
                            "failed_bundle_count": len(failures),
                        },
                    )
                except Exception as exc:
                    completion_error = exc
            try:
                stopped = run_json(
                    [
                        sys.executable,
                        str(MANAGER),
                        "stop",
                        "--identity",
                        str(service_identity),
                        "--reason",
                        "orchestrator_finally",
                    ],
                    env=env,
                )
                print(
                    json.dumps({"event": "service_stop", **stopped}, sort_keys=True),
                    flush=True,
                )
            except Exception as exc:
                print(
                    json.dumps(
                        {"event": "service_stop_error", "error": str(exc)},
                        sort_keys=True,
                    ),
                    file=sys.stderr,
                    flush=True,
                )
                raise OrchestratorError(
                    f"service cleanup verification failed: {exc}"
                ) from exc
            if completion_error is not None:
                raise OrchestratorError(
                    "service stopped but completion receipt failed: "
                    f"{completion_error}"
                ) from completion_error


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OrchestratorError as exc:
        print(f"orchestrator error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
