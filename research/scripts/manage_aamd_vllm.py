#!/usr/bin/env python3
"""Safely launch and stop one run-bound, ephemeral AAMD vLLM service.

The manager rejects other workloads; an explicitly fingerprinted, memory-bounded
keepalive may be allowed by a local profile and is never signaled.
It records PID, process start time, process group, GPU UUID, port, model identity,
CUDA visibility, and run ID.  Both explicit shutdown and an independently armed
watchdog revalidate that immutable identity before signaling the process group.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


# Keep direct CLI and importlib-based test loading equivalent.
if str(Path(__file__).resolve().parents[1]) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.aamd_runtime_config import load_runtime_config
from scripts.aamd_gpu_policy import background_allowed

LOCAL_RUNTIME = load_runtime_config()
RUNTIME_ROOT = Path(LOCAL_RUNTIME["runtime_root"])
MODEL_ID = "Qwen/Qwen2.5-VL-32B-Instruct"
MODEL_REVISION = "7cfb30d71a1f4f49a57592323337a4a4727301da"
MODEL_PATH = Path(LOCAL_RUNTIME["model_path"])
VLLM = Path(LOCAL_RUNTIME["vllm_executable"])
VLLM_VERSION = LOCAL_RUNTIME["vllm_version"]
VLLM_ENTRYPOINT_SHA256 = LOCAL_RUNTIME["vllm_entrypoint_sha256"]
MODEL_SMALL_FILE_SHA256 = {
    "config.json": "6a6152f97a7c91db7574ba13a6586fd2846438088befcce811511ad430d82280",
    "model.safetensors.index.json": "43636311918da5a5996dacd09e9699545ed81d02898d21a55d9c37b03b93f7d6",
    "tokenizer_config.json": "4abd3520120e266da84c0864fee064d1fb10806f02225911a47253dd38dc5f56",
}
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
WATCHDOG_POLL_SECONDS = 10.0
WATCHDOG_READY_TIMEOUT_SECONDS = 30.0
SERVER_ENV_PASSTHROUGH = (
    "AAMD_RUNTIME_CONFIG",
    "CUDA_DEVICE_ORDER",
    "CUDA_HOME",
    "CUDA_PATH",
    "LANG",
    "LC_ALL",
    "LD_LIBRARY_PATH",
    "NVIDIA_DRIVER_CAPABILITIES",
    "NVIDIA_VISIBLE_DEVICES",
    "PATH",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "TZ",
)


class ServiceError(RuntimeError):
    """Raised when service identity or allocation checks fail."""


@dataclass(frozen=True)
class ProcessIdentity:
    """Immutable Linux process identity used before every signal."""

    pid: int
    state: str
    parent_pid: int
    process_group_id: int
    session_id: int
    start_ticks: int
    cuda_visible_devices: str
    run_id: str
    command: tuple[str, ...]
    environment_zeroized: bool = False
    environment_unreadable: bool = False
    uid: int | None = None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def attest_runtime() -> dict[str, Any]:
    """Fail closed on model/vLLM drift before any process is started."""

    if VLLM_ENTRYPOINT_SHA256 is None:
        raise ServiceError("pin vllm_entrypoint_sha256 in AAMD_RUNTIME_CONFIG before launch")
    runtime_python = VLLM.parent / "python"
    measured_version = subprocess.run(
        [str(runtime_python), "-c", "import importlib.metadata; print(importlib.metadata.version('vllm'))"],
        check=True, text=True, capture_output=True, timeout=30,
    ).stdout.strip()
    if measured_version != VLLM_VERSION:
        raise ServiceError("installed vLLM version differs from runtime profile")
    if sha256_file(VLLM) != VLLM_ENTRYPOINT_SHA256:
        raise ServiceError("vLLM entrypoint hash drifted")
    for name, expected in MODEL_SMALL_FILE_SHA256.items():
        path = MODEL_PATH / name
        if not path.is_file() or sha256_file(path) != expected:
            raise ServiceError(f"model provenance file drifted: {name}")

    index = json.loads((MODEL_PATH / "model.safetensors.index.json").read_text())
    weight_map = index.get("weight_map") if isinstance(index, dict) else None
    if not isinstance(weight_map, dict):
        raise ServiceError("model index has no weight_map")
    indexed_shards = sorted(set(weight_map.values()))
    local_shards = sorted(path.name for path in MODEL_PATH.glob("model-*.safetensors"))
    if indexed_shards != local_shards or len(local_shards) != 18:
        raise ServiceError("model shard set does not match the frozen index")

    metadata_root = MODEL_PATH / ".cache/huggingface/download"
    entries: list[dict[str, Any]] = []
    for path in sorted(item for item in MODEL_PATH.iterdir() if item.is_file()):
        metadata_path = metadata_root / f"{path.name}.metadata"
        try:
            lines = metadata_path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise ServiceError(f"missing download metadata for {path.name}") from exc
        if len(lines) < 2 or lines[0] != MODEL_REVISION:
            raise ServiceError(f"model revision metadata drifted for {path.name}")
        entries.append(
            {
                "name": path.name,
                "size": path.stat().st_size,
                "revision": lines[0],
                "upstream_object_id": lines[1],
            }
        )
    tree_bytes = json.dumps(
        entries, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return {
        "model_id": MODEL_ID,
        "model_revision": MODEL_REVISION,
        "model_tree_metadata_sha256": hashlib.sha256(tree_bytes).hexdigest(),
        "model_tree_attestation": "hf_revision_object_ids_plus_local_sizes",
        "model_file_count": len(entries),
        "model_shard_count": len(local_shards),
        "small_file_sha256": dict(MODEL_SMALL_FILE_SHA256),
        "vllm_version": VLLM_VERSION,
        "vllm_entrypoint_sha256": VLLM_ENTRYPOINT_SHA256,
    }


def runtime_path(value: str | Path, *, label: str) -> Path:
    path = Path(value).expanduser().resolve(strict=False)
    runtime = RUNTIME_ROOT.resolve(strict=False)
    try:
        path.relative_to(runtime)
    except ValueError as exc:
        raise ServiceError(f"{label} must resolve below {runtime}") from exc
    if path == runtime:
        raise ServiceError(f"{label} must be below {runtime}")
    return path


def ensure_runtime_directory(path: Path, *, label: str) -> Path:
    """Create/validate one real directory below the runtime root.

    ``runtime_path`` resolves symlinks, which is appropriate for user-supplied
    roots but insufficient for derived service/cache/tmp children: an existing
    child symlink could otherwise redirect identities, logs, or growing data out
    of the run root.  Reject the link itself before and after creation and require
    the resolved directory to remain exactly the intended child.
    """

    intended = Path(os.path.abspath(path))
    if intended.is_symlink():
        raise ServiceError(f"{label} must not be a symlink")
    intended.mkdir(parents=True, exist_ok=True, mode=0o700)
    if intended.is_symlink() or not intended.is_dir():
        raise ServiceError(f"{label} must be a real directory")
    resolved = runtime_path(intended, label=label)
    if resolved != intended:
        raise ServiceError(f"{label} must not traverse a symlink")
    return resolved


def atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
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


def short_temp_alias(tmp_root: Path) -> Path:
    """Use a private short alias: Linux Unix-domain sockets have a 107-byte limit.

    The backing files stay in the run-scoped runtime directory. Never follow an
    existing alias unless its owner and exact target match this run.
    """
    target = tmp_root.resolve()
    suffix = hashlib.sha256(str(target).encode()).hexdigest()[:16]
    alias = Path("/tmp") / f"aamd-{os.getuid()}-{suffix}"
    try:
        alias.symlink_to(target, target_is_directory=True)
    except FileExistsError:
        pass
    if (not alias.is_symlink() or alias.lstat().st_uid != os.getuid()
            or os.readlink(alias) != str(target)):
        raise ServiceError("unsafe or conflicting short temporary alias")
    if len(str(alias).encode()) + 1 + 36 > 107:
        raise ServiceError("temporary IPC alias exceeds Unix socket path limit")
    return alias


def build_server_environment(
    *, run_id: str, gpu_index: int, tmp_root: Path, cache_root: Path
) -> dict[str, str]:
    """Build a minimal server environment with run-scoped writable state.

    In particular, do not forward arbitrary caller credentials (including the
    optional local OpenAI API key) into the long-lived model server.
    """

    env = {
        key: os.environ[key]
        for key in SERVER_ENV_PASSTHROUGH
        if key in os.environ
    }
    ipc_tmp = short_temp_alias(tmp_root)
    inherited_path = env.get("PATH", "")
    env["PATH"] = os.pathsep.join(
        part for part in (str(VLLM.parent), inherited_path) if part
    )

    cache_paths = {
        "HF_HOME": ensure_runtime_directory(
            cache_root / "huggingface", label="huggingface_cache"
        ),
        "HUGGINGFACE_HUB_CACHE": ensure_runtime_directory(
            cache_root / "huggingface/hub", label="huggingface_hub_cache"
        ),
        "HF_ASSETS_CACHE": ensure_runtime_directory(
            cache_root / "huggingface/assets", label="huggingface_assets_cache"
        ),
        "TRANSFORMERS_CACHE": ensure_runtime_directory(
            cache_root / "huggingface/transformers", label="transformers_cache"
        ),
        "XDG_CACHE_HOME": cache_root,
        "VLLM_CACHE_ROOT": ensure_runtime_directory(
            cache_root / "vllm", label="vllm_cache"
        ),
        "FLASHINFER_WORKSPACE_BASE": ensure_runtime_directory(
            cache_root / "flashinfer", label="flashinfer_cache"
        ),
        "TORCH_HOME": ensure_runtime_directory(
            cache_root / "torch", label="torch_cache"
        ),
        "TORCH_EXTENSIONS_DIR": ensure_runtime_directory(
            cache_root / "torch-extensions", label="torch_extensions_cache"
        ),
        "TORCHINDUCTOR_CACHE_DIR": ensure_runtime_directory(
            cache_root / "torchinductor", label="torchinductor_cache"
        ),
        "TRITON_CACHE_DIR": ensure_runtime_directory(
            cache_root / "triton", label="triton_cache"
        ),
        "CUDA_CACHE_PATH": ensure_runtime_directory(
            cache_root / "cuda", label="cuda_cache"
        ),
        "PYTHONPYCACHEPREFIX": ensure_runtime_directory(
            cache_root / "pycache", label="python_cache"
        ),
    }
    env.update({key: str(path) for key, path in cache_paths.items()})
    env.update(
        {
            "AAMD_RUN_ID": run_id,
            "CUDA_VISIBLE_DEVICES": str(gpu_index),
            "HF_HUB_CACHE": env["HUGGINGFACE_HUB_CACHE"],
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "TMPDIR": str(ipc_tmp),
            "TMP": str(ipc_tmp),
            "TEMP": str(ipc_tmp),
            "VLLM_RPC_BASE_PATH": str(ipc_tmp),
            "TOKENIZERS_PARALLELISM": "false",
        }
    )
    return env


def nvidia_lines(*args: str) -> list[str]:
    completed = subprocess.run(
        ["nvidia-smi", *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def gpu_identity(index: int) -> tuple[str, int]:
    lines = nvidia_lines(
        "--query-gpu=index,uuid,memory.used",
        "--format=csv,noheader,nounits",
    )
    matches: list[tuple[str, int]] = []
    for line in lines:
        parts = [part.strip() for part in line.split(",")]
        if len(parts) == 3 and int(parts[0]) == index:
            matches.append((parts[1], int(parts[2])))
    if len(matches) != 1:
        raise ServiceError(f"GPU {index} was not resolved exactly once")
    return matches[0]


def compute_processes(gpu_uuid: str) -> list[dict[str, str]]:
    lines = nvidia_lines(
        "--query-compute-apps=gpu_uuid,pid,process_name,used_memory",
        "--format=csv,noheader,nounits",
    )
    rows: list[dict[str, str]] = []
    for line in lines:
        parts = [part.strip() for part in line.split(",", 3)]
        if len(parts) == 4 and parts[0] == gpu_uuid:
            rows.append(
                {
                    "gpu_uuid": parts[0],
                    "pid": parts[1],
                    "process_name": parts[2],
                    "used_memory_mib": parts[3],
                }
            )
    return rows


def require_empty_gpu(index: int) -> tuple[str, int]:
    gpu_uuid, used_memory = gpu_identity(index)
    processes = compute_processes(gpu_uuid)
    foreign = [row for row in processes if not background_allowed(row, LOCAL_RUNTIME["allowed_background_processes"])]
    if foreign:
        raise ServiceError(
            f"GPU {index} has compute processes; refusing launch: {foreign}"
        )
    accounted = sum(int(row["used_memory_mib"]) for row in processes)
    if used_memory > 512 + accounted:
        raise ServiceError(
            f"GPU {index} reports {used_memory} MiB without an attributable compute process"
        )
    return gpu_uuid, used_memory


def require_free_port(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as handle:
        handle.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            handle.bind(("127.0.0.1", port))
        except OSError as exc:
            raise ServiceError(f"loopback port {port} is already in use") from exc


def proc_identity(pid: int) -> ProcessIdentity:
    proc = Path("/proc") / str(pid)
    stat = (proc / "stat").read_text(encoding="utf-8")
    closing = stat.rfind(")")
    if closing < 0:
        raise ServiceError("malformed /proc stat")
    suffix = stat[closing + 2 :].split()
    if len(suffix) <= 19:
        raise ServiceError("truncated /proc stat")
    state = suffix[0]
    parent_pid = int(suffix[1])
    pgid = int(suffix[2])
    session_id = int(suffix[3])
    start_ticks = int(suffix[19])
    cmdline = tuple(
        item.decode("utf-8")
        for item in (proc / "cmdline").read_bytes().split(b"\0")
        if item
    )
    environment_unreadable = False
    try:
        environ_bytes = (proc / "environ").read_bytes()
    except PermissionError:
        # Metadata remains readable on hardened /proc mounts. Do not infer run
        # ownership here; only the narrow live-ancestry check may accept it.
        environ_bytes = b""
        environment_unreadable = True
    environment_zeroized = bool(environ_bytes) and not environ_bytes.strip(b"\0")
    environ = environ_bytes.split(b"\0")
    cuda_values = tuple(
        item.decode("utf-8").split("=", 1)[1]
        for item in environ
        if item.startswith(b"CUDA_VISIBLE_DEVICES=")
    )
    cuda = cuda_values[0] if len(cuda_values) == 1 else ""
    run_values = tuple(
        item.decode("utf-8").split("=", 1)[1]
        for item in environ
        if item.startswith(b"AAMD_RUN_ID=")
    )
    run_id = run_values[0] if len(run_values) == 1 else ""
    return ProcessIdentity(
        pid=pid,
        state=state,
        parent_pid=parent_pid,
        process_group_id=pgid,
        session_id=session_id,
        start_ticks=start_ticks,
        cuda_visible_devices=cuda,
        run_id=run_id,
        command=cmdline,
        environment_zeroized=environment_zeroized,
        environment_unreadable=environment_unreadable,
        uid=proc.stat().st_uid,
    )


def process_group_members(process_group_id: int) -> list[ProcessIdentity]:
    """Return every live member of one process group, failing closed on ambiguity."""

    members: list[ProcessIdentity] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text(encoding="utf-8")
            closing = stat.rfind(")")
            suffix = stat[closing + 2 :].split()
            if closing < 0 or len(suffix) <= 2 or int(suffix[2]) != process_group_id:
                continue
            member = proc_identity(int(entry.name))
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError, ValueError, ServiceError) as exc:
            raise ServiceError(
                f"cannot verify process {entry.name} in group {process_group_id}: {exc}"
            ) from exc
        if member.state not in {"X", "x", "Z"}:
            members.append(member)
    return sorted(members, key=lambda item: item.pid)


def read_identity(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ServiceError(f"cannot read service identity: {exc}") from exc
    if not isinstance(value, dict):
        raise ServiceError("service identity must be an object")
    return value


def process_executable(pid: int) -> Path:
    return (Path("/proc") / str(pid) / "exe").resolve(strict=True)


def process_gpu_uuids(pid: int) -> set[str]:
    rows = nvidia_lines("--query-compute-apps=gpu_uuid,pid", "--format=csv,noheader,nounits")
    return {parts[0].strip() for row in rows
            if len(parts := row.split(",")) == 2 and parts[1].strip() == str(pid)}


def verified_service_members(identity: Mapping[str, Any]) -> list[ProcessIdentity]:
    """Retry a complete identity snapshot when a process exits during inspection."""
    for attempt in range(5):
        try:
            return _verified_service_members_once(identity)
        except FileNotFoundError as exc:
            if attempt == 4:
                raise ServiceError("process identities kept changing during verification") from exc
            time.sleep(0.05)
    raise AssertionError("unreachable")


def _verified_service_members_once(identity: Mapping[str, Any]) -> list[ProcessIdentity]:
    """Revalidate every live member before status checks or signals.

    The leader may exit before vLLM engine children.  The run marker, CUDA
    visibility, process group, session, and start-time boundary let us retain a
    strong identity without mistaking an unrelated process for this service.
    """

    leader_pid = int(identity["pid"])
    leader_start = int(identity["process_start_ticks"])
    process_group_id = int(identity["process_group_id"])
    session_id = int(identity["session_id"])
    cuda = str(identity["cuda_visible_devices"])
    run_id = str(identity["run_id"])
    if process_group_id != leader_pid or session_id != leader_pid:
        raise ServiceError("captured service is not a session-leading process group")
    members = process_group_members(process_group_id)
    members_by_pid = {member.pid: member for member in members}

    def descends_from_leader(member: ProcessIdentity) -> bool:
        """Accept a zeroized child only when its live ancestry reaches our leader."""

        seen = {member.pid}
        parent_pid = member.parent_pid
        while parent_pid != leader_pid:
            if parent_pid in seen:
                return False
            seen.add(parent_pid)
            parent = members_by_pid.get(parent_pid)
            if parent is None:
                return False
            parent_pid = parent.parent_pid
        return True

    for member in members:
        if member.process_group_id != process_group_id:
            raise ServiceError("service process group changed; refusing to signal")
        if member.session_id != session_id:
            raise ServiceError("service session changed; refusing to signal")
        if member.start_ticks < leader_start:
            raise ServiceError("older process joined service group; refusing to signal")
        if member.pid == leader_pid:
            if member.start_ticks != leader_start:
                raise ServiceError("leader PID was reused; refusing to signal")
            if member.cuda_visible_devices != cuda:
                raise ServiceError("service CUDA identity changed; refusing to signal")
            if member.run_id != run_id:
                raise ServiceError("service run marker changed; refusing to signal")
            continue
        if member.cuda_visible_devices == cuda and member.run_id == run_id:
            continue
        leader = members_by_pid.get(leader_pid)
        live_ancestry = leader is not None and descends_from_leader(member)
        zeroized_descendant = member.environment_zeroized and live_ancestry
        unreadable_descendant = False
        if not zeroized_descendant and not member.cuda_visible_devices and not member.run_id and live_ancestry:
            # setproctitle can erase inherited environment without leaving
            # an all-NUL buffer. Require OS ancestry, same UID/executable and
            # exact EngineCore title. Before CUDA registration attachments
            # may be empty; once attached they must match the captured GPU.
            gpu_uuid, _ = gpu_identity(int(identity["gpu_index"]))
            attachments = process_gpu_uuids(member.pid)
            same_executable = process_executable(member.pid) == process_executable(leader.pid)
            unreadable_descendant = (
                member.uid == leader.uid == os.getuid()
                and gpu_uuid == identity["gpu_uuid"]
                and member.start_ticks > leader_start
                and member.command and member.command[0] == "VLLM::EngineCore"
                and same_executable
                and attachments.issubset({str(identity["gpu_uuid"])})
            )
        if not (
            not member.cuda_visible_devices and not member.run_id
            and (zeroized_descendant or unreadable_descendant)
        ):
            raise ServiceError("service child identity changed; refusing to signal")
    return members


def identity_matches(identity: Mapping[str, Any]) -> bool:
    return bool(verified_service_members(identity))


def signal_service(identity: Mapping[str, Any], sig: signal.Signals) -> bool:
    """Signal only after a fresh whole-group identity check."""

    members = verified_service_members(identity)
    if not members:
        return False
    try:
        os.killpg(int(identity["process_group_id"]), sig)
    except ProcessLookupError:
        return False
    return True


def port_is_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as handle:
        handle.settimeout(0.5)
        return handle.connect_ex(("127.0.0.1", port)) == 0


def run_marked_processes(run_id: str) -> list[ProcessIdentity]:
    marked: list[ProcessIdentity] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            process = proc_identity(int(entry.name))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        except (OSError, UnicodeError, ValueError, ServiceError):
            continue
        if process.state not in {"X", "x", "Z"} and process.run_id == run_id:
            marked.append(process)
    return sorted(marked, key=lambda item: item.pid)


def verify_release(identity: Mapping[str, Any]) -> dict[str, Any]:
    members = verified_service_members(identity)
    if members:
        raise ServiceError(
            f"captured service group still has live processes: {[p.pid for p in members]}"
        )
    marked = run_marked_processes(str(identity["run_id"]))
    if marked:
        raise ServiceError(
            f"run-marked processes remain outside captured group: {[p.pid for p in marked]}"
        )
    if port_is_open(int(identity["port"])):
        raise ServiceError("captured vLLM port remains open after shutdown")

    gpu_uuid, used_memory = gpu_identity(int(identity["gpu_index"]))
    if gpu_uuid != str(identity["gpu_uuid"]):
        raise ServiceError("GPU UUID changed during shutdown verification")
    processes = compute_processes(gpu_uuid)
    run_gpu_pids: list[int] = []
    foreign_processes: list[dict[str, str]] = []
    for row in processes:
        try:
            process = proc_identity(int(row["pid"]))
        except (OSError, UnicodeError, ValueError, ServiceError):
            foreign_processes.append(row)
            continue
        if process.run_id == str(identity["run_id"]):
            run_gpu_pids.append(process.pid)
        else:
            foreign_processes.append(row)
    if run_gpu_pids:
        raise ServiceError(f"run GPU processes remain: {run_gpu_pids}")
    if not foreign_processes and used_memory > 512:
        raise ServiceError(
            f"GPU retains {used_memory} MiB without an attributable compute process"
        )
    return {
        "port_closed": True,
        "run_processes_gone": True,
        "gpu_memory_used_mib": used_memory,
        "foreign_gpu_processes": foreign_processes,
    }


def stop_captured(identity: Mapping[str, Any], *, reason: str) -> dict[str, Any]:
    pid = int(identity["pid"])
    already_stopped = not identity_matches(identity)
    if not already_stopped:
        signal_service(identity, signal.SIGTERM)
    for _ in range(60):
        if not identity_matches(identity):
            break
        time.sleep(1)
    else:
        if identity_matches(identity):
            signal_service(identity, signal.SIGKILL)
            time.sleep(2)
    if identity_matches(identity):
        raise ServiceError("captured service remains alive after shutdown")
    release = verify_release(identity)
    return {
        "ok": True,
        "already_stopped": already_stopped,
        "pid": pid,
        "reason": reason,
        "verification": release,
    }


def stop_identity(identity_path: Path, *, reason: str) -> dict[str, Any]:
    return stop_captured(read_identity(identity_path), reason=reason)


def foreign_gpu_processes(identity: Mapping[str, Any]) -> list[dict[str, str]]:
    """Return compute processes not attributable to the captured service."""

    members = verified_service_members(identity)
    member_pids = {member.pid for member in members}
    gpu_uuid, _used_memory = gpu_identity(int(identity["gpu_index"]))
    if gpu_uuid != str(identity["gpu_uuid"]):
        raise ServiceError("GPU UUID changed while watchdog was active")

    foreign: list[dict[str, str]] = []
    for row in compute_processes(gpu_uuid):
        try:
            pid = int(row["pid"])
        except (KeyError, TypeError, ValueError):
            foreign.append(row)
            continue
        if pid in member_pids or background_allowed(row, identity.get("allowed_background_processes", [])):
            continue
        try:
            process = proc_identity(pid)
        except (OSError, UnicodeError, ValueError, ServiceError):
            foreign.append(row)
            continue
        if process.run_id != str(identity["run_id"]):
            foreign.append(row)
    return foreign


def publish_watchdog_ready(
    *,
    ready_path: Path,
    identity_path: Path,
    completion_path: Path,
    run_id: str,
    deadline: int,
) -> dict[str, Any]:
    """Durably acknowledge that the independent watchdog entered its loop."""

    if ready_path.exists():
        raise ServiceError("watchdog ready path must be unused")
    current = proc_identity(os.getpid())
    if (
        current.state in {"X", "x", "Z"}
        or current.process_group_id != current.pid
        or current.session_id != current.pid
    ):
        raise ServiceError("watchdog is not a live session leader")
    receipt = {
        "run_id": run_id,
        "pid": current.pid,
        "process_start_ticks": current.start_ticks,
        "process_group_id": current.process_group_id,
        "session_id": current.session_id,
        "identity_path": str(identity_path),
        "completion_path": str(completion_path),
        "deadline_seconds": deadline,
    }
    atomic_json(ready_path, receipt)
    return receipt


def wait_for_watchdog_ready(
    ready_path: Path,
    *,
    expected: Mapping[str, Any],
    process: subprocess.Popen[bytes],
    timeout_seconds: float = WATCHDOG_READY_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Verify a child-authored ready receipt before releasing the server gate."""

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        returncode = process.poll()
        if returncode is not None:
            raise ServiceError(
                f"watchdog exited before readiness with status {returncode}"
            )
        if ready_path.exists():
            ready = read_identity(ready_path)
            fields = (
                "run_id",
                "pid",
                "process_start_ticks",
                "process_group_id",
                "session_id",
                "identity_path",
                "completion_path",
                "deadline_seconds",
            )
            if any(ready.get(field) != expected.get(field) for field in fields):
                raise ServiceError("watchdog ready receipt does not match launch identity")
            if not watchdog_identity_matches(ready):
                raise ServiceError("watchdog exited after publishing readiness")
            return ready
        time.sleep(0.05)
    raise ServiceError("watchdog readiness timed out")


def _watchdog_event(event: str, **details: Any) -> None:
    try:
        print(json.dumps({"event": event, **details}, sort_keys=True), flush=True)
    except OSError:
        # A full/broken log must not disarm the cleanup watchdog.
        pass


def watchdog(
    *,
    identity_path: Path,
    completion_path: Path,
    ready_path: Path,
    run_id: str,
    deadline: int,
) -> int:
    publish_watchdog_ready(
        ready_path=ready_path,
        identity_path=identity_path,
        completion_path=completion_path,
        run_id=run_id,
        deadline=deadline,
    )
    started = time.monotonic()
    identity_seen = False
    completion_seen = False
    latched_shutdown_reason: str | None = None
    captured_identity: dict[str, Any] | None = None
    while True:
        now = time.monotonic()
        deadline_reached = now - started >= deadline
        shutdown_reason = latched_shutdown_reason

        identity_exists = identity_path.exists()
        identity_seen = identity_seen or identity_exists
        if identity_exists:
            try:
                observed_identity = read_identity(identity_path)
                if observed_identity.get("run_id") != run_id:
                    raise ServiceError("service identity run ID mismatch")
                if captured_identity is None:
                    captured_identity = observed_identity
                elif observed_identity != captured_identity:
                    raise ServiceError("service identity file changed after capture")
            except Exception as exc:
                shutdown_reason = "service_identity_error"
                _watchdog_event(
                    "watchdog_identity_error", error_type=type(exc).__name__
                )

        if completion_path.exists():
            completion_seen = True
            completion_valid = False
            try:
                completion = read_identity(completion_path)
                if completion.get("run_id") != run_id:
                    raise ServiceError("completion run ID mismatch")
                completion_valid = True
                shutdown_reason = "completion"
            except Exception as exc:
                # The watchdog must survive malformed/transient completion I/O.
                shutdown_reason = "completion_receipt_error"
                _watchdog_event(
                    "watchdog_completion_error", error_type=type(exc).__name__
                )
            if completion_valid and not identity_exists and not identity_seen:
                print(
                    json.dumps(
                        {"ok": True, "reason": "completion_without_identity"},
                        sort_keys=True,
                    ),
                    flush=True,
                )
                return 0

        if deadline_reached:
            if not identity_exists and not identity_seen:
                print(
                    json.dumps(
                        {"ok": True, "reason": "deadline_without_identity"},
                        sort_keys=True,
                    ),
                    flush=True,
                )
                return 0
            shutdown_reason = (
                "hard_deadline_after_completion"
                if completion_seen
                else "hard_deadline"
            )

        if captured_identity is not None and shutdown_reason is None:
            try:
                foreign = foreign_gpu_processes(captured_identity)
            except Exception as exc:
                # Observation failure is itself fail-closed: stop only our
                # captured service, and retain the watchdog if that stop fails.
                shutdown_reason = "gpu_monitor_error"
                _watchdog_event(
                    "watchdog_gpu_monitor_error", error_type=type(exc).__name__
                )
            else:
                if foreign:
                    shutdown_reason = "foreign_gpu_process"
                    _watchdog_event(
                        "watchdog_foreign_gpu_process",
                        process_count=len(foreign),
                    )

        if shutdown_reason is not None:
            latched_shutdown_reason = shutdown_reason

        if shutdown_reason is not None:
            if captured_identity is None:
                _watchdog_event(
                    "watchdog_identity_missing",
                    reason=shutdown_reason,
                )
            else:
                try:
                    result = stop_captured(
                        captured_identity, reason=shutdown_reason
                    )
                except Exception as exc:
                    _watchdog_event(
                        "watchdog_stop_retry",
                        reason=shutdown_reason,
                        error_type=type(exc).__name__,
                    )
                else:
                    print(json.dumps(result, sort_keys=True), flush=True)
                    return 0

        time.sleep(WATCHDOG_POLL_SECONDS)


def watchdog_identity_matches(identity: Mapping[str, Any]) -> bool:
    pid = int(identity["pid"])
    try:
        current = proc_identity(pid)
    except (FileNotFoundError, ProcessLookupError):
        return False
    if current.state in {"X", "x", "Z"}:
        return False
    if current.start_ticks != int(identity["process_start_ticks"]):
        raise ServiceError("watchdog PID was reused")
    if current.process_group_id != pid or current.session_id != pid:
        raise ServiceError("watchdog process-group identity changed")
    joined = " ".join(current.command)
    required = (str(Path(__file__).resolve()), "watchdog", str(identity["run_id"]))
    if any(token not in joined for token in required):
        raise ServiceError("watchdog command identity changed")
    return True


def stop_watchdog(identity_path: Path) -> dict[str, Any]:
    if not identity_path.exists():
        return {"present": False, "stopped": True}
    identity = read_identity(identity_path)
    for _ in range(30):
        if not watchdog_identity_matches(identity):
            return {"present": True, "stopped": True, "forced": False}
        time.sleep(1)
    if watchdog_identity_matches(identity):
        os.kill(int(identity["pid"]), signal.SIGTERM)
    for _ in range(5):
        if not watchdog_identity_matches(identity):
            return {"present": True, "stopped": True, "forced": True}
        time.sleep(1)
    raise ServiceError("captured watchdog remains alive after completion")


def exec_server(gate_fd: int, command: Sequence[str]) -> int:
    """Block a fresh session leader until its identity and watchdog are durable."""

    try:
        token = os.read(gate_fd, 1)
    finally:
        os.close(gate_fd)
    if token != b"1":
        return 70
    if not command:
        raise ServiceError("exec-server requires a server command")
    os.execvpe(command[0], list(command), os.environ)
    return 70


def launch(args: argparse.Namespace) -> dict[str, Any]:
    if not RUN_ID_RE.fullmatch(args.run_id):
        raise ServiceError("invalid run ID")
    if args.gpu not in range(8):
        raise ServiceError("GPU index must be in [0, 7]")
    run_root = runtime_path(args.run_root, label="run_root")
    run_root = ensure_runtime_directory(run_root, label="run_root")
    service_root = ensure_runtime_directory(
        run_root / "service", label="service_root"
    )
    tmp_root = ensure_runtime_directory(run_root / "tmp", label="tmp_root")
    cache_root = ensure_runtime_directory(run_root / "cache", label="cache_root")
    identity_path = service_root / "identity.json"
    completion_path = service_root / "completion.json"
    watchdog_identity_path = service_root / "watchdog-identity.json"
    watchdog_ready_path = service_root / "watchdog-ready.json"
    if any(
        path.exists()
        for path in (
            identity_path,
            completion_path,
            watchdog_identity_path,
            watchdog_ready_path,
        )
    ):
        raise ServiceError("service identity paths must be unused")
    if not VLLM.is_file() or not MODEL_PATH.is_dir():
        raise ServiceError("vLLM executable or model directory is unavailable")
    provenance = attest_runtime()
    require_free_port(args.port)
    gpu_uuid, preflight_memory = require_empty_gpu(args.gpu)
    lock_root = ensure_runtime_directory(RUNTIME_ROOT / "locks", label="lock_root")
    gpu_lock_path = lock_root / f"aamd-{gpu_uuid}.lock"
    gpu_lock_fd = os.open(gpu_lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(gpu_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(gpu_lock_fd)
        raise ServiceError(f"GPU allocation lock is already held: {gpu_lock_path}") from exc
    os.set_inheritable(gpu_lock_fd, True)
    env = build_server_environment(
        run_id=args.run_id,
        gpu_index=args.gpu,
        tmp_root=tmp_root,
        cache_root=cache_root,
    )
    watchdog_env = {
        key: os.environ[key]
        for key in SERVER_ENV_PASSTHROUGH
        if key in os.environ
    }
    watchdog_env.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPYCACHEPREFIX": str(cache_root / "pycache"),
            "TMPDIR": str(tmp_root),
            "TMP": str(tmp_root),
            "TEMP": str(tmp_root),
        }
    )
    command = [
        str(VLLM),
        "serve",
        str(MODEL_PATH),
        "--host",
        "127.0.0.1",
        "--port",
        str(args.port),
        "--served-model-name",
        MODEL_ID,
        "--dtype",
        "bfloat16",
        "--tensor-parallel-size",
        "1",
        "--gpu-memory-utilization",
        str(args.gpu_memory_utilization),
        "--max-model-len",
        str(args.max_model_len),
        "--max-num-seqs",
        str(args.max_num_seqs),
        "--enable-prefix-caching",
        "--generation-config",
        "vllm",
    ]

    process: subprocess.Popen[bytes] | None = None
    watchdog_process: subprocess.Popen[bytes] | None = None
    identity: dict[str, Any] | None = None
    watchdog_snapshot: ProcessIdentity | None = None
    gate_read = -1
    gate_write = -1
    released = False
    try:
        # Close the allocation race immediately before creating the gated leader.
        gpu_uuid_second, _ = require_empty_gpu(args.gpu)
        if gpu_uuid_second != gpu_uuid:
            raise ServiceError("GPU UUID changed during allocation")
        require_free_port(args.port)

        gate_read, gate_write = os.pipe()
        server_log = (service_root / "server.log").open("xb", buffering=0)
        gated_command = [
            sys.executable,
            str(Path(__file__).resolve()),
            "exec-server",
            "--gate-fd",
            str(gate_read),
            "--",
            *command,
        ]
        try:
            process = subprocess.Popen(
                gated_command,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=server_log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                close_fds=True,
                pass_fds=(gate_read, gpu_lock_fd),
            )
        finally:
            server_log.close()
            os.close(gate_read)
            gate_read = -1

        snapshot = proc_identity(process.pid)
        if snapshot.state in {"X", "x", "Z"}:
            raise ServiceError("gated service leader exited before identity capture")
        if (
            snapshot.process_group_id != process.pid
            or snapshot.session_id != process.pid
            or snapshot.cuda_visible_devices != str(args.gpu)
            or snapshot.run_id != args.run_id
        ):
            raise ServiceError("gated service leader identity is invalid")
        identity = {
            "run_id": args.run_id,
            "pid": process.pid,
            "process_start_ticks": snapshot.start_ticks,
            "process_group_id": snapshot.process_group_id,
            "session_id": snapshot.session_id,
            "gpu_index": args.gpu,
            "gpu_uuid": gpu_uuid,
            "gpu_memory_used_mib_before_launch": preflight_memory,
            "allowed_background_processes": LOCAL_RUNTIME["allowed_background_processes"],
            "cuda_visible_devices": snapshot.cuda_visible_devices,
            "port": args.port,
            "model_id": MODEL_ID,
            "model_path": str(MODEL_PATH),
            "capture_command": list(snapshot.command),
            "server_command": command,
            "server_log": str(service_root / "server.log"),
            "watchdog_identity": str(watchdog_identity_path),
            "watchdog_ready": str(watchdog_ready_path),
            "hard_deadline_seconds": args.deadline_seconds,
            "gpu_lock_path": str(gpu_lock_path),
            "runtime_provenance": provenance,
        }
        watchdog_log = (service_root / "watchdog.log").open("xb", buffering=0)
        watchdog_command = [
            sys.executable,
            str(Path(__file__).resolve()),
            "watchdog",
            "--identity",
            str(identity_path),
            "--completion",
            str(completion_path),
            "--ready",
            str(watchdog_ready_path),
            "--run-id",
            args.run_id,
            "--deadline-seconds",
            str(args.deadline_seconds),
        ]
        try:
            watchdog_process = subprocess.Popen(
                watchdog_command,
                stdin=subprocess.DEVNULL,
                stdout=watchdog_log,
                stderr=subprocess.STDOUT,
                env=watchdog_env,
                start_new_session=True,
                close_fds=True,
            )
        finally:
            watchdog_log.close()
        watchdog_snapshot = proc_identity(watchdog_process.pid)
        if (
            watchdog_snapshot.state in {"X", "x", "Z"}
            or watchdog_snapshot.process_group_id != watchdog_process.pid
            or watchdog_snapshot.session_id != watchdog_process.pid
        ):
            raise ServiceError("watchdog identity is invalid")
        expected_ready = {
            "run_id": args.run_id,
            "pid": watchdog_process.pid,
            "process_start_ticks": watchdog_snapshot.start_ticks,
            "process_group_id": watchdog_snapshot.process_group_id,
            "session_id": watchdog_snapshot.session_id,
            "identity_path": str(identity_path),
            "completion_path": str(completion_path),
            "deadline_seconds": args.deadline_seconds,
        }
        wait_for_watchdog_ready(
            watchdog_ready_path,
            expected=expected_ready,
            process=watchdog_process,
        )
        atomic_json(
            watchdog_identity_path,
            {
                "run_id": args.run_id,
                "pid": watchdog_process.pid,
                "process_start_ticks": watchdog_snapshot.start_ticks,
                "process_group_id": watchdog_snapshot.process_group_id,
                "session_id": watchdog_snapshot.session_id,
                "command": list(watchdog_snapshot.command),
                "deadline_seconds": args.deadline_seconds,
                "ready_path": str(watchdog_ready_path),
            },
        )
        identity["watchdog_pid"] = watchdog_process.pid
        atomic_json(identity_path, identity)

        os.write(gate_write, b"1")
        released = True
        os.close(gate_write)
        gate_write = -1
        return {
            "ok": True,
            "identity": identity,
            "identity_path": str(identity_path),
        }
    except Exception as exc:
        if gate_write >= 0:
            os.close(gate_write)
            gate_write = -1
        cleanup_errors: list[str] = []
        if identity is not None:
            try:
                stop_captured(identity, reason="launch_rollback")
            except Exception as cleanup_exc:
                cleanup_errors.append(f"service cleanup: {cleanup_exc}")
        elif process is not None and process.poll() is None:
            # The child is still behind the exec gate. Closing the writer above
            # gives it EOF, so it exits without ever loading a model or spawning
            # descendants; no unverified signal is needed.
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cleanup_errors.append(
                    "gated leader did not exit after identity-capture failure"
                )

        if not completion_path.exists():
            try:
                atomic_json(
                    completion_path,
                    {"run_id": args.run_id, "status": "launch_failed"},
                )
            except Exception as cleanup_exc:
                cleanup_errors.append(f"completion receipt: {cleanup_exc}")
        if watchdog_process is not None:
            try:
                watchdog_process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                try:
                    current = proc_identity(watchdog_process.pid)
                    joined = " ".join(current.command)
                    if watchdog_snapshot is None or (
                        current.start_ticks != watchdog_snapshot.start_ticks
                        or current.process_group_id
                        != watchdog_snapshot.process_group_id
                        or current.session_id != watchdog_snapshot.session_id
                        or current.pid != watchdog_process.pid
                        or str(Path(__file__).resolve()) not in joined
                        or "watchdog" not in joined
                        or args.run_id not in joined
                    ):
                        raise ServiceError("watchdog identity changed during rollback")
                    os.kill(current.pid, signal.SIGTERM)
                    watchdog_process.wait(timeout=5)
                except Exception as cleanup_exc:
                    cleanup_errors.append(f"watchdog cleanup: {cleanup_exc}")
        failure = {
            "run_id": args.run_id,
            "status": "launch_failed",
            "released": released,
            "error": str(exc),
            "cleanup_errors": cleanup_errors,
        }
        try:
            atomic_json(service_root / "launch-failure.json", failure)
        except Exception:
            pass
        if cleanup_errors:
            raise ServiceError(
                f"launch failed ({exc}); rollback incomplete: {'; '.join(cleanup_errors)}"
            ) from exc
        if isinstance(exc, ServiceError):
            raise
        raise ServiceError(f"launch failed: {exc}") from exc
    finally:
        if gate_read >= 0:
            os.close(gate_read)
        if gate_write >= 0:
            os.close(gate_write)
        os.close(gpu_lock_fd)


def status(identity_path: Path) -> dict[str, Any]:
    identity = read_identity(identity_path)
    try:
        members = verified_service_members(identity)
        live = bool(members)
        member_pids = {member.pid for member in members}
        foreign_gpu_processes: list[dict[str, str]] = []
        owned_gpu_processes: list[dict[str, str]] = []
        gpu_uuid, used_memory = gpu_identity(int(identity["gpu_index"]))
        if gpu_uuid != str(identity["gpu_uuid"]):
            raise ServiceError("GPU UUID changed while service was live")
        for row in compute_processes(gpu_uuid):
            if background_allowed(row, identity.get("allowed_background_processes", [])):
                continue
            if int(row["pid"]) in member_pids:
                owned_gpu_processes.append(row)
                continue
            try:
                process = proc_identity(int(row["pid"]))
            except (OSError, UnicodeError, ValueError, ServiceError):
                foreign_gpu_processes.append(row)
                continue
            if process.run_id == str(identity["run_id"]):
                owned_gpu_processes.append(row)
            else:
                foreign_gpu_processes.append(row)
        if foreign_gpu_processes:
            raise ServiceError(
                f"foreign compute process appeared on captured GPU: {foreign_gpu_processes}"
            )
    except ServiceError as exc:
        return {"ok": False, "live": True, "identity_error": str(exc)}
    return {
        "ok": True,
        "live": live,
        "identity": identity,
        "gpu_memory_used_mib": used_memory,
        "owned_gpu_processes": owned_gpu_processes,
        "foreign_gpu_processes": foreign_gpu_processes,
        "port_open": port_is_open(int(identity["port"])),
    }


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)
    launch_parser = sub.add_parser("launch")
    launch_parser.add_argument("--run-root", required=True)
    launch_parser.add_argument("--run-id", required=True)
    launch_parser.add_argument("--gpu", type=int, required=True)
    launch_parser.add_argument("--port", type=int, required=True)
    launch_parser.add_argument("--deadline-seconds", type=int, default=21600)
    launch_parser.add_argument("--gpu-memory-utilization", type=float, default=0.94)
    launch_parser.add_argument("--max-model-len", type=int, default=16384)
    launch_parser.add_argument("--max-num-seqs", type=int, default=1)
    stop_parser = sub.add_parser("stop")
    stop_parser.add_argument("--identity", required=True)
    stop_parser.add_argument("--reason", default="explicit_stop")
    status_parser = sub.add_parser("status")
    status_parser.add_argument("--identity", required=True)
    watchdog_parser = sub.add_parser("watchdog")
    watchdog_parser.add_argument("--identity", required=True)
    watchdog_parser.add_argument("--completion", required=True)
    watchdog_parser.add_argument("--ready", required=True)
    watchdog_parser.add_argument("--run-id", required=True)
    watchdog_parser.add_argument("--deadline-seconds", type=int, required=True)
    exec_parser = sub.add_parser("exec-server")
    exec_parser.add_argument("--gate-fd", type=int, required=True)
    exec_parser.add_argument("server_command", nargs=argparse.REMAINDER)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "launch":
        if args.gpu not in range(8):
            raise ServiceError("GPU index must be in [0, 7]")
        if not 1024 <= args.port <= 65535:
            raise ServiceError("invalid port")
        if not 300 <= args.deadline_seconds <= 86400:
            raise ServiceError("deadline must be in [300, 86400]")
        if not 0.80 <= args.gpu_memory_utilization <= 0.98:
            raise ServiceError("gpu memory utilization must be in [0.80, 0.98]")
        result = launch(args)
    elif args.command == "stop":
        identity_path = runtime_path(args.identity, label="identity")
        identity = read_identity(identity_path)
        completion_path = identity_path.parent / "completion.json"
        if not completion_path.exists():
            atomic_json(
                completion_path,
                {
                    "run_id": str(identity["run_id"]),
                    "status": "explicit_stop",
                    "reason": args.reason,
                },
            )
        result = stop_captured(identity, reason=args.reason)
        result["watchdog"] = stop_watchdog(
            identity_path.parent / "watchdog-identity.json"
        )
    elif args.command == "status":
        result = status(runtime_path(args.identity, label="identity"))
    elif args.command == "watchdog":
        if not RUN_ID_RE.fullmatch(args.run_id):
            raise ServiceError("invalid run ID")
        result = {
            "ok": watchdog(
                identity_path=runtime_path(args.identity, label="identity"),
                completion_path=runtime_path(args.completion, label="completion"),
                ready_path=runtime_path(args.ready, label="watchdog_ready"),
                run_id=args.run_id,
                deadline=args.deadline_seconds,
            )
            == 0
        }
    else:
        command = list(args.server_command)
        if command and command[0] == "--":
            command = command[1:]
        return exec_server(args.gate_fd, command)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ServiceError as exc:
        print(f"service error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
