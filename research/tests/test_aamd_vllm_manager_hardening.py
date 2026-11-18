from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest


SCRIPTS_ROOT = Path(__file__).resolve().parents[1] / "scripts"


def _load_manager() -> ModuleType:
    name = "aamd_vllm_manager_hardening_under_test"
    spec = importlib.util.spec_from_file_location(
        name, SCRIPTS_ROOT / "manage_aamd_vllm.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


manager = _load_manager()


def _identity() -> dict[str, Any]:
    return {
        "run_id": "hardening-run",
        "pid": 4101,
        "process_start_ticks": 91_000,
        "process_group_id": 4101,
        "session_id": 4101,
        "gpu_index": 6,
        "gpu_uuid": "GPU-hardening",
        "cuda_visible_devices": "6",
        "port": 18_066,
    }


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def test_atomic_json_fsyncs_file_and_parent_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[int] = []
    real_fsync = manager.os.fsync

    def recording_fsync(fd: int) -> None:
        calls.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(manager.os, "fsync", recording_fsync)
    target = tmp_path / "service" / "identity.json"
    manager.atomic_json(target, {"ok": True})

    assert json.loads(target.read_text(encoding="utf-8")) == {"ok": True}
    assert len(calls) == 2


def test_server_environment_is_allowlisted_and_run_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime_root = tmp_path / "runtime"
    run_root = runtime_root / "run"
    tmp_root = run_root / "tmp"
    cache_root = run_root / "cache"
    tmp_root.mkdir(parents=True)
    cache_root.mkdir()
    monkeypatch.setattr(manager, "RUNTIME_ROOT", runtime_root)
    monkeypatch.setenv("AAMD_LOCAL_OPENAI_API_KEY", "must-not-reach-server")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-reach-server")

    env = manager.build_server_environment(
        run_id="hardening-run",
        gpu_index=6,
        tmp_root=tmp_root,
        cache_root=cache_root,
    )

    assert "AAMD_LOCAL_OPENAI_API_KEY" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert env["AAMD_RUN_ID"] == "hardening-run"
    assert env["CUDA_VISIBLE_DEVICES"] == "6"
    assert env["TMPDIR"] == str(tmp_root)
    for name in (
        "HF_HOME",
        "HUGGINGFACE_HUB_CACHE",
        "HF_HUB_CACHE",
        "HF_ASSETS_CACHE",
        "TRANSFORMERS_CACHE",
        "XDG_CACHE_HOME",
        "VLLM_CACHE_ROOT",
        "FLASHINFER_WORKSPACE_BASE",
        "TORCH_HOME",
        "TORCH_EXTENSIONS_DIR",
        "TORCHINDUCTOR_CACHE_DIR",
        "TRITON_CACHE_DIR",
        "CUDA_CACHE_PATH",
        "PYTHONPYCACHEPREFIX",
    ):
        Path(env[name]).resolve().relative_to(cache_root.resolve())


def test_launch_rejects_gpu_outside_managed_range() -> None:
    with pytest.raises(manager.ServiceError, match=r"GPU index must be in \[0, 7\]"):
        manager.launch(SimpleNamespace(run_id="hardening-run", gpu=8))


def test_ready_receipt_is_verified_against_fresh_watchdog_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ready_path = tmp_path / "watchdog-ready.json"
    expected = {
        "run_id": "hardening-run",
        "pid": 5101,
        "process_start_ticks": 81_000,
        "process_group_id": 5101,
        "session_id": 5101,
        "identity_path": str(tmp_path / "identity.json"),
        "completion_path": str(tmp_path / "completion.json"),
        "deadline_seconds": 600,
    }
    _write_json(ready_path, expected)
    verified: list[dict[str, Any]] = []
    monkeypatch.setattr(
        manager,
        "watchdog_identity_matches",
        lambda value: verified.append(dict(value)) or True,
    )

    class Process:
        @staticmethod
        def poll() -> None:
            return None

    assert manager.wait_for_watchdog_ready(
        ready_path,
        expected=expected,
        process=Process(),
        timeout_seconds=1,
    ) == expected
    assert verified == [expected]


def test_watchdog_retries_completion_stop_and_retains_deadline_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity_path = tmp_path / "identity.json"
    completion_path = tmp_path / "completion.json"
    _write_json(identity_path, _identity())
    _write_json(completion_path, {"run_id": "hardening-run", "status": "complete"})
    monkeypatch.setattr(manager, "publish_watchdog_ready", lambda **_kwargs: {})
    monotonic = iter((0.0, 1.0, 101.0))
    monkeypatch.setattr(manager.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(manager.time, "sleep", lambda _seconds: None)
    reasons: list[str] = []

    def stop(_identity_value: dict[str, Any], *, reason: str) -> dict[str, Any]:
        reasons.append(reason)
        if len(reasons) == 1:
            raise manager.ServiceError("transient release verification failure")
        return {"ok": True, "reason": reason}

    monkeypatch.setattr(manager, "stop_captured", stop)

    assert manager.watchdog(
        identity_path=identity_path,
        completion_path=completion_path,
        ready_path=tmp_path / "ready.json",
        run_id="hardening-run",
        deadline=100,
    ) == 0
    assert reasons == ["completion", "hard_deadline_after_completion"]


def test_watchdog_stops_only_captured_service_on_foreign_gpu_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity_path = tmp_path / "identity.json"
    _write_json(identity_path, _identity())
    monkeypatch.setattr(manager, "publish_watchdog_ready", lambda **_kwargs: {})
    monkeypatch.setattr(manager.time, "monotonic", lambda: 1.0)
    monkeypatch.setattr(manager.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        manager,
        "foreign_gpu_processes",
        lambda _identity_value: [
            {
                "gpu_uuid": "GPU-hardening",
                "pid": "9999",
                "process_name": "foreign",
                "used_memory_mib": "1024",
            }
        ],
    )
    stops: list[tuple[dict[str, Any], str]] = []

    def stop(identity_value: dict[str, Any], *, reason: str) -> dict[str, Any]:
        stops.append((identity_value, reason))
        return {"ok": True, "reason": reason}

    monkeypatch.setattr(manager, "stop_captured", stop)

    assert manager.watchdog(
        identity_path=identity_path,
        completion_path=tmp_path / "completion.json",
        ready_path=tmp_path / "ready.json",
        run_id="hardening-run",
        deadline=600,
    ) == 0
    assert stops == [(_identity(), "foreign_gpu_process")]


def test_foreign_gpu_detection_excludes_verified_service_members(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _identity()
    owned = manager.ProcessIdentity(
        pid=4102,
        state="S",
        parent_pid=4101,
        process_group_id=4101,
        session_id=4101,
        start_ticks=91_001,
        cuda_visible_devices="",
        run_id="",
        command=("vllm", "engine"),
        environment_zeroized=True,
    )
    foreign = manager.ProcessIdentity(
        pid=9001,
        state="S",
        parent_pid=1,
        process_group_id=9001,
        session_id=9001,
        start_ticks=92_000,
        cuda_visible_devices="6",
        run_id="other-run",
        command=("python", "foreign.py"),
    )
    rows = [
        {
            "gpu_uuid": "GPU-hardening",
            "pid": "4102",
            "process_name": "vllm",
            "used_memory_mib": "20000",
        },
        {
            "gpu_uuid": "GPU-hardening",
            "pid": "9001",
            "process_name": "foreign",
            "used_memory_mib": "1024",
        },
    ]
    monkeypatch.setattr(manager, "verified_service_members", lambda _value: [owned])
    monkeypatch.setattr(
        manager, "gpu_identity", lambda _index: ("GPU-hardening", 21024)
    )
    monkeypatch.setattr(manager, "compute_processes", lambda _uuid: rows)
    monkeypatch.setattr(
        manager,
        "proc_identity",
        lambda pid: foreign if pid == foreign.pid else owned,
    )

    assert manager.foreign_gpu_processes(identity) == [rows[1]]


def test_launch_waits_for_watchdog_ready_before_releasing_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime_root = tmp_path / "runtime"
    run_root = runtime_root / "run"
    executable = tmp_path / "bin" / "vllm"
    executable.parent.mkdir()
    executable.write_text("test", encoding="utf-8")
    model_path = tmp_path / "model"
    model_path.mkdir()
    monkeypatch.setattr(manager, "RUNTIME_ROOT", runtime_root)
    monkeypatch.setattr(manager, "VLLM", executable)
    monkeypatch.setattr(manager, "MODEL_PATH", model_path)
    monkeypatch.setattr(manager, "attest_runtime", lambda: {"attested": True})
    monkeypatch.setattr(manager, "require_free_port", lambda _port: None)
    monkeypatch.setattr(
        manager, "require_empty_gpu", lambda _gpu: ("GPU-hardening", 0)
    )
    events: list[str] = []
    processes: list[Any] = []

    class Process:
        def __init__(self, pid: int, command: list[str], env: dict[str, str]) -> None:
            self.pid = pid
            self.command = tuple(command)
            self.env = env

        @staticmethod
        def poll() -> None:
            return None

    def popen(command: list[str], **kwargs: Any) -> Process:
        process = Process(6101 + len(processes), command, kwargs.get("env") or {})
        processes.append(process)
        return process

    def process_identity(pid: int) -> Any:
        process = next(item for item in processes if item.pid == pid)
        is_server = "exec-server" in process.command
        return manager.ProcessIdentity(
            pid=pid,
            state="S",
            parent_pid=1,
            process_group_id=pid,
            session_id=pid,
            start_ticks=70_000 + pid,
            cuda_visible_devices=process.env.get("CUDA_VISIBLE_DEVICES", "")
            if is_server
            else "",
            run_id=process.env.get("AAMD_RUN_ID", "") if is_server else "",
            command=process.command,
        )

    monkeypatch.setattr(manager.subprocess, "Popen", popen)
    monkeypatch.setattr(manager, "proc_identity", process_identity)
    monkeypatch.setattr(
        manager,
        "wait_for_watchdog_ready",
        lambda *_args, **_kwargs: events.append("watchdog_ready") or {},
    )
    real_atomic_json = manager.atomic_json

    def atomic(path: Path, value: dict[str, Any]) -> None:
        events.append(f"write:{path.name}")
        real_atomic_json(path, value)

    monkeypatch.setattr(manager, "atomic_json", atomic)
    monkeypatch.setattr(
        manager.os,
        "write",
        lambda _fd, _payload: events.append("gate_release") or 1,
    )

    result = manager.launch(
        SimpleNamespace(
            run_root=str(run_root),
            run_id="hardening-run",
            gpu=6,
            port=18_066,
            deadline_seconds=600,
            gpu_memory_utilization=0.90,
            max_model_len=4096,
            max_num_seqs=1,
        )
    )

    assert result["ok"] is True
    assert events.index("watchdog_ready") < events.index("gate_release")
    assert events.index("write:identity.json") < events.index("gate_release")
