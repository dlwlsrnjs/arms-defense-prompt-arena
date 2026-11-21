from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import signal
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest


RESEARCH_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = RESEARCH_ROOT / "scripts"


def _load_script(module_name: str, filename: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(module_name, SCRIPTS_ROOT / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


manager = _load_script("aamd_vllm_manager_under_test", "manage_aamd_vllm.py")
runner = _load_script("aamd_32b_runner_under_test", "run_aamd_32b_labeling.py")


def _service_identity(*, run_id: str = "test-run") -> dict[str, Any]:
    return {
        "run_id": run_id,
        "pid": 2201,
        "process_start_ticks": 10_000,
        "process_group_id": 2201,
        "session_id": 2201,
        "gpu_index": 6,
        "gpu_uuid": "GPU-test",
        "cuda_visible_devices": "6",
        "port": 18_066,
    }


def _member(
    pid: int,
    *,
    start_ticks: int,
    parent_pid: int = 2201,
    run_id: str = "test-run",
    cuda_visible_devices: str = "6",
    environment_zeroized: bool = False,
) -> Any:
    return manager.ProcessIdentity(
        pid=pid,
        state="S",
        parent_pid=parent_pid,
        process_group_id=2201,
        session_id=2201,
        start_ticks=start_ticks,
        cuda_visible_devices=cuda_visible_devices,
        run_id=run_id,
        command=("vllm", "serve"),
        environment_zeroized=environment_zeroized,
    )


def test_signal_service_revalidates_identity_immediately_before_every_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _service_identity()
    events: list[tuple[Any, ...]] = []

    def verified(value: dict[str, Any]) -> list[Any]:
        assert value is identity
        events.append(("verified",))
        return [_member(2201, start_ticks=10_000)]

    def killpg(process_group_id: int, sig: signal.Signals) -> None:
        events.append(("killpg", process_group_id, sig))

    monkeypatch.setattr(manager, "verified_service_members", verified)
    monkeypatch.setattr(manager.os, "killpg", killpg)

    assert manager.signal_service(identity, signal.SIGTERM) is True
    assert manager.signal_service(identity, signal.SIGKILL) is True
    assert events == [
        ("verified",),
        ("killpg", 2201, signal.SIGTERM),
        ("verified",),
        ("killpg", 2201, signal.SIGKILL),
    ]


def test_dead_leader_does_not_hide_verified_surviving_children(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _service_identity()
    child = _member(2202, start_ticks=10_001)
    signals: list[tuple[int, signal.Signals]] = []
    live_members = [child]

    # The captured session/PGID leader is absent, but a later child bearing the
    # same run marker, CUDA identity, PGID and SID remains alive.
    monkeypatch.setattr(manager, "process_group_members", lambda _pgid: live_members)

    def killpg(pgid: int, sig: signal.Signals) -> None:
        signals.append((pgid, sig))
        live_members.clear()

    monkeypatch.setattr(manager.os, "killpg", killpg)
    monkeypatch.setattr(manager.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(manager, "verify_release", lambda _identity: {"ok": True})

    assert manager.verified_service_members(identity) == [child]
    result = manager.stop_captured(identity, reason="test")
    assert result["already_stopped"] is False
    assert signals == [(2201, signal.SIGTERM)]


def test_zeroized_vllm_descendant_is_verified_through_live_leader_ancestry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _service_identity()
    leader = _member(2201, start_ticks=10_000, parent_pid=1)
    engine = _member(
        2202,
        start_ticks=10_001,
        parent_pid=2201,
        run_id="",
        cuda_visible_devices="",
        environment_zeroized=True,
    )
    monkeypatch.setattr(
        manager, "process_group_members", lambda _pgid: [leader, engine]
    )

    assert manager.verified_service_members(identity) == [leader, engine]


def test_zeroized_process_without_captured_ancestry_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _service_identity()
    leader = _member(2201, start_ticks=10_000, parent_pid=1)
    unrelated = _member(
        2202,
        start_ticks=10_001,
        parent_pid=9999,
        run_id="",
        cuda_visible_devices="",
        environment_zeroized=True,
    )
    monkeypatch.setattr(
        manager, "process_group_members", lambda _pgid: [leader, unrelated]
    )

    with pytest.raises(manager.ServiceError, match="child identity changed"):
        manager.verified_service_members(identity)


def test_zeroized_leader_is_never_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _service_identity()
    leader = _member(
        2201,
        start_ticks=10_000,
        parent_pid=1,
        run_id="",
        cuda_visible_devices="",
        environment_zeroized=True,
    )
    monkeypatch.setattr(manager, "process_group_members", lambda _pgid: [leader])

    with pytest.raises(manager.ServiceError, match="CUDA identity changed"):
        manager.verified_service_members(identity)


class _FakeProcess:
    def __init__(
        self,
        *,
        pid: int,
        command: list[str],
        env: dict[str, str] | None,
        events: list[tuple[Any, ...]],
    ) -> None:
        self.pid = pid
        self.command = tuple(command)
        self.env = env or {}
        self.events = events
        self.alive = True

    def poll(self) -> int | None:
        return None if self.alive else 0

    def wait(self, timeout: float | None = None) -> int:
        if self.alive:
            raise manager.subprocess.TimeoutExpired(self.command, timeout)
        return 0

    def terminate(self) -> None:
        self.events.append(("unverified_terminate", self.pid))
        self.alive = False

    def kill(self) -> None:
        self.events.append(("unverified_kill", self.pid))
        self.alive = False


def _install_fake_launch_processes(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[_FakeProcess], list[tuple[Any, ...]]]:
    processes: list[_FakeProcess] = []
    events: list[tuple[Any, ...]] = []

    def popen(command: list[str], **kwargs: Any) -> _FakeProcess:
        process = _FakeProcess(
            pid=2200 + len(processes),
            command=command,
            env=kwargs.get("env"),
            events=events,
        )
        processes.append(process)
        events.append(("popen", process.pid))
        return process

    def process_identity(pid: int) -> Any:
        process = next(item for item in processes if item.pid == pid)
        events.append(("proc_identity", pid))
        if not process.alive:
            raise FileNotFoundError(pid)
        is_server = "serve" in process.command
        run_id = process.env.get("AAMD_RUN_ID", "")
        return manager.ProcessIdentity(
            pid=pid,
            state="S",
            parent_pid=1,
            process_group_id=pid,
            session_id=pid,
            start_ticks=9_000 + pid,
            cuda_visible_devices=process.env.get("CUDA_VISIBLE_DEVICES", "")
            if is_server
            else "",
            run_id=run_id,
            command=process.command,
        )

    def group_members(process_group_id: int) -> list[Any]:
        return [
            process_identity(item.pid)
            for item in processes
            if item.pid == process_group_id and item.alive
        ]

    def killpg(process_group_id: int, sig: signal.Signals) -> None:
        # A signal is only safe when a fresh identity read immediately precedes
        # it.  This makes an accidental Popen.terminate()/kill() insufficient.
        assert events[-1] == ("proc_identity", process_group_id)
        events.append(("killpg", process_group_id, sig))
        for item in processes:
            if item.pid == process_group_id:
                item.alive = False

    def kill(pid: int, sig: signal.Signals) -> None:
        assert events[-1] == ("proc_identity", pid)
        events.append(("kill", pid, sig))
        for item in processes:
            if item.pid == pid:
                item.alive = False

    monkeypatch.setattr(manager.subprocess, "Popen", popen)
    monkeypatch.setattr(manager, "proc_identity", process_identity)
    monkeypatch.setattr(manager, "process_group_members", group_members)
    monkeypatch.setattr(manager.os, "killpg", killpg)
    monkeypatch.setattr(manager.os, "kill", kill)
    monkeypatch.setattr(manager.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(
        manager,
        "verify_release",
        lambda _identity: {"run_processes_gone": True, "port_closed": True},
    )
    return processes, events


def _launch_args(run_root: Path) -> SimpleNamespace:
    return SimpleNamespace(
        run_root=str(run_root),
        run_id="test-run",
        gpu=6,
        port=18_066,
        deadline_seconds=600,
        gpu_memory_utilization=0.90,
        max_model_len=4096,
        max_num_seqs=1,
    )


def _prepare_launch_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    runtime_root = tmp_path / "runtime"
    run_root = runtime_root / "run"
    executable = tmp_path / "bin" / "vllm"
    executable.parent.mkdir()
    executable.write_text("test executable", encoding="utf-8")
    model_path = tmp_path / "model"
    model_path.mkdir()
    monkeypatch.setattr(manager, "RUNTIME_ROOT", runtime_root)
    monkeypatch.setattr(manager, "VLLM", executable)
    monkeypatch.setattr(manager, "MODEL_PATH", model_path)
    monkeypatch.setattr(manager, "attest_runtime", lambda: {"attested": True})
    monkeypatch.setattr(manager, "require_free_port", lambda _port: None)
    monkeypatch.setattr(
        manager,
        "wait_for_watchdog_ready",
        lambda _path, *, expected, process, **_kwargs: dict(expected),
    )
    return run_root


def test_launch_failure_after_watchdog_start_cleans_watchdog_and_server(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_root = _prepare_launch_paths(tmp_path, monkeypatch)
    processes, events = _install_fake_launch_processes(monkeypatch)
    monkeypatch.setattr(
        manager,
        "require_empty_gpu",
        lambda _gpu: ("GPU-test", 0),
    )
    monkeypatch.setattr(
        manager.os,
        "write",
        lambda _fd, _payload: (_ for _ in ()).throw(
            OSError("simulated gate release failure")
        ),
    )

    with pytest.raises(manager.ServiceError, match="gate release failure"):
        manager.launch(_launch_args(run_root))

    assert len(processes) == 2
    assert all(not process.alive for process in processes)
    assert not [event for event in events if event[0].startswith("unverified_")]


def test_partial_launch_failure_after_server_start_cleans_server(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_root = _prepare_launch_paths(tmp_path, monkeypatch)
    processes, events = _install_fake_launch_processes(monkeypatch)
    monkeypatch.setattr(
        manager,
        "require_empty_gpu",
        lambda _gpu: ("GPU-test", 0),
    )
    real_popen = manager.subprocess.Popen

    def fail_watchdog_start(command: list[str], **kwargs: Any) -> _FakeProcess:
        if len(processes) == 1:
            raise OSError("simulated watchdog spawn failure")
        return real_popen(command, **kwargs)

    monkeypatch.setattr(manager.subprocess, "Popen", fail_watchdog_start)

    with pytest.raises(manager.ServiceError, match="watchdog spawn failure"):
        manager.launch(_launch_args(run_root))

    assert len(processes) == 1
    assert processes[0].alive is False
    assert not [event for event in events if event[0].startswith("unverified_")]


def test_runner_finally_stops_identity_left_by_partial_manager_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_root = tmp_path / "runtime"
    run_root = runtime_root / "run"
    source_dir = runtime_root / "source"
    source_dir.mkdir(parents=True)
    (source_dir / "source-bundle-000.json").write_text(
        json.dumps({"bundle_id": "pilot-source-000"}),
        encoding="utf-8",
    )
    (source_dir / "source-manifest.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(runner, "RUNTIME_ROOT", runtime_root)
    monkeypatch.setattr(
        runner,
        "verify_source_directory",
        lambda _source_dir: [source_dir / "source-bundle-000.json"],
    )
    monkeypatch.setattr(runner, "gpu_is_empty", lambda _gpu: (True, "empty"))
    commands: list[list[str]] = []

    def run_json(command: list[str], *, env: dict[str, str]) -> dict[str, Any]:
        del env
        commands.append(command)
        if "launch" in command:
            identity_path = run_root / "service" / "identity.json"
            identity_path.parent.mkdir(parents=True, exist_ok=True)
            identity_path.write_text("{}\n", encoding="utf-8")
            raise runner.OrchestratorError("manager failed after identity commit")
        assert "stop" in command
        return {"ok": True}

    monkeypatch.setattr(runner, "run_json", run_json)

    with pytest.raises(
        runner.OrchestratorError,
        match="manager failed after identity commit",
    ):
        runner.main(
            [
                "--run-root",
                str(run_root),
                "--run-id",
                "test-run",
                "--source-dir",
                str(source_dir),
                "--gpu",
                "6",
                "--port",
                "18066",
                "--wait-seconds",
                "1",
            ]
        )

    assert len(commands) == 2
    assert "launch" in commands[0]
    assert "stop" in commands[1]


def test_runner_still_stops_service_when_completion_receipt_write_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_root = tmp_path / "runtime"
    run_root = runtime_root / "run"
    source_dir = runtime_root / "source"
    source_dir.mkdir(parents=True)
    source_bundle = source_dir / "source-bundle-000.json"
    source_bundle.write_text('{"bundle_id":"pilot-source-000"}\n', encoding="utf-8")
    (source_dir / "source-manifest.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(runner, "RUNTIME_ROOT", runtime_root)
    monkeypatch.setattr(runner, "verify_source_directory", lambda _path: [source_bundle])
    monkeypatch.setattr(runner, "gpu_is_empty", lambda _gpu: (True, "empty"))
    commands: list[list[str]] = []

    def run_json(command: list[str], *, env: dict[str, str]) -> dict[str, Any]:
        del env
        commands.append(command)
        if "launch" in command:
            identity = run_root / "service" / "identity.json"
            identity.parent.mkdir(parents=True)
            identity.write_text("{}\n", encoding="utf-8")
            raise runner.OrchestratorError("launch failed after identity capture")
        if "stop" in command:
            return {"ok": True}
        raise AssertionError(command)

    real_atomic_json = runner.atomic_json

    def fail_completion(path: Path, value: dict[str, Any]) -> None:
        if path == run_root / "service" / "completion.json":
            raise OSError("simulated completion write failure")
        real_atomic_json(path, value)

    monkeypatch.setattr(runner, "run_json", run_json)
    monkeypatch.setattr(runner, "atomic_json", fail_completion)
    with pytest.raises(
        runner.OrchestratorError,
        match="service stopped but completion receipt failed",
    ):
        runner.main(
            [
                "--run-root",
                str(run_root),
                "--run-id",
                "completion-failure-test",
                "--source-dir",
                str(source_dir),
                "--gpu",
                "6",
                "--port",
                "18066",
                "--wait-seconds",
                "1",
            ]
        )
    assert any("stop" in command for command in commands)


def _write_valid_source_fixture(source_dir: Path) -> Path:
    source_dir.mkdir(parents=True)
    task: dict[str, Any] = {
        "task_id": "task-test-000",
        "benchmark": "T3",
        "record_handle": "record-test-000",
        "title": "Payload-free adaptive transition review",
        "question": "Which abstract mechanism is supported?",
        "instructions": "Use only the visible evidence.",
        "evidence": [{"handle": "ev-1", "value": "abstract evidence"}],
        "taxonomy_id": "aamd-rcat-7-v1.1",
        "taxonomy_version": "1.1.0",
        "taxonomy_hash": "taxonomy-test-hash",
        "locked_axes": {"dialogue_horizon": {"code": "single_edge"}},
        "locked_axes_hash": "locked-axes-test-hash",
    }
    record = {field: task[field] for field in runner.PUBLIC_RECORD_FIELDS}
    task["record_hash"] = runner.canonical_sha256(record)
    queue = [
        {
            "ordinal": 0,
            "task_id": task["task_id"],
            "record_handle": task["record_handle"],
            "record_hash": task["record_hash"],
        }
    ]
    queue_hash = runner.canonical_sha256(queue)
    bundle_id = "attack-memory-v1-rcat7-pilot-source-000"
    bundle = {
        "schema_version": 3,
        "bundle_id": bundle_id,
        "visibility_mask_hash": runner.canonical_sha256(
            runner.EXPECTED_VISIBILITY_MASK
        ),
        "queue_hash": queue_hash,
        "tasks": [task],
    }
    bundle_path = source_dir / "source-bundle-000.json"
    raw = json.dumps(bundle, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    bundle_path.write_bytes(raw)
    manifest = {
        "schema_version": 1,
        "status": "pilot_only",
        "claim_bearing": False,
        "source": {
            "memory_flow_sha256": runner.EXPECTED_MEMORY_FLOW_SHA256,
            "artifact_manifest_sha256": runner.EXPECTED_ARTIFACT_MANIFEST_SHA256,
            "pack_id": runner.EXPECTED_PACK_ID,
        },
        "projection": {
            "task_count": 1,
            "bundle_count": 1,
            "visibility_mask": runner.EXPECTED_VISIBILITY_MASK,
            "visibility_mask_hash": runner.canonical_sha256(
                runner.EXPECTED_VISIBILITY_MASK
            ),
        },
        "bundles": [
            {
                "bundle_id": bundle_id,
                "path": bundle_path.name,
                "task_count": 1,
                "file_sha256": hashlib.sha256(raw).hexdigest(),
                "canonical_sha256": runner.canonical_sha256(bundle),
                "queue_hash": queue_hash,
            }
        ],
    }
    (source_dir / "source-manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return bundle_path


def test_review_bundle_id_mapping_matches_real_frozen_pilot_ids() -> None:
    source_ids = [
        "attack-memory-v1-rcat7-pilot-000",
        "attack-memory-v1-rcat7-pilot-001",
        "attack-memory-v1-rcat7-pilot-012",
    ]
    review_ids = [runner.derive_review_bundle_id(value) for value in source_ids]

    assert review_ids == [
        "attack-memory-v1-rcat7-pilot-review-000",
        "attack-memory-v1-rcat7-pilot-review-001",
        "attack-memory-v1-rcat7-pilot-review-012",
    ]
    assert len(set(review_ids)) == len(source_ids)
    assert all(output != source for source, output in zip(source_ids, review_ids))


def test_review_bundle_id_mapping_preserves_source_token_and_fails_on_overflow() -> None:
    assert runner.derive_review_bundle_id("pilot-source-000") == (
        "pilot-source-review-000"
    )
    assert runner.derive_review_bundle_id("pilot") == "pilot-review"
    with pytest.raises(runner.OrchestratorError, match="outside the generator contract"):
        runner.derive_review_bundle_id("a" * 160)


def test_successful_launch_is_gated_until_watchdog_identity_and_provenance_are_durable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_root = _prepare_launch_paths(tmp_path, monkeypatch)
    processes, events = _install_fake_launch_processes(monkeypatch)
    monkeypatch.setattr(
        manager,
        "require_empty_gpu",
        lambda _gpu: ("GPU-test", 0),
    )
    provenance = {
        "model_revision": "frozen-revision",
        "vllm_entrypoint_sha256": "frozen-entrypoint",
    }
    monkeypatch.setattr(manager, "attest_runtime", lambda: provenance)

    popen_calls: list[tuple[list[str], dict[str, Any]]] = []
    fake_popen = manager.subprocess.Popen

    def recording_popen(command: list[str], **kwargs: Any) -> _FakeProcess:
        popen_calls.append((list(command), dict(kwargs)))
        return fake_popen(command, **kwargs)

    monkeypatch.setattr(manager.subprocess, "Popen", recording_popen)

    flock_calls: list[tuple[int, int]] = []
    real_flock = manager.fcntl.flock

    def recording_flock(fd: int, operation: int) -> None:
        flock_calls.append((fd, operation))
        real_flock(fd, operation)

    monkeypatch.setattr(manager.fcntl, "flock", recording_flock)

    atomic_events: list[str] = []
    real_atomic_json = manager.atomic_json

    def recording_atomic_json(path: Path, value: dict[str, Any]) -> None:
        atomic_events.append(path.name)
        real_atomic_json(path, value)

    monkeypatch.setattr(manager, "atomic_json", recording_atomic_json)

    held_pipe_readers: list[int] = []
    real_pipe = os.pipe
    real_write = os.write

    def pipe_with_test_reader() -> tuple[int, int]:
        read_fd, write_fd = real_pipe()
        held_pipe_readers.append(os.dup(read_fd))
        return read_fd, write_fd

    def recording_write(fd: int, payload: bytes) -> int:
        events.append(("gate_release", payload))
        return real_write(fd, payload)

    monkeypatch.setattr(manager.os, "pipe", pipe_with_test_reader)
    monkeypatch.setattr(manager.os, "write", recording_write)

    try:
        result = manager.launch(_launch_args(run_root))
    finally:
        for fd in held_pipe_readers:
            os.close(fd)

    assert result["ok"] is True
    assert len(processes) == 2
    assert len(popen_calls) == 2
    server_command, server_kwargs = popen_calls[0]
    watchdog_command, watchdog_kwargs = popen_calls[1]
    assert "exec-server" in server_command
    assert "watchdog" in watchdog_command
    assert server_kwargs["start_new_session"] is True
    assert watchdog_kwargs["start_new_session"] is True
    assert server_kwargs["env"]["PATH"].split(os.pathsep)[0] == str(
        manager.VLLM.parent
    )
    assert server_kwargs["env"]["FLASHINFER_WORKSPACE_BASE"] == str(
        run_root / "cache" / "flashinfer"
    )
    assert server_kwargs["env"]["TORCHINDUCTOR_CACHE_DIR"] == str(
        run_root / "cache" / "torchinductor"
    )
    assert len(server_kwargs["pass_fds"]) == 2
    assert "pass_fds" not in watchdog_kwargs
    assert flock_calls == [
        (
            server_kwargs["pass_fds"][1],
            manager.fcntl.LOCK_EX | manager.fcntl.LOCK_NB,
        )
    ]
    assert atomic_events == ["watchdog-identity.json", "identity.json"]
    assert events.index(("popen", processes[1].pid)) < events.index(
        ("gate_release", b"1")
    )

    identity_path = run_root / "service" / "identity.json"
    persisted = json.loads(identity_path.read_text(encoding="utf-8"))
    assert persisted["runtime_provenance"] == provenance
    assert persisted["watchdog_pid"] == processes[1].pid
    assert persisted["gpu_lock_path"].endswith("aamd-GPU-test.lock")
    assert (run_root / "service" / "watchdog-identity.json").is_file()


def test_explicit_stop_waits_for_and_terminates_captured_watchdog(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime_root = tmp_path / "runtime"
    identity_path = runtime_root / "run" / "service" / "identity.json"
    identity_path.parent.mkdir(parents=True)
    identity_path.write_text(json.dumps({"run_id": "test-run"}), encoding="utf-8")
    watchdog_path = identity_path.parent / "watchdog-identity.json"
    watchdog_path.write_text(
        json.dumps(
            {
                "run_id": "test-run",
                "pid": 4411,
                "process_start_ticks": 88_000,
                "process_group_id": 4411,
                "session_id": 4411,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(manager, "RUNTIME_ROOT", runtime_root)
    monkeypatch.setattr(
        manager,
        "stop_captured",
        lambda _identity, reason: {"ok": True, "reason": reason},
    )
    alive = True
    identity_reads = 0

    def proc_identity(pid: int) -> Any:
        nonlocal identity_reads
        identity_reads += 1
        assert pid == 4411
        if not alive:
            raise FileNotFoundError(pid)
        return manager.ProcessIdentity(
            pid=pid,
            state="S",
            parent_pid=1,
            process_group_id=pid,
            session_id=pid,
            start_ticks=88_000,
            cuda_visible_devices="",
            run_id="",
            command=(
                sys.executable,
                str(Path(manager.__file__).resolve()),
                "watchdog",
                "--run-id",
                "test-run",
            ),
        )

    signals: list[tuple[int, signal.Signals]] = []

    def kill(pid: int, sig: signal.Signals) -> None:
        nonlocal alive
        signals.append((pid, sig))
        alive = False

    monkeypatch.setattr(manager, "proc_identity", proc_identity)
    monkeypatch.setattr(manager.os, "kill", kill)
    monkeypatch.setattr(manager.time, "sleep", lambda _seconds: None)

    assert (
        manager.main(
            [
                "stop",
                "--identity",
                str(identity_path),
                "--reason",
                "test_explicit_stop",
            ]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert payload["watchdog"] == {
        "present": True,
        "stopped": True,
        "forced": True,
    }
    assert signals == [(4411, signal.SIGTERM)]
    assert identity_reads >= 32
    completion = json.loads(
        (identity_path.parent / "completion.json").read_text(encoding="utf-8")
    )
    assert completion["status"] == "explicit_stop"


def test_one_byte_source_tamper_is_rejected_before_gpu_polling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_root = tmp_path / "runtime"
    source_dir = runtime_root / "source"
    run_root = runtime_root / "run"
    bundle_path = _write_valid_source_fixture(source_dir)
    bundle_path.write_bytes(bundle_path.read_bytes() + b" ")
    monkeypatch.setattr(runner, "RUNTIME_ROOT", runtime_root)
    gpu_polls = 0

    def gpu_poll(_gpu: int) -> tuple[bool, str]:
        nonlocal gpu_polls
        gpu_polls += 1
        raise AssertionError("GPU polling must not happen for a tampered source")

    monkeypatch.setattr(runner, "gpu_is_empty", gpu_poll)

    with pytest.raises(runner.OrchestratorError, match="file hash mismatch"):
        runner.main(
            [
                "--run-root",
                str(run_root),
                "--run-id",
                "tamper-test",
                "--source-dir",
                str(source_dir),
                "--gpu",
                "6",
                "--port",
                "18066",
            ]
        )
    assert gpu_polls == 0


def test_cleanup_failure_overrides_otherwise_successful_runner_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_root = tmp_path / "runtime"
    source_dir = runtime_root / "source"
    run_root = runtime_root / "run"
    source_dir.mkdir(parents=True)
    source_bundle = source_dir / "source-bundle-000.json"
    source_bundle.write_text(
        json.dumps({"bundle_id": "pilot-source-000"}),
        encoding="utf-8",
    )
    (source_dir / "source-manifest.json").write_text("{}\n", encoding="utf-8")
    generator = runtime_root / "generator.py"
    generator.write_text("# frozen test generator\n", encoding="utf-8")
    monkeypatch.setattr(runner, "RUNTIME_ROOT", runtime_root)
    monkeypatch.setattr(runner, "GENERATOR", generator)
    monkeypatch.setattr(
        runner, "verify_source_directory", lambda _source_dir: [source_bundle]
    )
    monkeypatch.setattr(runner, "gpu_is_empty", lambda _gpu: (True, "empty"))
    monkeypatch.setattr(runner, "endpoint_ready", lambda _url: True)
    runtime_binding = {
        "schema_version": 1,
        "file_sha256": "a" * 64,
        "canonical_sha256": "b" * 64,
        "attestation": {"run_id": "cleanup-failure-test"},
    }
    monkeypatch.setattr(
        runner, "build_runtime_attestation", lambda **_kwargs: {"run_id": "test"}
    )
    monkeypatch.setattr(
        runner,
        "persist_runtime_attestation",
        lambda _path, _record: runtime_binding,
    )
    monkeypatch.setattr(
        runner,
        "run_monitored_generator",
        lambda *_args, **_kwargs: runner.subprocess.CompletedProcess(
            args=["generator"],
            returncode=0,
            stdout='{"bundle_canonical_sha256":"verified-hash"}\n',
            stderr="",
        ),
    )
    monkeypatch.setattr(
        runner,
        "validate_generated_pair",
        lambda *_args, **_kwargs: {
            "bundle_id": "pilot-review-000",
            "task_count": 1,
            "bundle_canonical_sha256": "verified-hash",
            "bundle_file_sha256": "file-hash",
            "manifest_file_sha256": "manifest-hash",
        },
    )
    commands: list[list[str]] = []

    def run_json(command: list[str], *, env: dict[str, str]) -> dict[str, Any]:
        del env
        commands.append(command)
        if "launch" in command:
            identity = run_root / "service" / "identity.json"
            identity.parent.mkdir(parents=True, exist_ok=True)
            identity.write_text("{}\n", encoding="utf-8")
            return {"ok": True}
        if "stop" in command:
            raise runner.OrchestratorError("simulated cleanup verification failure")
        raise AssertionError(command)

    monkeypatch.setattr(runner, "run_json", run_json)

    with pytest.raises(
        runner.OrchestratorError,
        match="service cleanup verification failed: simulated cleanup verification failure",
    ):
        runner.main(
            [
                "--run-root",
                str(run_root),
                "--run-id",
                "cleanup-failure-test",
                "--source-dir",
                str(source_dir),
                "--gpu",
                "6",
                "--port",
                "18066",
            ]
        )

    assert "launch" in commands[0]
    assert "stop" in commands[-1]
    assert json.loads(
        (run_root / "labeling-result.json").read_text(encoding="utf-8")
    )["status"] == "complete"


def test_monitored_generator_terminates_child_on_service_ownership_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class GeneratorProcess:
        def __init__(self) -> None:
            self.returncode: int | None = None
            self.terminate_calls = 0
            self.kill_calls = 0
            self.wait_calls: list[float | None] = []

        def poll(self) -> int | None:
            return self.returncode

        def terminate(self) -> None:
            self.terminate_calls += 1
            self.returncode = -signal.SIGTERM

        def kill(self) -> None:
            self.kill_calls += 1
            self.returncode = -signal.SIGKILL

        def wait(self, timeout: float | None = None) -> int:
            self.wait_calls.append(timeout)
            assert self.returncode is not None
            return self.returncode

        def communicate(self, timeout: float | None = None) -> tuple[str, str]:
            raise AssertionError(f"communicate must not run after drift: {timeout}")

    child = GeneratorProcess()
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *_args, **_kwargs: child)
    monkeypatch.setattr(
        runner,
        "run_json",
        lambda *_args, **_kwargs: {
            "ok": False,
            "live": True,
            "identity_error": "foreign process appeared",
        },
    )

    with pytest.raises(runner.OrchestratorError, match="ownership drifted"):
        runner.run_monitored_generator(
            ["generator", "--test"],
            env={},
            identity_path=tmp_path / "identity.json",
            deadline_monotonic=runner.time.monotonic() + 100,
        )

    assert child.terminate_calls == 1
    assert child.kill_calls == 0
    assert child.wait_calls == [10]


def test_shutdown_retry_rechecks_identity_instead_of_bypassing_checks(monkeypatch):
    calls = []
    def run(command, *, env):
        calls.append(command)
        if len(calls) == 1:
            raise runner.OrchestratorError('service CUDA identity changed while exiting')
        return {'ok': True, 'verification': {'run_processes_gone': True}}
    monkeypatch.setattr(runner, 'run_json', run)
    monkeypatch.setattr(runner.time, 'sleep', lambda _: None)
    result = runner.verified_stop_with_retry(['manager', 'stop'], env={})
    assert result['ok'] and len(calls) == 2


def test_shutdown_retry_does_not_hide_persistent_ambiguity(monkeypatch):
    calls = []
    def run(command, *, env):
        calls.append(command)
        raise runner.OrchestratorError('persistent identity ambiguity')
    monkeypatch.setattr(runner, 'run_json', run)
    monkeypatch.setattr(runner.time, 'sleep', lambda _: None)
    with pytest.raises(runner.OrchestratorError, match='persistent'):
        runner.verified_stop_with_retry(['manager', 'stop'], env={})
    assert len(calls) == 5
