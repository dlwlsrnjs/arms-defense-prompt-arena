from __future__ import annotations

import json
import os
from dataclasses import replace

import pytest

from scripts import aamd_runtime_config as config
from scripts import manage_aamd_vllm as manager


def test_runtime_profile_rejects_relative_and_unrecognized_settings(tmp_path, monkeypatch):
    path = tmp_path / 'profile.json'
    monkeypatch.setenv('AAMD_RUNTIME_CONFIG', str(path))
    path.write_text(json.dumps({'runtime_root': 'relative'}))
    with pytest.raises(ValueError, match='absolute'):
        config.load_runtime_config()
    path.write_text(json.dumps({'model_revision': 'untrusted-revision'}))
    with pytest.raises(ValueError, match='unsupported'):
        config.load_runtime_config()
    path.write_text(json.dumps({'vllm_entrypoint_sha256': 'bad'}))
    with pytest.raises(ValueError, match='SHA-256'):
        config.load_runtime_config()


def test_runtime_profile_defaults_do_not_contain_previous_host(monkeypatch):
    monkeypatch.delenv('AAMD_RUNTIME_CONFIG', raising=False)
    profile = config.load_runtime_config()
    assert '/data1/users/ljk98' not in json.dumps(profile)
    assert profile['vllm_entrypoint_sha256'] is None


def test_runtime_profile_changes_only_explicit_values(tmp_path, monkeypatch):
    monkeypatch.delenv('AAMD_RUNTIME_CONFIG', raising=False)
    defaults = config.load_runtime_config()
    path = tmp_path / 'profile.json'
    path.write_text(json.dumps({'runtime_root': str(tmp_path / 'runs')}))
    monkeypatch.setenv('AAMD_RUNTIME_CONFIG', str(path))
    assert config.load_runtime_config() == {**defaults, 'runtime_root': str(tmp_path / 'runs')}


def _service(monkeypatch):
    identity = {'pid': 100, 'process_start_ticks': 10, 'process_group_id': 100,
                'session_id': 100, 'cuda_visible_devices': '0', 'run_id': 'local-test',
                'gpu_index': 0, 'gpu_uuid': 'GPU-local'}
    leader = manager.ProcessIdentity(100, 'S', 1, 100, 100, 10, '0', 'local-test',
                                     ('python', 'vllm'), uid=os.getuid())
    child = manager.ProcessIdentity(101, 'S', 100, 100, 100, 11, '', '',
                                    ('VLLM::EngineCore',), environment_unreadable=True, uid=os.getuid())
    monkeypatch.setattr(manager, 'gpu_identity', lambda _: ('GPU-local', 1000))
    monkeypatch.setattr(manager, 'compute_processes', lambda _: [{'pid': '101'}])
    monkeypatch.setattr(manager, 'process_gpu_uuids', lambda _: {'GPU-local'})
    monkeypatch.setattr(manager, 'process_executable', lambda _: '/usr/bin/python')
    return identity, leader, child


def test_unreadable_engine_requires_live_ancestry_same_uid_and_captured_gpu(monkeypatch):
    identity, leader, child = _service(monkeypatch)
    monkeypatch.setattr(manager, 'process_group_members', lambda _: [leader, child])
    assert manager.verified_service_members(identity) == [leader, child]


@pytest.mark.parametrize('change', [
    {'uid': -1}, {'parent_pid': 999}, {'start_ticks': 10},
    {'command': ('unrelated-python',)},
    {'process_group_id': 999}, {'session_id': 999},
])
def test_unreadable_process_does_not_bypass_identity_checks(monkeypatch, change):
    identity, leader, child = _service(monkeypatch)
    monkeypatch.setattr(manager, 'process_group_members', lambda _: [leader, replace(child, **change)])
    with pytest.raises(manager.ServiceError):
        manager.verified_service_members(identity)


def test_unreadable_child_must_be_present_on_exact_gpu(monkeypatch):
    identity, leader, child = _service(monkeypatch)
    monkeypatch.setattr(manager, 'process_group_members', lambda _: [leader, child])
    monkeypatch.setattr(manager, 'process_gpu_uuids', lambda _: {'GPU-foreign'})
    with pytest.raises(manager.ServiceError):
        manager.verified_service_members(identity)


def test_unreadable_child_without_live_leader_is_not_owned(monkeypatch):
    identity, _, child = _service(monkeypatch)
    monkeypatch.setattr(manager, 'process_group_members', lambda _: [child])
    with pytest.raises(manager.ServiceError):
        manager.verified_service_members(identity)


def test_short_ipc_path_keeps_run_storage_and_rejects_conflicting_alias(tmp_path):
    from pathlib import Path
    import hashlib
    target = tmp_path / ('long-run-name-' * 8) / 'tmp'
    target.mkdir(parents=True)
    alias = manager.short_temp_alias(target)
    try:
        assert alias.resolve() == target.resolve()
        assert len(str(alias).encode()) + 37 <= 107
        assert manager.short_temp_alias(target) == alias
    finally:
        alias.unlink()
    alias.write_text('foreign file')
    try:
        with pytest.raises(manager.ServiceError, match='conflicting'):
            manager.short_temp_alias(target)
    finally:
        alias.unlink()


def test_engine_proctitle_erasure_is_valid_before_cuda_registration(monkeypatch):
    identity, leader, child = _service(monkeypatch)
    child = replace(child, environment_unreadable=False)
    monkeypatch.setattr(manager, 'process_group_members', lambda _: [leader, child])
    monkeypatch.setattr(manager, 'process_gpu_uuids', lambda _: set())
    assert manager.verified_service_members(identity) == [leader, child]


def test_engine_with_different_executable_is_rejected(monkeypatch):
    identity, leader, child = _service(monkeypatch)
    monkeypatch.setattr(manager, 'process_group_members', lambda _: [leader, child])
    monkeypatch.setattr(manager, 'process_executable', lambda pid: str(pid))
    with pytest.raises(manager.ServiceError):
        manager.verified_service_members(identity)


def test_exited_child_retries_entire_snapshot(monkeypatch):
    identity, leader, child = _service(monkeypatch)
    snapshots = iter([[leader, child], [leader]])
    monkeypatch.setattr(manager, 'process_group_members', lambda _: next(snapshots))
    monkeypatch.setattr(manager, 'process_executable', lambda _: (_ for _ in ()).throw(FileNotFoundError()))
    assert manager.verified_service_members(identity) == [leader]


def test_repeated_snapshot_races_fail_closed(monkeypatch):
    identity, leader, child = _service(monkeypatch)
    monkeypatch.setattr(manager, 'process_group_members', lambda _: [leader, child])
    monkeypatch.setattr(manager, 'process_executable', lambda _: (_ for _ in ()).throw(FileNotFoundError()))
    with pytest.raises(manager.ServiceError, match='kept changing'):
        manager.verified_service_members(identity)
