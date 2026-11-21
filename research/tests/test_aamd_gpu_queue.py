from __future__ import annotations

import pytest

from scripts import aamd_gpu_policy as policy
from scripts import manage_aamd_vllm as manager
from scripts import queue_aamd_32b_labeling as queue


def capture():
    return {'pid': 123, 'start_ticks': 100, 'uid': 1000, 'command_sha256': 'a' * 64,
            'max_gpu_memory_mib': 1024}


def row(pid='123', memory='712'):
    return {'pid': pid, 'used_memory_mib': memory, 'process_name': 'python', 'gpu_uuid': 'GPU-test'}


def test_keepalive_exemption_requires_exact_fingerprint(monkeypatch):
    pinned = capture()
    monkeypatch.setattr(policy, 'process_fingerprint', lambda _: {k:v for k,v in pinned.items() if k != 'max_gpu_memory_mib'})
    assert policy.background_allowed(row(), [pinned])
    assert not policy.background_allowed(row(), [])
    assert not policy.background_allowed(row(pid='124'), [pinned])
    assert not policy.background_allowed(row(memory='1025'), [pinned])
    assert not policy.background_allowed(row(memory='N/A'), [pinned])
    for key, changed in [('start_ticks', 101), ('uid', 1001), ('command_sha256', 'b' * 64)]:
        assert not policy.background_allowed(row(), [{**pinned, key:changed}])


def test_missing_keepalive_is_not_an_allowed_process(monkeypatch):
    def missing(_):
        raise FileNotFoundError()
    monkeypatch.setattr(policy, 'process_fingerprint', missing)
    assert not policy.background_allowed(row(), [capture()])


def test_gpu_selection_tries_other_gpu_and_never_terminates_workloads(monkeypatch):
    seen = []
    def available(index):
        seen.append(index)
        if index == 0:
            raise manager.ServiceError('busy')
        return 'GPU-free', 722
    monkeypatch.setattr(manager, 'require_empty_gpu', available)
    selected, observations = queue.choose_gpu([0, 1])
    assert selected == 1 and seen == [0, 1]
    assert observations[0]['available'] is False
    assert observations[1]['available'] is True


def test_queue_stays_waiting_if_all_gpus_are_busy(monkeypatch):
    def busy(_):
        raise manager.ServiceError('foreign research process')
    monkeypatch.setattr(manager, 'require_empty_gpu', busy)
    selected, observations = queue.choose_gpu([0, 1])
    assert selected is None
    assert len(observations) == 2
    assert all(not value['available'] for value in observations)


def test_manager_rejects_other_workloads_even_when_keepalive_is_allowed(monkeypatch):
    monkeypatch.setattr(manager, 'gpu_identity', lambda _: ('GPU-test', 722))
    monkeypatch.setattr(manager, 'compute_processes', lambda _: [row(), row(pid='456', memory='1')])
    monkeypatch.setattr(manager, 'background_allowed', lambda entry, _: entry['pid'] == '123')
    with pytest.raises(manager.ServiceError, match='compute processes'):
        manager.require_empty_gpu(0)


def test_manager_accounts_for_small_background_memory_and_rejects_unattributed_memory(monkeypatch):
    monkeypatch.setattr(manager, 'gpu_identity', lambda _: ('GPU-test', 722))
    monkeypatch.setattr(manager, 'compute_processes', lambda _: [row()])
    monkeypatch.setattr(manager, 'background_allowed', lambda *_: True)
    assert manager.require_empty_gpu(0) == ('GPU-test', 722)
    monkeypatch.setattr(manager, 'gpu_identity', lambda _: ('GPU-test', 1600))
    with pytest.raises(manager.ServiceError, match='attributable'):
        manager.require_empty_gpu(0)


def test_postlaunch_conflict_retries_only_after_verified_cleanup(tmp_path):
    import json
    (tmp_path / 'service').mkdir()
    (tmp_path / 'service/identity.json').write_text('{}')
    status = {'status': 'pre_inference_gpu_conflict'}
    assert not queue.retryable_gpu_conflict(tmp_path, status)
    receipt = {'ok': True, 'verification': {'port_closed': True, 'run_processes_gone': True},
               'watchdog': {'stopped': True}}
    p = tmp_path / 'cleanup-verification.json'
    p.write_text(json.dumps(receipt))
    assert queue.retryable_gpu_conflict(tmp_path, status)
    assert not queue.retryable_gpu_conflict(tmp_path, {'status': 'failed'})
    receipt['verification']['run_processes_gone'] = False
    p.write_text(json.dumps(receipt))
    assert not queue.retryable_gpu_conflict(tmp_path, status)
    receipt['verification']['run_processes_gone'] = True
    p.write_text(json.dumps(receipt))
    (tmp_path / 'generated').mkdir()
    (tmp_path / 'generated/generation-manifest-000.json').write_text('{}')
    assert not queue.retryable_gpu_conflict(tmp_path, status)


def test_prelaunch_conflict_with_identity_is_not_silently_retried(tmp_path):
    assert queue.retryable_gpu_conflict(tmp_path, {'status': 'blocked_gpu_busy'})
    (tmp_path / 'service').mkdir()
    (tmp_path / 'service/identity.json').write_text('{}')
    assert not queue.retryable_gpu_conflict(tmp_path, {'status': 'blocked_gpu_busy'})


def test_progress_distinguishes_validated_responses_from_published_bundles(tmp_path):
    import json
    generated = tmp_path / 'generated'
    generated.mkdir()
    (generated / 'generation-manifest-000.progress.json').write_text(json.dumps(
        {'validated_tasks': 5, 'total_tasks': 24}))
    (generated / 'generation-manifest-001.progress.json').write_text(json.dumps(
        {'validated_tasks': 25, 'total_tasks': 24}))
    (generated / 'review-bundle-000.json').write_text(json.dumps({'tasks':[
        {'llm_proposal': {}}, {'llm_proposal': {}}]}))
    (generated / 'review-bundle-manifest.json').write_text('{}')
    assert queue.labeling_progress(tmp_path) == {'validated_tasks': 5, 'published_tasks': 2}
