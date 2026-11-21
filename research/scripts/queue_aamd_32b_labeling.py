#!/usr/bin/env python3
"""Wait for an available GPU, run one frozen AAMD smoke batch, then exit.

The detached queue launches no service while other research workloads are present.
The managed runner retains the independent server deadline and verified cleanup.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

if str(Path(__file__).resolve().parents[1]) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import manage_aamd_vllm as manager
from scripts import run_aamd_32b_labeling as runner

STOP_REQUESTED = False


def request_stop(_signum, _frame):
    global STOP_REQUESTED
    STOP_REQUESTED = True


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def choose_gpu(indices):
    observations = []
    for index in indices:
        try:
            uuid, used = manager.require_empty_gpu(index)
            observations.append({'gpu': index, 'available': True, 'uuid': uuid, 'used_memory_mib': used})
            return index, observations
        except (manager.ServiceError, OSError, ValueError, subprocess.SubprocessError) as exc:
            observations.append({'gpu': index, 'available': False, 'reason': str(exc)})
    return None, observations


def retryable_gpu_conflict(run_root, status):
    """Retry only proven pre-inference contention with verified own cleanup."""
    identity = run_root / 'service/identity.json'
    if status.get('status') == 'blocked_gpu_busy' and not identity.exists():
        return True
    if status.get('status') != 'pre_inference_gpu_conflict':
        return False
    try:
        receipt = json.loads((run_root / 'cleanup-verification.json').read_text())
    except (OSError, ValueError):
        return False
    verification = receipt.get('verification', {})
    watchdog = receipt.get('watchdog', {})
    if not (receipt.get('ok') is True and verification.get('port_closed') is True
            and verification.get('run_processes_gone') is True
            and (watchdog.get('stopped') is True or watchdog.get('present') is False)):
        return False
    return not any((run_root / 'generated').glob('generation-manifest-*.json'))


def labeling_progress(run_root):
    validated, published = 0, 0
    for path in (run_root / 'generated').glob('generation-manifest-*.progress.json'):
        try:
            value = json.loads(path.read_text())
            count, total = value['validated_tasks'], value['total_tasks']
            if type(count) is int and type(total) is int and 0 <= count <= total:
                validated += count
        except (OSError, ValueError, KeyError, TypeError):
            continue
    for path in (run_root / 'generated').glob('review-bundle-*.json'):
        try:
            tasks = json.loads(path.read_text()).get('tasks', [])
            if isinstance(tasks, list):
                published += sum(isinstance(t, dict) and 'llm_proposal' in t for t in tasks)
        except (OSError, ValueError, TypeError):
            continue
    return {'validated_tasks': validated, 'published_tasks': published}


def unused_port():
    with socket.socket() as handle:
        handle.bind(('127.0.0.1', 0))
        return handle.getsockname()[1]


def source_commitments(source_dir):
    paths = runner.verify_source_directory(source_dir)
    ids = [runner.derive_review_bundle_id(json.loads(p.read_text())['bundle_id']) for p in paths]
    if len(ids) != len(set(ids)):
        raise ValueError('review bundle IDs collide')
    return {str(p): manager.sha256_file(p) for p in [source_dir / 'source-manifest.json', *paths]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--queue-root', type=Path, required=True)
    parser.add_argument('--gpus', type=int, nargs='+', default=[0, 1])
    parser.add_argument('--poll-seconds', type=int, default=30)
    parser.add_argument('--max-wait-seconds', type=int, default=86400)
    parser.add_argument('--idle-confirm-seconds', type=int, default=30)
    parser.add_argument('--structured-output', action='store_true')
    parser.add_argument('--bundle-limit', type=int, default=1)
    parser.add_argument('--service-deadline-seconds', type=int, default=3600)
    args = parser.parse_args(argv)
    if not args.gpus or any(g < 0 or g > 7 for g in args.gpus) or len(set(args.gpus)) != len(args.gpus):
        parser.error('supply distinct physical GPU indices in [0, 7]')
    if not 1 <= args.poll_seconds <= 60 or not 1 <= args.max_wait_seconds <= 604800 or args.bundle_limit < 1 or not 1 <= args.idle_confirm_seconds <= 300:
        parser.error('invalid polling/wait/bundle limit')
    if not 300 <= args.service_deadline_seconds <= 86400:
        parser.error('invalid service deadline')
    queue_root = manager.runtime_path(args.queue_root, label='queue_root')
    if queue_root.exists():
        parser.error('queue root must be fresh')
    queue_root.mkdir(parents=True, mode=0o700)
    source_dir = manager.runtime_path(args.source_dir, label='source_dir')
    status_path = queue_root / 'queue-status.json'
    lock_path = manager.RUNTIME_ROOT / 'queue-labeling.lock'
    with lock_path.open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            parser.error('another labeling queue already holds this runtime lock')
        profile_path = Path(os.environ['AAMD_RUNTIME_CONFIG'])
        pinned_profile = manager.sha256_file(profile_path)
        pinned_sources = source_commitments(source_dir)
        all_source_bundles = runner.verify_source_directory(source_dir)
        selected_task_count = sum(len(json.loads(path.read_text())['tasks'])
                                  for path in all_source_bundles[:args.bundle_limit])
        scripts_root = Path(__file__).resolve().parent
        pinned_code = {str(scripts_root / name): manager.sha256_file(scripts_root / name)
            for name in ('queue_aamd_32b_labeling.py', 'run_aamd_32b_labeling.py',
                         'manage_aamd_vllm.py', 'generate_aamd_taxonomy_proposals.py',
                         'aamd_gpu_policy.py', 'aamd_runtime_config.py', 'aamd_proposal_schema.py')}
        provenance = manager.attest_runtime()
        manager.atomic_json(queue_root / 'queue-plan.json', {
            'created_at_utc': utc_now(), 'queue_pid': os.getpid(),
            'gpus': args.gpus, 'poll_seconds': args.poll_seconds,
            'max_wait_seconds': args.max_wait_seconds, 'idle_confirm_seconds': args.idle_confirm_seconds,
            'bundle_limit': args.bundle_limit, 'selected_task_count': selected_task_count,
            'service_deadline_seconds': args.service_deadline_seconds,
            'structured_output_variant': args.structured_output,
            'source_file_sha256': pinned_sources, 'code_file_sha256': pinned_code,
            'runtime_profile_file': str(profile_path),
            'runtime_profile_sha256': pinned_profile, 'runtime_provenance': provenance,
            'allowed_background_processes': manager.LOCAL_RUNTIME['allowed_background_processes'],
        })
        initial = time.monotonic()
        attempts = 0
        candidate_gpu = None
        candidate_since = 0.0
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, request_stop)
        while not STOP_REQUESTED and time.monotonic() - initial < args.max_wait_seconds:
            if (manager.sha256_file(profile_path) != pinned_profile
                    or source_commitments(source_dir) != pinned_sources
                    or any(manager.sha256_file(Path(path)) != sha for path, sha in pinned_code.items())):
                manager.atomic_json(status_path, {'status': 'stopped_input_drift', 'updated_at_utc': utc_now()})
                return 2
            gpu, observations = choose_gpu(args.gpus)
            if gpu is None:
                candidate_gpu = None
                manager.atomic_json(status_path, {'status': 'waiting_for_gpu', 'queue_pid': os.getpid(),
                    'updated_at_utc': utc_now(), 'observations': observations,
                    'elapsed_wait_seconds': round(time.monotonic() - initial), 'attempts': attempts})
                # Small sleeps make cancellation responsive; this runs in a
                # detached worker, never in the interactive assistant turn.
                for _ in range(args.poll_seconds):
                    if STOP_REQUESTED:
                        break
                    time.sleep(1)
                continue
            if candidate_gpu != gpu:
                candidate_gpu, candidate_since = gpu, time.monotonic()
            if time.monotonic() - candidate_since < args.idle_confirm_seconds:
                manager.atomic_json(status_path, {'status': 'confirming_gpu_idle',
                    'queue_pid': os.getpid(), 'candidate_gpu': gpu,
                    'updated_at_utc': utc_now(), 'observations': observations,
                    'idle_confirm_seconds': args.idle_confirm_seconds, 'attempts': attempts})
                time.sleep(1)
                continue
            attempts += 1
            run_root = queue_root / f'run-{attempts:02d}-gpu{gpu}'
            command = [sys.executable, str(runner.REPOSITORY_ROOT / 'research/scripts/run_aamd_32b_labeling.py'),
                '--source-dir', str(source_dir), '--run-root', str(run_root),
                '--run-id', f'aamd-queue-{os.getpid()}-{attempts}', '--gpu', str(gpu),
                '--port', str(unused_port()), '--bundle-limit', str(args.bundle_limit),
                '--wait-seconds', '1', '--poll-seconds', '1',
                '--service-deadline-seconds', str(args.service_deadline_seconds), '--startup-seconds', '900']
            if args.structured_output:
                command.append('--structured-output')
            manager.atomic_json(status_path, {'status': 'running', 'queue_pid': os.getpid(),
                'selected_gpu': gpu, 'run_root': str(run_root), 'updated_at_utc': utc_now(), 'command': command})
            with (queue_root / f'run-{attempts:02d}.log').open('x') as log:
                child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, close_fds=True)
                stop_sent = False
                last_heartbeat = 0.0
                while child.poll() is None:
                    if time.monotonic() - last_heartbeat >= 10:
                        phase = {}
                        try:
                            phase = json.loads((run_root / 'orchestrator-status.json').read_text())
                        except (OSError, ValueError):
                            pass
                        manager.atomic_json(status_path, {'status': 'running', 'queue_pid': os.getpid(),
                            'selected_gpu': gpu, 'run_root': str(run_root), 'updated_at_utc': utc_now(),
                            'total_tasks': selected_task_count, 'phase': phase.get('status', 'launching'),
                            **labeling_progress(run_root)})
                        last_heartbeat = time.monotonic()
                    if STOP_REQUESTED and not stop_sent:
                        child.send_signal(signal.SIGINT)
                        stop_sent = True
                    time.sleep(1)
                code = child.returncode
            child_status_path = run_root / 'orchestrator-status.json'
            child_status = json.loads(child_status_path.read_text()) if child_status_path.exists() else {}
            # Resource contention returns to waiting only after our captured
            # server and watchdog have verifiably stopped. Model/contract and
            # ambiguous cleanup failures remain terminal.
            if code != 0 and retryable_gpu_conflict(run_root, child_status) and not STOP_REQUESTED:
                candidate_gpu = None
                continue
            manager.atomic_json(status_path, {'status': 'completed' if code == 0 else 'failed',
                'queue_pid': os.getpid(), 'selected_gpu': gpu, 'run_root': str(run_root),
                'returncode': code, 'updated_at_utc': utc_now(), 'runner_status': child_status,
                'total_tasks': selected_task_count, **labeling_progress(run_root)})
            return code
        manager.atomic_json(status_path, {'status': 'cancelled' if STOP_REQUESTED else 'expired',
            'queue_pid': os.getpid(), 'updated_at_utc': utc_now()})
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
