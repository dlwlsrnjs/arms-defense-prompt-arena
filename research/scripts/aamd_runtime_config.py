"""Portable, explicitly pinned local settings for AAMD offline tooling.

Only filesystem/runtime identity may change here. Model revision, taxonomy,
proposal prompt and decoding remain pinned by the labeling contracts.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ALLOWED_FIELDS = {'runtime_root', 'model_path', 'vllm_executable', 'vllm_version', 'vllm_entrypoint_sha256', 'allowed_background_processes'}


def load_runtime_config() -> dict[str, Any]:
    defaults = {
        'runtime_root': str(REPOSITORY_ROOT / 'research/runtime/aamd'),
        'model_path': str(REPOSITORY_ROOT.parent / 'research/models/Qwen2.5-VL-32B-Instruct'),
        'vllm_executable': str(REPOSITORY_ROOT.parent / '.venv-vllm/bin/vllm'),
        'vllm_version': '0.16.0',
        'vllm_entrypoint_sha256': None,
        'allowed_background_processes': [],
    }
    config_path = os.environ.get('AAMD_RUNTIME_CONFIG')
    if config_path:
        path = Path(config_path).expanduser()
        if not path.is_absolute():
            raise ValueError('AAMD_RUNTIME_CONFIG must be an absolute path')
        raw = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(raw, dict) or set(raw) - ALLOWED_FIELDS:
            raise ValueError('runtime profile contains unsupported fields')
        defaults.update(raw)
    for name in ('runtime_root', 'model_path', 'vllm_executable'):
        value = defaults[name]
        if not isinstance(value, str) or not Path(value).is_absolute():
            raise ValueError(f'{name} must be an absolute path')
    version = defaults['vllm_version']
    if not isinstance(version, str) or not version or len(version) > 80:
        raise ValueError('vllm_version must be a pinned version')
    sha = defaults['vllm_entrypoint_sha256']
    if sha is not None and (not isinstance(sha, str) or len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha)):
        raise ValueError('vllm_entrypoint_sha256 must be a lowercase SHA-256')
    captures = defaults['allowed_background_processes']
    if not isinstance(captures, list) or len(captures) > 1:
        raise ValueError('at most one captured keepalive may be allowed')
    for capture in captures:
        if not isinstance(capture, dict) or set(capture) != {'pid', 'start_ticks', 'uid', 'command_sha256', 'max_gpu_memory_mib'}:
            raise ValueError('invalid captured background identity')
        if any(type(capture[k]) is not int or capture[k] < 0 for k in ('pid', 'start_ticks', 'uid', 'max_gpu_memory_mib')):
            raise ValueError('invalid background identity integer')
        if not 1 <= capture['max_gpu_memory_mib'] <= 1024:
            raise ValueError('background GPU memory must be bounded to 1024 MiB')
        sha = capture['command_sha256']
        if not isinstance(sha, str) or len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha):
            raise ValueError('invalid background argv digest')
    return defaults
