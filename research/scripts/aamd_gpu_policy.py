"""Recognize only explicitly captured, small keepalive GPU processes.

This module never signals a process. Research/model workloads cannot be exempted
by process name alone: PID start time, UID and exact argv digest must match.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence


def process_fingerprint(pid: int, *, proc_root: Path = Path('/proc')) -> dict[str, Any]:
    proc = proc_root / str(pid)
    stat = (proc / 'stat').read_text()
    closing = stat.rfind(')')
    fields = stat[closing + 2:].split()
    if closing < 0 or len(fields) <= 19 or fields[0] in {'Z', 'X', 'x'}:
        raise ValueError('process identity is unavailable')
    argv = [p.decode('utf-8') for p in (proc / 'cmdline').read_bytes().split(b'\0') if p]
    if len(argv) < 2 or Path(argv[1]).name != 'gpu_keepalive.py':
        raise ValueError('only the captured gpu_keepalive.py service may be exempted')
    return {
        'pid': pid, 'start_ticks': int(fields[19]), 'uid': proc.stat().st_uid,
        'command_sha256': hashlib.sha256(json.dumps(argv, separators=(',', ':')).encode()).hexdigest(),
    }


def background_allowed(row: Mapping[str, Any], captures: Sequence[Mapping[str, Any]]) -> bool:
    try:
        pid = int(row['pid'])
        memory = int(row['used_memory_mib'])
        for capture in captures:
            if capture['pid'] == pid:
                cap = capture['max_gpu_memory_mib']
                if type(cap) is not int or not 1 <= cap <= 1024 or not 0 <= memory <= cap:
                    return False
                return process_fingerprint(pid) == {k: capture[k] for k in (
                    'pid', 'start_ticks', 'uid', 'command_sha256')}
    except (KeyError, TypeError, ValueError, OSError, UnicodeError):
        return False
    return False
