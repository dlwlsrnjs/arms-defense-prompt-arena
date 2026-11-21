#!/usr/bin/env python3
"""Join the approved MemJack review on idle GPU 0, sharing per-case locks.
Leaves the GPU 1 supervisor untouched. Only the existing worker owns service
lifecycle and signaling; this helper never signals another process.
"""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'research'))
from scripts import queue_memjack_rejudge_v6 as queue

def choose_attempt(out):
    numbers=[]
    for p in out.glob('attempt-*-gpu0'):
        try:numbers.append(int(p.name.split('-')[1]))
        except (ValueError,IndexError):continue
    return max([1000,*numbers])+1

def main():
    out=queue.OUT
    lock=(out/'secondary-gpu0.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    queue.check_plan()
    approval=json.loads((out/'pilot-approved.json').read_text())
    if approval.get('pilot_cases')!=6:raise ValueError('pilot approval missing')
    data=queue.cases();idle_since=None;proc=None;log=None;attempt=None
    status_path=out/'secondary-gpu0-status.json'
    while True:
        queue.check_plan()
        recorded=sum((out/'results'/f'{queue.tid(c)}.json').exists() for c in data)
        status={'gpu':0,'total':len(data),'recorded':recorded,'remaining':len(data)-recorded,
                'shared_case_claims':True,'updated_unix':time.time()}
        if proc is not None:
            code=proc.poll()
            if code is None:
                status.update(state='running',worker_pid=proc.pid,attempt=attempt,
                              ready=(out/f'attempt-{attempt:03d}-gpu0/ready.json').exists())
            else:
                log.close();proc=None;idle_since=None
                run=out/f'attempt-{attempt:03d}-gpu0'
                if code and not (code==75 and (run/'cleanup-verification.json').exists()):
                    queue.save(status_path,dict(status,state='execution_failed',exit_code=code,attempt=attempt));return 1
        if proc is None:
            if recorded==len(data):
                queue.save(status_path,dict(status,state='complete'));return 0
            try:queue.manager.require_empty_gpu(0)
            except queue.manager.ServiceError:
                idle_since=None;status['state']='waiting_for_free_gpu'
            else:
                idle_since=idle_since or time.monotonic()
                if time.monotonic()-idle_since<30:status['state']='confirming_30_seconds_idle'
                else:
                    attempt=choose_attempt(out);log=(out/f'worker-{attempt:03d}-gpu0.log').open('a')
                    proc=subprocess.Popen([sys.executable,str(ROOT/'research/scripts/queue_memjack_rejudge_v6.py'),
                        'worker','--gpu','0','--attempt',str(attempt)],stdin=subprocess.DEVNULL,
                        stdout=log,stderr=subprocess.STDOUT,env=os.environ.copy(),start_new_session=True)
                    status.update(state='starting',worker_pid=proc.pid,attempt=attempt)
        queue.save(status_path,status);time.sleep(20)
if __name__=='__main__':raise SystemExit(main())
