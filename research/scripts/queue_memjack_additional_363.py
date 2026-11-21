"""Acquire exactly 363 new valid, distinct episodes without changing V7 adjudication."""
import argparse,fcntl,json,os,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'research'))
from scripts import queue_memjack_rejudge_v7 as q
STATE=ROOT/'research/runtime/aamd/memjack-additional-363-20261121'
class TargetReached(Exception):pass

def config():return json.loads((STATE/'selection.json').read_text())
def added():
 ids=set(config()['candidate_episode_ids']);return [p for p in (q.OUT/'results').glob('*.json') if 'memjack:'+p.stem in ids and json.loads(p.read_text()).get('status')=='valid']
def work():
 ids=set(config()['candidate_episode_ids']);return [c for c in original_work() if c['episode_id'] in ids]
original_work=q.work_cases

def worker(gpu,attempt):
 original=q.evaluate;q.work_cases=work
 def limited(port,case,run,path):
  slot=STATE/'slots'/f'{q.tid(case)}.json'
  while True:
   with (STATE/'quota.lock').open('a') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX)
    n=len(added())
    if n>=363:raise TargetReached()
    live=[]
    for p in (STATE/'slots').glob('*.json'):
     d=json.loads(p.read_text())
     if Path('/proc',str(d['pid'])).exists():live.append(p)
     else:p.unlink(missing_ok=True)
    if n+len(live)<363:
     q.save(slot,{'pid':os.getpid(),'episode_id':case['episode_id']});break
   time.sleep(3)
  try:return original(port,case,run,path)
  finally:slot.unlink(missing_ok=True)
 q.evaluate=limited
 try:q.worker(gpu,attempt)
 except TargetReached:pass
 except q.ResourceUnavailable:sys.exit(75)

def supervise():
 lock=(STATE/'supervisor.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 q.check_plan();active={};attempt=len(list(q.OUT.glob('attempt-*')))
 while True:
  for gpu,(p,log) in list(active.items()):
   if p.poll() is not None:
    log.close();del active[gpu]
    if p.returncode not in (0,75):q.save(STATE/'failure.json',{'gpu':gpu,'exit_code':p.returncode});return
  n=len(added());remaining=363-n
  q.save(STATE/'status.json',{'state':'complete' if remaining<=0 and not active else 'running' if active else 'waiting_for_free_gpu','additional_valid':n,'additional_target':363,'merged_baseline':637,'merged_valid':637+n,'remaining_valid':max(0,remaining),'workers':{str(g):p.pid for g,(p,_) in active.items()},'updated_unix':time.time()})
  if remaining<=0 and not active:return
  if remaining>0:
   for gpu in (0,1):
    if gpu in active:continue
    try:q.manager.require_empty_gpu(gpu)
    except Exception:continue
    attempt+=1;log=(STATE/f'worker-{attempt}-gpu{gpu}.log').open('a')
    p=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'worker','--gpu',str(gpu),'--attempt',str(attempt)],stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,env=os.environ.copy());active[gpu]=(p,log)
  time.sleep(20)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('mode',choices=['supervise','worker']);p.add_argument('--gpu',type=int);p.add_argument('--attempt',type=int);a=p.parse_args()
 if a.mode=='supervise':supervise()
 else:worker(a.gpu,a.attempt)
