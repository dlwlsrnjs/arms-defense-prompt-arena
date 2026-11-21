"""Read-only use of owned ready V6 services to pilot V7; no service lifecycle changes."""
import concurrent.futures,json,os,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'research'))
from scripts import queue_memjack_rejudge_v7 as q
OLD=ROOT/'research/runtime/aamd/memjack-8b-rejudge-v6-20261119'
TASKS=[('0151711fc7c353e2af50d62b',1),('041f55d6de11befdbd6cc462',9),('0c05e869b291bf3eb4e7e70e',7),('1f699d64667d7078469a8bc2',7),('ee03c4c13a64ef4c1620b164',19),('ee03c4c13a64ef4c1620b164',2),('ee03c4c13a64ef4c1620b164',18)]
def main():
 data={q.tid(c):c for c in q.cases()};out=q.OUT/'pilot-c';out.mkdir(parents=True,exist_ok=True)
 def one(task):
  i,(ident,n)=task;gpu=i%2;run=OLD/('attempt-004-gpu0' if gpu==0 else 'attempt-005-gpu1');identity=run/'service/identity.json'
  status=q.manager.status(identity)
  if not status['ok'] or not status['live']:raise RuntimeError('Owned pilot endpoint not available')
  c=dict(data[ident],rounds=[r for r in data[ident]['rounds'] if r['round']==n]);dest=out/f'{ident}-r{n}'
  dest.mkdir(exist_ok=True);res=q.evaluate_group(18600+gpu,c,dest,identity)
  q.save(dest/'result.json',res)
  if res['status']=='valid':q.save(dest/'memory.json',q.protocol.memory_record(res,c))
  return {'id':ident,'round':n,'status':res['status'],'judgment':res.get('judgment'),'attempts':res.get('attempts',res.get('provenance',{}).get('attempts'))}
 with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
  results=list(pool.map(one,enumerate(TASKS)))
 q.save(out/'summary.json',{'protocol':q.protocol.PROTOCOL,'scope':'Seven fresh single-round image-grounded spot checks, not full episode reruns.','results':results,'completed_unix':time.time(),'system_prompt_sha256':__import__('hashlib').sha256(q.protocol.SYSTEM.encode()).hexdigest()})
 print(json.dumps([{'id':r['id'],'round':r['round'],'status':r['status'],'decision':(r['judgment'] or {}).get('decision')} for r in results]),flush=True)
if __name__=='__main__':main()
