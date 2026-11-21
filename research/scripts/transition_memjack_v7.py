"""Transition only this project's owned V6 workers after a frozen V7 pilot approval."""
import json,os,signal,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'research'))
from scripts import queue_memjack_rejudge_v7 as new
from scripts import queue_memjack_rejudge_local_twothirds as old

def snapshot(pid,expected):
 p=Path('/proc')/str(pid)
 if not p.exists():return None
 if p.stat().st_uid!=os.getuid():raise RuntimeError('Refuse foreign UID')
 cmd=(p/'cmdline').read_bytes().split(b'\0');actual=[x.decode() for x in cmd if x]
 if not actual:return None
 if actual!=expected:raise RuntimeError('Refuse unexpected process identity: '+str(pid))
 ticks=(p/'stat').read_text().rsplit(')',1)[1].split()[19]
 return {'pid':pid,'start_ticks':ticks,'command':actual,'uid':p.stat().st_uid}

def terminate_owned(pid,expected):
 a=snapshot(pid,expected)
 if a is None:return
 if snapshot(pid,expected)!=a:raise RuntimeError('Process changed before signal')
 os.kill(pid,signal.SIGTERM)
 # A paused controller must continue to receive its pending TERM.
 if snapshot(pid,expected)==a:os.kill(pid,signal.SIGCONT)
 for _ in range(50):
  if snapshot(pid,expected) is None:return a
  time.sleep(.1)
 raise RuntimeError('Controller did not stop; do not escalate signals')

def main():
 approval=json.loads((new.OUT/'pilot-approved.json').read_text());new.check_plan()
 if not approval.get('approved') or approval['system_prompt_sha256']!=__import__('hashlib').sha256(new.protocol.SYSTEM.encode()).hexdigest():raise RuntimeError('Exact pilot approval required')
 status=json.loads((old.OUT/'supervisor-status.json').read_text());workers=status['workers']
 python=str(ROOT.parent/'.venv/bin/python');script=str(ROOT/'research/scripts/queue_memjack_rejudge_local_twothirds.py')
 # Locate exact same-user supervisor; never use broad pkill patterns.
 expected=[python,script,'supervise'];controllers=[]
 for p in Path('/proc').iterdir():
  if not p.name.isdigit():continue
  try:
   if p.stat().st_uid==os.getuid() and [x.decode() for x in (p/'cmdline').read_bytes().split(b'\0') if x]==expected:controllers.append(int(p.name))
  except (FileNotFoundError,PermissionError,ProcessLookupError):pass
 if len(controllers)>1:raise RuntimeError('Ambiguous old supervisor ownership')
 receipts=[]
 for pid in controllers:receipts.append(terminate_owned(pid,expected))
 for gpu,w in workers.items():
  run=Path(w['run']);attempt=int(run.name.split('-')[1])
  receipts.append(terminate_owned(w['pid'],[python,script,'worker','--gpu',gpu,'--attempt',str(attempt)]))
 # Services are separate groups. Existing manager revalidates captured PID/start ticks,
 # UID, GPU UUID, ancestry and run identity before every service signal.
 for w in workers.values():
  run=Path(w['run']);old.clean_stop(run/'service/identity.json',run)
 summary=old.progress(old.work_cases(),export=True)
 old.save(old.OUT/'superseded-by-v7.json',{'status':'superseded_for_quality_revision','final_v6_progress':summary,'v7_run':str(new.OUT),'controller_stop_receipts':receipts,'unix':time.time()})
 old.save(old.OUT/'supervisor-status.json',{'state':'superseded_by_v7','workers':{},'summary':summary,'updated_unix':time.time()})
 new.save(new.OUT/'prior-v6-snapshot.json',{'summary':summary,'old_run':str(old.OUT),'all_local_cases_will_be_reprocessed':True,'old_results_preserved':True})
 log=(new.OUT/'supervisor.log').open('a')
 proc=subprocess.Popen([python,str(ROOT/'research/scripts/queue_memjack_rejudge_v7.py'),'supervise'],stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,env=os.environ.copy())
 new.save(new.OUT/'supervisor-launch.json',{'pid':proc.pid,'unix':time.time(),'command':[python,str(ROOT/'research/scripts/queue_memjack_rejudge_v7.py'),'supervise']})
 print(json.dumps({'old_summary':summary,'new_supervisor_pid':proc.pid}))
if __name__=='__main__':main()
