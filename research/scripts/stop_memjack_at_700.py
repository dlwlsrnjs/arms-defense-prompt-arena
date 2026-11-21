"""Stop only owned additional-case workers and freeze 700 distinct valid proposals."""
import fcntl,json,os,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'research'))
from scripts import queue_memjack_additional_363 as queue
from scripts.transition_memjack_v7 import terminate_owned
q=queue.q;state=queue.STATE

def main():
 lock=(state/'target-700.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 cfg=queue.config();baseline_ids=set(cfg['baseline_valid_ids']);assert len(baseline_ids)==637
 while True:
  added=queue.added()
  q.save(state/'target-700-status.json',{'target_total':700,'baseline':637,'additional_valid':len(added),'remaining':max(0,63-len(added)),'state':'stopping' if len(added)>=63 else 'running','updated_unix':time.time()})
  if len(added)>=63:break
  time.sleep(5)
 launch=json.loads((state/'launch.json').read_text());receipts=[terminate_owned(launch['pid'],launch['command'])]
 status=json.loads((state/'status.json').read_text());python=launch['command'][0];script=launch['command'][1];runs=[]
 for gpu,pid in status['workers'].items():
  p=Path('/proc',str(pid),'cmdline')
  if not p.exists():continue
  cmd=[x.decode() for x in p.read_bytes().split(b'\0') if x]
  if len(cmd)!=7 or cmd[:3]!=[python,script,'worker'] or cmd[3:5]!=['--gpu',gpu] or cmd[5]!='--attempt':raise RuntimeError('Unexpected worker identity')
  run=q.OUT/f'attempt-{int(cmd[6]):03d}-gpu{gpu}';runs.append(run)
  receipts.append(terminate_owned(pid,cmd))
 for run in runs:q.clean_stop(run/'service/identity.json',run)
 # Keep the authorized baseline plus exactly 63 successful-format new episodes.
 baseline=[json.loads(s) for s in (ROOT/'research/deliverables/memjack-merged-review/merged-valid.jsonl').read_text().splitlines() if s.strip()]
 baseline=[x for x in baseline if x['episode_id'] in baseline_ids]
 assert len(baseline)==637
 new=sorted(queue.added(),key=lambda p:(p.stat().st_mtime,p.name))[:63]
 rows=baseline+[{'episode_id':json.loads(p.read_text())['episode_id'],'selected_version':7,'result_path':str(p),'memory_path':str(q.OUT/'memories'/p.name),'result':json.loads(p.read_text())} for p in new]
 assert len(rows)==len({x['episode_id'] for x in rows})==700
 out=ROOT/'research/deliverables/memjack-cohort-700';out.mkdir(exist_ok=True)
 (out/'cohort-700.jsonl').write_text(''.join(json.dumps(x,ensure_ascii=False)+'\n' for x in rows))
 receipt={'state':'complete','target_total':700,'unique_valid_frozen':700,'cohort_path':str(out/'cohort-700.jsonl'),'cohort_sha256':q.sha(out/'cohort-700.jsonl'),'stop_receipts':receipts,'extra_completed_preserved':max(0,len(queue.added())-63),'updated_unix':time.time(),'human_verified':False}
 q.save(state/'target-700-status.json',receipt);q.save(state/'status.json',receipt)
if __name__=='__main__':main()
