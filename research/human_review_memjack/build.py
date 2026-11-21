"""Freeze one cohort and reproducible probability samples; never call a GPU/model."""
import argparse,collections,fcntl,json,random,shutil,sys,time
from pathlib import Path
from common import read,save,file_sha,digest
HERE=Path(__file__).resolve().parent

def validate(mp,r,allowed,skipped):
 """Return the memory for one result/memory pair or None after counting why it is excluded."""
 if r.get('status')!='valid':skipped['unresolved']+=1;return None
 if not mp.exists():skipped['memory_missing']+=1;return None
 m=read(mp);proto=m.get('judge_provenance',{}).get('protocol')
 if proto not in allowed or m.get('schema_version')!=proto.replace('memjack-vlm-defense-review','defense-experience-memory'):skipped['wrong_protocol']+=1;return None
 if m['judgment']!=r['judgment'] or len(m['source_rounds'])!=m['judge_provenance']['source_round_count']:raise ValueError('Incomplete/inconsistent memory '+str(mp))
 if not m['judge_provenance'].get('actual_image_in_request') or not m['judge_provenance'].get('all_source_rounds_supplied'):raise ValueError('Missing actual image/full-round provenance')
 return m

def finish(out,skipped):
 out.sort(key=lambda x:(x[1]['source']['line'],x[1]['episode_id']))
 if len({m['episode_id'] for p,m in out})!=len(out):raise ValueError('Duplicate episode IDs')
 return out,dict(skipped)

def collect(run,allowed):
 out=[];skipped=collections.Counter()
 for p in (run/'results').glob('*.json'):
  m=validate(run/'memories'/p.name,read(p),allowed,skipped)
  if m is not None:out.append((run/'memories'/p.name,m))
 return finish(out,skipped)

def collect_cohort(cohort,allowed,expected_sha=None):
 """Read an already frozen cohort JSONL; each row must still agree with its on-disk result and memory."""
 if expected_sha and file_sha(cohort)!=expected_sha:raise ValueError('Cohort file hash mismatch')
 out=[];skipped=collections.Counter()
 for line in cohort.read_text().splitlines():
  if not line.strip():continue
  row=json.loads(line);r=read(row['result_path'])
  if r!=row['result']:raise ValueError('Cohort result differs from its source file: '+row['episode_id'])
  m=validate(Path(row['memory_path']),r,allowed,skipped)
  if m is None:raise ValueError('Cohort row is not a valid allowed-protocol record: '+row['episode_id'])
  if m['episode_id']!=row['episode_id']:raise ValueError('Cohort episode ID mismatch')
  out.append((Path(row['memory_path']),m))
 return finish(out,skipped)

def freeze(run,out,allow_small=False,cohort=None,cohort_sha=None):
 cfg=read(HERE/'protocol.json');allowed=cfg.get('allowed_judge_protocols',['memjack-vlm-defense-review-v6','memjack-vlm-defense-review-v7'])
 records,skipped=collect_cohort(cohort,allowed,cohort_sha) if cohort else collect(run,allowed);needed=cfg['population_size']
 if len(records)<needed and not allow_small:return {'state':'waiting','eligible_unique':len(records),'required':needed,'excluded':skipped}
 if out.exists():
  if (out/'manifest.json').exists():return {'state':'already_frozen','path':str(out)}
  raise ValueError('Output exists without completed manifest; do not overwrite')
 population=records[:min(12,needed) if allow_small else needed];N=len(population);n=min(cfg['primary_sample_size'],N);rng=random.Random(cfg['seed']);primary=rng.sample(range(N),n)
 positives=[i for i,(p,m) in enumerate(population) if m['judgment']['decision']=='success'];chosen=set(primary);have=sum(i in chosen for i in positives);target=min(cfg['minimum_success_sample'],len(positives));extra=rng.sample([i for i in positives if i not in chosen],max(0,target-have));chosen.update(extra)
 # Each allowed pipeline version must use exactly one judge prompt; a version may not silently mix prompts.
 by_protocol=collections.defaultdict(set)
 for p,m in population:by_protocol[m['judge_provenance']['protocol']].add(m['judge_provenance']['system_prompt_sha256'])
 if any(len(v)!=1 for v in by_protocol.values()):raise ValueError('Mixed judge prompts inside one pipeline version; freeze a homogeneous cohort')
 hashes={next(iter(v)) for v in by_protocol.values()};pipeline_counts=collections.Counter(m['judge_provenance']['protocol'] for p,m in population)
 image_ids=[m['image']['canonical_image'] for p,m in population]
 if len(set(image_ids))!=N:raise ValueError('Repeated images require a cluster-aware design; do not silently treat them as independent')
 stage=out.with_name(out.name+'.building');stage.mkdir(parents=True,exist_ok=False,mode=0o700)
 try:
  for d in ['cases','images','private','annotations/A','annotations/B']:(stage/d).mkdir(parents=True)
  frame=[];assigned=[]
  for i,(p,m) in enumerate(population):
   cid='case_'+digest({'seed':cfg['seed'],'episode':m['episode_id']})[:12]
   row={'case_id':cid,'episode_id':m['episode_id'],'source_line':m['source']['line'],'model_decision':m['judgment']['decision'],'image_canonical':m['image']['canonical_image'],'memory_sha256':file_sha(p),'judge_protocol':m['judge_provenance']['protocol'],'judge_system_sha256':m['judge_provenance']['system_prompt_sha256'],'cohort':'primary' if i in primary else ('success_supplement' if i in extra else 'not_sampled')};frame.append(row)
   if i not in chosen:continue
   raw=Path(m['image']['path'])
   if file_sha(raw)!=m['image']['file_sha256']:raise ValueError('Actual image hash mismatch')
   image_name=cid+raw.suffix.lower();shutil.copyfile(raw,stage/'images'/image_name)
   case={'case_id':cid,'image':image_name,'image_sha256':m['image']['file_sha256'],'rounds':[{'round':r['round'],'goal':r.get('intent_in'),'prompt':r['prompt'],'response':r['response']} for r in m['source_rounds']]}
   save(stage/'cases'/f'{cid}.json',case)
   save(stage/'private'/f'{cid}.json',{'episode_id':m['episode_id'],'judgment':m['judgment'],'observed_strategy':m['observed_strategy'],'review_disposition':m.get('review_disposition'),'evidence_with_offsets':m['evidence_with_offsets'],'supporting_evidence_with_offsets':m.get('supporting_evidence_with_offsets',[]),'normalization_actions':m['judge_provenance'].get('conservative_normalization_actions',[])})
   assigned.append(cid)
  save(stage/'private/frame.json',frame);save(stage/'protocol.json',cfg)
  orders={}
  for reviewer in ['A','B']:
   order=sorted(assigned);random.Random(str(cfg['seed'])+reviewer).shuffle(order);orders[reviewer]=order
  save(stage/'orders.json',orders)
  manifest={'protocol':cfg['protocol'],'state':'DEMO_NOT_FOR_INFERENCE' if allow_small else 'FROZEN','source_run':str(run.resolve()) if run else None,'population':N,'primary_n':n,'supplement_n':len(extra),'assigned_per_reviewer':len(assigned),'population_model_successes':len(positives),'seed':cfg['seed'],'judge_system_sha256_by_pipeline':{k:next(iter(v)) for k,v in sorted(by_protocol.items())},'pipeline_counts':dict(sorted(pipeline_counts.items())),'cohort_source':{'path':str(cohort.resolve()),'sha256':file_sha(cohort)} if cohort else None,'created_unix':time.time(),'frame_sha256':file_sha(stage/'private/frame.json'),'protocol_sha256':file_sha(stage/'protocol.json'),'sample_scheme':'SRS without replacement for overall estimates; random success-stratum top-up only for success precision/quality. Never pool supplement into overall agreement.'}
  manifest['assigned_files']={cid:{'case_sha256':file_sha(stage/'cases'/f'{cid}.json'),'proposal_sha256':file_sha(stage/'private'/f'{cid}.json'),'image':read(stage/'cases'/f'{cid}.json')['image'],'image_sha256':read(stage/'cases'/f'{cid}.json')['image_sha256']} for cid in assigned}
  save(stage/'manifest.json',manifest);stage.rename(out)
 except Exception:
  shutil.rmtree(stage);raise
 return {'state':'frozen','path':str(out),'manifest':manifest}

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--run',type=Path);ap.add_argument('--cohort',type=Path);ap.add_argument('--cohort-sha256');ap.add_argument('--out',type=Path,required=True);ap.add_argument('--watch',action='store_true');ap.add_argument('--demo',action='store_true');ap.add_argument('--zip-on-ready',action='store_true');args=ap.parse_args()
 if bool(args.run)==bool(args.cohort):ap.error('Provide exactly one of --run or --cohort')
 args.out.parent.mkdir(parents=True,exist_ok=True)
 lock=args.out.with_suffix('.watch.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 while True:
  result=freeze(args.run,args.out,args.demo,args.cohort,args.cohort_sha256);save(args.out.with_suffix('.watch-status.json'),dict(result,updated_unix=time.time()));print(json.dumps(result),flush=True)
  if result['state'] in ['frozen','already_frozen'] and args.zip_on_ready:
   from package import package
   archive=args.out.with_suffix('.zip')
   if not archive.exists():result['archive']=package(args.out,archive);save(args.out.with_suffix('.watch-status.json'),dict(result,updated_unix=time.time()))
  if result['state']!='waiting' or not args.watch:return
  time.sleep(60)
if __name__=='__main__':main()
