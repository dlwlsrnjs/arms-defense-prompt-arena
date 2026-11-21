#!/usr/bin/env python3
"""Independent, resumable three-model RCAT7 replication; never changes baseline."""
import argparse
import collections
import csv
import hashlib
import html
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'research'))
from scripts import generate_aamd_taxonomy_proposals as gen
from scripts import manage_aamd_vllm as manager
from scripts.aamd_proposal_schema import proposal_schema, POLICY
BASE = ROOT / 'research/runtime/aamd'
OUT = BASE / 'three-model-307-20261119'
OLD = ROOT.parent
SPECS = {
 'qwen3': {'id':'Qwen/Qwen3-32B','revision':'9216db5781bf21249d130ec9da846c4624c16137','directory':'Qwen3-32B','flags':[]},
 'mistral': {'id':'mistralai/Mistral-Small-3.1-24B-Instruct-2503','revision':'68faf511d618ef198fef186659617cfd2eb8e33a','directory':'Mistral-Small-3.1-24B-Instruct-2503','flags':['--tokenizer-mode','mistral','--config-format','mistral','--load-format','mistral']},
}

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path, value):
 path.parent.mkdir(parents=True, exist_ok=True)
 tmp = path.with_suffix(path.suffix+'.tmp')
 tmp.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n'); tmp.replace(path)
def inputs():
 taxonomy=json.loads(gen.DEFAULT_TAXONOMY_PATH.read_text())
 config=json.loads(gen.DEFAULT_CONFIG_PATH.read_text())
 prompt=gen.DEFAULT_PROMPT_PATH.read_bytes()
 contract=gen.build_taxonomy_contract(taxonomy,config,prompt)
 tasks=[]
 for p in sorted((BASE/'source-20261118').glob('source-bundle-*.json')):
  tasks.extend(json.loads(p.read_text())['tasks'])
 assert len(tasks)==307 and len({t['task_id'] for t in tasks})==307
 return taxonomy,config,prompt.decode(),contract,tasks

def rows(key, tasks, contract):
 p=OUT/key/'results.jsonl'
 result={}
 if p.exists():
  for line in p.read_text().splitlines():
   row=json.loads(line); tid=row['task_id']
   if tid in result: raise ValueError('duplicate task result')
   task=next(t for t in tasks if t['task_id']==tid)
   if row['record_hash']!=task['record_hash']: raise ValueError('record drift')
   if row['status']=='valid': gen.validate_proposal_body(row['body'],task,contract)
   result[tid]=row
 return result

def attest(spec):
 model=OLD/'research/models'/spec['directory']
 binary=OLD/'.venv-vllm/bin/vllm'
 if sha(binary)!='c593d6f7e96ce0f42d6b0b4efe7165651f1f856e36e9f484fe340ecfdacc927a': raise ValueError('vLLM binary drift')
 version=subprocess.check_output([str(binary.parent/'python'),'-c',"import importlib.metadata;print(importlib.metadata.version('vllm'))"],text=True).strip()
 if version!='0.16.0': raise ValueError('vLLM version drift')
 entries=[]
 for p in sorted(model.iterdir()):
  if not p.is_file(): continue
  meta=(model/'.cache/huggingface/download'/f'{p.name}.metadata').read_text().splitlines()
  if meta[0]!=spec['revision']: raise ValueError(f'revision mismatch: {p}')
  entries.append({'name':p.name,'size':p.stat().st_size,'revision':meta[0],'object_id':meta[1], 'sha256':sha(p) if p.suffix!='.safetensors' else None})
 weights={p.name for p in model.glob('*.safetensors')}
 if spec['directory']=='Qwen3-32B':
  expected=set(json.loads((model/'model.safetensors.index.json').read_text())['weight_map'].values())
 else: expected={'consolidated.safetensors'}
 if weights!=expected: raise ValueError('weight set mismatch')
 return {'model_id':spec['id'],'model_revision':spec['revision'],'vllm_version':version,'vllm_entrypoint_sha256':sha(binary),'files':entries,'attestation':'HF revision/object IDs and local sizes; small files SHA256; weights not fully rehashed'}

def baseline(tasks,contract):
 result={}
 for p in sorted((BASE/'full-307-queue-20261119-01/run-01-gpu0/generated').glob('review-bundle-*.json')):
  if p.name=='review-bundle-manifest.json':continue
  for task in json.loads(p.read_text())['tasks']:
   proposal=task['llm_proposal']
   body={k:proposal[k] for k in ('mapping_status','reviewed_axes','locked_axes_hash','benign_confound','rationale')}
   source=next(t for t in tasks if t['task_id']==task['task_id'])
   assert source['record_hash']==task['record_hash']
   gen.validate_proposal_body(body,source,contract)
   result[task['task_id']]={'status':'valid','body':body}
 assert len(result)==307
 return result

def report():
 _,_,_,contract,tasks=inputs()
 data={'baseline':baseline(tasks,contract),**{k:rows(k,tasks,contract) for k in SPECS}}
 summary={'task_count':307,'complete':all(len(data[k])==307 for k in SPECS),'models':{k:{'recorded':len(v),'valid':sum(r['status']=='valid' for r in v.values()),'errors':sum(r['status']!='valid' for r in v.values())} for k,v in data.items()},'agreements':{},'limitations':['Agreement is not accuracy; no gold labels.','Payload-free abstract evidence; no direct evaluation of images or attack success.','Qwen3 uses enable_thinking=false; explicit final rationales only.','Baseline and new models share the constrained JSON schema.']}
 def labels(r):
  b=r['body'];return {'mapping_status':b['mapping_status'],**{a['axis']:a['code'] for a in b['reviewed_axes']},'benign_confound':b['benign_confound']['code']}
 keys=list(data)
 for key, values in data.items():
  valid=[labels(r) for r in values.values() if r['status']=='valid']
  summary['models'][key]['label_distribution']={axis:dict(collections.Counter(r[axis] for r in valid)) for axis in valid[0]} if valid else {}
 for i,a in enumerate(keys):
  for b in keys[i+1:]:
   pairs=[(labels(data[a][t]),labels(data[b][t])) for t in data[a].keys()&data[b].keys() if data[a][t]['status']=='valid' and data[b][t]['status']=='valid']
   summary['agreements'][a+' vs '+b]={'denominator':len(pairs),'axes':{axis:{'agree':sum(x[axis]==y[axis] for x,y in pairs),'rate':sum(x[axis]==y[axis] for x,y in pairs)/len(pairs)} for axis in pairs[0][0]} if pairs else {}}
 save(OUT/'comparison-summary.json',summary)
 assembled=[]
 with (OUT/'comparison.csv').open('w',newline='') as f:
  writer=csv.writer(f);writer.writerow(['task_id','model','status','axis','label','confidence','evidence_handles','rationale'])
  for t in tasks:
   group={'task_id':t['task_id'],'record_handle':t['record_handle'],'models':{}}
   for key in keys:
    r=data[key].get(t['task_id'],{'status':'pending'});group['models'][key]=r
    if r['status']=='valid':
     body=r['body']; writer.writerow([t['task_id'],key,'valid','mapping_status',body['mapping_status'],'','',body['rationale']])
     for axis in body['reviewed_axes']:writer.writerow([t['task_id'],key,'valid',axis['axis'],axis['code'],axis['confidence'],json.dumps(axis['evidence_handles']),axis['rationale']])
     c=body['benign_confound'];writer.writerow([t['task_id'],key,'valid','benign_confound',c['code'],c['plausibility'],json.dumps(c['evidence_handles']),c['rationale']])
    else:writer.writerow([t['task_id'],key,r['status'],'','','','',r.get('error','')])
   vals=[labels(v) for v in group['models'].values() if v['status']=='valid']
   group['disagreement']=len(vals)>1 and any(v!=vals[0] for v in vals[1:]);assembled.append(group)
 save(OUT/'comparison-all-307.json',assembled)
 cards=[]
 for row in assembled:
  sections=''.join('<section><h3>'+html.escape(k)+'</h3><pre>'+html.escape(json.dumps(v,ensure_ascii=False,indent=2))+'</pre></section>' for k,v in row['models'].items())
  cards.append('<article class="'+('disagree' if row['disagreement'] else 'agree')+'"><h2>'+html.escape(row['task_id'])+'</h2><div>'+sections+'</div></article>')
 (OUT/'comparison.html').write_text('<!doctype html><meta charset="utf-8"><title>307건 3개 모델 비교</title><style>body{font-family:sans-serif;margin:24px}article{border-top:2px solid #999}article>div{display:flex;gap:16px}section{width:33%;min-width:0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}.disagree{background:#fff5df}</style><h1>307건 모델 라벨·판정 이유 비교</h1><p>일치율은 정확도가 아닙니다. 미완료·오류 건은 별도 표시하며, 판정 이유는 모델의 최종 설명입니다.</p><label><input type="checkbox" onchange="document.querySelectorAll(\'.agree\').forEach(e=>e.hidden=this.checked)">불일치만 보기</label><pre>'+html.escape(json.dumps(summary,ensure_ascii=False,indent=2))+'</pre>'+''.join(cards))
 return summary

def worker(key,gpu,attempt):
 spec=SPECS[key];taxonomy,config,prompt,contract,tasks=inputs()
 done=rows(key,tasks,contract);run=OUT/key/f'attempt-{attempt:03d}-gpu{gpu}'
 run.mkdir(parents=True,exist_ok=True)
 provenance=attest(spec)
 if provenance!=json.loads((OUT/f'{key}-attestation.json').read_text()):raise ValueError('model files drifted since comparison was prepared')
 save(run/'model-provenance.json',provenance)
 wrapper=run/'vllm-wrapper';binary=OLD/'.venv-vllm/bin/vllm'
 wrapper.write_text('#!/bin/sh\nexec '+shlex.quote(str(binary))+' "$@" '+shlex.join(spec['flags'])+'\n');wrapper.chmod(0o700)
 manager.MODEL_ID=spec['id'];manager.MODEL_REVISION=spec['revision'];manager.MODEL_PATH=OLD/'research/models'/spec['directory'];manager.VLLM=wrapper
 manager.attest_runtime=lambda:dict(provenance,wrapper_sha256=sha(wrapper))
 identity_path=run/'service/identity.json';port=18400+gpu
 try:
  manager.launch(argparse.Namespace(run_id=f'compare-{key}-{attempt:03d}',gpu=gpu,run_root=str(run),port=port,deadline_seconds=21600,gpu_memory_utilization=.94,max_model_len=16384,max_num_seqs=1))
  deadline=time.monotonic()+1200
  opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
  while True:
   status=manager.status(identity_path)
   if not status['ok']:raise RuntimeError('resource conflict: '+str(status))
   if not status['live']:raise RuntimeError('server exited during startup')
   try:
    with opener.open(f'http://127.0.0.1:{port}/v1/models',timeout=3) as resp:
     listed=json.load(resp)
     if any(v['id']==spec['id'] for v in listed['data']):break
   except Exception:pass
   if time.monotonic()>deadline:raise RuntimeError('server readiness timeout')
   time.sleep(5)
  for task in tasks:
   if task['task_id'] in done:continue
   status=manager.status(identity_path)
   if not status['ok'] or not status['live']:raise RuntimeError('resource conflict or server stopped: '+str(status))
   request=gen.build_chat_request(gen.render_prompt(prompt,taxonomy,task),config);request['model']=spec['id']
   request['response_format']={'type':'json_schema','json_schema':{'name':'rcat7_proposal','strict':True,'schema':proposal_schema(task,contract)}}
   if key=='qwen3':request['chat_template_kwargs']={'enable_thinking':False}
   raw_request=gen.canonical_json_bytes(request)
   row={'task_id':task['task_id'],'record_hash':task['record_hash'],'model_id':spec['id'],'revision':spec['revision'],'request_sha256':hashlib.sha256(raw_request).hexdigest(),'structured_output_policy':POLICY}
   # Transport failure is resumable; never invent or repair a proposal.
   req=urllib.request.Request(f'http://127.0.0.1:{port}/v1/chat/completions',data=raw_request,headers={'Content-Type':'application/json'})
   try:
    with opener.open(req,timeout=900) as resp:raw=resp.read()
   except Exception:
    if not manager.status(identity_path)['ok']:
     raise RuntimeError('resource conflict during inference')
    raise
   (run/(task['task_id']+'.response.json')).write_bytes(raw)
   row['response_sha256']=hashlib.sha256(raw).hexdigest()
   try:
    completion=json.loads(raw)
    if completion['model']!=spec['id']:raise ValueError('response model mismatch')
    choice=completion['choices'][0]
    if choice['finish_reason']!='stop':raise ValueError('incomplete response: '+str(choice['finish_reason']))
    row['body']=gen.validate_proposal_body(gen.strict_json_loads(choice['message']['content'],name='comparison proposal'),task,contract)
    row['usage']=completion.get('usage');row['status']='valid'
   except Exception as exc:row['status']='error';row['error']=str(exc)
   with (OUT/key/'results.jsonl').open('a') as f:f.write(json.dumps(row,ensure_ascii=False)+'\n');f.flush();os.fsync(f.fileno())
   done[task['task_id']]=row
   save(OUT/key/'progress.json',{'recorded':len(done),'valid':sum(v['status']=='valid' for v in done.values()),'total':307,'last_task_id':task['task_id']})
  return 0
 finally:
  if identity_path.exists():
   manager.atomic_json(run/'service/completion.json',{'status':'comparison-worker-ended'})
   error=None
   for _ in range(5):
    try:
     receipt=manager.stop_identity(identity_path,reason='comparison worker finished or yielded');manager.stop_watchdog(identity_path);save(run/'cleanup-verification.json',receipt);error=None;break
    except Exception as exc:error=exc;time.sleep(1)
   if error:raise error

def supervise():
 if (OUT/'input-modality-correction.json').exists():
  raise RuntimeError('This text-only comparison is retired; multimodal input correction required. See input-modality-correction.json')
 import fcntl
 OUT.mkdir(parents=True,exist_ok=True)
 lock=(OUT/'supervisor.lock').open('w');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 _,config,_,contract,tasks=inputs();baseline(tasks,contract)
 frozen_paths=[gen.DEFAULT_CONFIG_PATH,gen.DEFAULT_PROMPT_PATH,gen.DEFAULT_TAXONOMY_PATH,*sorted((BASE/'source-20261118').glob('*.json')),Path(__file__),Path(gen.__file__),Path(manager.__file__),ROOT/'research/scripts/aamd_proposal_schema.py',*sorted((BASE/'full-307-queue-20261119-01/run-01-gpu0/generated').glob('review-bundle-*.json')),OUT/'qwen3-attestation.json',OUT/'mistral-attestation.json']
 fingerprint={str(p):sha(p) for p in frozen_paths}
 manifest=OUT/'comparison-plan.json'
 plan={'models':SPECS,'baseline_model':gen.EXACT_MODEL_ID,'baseline_revision':gen.EXACT_MODEL_REVISION,'count':307,'decoding':config['decoding'],'schema_policy':POLICY,'qwen3_enable_thinking':False,'file_sha256':fingerprint}
 if manifest.exists() and json.loads(manifest.read_text())!=plan:raise ValueError('comparison plan drift')
 save(manifest,plan)
 active={};attempts={k:len(list((OUT/k).glob('attempt-*'))) for k in SPECS};failed={};idle={}
 while True:
  if any(sha(Path(p))!=s for p,s in fingerprint.items()):raise RuntimeError('frozen inputs/code changed')
  for key,(proc,gpu,log) in list(active.items()):
   code=proc.poll()
   if code is not None:
    log.close();del active[key]
    if code!=0:
     last=OUT/key/f'attempt-{attempts[key]:03d}-gpu{gpu}'
     if code==75 and (last/'cleanup-verification.json').exists():pass
     else:failed[key]={'exit_code':code,'attempt':str(last)}
  summary=report()
  if all(len(rows(k,tasks,contract))==307 or k in failed for k in SPECS) and not active:
   save(OUT/'completion.json',{'status':'complete' if not failed else 'failed','failures':failed,'summary':summary});return
  occupied={v[1] for v in active.values()}
  for gpu in (0,1):
   if gpu in occupied:continue
   try:manager.require_empty_gpu(gpu)
   except Exception:idle.pop(gpu,None);continue
   idle.setdefault(gpu,time.monotonic())
   if time.monotonic()-idle[gpu]<30:continue
   pending=[k for k in SPECS if k not in active and k not in failed and len(rows(k,tasks,contract))<307]
   if not pending:continue
   key=pending[0];attempts[key]+=1
   (OUT/key).mkdir(exist_ok=True)
   log=(OUT/key/f'worker-{attempts[key]:03d}.log').open('a')
   proc=subprocess.Popen([sys.executable,str(Path(__file__)),'worker','--key',key,'--gpu',str(gpu),'--attempt',str(attempts[key])],stdout=log,stderr=subprocess.STDOUT,env=os.environ.copy(),start_new_session=True)
   active[key]=(proc,gpu,log);idle.pop(gpu,None)
  save(OUT/'supervisor-status.json',{'active':{k:{'pid':v[0].pid,'gpu':v[1]} for k,v in active.items()},'failed':failed,'progress':summary['models'],'updated_unix':time.time(),'state':'running' if active else 'waiting_for_free_gpu'})
  time.sleep(20)

if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['supervise','worker','report','attest']);parser.add_argument('--key',choices=SPECS);parser.add_argument('--gpu',type=int);parser.add_argument('--attempt',type=int);args=parser.parse_args()
 if args.mode=='report': print(json.dumps(report(),ensure_ascii=False,indent=2))
 elif args.mode=='attest':print(json.dumps(attest(SPECS[args.key]),ensure_ascii=False,indent=2))
 elif args.mode=='supervise':supervise()
 else:
  try:sys.exit(worker(args.key,args.gpu,args.attempt))
  except Exception as exc:
   import traceback;traceback.print_exc()
   # Retry only a captured GPU conflict after the finally block verified cleanup.
   sys.exit(75 if 'resource conflict' in str(exc) else 1)
