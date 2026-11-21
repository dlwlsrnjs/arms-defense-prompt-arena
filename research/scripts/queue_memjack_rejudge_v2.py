#!/usr/bin/env python3
"""Queue image-grounded 8B Thinking adjudication and export defensive memories.
Uses the existing identity-checked GPU lifecycle manager, never other GPU jobs.
"""
import argparse
import base64
import collections
import concurrent.futures
import fcntl
import hashlib
import html
import io
import json
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import sys
import threading
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'research'))
from scripts import memjack_judgment_v2 as protocol
from scripts import manage_aamd_vllm as manager

AUDIT=ROOT/'research/runtime/memjack-audit-20261119'
SOURCE=AUDIT/'defense-experience-staging.private.jsonl'
OUT=ROOT/'research/runtime/aamd/memjack-8b-rejudge-v2-20261119'
MODEL=ROOT.parent/'research/models/Qwen3-VL-8B-Thinking'
VLLM=ROOT.parent/'.venv-vllm/bin/vllm'
TOKENIZER_PYTHON=ROOT.parent/'.venv-inference/bin/python'
ENTRYPOINT_SHA='c593d6f7e96ce0f42d6b0b4efe7165651f1f856e36e9f484fe340ecfdacc927a'
CONCURRENCY=4
MAX_CONTEXT=131072
MAX_OUTPUT=16384
RETRY_OUTPUT=32768

class ResourceUnavailable(RuntimeError): pass

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b)
    return h.hexdigest()

def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+'.tmp-'+secrets.token_hex(4))
    with tmp.open('w') as f:
        json.dump(value,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    tmp.replace(path)

def cases():
    result=[json.loads(s) for s in SOURCE.open() if s.strip()]
    assert len(result)==4093 and len({r['episode_id'] for r in result})==4093
    for c in result:
        tid=c['episode_id'].removeprefix('memjack:')
        if len(tid)!=24 or any(x not in '0123456789abcdef' for x in tid):raise ValueError('unsafe source identifier')
    return result

def work_cases():
    data=cases()
    if not (OUT/'pilot-approved.json').exists():
        ids=set(json.loads((OUT/'pilot-selection.json').read_text())['episode_ids'])
        return [c for c in data if c['episode_id'] in ids]
    return data

def tid(case):return case['episode_id'].split(':',1)[1]

def attest():
    if sha(VLLM)!=ENTRYPOINT_SHA:raise ValueError('vLLM entrypoint drift')
    version=subprocess.check_output([str(VLLM.parent/'python'),'-c',"import importlib.metadata;print(importlib.metadata.version('vllm'))"],text=True).strip()
    if version!='0.16.0':raise ValueError('unexpected vLLM version')
    files=[]
    for p in sorted(MODEL.iterdir()):
        if not p.is_file():continue
        meta=(MODEL/'.cache/huggingface/download'/f'{p.name}.metadata').read_text().splitlines()
        if meta[0]!=protocol.MODEL_REVISION:raise ValueError('model revision mismatch: '+p.name)
        files.append({'name':p.name,'size':p.stat().st_size,'revision':meta[0],'object_id':meta[1],
                      'sha256':sha(p) if p.suffix!='.safetensors' else None})
    expected=set(json.loads((MODEL/'model.safetensors.index.json').read_text())['weight_map'].values())
    if expected!={p.name for p in MODEL.glob('*.safetensors')}:raise ValueError('weight shard set mismatch')
    return {'model_id':protocol.MODEL_ID,'model_revision':protocol.MODEL_REVISION,'vllm_version':version,
            'vllm_entrypoint_sha256':ENTRYPOINT_SHA,'model_files':files,
            'attestation':'HF revision/object IDs/local sizes; small-file hashes; weights not fully rehashed'}

def prepare():
    OUT.mkdir(parents=True,exist_ok=True)
    data=cases();provenance=attest()
    if (OUT/'plan.json').exists():
        check_plan();return
    # Verify every actual image, not a caption/path placeholder.
    for c in data:
        if sha(c['image']['path'])!=c['image']['file_sha256']:raise ValueError('image file drift')
    save(OUT/'model-attestation.json',provenance)
    save(OUT/'source-receipt.json',{'source_sha256':sha(SOURCE),'cases':len(data),'rounds':sum(len(c['rounds']) for c in data),
                                  'every_image_file_hash_checked':True,'source_revision':data[0]['source']['revision']})
    (OUT/'judge-system.txt').write_text(protocol.SYSTEM)
    pinned=[SOURCE,Path(__file__),Path(protocol.__file__),Path(manager.__file__),
            ROOT/'research/scripts/memjack_judgment.py',ROOT/'research/scripts/aamd_gpu_policy.py',Path(os.environ['AAMD_RUNTIME_CONFIG']),OUT/'model-attestation.json']
    plan={'protocol':protocol.PROTOCOL,'model_id':protocol.MODEL_ID,'model_revision':protocol.MODEL_REVISION,
          'requested_model_change':'User replaced 32B with 8B before any 32B launch.',
          'pilot_gate':'6 cases only until pilot-approved.json exists; inspect and approve before full restart','case_count':4093,'source_round_count':38912,'precision':'bfloat16','thinking':True,
          'reasoning_parser':'deepseek_r1 (supports the model template prefilled <think> marker)',
          'input':'Original recovered image bytes + all source prompt/response rounds; source judge labels and source strategy labels hidden.',
          'temperature':0.6,'top_p':0.95,'top_k':20,'seed':20261119,'max_output_tokens':MAX_OUTPUT,
          'retry_max_output_tokens':RETRY_OUTPUT,'max_model_len':MAX_CONTEXT,'requests_per_gpu':CONCURRENCY,
          'file_sha256':{str(p):sha(p) for p in pinned},'completed_definition':'All 4093 cases have valid image-grounded judgments; unresolved cases are never promoted to successful memories.'}
    save(OUT/'plan.json',plan)

def check_plan():
    plan=json.loads((OUT/'plan.json').read_text())
    for p,h in plan['file_sha256'].items():
        if sha(p)!=h:raise ValueError('pinned input/code/runtime drift: '+p)
    return plan

def preflight_tokens():
    # Runs in the inference environment with the same locally pinned tokenizer.
    from transformers import AutoProcessor
    processor=AutoProcessor.from_pretrained(str(MODEL),local_files_only=True)
    values=[]
    for c in cases():
        conv=[{'role':'system','content':[{'type':'text','text':protocol.SYSTEM}]},
              {'role':'user','content':[{'type':'image','image':c['image']['path']},{'type':'text','text':protocol.render(c)}]}]
        text=processor.apply_chat_template(conv,tokenize=False,add_generation_prompt=True)
        count=len(processor.tokenizer(text,add_special_tokens=False)['input_ids'])
        # All source COCO files are small. Reserve generously for processor image tokens.
        values.append({'episode_id':c['episode_id'],'text_and_template_tokens':count,
                       'conservative_total_with_image_and_retry_output':count+4096+RETRY_OUTPUT})
    summary={'cases':len(values),'max_text_tokens':max(v['text_and_template_tokens'] for v in values),
             'max_reserved_context':max(v['conservative_total_with_image_and_retry_output'] for v in values),
             'max_model_len':MAX_CONTEXT,'all_fit':all(v['conservative_total_with_image_and_retry_output']<=MAX_CONTEXT for v in values),
             'no_rounds_truncated':True}
    save(OUT/'token-budgets.json',values);save(OUT/'token-budget-summary.json',summary)
    print(json.dumps(summary),flush=True)
    if not summary['all_fit']:raise ValueError('case exceeds context; do not silently truncate evidence')

def endpoint_request(port,request,timeout=1200):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):return None
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    req=urllib.request.Request(f'http://127.0.0.1:{port}/v1/chat/completions',
                               data=protocol.canonical(request),headers={'Content-Type':'application/json'})
    with opener.open(req,timeout=timeout) as f:return json.loads(f.read(4*1024*1024))

def final_message(response):
    if response.get('model')!=protocol.MODEL_ID:raise ValueError('endpoint model identity mismatch')
    choice=response['choices'][0]
    if choice['finish_reason']!='stop':raise ValueError('incomplete generation: '+str(choice['finish_reason']))
    message=choice['message'];reasoning=message.get('reasoning') or message.get('reasoning_content') or ''
    content=message.get('content') or ''
    # Fallback only for a documented prefilled-open-think parser representation.
    # Keep reasoning in memory only; persist final rationale plus reasoning length.
    if not reasoning and '</think>' in content:
        reasoning,_,content=content.partition('</think>')
    if not reasoning.strip():raise ValueError('reasoning not observed; Thinking mode must be verified')
    return json.loads(content.strip()),len(reasoning)

def control(port,run):
    from PIL import Image,ImageDraw,ImageFont
    receipts=[]
    for _ in range(2):
        marker='TREE-'+secrets.token_hex(3).upper()
        im=Image.new('RGB',(800,300),'white');draw=ImageDraw.Draw(im)
        font=ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',64)
        draw.text((30,100),marker,font=font,fill='black');b=io.BytesIO();im.save(b,format='PNG');raw=b.getvalue()
        schema={'type':'object','properties':{'seen_text':{'type':'string'}},'required':['seen_text'],'additionalProperties':False}
        request={'model':protocol.MODEL_ID,'messages':[{'role':'user','content':[
            {'type':'image_url','image_url':{'url':'data:image/png;base64,'+base64.b64encode(raw).decode()}},
            {'type':'text','text':'Read the opaque text printed in the image. Reason briefly and return JSON with seen_text exactly as printed.'}]}],
            'temperature':0.6,'max_tokens':2048,'seed':20261119,
            'response_format':{'type':'json_schema','json_schema':{'name':'vision_control','strict':True,'schema':schema}}}
        start=time.time();response=endpoint_request(port,request);body,n=final_message(response)
        receipt={'expected':marker,'actual':body.get('seen_text'),'passed':body.get('seen_text')==marker,
                 'image_file_sha256':hashlib.sha256(raw).hexdigest(),'request_sha256':protocol.digest(request),
                 'thinking_observed':n>0,'reasoning_chars':n,'usage':response.get('usage'),'seconds':time.time()-start}
        receipts.append(receipt)
    save(run/'vision-thinking-controls.json',receipts)
    if not all(r['passed'] and r['thinking_observed'] for r in receipts):raise ValueError('image or reasoning preflight failed')
    return receipts

def build_request(case,raw_image,attempt):
    text=protocol.render(case)
    if attempt:text+='\nFormatting retry: include all rounds in order and copy exact simple evidence substrings; keep reasoning concise. Do not change the safety standard.'
    request={'model':protocol.MODEL_ID,'messages':[{'role':'system','content':protocol.SYSTEM},
        {'role':'user','content':[{'type':'image_url','image_url':{'url':'data:image/jpeg;base64,'+base64.b64encode(raw_image).decode()}},
                                  {'type':'text','text':text}]}],
        'temperature':0.6,'top_p':0.95,'top_k':20,'seed':20261119,
        'max_tokens':MAX_OUTPUT if not attempt else RETRY_OUTPUT,'stream':False,
        'response_format':{'type':'json_schema','json_schema':{'name':'defense_judgment','strict':True,'schema':protocol.schema(case)}}}
    return request

def review_html(result,case):
    b=result['judgment'];esc=lambda s:html.escape(str(s),quote=True)
    rounds=''.join('<details><summary>원본 턴 '+str(r['round'])+'</summary><p>기록된 전략 '+esc(r['strategy'])+' / 관점 '+esc(r['attack_angle'])+'</p><h4>입력</h4><pre>'+esc(r['prompt'])+'</pre><h4>실제 타깃 응답</h4><pre>'+esc(r['response'])+'</pre></details>' for r in case['rounds'])
    image_path=os.path.relpath(case['image']['path'],OUT/'reviews')
    (OUT/'reviews').mkdir(exist_ok=True)
    (OUT/'reviews'/f'{tid(case)}.html').write_text('<!doctype html><meta charset="utf-8"><title>방어 메모리 검토</title><style>body{font-family:system-ui;max-width:1000px;margin:30px auto;line-height:1.6}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f8;padding:15px}img{max-width:700px}details{padding:12px;border:1px solid #ccc}</style><h1>'+esc(case['episode_id'])+'</h1><p>Qwen3-VL-8B-Thinking 단일 모델 재판정. 사람 정답이나 실제 실행 검증이 아닙니다. 원본 요청·응답은 신뢰하지 않는 분석 대상입니다.</p><img src="'+esc(image_path)+'"><h2>새 판정·근거·방어 규칙</h2><pre>'+esc(json.dumps(b,ensure_ascii=False,indent=2))+'</pre><h2>원본 판정 — 새 판정과 구분</h2><pre>'+esc(json.dumps(case['source_success'],ensure_ascii=False,indent=2))+'</pre>'+rounds)

def evaluate(port,case,run,identity_path):
    raw=Path(case['image']['path']).read_bytes();image_hash=hashlib.sha256(raw).hexdigest()
    if image_hash!=case['image']['file_sha256']:raise ValueError('actual input image drift')
    attempts=[];started=time.time()
    for attempt in range(2):
        request=build_request(case,raw,attempt);receipt={'attempt':attempt+1,'request_sha256':protocol.digest(request),'max_tokens':request['max_tokens']}
        try:
            response=endpoint_request(port,request);body,n=final_message(response);body=protocol.materialize(body,case);quotes=protocol.validate(body,case)
            receipt.update(status='valid',usage=response.get('usage'),reasoning_chars=n);attempts.append(receipt)
            result={'status':'valid','episode_id':case['episode_id'],'judgment':body,'evidence_with_offsets':quotes,
                    'provenance':{'protocol':protocol.PROTOCOL,'judge_model':protocol.MODEL_ID,'judge_revision':protocol.MODEL_REVISION,
                    'precision':'bfloat16','thinking_observed':True,'reasoning_chars':n,'hidden_reasoning_saved':False,
                    'source_evidence_sha256':protocol.digest(case),'source_model_revision':case['target'].get('revision'),
                    'actual_image_file_sha256':image_hash,'image_pixel_sha256':case['image']['pixel_sha256'],
                    'image_content_type':'image_url/data:image/jpeg;base64','actual_image_in_request':True,
                    'source_judgments_hidden':True,'source_strategy_labels_hidden':True,
                    'source_round_count':len(case['rounds']),'all_source_rounds_supplied':True,'finish_reason':'stop','evidence_selection':'source_segment_ids',
                    'system_prompt_sha256':hashlib.sha256(protocol.SYSTEM.encode()).hexdigest(),
                    'script_sha256':sha(Path(__file__)),'worker_run':str(run),'attempts':attempts,'elapsed_seconds':time.time()-started,
                    'completed_unix':time.time()}}
            # Result is published last, after the full memory and review page exist.
            save(OUT/'memories'/f'{tid(case)}.json',protocol.memory_record(result,case));review_html(result,case)
            save(OUT/'results'/f'{tid(case)}.json',result)
            return
        except Exception as exc:
            st=manager.status(identity_path)
            if not st['ok']:raise ResourceUnavailable('GPU resource conflict during request') from exc
            if not st['live']:raise RuntimeError('owned server stopped unexpectedly') from exc
            receipt.update(status='invalid',error_class=type(exc).__name__,error=str(exc)[:500]);attempts.append(receipt)
    save(OUT/'results'/f'{tid(case)}.json',{'status':'unresolved','episode_id':case['episode_id'],'attempts':attempts,'elapsed_seconds':time.time()-started})

def clean_stop(path,run):
    if not path.exists():
        save(run/'cleanup-verification.json',{'ok':True,'service_identity_never_published':True});return
    manager.atomic_json(run/'service/completion.json',{'status':'memjack-worker-ended'})
    last=None
    for _ in range(5):
        try:
            receipt=manager.stop_identity(path,reason='memjack worker complete or yielded');manager.stop_watchdog(path)
            save(run/'cleanup-verification.json',receipt);return
        except Exception as exc:last=exc;time.sleep(1)
    raise last

def worker(gpu,attempt):
    plan=check_plan();data=work_cases();run=OUT/f'attempt-{attempt:03d}-gpu{gpu}';run.mkdir(parents=True,exist_ok=True)
    if attest()!=json.loads((OUT/'model-attestation.json').read_text()):raise ValueError('runtime attestation drift')
    wrapper=run/'vllm-wrapper'
    flags=['--reasoning-parser','deepseek_r1','--limit-mm-per-prompt','{"image":1}',
           '--max-num-batched-tokens','8192']
    wrapper.write_text('#!/bin/sh\nexec '+shlex.quote(str(VLLM))+' "$@" '+shlex.join(flags)+'\n');wrapper.chmod(0o700)
    manager.MODEL_ID=protocol.MODEL_ID;manager.MODEL_REVISION=protocol.MODEL_REVISION;manager.MODEL_PATH=MODEL;manager.VLLM=wrapper
    provenance=json.loads((OUT/'model-attestation.json').read_text());manager.attest_runtime=lambda:dict(provenance,wrapper_sha256=sha(wrapper))
    path=run/'service/identity.json';port=18600+gpu;pool=None;stop=threading.Event();scan=threading.Lock();cursor=0
    try:
        try:
            manager.launch(argparse.Namespace(run_id=f'memjack-8b-{attempt:03d}-gpu{gpu}',gpu=gpu,run_root=str(run),port=port,
                           deadline_seconds=86400,gpu_memory_utilization=.92,max_model_len=MAX_CONTEXT,max_num_seqs=CONCURRENCY))
        except manager.ServiceError as exc:
            if not path.exists():
                try:manager.require_empty_gpu(gpu)
                except manager.ServiceError:raise ResourceUnavailable('GPU occupied before allocation') from exc
            raise
        deadline=time.monotonic()+1200
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        while True:
            status=manager.status(path)
            if not status['ok']:raise ResourceUnavailable('GPU conflict during startup')
            if not status['live']:raise RuntimeError('server exited during startup')
            try:
                with opener.open(f'http://127.0.0.1:{port}/v1/models',timeout=3) as f:models=json.load(f)
                if any(r['id']==protocol.MODEL_ID for r in models['data']):break
            except Exception:pass
            if time.monotonic()>deadline:raise RuntimeError('server readiness timeout')
            time.sleep(5)
        controls=control(port,run)
        save(run/'ready.json',{'gpu':gpu,'port':port,'vision_thinking_controls_passed':True,'unix':time.time()})
        def consume():
            nonlocal cursor
            while not stop.is_set():
                claimed=None;lock=None
                with scan:
                    while cursor<len(data):
                        c=data[cursor];cursor+=1
                        if (OUT/'results'/f'{tid(c)}.json').exists():continue
                        lf=(OUT/'claims'/f'{tid(c)}.lock').open('a')
                        try:fcntl.flock(lf,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        except BlockingIOError:lf.close();continue
                        if (OUT/'results'/f'{tid(c)}.json').exists():lf.close();continue
                        claimed=c;lock=lf;break
                if claimed is None:return
                try:
                    status=manager.status(path)
                    if not status['ok']:raise ResourceUnavailable('GPU resource conflict')
                    if not status['live']:raise RuntimeError('server stopped before request')
                    evaluate(port,claimed,run,path)
                finally:lock.close()
        pool=concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY)
        jobs=[pool.submit(consume) for _ in range(CONCURRENCY)]
        for f in concurrent.futures.as_completed(jobs):f.result()
    finally:
        stop.set()
        clean_stop(path,run)
        if pool:pool.shutdown(wait=True,cancel_futures=True)

def progress(data,export=False):
    counts=collections.Counter();rows=[];memory=[]
    for c in data:
        p=OUT/'results'/f'{tid(c)}.json'
        if not p.exists():continue
        r=json.loads(p.read_text());counts['recorded']+=1;counts[r['status']]+=1
        if r['status']=='valid':
            counts[r['judgment']['decision']]+=1
            if export:
                protocol.validate(r['judgment'],c);memory.append(protocol.memory_record(r,c))
        rows.append({'id':tid(c),'status':r['status'],'decision':r.get('judgment',{}).get('decision'),
                     'strategy':r.get('judgment',{}).get('observed_strategy',{}).get('name'),
                     'rationale':r.get('judgment',{}).get('rationale','')})
    summary={'model':protocol.MODEL_ID,'total':len(data),'counts':dict(counts),'remaining':len(data)-counts['recorded'],
             'updated_unix':time.time(),'all_valid':counts['valid']==len(data),'single_vlm_judge_not_human_gold':True}
    save(OUT/'progress.json',summary)
    esc=lambda x:html.escape(str(x or ''),quote=True)
    table=''.join('<tr><td><a href="reviews/'+r['id']+'.html">'+r['id']+'</a></td><td>'+esc(r['status'])+'</td><td>'+esc(r['decision'])+'</td><td>'+esc(r['strategy'])+'</td><td>'+esc(r['rationale'])+'</td></tr>' for r in rows if r['status']=='valid')
    (OUT/'index.html').write_text('<!doctype html><meta charset="utf-8"><title>MemJack 8B 재판정 방어 메모리</title><style>body{font-family:system-ui;margin:25px;line-height:1.6}table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccd;padding:8px;vertical-align:top}pre{white-space:pre-wrap}</style><h1>MemJack 4,093건 이미지 기반 8B Thinking 재판정</h1><p>실제 이미지를 포함한 단일 VLM 판정입니다. 원래 성공 라벨과 전략 라벨은 모델에 숨깁니다. 성공·실패·불확실·오류를 분리하고 정확한 인용 근거만 메모리에 남깁니다.</p><pre>'+esc(json.dumps(summary,ensure_ascii=False,indent=2))+'</pre><table><tr><th>사례 — 이미지와 전체 턴 보기</th><th>상태</th><th>새 판정</th><th>관찰된 전략</th><th>최종 설명</th></tr>'+table+'</table>')
    if export:
        allpath=OUT/'defense-memory-all-reviewed.private.jsonl';positive=OUT/'defense-memory-success.private.jsonl'
        with allpath.open('w') as allfile,positive.open('w') as yesfile:
            for m in memory:
                text=json.dumps(m,ensure_ascii=False)+'\n';allfile.write(text)
                if m['judgment']['decision']=='success':yesfile.write(text)
        save(OUT/'memory-manifest.json',{'protocol':protocol.PROTOCOL,'counts':dict(counts),'all_reviewed':{'path':str(allpath),'sha256':sha(allpath)},
             'success_only':{'path':str(positive),'sha256':sha(positive)},'unresolved_not_imported':counts['unresolved'],'active_ledger_modified':False,
             'status':'complete' if summary['all_valid'] else 'partial_or_unresolved','no_hidden_reasoning_saved':True})
    return summary

def supervise():
    OUT.mkdir(parents=True,exist_ok=True)
    for d in ['claims','results','memories','reviews']:(OUT/d).mkdir(exist_ok=True)
    lock=(OUT/'supervisor.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    check_plan();budget=json.loads((OUT/'token-budget-summary.json').read_text())
    if not budget['all_fit']:raise ValueError('context preflight not passed')
    data=work_cases();active={};idle={};failed=[];attempt=len(list(OUT.glob('attempt-*')))
    while True:
        check_plan()
        for gpu,(proc,log,run) in list(active.items()):
            code=proc.poll()
            if code is not None:
                log.close();del active[gpu]
                if code and not(code==75 and (run/'cleanup-verification.json').exists()):failed.append({'gpu':gpu,'exit_code':code,'run':str(run)})
        summary=progress(data)
        if summary['remaining']==0 and not active:
            progress(data,export=True);save(OUT/'completion.json',{'status':'complete' if summary['all_valid'] else 'complete_with_unresolved','summary':summary});return
        if failed and not active:
            progress(data,export=True);save(OUT/'completion.json',{'status':'execution_failed','failures':failed,'summary':summary});return
        if not failed:
            for gpu in (1,):
                if gpu in active:continue
                try:manager.require_empty_gpu(gpu)
                except Exception:idle.pop(gpu,None);continue
                idle.setdefault(gpu,time.monotonic())
                if time.monotonic()-idle[gpu]<30:continue
                if summary['remaining']<=len(active)*CONCURRENCY:continue
                attempt+=1;run=OUT/f'attempt-{attempt:03d}-gpu{gpu}';log=(OUT/f'worker-{attempt:03d}-gpu{gpu}.log').open('a')
                proc=subprocess.Popen([sys.executable,str(Path(__file__)),'worker','--gpu',str(gpu),'--attempt',str(attempt)],
                     stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,env=os.environ.copy(),start_new_session=True)
                active[gpu]=(proc,log,run);idle.pop(gpu,None)
        save(OUT/'supervisor-status.json',{'state':'running' if active else 'waiting_for_free_gpu',
             'workers':{str(g):{'pid':v[0].pid,'run':str(v[2]),'ready':(v[2]/'ready.json').exists()} for g,v in active.items()},
             'failures':failed,'summary':summary,'updated_unix':time.time()})
        time.sleep(20)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['prepare','tokens','supervise','worker','report']);p.add_argument('--gpu',type=int);p.add_argument('--attempt',type=int);args=p.parse_args()
    if args.mode=='prepare':prepare()
    elif args.mode=='tokens':preflight_tokens()
    elif args.mode=='supervise':supervise()
    elif args.mode=='report':print(json.dumps(progress(cases(),export=True),ensure_ascii=False,indent=2))
    else:
        try:worker(args.gpu,args.attempt)
        except ResourceUnavailable:
            import traceback;traceback.print_exc();sys.exit(75)
