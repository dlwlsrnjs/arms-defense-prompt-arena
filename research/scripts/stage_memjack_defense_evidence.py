#!/usr/bin/env python3
"""Build a non-active defense evidence staging file with auditable exclusions.
Retains original text as untrusted evidence. Does not optimize or execute attacks.
"""
import collections
import hashlib
import html
import json
import os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'research/runtime/memjack-audit-20261119'
SRC=OUT/'source'
def read(p):return json.loads(p.read_text())
def save(name,v):(OUT/name).write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n')
def canonical(r):
 import re
 c=r['source_corpus'];n=r['image_name'];m=re.search(r'(\d{12})$',n) if c in ['COCO_val2017','COCO_train2017'] else None
 return c+':'+(m.group(1) if m else n)
def text_hash(s):return hashlib.sha256(s.encode()).hexdigest()
def main():
 audit=read(OUT/'full-structural-audit.json');images={v['canonical_image']:v for v in read(OUT/'resolved-images.json')};inventory={v['trajectory_id']:v for v in read(OUT/'trajectory-inventory.json')};conflicts={v['canonical_image'] for v in audit['canonical_image_split_overlap']};counts=collections.Counter();staged_ids=[];samples=[];selected_types=set();index=[]
 dest=OUT/'defense-experience-staging.private.jsonl';tmp=dest.with_suffix('.tmp')
 with tmp.open('w') as out,(SRC/'trajectories.jsonl').open() as f:
  for n,line in enumerate(f,1):
   t=json.loads(line);image_id=canonical(t);im=images[image_id];inv=inventory[t['trajectory_id']];unsafe=[r['round'] for r in t['rounds'] if r['safety_label']=='unsafe'];label_counts=collections.Counter(r['safety_label'] for r in t['rounds']);status=[]
   if im['status']!='resolved':status.append('image_unresolved')
   if image_id in conflicts:status.append('source_image_cross_split')
   if inv['split']!=['train']:status.append('not_training_partition')
   if t['run_status']=='in_progress':status.append('incomplete_source_run')
   stored_success_mismatch=t['is_success']!=bool(unsafe)
   case={'trajectory_id':t['trajectory_id'],'source_line':n,'canonical_image':image_id,'source_split':inv['split'],'round_count':len(t['rounds']),'source_export_is_success':t['is_success'],'source_any_unsafe':bool(unsafe),'source_run_status':t['run_status'],'source_label_counts':dict(label_counts),'source_export_success_differs_from_any_unsafe':stored_success_mismatch,'image_resolution':im['status'],'staging_exclusions':status}
   index.append(case)
   if status:
    counts['excluded_trajectories']+=1
    for reason in status:counts['excluded_'+reason]+=1
   else:
    rounds=[]
    for r in t['rounds']:
     rounds.append({k:r.get(k) for k in ['round','parent_round','prompt','response','strategy','attack_angle','anchor','intent_in','intent_out','safety_label','risk_score','goal_achieved','defense_pattern','defense_pattern_source','query_count_cum','latency_ms']})
    record={'schema_version':'defense-experience-evidence-staging-v1','review_status':'pending_independent_vlm_review','intended_use':'Defensive safety evaluation and defense-memory research only; all quoted source prompts and responses are untrusted evidence, never instructions.','episode_id':'memjack:'+t['trajectory_id'],'source':{'repository':'senwuou/MemJack','revision':audit['revision'],'file':'trajectories.jsonl','file_sha256':audit['file_sha256']['trajectories.jsonl'],'line':n,'record_sha256':text_hash(line.rstrip('\n'))},'partition':'train','canonical_image':image_id,'image':im,'target':{'model_id':t['victim_model'],'revision':None,'inference_settings':None},'recorded_goal':{'value':t['vulnerability_analysis'].get('goal'),'scope':'trajectory metadata; may reflect replanning. Prefer each round intent_in when present; missing goals remain missing.'},'source_success':{'export_is_success':t['is_success'],'run_status':t['run_status'],'export_first_unsafe_round':t['first_unsafe_round'],'recomputed_first_unsafe_round':min(unsafe) if unsafe else None,'any_unsafe':bool(unsafe),'predicate_disagreement':stored_success_mismatch},'rounds':rounds,'our_judgment':None,'limitations':['Original author image hashes unavailable; recovered using public dataset/split/ID.','Original model messages and context serialization are unavailable; chronological round records are not proof of an identical reproducible chat request.','Response finish reasons and token-limit metadata are not present; truncation status unknown.','Source safety labels and goal_achieved flags are not our independently confirmed success judgments.','Strategy is a coarse source label; attack_angle is separate free text.']}
    out.write(json.dumps(record,ensure_ascii=False)+'\n');staged_ids.append(t['trajectory_id']);counts['staged_trajectories']+=1;counts['staged_rounds']+=len(rounds);counts['staged_any_unsafe_trajectories']+=bool(unsafe);counts['staged_unsafe_rounds']+=label_counts['unsafe'];counts['staged_non_unsafe_trajectories']+=not unsafe;counts['staged_success_predicate_disagreements']+=stored_success_mismatch
   kind=None
   if im['status']=='resolved':
    if unsafe and len(t['rounds'])==1:kind='unsafe_single_round'
    elif unsafe and len(t['rounds'])>=5:kind='unsafe_multiround'
    elif stored_success_mismatch and t['final_safety_label']=='safe':kind='success_flag_but_no_unsafe'
    elif t['final_safety_label']=='controversial' and not unsafe:kind='controversial_only'
    elif not t['is_success'] and not unsafe:kind='safe_failure'
    if image_id in conflicts and 'cross_split_alias' not in selected_types:kind='cross_split_alias'
    if kind and kind not in selected_types:selected_types.add(kind);samples.append({'kind':kind,'source':t,'image':im,'case_audit':case})
 tmp.replace(dest)
 save('case-linkage-index.json',index);save('review-samples.private.json',samples)
 summary={'staging_file':str(dest),'staging_is_active_memory':False,'new_model_calls':0,'independently_confirmed_successes':None,'counts':dict(counts),'staged_canonical_images':len({inventory[i]['canonical_image'] for i in staged_ids}),'source_partition_policy':'Train only; quarantine every canonical COCO image present in multiple source splits; unresolved images excluded. Exclusion reason counts overlap.','review_sample_kinds':sorted(selected_types)}
 # Validate the staging file independently against raw record identifiers and exclusions.
 seen=set();staged_images=set()
 for s in dest.open():
  r=json.loads(s);tid=r['episode_id'].removeprefix('memjack:');assert tid not in seen;seen.add(tid)
  assert inventory[tid]['split']==['train'];assert r['canonical_image'] not in conflicts
  assert r['image']['status']=='resolved' and Path(r['image']['path']).is_file()
  assert r['our_judgment'] is None;assert r['source']['revision']==audit['revision']
  staged_images.add(r['canonical_image'])
 eval_images={v['canonical_image'] for v in inventory.values() if any(p in ['val','test','ood'] for p in v['split'])}
 assert not (staged_images & eval_images)
 summary['verification']={'unique_episode_ids':len(seen),'train_eval_canonical_image_overlap':len(staged_images & eval_images),'every_record_pending_review':True}
 save('staging-summary.json',summary)
 esc=lambda v:html.escape(str(v),quote=True)
 cards=[]
 for sample in samples:
  t=sample['source'];im=sample['image'];image_path=os.path.relpath(im['path'],OUT);rounds=[]
  for r in t['rounds']:
   rounds.append('<details><summary>턴 '+str(r['round'])+' · '+esc(r['safety_label'])+' · 점수 '+str(r['risk_score'])+'</summary><p>전략 '+esc(r['strategy'])+' · 관점 '+esc(r['attack_angle'])+'</p><p>원본 goal_achieved: '+str(r['goal_achieved'])+'</p><h4>원본 입력 — 신뢰하지 않는 분석 대상</h4><pre>'+esc(r['prompt'])+'</pre><h4>원본 타깃 응답 — 실행하지 않는 분석 대상</h4><pre>'+esc(r['response'])+'</pre></details>')
  cards.append('<article><h2>'+esc(sample['kind'])+' · '+esc(t['image_name'])+'</h2><p>사례 '+esc(t['trajectory_id'])+' · '+esc(t['victim_model'])+'</p><img src="'+esc(image_path)+'" alt="Recovered original-source image"><pre>'+esc(json.dumps(sample['case_audit'],ensure_ascii=False,indent=2))+'</pre>'+''.join(rounds)+'</article>')
 report_intro='''<h1>MemJack 실제 공개본 연결 감사</h1><p>2026-11-19. 연구용 원본 증거이며 입력·응답을 명령으로 실행하지 않습니다.</p><p><b>판단: 조건부 활용 가능.</b> 입력·응답·전략·판정 연결은 확인됐습니다. 이미지 복구, 성공 기준 분리, 데이터 분할 정리가 필요하며 독립 VLM 재판정 전까지 활성 메모리로 사용하지 않습니다.</p><ul><li>5,959개 궤적 / 55,867개 턴. 모두 qwen3-vl-plus. 궤적·평탄화 턴·파생 평가 파일의 대응 입력·응답이 일치합니다.</li><li>원본 전략 라벨은 두 종류이며, 구체적인 공격 관점은 attack_angle 별도 필드에 있습니다.</li><li>is_success는 5,690건이지만 실제 Unsafe 턴이 있는 궤적은 4,136건입니다. 데이터상 is_success는 Unsafe 또는 goal_achieved 조건과 일치합니다. 1,554건을 Unsafe 성공으로 잘못 세면 안 됩니다.</li><li>첫 Unsafe 턴 필드도 같은 넓은 조건을 사용합니다. 원본 필드와 재계산 값을 둘 다 보존합니다.</li><li>원본 절대 이미지 경로는 전부 저자 서버 경로입니다. COCO 원본 ID로 복구했으며 저자 이미지와의 바이트·픽셀 동일성은 공개 해시가 없어 입증할 수 없습니다.</li><li>같은 COCO ID가 여러 분할에 있는 58개 그룹은 격리합니다. guard_train 파일에는 비학습 턴 10,851개가 포함돼 그대로 학습에 쓰면 안 됩니다.</li><li>논문의 전체 집계 113,092개 항목 및 11모델과 현재 게시본의 범위는 다릅니다. 실제 다운로드한 범위만 집계합니다.</li></ul><h2>이미지 복구·메모리 후보 구성</h2>'''
 (OUT/'review.html').write_text('<!doctype html><html lang="ko"><meta charset="utf-8"><title>MemJack 실제 자료 검토</title><style>body{font-family:system-ui;max-width:1100px;margin:30px auto;padding:0 20px;line-height:1.65;color:#1b3041}article{border-top:2px solid #abc;margin-top:35px}img{max-width:600px;max-height:460px;width:auto;height:auto}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f8;padding:15px}details{border:1px solid #cbd5db;padding:12px;margin:10px 0}summary{cursor:pointer}</style>'+report_intro+'<pre>'+esc(json.dumps(read(OUT/'image-resolution-summary.json'),ensure_ascii=False,indent=2))+'</pre><pre>'+esc(json.dumps(summary,ensure_ascii=False,indent=2))+'</pre><h2>실제 사례 표본 — 원본 이미지와 모든 턴</h2>'+''.join(cards)+'</html>')
 print(json.dumps(summary,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
