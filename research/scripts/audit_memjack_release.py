#!/usr/bin/env python3
"""Audit the pinned public MemJack release for defensive evidence reuse.
No model calls, attack execution, or unpickling. Raw text is not printed.
"""
import collections
import hashlib
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'research/runtime/memjack-audit-20261119'
SOURCE=OUT/'source'
SHARED=['round','prompt','response','safety_label','risk_score','strategy','attack_angle','defense_pattern','defense_pattern_source','goal_achieved','anchor','query_count_cum','latency_ms']
CONTEXT=['trajectory_id','source_corpus','sample_id','image_path','image_name','victim_model','total_rounds']

def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def lines(path):
 with path.open() as f:
  for n,s in enumerate(f,1):
   if s.strip():yield n,json.loads(s)
def save(name,v):
 (OUT/name).write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n')
def canonical_image(corpus,name):
 if corpus in {'COCO_val2017','COCO_train2017'}:
  match=re.search(r'(\d{12})$',Path(name).stem)
  if match:return corpus+':'+match.group(1)
 return corpus+':'+str(name)

def main():
 counts=collections.Counter();missing=collections.Counter();labels=collections.Counter();strategies=collections.Counter();angles=collections.Counter();patterns=collections.Counter();models=collections.Counter();corpora=collections.Counter();issues=collections.Counter();examples=collections.defaultdict(list)
 expected={};round_meta={};trajectories={};images={};records=[]
 split_sets={k:set((SOURCE/'splits'/f'{k}_ids.txt').read_text().split()) for k in ['train','val','test','ood']}
 for line,t in lines(SOURCE/'trajectories.jsonl'):
  counts['trajectories']+=1;tid=t['trajectory_id'];rr=t['rounds'];image=canonical_image(t['source_corpus'],t['image_name']);splits=[k for k,s in split_sets.items() if t['image_name'] in s]
  if tid in trajectories:issues['duplicate_trajectory_id']+=1
  trajectories[tid]={'line':line,'image':image,'image_name':t['image_name'],'split':splits[0] if len(splits)==1 else None,'source_corpus':t['source_corpus'],'is_success':t['is_success'],'round_count':len(rr)}
  models[t['victim_model']]+=1;corpora[t['source_corpus']]+=1
  if len(splits)!=1:issues['unassigned_or_multiply_assigned_trajectory']+=1
  if t['total_rounds']!=len(rr):issues['declared_round_count_mismatch']+=1
  nums=[r['round'] for r in rr]
  if nums!=list(range(1,len(rr)+1)):issues['nonsequential_round_numbers']+=1
  unsafe=[r['round'] for r in rr if r['safety_label']=='unsafe']
  if t['is_success']!=bool(unsafe):issues['trajectory_success_vs_any_unsafe_mismatch']+=1
  first=min(unsafe) if unsafe else None
  if t.get('first_unsafe_round')!=first:issues['first_unsafe_round_mismatch']+=1
  if rr and t['final_safety_label']!=rr[-1]['safety_label']:issues['final_label_mismatch']+=1
  if rr and t['final_risk_score']!=rr[-1]['risk_score']:issues['final_score_mismatch']+=1
  counts['successful_trajectories']+=bool(unsafe)
  group=images.setdefault(image,{'canonical_image':image,'source_corpus':t['source_corpus'],'names':set(),'author_paths':set(),'splits':set(),'trajectory_ids':[]})
  group['names'].add(t['image_name']);group['author_paths'].add(t['image_path']);group['splits'].update(splits);group['trajectory_ids'].append(tid)
  if not Path(t['image_path']).is_file():counts['unresolved_original_image_path_trajectories']+=1
  for r in rr:
   counts['nested_rounds']+=1;key=(tid,r['round']);labels[r['safety_label']]+=1;strategies[r['strategy']]+=1;angles[r['attack_angle']]+=1;patterns[r['defense_pattern']]+=1
   for field in ['prompt','response','strategy','attack_angle','anchor','intent_in','intent_out']:
    if not isinstance(r.get(field),str) or not r[field].strip():missing[field]+=1
   for field in ['round','query_count_cum','latency_ms']:
    if type(r.get(field)) is not int:issues['invalid_'+field]+=1
   if r['safety_label'] not in ['safe','controversial','unsafe']:issues['invalid_safety_label']+=1
   if type(r.get('goal_achieved')) is not bool:issues['invalid_goal_achieved']+=1
   if not isinstance(r.get('risk_score'),(int,float)) or not 0<=r['risk_score']<=1:issues['invalid_risk_score']+=1
   counts['goal_achieved_true']+=bool(r['goal_achieved'])
   if r['goal_achieved']!=(r['safety_label']=='unsafe'):issues['goal_achieved_vs_unsafe_mismatch']+=1
   ranges={'safe':(0,.25),'controversial':(.35,.70),'unsafe':(.90,1)}
   if r['safety_label'] in ranges:
    lo,hi=ranges[r['safety_label']]
    if not lo<=r['risk_score']<=hi:issues['label_vs_paper_risk_band_mismatch']+=1
   counts['parent_round_null']+=r.get('parent_round') is None
   if r.get('parent_round') is not None and (type(r['parent_round']) is not int or r['parent_round'] not in nums or r['parent_round']>=r['round']):issues['invalid_parent_round']+=1
   counts['has_reflection_object']+=isinstance(r.get('reflection'),dict) and bool(r['reflection'])
   if key in expected:issues['duplicate_nested_round_key']+=1
   expected[key]=digest({**{f:t[f] for f in CONTEXT},**{f:r.get(f) for f in SHARED}})
   round_meta[key]={'label':r['safety_label'],'image':image,'split':splits[0] if len(splits)==1 else None,'prompt_hash':digest(r['prompt']),'response_hash':digest(r['response']),'fields':{f:r.get(f) for f in ['risk_score','goal_achieved','attack_angle','defense_pattern']},'nested_goal':r.get('intent_in'),'trajectory_goal':t.get('vulnerability_analysis',{}).get('goal')}
  records.append({'trajectory_id':tid,'source_line':line,'canonical_image':image,'image_name':t['image_name'],'split':splits,'corpus':t['source_corpus'],'round_count':len(rr),'is_success':t['is_success'],'first_unsafe_round':first,'run_status':t['run_status'],'replan_count':t.get('vulnerability_analysis',{}).get('replan_count'),'image_path':t['image_path']})
 seen=set()
 for line,r in lines(SOURCE/'rounds.jsonl'):
  counts['flat_rounds']+=1;key=(r['trajectory_id'],r['round'])
  if key in seen:issues['duplicate_flat_round_key']+=1
  seen.add(key)
  if key not in expected:issues['orphan_flat_round']+=1;continue
  if digest({f:r.get(f) for f in CONTEXT+SHARED})!=expected[key]:
   issues['flat_vs_nested_shared_fields_mismatch']+=1
   if len(examples['flat_vs_nested_shared_fields_mismatch'])<10:examples['flat_vs_nested_shared_fields_mismatch'].append({'trajectory_id':key[0],'round':key[1]})
  if r.get('goal')!=round_meta[key]['nested_goal']:counts['flat_goal_differs_from_round_intent_in']+=1
  if r.get('goal')!=round_meta[key]['trajectory_goal']:counts['flat_goal_differs_from_trajectory_goal']+=1
 issues['nested_round_missing_from_flat']=len(set(expected)-seen)
 derived={}
 for filename,prefix in [('guard_train.jsonl','guard'),('defense_pattern_train.jsonl','defense_pattern')]:
  dc=collections.Counter();dseen=set();dlabels=collections.Counter()
  for line,r in lines(SOURCE/'derived'/filename):
   dc['rows']+=1;key=(r['trajectory_id'],r['round'])
   if key in dseen:dc['duplicate_round_keys']+=1
   dseen.add(key)
   if key not in round_meta:dc['orphan_round_keys']+=1;continue
   m=round_meta[key]
   if m['split']!='train':dc['non_train_rows']+=1
   if digest(r['prompt'])!=m['prompt_hash'] or digest(r['response'])!=m['response_hash']:dc['prompt_or_response_mismatch']+=1
   if r['safety_label']!=m['label']:dc['safety_label_mismatch']+=1
   dlabels[r['safety_label']]+=1
  dc['missing_source_rounds']=len(set(round_meta)-dseen)
  derived[filename]={'counts':dict(dc),'safety_labels':dict(dlabels)}
 pairs=collections.Counter();pairtypes=collections.Counter()
 for line,p in lines(SOURCE/'derived/dpo_turning_point.jsonl'):
  pairs['rows']+=1;pairtypes[p['pair_type']]+=1
  for side in ['chosen','rejected']:
   r=p[side];key=(r['trajectory_id'],r['round']);m=round_meta.get(key)
   if m is None:pairs['orphan_'+side]+=1;continue
   if m['split']!='train':pairs['non_train_'+side]+=1
   if digest(r['prompt'])!=m['prompt_hash'] or digest(r['response'])!=m['response_hash']:pairs['text_mismatch_'+side]+=1
  if p['chosen']['prompt']!=p['rejected']['prompt']:pairs['different_prompts_between_sides']+=1
  if p.get('shared_prompt') is None:pairs['shared_prompt_null']+=1
  if p['chosen']['safety_label']=='unsafe':pairs['chosen_unsafe']+=1
  if p['rejected']['safety_label']!='unsafe':pairs['rejected_not_unsafe']+=1
 collision_groups=[]
 for image,g in images.items():
  if len(g['splits'])>1:collision_groups.append({'canonical_image':image,'names':sorted(g['names']),'splits':sorted(g['splits']),'trajectory_ids':g['trajectory_ids']})
 physical=[p for p in SOURCE.rglob('*') if p.is_file() and '.cache' not in p.parts]
 counts['downloaded_files']=len(physical);counts['downloaded_bytes']=sum(p.stat().st_size for p in physical)
 counts['canonical_images']=len(images);counts['canonical_images_multiple_names']=sum(len(g['names'])>1 for g in images.values());counts['canonical_images_cross_split']=len(collision_groups)
 result={'revision':'3ba067e58b99c3becc57b13e9352f0264bea9338','counts':dict(counts),'missing_or_empty_text_fields':dict(missing),'issues':dict(issues),'issue_examples':dict(examples),'labels':dict(labels),'strategies':dict(strategies),'top_attack_angles':angles.most_common(15),'defense_patterns':dict(patterns),'models':dict(models),'corpora':dict(corpora),'raw_split_name_sizes':{k:len(s) for k,s in split_sets.items()},'canonical_image_split_overlap':collision_groups,'derived':derived,'dpo_turning_point':{'counts':dict(pairs),'types':dict(pairtypes)},'file_sha256':{str(p.relative_to(SOURCE)):sha(p) for p in physical},'new_model_calls':0}
 save('full-structural-audit.json',result);save('trajectory-inventory.json',records)
 save('image-inventory.json',[{**g,'names':sorted(g['names']),'author_paths':sorted(g['author_paths']),'splits':sorted(g['splits'])} for g in images.values()])
 print(json.dumps({k:v for k,v in result.items() if k not in ['file_sha256','canonical_image_split_overlap','top_attack_angles']},ensure_ascii=False,indent=2))
if __name__=='__main__':main()
