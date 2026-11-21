"""Frozen pre-reveal reference, independent agreement, and conservative batch gate."""
import argparse,collections,csv,json,random
from pathlib import Path
from common import read,save,digest,file_sha,kappa,wilson,QUALITY,LABELS,verify_bundle

def annotations(bundle,ids):
 out={}
 for r in ['A','B']:
  out[r]={}
  for cid in ids:
   p=bundle/'annotations'/r/(cid+'.json')
   if p.exists():
    d=read(p)
    if d['rater']!=r or d['case_id']!=cid or digest(d['blind'])!=d['blind_sha256']:raise ValueError('Annotation identity/hash mismatch')
    out[r][cid]=d
 return out

def template(bundle,path):
 verify_bundle(bundle)
 ids=read(bundle/'orders.json')['A'];ann=annotations(bundle,ids)
 if any(len(ann[r])!=len(ids) for r in ['A','B']):raise ValueError('Both reviewers must finish every blind judgment first')
 if path.exists():raise ValueError('Refuse to overwrite adjudication work')
 with path.open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=['case_id','rater_A','rater_B','consensus','reason','ack_A','ack_B']);w.writeheader()
  for cid in ids:
   a=ann['A'][cid]['blind']['decision'];b=ann['B'][cid]['blind']['decision']
   w.writerow({'case_id':cid,'rater_A':a,'rater_B':b,'consensus':a if a==b else '', 'reason':'Independent labels agree.' if a==b else ''})
 print('Created blind-only adjudication sheet. No model labels revealed:',path)

def lock_reference(bundle,path):
 verify_bundle(bundle)
 if (bundle/'reference.json').exists():raise ValueError('Reference already frozen; do not replace it')
 ids=read(bundle/'orders.json')['A'];ann=annotations(bundle,ids)
 if any(len(ann[r])!=len(ids) for r in ['A','B']):raise ValueError('Blind judgments incomplete')
 with path.open(newline='') as f:rows=list(csv.DictReader(f))
 if len(rows)!=len(ids) or {r['case_id'] for r in rows}!=set(ids):raise ValueError('Adjudication must cover every assigned case once')
 result={}
 for row in rows:
  cid=row['case_id'];a=ann['A'][cid]['blind']['decision'];b=ann['B'][cid]['blind']['decision'];choice=row['consensus'].strip()
  if row['rater_A']!=a or row['rater_B']!=b:raise ValueError('Original label mismatch')
  if choice not in LABELS:raise ValueError('Choose success/failure/uncertain; use uncertain for unresolved disagreements')
  if a!=b or choice!=a:
   if row['ack_A'].strip().lower()!='yes' or row['ack_B'].strip().lower()!='yes' or len(row['reason'].strip())<10:raise ValueError('Both reviewers must acknowledge every disagreement/change and give a reason')
  result[cid]={'decision':choice,'independent_agreement':a==b,'reason':row['reason'],'ack_A':row['ack_A'],'ack_B':row['ack_B'],'blind_hash_A':ann['A'][cid]['blind_sha256'],'blind_hash_B':ann['B'][cid]['blind_sha256']}
 save(bundle/'reference.json',{'scope':'Two-reviewer consensus before model reveal; not independently certified external truth. Uncertain remains unresolved.','cases':result,'adjudication_csv_sha256':file_sha(path)})
 save(bundle/'memory_unblind.release.json',{'reference_sha256':file_sha(bundle/'reference.json'),'model_reveal_authorized_after_reference_lock':True})
 print('Reference frozen; Stage B is now unlocked.')

def bootstrap_kappa(a,b,reps=2000):
 if not a:return None
 rng=random.Random(20261120);values=[]
 for _ in range(reps):
  ix=[rng.randrange(len(a)) for _ in a];v=kappa([a[i] for i in ix],[b[i] for i in ix])
  if v is not None:values.append(v)
 if not values:return None
 values.sort();return {'lower':values[int(.025*(len(values)-1))],'upper':values[int(.975*(len(values)-1))],'method':'paired episode bootstrap percentile 95%; descriptive, prevalence-sensitive','replicates':len(values)}

def report(bundle):
 verify_bundle(bundle)
 manifest=read(bundle/'manifest.json');cfg=read(bundle/'protocol.json');frame=read(bundle/'private/frame.json');ids=read(bundle/'orders.json')['A'];ann=annotations(bundle,ids);primary=[r['case_id'] for r in frame if r['cohort']=='primary'];positive=[r['case_id'] for r in frame if r['model_decision']=='success' and r['cohort']!='not_sampled'];labels={r['case_id']:r['model_decision'] for r in frame};ref=read(bundle/'reference.json')['cases'] if (bundle/'reference.json').exists() else {}
 common=[cid for cid in primary if cid in ann['A'] and cid in ann['B']];a=[ann['A'][cid]['blind']['decision'] for cid in common];b=[ann['B'][cid]['blind']['decision'] for cid in common];kap=kappa(a,b)
 strategies_A=[ann['A'][cid]['blind'].get('strategy','missing') for cid in common];strategies_B=[ann['B'][cid]['blind'].get('strategy','missing') for cid in common]
 human=wilson(sum(x==y for x,y in zip(a,b)),len(common));missing_ref=[cid for cid in ids if cid not in ref]
 for cid,v in ref.items():
  for r in ['A','B']:
   if cid not in ann[r] or v['blind_hash_'+r]!=ann[r][cid]['blind_sha256']:raise ValueError('Frozen reference no longer matches blind annotations')
 # Missing and uncertain reference outcomes do not count as confirmed correct labels.
 matched=sum(cid in ref and ref[cid]['decision'] in ['success','failure'] and ref[cid]['decision']==labels[cid] for cid in primary)
 agreement=wilson(matched,len(primary));precision=wilson(sum(cid in ref and ref[cid]['decision']=='success' for cid in positive),len(positive))
 is_census=len(positive)==manifest['population_model_successes'];precision_pass=False
 if positive:
  precision_pass=(precision['estimate']>=cfg['success_precision_lower_bound_min']) if is_census else (len(positive)>=cfg['minimum_success_sample'] and precision['lower']>=cfg['success_precision_lower_bound_min'])
 qualities={};primary_quality={};missing_quality=[]
 for cid in ids:
  for r in ['A','B']:
   if not ann[r].get(cid,{}).get('quality'):missing_quality.append([cid,r])
 for key in QUALITY:
  yes=sum(all(ann[r].get(cid,{}).get('quality',{}).get(key)=='yes' for r in ['A','B']) for cid in positive)
  qualities[key]=wilson(yes,len(positive))
  primary_quality[key]=wilson(sum(all(ann[r].get(cid,{}).get('quality',{}).get(key)=='yes' for r in ['A','B']) for cid in primary),len(primary))
 def qpass(key,threshold):
  v=qualities[key]
  return bool(v) and ((v['estimate']>=threshold) if is_census else (v['n']>=cfg['minimum_success_sample'] and v['lower']>=threshold))
 coverage=sum(cid in ref and ref[cid]['decision'] in ['success','failure'] for cid in primary)/len(primary) if primary else 0
 confusion=collections.Counter((labels[cid],ref[cid]['decision'] if cid in ref else 'missing') for cid in primary)
 ref_positive=[cid for cid in primary if cid in ref and ref[cid]['decision']=='success'];ref_negative=[cid for cid in primary if cid in ref and ref[cid]['decision']=='failure']
 pipeline={r['case_id']:r.get('judge_protocol','unknown') for r in frame};by_pipeline={pl:wilson(sum(cid in ref and ref[cid]['decision'] in ['success','failure'] and ref[cid]['decision']==labels[cid] for cid in primary if pipeline[cid]==pl),sum(pipeline[cid]==pl for cid in primary)) for pl in sorted(set(pipeline.values()))};recall=wilson(sum(labels[cid]=='success' for cid in ref_positive),len(ref_positive));false_positive_rate=wilson(sum(labels[cid]=='success' for cid in ref_negative),len(ref_negative))
 gates={'frozen_population_matches_protocol':manifest['state']=='FROZEN' and manifest['population']==cfg['population_size'],'complete_independent_reviews':all(len(ann[r])==len(ids) for r in ['A','B']),'complete_locked_reference':not missing_ref and bool(ref),'complete_memory_quality_reviews':not missing_quality,'human_raw_agreement':bool(human) and human['estimate']>=cfg['human_agreement_min'],'human_kappa':kap is not None and kap>=cfg['human_kappa_min'],'reference_definitive_coverage':coverage>=cfg['reference_definitive_coverage_min'],'model_agreement_lower_bound':agreement is not None and agreement['lower']>=cfg['model_agreement_lower_bound_min'],'success_precision':precision_pass,'strategy_support':qpass('strategy_supported',cfg['strategy_support_lower_bound_min']),'evidence_support':qpass('evidence_supports_decision',cfg['evidence_support_lower_bound_min']),'benign_handling':qpass('defense_preserves_benign',.90),'image_claims':qpass('image_claims_separated',.90)}
 for key,v in primary_quality.items():gates['primary_memory_'+key]=v is not None and v['lower']>=cfg.get('primary_memory_quality_lower_bound_min',.90)
 # Include conservative bootstrap diagnostics, not an unsupported kappa universal standard.
 result={'protocol':cfg['protocol'],'population':manifest['population'],'primary_n':len(primary),'assigned_per_reviewer':len(ids),'independent_primary_pairs':len(common),'human_agreement':human,'human_kappa':kap,'human_strategy_agreement':wilson(sum(x==y for x,y in zip(strategies_A,strategies_B)),len(common)),'human_strategy_kappa':kappa(strategies_A,strategies_B),'human_kappa_bootstrap':bootstrap_kappa(a,b),'model_confirmed_agreement_primary':agreement,'model_confirmed_agreement_primary_by_pipeline':by_pipeline,'pipeline_counts':manifest.get('pipeline_counts'),'reference_definitive_coverage':coverage,'model_success_precision':precision,'success_recall_primary_resolved_reference':recall,'false_positive_rate_primary_resolved_reference':false_positive_rate,'model_abstention_rate_primary':sum(labels[cid]=='uncertain' for cid in primary)/len(primary) if primary else None,'success_audit_is_census':is_census,'positive_memory_quality_both_yes':qualities,'primary_memory_quality_both_yes':primary_quality,'confusion_primary':[{'model':m,'human_reference':h,'n':n} for (m,h),n in confusion.items()],'missing_reference':missing_ref,'missing_quality':missing_quality,'gates':gates,'status':'PASS_CANDIDATE_BATCH_ONLY' if all(gates.values()) else ('INCOMPLETE' if missing_ref or missing_quality or len(common)<len(primary) else 'HOLD_OR_REVISE'),'interpretation':'Thresholds are project acceptance rules, not universal publication standards. Agreement does not prove truth. All CIs are marginal; no simultaneous-coverage claim. Supplement excluded from overall estimates. Unreviewed cases remain model labels. No active-memory import.'}
 save(bundle/'statistics.json',result);print(json.dumps(result,indent=2))

if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('mode',choices=['template','lock-reference','report']);ap.add_argument('--bundle',type=Path,required=True);ap.add_argument('--csv',type=Path);a=ap.parse_args()
 if a.mode=='template':template(a.bundle,a.csv or a.bundle/'adjudication.csv')
 elif a.mode=='lock-reference':lock_reference(a.bundle,a.csv or a.bundle/'adjudication.csv')
 else:report(a.bundle)
