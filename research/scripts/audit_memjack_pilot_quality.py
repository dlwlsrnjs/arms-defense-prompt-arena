"""Read-only structural/provenance audit for the fixed six-case English pilot."""
import collections
import hashlib
import json
from pathlib import Path
import sys
import time
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'research'))
from scripts import memjack_judgment_v6 as protocol
OUT=ROOT/'research/runtime/aamd/memjack-8b-rejudge-v6-20261119'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 ids=set(json.loads((OUT/'pilot-selection.json').read_text())['episode_ids'])
 cases={c['episode_id']:c for c in map(json.loads,(ROOT/'research/runtime/memjack-audit-20261119/defense-experience-staging.private.jsonl').open()) if c['episode_id'] in ids}
 records=[]
 for episode,c in cases.items():
  tid=episode.split(':')[1];path=OUT/'results'/f'{tid}.json'
  if not path.exists():raise ValueError('Pilot pending: '+episode)
  result=json.loads(path.read_text())
  if result['status']!='valid':raise ValueError('Pilot unresolved: '+episode)
  offsets=protocol.validate(result['judgment'],c)
  memorypath=OUT/'memories'/path.name;memory=json.loads(memorypath.read_text())
  assert memory==protocol.memory_record(result,c)
  assert sha(c['image']['path'])==c['image']['file_sha256']
  provenance=result['provenance'];assert provenance['actual_image_in_request'] and provenance['all_source_rounds_supplied']
  assert provenance['source_round_count']==len(c['rounds'])
  coverage=[n for g in provenance['group_results'] for n in g['rounds']]
  assert coverage==[r['round'] for r in c['rounds']]
  for g in provenance['group_results']:
   v=g['candidate_positive_verification']
   assert v is not None
   if g['decision']=='success':assert v['required'] and v['all_received_fresh_actual_image_review']
  assert (OUT/'reviews'/f'{tid}.html').exists()
  records.append({'episode_id':episode,'rounds':len(c['rounds']),'decision':result['judgment']['decision'],'primary_round':result['judgment']['primary_round'],'strategy':result['judgment']['observed_strategy']['name'],'harm_kind':result['judgment']['harm_assessment']['kind'],'result_sha256':sha(path),'memory_sha256':sha(memorypath),'exact_evidence_quotes_revalidated':True,'full_source_round_coverage':True,'actual_image_hash_verified':True})
 groups=[]
 for f in OUT.glob('attempt-*/groups/*/*/result.json'):
  r=json.loads(f.read_text())
  if r['status']=='valid':groups.append(r)
 errors=collections.Counter(a.get('error','') for r in groups for a in r.get('attempts',r.get('provenance',{}).get('attempts',[])) if a.get('status')=='invalid')
 report={'checked_unix':time.time(),'protocol':protocol.PROTOCOL,'cases':len(records),'rounds':sum(r['rounds'] for r in records),'explanation_language':'English','records':records,'decisions':dict(collections.Counter(r['decision'] for r in records)),'group_attempt_errors':dict(errors),'structural_checks_passed':True,'human_semantic_review_required_before_full_approval':True,'single_8b_model_not_human_gold':True}
 (OUT/'pilot-structural-audit.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({k:v for k,v in report.items() if k!='records'},indent=2))
if __name__=='__main__':main()
