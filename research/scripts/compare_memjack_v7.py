"""Read-only version comparison and evidence integrity audit of V7 full cases."""
import collections,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'research'))
from scripts import queue_memjack_rejudge_v7 as q
OLD=ROOT/'research/runtime/aamd/memjack-8b-rejudge-v6-20261119'
def main():
 data={c['episode_id']:c for c in q.work_cases()};matrix=collections.Counter();errors=[];rows=[]
 for path in sorted((q.OUT/'results').glob('*.json')):
  new=json.loads(path.read_text());ident=new['episode_id'];prior=OLD/'results'/path.name
  before=json.loads(prior.read_text()) if prior.exists() else None
  old_label=before.get('judgment',{}).get('decision',before['status']) if before else 'not_previously_processed'
  new_label=new.get('judgment',{}).get('decision',new['status']);matrix[(old_label,new_label)]+=1
  if new['status']=='valid':
   try:
    q.protocol.validate(new['judgment'],data[ident]);mem=json.loads((q.OUT/'memories'/path.name).read_text())
    for e in mem['evidence_with_offsets']+mem['supporting_evidence_with_offsets']:
     t=next(r[e['field']] for r in mem['source_rounds'] if r['round']==e['round'])
     if t[e['start_char']:e['end_char']]!=e['quote'] or hashlib.sha256(t.encode()).hexdigest()!=e['source_text_sha256']:raise ValueError('quote integrity mismatch')
   except Exception as exc:errors.append({'episode_id':ident,'error':str(exc)})
  rows.append({'episode_id':ident,'before':old_label,'after':new_label})
 q.save(q.OUT/'version-comparison.json',{'matrix':[{'before':a,'after':b,'count':n} for (a,b),n in matrix.items()],'compared_full_cases':len(rows),'integrity_errors':errors,'cases':rows,'interpretation':'Label changes are single-model rejudgments, not an independently measured accuracy improvement.'})
 print(json.dumps({'full_cases':len(rows),'integrity_errors':len(errors),'matrix':dict((a+' -> '+b,n) for (a,b),n in matrix.items())}))
if __name__=='__main__':main()
