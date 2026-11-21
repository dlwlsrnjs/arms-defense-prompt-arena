import copy
import json
from scripts import queue_memjack_rejudge_v4 as q
from scripts import memjack_judgment_v4 as p

def sample():
 return {'episode_id':'memjack:'+'a'*24,'rounds':[{'round':i,'prompt':'Original input evidence for round '+str(i),'response':'Original saved response evidence for round '+str(i)} for i in range(1,5)]}

def group_result(c):
 n=c['rounds'][0]['round'];success=n==4
 body={'round_scores':[{'round':r['round'],'validity':'aligned','goal_completion':5 if success else 0,'harmfulness':3 if success else 0} for r in c['rounds']],
 'decision':'success' if success else 'failure','primary_round':n,'evidence':[{'round':n,'field':f,'quote':c['rounds'][0][f]} for f in ['prompt','response']],
 'rationale':'Observed primary response assessment.','observed_strategy':{'name':p.STRATEGIES[0],'description':'Round '+str(n)+': the input adds unsupported context to the visible scene.','visual_role':'The actual image contradicts the alleged hidden context.'},
 'target_behavior':'The primary response provided the evaluated assistance.','harm_assessment':{'kind':'actionable_harm' if success else 'none_or_uncertain','reason':'Evaluate only the saved response.'},'visual_grounding':'partial','defense_rule':'When hidden context is alleged, separate visual evidence from assumptions.','benign_handling':'Help with an ordinary scene description.','limitations':'Single-model evaluation.'}
 return {'status':'valid','episode_id':c['episode_id'],'judgment':body,'provenance':{'attempts':[],'actual_image_in_request':True}}

def setup(monkeypatch,tmp_path):
 monkeypatch.setattr(q,'OUT',tmp_path)
 monkeypatch.setattr(q,'review_html',lambda *a:None)
 monkeypatch.setattr(p,'memory_record',lambda result,case:result)

def test_every_round_evaluated_once_and_late_success_selected(monkeypatch,tmp_path):
 setup(monkeypatch,tmp_path);calls=[]
 def evaluate(port,c,run,identity):
  calls.extend(r['round'] for r in c['rounds']);return group_result(c)
 monkeypatch.setattr(q,'evaluate_group',evaluate)
 q.evaluate(1,sample(),tmp_path/'run',None)
 result=json.loads(next((tmp_path/'results').glob('*.json')).read_text())
 assert calls==[1,2,3,4]
 assert result['judgment']['decision']=='success' and result['judgment']['primary_round']==4
 assert [s['round'] for s in result['judgment']['round_scores']]==[1,2,3,4]
 assert result['provenance']['source_round_count']==4
 assert result['provenance']['group_count']==2

def test_failed_group_never_promoted_to_memory(monkeypatch,tmp_path):
 setup(monkeypatch,tmp_path)
 def evaluate(port,c,run,identity):
  return {'status':'unresolved','attempts':[]} if c['rounds'][0]['round']==4 else group_result(c)
 monkeypatch.setattr(q,'evaluate_group',evaluate)
 q.evaluate(1,sample(),tmp_path/'run',None)
 result=json.loads(next((tmp_path/'results').glob('*.json')).read_text())
 assert result['status']=='unresolved'
 assert not (tmp_path/'memories').exists()
