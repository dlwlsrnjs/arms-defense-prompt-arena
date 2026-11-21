"""Comparison reports must preserve missing cases and disagreements honestly."""
import importlib.util
import sys
from pathlib import Path

PATH=Path(__file__).resolve().parents[1]/'scripts/compare_aamd_models.py'
spec=importlib.util.spec_from_file_location('compare_aamd_models',PATH)
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)

def test_partial_report_and_html_escape(tmp_path,monkeypatch):
 tasks=[{'task_id':'<unsafe>','record_handle':'record'}]
 body={'mapping_status':'mapped','reviewed_axes':[{'axis':'semantic_linkage','code':'positive','confidence':60,'evidence_handles':['ev1'],'rationale':'<script>alert(1)</script>'}],'benign_confound':{'code':'uncertain','plausibility':'uncertain','evidence_handles':[],'rationale':'reason'},'rationale':'overall'}
 monkeypatch.setattr(m,'OUT',tmp_path)
 monkeypatch.setattr(m,'inputs',lambda:(None,None,None,None,tasks))
 monkeypatch.setattr(m,'baseline',lambda *args:{'<unsafe>':{'status':'valid','body':body}})
 monkeypatch.setattr(m,'rows',lambda key,*args:{'<unsafe>':{'status':'error','error':'invalid JSON'}} if key=='qwen3' else {})
 result=m.report()
 assert result['agreements']['baseline vs qwen3']['denominator']==0
 assert result['models']['qwen3']['errors']==1
 assert result['models']['mistral']['valid']==0
 assert not result['complete']
 text=(tmp_path/'comparison.html').read_text()
 assert '<script>alert(1)</script>' not in text
 assert '&lt;script&gt;' in text
 assert 'pending' in text

def test_real_frozen_inputs_and_baseline():
 _,_,_,contract,tasks=m.inputs()
 data=m.baseline(tasks,contract)
 assert len(data)==len(tasks)==307
 assert all(r['body']['rationale'] for r in data.values())
