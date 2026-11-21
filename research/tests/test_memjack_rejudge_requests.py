import json
import base64
import pytest
from scripts import queue_memjack_rejudge as q
from scripts import memjack_judgment as p

def case():
 return {'recorded_goal':{'value':'recorded benchmark objective'},'rounds':[
  {'round':1,'intent_in':'recorded objective','prompt':'source input','response':'source response',
   'strategy':'HIDDEN_STRATEGY','safety_label':'HIDDEN_LABEL','risk_score':.99}]}

def test_request_contains_actual_image_and_no_original_judge_labels():
 image=b'actual source image bytes'
 request=q.build_request(case(),image,0)
 content=request['messages'][1]['content']
 assert content[0]['type']=='image_url'
 assert base64.b64decode(content[0]['image_url']['url'].split(',',1)[1])==image
 assert 'HIDDEN_LABEL' not in content[1]['text']
 assert 'HIDDEN_STRATEGY' not in content[1]['text']
 assert request['model']=='Qwen/Qwen3-VL-8B-Thinking'
 assert request['response_format']['type']=='json_schema'

@pytest.mark.parametrize('reasoning_key',['reasoning','reasoning_content'])
def test_final_message_requires_finished_reasoning_but_does_not_return_it(reasoning_key):
 response={'model':p.MODEL_ID,'choices':[{'finish_reason':'stop','message':{reasoning_key:'private scratchpad','content':'{"final":true}'}}]}
 body,count=q.final_message(response)
 assert body=={'final':True} and count==len('private scratchpad')
 assert 'private scratchpad' not in json.dumps(body)

def test_incomplete_or_non_thinking_output_is_not_accepted():
 response={'model':p.MODEL_ID,'choices':[{'finish_reason':'length','message':{'content':'{}','reasoning':'thinking'}}]}
 with pytest.raises(ValueError,match='incomplete'):q.final_message(response)
 response['choices'][0]['finish_reason']='stop';response['choices'][0]['message'].pop('reasoning')
 with pytest.raises(ValueError,match='reasoning not observed'):q.final_message(response)
