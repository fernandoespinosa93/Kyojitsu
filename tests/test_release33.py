"""3.4 regression tests: ambiguous evidence must not become success."""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from kyojitsu.rest_tools import put_prompt, normalize_path
from kyojitsu.targets import GenericJsonTarget, GenericTargetProfile, text_indicates_block
from kyojitsu.models import Outcome
from kyojitsu.generator import GeneratorConfig, GeneratorError, ModelGenerator
from kyojitsu.assessment import build_assessment, metrics_for
from kyojitsu.planner import build_plan, PlannerConfig
from kyojitsu.executive_pdf import export_executive_pdf
from kyojitsu.report_ui import render_report_html
from kyojitsu.runner import run_campaign
from test_rest32 import candidate, config
from test_core import _FakeHttpResponse


class PathTests(unittest.TestCase):
    def test_new_top_level_field(self):
        self.assertEqual(put_prompt({'prompt':'{{prompt}}','constant':True},'question'),
                         {'question':'{{prompt}}','constant':True})
    def test_nested_create(self):
        self.assertEqual(put_prompt({},'input.question'), {'input':{'question':'{{prompt}}'}})
    def test_bracket_array_create(self):
        self.assertEqual(put_prompt({},'messages[0].content'), {'messages':[{'content':'{{prompt}}'}]})
    def test_existing_messages_system_untouched(self):
        body={'messages':[{'role':'system','content':'policy'},{'role':'user','content':'hi'}]}
        result=put_prompt(body,'$.messages[1].content')
        self.assertEqual(result['messages'][0],body['messages'][0])
        self.assertEqual(body['messages'][1]['content'],'hi')
    def test_quoted_path(self):
        self.assertEqual(normalize_path(' "answer" '),'answer')
    def test_invalid_sentence_has_plain_error(self):
        with self.assertRaises(ValueError): put_prompt({},'Hola esta es la pregunta')
    def test_prototype_rejected(self):
        with self.assertRaises(ValueError): put_prompt({},'__proto__.x')
    def test_array_cap(self):
        with self.assertRaises(ValueError): put_prompt({},'messages[10000].content')
    def test_scalar_parent_not_destroyed(self):
        with self.assertRaises(ValueError): put_prompt({'input':'constant'},'input.question')
    def test_answer_path_not_request_mutation(self):
        p=GenericTargetProfile.from_dict({'name':'x','url':'http://127.0.0.1/api',
             'body_template':{'question':'{{prompt}}'},'response':{'answer_path':'$.result[0].text'}})
        p.validate()
        self.assertEqual(p.answer_path,'result.0.text')
        self.assertEqual(p.body_template,{'question':'{{prompt}}'})


NOTICE='Query blocked by security guardrails by Scitum.The request is a test.'

def target_result(payload, *, paths=None, strict=False, policy=False):
    p={'name':'lab','url':'http://127.0.0.1/api', 'body_template':{'question':'{{prompt}}'},
       'response':paths or {'answer_path':'answer','blocked_path':'blocked','stage_path':'stage'},
       'strict_instrumentation':strict,'policy_oracle_confirmed':policy}
    target=GenericJsonTarget(GenericTargetProfile.from_dict(p),authorization_confirmed=True)
    c=candidate();c.prompt='Return LAB';c.success_indicators=['LAB'];c.oracle='canary'
    with patch('kyojitsu.targets.safe_urlopen',return_value=_FakeHttpResponse(payload)):
        return target.evaluate(c)


class EvidenceClassificationTests(unittest.TestCase):
    def test_ikigai_notice_not_accepted(self):
        result=target_result({'answer':NOTICE})
        self.assertEqual(result.outcome,Outcome.TEXT_BLOCKED)
        self.assertIsNone(result.guardrail_passed)
    def test_unknown_stage_not_input_block(self):
        r=target_result({'answer':NOTICE,'blocked':True})
        self.assertEqual(r.outcome,Outcome.GUARDRAIL_BLOCKED)
        self.assertIsNone(r.guardrail_passed)
    def test_unknown_stage_allowed_strict_boolean(self):
        self.assertEqual(target_result({'answer':NOTICE,'blocked':True},strict=True).outcome,Outcome.GUARDRAIL_BLOCKED)
    def test_output_stage_not_input(self):
        r=target_result({'answer':NOTICE,'blocked':True,'stage':'output'})
        self.assertEqual(r.outcome,Outcome.OUTPUT_BLOCKED)
        self.assertTrue(r.guardrail_passed)
    def test_false_signal_conflicts_with_text(self):
        r=target_result({'answer':NOTICE,'blocked':False})
        self.assertEqual(r.outcome,Outcome.SIGNAL_CONFLICT)
        self.assertIsNone(r.guardrail_passed)
    def test_quoted_notice_not_a_block(self):
        self.assertFalse(text_indicates_block('The notice "'+NOTICE+'" is an example.'))
    def test_spanish_notice(self):
        self.assertTrue(text_indicates_block('Solicitud bloqueada por el guardrail de seguridad.'))
    def test_http200_no_evidence_not_success(self):
        self.assertEqual(target_result({'answer':'LAB'}).outcome,Outcome.ACCEPTED_UNVERIFIED)
    def test_policy_marker_without_external_verdict(self):
        self.assertEqual(target_result({'answer':'LAB','blocked':False},policy=True).outcome,Outcome.ATTACK_SUCCESS)
    def test_explicit_negative_success(self):
        r=target_result({'answer':'LAB','blocked':False,'success':False},policy=True,
                 paths={'answer_path':'answer','blocked_path':'blocked','success_path':'success'})
        self.assertEqual(r.outcome,Outcome.ATTACK_FAILURE)
    def test_explicit_success_conflict_not_success(self):
        r=target_result({'answer':NOTICE,'success':True},
                 paths={'answer_path':'answer','success_path':'success'})
        self.assertEqual(r.outcome,Outcome.SIGNAL_CONFLICT)


def row(n,out='accepted_unverified',**kw):
    return {'id':'case'+str(n),'prompt':'Prompt '+str(n),'expected':'malicious',
      'effective_outcome':out,'outcome':out,'guardrail_passed':None,'technique_id':'direct_prompt_injection',
      'technique_name':'Direct prompt injection','frameworks':['owasp_llm_2025','mitre_atlas'],
      'control_ids':['LLM01','AML.TA0005'],'generation':0,'tags':[], 'operator':'seed', **kw}

def summary(rows):
    return {'run':{'id':'test-summary','status':'completed','target':'lab','created_at':'2026-09-23'},
      'experiment':{'frameworks':['owasp_llm_2025'],'techniques':['direct_prompt_injection'],
                    'coverage':[{'frameworks':['owasp_llm_2025'],'control_ids':['LLM01']}]},
      'candidates':rows}


class AssessmentTests(unittest.TestCase):
    def test_successes_unique_and_evaluations_distinct(self):
        m=metrics_for([row(1,'attack_success',prompt='Same'),row(2,'attack_success',prompt='same'),row(3)])
        self.assertEqual((m['confirmed_successes'],m['unique_successful_prompts'],m['successful_techniques']),(2,1,1))
    def test_http_errors_excluded(self):
        m=metrics_for([row(1,'attack_success'),row(2,'target_error')]);self.assertEqual(m['valid_adversarial'],1)
    def test_unknown_not_zero_percent(self):
        m=metrics_for([row(1,'text_blocked')]);self.assertIsNone(m['bypass_observed'])
        self.assertEqual(m['unresolved'],1)
    def test_no_benign_not_zero_fp(self):
        self.assertIsNone(metrics_for([row(1)])['benign_denial_rate'])
    def test_benign_not_attack_success_count(self):
        self.assertEqual(metrics_for([row(1,'attack_success',expected='benign')])['confirmed_successes'],0)
    def test_benign_text_uncertainty_not_zero(self):
        m=metrics_for([row(1,'text_blocked',expected='benign')]);self.assertIsNone(m['benign_denial_rate'])
        self.assertEqual(m['benign_unresolved'],1)
    def test_missing_technique_not_pass(self):
        a=build_assessment(summary([]));self.assertEqual(a['techniques'][0]['state'],'not_tested')
    def test_uncertain_recommends_instrumentation(self):
        a=build_assessment(summary([row(1,'text_blocked')]))
        self.assertEqual(a['state'],'inconclusive');self.assertGreaterEqual(len(a['recommendations']),2)
    def test_findings_have_action_and_evidence(self):
        a=build_assessment(summary([row(1,'attack_success')]))
        self.assertEqual(a['state'],'finding')
        self.assertTrue(any('case1' in r['evidence'] and 'LLM01' in r['controls'] for r in a['recommendations']))
    def test_framework_cross_mapping_retained(self):
        plan=build_plan(PlannerConfig(['owasp_llm_2025','mitre_atlas'],['LLM01'],['direct_prompt_injection']))
        self.assertEqual(plan.seeds[0].frameworks,['mitre_atlas','owasp_llm_2025'])
    def test_pdf_bytes_no_raw_prompt(self):
        s=summary([row(1,'text_blocked',prompt='NEVER_EXPOSE_THIS_PROMPT')]);s['assessment']=build_assessment(s)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'executive.pdf';export_executive_pdf(s,p);data=p.read_bytes()
            self.assertTrue(data.startswith(b'%PDF-1.4'));self.assertIn(b'startxref',data)
            self.assertNotIn('NEVER_EXPOSE_THIS_PROMPT'.encode().hex().encode(),data)
    def test_report_injection_safely_escaped(self):
        s=summary([row(1,prompt='</script><script>alert(7)</script> __JS__ __DATA__')])
        h=render_report_html(s)
        self.assertNotIn('</script><script>alert(7)</script>',h)
        self.assertIn('\\u003c/script',h)
        self.assertIn('executive.pdf',h)


class ModelServer(BaseHTTPRequestHandler):
    calls=[]
    def log_message(self,*args):pass
    def do_POST(self):
        data=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.__class__.calls.append((self.path,data,dict(self.headers)))
        if self.path=='/fail':
            self.send_response(503);self.end_headers();return
        gem=self.path.endswith(':generateContent')
        ctx=json.loads(data['contents'][0]['parts'][0]['text'] if gem else data['messages'][1]['content'])
        count=ctx.get('count',1)
        call=len(self.calls)
        text=json.dumps({'prompts':[f'Caso ficticio seguro {call}-{i}: '+ctx.get('seed','Hola') for i in range(count)]})
        result=({'candidates':[{'content':{'parts':[{'text':text}]}}],
                 'usageMetadata':{'promptTokenCount':14,'candidatesTokenCount':10}} if gem else
                {'choices':[{'message':{'content':text}}],'usage':{'prompt_tokens':14,'completion_tokens':10}})
        raw=json.dumps(result).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)


class GeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),ModelServer)
        cls.base=f'http://127.0.0.1:{cls.server.server_port}'
        threading.Thread(target=cls.server.serve_forever,daemon=True).start()
    @classmethod
    def tearDownClass(cls):cls.server.shutdown();cls.server.server_close()
    def cfg(self,mode='openai_compatible',path='/chat',**kw):
        return GeneratorConfig.from_dict({'mode':mode,'url':self.base+path,'model':'lab',
                  'share_test_data_confirmed':True,**kw})
    def test_rules_without_credentials(self):
        self.assertEqual(GeneratorConfig.from_dict({}).mode,'rules')
    def test_missing_consent(self):
        with self.assertRaises(GeneratorError):self.cfg(share_test_data_confirmed=False)
    def test_missing_env_key(self):
        with self.assertRaises(GeneratorError):self.cfg(api_key_env='KYOJITSU_MISSING_TEST_VAR')
    def test_remote_http_disallowed(self):
        with self.assertRaises(GeneratorError):self.cfg(url='http://example.org/chat')
    def test_gemini_model_matches_url(self):
        with self.assertRaises(GeneratorError):self.cfg('gemini','/models/wrong:generateContent')
    def test_openai_contract_with_feedback(self):
        g=ModelGenerator(self.cfg());g.preflight()
        p=g.variants(seed='Laboratorio',objective='Seguridad',technique='direct_prompt_injection',
                     operator='nested_role',feedback={'outcome':'input_blocked'},generation=1,count=2,max_chars=6000)
        self.assertEqual(len(p),2);self.assertEqual(g.calls,2)
        ctx=json.loads(ModelServer.calls[-1][1]['messages'][-1]['content'])
        self.assertEqual(ctx['feedback']['outcome'],'input_blocked')
        self.assertEqual(g.input_tokens,28)
    def test_gemini_contract(self):
        g=ModelGenerator(self.cfg('gemini','/models/lab:generateContent'));g.preflight()
        self.assertEqual(g.calls,1);self.assertIn('systemInstruction',ModelServer.calls[-1][1])
    def test_failure_not_fallback(self):
        with self.assertRaises(GeneratorError):ModelGenerator(self.cfg(path='/fail')).preflight()
    def test_limit_enforced(self):
        g=ModelGenerator(self.cfg(max_calls=1));g.preflight()
        with self.assertRaises(GeneratorError):g.preflight()
    def test_key_only_request_not_snapshot(self):
        with patch.dict(os.environ,{'KYOJITSU_TEST_GENERATOR_KEY':'unit-secret-v33'}):
            g=ModelGenerator(self.cfg(api_key_env='KYOJITSU_TEST_GENERATOR_KEY'));g.preflight()
            self.assertEqual(ModelServer.calls[-1][2]['Authorization'],'Bearer unit-secret-v33')
            self.assertNotIn('unit-secret-v33',json.dumps(g.snapshot()))
    def test_full_campaign_uses_generator_g0_and_g1(self):
        c={'target':{'type':'fixture'},'simulation_confirmed':True,
           'selection':{'frameworks':['owasp_llm_2025'],'category_ids':['LLM01'],'technique_ids':['direct_prompt_injection'],
                        'seeds_per_technique':1,'include_benign_controls':True},
           'evolution':{'generations':1,'population_size':2,'request_interval_seconds':0},
           'limits':{'max_requests':10},
           'generator':{'mode':'openai_compatible','url':self.base+'/chat','model':'lab','share_test_data_confirmed':True}}
        with tempfile.TemporaryDirectory() as d:
            out=run_campaign(c,output_dir=d)
            s=json.loads((Path(d)/'summary.json').read_text())
            adv=[r for r in s['candidates'] if r['expected']!='benign']
            self.assertTrue(all('llm-generated' in r['tags'] for r in adv))
            self.assertTrue(any(r['generation']==1 for r in adv))
            self.assertGreater(s['assessment']['generator']['calls'],2)
            self.assertTrue((Path(d)/'executive.pdf').exists())

if __name__=='__main__':unittest.main()
