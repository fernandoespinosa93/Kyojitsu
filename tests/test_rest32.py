from __future__ import annotations

import io
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from kyojitsu.models import Candidate, Outcome
from kyojitsu.rest_tools import import_curl, put_prompt, redact_config
from kyojitsu.runner import build_target, run_campaign
from kyojitsu.targets import GenericJsonTarget, GenericTargetProfile, ConnectionTestError
from kyojitsu.studio_ui import STUDIO_HTML

TOKEN = 'unit-test-secret-32'


class TestEndpoint(BaseHTTPRequestHandler):
    calls = []
    server_version = 'KyojitsuRegressionEndpoint/1.0'

    def log_message(self, *_):
        pass

    def send_json(self, value, status=200):
        raw = json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('X-Kyojitsu-Lab', 'true')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
        self.__class__.calls.append((self.path, data, self.headers.get('Authorization')))
        if self.path.startswith('/auth') and self.headers.get('Authorization') != 'Bearer ' + TOKEN:
            return self.send_json({'error': 'unauthorized'}, 401)
        if self.path == '/403':
            return self.send_json({'error': 'permissions'}, 403)
        if self.path == '/500':
            return self.send_json({'error': 'server'}, 500)
        if self.path == '/redirect':
            self.send_response(307)
            self.send_header('Location', '/sink')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if self.path == '/html':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'<html>login page</html>')
            return
        if self.path == '/blocked':
            return self.send_json({'guard': {'blocked': True, 'stage': 'input'}})
        if self.path == '/badbool':
            return self.send_json({'result': {'text': 'hello'}, 'guard': {'blocked': 'unknown'}})
        if self.path == '/reflect':
            return self.send_json({'result': {'text': 'echo ' + self.headers.get('Authorization', '')}, 'guard': {'blocked': False}})
        if self.path == '/slow':
            time.sleep(.2)
        prompt = data.get('input', {}).get('question', data.get('prompt', ''))
        return self.send_json({'result': {'text': 'Received: ' + prompt}, 'guard': {'blocked': False, 'stage': 'model'}})


def profile(url):
    return {'name': 'test', 'url': url, 'headers': {'Content-Type': 'application/json'},
            'body_template': {'input': {'question': '{{prompt}}'}},
            'response': {'answer_path': 'result.text', 'blocked_path': 'guard.blocked', 'stage_path': 'guard.stage'},
            'timeout_seconds': 2, 'strict_instrumentation': True}


def config(url):
    return {'target': {'type': 'generic', 'profile': profile(url)}, 'authorization_confirmed': True,
            'selection': {'frameworks': ['owasp_llm_2025'], 'category_ids': ['LLM01'],
                          'technique_ids': ['direct_prompt_injection'], 'seeds_per_technique': 1,
                          'include_benign_controls': True},
            'evolution': {'generations': 1, 'population_size': 2, 'request_interval_seconds': 0},
            'limits': {'max_requests': 10}}


def candidate():
    return Candidate(id='candidate1', run_id='run1', root_seed_id='seed1', parent_id=None,
                     generation=0, prompt='Test', category='LLM01', operator='seed', expected='malicious')


class CurlImportTests(unittest.TestCase):
    def test_nested_json_bearer_autodetection_no_execution(self):
        command = "curl 'https://example.invalid/api' -H 'Authorization: Bearer abc123' --data-raw '{\"input\":{\"question\":\"hola\"},\"model\":\"lab\"}'"
        with patch('urllib.request.urlopen', side_effect=AssertionError('No network during import')):
            result = import_curl(command)
        self.assertFalse(result['executed'])
        self.assertEqual(result['prompt_path'], 'input.question')
        self.assertEqual(result['profile']['body_template']['input']['question'], '{{prompt}}')
        self.assertEqual(result['profile']['headers']['Authorization'], 'Bearer abc123')
        self.assertEqual(result['profile']['body_template']['model'], 'lab')

    def test_messages_uses_last_user_not_system(self):
        body = {'messages': [{'role': 'system', 'content': 'policy'}, {'role': 'user', 'content': 'one'}, {'role': 'user', 'content': 'two'}]}
        r = import_curl("curl https://example.invalid/api --json '" + json.dumps(body) + "'")
        self.assertEqual(r['prompt_path'], 'messages.2.content')
        self.assertEqual(r['profile']['body_template']['messages'][0]['content'], 'policy')

    def test_basic_auth_and_cookie(self):
        r = import_curl("curl https://example.invalid/api -u user:pass -b 'session=abc' -d '{\"prompt\":\"hi\"}'")
        self.assertEqual(r['profile']['headers']['Authorization'], 'Basic dXNlcjpwYXNz')
        self.assertEqual(r['profile']['headers']['Cookie'], 'session=abc')

    def test_continuation_and_short_attached_options(self):
        r = import_curl("curl.exe 'https://example.invalid/api' \\\n -XPOST -H'X-API-Key: key' --data-raw '{\"prompt\":\"hi\"}'")
        self.assertEqual(r['profile']['headers']['X-API-Key'], 'key')
        self.assertEqual(r['profile']['method'], 'POST')

    def test_literal_shell_like_prompt_is_data_only(self):
        r = import_curl("curl https://example.invalid/api --json '{\"prompt\":\"$(touch /tmp/never-execute)\"}'")
        self.assertFalse(r['executed'])

    def test_shell_chaining_rejected(self):
        with self.assertRaises(ValueError):
            import_curl("curl https://example.invalid/api -d '{}' ; touch /tmp/x")

    def test_file_loading_rejected(self):
        with self.assertRaises(ValueError):
            import_curl('curl https://example.invalid/api -d @/etc/passwd')

    def test_insecure_rejected(self):
        with self.assertRaises(ValueError):
            import_curl("curl -k https://example.invalid/api -d '{}' ")

    def test_unsupported_flag_rejected_not_ignored(self):
        with self.assertRaises(ValueError):
            import_curl('curl https://example.invalid/api --config config.txt')

    def test_non_json_rejected(self):
        with self.assertRaises(ValueError):
            import_curl("curl https://example.invalid/api -d 'prompt=hi'")

    def test_multiple_urls_rejected(self):
        with self.assertRaises(ValueError):
            import_curl("curl https://example.invalid/api https://other.invalid/api -d '{}' ")

    def test_ambiguous_prompt_needs_operator(self):
        r = import_curl("curl https://example.invalid/api --json '{\"a\":\"one\",\"b\":\"two\"}'")
        self.assertIsNone(r['prompt_path'])
        self.assertTrue(r['warnings'])
        self.assertEqual(put_prompt(r['original_body'], 'b')['b'], '{{prompt}}')

    def test_credential_export_redaction(self):
        c = config('https://example.invalid/api?token=URL-secret')
        c['target']['profile']['headers']['Authorization'] = 'Bearer ' + TOKEN
        c['target']['profile']['body_template']['api_key'] = 'body-secret'
        c['connection_token'] = 'studio-secret'
        data = json.dumps(redact_config(c))
        for forbidden in (TOKEN, 'body-secret', 'URL-secret', 'studio-secret'):
            self.assertNotIn(forbidden, data)
        self.assertIn('{{prompt}}', data)

    def test_studio_has_no_money_or_legacy_tab(self):
        self.assertNotIn('id="budget"', STUDIO_HTML)
        self.assertNotIn('id="sumBudget"', STUDIO_HTML)
        self.assertNotIn('data-target="ikigai"', STUDIO_HTML)
        self.assertRegex(STUDIO_HTML, r'<button[^>]*data-target="generic"[^>]*>API REST</button>')
        self.assertIn('minmax(0,1fr)', STUDIO_HTML)


class RestConnectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), TestEndpoint)
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def target(self, path='/echo', **kwargs):
        p = profile(self.base + path)
        p.update(kwargs)
        return GenericJsonTarget(GenericTargetProfile.from_dict(p), authorization_confirmed=True)

    def test_connection_probe_uses_post_and_real_contract(self):
        start = len(TestEndpoint.calls)
        result = self.target().connection_test()
        self.assertTrue(result['reachable'])
        self.assertTrue(result['contract_valid'])
        self.assertEqual(len(TestEndpoint.calls), start + 1)
        self.assertIn('saludo', TestEndpoint.calls[-1][1]['input']['question'])
        self.assertEqual(result['http_status'], 200)

    def test_missing_answer_suggests_actual_paths(self):
        t = self.target(response={'answer_path': 'wrong', 'blocked_path': None}, strict_instrumentation=False)
        result = t.connection_test()
        self.assertFalse(result['contract_valid'])
        self.assertTrue(result['reachable'])
        self.assertIn('result.text', result['answer_paths'])

    def test_html_is_not_valid_json(self):
        result = self.target('/html').connection_test()
        self.assertFalse(result['contract_valid'])
        self.assertTrue(result['reachable'])

    def test_auth_401_does_not_become_guardrail_block(self):
        t = self.target('/auth')
        self.assertEqual(t.connection_test()['http_status'], 401)
        self.assertEqual(t.evaluate(candidate()).outcome, Outcome.TARGET_ERROR)

    def test_403_is_not_guardrail_block_even_legacy_mapping(self):
        t = self.target('/403', blocked_http_statuses=[403])
        self.assertFalse(t.connection_test()['contract_valid'])
        self.assertEqual(t.evaluate(candidate()).outcome, Outcome.TARGET_ERROR)

    def test_500_is_failed_test(self):
        self.assertFalse(self.target('/500').connection_test()['contract_valid'])

    def test_explicit_block_without_answer_is_valid_evidence(self):
        self.assertTrue(self.target('/blocked').connection_test()['contract_valid'])
        self.assertEqual(self.target('/blocked').evaluate(candidate()).outcome, Outcome.INPUT_BLOCKED)

    def test_boolean_instrumentation_is_strict(self):
        self.assertFalse(self.target('/badbool').connection_test()['contract_valid'])
        self.assertEqual(self.target('/badbool').evaluate(candidate()).outcome, Outcome.INVALID_RESPONSE)

    def test_redirect_is_not_followed(self):
        n = len(TestEndpoint.calls)
        result = self.target('/redirect').connection_test()
        self.assertFalse(result['contract_valid'])
        self.assertEqual(result['http_status'], 307)
        self.assertEqual([x[0] for x in TestEndpoint.calls[n:]], ['/redirect'])

    def test_authenticated_test_and_campaign_preserve_credentials_in_memory_only(self):
        c = config(self.base + '/reflect')
        c['target']['profile']['headers']['Authorization'] = 'Bearer ' + TOKEN
        with tempfile.TemporaryDirectory() as temp:
            events = []
            run_campaign(c, output_dir=temp, event_callback=events.append)
            self.assertTrue(any(e['type'] == 'candidate_started' for e in events))
            self.assertTrue(any(e['type'] == 'candidate_evaluated' and e['http_status'] == 200 for e in events))
            for file in Path(temp).rglob('*'):
                if file.is_file():
                    self.assertNotIn(TOKEN.encode(), file.read_bytes(), str(file))
            self.assertNotIn(TOKEN, json.dumps(events))

    def test_reflected_secret_redacted_from_probe(self):
        t = self.target('/reflect', headers={'Authorization': 'Bearer '+TOKEN})
        self.assertNotIn(TOKEN, json.dumps(t.connection_test()))

    def test_stopped_server_does_not_generate_report(self):
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        sock.close()
        c = config(f'http://127.0.0.1:{port}/echo')
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / 'should-not-exist'
            with self.assertRaises(ConnectionTestError):
                run_campaign(c, output_dir=out)
            self.assertFalse((out/'report.html').exists())

    def test_missing_target_never_defaults_to_fixture(self):
        with self.assertRaises(ValueError):
            build_target({}, authorization_confirmed=True)

    def test_fixture_requires_separate_opt_in(self):
        c = config(self.base+'/echo')
        c['target'] = {'type': 'fixture'}
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                run_campaign(c, output_dir=temp)

    def test_cancel_stops_future_requests(self):
        c = config(self.base+'/echo')
        events = []
        def cancelled():
            return sum(e['type']=='candidate_evaluated' for e in events) >= 2
        with tempfile.TemporaryDirectory() as temp:
            result = run_campaign(c, output_dir=temp, event_callback=events.append, cancel_check=cancelled)
        self.assertEqual(result['result']['status'], 'cancelled')
        self.assertEqual(result['result']['evaluated'], 2)


class StudioHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api_server = ThreadingHTTPServer(('127.0.0.1', 0), TestEndpoint)
        cls.api_thread = threading.Thread(target=cls.api_server.serve_forever, daemon=True)
        cls.api_thread.start()
        cls.target_url = f'http://127.0.0.1:{cls.api_server.server_port}/auth'
        cls.temp = tempfile.TemporaryDirectory()
        sock = socket.socket(); sock.bind(('127.0.0.1',0)); port = sock.getsockname()[1]; sock.close()
        cls.base = f'http://127.0.0.1:{port}'
        root = Path(__file__).resolve().parents[1]
        env = dict(os.environ, PYTHONPATH=str(root/'src'))
        cls.proc = subprocess.Popen([sys.executable,'-m','kyojitsu','studio','--host','127.0.0.1','--port',str(port),'--runs-dir',cls.temp.name,'--no-open'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                html = urllib.request.urlopen(cls.base+'/',timeout=.2).read().decode()
                cls.csrf = re.search("const TOKEN='([^']+)'",html).group(1)
                break
            except (OSError, AttributeError):
                time.sleep(.05)
        else:
            raise RuntimeError('Studio did not start')

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate(); cls.proc.wait(timeout=5)
        cls.api_server.shutdown(); cls.api_server.server_close(); cls.temp.cleanup()

    def post(self, path, data):
        req=urllib.request.Request(self.base+path, data=json.dumps(data).encode(), headers={'Content-Type':'application/json','X-Kyojitsu-Token':self.csrf})
        try:
            with urllib.request.urlopen(req,timeout=5) as resp:
                return resp.status,json.load(resp)
        except urllib.error.HTTPError as exc:
            return exc.code,json.load(exc)

    def cfg(self):
        c=config(self.target_url)
        c['target']['profile']['headers']['Authorization']='Bearer '+TOKEN
        return c

    def test_run_without_connection_token_rejected(self):
        code,data=self.post('/api/run',self.cfg())
        self.assertEqual(code,400)
        self.assertIn('conexi',data['error'])

    def test_changed_contract_invalidates_token(self):
        c=self.cfg(); _,result=self.post('/api/test-target',c)
        self.assertTrue(result['ok'])
        c['connection_token']=result['connection_token']
        c['target']['profile']['body_template']['extra']='changed'
        code,_=self.post('/api/run',c)
        self.assertEqual(code,400)

    def test_complete_real_http_campaign_through_studio(self):
        c=self.cfg(); _,r=self.post('/api/test-target',c)
        self.assertTrue(r['ok']); c['connection_token']=r['connection_token']
        code,r=self.post('/api/run',c); self.assertEqual(code,202)
        for _ in range(100):
            state=json.load(urllib.request.urlopen(self.base+'/api/status'))
            if state['state']!='running': break
            time.sleep(.03)
        self.assertEqual(state['state'],'completed',state.get('error'))
        self.assertGreater(state['evaluated'],0)
        self.assertTrue(any(e['type']=='candidate_started' for e in state['events']))
        self.assertIn('source',state)
        html=urllib.request.urlopen(self.base+state['report_url']).read()
        self.assertIn(b'Kyojitsu',html)
        self.assertNotIn(TOKEN.encode(),html)

    def test_curl_import_does_not_need_target_running(self):
        code,r=self.post('/api/import-curl',{'curl':"curl https://example.invalid/chat --json '{\"prompt\":\"Hi\"}'"})
        self.assertEqual(code,200); self.assertFalse(r['executed'])

    def test_fixture_no_confirmation_rejected(self):
        c=self.cfg();c['target']={'type':'fixture'}
        code,_=self.post('/api/run',c)
        self.assertEqual(code,400)

    def test_empty_techniques_not_auto_all(self):
        c=self.cfg();c['selection']['technique_ids']=[]
        code,_=self.post('/api/plan',c)
        self.assertEqual(code,400)

    def test_local_host_validation(self):
        req=urllib.request.Request(self.base+'/api/status',headers={'Host':'malicious.invalid'})
        with self.assertRaises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req)
        self.assertEqual(e.exception.code,403)


if __name__=='__main__':
    unittest.main()


class ObservationTests(unittest.TestCase):
    def test_missing_signal_not_zero_bypass(self):
        from kyojitsu.reporting import _observed_bypass
        self.assertIsNone(_observed_bypass([{'guardrail_passed': None}]))
        self.assertEqual(_observed_bypass([{'guardrail_passed': 1}, {'guardrail_passed': 0}, {'guardrail_passed': None}]), 50)

    def test_policy_confirmation_requires_boolean_true(self):
        self.assertFalse(GenericTargetProfile.from_dict({'policy_oracle_confirmed': 'false'}).policy_oracle_confirmed)
        self.assertTrue(GenericTargetProfile.from_dict({'policy_oracle_confirmed': True}).policy_oracle_confirmed)
