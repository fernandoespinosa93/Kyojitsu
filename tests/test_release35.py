from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from kyojitsu.generator import GeneratorConfig, ModelGenerator, discover_models
from kyojitsu.studio_ui import STUDIO_HTML


class GeminiCompatHandler(BaseHTTPRequestHandler):
    key = 'temp-key-35'
    calls = []

    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.__class__.calls.append(('GET', self.path, dict(self.headers)))
        if self.headers.get('x-goog-api-key') != self.key:
            self.send_response(401); self.end_headers(); return
        body = {
            'models': [
                {'name': 'models/gemini-2.5-flash', 'baseModelId': 'gemini-2.5-flash', 'displayName': 'Gemini 2.5 Flash', 'supportedGenerationMethods': ['generateContent']},
                {'name': 'models/gemini-3.8-flash', 'baseModelId': 'gemini-3.8-flash', 'displayName': 'Gemini 3.8 Flash', 'supportedGenerationMethods': ['generateContent']},
            ]
        }
        raw = json.dumps(body).encode()
        self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
        self.__class__.calls.append(('POST', self.path, dict(self.headers), body))
        if self.headers.get('x-goog-api-key') != self.key:
            self.send_response(401); self.end_headers(); return
        # Interactions legacy output shape deliberately exercises the parser.
        if self.path.endswith('/interactions'):
            ctx = json.loads(body['input'])
            text = json.dumps({'prompts':['Variante desde outputs: '+ctx.get('objective','prueba')]})
            payload = {'status':'completed','outputs':[{'type':'text','text':text}]}
        else:
            ctx = json.loads(body['contents'][0]['parts'][0]['text'])
            text = json.dumps({'prompts':['Variante desde generateContent: '+ctx.get('objective','prueba')]})
            payload = {'candidates':[{'content':{'parts':[{'text':text}]}}]}
        raw=json.dumps(payload).encode()
        self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)


class Release35Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0),GeminiCompatHandler)
        cls.base=f'http://127.0.0.1:{cls.server.server_port}'
        threading.Thread(target=cls.server.serve_forever,daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close()

    def test_discovery_prefers_legacy_transport_for_25(self):
        with patch('kyojitsu.generator.GEMINI_MODELS_URL',self.base+'/v1beta/models'):
            out=discover_models({'mode':'gemini','api_key':GeminiCompatHandler.key,'timeout_seconds':5})
        by_id={x['id']:x for x in out['models']}
        self.assertEqual(by_id['gemini-2.5-flash']['transport'],'generateContent')
        self.assertIn(':generateContent',by_id['gemini-2.5-flash']['generation_url'])
        self.assertEqual(by_id['gemini-3.8-flash']['transport'],'Interactions')

    def test_gemini_legacy_outputs_shape_is_parsed(self):
        cfg=GeneratorConfig.from_dict({'mode':'gemini','url':self.base+'/v1beta/interactions','model':'gemini-3.8-flash','api_key':GeminiCompatHandler.key,'share_test_data_confirmed':True,'timeout_seconds':5})
        out=ModelGenerator(cfg).preflight()
        self.assertTrue(out['ok'])

    def test_gemini_generate_content_contract_is_supported(self):
        cfg=GeneratorConfig.from_dict({'mode':'gemini','url':self.base+'/v1beta/models/gemini-2.5-flash:generateContent','model':'gemini-2.5-flash','api_key':GeminiCompatHandler.key,'share_test_data_confirmed':True,'timeout_seconds':5})
        out=ModelGenerator(cfg).preflight()
        self.assertTrue(out['ok'])

    def test_ui_has_new_origin_particle_layer_and_non_confusing_placeholder(self):
        self.assertIn('flowParticles',STUDIO_HTML)
        self.assertIn('Aún no hay una respuesta del endpoint',STUDIO_HTML)
        self.assertIn('3.8.1',STUDIO_HTML)


if __name__ == '__main__':
    unittest.main()
