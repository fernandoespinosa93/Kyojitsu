from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from kyojitsu.generator import GeneratorConfig, ModelGenerator, discover_models
from kyojitsu.runner import run_campaign
from kyojitsu.studio_ui import STUDIO_HTML


class ProviderHandler(BaseHTTPRequestHandler):
    calls = []
    key = "temp-key-34"

    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.__class__.calls.append(("GET", self.path, dict(self.headers)))
        if self.headers.get("x-api-key") == self.key:
            body = {"data": [{"id": "claude-lab", "display_name": "Claude Lab"}]}
        elif self.headers.get("x-goog-api-key") == self.key:
            body = {"models": [{"name": "models/gemini-lab", "baseModelId": "gemini-lab", "displayName": "Gemini Lab", "supportedGenerationMethods": ["generateContent"]}]}
        elif self.headers.get("Authorization") == "Bearer " + self.key:
            body = {"data": [{"id": "openai-lab"}]}
        else:
            self.send_response(401); self.end_headers(); return
        raw = json.dumps(body).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        self.__class__.calls.append(("POST", self.path, dict(self.headers), data))
        if self.headers.get("x-goog-api-key") == self.key:
            ctx = json.loads(data["input"])
            text = json.dumps({"prompts": ["Caso seguro generado: " + ctx.get("objective", "prueba") + f" #{len(self.__class__.calls)}"]})
            body = {"steps": [{"type": "model_output", "content": [{"type": "text", "text": text}]}]}
        else:
            ctx = json.loads(data["messages"][-1]["content"])
            text = json.dumps({"prompts": ["Caso seguro generado: " + ctx.get("objective", "prueba") + f" #{len(self.__class__.calls)}"]})
            body = {"choices": [{"message": {"content": text}}]}
        raw = json.dumps(body).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)


class Release34Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ProviderHandler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close()

    def test_studio_has_temporary_key_and_real_provider_urls(self):
        self.assertIn('id="generatorApiKey"', STUDIO_HTML)
        self.assertIn('https://api.anthropic.com/v1/messages', STUDIO_HTML)
        self.assertIn('https://api.anthropic.com/v1/models', STUDIO_HTML)
        self.assertIn('https://generativelanguage.googleapis.com/v1beta/interactions', STUDIO_HTML)
        self.assertIn('https://generativelanguage.googleapis.com/v1beta/models', STUDIO_HTML)
        self.assertNotIn('generatorKeyEnv', STUDIO_HTML)
        self.assertIn('flowParticles', STUDIO_HTML)

    def test_anthropic_model_discovery_uses_temporary_key(self):
        with patch('kyojitsu.generator.ANTHROPIC_MODELS_URL', self.base + '/v1/models'):
            out = discover_models({"mode": "anthropic", "api_key": ProviderHandler.key, "timeout_seconds": 5})
        self.assertEqual(out['models'][0]['id'], 'claude-lab')
        self.assertNotIn(ProviderHandler.key, json.dumps(out))

    def test_gemini_model_discovery_filters_generation_models(self):
        with patch('kyojitsu.generator.GEMINI_MODELS_URL', self.base + '/v1beta/models'):
            out = discover_models({"mode": "gemini", "api_key": ProviderHandler.key, "timeout_seconds": 5})
        self.assertEqual(out['models'][0]['id'], 'gemini-lab')
        self.assertNotIn(ProviderHandler.key, json.dumps(out))

    def test_gemini_interactions_contract(self):
        cfg = GeneratorConfig.from_dict({"mode": "gemini", "url": self.base + '/v1beta/interactions', "model": "gemini-lab", "api_key": ProviderHandler.key, "share_test_data_confirmed": True, "timeout_seconds": 5})
        g = ModelGenerator(cfg); result = g.preflight()
        self.assertTrue(result['ok'])
        last = [c for c in ProviderHandler.calls if c[0] == 'POST'][-1]
        self.assertEqual(last[1], '/v1beta/interactions')
        self.assertEqual(last[3]['model'], 'gemini-lab')
        self.assertFalse(last[3]['store'])
        headers = {str(k).lower(): v for k, v in last[2].items()}
        self.assertEqual(headers.get('x-goog-api-key'), ProviderHandler.key)

    def test_temporary_key_never_persisted_in_campaign_artifacts(self):
        campaign = {
            'target': {'type': 'fixture'}, 'simulation_confirmed': True,
            'selection': {'frameworks': ['owasp_llm_2025'], 'category_ids': ['LLM01'], 'technique_ids': ['direct_prompt_injection'], 'seeds_per_technique': 1, 'include_benign_controls': False},
            'evolution': {'generations': 0, 'population_size': 2, 'request_interval_seconds': 0},
            'limits': {'max_requests': 2},
            'generator': {'mode': 'openai_compatible', 'url': self.base + '/chat/completions', 'model': 'openai-lab', 'api_key': ProviderHandler.key, 'share_test_data_confirmed': True, 'max_calls': 4, 'timeout_seconds': 5},
        }
        with tempfile.TemporaryDirectory() as d:
            run_campaign(campaign, output_dir=d)
            root = Path(d)
            for name in ['campaign.json', 'summary.json', 'assessment.json', 'report.html', 'report.md']:
                self.assertNotIn(ProviderHandler.key, (root/name).read_text(encoding='utf-8'))
            conn = sqlite3.connect(root/'kyojitsu.db')
            blobs = '\n'.join(str(row[0]) for row in conn.execute("SELECT config_json FROM runs"))
            conn.close()
            self.assertNotIn(ProviderHandler.key, blobs)


if __name__ == '__main__':
    unittest.main()
