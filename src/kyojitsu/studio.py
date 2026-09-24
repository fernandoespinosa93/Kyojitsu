from __future__ import annotations

import hashlib
import json
import mimetypes
import secrets
import threading
import time
import webbrowser
from collections import Counter
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse, parse_qs

from .generator import GeneratorConfig, ModelGenerator, discover_models
from .frameworks import catalog_json
from .runner import build_campaign_plan, build_target, run_campaign
from .rest_tools import import_curl, put_prompt
from .targets import GenericJsonTarget
from .studio_ui import STUDIO_HTML


@dataclass
class StudioState:
    lock: threading.RLock = field(default_factory=threading.RLock)
    cancel: threading.Event = field(default_factory=threading.Event)
    state: str = 'idle'
    job_id: str | None = None
    output_dir: str | None = None
    report_url: str | None = None
    error: str | None = None
    progress: float = 0
    max_requests: int = 1
    candidate_events: int = 0
    seq: int = 0
    events: list[dict] = field(default_factory=list)
    source: dict = field(default_factory=dict)
    outcomes: Counter = field(default_factory=Counter)
    malicious_known: int = 0
    malicious_passed: int = 0
    observed_errors: int = 0

    def reset_for_job(self, job_id: str, output_dir: Path, max_requests: int) -> None:
        with self.lock:
            self.state, self.job_id, self.output_dir = 'running', job_id, str(output_dir)
            self.report_url = self.error = None
            self.progress = self.candidate_events = self.seq = 0
            self.max_requests = max(1, max_requests)
            self.events = []
            self.source = {}
            self.outcomes.clear()
            self.malicious_known = self.malicious_passed = self.observed_errors = 0
            self.cancel.clear()

    def add_event(self, event: dict) -> None:
        with self.lock:
            self.seq += 1
            event = dict(event, seq=self.seq, time=time.time())
            if event.get('type') == 'preflight_started':
                self.source = {'mode': event.get('target_type'), 'simulation': event.get('target_type') == 'fixture'}
            if event.get('type') == 'preflight_passed':
                health = event.get('health') or {}
                self.source.update(url=health.get('url', ''), simulation=health.get('simulation', self.source.get('simulation', False)))
            if event.get('type') == 'candidate_evaluated':
                self.candidate_events += 1
                outcome = event.get('outcome', '')
                self.outcomes[outcome] += 1
                self.observed_errors += int(outcome in {'target_error', 'transport_error', 'invalid_response'})
                if event.get('expected') != 'benign' and event.get('guardrail_passed') is not None:
                    self.malicious_known += 1
                    self.malicious_passed += int(bool(event['guardrail_passed']))
                self.progress = min(99, 100 * self.candidate_events / self.max_requests)
            self.events.append(event)
            self.events = self.events[-1200:]

    def finish(self, report_url: str, status: str = 'completed', reason: str = '') -> None:
        with self.lock:
            self.state = status
            if status == 'completed':
                self.progress = 100
            self.report_url = report_url
            self.error = reason or None

    def fail(self, message: str) -> None:
        self.add_event({'type': 'error', 'message': message})
        with self.lock:
            self.state, self.error = 'failed', message

    def snapshot(self, after: int = 0) -> dict:
        with self.lock:
            return {'state': self.state, 'job_id': self.job_id, 'report_url': self.report_url,
                    'error': self.error, 'progress': round(self.progress, 2), 'seq': self.seq,
                    'evaluated': self.candidate_events, 'max_requests': self.max_requests,
                    'outcomes': dict(self.outcomes), 'errors': self.observed_errors,
                    'bypass_rate': round(100 * self.malicious_passed / self.malicious_known, 2) if self.malicious_known else None,
                    'bypass_denominator': self.malicious_known,
                    'source': dict(self.source), 'events': [e for e in self.events if e['seq'] > after]}


def target_fingerprint(config: dict) -> str:
    payload = {'target': config.get('target'), 'authorized': config.get('authorization_confirmed')}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def serve_studio(*, host: str, port: int, runs_dir: Path, open_browser: bool = True) -> None:
    if host not in {'127.0.0.1', 'localhost'}:
        raise ValueError('Studio solo escucha en localhost: contiene configuraci\u00f3n y evidencias privadas.')
    runs_dir = Path(runs_dir).resolve()
    runs_dir.mkdir(parents=True, exist_ok=True)
    csrf = secrets.token_urlsafe(24)
    state = StudioState()
    verified: dict[str, tuple[str, float]] = {}
    html = STUDIO_HTML.replace('__KYOJITSU_CSRF__', csrf).encode('utf-8')

    class Handler(BaseHTTPRequestHandler):
        server_version = 'KyojitsuStudio/3.8.1'

        def log_message(self, fmt, *args):
            if not self.path.startswith('/api/status'):
                # No headers, request body, curl, credentials or target URLs are logged.
                super().log_message(fmt, *args)

        def _local_host(self) -> bool:
            expected = {f'127.0.0.1:{self.server.server_address[1]}', f'localhost:{self.server.server_address[1]}'}
            if self.headers.get('Host') not in expected:
                self._json({'error': 'Host no permitido.'}, 403)
                return False
            return True

        def _json(self, payload, status=200):
            body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _error(self, message, status=400):
            self._json({'error': message}, status)

        def _body_json(self):
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 2_000_000:
                raise ValueError('Body vac\u00edo o demasiado grande.')
            data = json.loads(self.rfile.read(length).decode('utf-8'))
            if not isinstance(data, dict):
                raise ValueError('El body debe ser un objeto JSON.')
            return data

        def do_GET(self):
            if not self._local_host():
                return
            parsed = urlparse(self.path)
            if parsed.path == '/':
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(html)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Frame-Options', 'DENY')
                self.end_headers()
                self.wfile.write(html)
            elif parsed.path == '/api/catalog':
                self._json(catalog_json())
            elif parsed.path == '/api/status':
                try:
                    after = int(parse_qs(parsed.query).get('after', ['0'])[0])
                except ValueError:
                    after = 0
                self._json(state.snapshot(after))
            elif parsed.path.startswith('/runs/'):
                self._serve_run_file(parsed.path)
            else:
                self._error('Recurso no encontrado.', 404)

        def _serve_run_file(self, path):
            parts = [unquote(x) for x in path.split('/') if x]
            if len(parts) != 3 or parts[0] != 'runs':
                return self._error('Ruta inv\u00e1lida.', 404)
            _, job_id, filename = parts
            if '/' in job_id or '\\' in job_id or filename not in {'report.html', 'summary.json', 'candidates.csv', 'report.md', 'plan.json', 'campaign.json', 'executive.pdf', 'assessment.json'}:
                return self._error('Artefacto no permitido.', 403)
            candidate = (runs_dir / job_id / filename).resolve()
            if not candidate.is_relative_to(runs_dir) or not candidate.is_file():
                return self._error('Artefacto no encontrado.', 404)
            body = candidate.read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', (mimetypes.guess_type(filename)[0] or 'application/octet-stream') + ('' if filename.endswith('.pdf') else '; charset=utf-8'))
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if not self._local_host():
                return
            if not secrets.compare_digest(self.headers.get('X-Kyojitsu-Token', ''), csrf):
                return self._error('Token local inv\u00e1lido.', 403)
            try:
                config = self._body_json()
                if self.path == '/api/import-curl':
                    return self._json(import_curl(config.get('curl', ''), config.get('prompt_path')))
                if self.path == '/api/generator-models':
                    return self._json(discover_models(config.get('generator')))
                if self.path == '/api/test-generator':
                    generator_config = GeneratorConfig.from_dict(config.get('generator'))
                    if generator_config.mode == 'rules':
                        return self._json({'ok': True, 'message': 'Reglas locales: no se llama a un LLM.'})
                    return self._json(ModelGenerator(generator_config).preflight())
                if self.path == '/api/prompt-path':
                    return self._json({'body_template': put_prompt(config.get('body', {}), config.get('path', ''))})
                if self.path in {'/api/test-target', '/api/preflight'}:
                    if (config.get('target') or {}).get('type') == 'fixture':
                        return self._json({'ok': False, 'health': {'message': 'La simulaci\u00f3n no prueba conectividad con una API.', 'reachable': False}})
                    target, _ = build_target(dict(config.get('target') or {}), authorization_confirmed=config.get('authorization_confirmed') is True)
                    if not isinstance(target, GenericJsonTarget):
                        raise ValueError('Usa el perfil API REST del Studio.')
                    health = target.connection_test()
                    token = None
                    if health['contract_valid']:
                        token = secrets.token_urlsafe(24)
                        with state.lock:
                            now = time.monotonic()
                            for k in list(verified):
                                if now - verified[k][1] > 300:
                                    del verified[k]
                            verified[token] = (target_fingerprint(config), now)
                    return self._json({'ok': health['contract_valid'], 'health': health, 'connection_token': token, 'valid_for_seconds': 300})
                if self.path == '/api/plan':
                    if not (config.get('selection') or {}).get('technique_ids'):
                        raise ValueError('Selecciona al menos una t\u00e9cnica; no se ejecutar\u00e1n t\u00e9cnicas por defecto.')
                    return self._json(build_campaign_plan(config).to_dict())
                if self.path == '/api/cancel':
                    state.cancel.set()
                    state.add_event({'type': 'cancel_requested', 'message': 'Se detendr\u00e1 al terminar la solicitud en curso.'})
                    return self._json({'ok': True})
                if self.path == '/api/run':
                    if not (config.get('selection') or {}).get('technique_ids'):
                        raise ValueError('Selecciona al menos una t\u00e9cnica.')
                    GeneratorConfig.from_dict(config.get("generator"))
                    plan = build_campaign_plan(config)
                    if not plan.seeds:
                        raise ValueError('La selecci\u00f3n no gener\u00f3 pruebas ejecutables.')
                    target_cfg = dict(config.get('target') or {})
                    if target_cfg.get('type') == 'fixture':
                        if config.get('simulation_confirmed') is not True:
                            raise ValueError('Confirma expl\u00edcitamente que deseas datos de simulaci\u00f3n.')
                    else:
                        target, _ = build_target(target_cfg, authorization_confirmed=config.get('authorization_confirmed') is True)
                        if not isinstance(target, GenericJsonTarget):
                            raise ValueError('Selecciona API REST.')
                        record = verified.get(str(config.get('connection_token', '')))
                        if not record or record[0] != target_fingerprint(config) or time.monotonic() - record[1] > 300:
                            raise ValueError('Primero prueba la conexi\u00f3n con esta configuraci\u00f3n. El test caduca a los 5 minutos y al cambiar el endpoint o el JSON.')
                    maximum = int((config.get('limits') or {}).get('max_requests', 80))
                    if not 1 <= maximum <= 5000:
                        raise ValueError('El l\u00edmite debe estar entre 1 y 5000 evaluaciones.')
                    with state.lock:
                        if state.state == 'running':
                            return self._error('Ya hay una campa\u00f1a en ejecuci\u00f3n.', 409)
                        job = f"campaign-{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(2)}"
                        output = runs_dir / job
                        state.reset_for_job(job, output, maximum)
                    threading.Thread(target=self._run_job, args=(config, output, job), daemon=True).start()
                    return self._json({'ok': True, 'job_id': job}, 202)
                self._error('Endpoint no encontrado.', 404)
            except (ValueError, TypeError, KeyError, OSError) as exc:
                self._error(str(exc))

        def _run_job(self, config, output, job):
            try:
                result = run_campaign(config, output_dir=output, event_callback=state.add_event, cancel_check=state.cancel.is_set)
                status = result['result']['status']
                url = f'/runs/{job}/report.html'
                state.add_event({'type': 'artifacts_ready', 'report_url': url})
                state.finish(url, status, result['result'].get('stop_reason', ''))
            except Exception as exc:
                state.fail(str(exc))
            finally:
                # Studio keys are transient: remove the only request-scoped copy as soon as the job ends.
                generator = (config.get('generator') or {}) if isinstance(config, dict) else {}
                if isinstance(generator, dict):
                    generator['api_key'] = ''

    server = ThreadingHTTPServer((host, port), Handler)
    url = f'http://{host}:{server.server_address[1]}/'
    print(f'Kyojitsu 3.8.1: {url}', flush=True)
    print('Ctrl+C para cerrar. API REST requiere test de conectividad.', flush=True)
    if open_browser:
        threading.Timer(.35, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever(poll_interval=.2)
    except KeyboardInterrupt:
        pass
    finally:
        state.cancel.set()
        server.server_close()
