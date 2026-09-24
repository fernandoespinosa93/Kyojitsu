"""Safe import and inspection helpers. Never execute pasted shell commands."""
from __future__ import annotations

import base64
import copy
import json
import re
import shlex
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SECRET_KEY = re.compile(r"(authorization|cookie|token|secret|password|passwd|api.?key|credential|signature)", re.I)
ENV = re.compile(r"\$\{ENV:[A-Za-z_][A-Za-z0-9_]*\}")


def safe_url(url: str) -> str:
    p = urlsplit(url)
    # No query values are needed in public provenance.
    return urlunsplit((p.scheme, p.netloc.split('@')[-1], p.path,
                       urlencode([(k, '[REDACTED]') for k, _ in parse_qsl(p.query, keep_blank_values=True)]), ''))


def string_paths(value: Any, prefix: str = '') -> list[str]:
    if isinstance(value, str):
        return [prefix] if prefix else []
    if isinstance(value, dict):
        return [p for k, v in value.items() for p in string_paths(v, f'{prefix}.{k}' if prefix else str(k))]
    if isinstance(value, list):
        return [p for i, v in enumerate(value) for p in string_paths(v, f'{prefix}.{i}' if prefix else str(i))]
    return []


def get_path(value: Any, path: str) -> Any:
    cur = value
    if not path:
        return None
    try:
        for key in path.split('.'):
            cur = cur[int(key)] if isinstance(cur, list) else cur[key]
        return cur
    except (KeyError, ValueError, IndexError, TypeError):
        return None


def normalize_path(path: str) -> str:
    """Accept common dot / JSONPath array notation, never evaluate expressions."""
    if not isinstance(path, str):
        raise ValueError('Escribe el nombre de un campo, por ejemplo question o messages.0.content.')
    path = path.strip()
    if len(path) > 200:
        raise ValueError('La ruta del campo es demasiado larga.')
    if len(path) > 1 and path[0] == path[-1] and path[0] in "\"'":
        path = path[1:-1].strip()
    if path.startswith('$.'):
        path = path[2:]
    path = re.sub(r'\[(\d+)\]', r'.\1', path)
    parts = path.split('.')
    if not path or len(parts) > 24 or any(not re.fullmatch(r'[\w-]+', x) for x in parts):
        raise ValueError('Usa el nombre del campo, no el texto de la pregunta ni un JSON. Ejemplos: question, input.text, messages.0.content.')
    if parts[0].isdigit() or any(x in {'__proto__', 'prototype', 'constructor'} for x in parts):
        raise ValueError('La ruta debe empezar por el nombre de un campo del objeto JSON.')
    if any(x.isdigit() and int(x) > 100 for x in parts):
        raise ValueError('El índice de una lista debe estar entre 0 y 100.')
    return '.'.join(parts)


def put_prompt(body: dict[str, Any], path: str) -> dict[str, Any]:
    """Create missing fields safely, move an old placeholder, keep other constants."""
    if not isinstance(body, dict):
        raise ValueError('El JSON de solicitud debe ser un objeto entre llaves.')
    path = normalize_path(path)
    result = copy.deepcopy(body)
    old_paths = [p for p in string_paths(result) if get_path(result, p) == '{{prompt}}' and p != path]
    cur: Any = result
    parts = path.split('.')
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        if isinstance(cur, list):
            if not part.isdigit():
                raise ValueError('Dentro de una lista usa un numero, por ejemplo messages.0.content.')
            key = int(part)
            while len(cur) <= key:
                cur.append(None)
        elif isinstance(cur, dict):
            key = part
        else:
            raise ValueError('La ruta atraviesa un campo de texto. Corrige el JSON o elige otra ruta.')
        previous = cur.get(key) if isinstance(cur, dict) else cur[key]
        if last:
            if previous is not None and not isinstance(previous, str):
                raise ValueError('El campo elegido es un objeto, lista o numero. Elige el campo que contiene texto.')
            cur[key] = '{{prompt}}'
        else:
            expected = list if parts[i+1].isdigit() else dict
            if previous is None:
                cur[key] = expected()
            elif not isinstance(previous, expected):
                raise ValueError('La estructura no coincide con la ruta. Usa, por ejemplo, messages.0.content para una lista.')
            cur = cur[key]
    for old in old_paths:
        parent = result
        oldparts = old.split('.')
        try:
            for key in oldparts[:-1]:
                parent = parent[int(key)] if isinstance(parent, list) else parent[key]
            key = int(oldparts[-1]) if isinstance(parent, list) else oldparts[-1]
            if parent[key] == '{{prompt}}':
                if isinstance(parent, dict):
                    del parent[key]
                else:
                    parent[key] = ''
        except (KeyError, IndexError, TypeError):
            pass
    return result


def redact_config(config: dict[str, Any]) -> dict[str, Any]:
    """Remove literal credentials, header values and imported body constants from exports."""
    def walk(value: Any, key: str = '') -> Any:
        if key in {'connection_token', 'curl', 'curl_command'}:
            return '[REDACTED]'
        if key == 'headers' and isinstance(value, dict):
            return {k: (v if k.lower() in {'accept', 'content-type'} or ENV.fullmatch(str(v)) else '[REDACTED]') for k, v in value.items()}
        if key in {'url', 'preflight_url'} and isinstance(value, str):
            return safe_url(value)
        if SECRET_KEY.search(key) and key not in {'secret_indicators', 'api_key_env'}:
            return '[REDACTED]'
        if isinstance(value, dict):
            return {k: walk(v, str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v, key) for v in value]
        return value
    clean = walk(copy.deepcopy(config))
    clean.pop('connection_token', None)
    profile = clean.get('target', {}).get('profile', {})
    # An arbitrary field can carry a credential. Imported non-prompt constants are private.
    def scrub_body(v: Any) -> Any:
        if isinstance(v, dict):
            return {k: scrub_body(x) for k, x in v.items()}
        if isinstance(v, list):
            return [scrub_body(x) for x in v]
        if isinstance(v, str):
            return '{{prompt}}' if '{{prompt}}' in v else '[REDACTED]'
        return v
    if 'body_template' in profile:
        profile['body_template'] = scrub_body(profile['body_template'])
    return clean


def credential_values(profile: Any) -> set[str]:
    """Known credentials for redaction of reflected responses and transport errors."""
    from .targets import _resolve_env
    values: set[str] = set()
    for k, v in profile.headers.items():
        if k.lower() not in {'accept', 'content-type', 'user-agent'}:
            s = _resolve_env(v)
            values.add(s)
            if k.lower() == 'authorization' and ' ' in s:
                values.add(s.split(' ', 1)[1])
    def find(v: Any, key: str = '') -> None:
        if isinstance(v, dict):
            for k, x in v.items():
                find(x, k)
        elif isinstance(v, list):
            for x in v:
                find(x, key)
        elif isinstance(v, str) and SECRET_KEY.search(key):
            values.add(_resolve_env(v))
    find(profile.body_template)
    for _, v in parse_qsl(urlsplit(profile.url).query):
        if v:
            values.add(v)
    return {s for s in values if s and s != '{{prompt}}'}


def redact_text(text: str, secrets: set[str]) -> str:
    for value in sorted(secrets, key=len, reverse=True):
        text = text.replace(value, '[REDACTED]')
    return text


def import_curl(command: str, prompt_path: str | None = None) -> dict[str, Any]:
    if not isinstance(command, str) or not command.strip() or len(command) > 200_000:
        raise ValueError('Pega un comando cURL de hasta 200 KB.')
    # Bash, PowerShell and cmd multiline continuations (not shell evaluation).
    normalized = re.sub(r'(?:\\|`|\^)\r?\n', ' ', command.strip())
    try:
        lex = shlex.shlex(normalized, posix=True, punctuation_chars=';&|<>')
        lex.whitespace_split = True
        lex.commenters = ''
        tokens = list(lex)
    except ValueError as exc:
        raise ValueError('No se pudo leer cURL. Revisa comillas; usa Copiar como cURL (bash).') from exc
    if not tokens or tokens.pop(0).lower() not in {'curl', 'curl.exe'}:
        raise ValueError('El texto debe empezar con curl o curl.exe.')
    url = None
    method = None
    headers: dict[str, str] = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    data = None
    warnings: list[str] = []
    flags = {'-X', '--request', '-H', '--header', '-d', '--data', '--data-raw', '--data-binary', '--json', '--url', '-u', '--user', '--oauth2-bearer', '-b', '--cookie'}
    i = 0
    while i < len(tokens):
        token = tokens[i]
        i += 1
        if token in {'-s', '--silent', '-S', '--show-error', '--compressed', '-L', '--location'}:
            if token in {'-L', '--location'}:
                warnings.append('No se seguir\u00e1n redirecciones: usa la URL final para no reenviar credenciales a otro destino.')
            continue
        if token in {'-k', '--insecure'}:
            raise ValueError('No se importa --insecure. Usa HTTPS con certificado v\u00e1lido o HTTP solo en tu laboratorio local.')
        value = None
        if token.startswith('--') and '=' in token:
            token, value = token.split('=', 1)
        elif len(token) > 2 and token[:2] in {'-H', '-X', '-d', '-u', '-b'}:
            token, value = token[:2], token[2:]
        if token in flags:
            if value is None:
                if i >= len(tokens):
                    raise ValueError(f'Falta el valor de {token}.')
                value = tokens[i]
                i += 1
            if token in {'-H', '--header'}:
                if value.startswith('@') or ':' not in value or '\n' in value or '\r' in value:
                    raise ValueError('Cada header debe ser Nombre: valor, sin archivos ni saltos de l\u00ednea.')
                k, v = value.split(':', 1)
                k, v = k.strip(), v.strip()
                if k.lower() in {'host', 'content-length', 'connection', 'transfer-encoding'}:
                    warnings.append(f'Header {k} omitido: lo calcula el cliente HTTP.')
                else:
                    for old in list(headers):
                        if old.lower() == k.lower():
                            del headers[old]
                    headers[k] = v
            elif token in {'-X', '--request'}:
                method = value.upper()
            elif token == '--url':
                if url:
                    raise ValueError('Solo se admite una URL por importaci\u00f3n.')
                url = value
            elif token in {'-u', '--user'}:
                if ':' not in value:
                    raise ValueError('Basic auth requiere usuario:contrase\u00f1a; no se pueden solicitar credenciales interactivamente.')
                headers['Authorization'] = 'Basic ' + base64.b64encode(value.encode()).decode()
            elif token == '--oauth2-bearer':
                headers['Authorization'] = 'Bearer ' + value
            elif token in {'-b', '--cookie'}:
                if '=' not in value or value.startswith('@'):
                    raise ValueError('Solo se admiten cookies literales, no archivos de cookies.')
                headers['Cookie'] = value
            else:
                if data is not None:
                    raise ValueError('Usa un solo body JSON; no se concatenan varios --data.')
                if value.startswith('@') and token != '--data-raw':
                    raise ValueError('No se leen archivos @archivo. Pega el JSON directamente.')
                data = value
        elif token.startswith('http://') or token.startswith('https://'):
            if url:
                raise ValueError('Solo se admite una URL por importaci\u00f3n.')
            url = token
        else:
            raise ValueError(f'Opci\u00f3n no admitida: {token[:60]}. Se cancela la importaci\u00f3n; no se ejecuta el comando.')
    if not url:
        raise ValueError('No se encontr\u00f3 una URL http:// o https://.')
    p = urlsplit(url)
    if p.username or p.password or not p.hostname:
        raise ValueError('Usa autenticaci\u00f3n en headers o -u, no dentro de la URL.')
    method = method or ('POST' if data is not None else 'GET')
    if method not in {'POST', 'PUT', 'PATCH'}:
        raise ValueError('Este adaptador prueba API REST JSON con POST, PUT o PATCH. Configura el endpoint que recibe el prompt, no una URL de salud GET.')
    try:
        body = json.loads(data or '{}')
    except json.JSONDecodeError as exc:
        raise ValueError('El body del cURL debe ser JSON. Formularios y multipart requieren otro adaptador.') from exc
    if not isinstance(body, dict):
        raise ValueError('El body JSON debe ser un objeto.')
    paths = string_paths(body)
    explicit = [p for p in paths if '{{prompt}}' in str(get_path(body, p))]
    detected = prompt_path
    if not detected and len(explicit) == 1:
        detected = explicit[0]
    if not detected:
        priorities = ['prompt', 'query', 'question', 'input', 'text', 'message']
        matches = [p for p in paths if p.split('.')[-1].lower() in priorities]
        users = [p for p in paths if p.endswith('.content') and get_path(body, p.rsplit('.', 1)[0] + '.role') == 'user']
        if users:
            detected = users[-1]
        elif len(matches) == 1:
            detected = matches[0]
    template = put_prompt(body, detected) if detected else body
    if not detected:
        warnings.append('No se pudo elegir un campo de prompt sin ambig\u00fcedad. Selecciona la ruta y vuelve a aplicar el campo.')
    return {
        'profile': {'name': 'API REST', 'url': url, 'method': method, 'headers': headers,
                    'body_template': template, 'response': {'answer_path': 'answer', 'blocked_path': None, 'stage_path': None},
                    'blocked_http_statuses': [], 'timeout_seconds': 30},
        'original_body': body, 'prompt_paths': paths, 'prompt_path': detected,
        'warnings': warnings, 'executed': False,
    }
