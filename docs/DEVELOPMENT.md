# Desarrollo de Kyojitsu

## Requisitos

- Python 3.11+
- Node.js solo para `node --check` durante desarrollo/CI
- pytest para tests
- Playwright opcional para QA visual

## Instalación editable

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
pip install pytest
```

## Ejecutar Studio

```bash
kyojitsu studio --port 8765
```

O usa los launchers `run_studio.*`.

## Ejecutar fixture local

```bash
python examples/mock_guardrail_server.py
```

Consulta `examples/` para campañas y perfiles.

## Tests

```bash
PYTHONPATH=src pytest -q
```

Sintaxis frontend:

```bash
node --check src/kyojitsu/web/studio.js
node --check src/kyojitsu/web/report.js
```

Compilación Python:

```bash
python -m compileall src/kyojitsu
```

## QA de navegador

Instala:

```bash
pip install playwright
playwright install chromium
```

Los scripts viven en `qa/`. El QA debe verificar, al menos:

- wizard siguiente/atrás;
- campaña fixture pequeña;
- animación de charts al cambiar de ruta;
- historia G0 → Gn al pulsar Reproducir;
- responsive desktop/tablet/móvil;
- cero `pageerror`.

## Reportes standalone

No pruebes únicamente `report.js` de forma aislada. Genera una campaña y abre el `report.html` exportado, porque la exportación embebe datos, CSS y JS.

## Regenerar demo

```bash
run_demo.bat
```

O usa el equivalente `.ps1`.

## Versionado

Para una release patch:

1. actualiza `pyproject.toml`;
2. actualiza `src/kyojitsu/__init__.py`;
3. actualiza versión visible en Studio/reporte;
4. actualiza `CHANGELOG.md`;
5. ejecuta tests + QA;
6. limpia caches y outputs reales;
7. crea ZIP/release.

## Git hygiene

Antes del commit:

```bash
git status
git diff --check
```

No añadas `runs/`, `*.db`, `.env`, caches o claves.
