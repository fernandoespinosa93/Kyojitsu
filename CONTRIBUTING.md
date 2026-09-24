# Contribuir a Kyojitsu

Gracias por mejorar Kyojitsu. Antes de tocar el código, lee `AGENTS.md` y `docs/ARCHITECTURE.md`.

## Flujo recomendado

1. Crea una rama desde `main`.
2. Mantén cada PR enfocada en un problema o feature.
3. Añade o actualiza pruebas.
4. Ejecuta la suite local.
5. Describe en el PR qué cambia, cómo probarlo y qué riesgos tiene.

## Preparar entorno

```bash
python -m venv .venv
# activa el entorno
pip install -e .
pip install pytest
```

Para QA de navegador:

```bash
pip install playwright
playwright install chromium
```

## Validación mínima

```bash
python -m compileall src/kyojitsu
node --check src/kyojitsu/web/studio.js
node --check src/kyojitsu/web/report.js
PYTHONPATH=src pytest -q
```

## Estilo

- Python 3.11+.
- Evita dependencias innecesarias; el runtime base está diseñado para usar principalmente stdlib.
- Mantén mensajes de usuario en español claro, con acentos correctos.
- No introduzcas términos técnicos sin explicación cuando aparezcan en la UI.
- No añadas efectos visuales que oculten evidencia o estados.

## Seguridad

- Nunca incluyas claves reales en fixtures o tests.
- Usa servidores fake/locales para contratos de proveedores.
- No cambies el comportamiento de autorización/preflight sin pruebas específicas.
- No reduzcas redacción de secretos para facilitar debugging.

## UI y reportes

- El Studio y el reporte deben funcionar en desktop, tablet y móvil.
- Respeta `prefers-reduced-motion`.
- Si modificas `report.js/css/html`, regenera un reporte standalone y pruébalo, no solo los archivos fuente.
- Si modificas el wizard, valida pasos siguiente/atrás y navegación lateral.

## Pull Requests

Incluye:

- **Motivación**
- **Cambios**
- **Cómo probar**
- **Capturas** si cambia UI
- **Riesgos / compatibilidad**
- **Checklist de seguridad** cuando afecte red, credenciales, clasificación o almacenamiento
