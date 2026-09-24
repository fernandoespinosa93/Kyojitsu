# AGENTS.md — Guía para agentes e IAs que trabajen en Kyojitsu

Este archivo es el punto de entrada para cualquier IA, agente de código o nuevo mantenedor que necesite modificar Kyojitsu sin romper sus invariantes de seguridad o de evidencia.

## 1. Propósito del proyecto

Kyojitsu ejecuta campañas autorizadas de AI Red Team contra un endpoint REST que representa una aplicación/guardrail de LLM. Genera variantes, ejecuta solicitudes, guarda evidencia, calcula métricas, mapea técnicas a frameworks y genera reportes.

No es un proxy de producción, no es un servicio multiusuario y no es una certificación automática de cumplimiento.

## 2. Invariantes que NO debes romper

1. **No inventar resultados.** Si el endpoint no responde, no debe generarse un assessment como si la campaña hubiese sido ejecutada correctamente.
2. **HTTP 200 no equivale a bypass.** La clasificación depende de señales observables, criterio externo o revisión.
3. **No inferir una etapa de bloqueo inexistente.** `blocked=true` sin `stage` significa etapa desconocida.
4. **Target y generador son conexiones distintas.** El LLM que crea variantes nunca debe confundirse con la API evaluada.
5. **No fallback silencioso.** Si el generador LLM falla, la campaña no debe cambiar a reglas locales sin avisar.
6. **Claves temporales.** Las API keys del generador no deben persistirse en SQLite, JSON, HTML, PDF o logs.
7. **Autorización explícita.** Las campañas reales requieren confirmación del operador y un preflight válido.
8. **No ejecutar cURL.** El importador solo analiza texto; jamás debe invocar shell.
9. **Preservar trazabilidad.** Cada candidato debe conservar generación, técnica, operador, parent/root seed y evidencia.
10. **No llamar “cumplimiento” a cobertura.** OWASP/MITRE estructuran el assessment, no certifican un producto.

## 3. Mapa del código

- `src/kyojitsu/engine.py` — loop evolutivo G0 → Gn, selección de élite, eventos.
- `src/kyojitsu/planner.py` — construye el plan a partir de frameworks/técnicas.
- `src/kyojitsu/frameworks.py` — catálogo OWASP/MITRE y crosswalks.
- `src/kyojitsu/generator.py` — Anthropic/Gemini/OpenAI-compatible, discovery y generación.
- `src/kyojitsu/mutations.py` — mutaciones locales y política adaptativa.
- `src/kyojitsu/targets.py` — contratos REST, clasificación observable y fixture.
- `src/kyojitsu/scoring.py` — fitness de candidatos.
- `src/kyojitsu/storage.py` — SQLite y evidencia auditable.
- `src/kyojitsu/assessment.py` — métricas, estados y recomendaciones.
- `src/kyojitsu/reporting.py` — summary, HTML, CSV, Markdown y assessment.
- `src/kyojitsu/executive_pdf.py` — PDF ejecutivo.
- `src/kyojitsu/studio.py` — servidor localhost y endpoints internos del Studio.
- `src/kyojitsu/web/studio.*` — UI de configuración/ejecución.
- `src/kyojitsu/web/report.*` — dashboard HTML y animaciones.

## 4. Frontend: reglas importantes

### Studio

- El wizard debe conservar cinco pasos: Conexión, Marco y técnicas, Generador, Evolución y Revisar.
- Las configuraciones no deben resetearse al avanzar/retroceder.
- Los paneles de cada paso deben usar todo el ancho disponible antes de `Revisar`.
- La vista debe permanecer responsive sin scroll horizontal a nivel documento.

### Reporte

- El HTML generado es standalone: CSS y JS se incrustan al exportar.
- Las gráficas deben volver a animarse al navegar entre vistas.
- `Origen de los casos` conserva fondo punteado oscuro.
- Al pulsar **Reproducir**, el grafo debe narrar G0 → Gn: ocultar escena, revelar G0, trazar relaciones a G1, revelar sus nodos, repetir hasta Gn y después reproducir casos.
- La animación de lineage está orquestada en JS con `Element.animate()` y `getTotalLength()`. No la sustituyas por una animación CSS instantánea.
- Respeta `prefers-reduced-motion`.

## 5. Cómo añadir una técnica

1. Añade el `TechniqueSpec` y mappings en `frameworks.py`.
2. Define semillas/plantillas y capacidad requerida.
3. Si necesita una mutación local nueva, añádela en `mutations.py` y registra el operador.
4. Añade pruebas para el catálogo/plan.
5. Verifica que reportes y assessment muestren el nuevo mapping sin duplicar conteos globales.

## 6. Cómo añadir un proveedor LLM

1. Amplía `GeneratorConfig` y validación en `generator.py`.
2. Implementa discovery de modelos si el proveedor lo soporta.
3. Implementa un parser estricto de salida.
4. Redacta secretos en errores.
5. Añade preflight y pruebas con servidor local/fake. No uses claves reales en tests.
6. Añade documentación en `docs/GENERADOR_LLM.md`.

## 7. Cómo añadir una señal del guardrail

1. Amplía el perfil en `targets.py`.
2. Define semántica explícita: tipo, ruta JSON y cómo afecta outcome.
3. No conviertas texto heurístico en señal estructurada.
4. Añade casos contradictorios y faltantes en tests.
5. Actualiza assessment/reportes si la señal cambia denominadores.

## 8. Comandos obligatorios antes de entregar

```bash
python -m compileall src/kyojitsu
node --check src/kyojitsu/web/studio.js
node --check src/kyojitsu/web/report.js
PYTHONPATH=src pytest -q
```

Para cambios de UI/animaciones, ejecuta además el QA Playwright de la release correspondiente en `qa/`.

## 9. Archivos generados

No edites manualmente un `runs/<campaign>/report.html` pensando que eso cambia futuros reportes. El origen está en:

- `src/kyojitsu/web/report.html`
- `src/kyojitsu/web/report.css`
- `src/kyojitsu/web/report.js`

Después regenera una campaña/demo para validar el HTML standalone.

## 10. Compatibilidad y versiones

Al preparar una release:

- incrementa versión en `pyproject.toml`;
- actualiza `src/kyojitsu/__init__.py`;
- actualiza versión visible en `studio.html` y `report.html`;
- actualiza `studio.py`/User-Agent del generador si corresponde;
- añade entrada en `CHANGELOG.md`;
- regenera `BUILD_INFO.txt` y QA.

## 11. Qué NO commitear

- `.env`
- claves o tokens
- `runs/` reales
- archivos `*.db`
- `__pycache__/`
- `.pytest_cache/`
- screenshots con secretos

## 12. Criterio de finalización

Un cambio no está terminado solo porque “se ve bien”. Debe:

- preservar evidencia y clasificación;
- pasar tests;
- no filtrar secretos;
- funcionar sin Internet salvo las APIs explícitamente configuradas;
- degradar con claridad cuando falta telemetría;
- ser responsive y accesible;
- dejar documentación suficiente para el siguiente mantenedor.
