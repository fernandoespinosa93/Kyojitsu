# Arquitectura técnica de Kyojitsu

## 1. Resumen

Kyojitsu es una aplicación Python local con frontend HTML/CSS/JavaScript embebido. El motor utiliza SQLite como registro auditable y genera artefactos estáticos por campaña.

No existe un backend JavaScript ni un framework SPA. El servidor de Studio usa `http.server.ThreadingHTTPServer` y la mayor parte del runtime depende solo de la biblioteca estándar de Python.

## 2. Componentes

```text
┌───────────────────────────────┐
│ Studio web (localhost)        │
│ studio.html/css/js            │
└───────────────┬───────────────┘
                │ JSON interno
                ▼
┌───────────────────────────────┐
│ studio.py / runner.py         │
│ validación + campaña          │
└───────┬───────────────┬───────┘
        │               │
        ▼               ▼
  planner.py       generator.py
  frameworks.py    LLM opcional
        │               │
        └───────┬───────┘
                ▼
          engine.py
       G0 → G1 → ... Gn
                │
        ┌───────┴────────┐
        ▼                ▼
    targets.py       storage.py
    API evaluada     SQLite
        │                │
        └───────┬────────┘
                ▼
        assessment.py
        reporting.py
        executive_pdf.py
                │
                ▼
 report.html / PDF / JSON / CSV
```

## 3. Planificación

`planner.py` recibe:

- frameworks;
- categorías;
- técnicas;
- número de semillas por técnica;
- controles benignos;
- indicadores ficticios opcionales.

Genera un `PlanResult` con seeds y mappings. `frameworks.py` contiene el catálogo y los crosswalks de técnicas.

El planner no hace llamadas al target.

## 4. Generación

### Reglas locales

`mutations.py` implementa operadores deterministas/estocásticos sobre texto. `AdaptiveMutationPolicy` ajusta la selección de operadores a partir de resultados previos.

### LLM generador

`generator.py` implementa:

- configuración y validación;
- discovery de modelos;
- contratos Anthropic/Gemini/OpenAI-compatible;
- preflight;
- generación de variantes;
- parsing y límites;
- redacción de secretos en errores.

La API del generador es independiente de la API evaluada.

## 5. Motor evolutivo

`engine.EvolutionEngine.run()`:

1. crea run y guarda seeds;
2. selecciona población inicial;
3. opcionalmente solicita variantes iniciales al LLM;
4. evalúa G0;
5. calcula fitness;
6. marca élite;
7. registra snapshot de operadores;
8. produce nueva población;
9. repite hasta Gn, cancelación o límite.

Los controles benignos se miden, pero nunca se usan como padres para optimizar la búsqueda adversarial.

## 6. Target y clasificación

`targets.py` contiene:

- `GenericJsonTarget` para APIs REST configurables;
- `IkigaiHttpTarget` por compatibilidad;
- `DeterministicFixtureTarget` para simulación.

`GenericTargetProfile` describe URL, método, headers, body, prompt path, answer path y señales opcionales.

La clasificación separa evidencia estructurada de heurísticas textuales. Un texto tipo “blocked by guardrails” no se eleva automáticamente a telemetría estructurada.

## 7. Scoring

`scoring.py` combina las señales observadas en un fitness utilizado para selección. El fitness sirve para orientar la búsqueda; no es una probabilidad de compromiso ni un score de cumplimiento.

`similarity.py` usa una aproximación léxica. No es un embedding neuronal.

## 8. Persistencia

`storage.RunStore` usa SQLite.

Registra, entre otros:

- metadatos del run;
- seeds;
- candidatos;
- padres/raíces;
- outcomes;
- respuestas;
- latencias;
- HTTP status;
- fitness;
- selección;
- snapshots de operadores;
- revisiones humanas.

SQLite es la fuente de verdad para regenerar reportes.

## 9. Assessment

`assessment.py` calcula métricas y resultados de la muestra. Mantiene separados:

- bloqueos explícitos;
- ataques confirmados;
- casos pendientes;
- errores;
- controles benignos.

Los mappings por framework pueden solaparse; las filas de categorías no deben sumarse como si fueran poblaciones disjuntas.

## 10. Reporting

`reporting.py` construye un summary público a partir de SQLite y exporta:

- JSON;
- CSV;
- Markdown;
- HTML;
- assessment.

`report_ui.py` lee `web/report.html/css/js` y produce un HTML standalone con datos embebidos.

`executive_pdf.py` genera el PDF ejecutivo sin depender del navegador.

## 11. Animaciones del reporte

Las animaciones principales están en `web/report.js`:

- dona: Web Animations sobre `strokeDasharray`;
- barras: `scaleX` sobre rectángulos SVG;
- tendencia: longitud real de paths con `getTotalLength()`;
- lineage: `playOriginStory()` controla explícitamente la historia G0 → Gn.

El grafo de origen no depende de una animación CSS para su narrativa. JS oculta la escena, revela G0, dibuja edges a la siguiente generación y crea sus nodos con stagger.

## 12. Studio

`studio.py` sirve la aplicación solo en localhost por defecto y expone endpoints internos:

- `/api/catalog`
- `/api/status`
- `/api/import-curl`
- `/api/generator-models`
- `/api/test-generator`
- `/api/prompt-path`
- `/api/test-target`
- `/api/preflight`
- `/api/plan`
- `/api/run`
- `/api/cancel`

Las rutas `/runs/<job>/<artifact>` están restringidas a una lista de artefactos permitidos.

## 13. Seguridad de credenciales

Los headers del target pueden contener secretos necesarios para las solicitudes. Los valores se redactan en previews/reportes.

La API key del generador se guarda únicamente en la configuración en memoria de la campaña y se limpia al terminar el trabajo.

Cualquier cambio en esta lógica debe tener tests de no persistencia.

## 14. Extensibilidad

Puntos de extensión principales:

- nuevos targets: implementar `Target`;
- nuevos proveedores: ampliar `generator.py`;
- nuevas técnicas: `frameworks.py` + seeds;
- nuevas mutaciones: `mutations.py`;
- nuevas métricas: `assessment.py`;
- nuevas visualizaciones: `web/report.*`;
- nuevos artefactos: `reporting.py`.

Antes de modificar uno de estos puntos, lee `AGENTS.md`.
