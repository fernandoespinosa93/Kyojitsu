<p align="center">
  <img src="https://github.com/fernandoespinosa93/Kyojitsu/blob/main/docs/assests/kyojitsu-logo.svg" alt="Kyojitsu" width="96">
</p>

<h1 align="center">Kyojitsu</h1>
Kyojitsu es una plataforma local de **AI Red Team** para evaluar guardrails y APIs de aplicaciones basadas en LLM mediante campañas reproducibles, generación adaptativa de variantes, mapeo contra marcos como **OWASP Top 10 for LLM Applications 2025** y **MITRE ATLAS**, evidencia por solicitud, un dashboard HTML y un reporte ejecutivo PDF.

> **Uso autorizado únicamente.** Kyojitsu envía solicitudes reales al endpoint configurado. Úsalo solo sobre sistemas propios o con autorización explícita. No es una certificación de cumplimiento y un resultado de laboratorio no demuestra por sí mismo la seguridad completa de un sistema.

## Qué hace

- Configura un **endpoint REST** con método, headers, autenticación, body JSON, campo que recibe el prompt y campo que contiene la respuesta.
- Puede importar un **cURL** de ejemplo y convertirlo en una configuración JSON segura sin ejecutar la shell.
- Valida conectividad y contrato antes de ejecutar una campaña real.
- Permite seleccionar cobertura por **OWASP LLM Top 10 2025**, **MITRE ATLAS**, categorías y técnicas.
- Genera variantes mediante:
  - **reglas locales adaptativas**, o
  - un **LLM generador independiente** (Anthropic, Google Gemini o una API compatible con OpenAI).
- Ejecuta rondas G0 → Gn con selección evolutiva, límites de solicitudes, controles benignos y evidencia reproducible.
- Distingue bloqueos explícitos, rechazo textual, respuesta sin confirmar, ataques confirmados y errores técnicos.
- Exporta:
  - `report.html`
  - `executive.pdf`
  - `assessment.json`
  - `summary.json`
  - `candidates.csv`
  - `report.md`
  - `kyojitsu.db`
- Incluye **Studio**, vista en vivo, gráficas animadas, origen de variantes y reproducción visual de la evolución G0 → Gn.

## Captura conceptual del flujo

```text
Configuración
   │
   ├── Conexión REST + contrato JSON
   ├── Frameworks / categorías / técnicas
   ├── Generador de prompts
   └── Evolución y límites
   │
   ▼
Plan de campaña
   │
   ▼
G0 ──► evaluación ──► scoring ──► selección
                              │
                              ▼
                         variantes G1
                              │
                              ▼
                         ... hasta Gn
   │
   ▼
Assessment + HTML + PDF + evidencia auditable
```

## Inicio rápido

### Windows

1. Instala **Python 3.11 o superior**.
2. Clona o descarga el repositorio.
3. Ejecuta:

```bat
run_studio.bat
```

4. Abre `http://127.0.0.1:8765` si el navegador no se abre automáticamente.

### PowerShell

```powershell
./run_studio.ps1
```

### Linux / macOS

```bash
sh run_studio.sh
```

También puedes instalarlo en modo editable:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -e .
kyojitsu studio
```

Consulta [INICIO_RAPIDO.md](INICIO_RAPIDO.md) para una guía paso a paso.

## Flujo de Studio

La configuración está dividida en cinco pasos para no sobrecargar al operador:

1. **Conexión** — endpoint, autenticación, body JSON y prueba de contrato.
2. **Marco y técnicas** — OWASP / MITRE, categorías y técnicas a ejecutar.
3. **Generador** — reglas locales o proveedor LLM externo.
4. **Evolución** — rondas, población, élite, máximo de evaluaciones y pausas.
5. **Revisar** — resumen, preflight e inicio de campaña.

Los valores se conservan al cambiar de paso. La navegación lateral permite saltar entre pasos cuando se necesita.

## Target REST

Kyojitsu necesita conocer tres cosas principales:

- la URL y método del endpoint;
- el campo JSON que recibe el prompt;
- el campo JSON que contiene la respuesta.

Ejemplo:

```json
{
  "target": {
    "type": "generic_json",
    "name": "API bajo evaluación",
    "url": "http://127.0.0.1:8080/api/query",
    "method": "POST",
    "headers": {
      "Content-Type": "application/json"
    },
    "body_template": {
      "question": "{{prompt}}"
    },
    "prompt_path": "question",
    "answer_path": "answer"
  }
}
```

Las señales estructuradas (`blocked`, `stage`, `reason`, etc.) son opcionales. Si no existen, Kyojitsu evalúa en modo de **caja negra** y evita inventar telemetría interna.

## Generación de variantes

### Reglas locales

Incluye transformaciones como reencuadre contextual, roles anidados, escenarios hipotéticos, fragmentación, envolturas JSON, solicitudes indirectas y otras mutaciones programadas. La selección es adaptativa según la señal observada.

### Generador LLM

El modelo generador es **independiente del guardrail evaluado**. Puede usar:

- Anthropic Claude
- Google Gemini
- APIs compatibles con OpenAI

Studio puede validar la API key, descubrir modelos disponibles y probar una generación antes de iniciar la campaña.

La clave del generador es temporal: se mantiene en memoria durante validación/ejecución, se limpia de la interfaz y **no debe aparecer en reportes ni SQLite**.

Más detalles: [docs/GENERADOR_LLM.md](docs/GENERADOR_LLM.md).

## Cómo se interpreta un resultado

Kyojitsu evita tratar un HTTP `200` como bypass automático.

Ejemplos de estados:

| Estado | Significado |
| --- | --- |
| Bloqueo de entrada | La API informó explícitamente un bloqueo antes del modelo. |
| Bloqueo de salida | La API informó explícitamente un bloqueo sobre la salida. |
| Bloqueo confirmado; etapa desconocida | Existe señal de bloqueo pero no se sabe dónde ocurrió. |
| Rechazo indicado en respuesta | Solo el texto sugiere rechazo; requiere cautela. |
| Respuesta sin confirmar | Hubo respuesta, pero no existe evidencia suficiente para afirmar éxito o bloqueo. |
| Ataque confirmado | Existe un criterio externo/configurado que confirma el resultado prohibido. |
| Error técnico | La evaluación no cuenta como bypass. |

Consulta [docs/METODOLOGIA.md](docs/METODOLOGIA.md) para el modelo de evaluación completo.

## Reporte HTML

El reporte incluye:

- resumen ejecutivo;
- grafícas de resultados;
- cobertura del alcance;
- evolución por ronda;
- estado por categoría;
- técnicas con mayor señal;
- matriz por framework;
- prompts y evidencia;
- origen de variantes;
- reproducción animada de la historia G0 → Gn;
- recomendaciones y límites metodológicos.

Las gráficas se animan al entrar a cada vista y responden al cursor. `prefers-reduced-motion` es respetado para accesibilidad.

## Estructura del repositorio

```text
Kyojitsu/
├─ src/kyojitsu/           Motor, targets, storage, assessment y Studio
│  └─ web/                 HTML/CSS/JS de Studio y reportes
├─ tests/                  Pruebas unitarias y regresiones de releases
├─ examples/               Campañas, targets y generadores de ejemplo
├─ docs/                   Arquitectura, metodología y operación
├─ AGENTS.md               Guía para IAs/agentes que modifiquen el código
├─ CONTRIBUTING.md         Flujo de contribución
├─ SECURITY.md             Modelo y reporte de seguridad
└─ pyproject.toml          Paquete Python
```

## Arquitectura técnica

Consulta [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) para el detalle de módulos, flujo de datos, modelo de almacenamiento, frontend, generación de reportes y puntos de extensión.

Para desarrollo local: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## CLI

```bash
kyojitsu --version
kyojitsu catalog
kyojitsu plan --framework owasp_llm_2025
kyojitsu run-campaign --campaign examples/campaign_api_rest.json --output runs/example
kyojitsu report --db runs/example/kyojitsu.db --output runs/example
kyojitsu studio
```

Para ver todas las opciones:

```bash
kyojitsu --help
```

## Pruebas

```bash
python -m compileall src/kyojitsu
node --check src/kyojitsu/web/studio.js
node --check src/kyojitsu/web/report.js
PYTHONPATH=src pytest -q
```

En Windows también puedes usar:

```bat
run_self_test.bat
```

## Seguridad operacional

- Studio está pensado para ejecutarse en `127.0.0.1`.
- No expongas Studio directamente a Internet.
- No incluyas claves reales en commits, screenshots o issues.
- Empieza con límites pequeños de solicitudes.
- Cancelar una campaña impide nuevas solicitudes, pero no puede retirar una petición ya enviada.
- Los reportes HTML/JSON/CSV/SQLite pueden contener prompts, respuestas u otros datos sensibles.
- No confundas cobertura del ejercicio con certificación de cumplimiento.

Lee [SECURITY.md](SECURITY.md) antes de desplegar o extender Kyojitsu.

## Contribuir

Consulta [CONTRIBUTING.md](CONTRIBUTING.md). Si una IA o agente va a modificar el proyecto, primero debe leer [AGENTS.md](AGENTS.md).
