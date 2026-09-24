# Generador de prompts con LLM

## Dos conexiones distintas

Kyojitsu separa el sistema que **se evalúa** del modelo que **crea nuevas variantes de prueba**.

- **API evaluada:** recibe los prompts y devuelve la respuesta del guardrail o de la aplicación.
- **Generador:** escribe variantes nuevas para las técnicas seleccionadas y utiliza resultados resumidos de rondas anteriores como retroalimentación.

La URL, la autenticación y los límites de ambas conexiones son independientes. Conectar Ikigai o cualquier otra API como objetivo no configura automáticamente un generador de IA.

El modo predeterminado es **Reglas locales adaptativas**, que no envía datos a proveedores externos. Si quieres que un LLM escriba variantes nuevas, selecciona un proveedor en **Generador de prompts**.

## Clave temporal

La clave se pega en **Clave temporal del proveedor**. Kyojitsu la usa en memoria para validar el proveedor, descubrir modelos y ejecutar la campaña. Al iniciar la campaña, el campo se limpia de la interfaz y la copia que conserva el proceso se elimina al finalizar.

La clave no se escribe en `campaign.json`, `summary.json`, `assessment.json`, CSV, Markdown, HTML, PDF ni SQLite. Tampoco se muestra completa en el Log. Si cierras Studio, tendrás que introducirla de nuevo.

No pegues claves en capturas, documentación o chats.

## Anthropic Claude

Kyojitsu usa los endpoints oficiales:

- Generación: `https://api.anthropic.com/v1/messages`
- Modelos: `https://api.anthropic.com/v1/models`

Pulsa **Validar clave y cargar modelos**. Si la credencial es válida, Kyojitsu consulta el catálogo disponible para esa cuenta y carga los modelos que devuelve Anthropic. Después elige uno y pulsa **Probar generación**.

## Google Gemini

Kyojitsu usa la interfaz REST actual de Gemini:

- Generación: `https://generativelanguage.googleapis.com/v1beta/interactions`
- Modelos: `https://generativelanguage.googleapis.com/v1beta/models`

La clave se envía mediante `x-goog-api-key`. Kyojitsu muestra modelos disponibles para la credencial y filtra los que declaran capacidad de generación de contenido.

El código conserva compatibilidad de laboratorio con el contrato antiguo `models/{modelo}:generateContent`, pero Studio utiliza **Interactions API** para configuraciones nuevas.

## API compatible con OpenAI

Para OpenAI o un servidor compatible con Chat Completions, la URL habitual es:

`https://api.openai.com/v1/chat/completions`

Kyojitsu intenta obtener el catálogo desde el endpoint `/v1/models` derivado de esa URL. En servidores compatibles, la disponibilidad y los parámetros admitidos dependen del proveedor; **Probar generación** confirma el contrato antes de ejecutar.

## Qué se comparte con el generador

Tras tu confirmación, Kyojitsu puede enviar al generador:

- objetivo de prueba;
- técnica seleccionada;
- texto base sanitizado;
- transformación solicitada;
- resultado resumido de intentos anteriores.

No necesita enviar las credenciales de la API evaluada. Evita usar secretos reales, datos personales o contenido de producción que no esté autorizado para salir de tu entorno.

El generador debe devolver una lista JSON de variantes. Kyojitsu valida formato, longitud y duplicados; registra procedencia, modelo, latencia y huellas de los contextos y salidas. Si el proveedor falla o devuelve un contrato inválido, la campaña registra el fallo: **no cambia silenciosamente a reglas locales**.

## Qué significa «evolutivo»

En **Reglas locales**, el motor aplica transformaciones programadas y cambia su selección según los resultados. En **Generador LLM**, el modelo produce nuevas redacciones utilizando el objetivo, la técnica y retroalimentación de rondas anteriores.

Ningún modo entrena una GAN neuronal ni modifica los pesos del modelo. Es generación con realimentación y selección evolutiva. La novedad textual y la similitud léxica no prueban por sí solas que una variante conserve exactamente la intención adversarial; los resultados importantes necesitan evidencia independiente.


## Compatibilidad de Google Gemini

Kyojitsu consulta `https://generativelanguage.googleapis.com/v1beta/models` y asigna un transporte por modelo. Para Gemini 1.x/2.x usa el endpoint `.../models/{modelo}:generateContent`, que sigue soportado por Google. Para Gemini 3+ usa `https://generativelanguage.googleapis.com/v1beta/interactions`. El parser acepta respuestas Interactions con `steps` y con el esquema anterior `outputs`. Siempre usa **Probar generación** después de escoger el modelo.
