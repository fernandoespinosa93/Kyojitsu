# Kyojitsu 3.8.1 | Inicio rápido

## 1. Actualizar

Cierra el Studio anterior con Ctrl+C y extrae el ZIP en una carpeta nueva. No sustituyas solo un archivo: cambiaron motor, interfaz, recursos y reportes. Ejecuta `run_studio.bat`; requiere Python 3.11+. La barra lateral debe indicar 3.8.1. Studio está en `http://127.0.0.1:8765`. No necesitas pip ni Node para usarlo.

## 2. Configuración guiada

Studio usa ahora un asistente de cinco pasos: **Conexión → Marco y técnicas → Generador de prompts → Evolución y límites → Revisar y ejecutar**. Solo se muestra un bloque de configuración a la vez. Usa **Siguiente** y **Atrás** para avanzar; la barra lateral permite saltar directamente a un paso si necesitas corregir algo.

El último paso concentra el resumen, **Probar API**, **Ver plan**, **Iniciar campaña** y el **Log**. Así puedes revisar el alcance completo antes de enviar solicitudes al endpoint.

## 3. Conectar la API que vas a evaluar

La URL es la del endpoint que recibe preguntas, no la página principal. Puedes importar un cURL con JSON y revisar método, autenticación y cuerpo. No se ejecuta el comando.

En el laboratorio mostrado por el operador, la configuración era:

| Campo | Valor |
|---|---|
| URL | `http://127.0.0.1:80/api/query` |
| Método | `POST` |
| Campo que recibe la pregunta | `question` |
| Campo que contiene la respuesta | `answer` |
| Campo de bloqueo | `blocked`, solo si realmente existe |
| Campo del motivo | `reason`, si existe |
| Campo de etapa | Vacío si la API no devuelve una etapa; `stage` solo si existe |

```json
{"question":"{{prompt}}","session_id":"api_default","use_guardrails":true}
```

Headers:

```json
{"Content-Type":"application/json","Accept":"application/json"}
```

Este puerto corresponde a la captura del laboratorio, no se asume para otras instalaciones. Usa el puerto donde tu servidor realmente escucha. No es necesario cambiar a 5000 si el endpoint en 80 funciona. `127.0.0.1` se refiere al equipo donde se ejecuta Python.

Al escribir `question` en el campo de entrada y pulsar **Aplicar campo al JSON**, se crea o actualiza el campo y se retira el marcador anterior. Se conservan las constantes de otros campos. También admite `input.text` o `messages[0].content`. El campo de respuesta NO cambia lo que se envía: se verifica con **Probar API**. Escribe un nombre de campo, no la pregunta completa.

Confirma autorización y prueba la conexión. Se envía una consulta benigna real. HTTP y ruta de respuesta deben ser correctos. Cambiar URL, headers, JSON o contrato requiere otra prueba. La conexión se revalida antes de ejecutar; una API apagada no produce resultados de simulación.

Si la API solo dice «Query blocked by security guardrails» en su respuesta, se mostrará **Bloqueo indicado en texto**: requiere revisión y no permite conocer la etapa. Si `blocked=false` contradice ese texto, se mostrará **Señales contradictorias**. Para medir con precisión, la API debe devolver señales explícitas coherentes. `blocked=true` sin etapa no se atribuye a la entrada.

## 4. Elegir cómo se generan los casos

- **Reglas locales:** no usa un proveedor de IA. Cambia los ejemplos con doce transformaciones programadas y selecciona variantes usando los resultados. Tiene un repertorio limitado.
- **Anthropic Claude / Google Gemini / API compatible con OpenAI:** conecta un modelo independiente que escribe nuevas variantes usando el objetivo, la técnica y la retroalimentación de rondas anteriores. Pulsa **Validar clave y cargar modelos** para comprobar la credencial y descubrir dinámicamente qué modelos están disponibles. Después elige el modelo y usa **Probar generación**.

La clave del generador es temporal: no se configura en los headers del guardrail, no se guarda en los reportes y se elimina de la interfaz al iniciar la campaña. Son dos conexiones distintas. Ningún modo entrena una GAN. El origen de cada texto se muestra en vivo, en la evidencia y en el reporte. Lee `docs/GENERADOR_LLM.md`.

Para Google Gemini, Kyojitsu selecciona automáticamente el endpoint adecuado al modelo descubierto: las familias 1.x/2.x usan `generateContent`, mientras las familias 3+ usan Interactions. Si cambias manualmente el modelo, revisa que la URL del generador se haya actualizado y ejecuta **Probar generación** antes de iniciar la campaña.

## 5. Seleccionar marco, técnicas y tamaño

Para empezar: una técnica, dos ejemplos iniciales, una ronda adicional, cuatro variantes por ronda, consultas permitidas activadas, tope de diez evaluaciones y pausa de 0.5 s. Son valores sugeridos para verificar el flujo, no una evaluación de robustez suficiente.

**Rondas adicionales** cuenta las rondas después de G0. **Casos por ronda** limita las variantes adversariales. **Parte seleccionada** 0.25 toma el 25% mejor puntuado para crear nuevas versiones; no significa 25% de ataques exitosos. **Número para repetir la selección** controla el azar local; un LLM o API puede seguir respondiendo distinto. **Límite total** incluye las consultas permitidas, pero no los tests de conexión ni las llamadas al generador.

Los textos ficticios restringidos son opcionales y avanzados. Solo sirven para detectar divulgación cuando tu laboratorio YA prohíbe mostrarlos. Kyojitsu no instala esa regla. Repetir una palabra que venía en la pregunta no demuestra un ataque exitoso. Nunca uses secretos reales.

## 6. Ejecutar y leer resultados

**Ver plan** no envía preguntas. **Iniciar campaña** abre la vista en vivo. Las animaciones reflejan eventos del motor; no fingen observar el interior del LLM. El Log indica preparación, solicitudes, resultados y errores. Cancelar evita nuevas solicitudes; las que ya están en curso terminan o agotan su tiempo de espera.

El resumen ejecutivo distingue prompts distintos con ataque confirmado, técnicas con hallazgos, bloqueos y pendientes. Revisa la matriz por marco y sus recomendaciones, que incluyen evidencia, acción y cómo comprobar una mejora. Un 0 de ataques confirmados con casos pendientes NO equivale a 100% de protección.

Pulsa **PDF ejecutivo** para obtener el archivo generado por la campaña. `demo_visual.html` y `executive.pdf` de la raíz son ejemplos sintéticos, no resultados de tu Ikigai. Cada campaña real guarda su propio PDF en `runs`.

Los reportes antiguos conservan su código. Volver a exportar actualiza el formato, NO reclasifica automáticamente los resultados registrados. Ejecuta una campaña nueva para probar la corrección del evaluador. Conserva siempre las bases originales antes de actualizar o registrar revisiones.

## 7. Autodiagnóstico

Ejecuta `run_self_test.bat`. En Linux/macOS: `sh run_self_test.sh`. Los tests no llaman a tu API ni consumen una clave comercial. Node es opcional para comprobar sintaxis JavaScript. Ver `QA_RELEASE.md` para el alcance exacto de la validación.
