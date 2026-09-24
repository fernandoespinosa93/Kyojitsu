# Guía para presentar los resultados

Explica primero la diferencia entre una solicitud aceptada por la API, un bloqueo observado y un objetivo adversarial confirmado. Usa una política de laboratorio explícita y casos inocuos. No presentes la coincidencia de un marcador como falla cuando el modelo tenía permitido escribirlo.

Muestra la API y su conexión, el marco y alcance, el modo de generación y los límites. Ejecuta pocas pruebas mientras se ven los eventos reales. Después presenta resultados por categoría, casos pendientes y una recomendación con evidencia. Para comparar defensas, conserva el mismo corpus y protocolo antes y después del cambio; no compares dos poblaciones distintas como si fueran una mejora causal.

Di «fuzzing evolutivo con generación por reglas» o «con generación mediante un LLM» según el modo. No digas «GAN entrenada»: no se entrenan redes adversariales en este proyecto. El modelo usa realimentación durante inferencia. No garantices preservación semántica ni cobertura de toda una taxonomía.

Las cifras de `demo_visual.html` son sintéticas. Identifícalas como ejemplo, nunca como resultados de Ikigai o de un fabricante. Los datasets históricos no demuestran una comparación válida entre fabricantes sin controlar configuración, modelos, fechas, muestras y criterios de éxito.
