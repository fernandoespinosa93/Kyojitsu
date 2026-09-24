# Changelog

## 3.8.1

- Restaurado el look punteado del panel **Origen de los casos** con superficie grafito y conexiones violeta/magenta sin degradados decorativos.
- La reproducción del lineage ahora está orquestada en JavaScript: al pulsar **Reproducir** se oculta la escena, nace G0, se dibujan relaciones a G1, aparecen sus nodos y el patrón continúa hasta Gn; después comienza la reproducción de evidencia.
- Las gráficas **Resultado de las pruebas**, **Cobertura del alcance**, **Estado por categoría**, **Técnicas con mayor señal** y la tendencia por ronda usan animaciones explícitas con Web Animations API y se reproducen de nuevo al entrar a cada sección.
- Los paneles del wizard usan todo el ancho disponible en Conexión, Marco y técnicas, Generador y Evolución; el botón Siguiente del primer paso recupera un tamaño compacto.
- Se añadieron `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`, documentación técnica de arquitectura/desarrollo, plantillas de GitHub y CI para facilitar mantenimiento por personas o agentes de IA.
- Se reforzaron pruebas de regresión y QA de animaciones.

## 3.8.0

- **Configuración guiada en 5 pasos.** Studio ya no muestra Conexión, Marco y técnicas, Generador, Evolución y límites y Resumen al mismo tiempo. El operador avanza con **Atrás / Siguiente** y puede saltar a un paso desde la navegación lateral.
- El quinto paso **Revisar y ejecutar** concentra el resumen de la campaña, preflight, plan, ejecución y Log. Esto reduce la carga visual durante la configuración.
- **Las gráficas del reporte vuelven a animarse cada vez que se entra a su vista.** La dona reconstruye sus segmentos, las barras crecen y las líneas/puntos de tendencia se trazan progresivamente al navegar entre Resumen ejecutivo, Marco y resultados, Evidencia y Origen de variantes.
- La dona, líneas y barras incorporan respuesta al cursor/foco: énfasis de segmento, serie, punto o barra sin introducir colores decorativos nuevos.
- **Reproducción de Origen de los casos corregida.** Al pulsar Reproducir, el grafo se oculta primero; luego aparecen las generaciones y nodos, se dibujan las relaciones padre/hijo y finalmente las partículas recorren las conexiones. La reproducción de casos comienza después de esa introducción visual.
- Responsive reforzado para Studio y reporte: los layouts se reorganizan en desktop, laptop, tablet y móvil; las tablas y el grafo usan scroll interno cuando necesitan más ancho sin provocar scroll horizontal a nivel de documento.
- Se conserva el sistema visual grafito/plum, el logotipo Kyojitsu, la compatibilidad Gemini/OpenAI/Anthropic y el uso temporal de credenciales del generador.
- Suite automatizada: **133 pruebas**. QA específico de esta versión: **9 comprobaciones de navegador** para wizard, animaciones, replay, responsive y ausencia de excepciones JavaScript.

## 3.7.1

- Animaciones de entrada e interacción para gráficos ejecutivos.
- Ajustes responsive adicionales y replay inicial del grafo de variantes.

## 3.7.0

- Nuevo logotipo compacto de Kyojitsu integrado en Studio y reportes.
- Paleta unificada grafito/plum y eliminación de fondos azules heredados en reportes.
- Refinamiento de Origen de los casos y Flujo del motor.

## 3.6.0

- Rediseño visual hacia superficies grafito/negras con violeta, lavanda y magenta como identidad principal.
- Flujo del motor con partículas en canvas y Origen de variantes con relaciones padre/hijo animadas.
- Compatibilidad Gemini 1.x/2.x con `generateContent` y Gemini 3+ con Interactions.

## 3.3.0

Generador LLM opcional, resumen ejecutivo por framework, PDF real, mejoras de clasificación y auditoría de datasets.

## 3.2.0

API REST configurable, importación de cURL, validación previa obligatoria, simulación separada, eventos en vivo, ayudas y correcciones de navegación.

## 3.0.1

Corrección del literal de variable de entorno que rompía el JavaScript del Studio.
