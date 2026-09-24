# Integración con APIs e Ikigai

La interfaz 3.4 utiliza API REST configurable. No requiere modificar Ikigai para enviar preguntas, recibir respuestas y conservar evidencia. La calidad de las métricas depende de las señales que devuelva la API: `blocked`, motivo, etapa y, cuando exista, un criterio independiente del resultado.

`patch_ikigai.py` es un parche experimental heredado para una versión específica del laboratorio. NO se ejecuta automáticamente. No fue revalidado contra una instalación privada diferente. Antes de usarlo, compara el código, haz una copia y revisa el cambio. El contrato histórico `kyojitsu-v2` identifica ese servidor, no la versión actual del cliente.

La modalidad API REST genérica comprueba alcance y contrato de respuesta, pero no puede garantizar por sí sola que el servidor tenga una defensa instalada ni su modo de fallo. Confirma esa configuración en el laboratorio.
