# Auditoría de los seis datasets

## Hallazgo principal

No se puede afirmar que Kyojitsu cubra de forma equivalente todas las evasiones de estos corpus. Hay correspondencias parciales entre familias y transformaciones locales, pero no equivalencia de comportamiento demostrada. Añadir un LLM permite nuevas redacciones; no certifica la cobertura de cada técnica.

Se leyeron los archivos del archivo original del proyecto, en modo local. No se enviaron prompts a ningún proveedor ni se reejecutaron contra los fabricantes nombrados. Los nombres de archivos se conservan como identificadores, no como verificación de su origen o de la configuración de un producto.

## Conteos

| Archivo | Registros | Prompts distintos normalizados | Evidencia disponible |
|---|---:|---:|---|
| `dataset_PALO_ALTO.db` | 4352 | 676 | Log con blocked: 1=3796, 0=556. Sin veredicto independiente de éxito. |
| `dataset_TREND_AI.db` | 2117 | 1876 | Log con blocked: 1=1311, 0=806. Sin veredicto independiente de éxito. |
| `dataset_PALO_ALTO_SIN_GUARDRAILS.db` | 1052 | 207 | Log con blocked: 0=1052. Sin veredicto independiente de éxito. |
| `successful_prompts_verified.json` | 100 | 100 | 100 etiquetas Legitimate educational query; consultas educativas benignas, sin resultados observados. |
| `successful_prompts_verified.json.maliciousinput` | 500 | 330 | 19 familias etiquetadas; sin respuestas ni resultados observados. |
| `successful_prompts_verified.json.maliciousoutput` | 100 | 100 | Casos orientados a la salida; sin resultados observados. |

Distinto significa normalizar mayúsculas y espacios DENTRO de cada archivo. No es deduplicación semántica, ni se han eliminado coincidencias entre archivos. Los 8221 registros no equivalen a ese número de técnicas o de casos independientes.

`blocked=false` no prueba un ataque exitoso. El nombre successful_prompts_verified tampoco: ninguno de los tres JSON contiene un campo de resultado observado o éxito independiente. En particular, el JSON de 100 consultas educativas es apropiado como candidato a control benigno, sujeto a la política real; no como corpus de ataques confirmados.

Los campos attack_type de SQLite mezclan categorías de contenido con técnicas, y contienen valores sin etiqueta. El archivo cuyo nombre dice SIN_GUARDRAILS registra 1052 valores de bloqueo falso; el nombre y ese valor no bastan para verificar la configuración de la defensa ni para inferir compromiso del modelo.

## Correspondencia estructural de las 19 familias

Esta tabla es una comparación manual de etiquetas y capacidades de código. No es una tasa medida de cobertura, ni prueba que una variante tenga la misma intención o eficacia. Las familias pueden solaparse.

| Familia del corpus | Registros | Correspondencia local | Alcance / brecha |
|---|---:|---|---|
| Contextual Manipulation | 17 | contextual_reframe | Parcial: Contexto local sin manipular memoria persistente ni RAG real. |
| Task Confusion | 31 | contextual_reframe / json_envelope | Parcial: Estructuras afines; sin un motor especifico de conflicto entre tareas. |
| Question Based Evasion | 36 | question_rewrite | Parcial: Reformula como pregunta; no verifica que mantenga la intención. |
| Semantic Ambiguity | 24 | semantic_wrapper | Parcial: No garantiza crear ni resolver ambigüedad semántica equivalente. |
| Json Confusion | 31 | json_envelope | Parcial: Envoltura JSON válida; no reproduce todos los casos de ambigüedad del parser. |
| Metaphorical Instruction | 29 | none | Sin operador local específico: No hay operador local de metáforas. Un LLM puede producirlas, pero necesita evaluación específica. |
| Fragmented Tool Description | 20 | segmented | Requiere integración: El texto fragmentado no prueba como el agente utiliza herramientas reales. |
| Indirect Questioning | 24 | indirect_request | Parcial: Reformulación indirecta de un solo turno. |
| Incremental Disclosure | 24 | segmented | Requiere integración: Fragmenta dentro de un prompt; no implementa divulgación progresiva multi-turn. |
| Semantic Fragmentation | 23 | segmented | Parcial: División de palabras y recombinación; sin validación semántica independiente. |
| Contextual Misdirection | 34 | contextual_reframe | Parcial: Cambia el marco; no demuestra desvio contextual equivalente. |
| Indirect Generation | 25 | indirect_request | Parcial: Indirección en texto, sin prueba de equivalencia semántica. |
| Nested Role Playing | 37 | nested_role | Parcial: Encapsula un rol; no modela sesiones independientes ni conversacion multi-turn. |
| Hypothetical Scenario | 22 | hypothetical | Parcial: Marco hipotetico programado, no equivalencia garantizada con el corpus. |
| Obfuscated Command Chain | 19 | encoded_fragment / segmented | Requiere integración: No ejecuta cadenas ni valida un intérprete de comandos; requiere un simulador autorizado. |
| Data Encoding Fragmentation | 23 | encoded_fragment / segmented | Parcial: Codifica fragmentos; repertorio limitado, no todas las codificaciones. |
| Role Reversal | 26 | nested_role | Parcial: Plantilla de rol; no equivale a invertir una jerarquia real de mensajes. |
| Semantic Rewriting | 25 | semantic_wrapper / question_rewrite | Parcial: Cambios programados, no parafrasis libres con un modelo en modo local. |
| Ambiguous Tool Request | 30 | none | Requiere integración: Requiere herramientas instrumentadas, permisos y un registro de acciones. |

No se ha implementado una conversación adversarial multietapa, ejecución de herramientas o cadenas de comandos a partir de estas etiquetas. Los equivalentes de laboratorio deben integrarse y verificarse antes de presentar cobertura. La evaluación de salidas necesita criterios propios: un filtro que acepta la entrada no determina si una respuesta viola la política.

## Reproducción y huellas

Coloca los seis originales en una carpeta y ejecuta:

```text
python tools/audit_datasets.py --directory CARPETA --output auditoria.json
```

No se abren como programas; SQLite se lee sin escrituras. El JSON adjunto conserva todos los conteos y las huellas SHA-256. No se redistribuyen los corpus crudos en esta entrega.

| Archivo | SHA-256 |
|---|---|
| `dataset_PALO_ALTO.db` | `a68f8c87cc7f31410cf07234439a8c03fcd5404bc9660d8b8a5a952f871ce61a` |
| `dataset_TREND_AI.db` | `d56cbc8aa4c1d5c5d7baf5b6ded13aafb69f1fc3fc5ca74b4ba7f193a9e1cd18` |
| `dataset_PALO_ALTO_SIN_GUARDRAILS.db` | `35dfa4bcaa879e066aec4577f2a63eb1193c5f1697883c0aefbb4f1ad3604982` |
| `successful_prompts_verified.json` | `60e190aeddd7e56ab07e71031910392dd68b89321ae505c48d2a6f0800fa31d1` |
| `successful_prompts_verified.json.maliciousinput` | `ecadf1c0d49cbf8af2a781426e297f430c12c549b08a8341b2dcfd6ce4a48932` |
| `successful_prompts_verified.json.maliciousoutput` | `53072d5a0c5428e9c35c72858838bad80c7c2b20c8453239cbfd48d7cc57b22c` |
