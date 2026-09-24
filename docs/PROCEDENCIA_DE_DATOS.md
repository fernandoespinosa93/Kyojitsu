# Procedencia

Se conservan los corpus pequeños de laboratorio de las entregas previas en `data` y `examples`. No son una fuente completa de técnicas reales ni un benchmark de fabricantes. Los ejemplos del catálogo están orientados a pruebas acotadas.

Los seis archivos históricos del ZIP original se leyeron localmente para obtener esquema, conteos, duplicados y etiquetas. No se ejecutaron ni enviaron a una API. `docs/dataset_audit.json` contiene huellas y agregados; `docs/AUDITORIA_DATASETS.md` explica la correspondencia estructural y sus límites. Los originales no se incluyen en este paquete actualizado.

`tools/audit_datasets.py --directory CARPETA --output informe.json` reproduce la auditoría de SQLite/JSON. SQLite se abre en modo de solo lectura e inmutable. El programa no interpreta instrucciones de los prompts.

Los ejemplos HTML/PDF de esta entrega proceden de una ejecución sintética, no del laboratorio privado del usuario. Las capturas entregadas por el usuario no contienen toda la evidencia cruda para reclasificar cada solicitud.
