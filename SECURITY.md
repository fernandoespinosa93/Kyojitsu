# Seguridad

## Uso previsto

Kyojitsu es una herramienta de evaluación de seguridad para sistemas autorizados. Puede generar tráfico adversarial hacia una API configurada por el operador.

No lo uses contra servicios de terceros sin autorización explícita.

## Superficie de seguridad

- Studio escucha por defecto en `127.0.0.1`.
- Las acciones POST internas usan un token local anti-CSRF.
- Las campañas REST requieren confirmación de autorización y preflight.
- El importador de cURL analiza texto; no ejecuta comandos.
- Las redirecciones HTTP no se siguen automáticamente.
- Las claves del generador deben permanecer en memoria y no persistirse en artefactos.
- Los archivos de campañas pueden contener datos sensibles y deben tratarse como evidencia de seguridad.

## Reportar una vulnerabilidad

Si el repositorio tiene GitHub Private Vulnerability Reporting habilitado, úsalo. Si no, contacta al propietario del repositorio por un canal privado.

No publiques en un issue:

- claves API;
- tokens;
- URLs privadas sensibles;
- prompts/respuestas confidenciales;
- payloads que expongan datos reales de clientes.

Incluye, cuando sea posible:

- versión de Kyojitsu;
- pasos mínimos para reproducir;
- impacto esperado/observado;
- logs redactados;
- una prueba local o fixture que reproduzca el fallo.

## Secretos

Antes de subir código a GitHub:

```bash
git status
git grep -n -I -E '(api[_-]?key|authorization: bearer|secret|token)' -- . ':!data/*'
```

Revisa manualmente cualquier coincidencia. La existencia de palabras como `api_key` en el código no implica un secreto; busca valores reales.

## Datos de campañas

`runs/` y `*.db` están ignorados por Git. No fuerces su inclusión salvo que sean fixtures sintéticos y revisados.
