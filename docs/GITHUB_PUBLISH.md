# Publicar Kyojitsu en GitHub

## Contenido a subir

Sube el contenido de la raíz del proyecto: `src/`, `tests/`, `docs/`, `examples/`, `qa/`, `tools/`, launchers, `pyproject.toml`, `README.md`, `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`, `.gitignore` y `.github/`.

## No subir

- `runs/` reales (solo conserva `.gitkeep` si quieres mantener la carpeta)
- `*.db`
- `.env`
- `__pycache__/`
- `.pytest_cache/`
- claves/tokens
- reportes de clientes

## Comandos típicos

```bash
git init
git add .
git status
git commit -m "Initial Kyojitsu release"
git branch -M main
git remote add origin <URL_DEL_REPO>
git push -u origin main
```

## Antes de hacer público el repositorio

- decide una licencia;
- revisa redistribución de datasets;
- ejecuta tests;
- revisa secretos;
- elimina evidencia real de clientes;
- activa GitHub Private Vulnerability Reporting si está disponible.
