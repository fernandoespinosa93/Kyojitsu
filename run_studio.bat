@echo off
setlocal
cd /d "%~dp0"
set "PYTHONPATH=%CD%\src"
where py >nul 2>nul
if %errorlevel%==0 (
  py -m kyojitsu studio --host 127.0.0.1 --port 8765 --runs-dir runs
) else (
  python -m kyojitsu studio --host 127.0.0.1 --port 8765 --runs-dir runs
)
