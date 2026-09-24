@echo off
setlocal
cd /d "%~dp0"
set "PYTHONPATH=%CD%\src"
where py >nul 2>nul
if %errorlevel%==0 (
  py -m kyojitsu run-campaign --campaign examples\campaign_fixture.json --output runs\demo
) else (
  python -m kyojitsu run-campaign --campaign examples\campaign_fixture.json --output runs\demo
)
if errorlevel 1 exit /b 1
start "" "runs\demo\report.html"
echo Demo funcional abierta en el navegador.
