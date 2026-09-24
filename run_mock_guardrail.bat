@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py examples\mock_guardrail_server.py
) else (
  python examples\mock_guardrail_server.py
)
