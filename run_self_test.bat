@echo off
setlocal
cd /d "%~dp0"
set "PYTHONPATH=%CD%\src"
where py >nul 2>nul
if %ERRORLEVEL%==0 (
  py -3 -m unittest discover -s tests -q
) else (
  python -m unittest discover -s tests -q
)
set EXITCODE=%ERRORLEVEL%
if not %EXITCODE%==0 pause
exit /b %EXITCODE%
