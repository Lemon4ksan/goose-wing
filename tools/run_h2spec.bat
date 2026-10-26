@echo off
setlocal
cd /d "%~dp0\.."

set "PYTHONUTF8=1"
python tools\h2spec\runner.py %*
exit /b %ERRORLEVEL%
