@echo off
setlocal
cd /d "%~dp0\.."

set "PYTHONUTF8=1"
python tools\autobahn\runner.py %*
exit /b %ERRORLEVEL%
