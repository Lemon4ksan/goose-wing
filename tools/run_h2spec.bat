:: SPDX-License-Identifier: Apache-2.0
:: Copyright (c) 2026 Lemon4ksan

@echo off
setlocal
cd /d "%~dp0\.."

set "PYTHONUTF8=1"
python tools\h2spec\runner.py %*
exit /b %ERRORLEVEL%
