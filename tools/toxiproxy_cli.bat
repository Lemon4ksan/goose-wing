:: SPDX-License-Identifier: Apache-2.0
:: Copyright (c) 2026 Lemon4ksan

@echo off
setlocal
cd /d "%~dp0.."
if exist "tools\bin\toxiproxy-cli.exe" (
    "tools\bin\toxiproxy-cli.exe" %*
) else (
    toxiproxy-cli %*
)
