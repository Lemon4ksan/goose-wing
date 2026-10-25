@echo off
setlocal
cd /d "%~dp0.."
if exist "tools\bin\toxiproxy-cli.exe" (
    "tools\bin\toxiproxy-cli.exe" %*
) else (
    toxiproxy-cli %*
)
