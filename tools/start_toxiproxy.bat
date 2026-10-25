@echo off
setlocal
cd /d "%~dp0.."
if exist "tools\bin\toxiproxy-server.exe" (
    echo Starting Toxiproxy Server from tools\bin...
    start "Toxiproxy Server" "tools\bin\toxiproxy-server.exe" -host 127.0.0.1 -port 8474 %*
) else (
    echo Starting Toxiproxy Server via python supervisor...
    python tools\toxiproxy\server.py %*
)
