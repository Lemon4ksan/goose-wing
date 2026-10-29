# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

<#
.SYNOPSIS
    test_autobahn.ps1 - Autobahn WebSocket Conformance Testsuite automation.
    Wraps tools/autobahn.py to build the native server and execute conformance cases.

.PARAMETER Cases
    Case or glob to include (e.g. 1.*, 6.4.1, 7.*).

.PARAMETER Exclude
    Case or glob to exclude.

.PARAMETER Parallelism
    Max test cases to run in parallel (default: 1).

.PARAMETER OutDir
    Directory to store Autobahn HTML/JSON test reports.

.PARAMETER Rebuild
    Force rebuild of native Goose Autobahn server before testing.

.PARAMETER Docker
    Run Autobahn test suite via official Docker image (crossbario/autobahn-testsuite).

.PARAMETER Compose
    Launch full Autobahn stack (server + fuzzing client) via docker-compose.
#>

param(
    [string]$Cases = "",
    [string]$Exclude = "",
    [int]$Parallelism = 1,
    [string]$OutDir = "",
    [switch]$Rebuild,
    [switch]$Docker,
    [switch]$Compose
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$pythonScript = Join-Path $root "tools\autobahn.py"

Write-Host "============================================================"
Write-Host "  goose-wing Autobahn WebSocket Conformance Testsuite"
Write-Host "============================================================"

$pyArgs = @($pythonScript)

if ($Cases -ne "") {
    $pyArgs += @("-i", $Cases)
}
if ($Exclude -ne "") {
    $pyArgs += @("-x", $Exclude)
}
if ($Parallelism -gt 1) {
    $pyArgs += @("-p", $Parallelism)
}
if ($OutDir -ne "") {
    $pyArgs += @("-o", $OutDir)
}
if ($Rebuild) {
    $pyArgs += "--rebuild"
}
if ($Docker) {
    $pyArgs += "--docker"
}
if ($Compose) {
    $pyArgs += "--compose"
}

$pyCmd = Get-Command "python" -ErrorAction SilentlyContinue
if (-not $pyCmd) {
    $pyCmd = Get-Command "python3" -ErrorAction SilentlyContinue
}

if (-not $pyCmd) {
    Write-Host "Error: Python 3 is required to run the Autobahn testsuite harness." -ForegroundColor Red
    exit 1
}

& $pyCmd.Source @pyArgs
exit $LASTEXITCODE
