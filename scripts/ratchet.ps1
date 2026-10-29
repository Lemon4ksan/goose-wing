# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

# scripts/ratchet.ps1
# CI ratchet delta gate and baseline comparator for goose-crap.
# Enforces zero regressions in unproven bce:keep bounds panics or G-CRAP complexity.

param(
    [switch]$Save,
    [double]$Delta = 5.0,
    [double]$Cov = 0.85,
    [string]$BaselineFile = ""
)

$root = Split-Path -Parent $PSScriptRoot
$litBin = Join-Path $root "..\goose-lit\bin\goose-lit.exe"

if (-not (Test-Path $litBin)) {
    $litDir = Join-Path $root "..\goose-lit"
    if (Test-Path (Join-Path $litDir "bin.goose")) {
        Write-Host "Building native goose-lit..." -ForegroundColor Cyan
        & goose build --cc gcc -O2 -o "$litBin" (Join-Path $litDir "bin.goose")
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error: Failed to compile goose-lit." -ForegroundColor Red
            exit $LASTEXITCODE
        }
    } else {
        $cmd = Get-Command "goose-lit" -ErrorAction SilentlyContinue
        if ($cmd) {
            $litBin = $cmd.Source
        } else {
            Write-Host "Error: goose-lit binary not found. Please clone goose-lit beside goose-wing." -ForegroundColor Red
            exit 1
        }
    }
}

if (-not $BaselineFile) {
    $BaselineFile = Join-Path $PSScriptRoot "gcrap_baseline.txt"
}

if ($Save) {
    Write-Host "Saving G-CRAP baseline snapshot to $BaselineFile (cov=$Cov)..." -ForegroundColor Cyan
    & $litBin crap $root --save-baseline "$BaselineFile" --cov $Cov
    exit $LASTEXITCODE
} else {
    if (-not (Test-Path $BaselineFile)) {
        Write-Host "Error: Baseline file not found at $BaselineFile. Run with -Save first." -ForegroundColor Red
        exit 1
    }
    Write-Host "Evaluating CI ratchet gate against $BaselineFile (delta=$Delta, cov=$Cov)..." -ForegroundColor Cyan
    & $litBin crap $root --baseline "$BaselineFile" --cov $Cov --delta $Delta
    exit $LASTEXITCODE
}
