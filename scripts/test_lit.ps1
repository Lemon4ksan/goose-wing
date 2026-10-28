# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

# scripts/test_lit.ps1
# Master test runner for goose-lit native test suites in goose-wing.

param(
    [string]$Pattern = "*",
    [switch]$Verbose
)

$ErrorActionPreference = "Continue"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$litTestsDir = Join-Path $root "tests\lit"
$litBin = Resolve-Path (Join-Path $root "..\goose-lit\bin\goose-lit.exe") -ErrorAction SilentlyContinue

if (-not $litBin -or -not (Test-Path $litBin)) {
    $litSrc = Join-Path $root "..\goose-lit\bin.goose"
    if (Test-Path $litSrc) {
        Write-Host "Building native goose-lit runner..." -ForegroundColor Cyan
        $outBin = Join-Path $root "..\goose-lit\bin\goose-lit.exe"
        & goose build --cc gcc -O2 -o $outBin $litSrc
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error: Failed to build goose-lit." -ForegroundColor Red
            exit $LASTEXITCODE
        }
        $litBin = $outBin
    } else {
        $cmd = Get-Command "goose-lit" -ErrorAction SilentlyContinue
        if ($cmd) {
            $litBin = $cmd.Source
        } else {
            Write-Host "ERROR: goose-lit binary not found. Please ensure goose-lit is cloned beside goose-wing." -ForegroundColor Red
            exit 1
        }
    }
}

if (-not (Test-Path $litTestsDir)) {
    Write-Host "ERROR: LIT tests directory not found at $litTestsDir" -ForegroundColor Red
    exit 1
}

$litArgs = @()
if ($Pattern -ne "*") {
    $matched = Get-ChildItem -Path $litTestsDir -Filter "$Pattern" | Where-Object { $_.Extension -eq ".goose" }
    if ($matched.Count -eq 0) {
        Write-Host "No tests found matching pattern '$Pattern' in $litTestsDir" -ForegroundColor Yellow
        exit 0
    }
    foreach ($m in $matched) {
        $litArgs += $m.FullName
    }
} else {
    $litArgs += $litTestsDir
}

if ($Verbose) {
    $litArgs += "--verbose"
}

Write-Host "Running native goose-lit verification suites..." -ForegroundColor Cyan
& $litBin @litArgs
exit $LASTEXITCODE
