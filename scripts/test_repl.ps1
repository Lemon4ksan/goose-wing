# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

# scripts/test_repl.ps1
# Master batch test runner for Gosling REPL in-memory verification suites.

param(
    [string]$Filter = "*.repl",
    [switch]$PerProcess
)

$ErrorActionPreference = "Continue"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$replDir = Join-Path $PSScriptRoot "repl"
$goslingRepl = Resolve-Path (Join-Path $root "..\gosling\bin\gosling-repl.exe") -ErrorAction SilentlyContinue

if (-not $goslingRepl -or -not (Test-Path $goslingRepl)) {
    Write-Host "ERROR: gosling-repl binary not found at $goslingRepl" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $replDir)) {
    Write-Host "ERROR: REPL scripts directory not found at $replDir" -ForegroundColor Red
    exit 1
}

$scripts = Get-ChildItem -Path $replDir -Filter $Filter | Sort-Object Name
if ($scripts.Count -eq 0) {
    Write-Host "No .repl scripts found matching filter '$Filter'" -ForegroundColor Yellow
    exit 0
}

Write-Host "Running REPL verification suites ($($scripts.Count) found)`n"

if (-not $PerProcess) {
    # Single-process batch execution mode
    $filePaths = @($scripts | ForEach-Object { $_.FullName })
    & $goslingRepl --batch @filePaths
    exit $LASTEXITCODE
}

# Per-process isolated execution mode
$passed = 0
$failed = 0
$totalDurationMs = 0
$results = @()

foreach ($s in $scripts) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $out = & $goslingRepl $s.FullName 2>&1
    $rc = $LASTEXITCODE
    $sw.Stop()
    $durMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
    $totalDurationMs += $durMs

    if ($rc -eq 0) {
        $passed++
        Write-Host "  [PASS] $($s.Name) ($($durMs) ms)" -ForegroundColor Green
        $results += [PSCustomObject]@{
            Suite    = $s.Name
            Status   = "PASS"
            Duration = "$($durMs) ms"
        }
    } else {
        $failed++
        Write-Host "  [FAIL] $($s.Name) ($($durMs) ms)" -ForegroundColor Red
        if ($out) {
            Write-Host ($out -join "`n") -ForegroundColor Yellow
        }
        $results += [PSCustomObject]@{
            Suite    = $s.Name
            Status   = "FAIL"
            Duration = "$($durMs) ms"
        }
    }
}

Write-Host "`nPassed $passed of $($scripts.Count) suites in $($totalDurationMs) ms" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })

if ($failed -gt 0) {
    exit 1
}
exit 0
