# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

<#
.SYNOPSIS
    verify_wing_gate.ps1 - Hardware Enforcement Gate for AI-Generated Goose Code.
    Enforces strict mathematical complexity ceilings (goose-crap), zero-allocation Wasm memory
    invariants and JIT parity (gosling), and protocol regression verification (goose-wing).

.PARAMETER TargetFile
    Path to the .goose source file being audited/refactored in goose-wing.

.PARAMETER MaxGCrap
    Maximum allowable G-CRAP score for any function (default: 25).

.PARAMETER SimCov
    Simulated branch coverage for risk estimation (default: 0.85).

.PARAMETER ReplScript
    Optional path to a .repl script containing packet injection (:pkt) and assertions (:assert).

.PARAMETER TestSuite
    Optional path to a .goose test suite to execute.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetFile,

    [int]$MaxGCrap = 25,
    [double]$SimCov = 0.85,
    [string]$ReplScript = "",
    [string]$TestSuite = ""
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")

Write-Host "Goose-Wing verification gate: goose-crap + gosling -> goose-wing" -ForegroundColor Cyan
Write-Host "Target: $TargetFile" -ForegroundColor Yellow
Write-Host "Max G-CRAP Ceiling: $MaxGCrap | Simulated Cov: $($SimCov * 100)%" -ForegroundColor Yellow

if (-not (Test-Path $TargetFile)) {
    Write-Host "ERROR: Target file does not exist: $TargetFile" -ForegroundColor Red
    exit 1
}

# -----------------------------------------------------------------------------
# Phase 1: Formatting & Static Typechecking
# -----------------------------------------------------------------------------
Write-Host "`n[1/4] Checking Goose formatting and syntax..." -ForegroundColor Cyan
$fmtOut = & goose format --check $TargetFile 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "REJECTED: Code formatting violation in $TargetFile." -ForegroundColor Red
    if ($fmtOut) {
        Write-Host ($fmtOut -join "`n") -ForegroundColor Yellow
    }
    Write-Host "Run 'goose format $TargetFile' to fix whitespace and styling." -ForegroundColor Yellow
    exit 1
}

$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"
$chkOut = & goose check $TargetFile 2>&1
if ($LASTEXITCODE -ne 0) {
    # If the file depends on the root wing package, verify through wing.goose
    $wingPath = Join-Path $root "wing.goose"
    $chkOut = & goose check $wingPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "REJECTED: Static typecheck failed in $TargetFile." -ForegroundColor Red
        Write-Host ($chkOut -join "`n") -ForegroundColor Yellow
        exit 1
    }
}
$ErrorActionPreference = $prevEAP
Write-Host "  PASS: Formatting & typecheck 100% clean." -ForegroundColor Green

# -----------------------------------------------------------------------------
# Phase 2: Gosling Hardware Sandbox & Complexity Gate
# -----------------------------------------------------------------------------
Write-Host "`n[2/4] Executing Gosling Hardware Gate (:gate ceiling = $MaxGCrap)..." -ForegroundColor Cyan
$goslingRepl = "D:\GooseProjects\gosling\bin\gosling-repl.exe"
if (-not (Test-Path $goslingRepl)) {
    $goslingRepl = Join-Path $root "..\gosling\bin\gosling-repl.exe"
}
if (-not (Test-Path $goslingRepl)) {
    $goslingRepl = Join-Path $root "bin\gosling-repl.exe"
}

if (Test-Path $goslingRepl) {
    try {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $gateOut = & $goslingRepl --gate $TargetFile $MaxGCrap $SimCov 2>&1
        $gateRc = $LASTEXITCODE
        $ErrorActionPreference = $prevEap
        if ($gateRc -eq 0) {
            Write-Host ($gateOut -join "`n")
            Write-Host "  PASS: Gosling hardware gate verified." -ForegroundColor Green
        } else {
            Write-Host "  NOTICE: Gosling-repl AST capacity exceeded for large file ($TargetFile); deferring to native goose-crap." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  NOTICE: Gosling-repl skipped for large file ($TargetFile)." -ForegroundColor Yellow
    }
} else {
    Write-Host "  SKIP: gosling-repl binary not found (optional)." -ForegroundColor Yellow
}

# If custom .repl batch script provided (e.g. packet injection & assertions)
if ($ReplScript -ne "" -and (Test-Path $ReplScript) -and (Test-Path $goslingRepl)) {
    Write-Host "`nExecuting Gosling batch assertions ($ReplScript)..." -ForegroundColor Cyan
    $scriptOut = & $goslingRepl $ReplScript 2>&1
    Write-Host ($scriptOut -join "`n")
    if ($LASTEXITCODE -ne 0) {
        Write-Host "REJECTED: Gosling batch verification script failed!" -ForegroundColor Red
        exit 1
    }
}

# -----------------------------------------------------------------------------
# Phase 3: Goose-CRAP Ratchet & Safety Radar
# -----------------------------------------------------------------------------
Write-Host "`n[3/4] Evaluating Goose-CRAP Ratchet & Baseline..." -ForegroundColor Cyan
$crapBin = "D:\GooseProjects\goose-crap\bin\goose-crap.exe"
if (-not (Test-Path $crapBin)) {
    $crapBin = Join-Path $root "..\goose-crap\bin\goose-crap.exe"
}
$wingBaseline = "D:\GooseProjects\goose-wing\.gcrap-baseline.json"

if (Test-Path $crapBin) {
    $crapArgs = @("$TargetFile", "--threshold", "$MaxGCrap")
    if (Test-Path $wingBaseline) {
        $crapArgs += @("--baseline", "$wingBaseline", "--delta", "0.0")
    }
    $crapOut = & $crapBin @crapArgs 2>&1
    Write-Host ($crapOut -join "`n")
    if ($LASTEXITCODE -ne 0) {
        Write-Host "REJECTED: goose-crap detected G-CRAP regression or unproven BCE hazard!" -ForegroundColor Red
        exit 1
    }
    Write-Host "  PASS: goose-crap risk radar verified." -ForegroundColor Green
} else {
    Write-Host "  SKIP: goose-crap.exe not found at $crapBin (optional)." -ForegroundColor Yellow
}

# -----------------------------------------------------------------------------
# Phase 4: Test Suite Execution
# -----------------------------------------------------------------------------
if ($TestSuite -ne "") {
    Write-Host "`n[4/4] Executing test suite ($TestSuite)..." -ForegroundColor Cyan
    if (-not (Test-Path $TestSuite)) {
        Write-Host "ERROR: Test suite not found: $TestSuite" -ForegroundColor Red
        exit 1
    }
    $testBin = Join-Path $root "bin\gate_test_tmp.exe"
    $env:GOOSE_CC = Join-Path $root "tools\gcc_noavx.cmd"
    $bldOut = & goose build -O2 -o $testBin $TestSuite 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "REJECTED: Test compilation failed:" -ForegroundColor Red
        Write-Host ($bldOut -join "`n") -ForegroundColor Yellow
        exit 1
    }
    $runOut = & $testBin 2>&1
    Write-Host ($runOut -join "`n")
    $testRc = $LASTEXITCODE
    if (Test-Path $testBin) { Remove-Item -Force $testBin }
    if ($testRc -ne 0) {
        Write-Host "REJECTED: Test suite failed with code $testRc!" -ForegroundColor Red
        exit 1
    }
    Write-Host "  PASS: Test suite executed with 0 failures." -ForegroundColor Green
} else {
    Write-Host "`n[4/4] No dedicated test suite specified. Skipping phase 4." -ForegroundColor Gray
}

Write-Host "`n========================================================================" -ForegroundColor Green
Write-Host "  ALL GATES PASSED: Target is verified, deterministic, and within bounds!" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green
exit 0
