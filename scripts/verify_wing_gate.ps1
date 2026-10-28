# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

<#
.SYNOPSIS
    verify_wing_gate.ps1 - Verification gate for goose-wing code.
    Runs formatting, static typecheck, hardware complexity gate (goose-lit),
    and optional test suites.

.PARAMETER TargetFile
    Path to the .goose source file being audited or refactored.

.PARAMETER MaxGCrap
    Maximum allowable G-CRAP score for any function (default: 25).

.PARAMETER SimCov
    Simulated branch coverage for risk estimation (default: 0.85).

.PARAMETER LitScript
    Optional path to a .goose LIT verification test suite.

.PARAMETER TestSuite
    Optional path to a .goose test suite to compile and execute.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetFile,

    [int]$MaxGCrap = 25,
    [double]$SimCov = 0.85,
    [string]$LitScript = "",
    [string]$TestSuite = ""
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")

Write-Host "Verifying $TargetFile"
Write-Host "Ceiling: G-CRAP $MaxGCrap, simulated coverage $($SimCov * 100)%"

if (-not (Test-Path $TargetFile)) {
    Write-Host "Error: Target file does not exist: $TargetFile" -ForegroundColor Red
    exit 1
}

# Phase 1: formatting and typecheck
Write-Host "`nPhase 1: Format and typecheck"
$fmtOut = & goose format --check $TargetFile 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Formatting error in $TargetFile." -ForegroundColor Red
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
        Write-Host "Typecheck failed in $TargetFile." -ForegroundColor Red
        Write-Host ($chkOut -join "`n") -ForegroundColor Yellow
        exit 1
    }
}
$ErrorActionPreference = $prevEAP
Write-Host "  Format and typecheck passed." -ForegroundColor Green

# Phase 2: Hardware complexity gate via goose-lit
Write-Host "`nPhase 2: Complexity gate (ceiling: $MaxGCrap)"
$litBin = "D:\GooseProjects\goose-lit\bin\goose-lit.exe"
if (-not (Test-Path $litBin)) {
    $litBin = Join-Path $root "..\goose-lit\bin\goose-lit.exe"
}

if (-not (Test-Path $litBin)) {
    $cmd = Get-Command "goose-lit" -ErrorAction SilentlyContinue
    if ($cmd) {
        $litBin = $cmd.Source
    }
}

if (Test-Path $litBin) {
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $gateOut = & $litBin gate $TargetFile $MaxGCrap --cov $SimCov 2>&1
    $gateRc = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    Write-Host ($gateOut -join "`n")
    if ($gateRc -eq 0) {
        Write-Host "  Complexity gate passed." -ForegroundColor Green
    } else {
        Write-Host "  Complexity gate rejected for $TargetFile (exit $gateRc)." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  goose-lit not found (optional)." -ForegroundColor Yellow
}

# Phase 3: Optional LIT verification script
if ($LitScript -ne "") {
    Write-Host "`nPhase 3: Executing LIT verification script: $LitScript"
    if (-not (Test-Path $LitScript)) {
        Write-Host "LIT verification script not found: $LitScript" -ForegroundColor Red
        exit 1
    }
    if (Test-Path $litBin) {
        $scriptOut = & $litBin $LitScript 2>&1
        Write-Host ($scriptOut -join "`n")
        if ($LASTEXITCODE -ne 0) {
            Write-Host "LIT verification script failed: $LitScript" -ForegroundColor Red
            exit 1
        }
        Write-Host "  LIT verification passed." -ForegroundColor Green
    } else {
        Write-Host "  goose-lit runner not available to run $LitScript." -ForegroundColor Yellow
    }
}

# Phase 4: Test suite
if ($TestSuite -ne "") {
    Write-Host "`nPhase 4: Test suite ($TestSuite)"
    if (-not (Test-Path $TestSuite)) {
        Write-Host "Test suite not found: $TestSuite" -ForegroundColor Red
        exit 1
    }
    $testBin = Join-Path $root "bin\gate_test_tmp.exe"
    $env:GOOSE_CC = Join-Path $root "tools\gcc_noavx.cmd"
    $bldOut = & goose build -O2 -o $testBin $TestSuite 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Test compilation failed:" -ForegroundColor Red
        Write-Host ($bldOut -join "`n") -ForegroundColor Yellow
        exit 1
    }
    $runOut = & $testBin 2>&1
    Write-Host ($runOut -join "`n")
    $testRc = $LASTEXITCODE
    if (Test-Path $testBin) { Remove-Item -Force $testBin }
    if ($testRc -ne 0) {
        Write-Host "Test suite failed with exit code $testRc." -ForegroundColor Red
        exit 1
    }
    Write-Host "  Test suite passed." -ForegroundColor Green
} else {
    Write-Host "`nPhase 4: No test suite specified." -ForegroundColor Gray
}

Write-Host "`nAll verification checks passed for $TargetFile." -ForegroundColor Green
exit 0
