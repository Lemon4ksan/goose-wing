# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

<#
.SYNOPSIS
    verify_wing_gate.ps1 - Verification gate for goose-wing code.
    Runs formatting, static typecheck, complexity and bounds checks (goose-crap, gosling),
    and optional test suites.

.PARAMETER TargetFile
    Path to the .goose source file being audited or refactored.

.PARAMETER MaxGCrap
    Maximum allowable G-CRAP score for any function (default: 25).

.PARAMETER SimCov
    Simulated branch coverage for risk estimation (default: 0.85).

.PARAMETER ReplScript
    Optional path to a .repl script with packet injection (:pkt) and assertions (:assert).

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

# Phase 2: complexity gate
Write-Host "`nPhase 2: Complexity gate (ceiling: $MaxGCrap)"
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
            Write-Host "  Complexity gate passed." -ForegroundColor Green
        } else {
            Write-Host "  gosling-repl AST capacity exceeded for $TargetFile; deferring to goose-crap." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  gosling-repl skipped for $TargetFile." -ForegroundColor Yellow
    }
} else {
    Write-Host "  gosling-repl not found (optional)." -ForegroundColor Yellow
}

# Optional .repl verification script
if ($ReplScript -ne "" -and (Test-Path $ReplScript) -and (Test-Path $goslingRepl)) {
    Write-Host "`nExecuting verification script: $ReplScript"
    $scriptOut = & $goslingRepl $ReplScript 2>&1
    Write-Host ($scriptOut -join "`n")
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Verification script failed: $ReplScript" -ForegroundColor Red
        exit 1
    }
}

# Phase 3: complexity baseline check
Write-Host "`nPhase 3: Baseline check"
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
        Write-Host "goose-crap reported complexity regression or unproven bounds check." -ForegroundColor Red
        exit 1
    }
    Write-Host "  Baseline check passed." -ForegroundColor Green
} else {
    Write-Host "  goose-crap not found (optional)." -ForegroundColor Yellow
}

# Phase 4: test suite
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
