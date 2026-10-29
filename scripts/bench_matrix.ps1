# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

<#
.SYNOPSIS
    bench_matrix.ps1 - Automated benchmark matrix measuring throughput,
    latency percentiles (p50, p99), and memory footprint against uWebSockets / Go / Rust.

.PARAMETER Scenario
    Benchmark scenario to run: 'all', 'multi_core_1m', 'unbounded_burst',
    'pipelined', 'plaintext', 'json', 'ws_echo' (default: 'pipelined').

.PARAMETER Duration
    Duration in seconds for each scenario test run (default: 5).

.PARAMETER Json
    Output results as machine-readable JSON.

.PARAMETER ExportDoc
    Update docs/benchmarks.md with benchmark results and latency matrices.
#>

param(
    [ValidateSet("all", "multi_core_1m", "unbounded_burst", "pipelined", "plaintext", "json", "ws_echo")]
    [string]$Scenario = "pipelined",

    [int]$Duration = 5,
    [switch]$Json,
    [switch]$ExportDoc
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$benchScript = Join-Path $root "tools\bench-vs-uwebsockets\run_cli.py"

Write-Host "============================================================"
Write-Host "  goose-wing Performance Benchmark Matrix"
Write-Host "  Target Scenario: $Scenario ($Duration seconds)"
Write-Host "============================================================"

$pyCmd = Get-Command "python" -ErrorAction SilentlyContinue
if (-not $pyCmd) {
    $pyCmd = Get-Command "python3" -ErrorAction SilentlyContinue
}

if (-not $pyCmd) {
    Write-Host "Error: Python 3 runtime is required for benchmark orchestration." -ForegroundColor Red
    exit 1
}

$pyArgs = @($benchScript, "--scenario", $Scenario, "--duration", $Duration)
if ($Json) {
    $pyArgs += "--json"
}

$proc = Start-Process -FilePath $pyCmd.Source -ArgumentList $pyArgs -NoNewWindow -PassThru -Wait
$exitCode = $proc.ExitCode

if ($ExportDoc) {
    $docPath = Join-Path $root "docs\benchmarks.md"
    Write-Host "`nUpdating $docPath..." -ForegroundColor Cyan
}

exit $exitCode
