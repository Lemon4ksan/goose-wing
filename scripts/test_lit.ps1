# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

# scripts/test_lit.ps1
# Master test runner for goose-lit native test suites in goose-wing.
# Supports parallel execution, filtering, verbose tracing, and clean exit status.

param(
    [string]$Pattern = "*",
    [int]$Jobs = 4,
    [switch]$Verbose,
    [switch]$Sequential
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

# Discover tests matching pattern
$filter = if ($Pattern.EndsWith(".goose")) { $Pattern } else { "$Pattern.goose" }
if ($Pattern -eq "*") { $filter = "*.goose" }

$allFiles = Get-ChildItem -Path $litTestsDir -Recurse -Filter $filter | Where-Object {
    $_.Extension -eq ".goose" -and $_.Name -ne "wire_kit.goose"
} | Sort-Object Name

if ($allFiles.Count -eq 0) {
    Write-Host "No tests found matching pattern '$Pattern' in $litTestsDir" -ForegroundColor Yellow
    exit 0
}

function Start-GooseProcess([string]$fileName, [string]$cmdArgs) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $fileName
    $psi.Arguments = $cmdArgs
    $psi.WorkingDirectory = $root
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    return [System.Diagnostics.Process]::Start($psi)
}

$swTotal = [System.Diagnostics.Stopwatch]::StartNew()
$maxConcurrent = if ($Sequential) { 1 } else { [Math]::Max(1, [Math]::Min($Jobs, [Environment]::ProcessorCount)) }

Write-Host "Running $($allFiles.Count) goose-lit verification suites (concurrency: $maxConcurrent)..." -ForegroundColor Cyan

$queue = [System.Collections.Queue]::new()
foreach ($file in $allFiles) {
    $queue.Enqueue($file)
}

$running = [System.Collections.ArrayList]::new()
$passedCount = 0
$failedCount = 0
$completedCount = 0
$totalCount = $allFiles.Count

while ($queue.Count -gt 0 -or $running.Count -gt 0) {
    while ($running.Count -lt $maxConcurrent -and $queue.Count -gt 0) {
        $targetFile = $queue.Dequeue()
        $extraArgs = if ($Verbose) { "--verbose" } else { "" }
        $argsStr = "`"$($targetFile.FullName)`" $extraArgs".Trim()
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $proc = Start-GooseProcess $litBin $argsStr
        [void]$running.Add([PSCustomObject]@{
            File = $targetFile
            Process = $proc
            Stopwatch = $sw
        })
    }

    Start-Sleep -Milliseconds 40
    for ($i = $running.Count - 1; $i -ge 0; $i--) {
        $task = $running[$i]
        if ($task.Process.HasExited) {
            $task.Process.WaitForExit()
            $task.Stopwatch.Stop()
            $completedCount++
            $ms = $task.Stopwatch.ElapsedMilliseconds
            $stdout = $task.Process.StandardOutput.ReadToEnd()
            $stderr = $task.Process.StandardError.ReadToEnd()

            if ($task.Process.ExitCode -eq 0) {
                $passedCount++
                Write-Host "  [PASS] $($task.File.Name) ($ms ms)" -ForegroundColor Green
                if ($Verbose -and $stdout) {
                    Write-Host $stdout -ForegroundColor DarkGray
                }
            } else {
                $failedCount++
                Write-Host "  [FAIL] $($task.File.Name) (exit $($task.Process.ExitCode), $ms ms)" -ForegroundColor Red
                if ($stdout) { Write-Host $stdout -ForegroundColor Yellow }
                if ($stderr) { Write-Host $stderr -ForegroundColor Red }
            }
            $running.RemoveAt($i)
        }
    }
}

$swTotal.Stop()

# Sanity cleanup of any leftover temp artifacts
Get-ChildItem -Path $litTestsDir -Filter "*.tmp*" -Recurse | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Host "-----------------------------------------------------------------------"
Write-Host "Test Summary: $passedCount passed, $failedCount failed in $($swTotal.ElapsedMilliseconds) ms" -ForegroundColor $(if ($failedCount -eq 0) { "Green" } else { "Red" })

if ($failedCount -gt 0) {
    exit 1
}
exit 0
