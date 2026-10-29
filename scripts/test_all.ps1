# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

# scripts/test_all.ps1
# High-performance parallel verification runner for goose-wing.
param(
    [string]$Pattern = "*_test.goose",
    [switch]$CheckOnly,
    [switch]$Release,
    [switch]$KeepBinaries,
    [switch]$Lit,
    [int]$Jobs = 4
)

$root = Split-Path -Parent $PSScriptRoot
$testsDir = Join-Path $root "tests"
$binDir = Join-Path $root "bin"
$optFlag = "-O2"

# Ensure 16-byte stack alignment and 32MB stack on Windows x64 to prevent GCC 16 AVX2 #GP faults
if ($IsWindows -or $env:OS -like "*Windows*") {
    $gccNoAvx = Join-Path $root "tools\gcc_noavx.cmd"
    if ((Test-Path $gccNoAvx) -and (-not $env:GOOSE_CC)) {
        $env:GOOSE_CC = $gccNoAvx
    }
}

Write-Host "Goose-wing test runner" -ForegroundColor Cyan

# Helper to start process with redirected output (avoids terminal cursor collisions)
function Start-GooseProcess([string]$fileName, [string]$cmdArgs, [bool]$redirect = $true) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $fileName
    $psi.Arguments = $cmdArgs
    $psi.WorkingDirectory = $root
    $psi.UseShellExecute = $false
    if ($redirect) {
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
    }
    return [System.Diagnostics.Process]::Start($psi)
}

# Determine total verification steps
$totalSteps = if ($CheckOnly) { 2 } elseif ($Lit) { 4 } else { 3 }

# Typecheck core and wing libraries
Write-Host "`n[1/$totalSteps] Typechecking core and wing libraries..." -ForegroundColor Yellow
$swCore = [System.Diagnostics.Stopwatch]::StartNew()
$corePath = Join-Path $root "core.goose"
$checkCoreOut = & goose check $corePath 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: goose check core.goose failed." -ForegroundColor Red
    Write-Host ($checkCoreOut -join "`n") -ForegroundColor Yellow
    exit 1
}

$wingPath = Join-Path $root "wing.goose"
$checkWingOut = & goose check $wingPath 2>&1
$swCore.Stop()

if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: goose check wing.goose failed." -ForegroundColor Red
    Write-Host ($checkWingOut -join "`n") -ForegroundColor Yellow
    exit 1
}

$examplesDir = Join-Path $root "examples"
if (Test-Path $examplesDir) {
    $exampleFiles = Get-ChildItem -Path $examplesDir -Filter "*.goose"
    foreach ($ex in $exampleFiles) {
        $checkExOut = & goose check $ex.FullName 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error: goose check $($ex.Name) failed." -ForegroundColor Red
            Write-Host ($checkExOut -join "`n") -ForegroundColor Yellow
            exit 1
        }
    }
}
$swCore.Stop()
Write-Host "  core, wing and examples typechecked cleanly in $($swCore.ElapsedMilliseconds) ms." -ForegroundColor Green

# Discover test suites
$testFiles = Get-ChildItem -Path $testsDir -Filter $Pattern | Where-Object { $_.Extension -eq ".goose" } | Sort-Object Name
if ($testFiles.Count -eq 0) {
    Write-Host "No test files matching '$Pattern' found in $testsDir." -ForegroundColor Yellow
    exit 0
}

# Check-only mode
if ($CheckOnly) {
    Write-Host "`n[2/$totalSteps] Running typecheck on $($testFiles.Count) suites..." -ForegroundColor Yellow
    $swCheck = [System.Diagnostics.Stopwatch]::StartNew()
    $failed = 0
    foreach ($file in $testFiles) {
        $out = & goose check $file.FullName 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error: typechecking $($file.Name) failed." -ForegroundColor Red
            Write-Host ($out -join "`n") -ForegroundColor Yellow
            $failed++
        }
    }
    $swCheck.Stop()
    if ($failed -gt 0) {
        exit 1
    }
    Write-Host "  All $($testFiles.Count) suites typechecked cleanly in $($swCheck.Elapsed.TotalSeconds.ToString('F2')) s." -ForegroundColor Green
    Write-Host "`nTypecheck complete ($($swCheck.Elapsed.TotalSeconds.ToString('F2')) s)." -ForegroundColor Green
    exit 0
}

# Parallel compilation
$maxConcurrent = if ($Jobs -gt 0) { [Math]::Min($Jobs, [Environment]::ProcessorCount) } else { 4 }
Write-Host "`n[2/$totalSteps] Compiling $($testFiles.Count) suites (max $maxConcurrent parallel, $optFlag)..." -ForegroundColor Yellow
$swBuild = [System.Diagnostics.Stopwatch]::StartNew()

if (-not (Test-Path $binDir)) {
    New-Item -ItemType Directory -Path $binDir -Force | Out-Null
}

$buildTasks = @()
$queue = [System.Collections.Queue]::new()
foreach ($file in $testFiles) {
    $exeName = Join-Path $binDir "$($file.BaseName).exe"
    $queue.Enqueue([PSCustomObject]@{
        File = $file
        Exe = $exeName
        Process = $null
        Stopwatch = $null
    })
}

$running = [System.Collections.ArrayList]::new()
$buildFailed = 0
$completedCount = 0
$totalCount = $queue.Count

while ($queue.Count -gt 0 -or $running.Count -gt 0) {
    while ($running.Count -lt $maxConcurrent -and $queue.Count -gt 0) {
        $task = $queue.Dequeue()
        $cmdArgs = "build $optFlag -o `"$($task.Exe)`" `"$($task.File.FullName)`""
        $task.Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $task.Process = Start-GooseProcess "goose" $cmdArgs $true
        [void]$running.Add($task)
        $buildTasks += $task
    }

    Start-Sleep -Milliseconds 50
    for ($i = $running.Count - 1; $i -ge 0; $i--) {
        $task = $running[$i]
        if ($task.Process.HasExited) {
            $completedCount++
            $task.Process.WaitForExit()
            $task.Stopwatch.Stop()
            $elapsedSec = $task.Stopwatch.Elapsed.TotalSeconds.ToString("F1")

            if ($task.Process.ExitCode -eq 0) {
                Write-Host "  [$completedCount/$totalCount] Built $($task.File.Name) ($elapsedSec s)" -ForegroundColor Green
            } else {
                Write-Host "  [$completedCount/$totalCount] [FAIL] $($task.File.Name) (code $($task.Process.ExitCode))" -ForegroundColor Red
                $out = $task.Process.StandardOutput.ReadToEnd()
                $err = $task.Process.StandardError.ReadToEnd()
                if ($out) { Write-Host $out -ForegroundColor Yellow }
                if ($err) { Write-Host $err -ForegroundColor Red }
                $buildFailed++
            }
            $running.RemoveAt($i)
        }
    }
}
$swBuild.Stop()

if ($buildFailed -ne 0) {
    Write-Host "Error: $buildFailed suite(s) failed to compile." -ForegroundColor Red
    exit 1
}
Write-Host "  All $($testFiles.Count) suites compiled cleanly in $($swBuild.Elapsed.TotalSeconds.ToString('F2')) s." -ForegroundColor Green

# Execute test suites
Write-Host "`n[3/$totalSteps] Executing verification suites..." -ForegroundColor Yellow
$swRun = [System.Diagnostics.Stopwatch]::StartNew()
$passedSuites = 0
$failedSuites = 0

foreach ($task in $buildTasks) {
    try {
        if (-not (Test-Path $task.Exe)) {
            Write-Host "  [FAIL] bin/$([System.IO.Path]::GetFileName($task.Exe)) executable not found" -ForegroundColor Red
            $failedSuites++
            continue
        }
        Write-Host "`nRunning tests/$($task.File.Name)..." -ForegroundColor Cyan
        $runProc = Start-GooseProcess $task.Exe "" $false
        $runProc.WaitForExit()
        if ($runProc.ExitCode -eq 0) {
            $passedSuites++
        } else {
            Write-Host "  [FAIL] bin/$([System.IO.Path]::GetFileName($task.Exe)) exited with code $($runProc.ExitCode)" -ForegroundColor Red
            $failedSuites++
        }
    } finally {
        if (-not $KeepBinaries -and (Test-Path $task.Exe)) {
            Remove-Item $task.Exe -Force -ErrorAction SilentlyContinue
        }
    }
}
$swRun.Stop()

$totalSeconds = $swCore.Elapsed.TotalSeconds + $swBuild.Elapsed.TotalSeconds + $swRun.Elapsed.TotalSeconds
Write-Host "`nSummary: $passedSuites/$($testFiles.Count) suites passed ($failedSuites failed)" -ForegroundColor $(if ($failedSuites -eq 0) { "Green" } else { "Red" })
Write-Host "Timing:  Build: $($swBuild.Elapsed.TotalSeconds.ToString('F2'))s | Run: $($swRun.Elapsed.TotalSeconds.ToString('F2'))s | Total: $($totalSeconds.ToString('F2'))s" -ForegroundColor Cyan

if ($failedSuites -ne 0) {
    exit 1
}

if ($Lit) {
    Write-Host "`n[$totalSteps/$totalSteps] Executing Goose LIT native verification suites..." -ForegroundColor Yellow
    $litScript = Join-Path $PSScriptRoot "test_lit.ps1"
    & powershell -ExecutionPolicy Bypass -File $litScript -Jobs $Jobs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Goose LIT verification suites failed." -ForegroundColor Red
        exit 1
    }
}

exit 0
