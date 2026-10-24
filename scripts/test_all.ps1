# scripts/test_all.ps1
# High-performance parallel verification runner for goose-wing.
param(
    [string]$Pattern = "*_test.goose",
    [switch]$CheckOnly,
    [switch]$Release,
    [switch]$KeepBinaries
)

$root = Split-Path -Parent $PSScriptRoot
$testsDir = Join-Path $root "tests"
$optFlag = if ($Release) { "-O2" } else { "-O0" }

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " goose-wing High-Performance Test Runner" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Helper to start process with redirected output (avoids terminal cursor collisions)
function Start-GooseProcess([string]$fileName, [string]$cmdArgs, [bool]$redirect = $true) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $fileName
    $psi.Arguments = $cmdArgs
    $psi.UseShellExecute = $false
    if ($redirect) {
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
    }
    return [System.Diagnostics.Process]::Start($psi)
}

# 1. Typecheck library core
Write-Host "`n[1/3] Typechecking wing library..." -ForegroundColor Yellow
$swCore = [System.Diagnostics.Stopwatch]::StartNew()
$wingPath = Join-Path $root "wing.goose"
$checkProc = Start-GooseProcess "goose" "check `"$wingPath`"" $true
$checkOut = $checkProc.StandardOutput.ReadToEnd()
$checkProc.WaitForExit()
$swCore.Stop()

if ($checkProc.ExitCode -ne 0) {
    Write-Host "FATAL: goose check wing.goose failed!" -ForegroundColor Red
    Write-Host $checkOut -ForegroundColor Yellow
    exit 1
}
Write-Host "  OK: wing library typechecked cleanly in $($swCore.ElapsedMilliseconds)ms." -ForegroundColor Green

# 2. Discover test suites
$testFiles = Get-ChildItem -Path $testsDir -Filter $Pattern | Where-Object { $_.Extension -eq ".goose" } | Sort-Object Name
if ($testFiles.Count -eq 0) {
    Write-Host "No test files matching '$Pattern' found in $testsDir." -ForegroundColor Yellow
    exit 0
}

# 3. Check-only mode
if ($CheckOnly) {
    Write-Host "`n[2/2] Running typecheck on $($testFiles.Count) suites..." -ForegroundColor Yellow
    $swCheck = [System.Diagnostics.Stopwatch]::StartNew()
    $failed = 0
    foreach ($file in $testFiles) {
        $proc = Start-GooseProcess "goose" "check `"$($file.FullName)`"" $true
        $out = $proc.StandardOutput.ReadToEnd()
        $err = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit()
        if ($proc.ExitCode -ne 0) {
            Write-Host "FATAL: Typechecking $($file.Name) failed!" -ForegroundColor Red
            if ($out) { Write-Host $out -ForegroundColor Yellow }
            if ($err) { Write-Host $err -ForegroundColor Red }
            $failed++
        }
    }
    $swCheck.Stop()
    if ($failed -gt 0) {
        exit 1
    }
    Write-Host "  OK: All $($testFiles.Count) suites typechecked cleanly in $($swCheck.Elapsed.TotalSeconds.ToString('F2'))s." -ForegroundColor Green
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host " Typecheck Complete: 100% Valid ($($swCheck.Elapsed.TotalSeconds.ToString('F2'))s)" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Cyan
    exit 0
}

# 4. Parallel compilation using bounded worker pool (prevents temp file collisions & I/O thrashing)
$maxConcurrent = [Math]::Min(8, [Environment]::ProcessorCount)
Write-Host "`n[2/3] Compiling $($testFiles.Count) suites (max $maxConcurrent parallel, $optFlag)..." -ForegroundColor Yellow
$swBuild = [System.Diagnostics.Stopwatch]::StartNew()

$buildTasks = @()
$queue = [System.Collections.Queue]::new()
foreach ($file in $testFiles) {
    $exeName = [System.IO.Path]::ChangeExtension($file.FullName, ".exe")
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
                Write-Host "  [$completedCount/$totalCount] FAIL: $($task.File.Name) (code $($task.Process.ExitCode))" -ForegroundColor Red
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
    Write-Host "FATAL: $buildFailed suite(s) failed to compile!" -ForegroundColor Red
    exit 1
}
Write-Host "  OK: All $($testFiles.Count) suites compiled cleanly in $($swBuild.Elapsed.TotalSeconds.ToString('F2'))s." -ForegroundColor Green

# 5. Execute test suites sequentially with formatted reports
Write-Host "`n[3/3] Executing verification suites..." -ForegroundColor Yellow
$swRun = [System.Diagnostics.Stopwatch]::StartNew()
$passedSuites = 0
$failedSuites = 0

foreach ($task in $buildTasks) {
    try {
        if (-not (Test-Path $task.Exe)) {
            Write-Host "  FAIL: tests/$($task.File.Name) executable not found" -ForegroundColor Red
            $failedSuites++
            continue
        }
        Write-Host "`n>>> Running tests/$($task.File.Name)..." -ForegroundColor Cyan
        $runProc = Start-GooseProcess $task.Exe "" $false
        $runProc.WaitForExit()
        if ($runProc.ExitCode -eq 0) {
            $passedSuites++
        } else {
            Write-Host "  FAIL: tests/$($task.File.Name) exited with code $($runProc.ExitCode)" -ForegroundColor Red
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
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " Summary: $passedSuites/$($testFiles.Count) suites passed ($failedSuites failed)" -ForegroundColor $(if ($failedSuites -eq 0) { "Green" } else { "Red" })
Write-Host " Timing:  Build: $($swBuild.Elapsed.TotalSeconds.ToString('F2'))s | Run: $($swRun.Elapsed.TotalSeconds.ToString('F2'))s | Total: $($totalSeconds.ToString('F2'))s" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

if ($failedSuites -ne 0) {
    exit 1
}
exit 0
