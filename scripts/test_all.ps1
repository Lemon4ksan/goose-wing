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

# Helper to start process with reliable ExitCode
function Start-GooseProcess([string]$fileName, [string]$cmdArgs) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $fileName
    $psi.Arguments = $cmdArgs
    $psi.UseShellExecute = $false
    return [System.Diagnostics.Process]::Start($psi)
}

# 1. Typecheck library core
Write-Host "`n[1/3] Typechecking wing library..." -ForegroundColor Yellow
$swCore = [System.Diagnostics.Stopwatch]::StartNew()
$wingPath = Join-Path $root "wing.goose"
$checkProc = Start-GooseProcess "goose" "check `"$wingPath`""
$checkProc.WaitForExit()
$swCore.Stop()
if ($checkProc.ExitCode -ne 0) {
    Write-Host "FATAL: goose check wing.goose failed!" -ForegroundColor Red
    exit 1
}
Write-Host "  OK: wing library typechecked cleanly in $($swCore.ElapsedMilliseconds)ms." -ForegroundColor Green

# 2. Discover test suites
$testFiles = Get-ChildItem -Path $testsDir -Filter $Pattern | Sort-Object Name
if ($testFiles.Count -eq 0) {
    Write-Host "No test files matching '$Pattern' found in $testsDir." -ForegroundColor Yellow
    exit 0
}

# 3. Check-only mode (ultra fast, ~1.5s for all suites)
if ($CheckOnly) {
    Write-Host "`n[2/2] Running multi-test typecheck on $($testFiles.Count) suites..." -ForegroundColor Yellow
    $swCheck = [System.Diagnostics.Stopwatch]::StartNew()
    $fileList = ($testFiles | ForEach-Object { "`"$($_.FullName)`"" }) -join " "
    $multiProc = Start-GooseProcess "goose" ("--check --multi-test " + $fileList)
    $multiProc.WaitForExit()
    $swCheck.Stop()
    if ($multiProc.ExitCode -ne 0) {
        Write-Host "FATAL: Test typechecking failed!" -ForegroundColor Red
        exit 1
    }
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host " All $($testFiles.Count) suites typechecked cleanly in $($swCheck.Elapsed.TotalSeconds.ToString('F2'))s!" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Cyan
    exit 0
}

# 4. Parallel compilation using CPU cores
Write-Host "`n[2/3] Compiling $($testFiles.Count) suites in parallel ($optFlag)..." -ForegroundColor Yellow
$swBuild = [System.Diagnostics.Stopwatch]::StartNew()

$buildTasks = @()
foreach ($file in $testFiles) {
    $exeName = [System.IO.Path]::ChangeExtension($file.FullName, ".exe")
    $args = "build $optFlag -o `"$exeName`" `"$($file.FullName)`""
    $proc = Start-GooseProcess "goose" $args
    $buildTasks += [PSCustomObject]@{
        File = $file
        Exe = $exeName
        Process = $proc
    }
}

$buildFailed = 0
foreach ($task in $buildTasks) {
    $task.Process.WaitForExit()
    if ($task.Process.ExitCode -ne 0) {
        Write-Host "  FAIL: Build error for $($task.File.Name)" -ForegroundColor Red
        $buildFailed++
    }
}
$swBuild.Stop()

if ($buildFailed -ne 0) {
    Write-Host "FATAL: $buildFailed suite(s) failed to compile!" -ForegroundColor Red
    exit 1
}
Write-Host "  OK: All $($testFiles.Count) suites compiled in $($swBuild.Elapsed.TotalSeconds.ToString('F2'))s." -ForegroundColor Green

# 5. Execute test suites
Write-Host "`n[3/3] Executing verification suites..." -ForegroundColor Yellow
$swRun = [System.Diagnostics.Stopwatch]::StartNew()
$passedSuites = 0
$failedSuites = 0

foreach ($task in $buildTasks) {
    try {
        Write-Host "`n>>> Running tests/$($task.File.Name)..." -ForegroundColor Cyan
        $runProc = Start-GooseProcess $task.Exe ""
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
