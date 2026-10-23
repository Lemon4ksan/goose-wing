# scripts/test_all.ps1
# Automated test runner for goose-wing verification suites.
param(
    [string]$Pattern = "*_test.goose",
    [switch]$KeepBinaries
)

$root = Split-Path -Parent $PSScriptRoot
$testsDir = Join-Path $root "tests"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " goose-wing Comprehensive Verification Suite Runner" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Typecheck wing.goose first
Write-Host "`n[1/2] Checking wing library type integrity (goose check wing.goose)..." -ForegroundColor Yellow
$checkProcess = Start-Process -FilePath "goose" -ArgumentList "check", (Join-Path $root "wing.goose") -NoNewWindow -PassThru -Wait
if ($checkProcess.ExitCode -ne 0) {
    Write-Host "FATAL: goose check failed with exit code $($checkProcess.ExitCode)!" -ForegroundColor Red
    exit 1
}
Write-Host "  OK: Library typechecked cleanly." -ForegroundColor Green

# 2. Discover and execute test suites
$testFiles = Get-ChildItem -Path $testsDir -Filter $Pattern | Sort-Object Name
Write-Host "`n[2/2] Running $($testFiles.Count) test suites in $testsDir..." -ForegroundColor Yellow

$passedSuites = 0
$failedSuites = 0
$totalStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

foreach ($file in $testFiles) {
    $exeName = [System.IO.Path]::ChangeExtension($file.FullName, ".exe")
    $relPath = "tests/$($file.Name)"
    Write-Host "`n>>> Compiling & Running $relPath..." -ForegroundColor Cyan

    $buildProcess = Start-Process -FilePath "goose" -ArgumentList "build", "-o", $exeName, $file.FullName -NoNewWindow -PassThru -Wait
    if ($buildProcess.ExitCode -ne 0) {
        Write-Host "  FAIL: Build failed for $relPath (code $($buildProcess.ExitCode))" -ForegroundColor Red
        $failedSuites++
        continue
    }

    try {
        $runProcess = Start-Process -FilePath $exeName -NoNewWindow -PassThru -Wait
        if ($runProcess.ExitCode -eq 0) {
            $passedSuites++
        } else {
            Write-Host "  FAIL: Test suite $relPath returned exit code $($runProcess.ExitCode)" -ForegroundColor Red
            $failedSuites++
        }
    } finally {
        if (-not $KeepBinaries -and (Test-Path $exeName)) {
            Remove-Item $exeName -Force -ErrorAction SilentlyContinue
        }
    }
}

$totalStopwatch.Stop()
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " Summary: $passedSuites/$($testFiles.Count) suites passed ($failedSuites failed) in $($totalStopwatch.Elapsed.TotalSeconds.ToString('F2'))s" -ForegroundColor $(if ($failedSuites -eq 0) { "Green" } else { "Yellow" })
Write-Host "============================================================" -ForegroundColor Cyan

if ($failedSuites -ne 0) {
    exit 1
}
exit 0
