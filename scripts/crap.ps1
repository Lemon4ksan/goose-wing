# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

# scripts/crap.ps1
# Local runner for goose-lit crap risk radar in goose-wing.

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CrapArgs
)

$root = Split-Path -Parent $PSScriptRoot
$litBin = Join-Path $root "..\goose-lit\bin\goose-lit.exe"

# If binary does not exist, build it from sibling goose-lit repository
if (-not (Test-Path $litBin)) {
    $litDir = Join-Path $root "..\goose-lit"
    if (Test-Path (Join-Path $litDir "bin.goose")) {
        Write-Host "Building native goose-lit..." -ForegroundColor Cyan
        & goose build --cc gcc -O2 -o "$litBin" (Join-Path $litDir "bin.goose")
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error: Failed to compile goose-lit." -ForegroundColor Red
            exit $LASTEXITCODE
        }
    } else {
        $cmd = Get-Command "goose-lit" -ErrorAction SilentlyContinue
        if ($cmd) {
            $litBin = $cmd.Source
        } else {
            Write-Host "Error: goose-lit binary not found. Please clone goose-lit beside goose-wing." -ForegroundColor Red
            exit 1
        }
    }
}

if ($CrapArgs.Count -eq 0) {
    # Default scan: analyze goose-wing core and http
    Write-Host "Running default goose-lit crap risk audit on goose-wing..." -ForegroundColor Cyan
    & $litBin crap $root --threshold 25.0 --format table
} else {
    & $litBin crap @CrapArgs
}
exit $LASTEXITCODE
