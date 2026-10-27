# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

# scripts/crap.ps1
# Local runner for goose-crap risk radar in goose-wing.
# TODO: make a goose-crap github ci/cd
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CrapArgs
)

$root = Split-Path -Parent $PSScriptRoot
$crapBin = Join-Path $root "..\goose-crap\bin\goose-crap.exe"

# If binary does not exist, build it from sibling goose-crap repository
if (-not (Test-Path $crapBin)) {
    $crapDir = Join-Path $root "..\goose-crap"
    if (Test-Path (Join-Path $crapDir "bin.goose")) {
        Write-Host "Building native goose-crap..." -ForegroundColor Cyan
        & goose build -o "$crapBin" (Join-Path $crapDir "bin.goose")
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error: Failed to compile goose-crap." -ForegroundColor Red
            exit $LASTEXITCODE
        }
    } else {
        # Check PATH
        $cmd = Get-Command "goose-crap" -ErrorAction SilentlyContinue
        if ($cmd) {
            $crapBin = $cmd.Source
        } else {
            Write-Host "Error: goose-crap binary not found. Please clone goose-crap beside goose-wing." -ForegroundColor Red
            exit 1
        }
    }
}

if ($CrapArgs.Count -eq 0) {
    # Default scan: analyze goose-wing core, http, http3, quic, and tls
    Write-Host "Running default goose-crap risk audit on goose-wing..." -ForegroundColor Cyan
    & $crapBin $root --threshold 25.0 --format table
} else {
    & $crapBin @CrapArgs
}
exit $LASTEXITCODE
