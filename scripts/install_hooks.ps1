# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

# scripts/install_hooks.ps1
# Configures git to use .githooks for automated pre-commit G-CRAP gating.

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $root

try {
    Write-Host "Configuring git hooks path to .githooks..." -ForegroundColor Cyan
    & git config core.hooksPath .githooks
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Successfully configured core.hooksPath = .githooks" -ForegroundColor Green
        Write-Host "Pre-commit gate active: format check, typecheck, and G-CRAP ceiling 25 enforcement." -ForegroundColor Cyan
    } else {
        Write-Host "Failed to configure git hooks path." -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}
