# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

<#
.SYNOPSIS
    Applies or checks SPDX Apache-2.0 and Copyright headers across goose-wing.

.PARAMETER Check
    Validates headers without writing changes (exits with code 1 on missing headers).

.PARAMETER DryRun
    Previews modifications without writing to disk.

.PARAMETER Ext
    Specific extension to filter (e.g. -Ext .goose).
#>
[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$DryRun,
    [string]$Ext
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$toolPath = Join-Path $repoRoot "tools\licensing.py"

$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Error "Python 3 is required to run tools/licensing.py but was not found on PATH."
    exit 1
}

$argsList = @()
if ($Check) { $argsList += "--check" }
if ($DryRun) { $argsList += "--dry-run" }
if ($Ext) { $argsList += "--ext", $Ext }

& python $toolPath @argsList
exit $LASTEXITCODE
