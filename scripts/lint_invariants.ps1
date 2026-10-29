# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

# scripts/lint_invariants.ps1
# Automated static enforcement of engineering clarity, anti-aliasing,
# documentation hygiene, and linear git history invariants.

param(
    [string]$TargetFile = "",
    [switch]$Staged,
    [switch]$StrictExamples
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$violations = 0

# 1. Enforce Linear Git History (Reject active merge commits)
$mergeHead = Join-Path $root ".git\MERGE_HEAD"
if (Test-Path $mergeHead) {
    Write-Host "[LINT REJECTED] Linear history violation: .git/MERGE_HEAD detected. Merge commits are prohibited; use rebase or fast-forward." -ForegroundColor Red
    exit 1
}

# 2. Collect files to inspect
$filesToScan = @()
if ($TargetFile -ne "") {
    if (Test-Path $TargetFile) {
        $filesToScan += (Resolve-Path $TargetFile).Path
    }
} elseif ($Staged) {
    $stagedRaw = & git diff --cached --name-only --diff-filter=ACM 2>$null
    foreach ($f in $stagedRaw) {
        if ($f -match '\.goose$') {
            $full = Join-Path $root $f
            if (Test-Path $full) {
                $filesToScan += $full
            }
        }
    }
} else {
    $filesToScan = Get-ChildItem -Path $root -Recurse -Filter "*.goose" -File |
        Where-Object { $_.FullName -notmatch '\\(vendor|scratch|\.gemini)\\' } |
        Select-Object -ExpandProperty FullName
}

$aiBuzzwords = '\b(crucial|robust|seamlessly|comprehensive|delve|meticulously|pivotal|game-changer|plethora|tapestry|leverage)\b'
$roboticNoise = '\b(does not panic|will not panic|never panics)\b'

foreach ($file in $filesToScan) {
    $relPath = $file
    if ($file.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        $relPath = $file.Substring($root.Length).TrimStart('\', '/')
    }
    $lines = Get-Content -Path $file

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $lineNum = $i + 1

        # Rule 1: No primitive or slice type aliases
        if ($line -match '^\s*type\s+([A-Za-z0-9_]+)\s*=\s*(const\s+)?(u8|u16|u32|u64|i8|i16|i32|i64|bool|f32|f64)') {
            Write-Host "[LINT] ${relPath}:${lineNum} -> Redundant primitive/slice type alias '$($Matches[1])'. Use canonical Goose types directly." -ForegroundColor Red
            $violations++
        }

        # Rule 2: No import namespace aliasing
        if ($line -match '^\s*import\s+[A-Za-z0-9_\.]+\s+as\s+([A-Za-z0-9_]+)') {
            Write-Host "[LINT] ${relPath}:${lineNum} -> Namespace alias 'as $($Matches[1])' prohibited unless resolving hard collision." -ForegroundColor Red
            $violations++
        }

        # Rule 3: No deprecated prefix extern syntax
        if ($line -match '^\s*extern\s+"[^"]+"\s+fn\s+') {
            Write-Host "[LINT] ${relPath}:${lineNum} -> Deprecated prefix extern syntax. Place symbol after signature: extern fn foo() = `"sym`";" -ForegroundColor Red
            $violations++
        }

        # Rule 4: Comment hygiene (AI buzzwords & robotic panic disclaimers)
        if ($line -match '//(.*)$') {
            $commentText = $Matches[1]
            if ($commentText -imatch $aiBuzzwords) {
                Write-Host "[LINT] ${relPath}:${lineNum} -> Banned AI buzzword '$($Matches[1])' in comment." -ForegroundColor Red
                $violations++
            }
            if ($commentText -imatch $roboticNoise) {
                Write-Host "[LINT] ${relPath}:${lineNum} -> Robotic noise '$($Matches[1])' in comment. Only document failure conditions, not absence of panics." -ForegroundColor Red
                $violations++
            }
        }

        # Rule 5: No consecutive raw bool parameters (boolean trap)
        if ($line -match '^\s*(inline\s+)?fn\s+([A-Za-z0-9_]+).*\:\s*bool\s*,\s*[A-Za-z0-9_]+\s*:\s*bool') {
            Write-Host "[LINT] ${relPath}:${lineNum} -> Function '$($Matches[2])' has consecutive raw 'bool' parameters (boolean trap). Use explicit enums or config structs." -ForegroundColor Red
            $violations++
        }

        # Rule 6: Cursor-advancing parser functions should include // Example:
        if ($StrictExamples -and ($relPath -notmatch '^(tests|examples|bench)\\')) {
            if ($line -match '^\s*fn\s+(parse|decode|extract|scan)_([A-Za-z0-9_]+).*\b(idx|pos|offset)\s*:\s*(i64|u64|i32|u32)&') {
                $fnName = "$($Matches[1])_$($Matches[2])"
                $hasExample = $false
                $lookback = [Math]::Max(0, $i - 12)
                for ($k = $lookback; $k -lt $i; $k++) {
                    if ($lines[$k] -match '//\s*Example:') {
                        $hasExample = $true
                        break
                    }
                }
                if (-not $hasExample) {
                    Write-Host "[LINT] ${relPath}:${lineNum} -> Cursor-advancing function '$fnName' is missing a '// Example:' input/output contract block." -ForegroundColor Yellow
                    $violations++
                }
            }
        }
    }
}

if ($violations -gt 0) {
    Write-Host "`n[LINT REJECTED] Found $violations invariant violation(s)." -ForegroundColor Red
    exit 1
}

Write-Host "[LINT PASSED] All code clarity, anti-aliasing, and history invariants satisfied." -ForegroundColor Green
exit 0
