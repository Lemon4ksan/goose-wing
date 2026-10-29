# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

# scripts/lint_invariants.ps1
# Automated static enforcement of engineering clarity, anti-aliasing (zero pass-through wrappers),
# expanded input/output contracts (// Example:), zero-alloc loop invariants, formatting geometry,
# and linear git history.

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
$incompleteMarkers = '\b(TODO|FIXME|HACK|XXX)\b|simplified for now|placeholder implementation'

foreach ($file in $filesToScan) {
    $relPath = $file
    if ($file.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        $relPath = $file.Substring($root.Length).TrimStart('\', '/')
    }
    $isTestOrExample = ($relPath -match '^(tests|examples|bench|tools|core\\test)\\' -or $relPath -match '_test\.goose$')
    $lines = Get-Content -Path $file

    # Count function name occurrences in file to distinguish polymorphic overloads
    $fnCounts = @{}
    foreach ($ln in $lines) {
        if ($ln -match '^\s*(pub\s+)?(inline\s+)?fn\s+([A-Za-z0-9_]+)') {
            $n = $Matches[3]
            if ($fnCounts.ContainsKey($n)) { $fnCounts[$n]++ } else { $fnCounts[$n] = 1 }
        }
    }

    # Tracking state for geometry & complexity synergy
    $consecutiveBlankLines = 0
    $inFunction = $false
    $fnStartLine = 0
    $fnName = ""
    $fnBraceDepth = 0
    $fnHasLoop = $false
    $inLoop = $false
    $loopBraceDepth = 0

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $lineNum = $i + 1

        # Check: Consecutive blank lines
        if ($line.Trim() -eq "") {
            $consecutiveBlankLines++
            if ($consecutiveBlankLines -ge 2) {
                Write-Host "[LINT] ${relPath}:${lineNum} -> Multiple consecutive blank lines. Keep vertical rhythm to at most 1 blank line." -ForegroundColor Yellow
                $violations++
            }
        } else {
            $consecutiveBlankLines = 0
        }

        # Check: Tab characters (\t)
        if ($line -match '\t') {
            Write-Host "[LINT] ${relPath}:${lineNum} -> Tab character '\t' detected. Use strictly 4 spaces per indentation level." -ForegroundColor Red
            $violations++
        }

        # Check: Trailing whitespace
        if ($line -match '[ \t]+$') {
            Write-Host "[LINT] ${relPath}:${lineNum} -> Trailing whitespace detected." -ForegroundColor Yellow
            $violations++
        }

        # Check: Hard line length ceiling (120 columns)
        if ($line.Length -gt 120) {
            $isExempt = ($line -match 'https?://') -or 
                        ($line -match '//\s*(CHECK|RUN):') -or 
                        ($line -match '"[^"]{35,}"') -or 
                        ($line -match '^\s*//\s*(RFC|Vector|Table|https?://)')
            if (-not $isExempt) {
                Write-Host "[LINT] ${relPath}:${lineNum} -> Line exceeds hard ceiling of 120 columns ($($line.Length) chars). Break expressions or invert guards." -ForegroundColor Yellow
                $violations++
            }
        }

        # Rule 1: Pass-through function alias detection
        if ($line -match '^\s*(pub\s+)?(inline\s+)?fn\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)') {
            $curFn = $Matches[3]
            $rawParams = $Matches[4].Trim()
            $isOverload = ($fnCounts[$curFn] -gt 1)
            $isContainerTraitMethod = ($curFn -in @('append', 'push', 'clear', 'reset', 'do'))

            if (-not $isOverload -and -not $isContainerTraitMethod) {
                $paramNames = @()
                if ($rawParams -ne "") {
                    $parts = $rawParams -split ','
                    foreach ($p in $parts) {
                        $pTrim = $p.Trim()
                        if ($pTrim -match '^([A-Za-z0-9_]+)\s*:') {
                            $paramNames += $Matches[1]
                        }
                    }
                }
                $expectedArgStr = ($paramNames -join ', ')

                $callee = ""
                $callArgs = ""
                if ($line -match '\{\s*(return\s+)?([A-Za-z0-9_:]+)\s*\(([^)]*)\)\s*;\s*\}') {
                    $callee = $Matches[2]
                    $callArgs = ($Matches[3] -split ',' | ForEach-Object { $_.Trim() }) -join ', '
                } elseif (($i + 2) -lt $lines.Count -and $line -match '\{\s*$') {
                    $nextLine = $lines[$i + 1].Trim()
                    $closeLine = $lines[$i + 2].Trim()
                    if ($closeLine -eq '}' -and $nextLine -match '^(return\s+)?([A-Za-z0-9_:]+)\s*\(([^)]*)\)\s*;$') {
                        $callee = $Matches[2]
                        $callArgs = ($Matches[3] -split ',' | ForEach-Object { $_.Trim() }) -join ', '
                    }
                }

                # Exclude C FFI extern boundaries (native_* / wing_*)
                if ($callee -ne "" -and $callee -notmatch '^(native_|wing_)' -and $paramNames.Count -gt 0 -and $callArgs -eq $expectedArgStr -and $callee -ne $curFn) {
                    Write-Host "[LINT] ${relPath}:${lineNum} -> Meaningless pass-through function alias '$curFn' simply calls '$callee($callArgs)' with identical arguments." -ForegroundColor Red
                    $violations++
                }
            }
        }

        # Rule 1b: Redundant 0-arg struct constructor wrapper detection
        # Detects fn new_foo() -> Foo { return Foo { .. }; }
        if ($line -match '^\s*(pub\s+)?(inline\s+)?fn\s+([A-Za-z0-9_]+)\s*\(\s*\)\s*->\s*([A-Za-z0-9_:]+)') {
            $curFn = $Matches[3]
            $retType = $Matches[4]
            $baseRetType = ($retType -split ':')[-1]

            $structConstructed = ""
            if ($line -match '\{\s*(return\s+)?([A-Za-z0-9_:]+)\s*\{\s*\.\.\s*\}\s*;\s*\}') {
                $structConstructed = ($Matches[2] -split ':')[-1]
            } elseif (($i + 2) -lt $lines.Count -and $line -match '\{\s*$') {
                $nextLine = $lines[$i + 1].Trim()
                $closeLine = $lines[$i + 2].Trim()
                if ($closeLine -eq '}' -and $nextLine -match '^(return\s+)?([A-Za-z0-9_:]+)\s*\{\s*\.\.\s*\}\s*;$') {
                    $structConstructed = ($Matches[2] -split ':')[-1]
                }
            }

            if ($structConstructed -ne "" -and $structConstructed -eq $baseRetType) {
                Write-Host "[LINT] ${relPath}:${lineNum} -> Redundant 0-arg struct constructor wrapper '$curFn' merely returns '$baseRetType { .. }'. Use native struct default syntax directly at call sites." -ForegroundColor Red
                $violations++
            }
        }

        # Rule 2: No primitive or slice type aliases
        if ($line -match '^\s*type\s+([A-Za-z0-9_]+)\s*=\s*(const\s+)?(u8|u16|u32|u64|i8|i16|i32|i64|bool|f32|f64|usize|isize)(\[.*\])?') {
            Write-Host "[LINT] ${relPath}:${lineNum} -> Redundant primitive/slice type alias '$($Matches[1])'. Use canonical Goose types directly." -ForegroundColor Red
            $violations++
        }

        # Rule 3: No import namespace aliasing
        if ($line -match '^\s*import\s+[A-Za-z0-9_\.]+\s+as\s+([A-Za-z0-9_]+)') {
            Write-Host "[LINT] ${relPath}:${lineNum} -> Namespace alias 'as $($Matches[1])' prohibited." -ForegroundColor Red
            $violations++
        }

        # Rule 4: No deprecated prefix extern syntax
        if ($line -match '^\s*extern\s+"[^"]+"\s+fn\s+') {
            Write-Host "[LINT] ${relPath}:${lineNum} -> Deprecated prefix extern syntax. Place symbol after signature: extern fn foo() = `"sym`";" -ForegroundColor Red
            $violations++
        }

        # Rule 5: Comment hygiene (AI buzzwords, robotic panic disclaimers, and TODO/placeholder markers)
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
            if (-not $isTestOrExample -and $commentText -cmatch $incompleteMarkers) {
                Write-Host "[LINT] ${relPath}:${lineNum} -> Incomplete code marker ('$($Matches[0])') prohibited in production modules." -ForegroundColor Red
                $violations++
            }
        }

        # Rule 6: Expanded // Example: Input/Output Contract Coverage
        if ($StrictExamples -and -not $isTestOrExample) {
            if ($line -match '^\s*(pub\s+)?(inline\s+)?fn\s+([A-Za-z0-9_]+)(<[^>]+>)?\s*\(([^)]*)\)\s*(->\s*([^\{]+))?') {
                $name = $Matches[3]
                $params = $Matches[5]
                $ret = $Matches[7]

                $isExempt = ($name -match '^(new_|is_|has_|get_|set_|len|cap|clear|reset|init_|alloc_)') -or
                            ($name -in @('append', 'push', 'clear', 'reset', 'do', 'next'))

                if (-not $isExempt) {
                    $needsExample = $false
                    $reason = ""

                    # Category A: Advances a wire cursor or SliceReader
                    if ($params -match '\b(idx|pos|offset)\s*:\s*(i64|u64|usize|i32|u32)&' -or
                        $params -match '\b(r|rd|reader|sr)\s*:\s*(core::)?(SliceReader|WireReader)&') {
                        $needsExample = $true
                        $reason = "advances a wire cursor or SliceReader"
                    }
                    # Category B: Consumes a wire slice and returns (consumed_len, bool) or (token, bool)
                    elseif ($params -match '\b(s|raw|buf|src|input)\s*:\s*(const\s+)?u8\[:\]' -and 
                            ($ret -match '\b(i64|u64|usize|i32|u32)\s*,\s*bool' -or $ret -match '(const\s+)?u8\[:\]\s*,\s*bool')) {
                        $needsExample = $true
                        $reason = "consumes a wire slice and returns (consumed_len, bool)"
                    }
                    # Category C: RFC grammar parsers, decoders, and extractors
                    elseif ($name -match '^(parse|decode|extract|scan)_') {
                        $needsExample = $true
                        $reason = "parses wire tokens or RFC grammar"
                    }
                    # Category D: Wire transformers, sanitizers, and bitmask builders
                    elseif ($name -match '^(unescape|escape|sanitize)_' -or $name -match '^build_.*_type') {
                        $needsExample = $true
                        $reason = "transforms wire tokens or builds wire type bitmasks"
                    }

                    if ($needsExample) {
                        $hasExample = $false
                        $lookback = [Math]::Max(0, $i - 15)
                        for ($k = $lookback; $k -lt $i; $k++) {
                            if ($lines[$k] -match '//\s*Example(:|s:)?') {
                                $hasExample = $true
                                break
                            }
                        }
                        if (-not $hasExample) {
                            Write-Host "[LINT] ${relPath}:${lineNum} -> Function '$name' $reason but is missing an input/output contract block ('// Example:')." -ForegroundColor Yellow
                            $violations++
                        }
                    }
                }
            }
        }

        # Rule 9: Prohibition of intermediate out-parameters for pure computations
        if (-not $isTestOrExample -and $line -match '^\s*(pub\s+)?(inline\s+)?fn\s+([A-Za-z0-9_]+)\b.*?(out_[a-zA-Z0-9_]*(hex|ha\d+|response_hex)\s*:\s*[^,)]+&)') {
            Write-Host "[LINT] ${relPath}:${lineNum} -> C-style intermediate out-parameter '$($Matches[4])' prohibited in '$($Matches[3])'. Return value directly via RVO ('-> u8[..N]')." -ForegroundColor Red
            $violations++
        }

        # Rule 10: Prohibition of artificial slice/cursor wrappers in parsers (Lingua Franca is const u8[:])
        if (-not $isTestOrExample -and $line -match '^\s*(pub\s+)?(inline\s+)?fn\s+(parse_[a-zA-Z0-9_]+|decode_[a-zA-Z0-9_]+|demux_[a-zA-Z0-9_]+)\b.*?\b([A-Za-z0-9_]+:\s*(core::)?(SliceReader|ByteCursor|WireReader)&)') {
            if ($relPath -notmatch '^(core\\io|quic\\frames)\.goose$') {
                Write-Host "[LINT] ${relPath}:${lineNum} -> Parser '$($Matches[3])' takes artificial cursor wrapper '$($Matches[4])'. Lingua franca is 'const u8[:]' with 'idx: i64&'." -ForegroundColor Red
                $violations++
            }
        }

        # Track Function Geometry, Nesting Depth, and Zero Heap Allocation in Loops
        if ($line -match '^\s*(pub\s+)?(inline\s+)?fn\s+([A-Za-z0-9_]+)') {
            $inFunction = $true
            $fnStartLine = $lineNum
            $fnName = $Matches[3]
            $fnBraceDepth = 0
            $fnHasLoop = $false
            $inLoop = $false
            $loopBraceDepth = 0
        }

        if ($inFunction) {
            # Check Nesting Depth Ceiling (maximum 3 levels, indentation <= 16 spaces from col 0)
            if (-not $isTestOrExample -and $line.Trim() -ne "" -and -not ($line -match '^\s*//')) {
                $trimmed = $line.TrimStart(' ')
                $indent = $line.Length - $trimmed.Length
                if ($indent -ge 20) {
                    Write-Host "[LINT] ${relPath}:${lineNum} -> Excessive nesting depth (indented $indent spaces >= 20). Maximum allowed nesting is 3 levels (16 spaces). Flatten with guard clauses." -ForegroundColor Red
                    $violations++
                }
            }

            # Check loop start
            if ($line -match '^\s*(while|for)\b') {
                $fnHasLoop = $true
                $inLoop = $true
                $loopBraceDepth = $fnBraceDepth
            }

            # Check Zero Heap Allocation in Loops
            if (-not $isTestOrExample -and $inLoop -and $line -match '^\s*var\s+[A-Za-z0-9_]+\s*:\s*[A-Za-z0-9_]*\[>\.\.\]') {
                Write-Host "[LINT] ${relPath}:${lineNum} -> Dynamic heap allocation inside loop ('var ...: ...[>..]'). Hoist buffer outside loop and call .clear()." -ForegroundColor Red
                $violations++
            }

            # Update brace depth
            $openCount = ([regex]::Matches($line, '\{')).Count
            $closeCount = ([regex]::Matches($line, '\}')).Count
            $fnBraceDepth += ($openCount - $closeCount)

            if ($inLoop -and $fnBraceDepth -le $loopBraceDepth) {
                $inLoop = $false
            }

            # Exited function
            if ($fnBraceDepth -le 0 -and ($openCount -gt 0 -or $closeCount -gt 0)) {
                $fnLen = $lineNum - $fnStartLine + 1
                if (-not $isTestOrExample -and $fnHasLoop -and $fnLen -gt 65) {
                    Write-Host "[LINT] ${relPath}:${fnStartLine} -> Loop-containing function '$fnName' exceeds 65 lines ($fnLen lines). Extract loop body to preserve cache locality and keep G-CRAP <= 25.0." -ForegroundColor Yellow
                    $violations++
                }
                $inFunction = $false
            }
        }
    }
}

if ($violations -gt 0) {
    Write-Host "`n[LINT REJECTED] Found $violations invariant violation(s)." -ForegroundColor Red
    exit 1
}

Write-Host "[LINT PASSED] All code clarity, anti-aliasing, geometry, and history invariants satisfied." -ForegroundColor Green
exit 0
