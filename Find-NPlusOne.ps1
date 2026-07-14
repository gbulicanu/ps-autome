#!/usr/bin/env pwsh
#Requires -Version 7.0
<#
.SYNOPSIS
    Scans a repository for likely N+1 query problems in C# / EF Core code.

.NOTES
    Cross-platform: uses only .NET/PowerShell APIs available in PowerShell 7+ (pwsh) on
    Windows, macOS, and Linux - no Windows-only cmdlets, COM, or backslash-only path logic.

    On macOS/Linux, either run it via `pwsh ./Find-NPlusOne.ps1 <RepoPath>`, or make it
    directly executable once:
        chmod +x Find-NPlusOne.ps1
        ./Find-NPlusOne.ps1 <RepoPath>
    (the shebang line above requires `pwsh` to be on your PATH; install it from
    https://aka.ms/install-powershell or `brew install powershell` on macOS).

.DESCRIPTION
    Find-NPlusOne.ps1 walks a repo directory, looks at every *.cs file, and uses a set of
    regex/structural heuristics to flag code that is likely to cause the N+1 query problem
    with Entity Framework Core (a query executed once per loop iteration instead of once
    up front, e.g. via .Include()/.ToList() before the loop).

    This is STATIC, HEURISTIC analysis (no Roslyn/semantic model). It is a fast first pass
    to point you at suspicious loops - always eyeball the flagged lines. It is intentionally
    biased towards false positives over false negatives (better to review a few extra lines
    than silently miss a real N+1).

    Detected patterns:
      1. EF-Query-In-Loop        - A DbSet/LINQ query-executing call (Where, First, ToList,
                                    Count, Find, Load, ...; sync or *Async) is invoked inside
                                    the body of a for/foreach/while loop.
      2. Navigation-Enumeration  - A chained member-access + enumeration call that looks like
                                    a lazy-loaded navigation property being materialized
                                    inside a loop (e.g. order.Items.Count(), cust.Orders.ToList()).
      3. Async-Query-In-Loop     - An `await ...Async(` EF Core call inside a loop body.
      4. Missing-Include-Hint    - The loop iterates over a query result that has no
                                    .Include( on the same statement/nearby lines, AND the loop
                                    body dereferences a second-level navigation property.
                                    Lower-confidence, informational only.

.PARAMETER RepoPath
    Path to the repository (or any directory) to scan. Required, positional.

.PARAMETER OutputFormat
    Console (default), Markdown, or Json.

.PARAMETER OutputPath
    Optional file path to write the report to (in addition to, or instead of, console).
    If omitted with Markdown/Json, the report is printed to the console.

.PARAMETER IncludeTests
    By default, files whose path contains "Test" (Tests/, .Tests., *Test.cs, *Tests.cs) are
    still scanned but marked lower severity. Pass -ExcludeTests to skip them entirely.

.PARAMETER ExcludeTests
    Skip files that look like test files.

.PARAMETER FailOnHigh
    If set, the script exits with a non-zero exit code when at least one High severity
    finding is reported. Useful as a CI gate.

.EXAMPLE
    ./Find-NPlusOne.ps1 -RepoPath C:\src\MyApp

.EXAMPLE
    ./Find-NPlusOne.ps1 C:\src\MyApp -OutputFormat Markdown -OutputPath report.md

.EXAMPLE
    ./Find-NPlusOne.ps1 C:\src\MyApp -OutputFormat Json -OutputPath findings.json -FailOnHigh
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$RepoPath,

    [Parameter(Position = 1)]
    [ValidateSet('Console', 'Markdown', 'Json')]
    [string]$OutputFormat = 'Console',

    [string]$OutputPath,

    [switch]$ExcludeTests,

    [switch]$FailOnHigh
)

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $RepoPath)) {
    Write-Error "RepoPath '$RepoPath' does not exist."
    exit 1
}

$RepoPath = (Resolve-Path -LiteralPath $RepoPath).ProviderPath

$excludedDirNames = @('bin', 'obj', 'node_modules', 'packages', '.git', '.vs', '.vscode', 'TestResults')

# Query-executing LINQ / EF Core method names (sync + Async variants handled via optional 'Async' suffix)
$queryMethodNames = @(
    'Where', 'First', 'FirstOrDefault', 'Single', 'SingleOrDefault',
    'ToList', 'ToArray', 'ToDictionary', 'ToHashSet',
    'Count', 'LongCount', 'Any', 'All',
    'Sum', 'Average', 'Min', 'Max',
    'Find', 'Load', 'Contains', 'Skip', 'Take',
    'GroupBy', 'OrderBy', 'OrderByDescending', 'FromSqlRaw', 'FromSqlInterpolated',
    'ExecuteQuery', 'SqlQuery'
)
# Build: \.(Where|First|FirstAsync|FirstOrDefault|FirstOrDefaultAsync|...)\s*\(
$methodAlternation = ($queryMethodNames | ForEach-Object { [regex]::Escape($_) + '(Async)?' }) -join '|'
$queryCallRegex = "\.($methodAlternation)\s*\("

$loopStartRegex = '^\s*(foreach|for|while)\s*\('
$includeRegex = '\.Include\s*\('
$navEnumerationRegex = '\b[\w]+\.[\w]+\.(Count|LongCount|Any|ToList|ToArray|Sum|Average|Min|Max|Where|OrderBy)\s*\('
$awaitAsyncRegex = '\bawait\b.*\.(?:\w+Async)\s*\('

$patternCatalog = @{
    'EF-Query-In-Loop'       = @{ Severity = 'High';   Description = 'EF Core / LINQ query executed inside a loop iteration - likely one round-trip per row instead of one batched query.' }
    'Async-Query-In-Loop'    = @{ Severity = 'High';   Description = 'Awaited async EF Core query executed inside a loop iteration.' }
    'Navigation-Enumeration' = @{ Severity = 'Medium'; Description = 'A navigation property collection is being enumerated inside a loop - if lazy loading is enabled this triggers a query per parent entity.' }
    'Missing-Include-Hint'   = @{ Severity = 'Low';    Description = 'Loop iterates over a query with no visible .Include(...) nearby, and the loop body dereferences a nested property - verify the navigation is eager-loaded or explicitly projected.' }
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Strip-CommentsAndStrings {
    param([string]$Line)
    # Best-effort: blank out string/char literal contents and strip // line comments so
    # brace counting and pattern matching aren't confused by braces/text inside strings.
    if ($null -eq $Line) { return '' }
    $result = $Line -replace '"(?:[^"\\]|\\.)*"', '""'
    $result = $result -replace "'(?:[^'\\]|\\.)*'", "''"
    $commentIndex = $result.IndexOf('//')
    if ($commentIndex -ge 0) {
        $result = $result.Substring(0, $commentIndex)
    }
    return $result
}

function Get-CSharpFiles {
    param([string]$Root, [bool]$SkipTests)

    # -Filter is case-sensitive on case-sensitive filesystems (typical on Linux); match the
    # extension case-insensitively ourselves so *.CS files aren't silently skipped there.
    Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -ieq '.cs' } |
        Where-Object {
            $full = $_.FullName
            $inExcluded = $false
            foreach ($seg in $full.Split([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)) {
                if ($excludedDirNames -contains $seg) { $inExcluded = $true; break }
            }
            if ($inExcluded) { return $false }
            if ($SkipTests -and ($full -match '(?i)[\\/]tests?[\\/]|\.tests?\.cs$|Tests?\.cs$')) {
                return $false
            }
            return $true
        }
}

function Find-LoopBlocks {
    <#
        Returns an array of objects describing each for/foreach/while loop in the file:
        StartLineNumber (1-based, the loop keyword line), BodyStartLineNumber, BodyEndLineNumber.
        Uses simple brace-depth counting on comment/string-stripped lines. Best-effort for
        typically-formatted C# - not a full parser.
    #>
    param([string[]]$Lines)

    $blocks = New-Object System.Collections.Generic.List[object]
    $stripped = $Lines | ForEach-Object { Strip-CommentsAndStrings $_ }

    for ($i = 0; $i -lt $stripped.Count; $i++) {
        if ($stripped[$i] -notmatch $loopStartRegex) { continue }
        # skip `} while (...)` tail of a do-while, already handled by its own do{ open
        if ($stripped[$i] -match '^\s*\}\s*while') { continue }

        # find the opening brace, starting on this line, scanning forward a few lines for
        # loops whose `{` is on its own line (Allman style) or loops with no braces at all.
        # Track paren depth across lines so a `;` inside a multi-line `for (...)` header
        # (e.g. `for (int i = 0;` on its own line) isn't mistaken for the end of a
        # brace-less single-statement body.
        $openLineIdx = -1
        $singleStatementLineIdx = -1
        $parenDepth = 0
        $headerEndSeen = $false
        for ($j = $i; $j -lt [Math]::Min($i + 6, $stripped.Count); $j++) {
            $parenDepth += (([regex]::Matches($stripped[$j], '\(')).Count - ([regex]::Matches($stripped[$j], '\)')).Count)
            if ($stripped[$j].Contains('{')) { $openLineIdx = $j; break }
            if ($parenDepth -le 0) { $headerEndSeen = $true }
            # Only once the loop header's parens are fully balanced (depth back to 0) can a
            # trailing `;` mean "brace-less single-statement body ends here". Note the body
            # statement may be on a later line than the header itself, e.g.:
            #   foreach (var x in y)
            #       DoWork(x);
            if ($headerEndSeen -and $stripped[$j].TrimEnd().EndsWith(';')) {
                # e.g. `for (int i = 0; i < 10; i++) DoWork(i);` on one line, or a header that
                # spans lines with the single-statement body on its own following line.
                $singleStatementLineIdx = $j
                break
            }
        }

        if ($singleStatementLineIdx -ge 0) {
            $blocks.Add([pscustomobject]@{
                StartLineNumber     = $i + 1
                BodyStartLineNumber = $singleStatementLineIdx + 1
                BodyEndLineNumber   = $singleStatementLineIdx + 1
                SingleStatement     = $true
            })
            continue
        }
        if ($openLineIdx -lt 0) { continue }

        # count braces to find the matching close
        $depth = 0
        $closeLineIdx = -1
        for ($j = $openLineIdx; $j -lt $stripped.Count; $j++) {
            $openCount = ([regex]::Matches($stripped[$j], '\{')).Count
            $closeCount = ([regex]::Matches($stripped[$j], '\}')).Count
            $depth += $openCount
            $depth -= $closeCount
            if ($depth -le 0) { $closeLineIdx = $j; break }
        }
        if ($closeLineIdx -lt 0) { $closeLineIdx = $stripped.Count - 1 }

        $blocks.Add([pscustomobject]@{
            StartLineNumber     = $i + 1
            BodyStartLineNumber = $openLineIdx + 2   # first line strictly inside the braces (1-based)
            BodyEndLineNumber   = $closeLineIdx       # 1-based number of the last line strictly inside the braces
                                                       # (numerically equal to the closing brace's 0-based index)
            SingleStatement     = $false
        })
    }

    return $blocks
}

function Test-N1InBlock {
    param(
        [string[]]$Lines,
        [pscustomobject]$Block,
        [string]$FilePath
    )

    $findings = New-Object System.Collections.Generic.List[object]

    if ($Block.SingleStatement) {
        $bodyLineNumbers = @($Block.BodyStartLineNumber)
    }
    elseif ($Block.BodyEndLineNumber -ge $Block.BodyStartLineNumber) {
        $bodyLineNumbers = @($Block.BodyStartLineNumber..$Block.BodyEndLineNumber) | Where-Object { $_ -ge 1 -and $_ -le $Lines.Count }
    }
    else {
        $bodyLineNumbers = @()   # empty body, e.g. `foreach (...) { }`
    }

    $sawIncludeNearby = $false
    $headerAreaStart = [Math]::Max(1, $Block.StartLineNumber - 5)
    for ($n = $headerAreaStart; $n -le $Block.StartLineNumber; $n++) {
        if ($n -ge 1 -and $n -le $Lines.Count -and $Lines[$n - 1] -match $includeRegex) { $sawIncludeNearby = $true }
    }

    $bodyDereferencesNestedProp = $false

    foreach ($lineNo in $bodyLineNumbers) {
        $text = $Lines[$lineNo - 1]
        $strippedText = Strip-CommentsAndStrings $text

        if ($strippedText -match $awaitAsyncRegex -and $strippedText -match $queryCallRegex) {
            $findings.Add([pscustomobject]@{
                File = $FilePath; Line = $lineNo; Pattern = 'Async-Query-In-Loop'
                Snippet = $text.Trim()
            })
        }
        elseif ($strippedText -match $queryCallRegex) {
            $findings.Add([pscustomobject]@{
                File = $FilePath; Line = $lineNo; Pattern = 'EF-Query-In-Loop'
                Snippet = $text.Trim()
            })
        }

        if ($strippedText -match $navEnumerationRegex) {
            $findings.Add([pscustomobject]@{
                File = $FilePath; Line = $lineNo; Pattern = 'Navigation-Enumeration'
                Snippet = $text.Trim()
            })
        }

        if ($strippedText -match '\b\w+\.\w+\.\w+\b') {
            $bodyDereferencesNestedProp = $true
        }
    }

    if (-not $sawIncludeNearby -and $bodyDereferencesNestedProp -and $bodyLineNumbers.Count -gt 0) {
        $findings.Add([pscustomobject]@{
            File = $FilePath; Line = $Block.StartLineNumber; Pattern = 'Missing-Include-Hint'
            Snippet = $Lines[$Block.StartLineNumber - 1].Trim()
        })
    }

    return $findings
}

# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

Write-Host "Scanning '$RepoPath' for C# / EF Core N+1 patterns..." -ForegroundColor Cyan

$files = Get-CSharpFiles -Root $RepoPath -SkipTests:$ExcludeTests.IsPresent
$allFindings = New-Object System.Collections.Generic.List[object]
$fileCount = 0

foreach ($file in $files) {
    $fileCount++
    try {
        $lines = Get-Content -LiteralPath $file.FullName -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not read '$($file.FullName)': $_"
        continue
    }
    if (-not $lines -or $lines.Count -eq 0) { continue }

    $relativePath = $file.FullName.Substring($RepoPath.Length).TrimStart('\', '/')
    $blocks = Find-LoopBlocks -Lines $lines

    foreach ($block in $blocks) {
        $blockFindings = Test-N1InBlock -Lines $lines -Block $block -FilePath $relativePath
        foreach ($f in $blockFindings) { $allFindings.Add($f) }
    }
}

# de-duplicate identical (file, line, pattern) hits that can arise from nested loops re-scanning the same line
$distinctFindings = $allFindings |
    Sort-Object File, Line, Pattern -Unique |
    ForEach-Object {
        $meta = $patternCatalog[$_.Pattern]
        [pscustomobject]@{
            File        = $_.File
            Line        = $_.Line
            Pattern     = $_.Pattern
            Severity    = $meta.Severity
            Description = $meta.Description
            Snippet     = $_.Snippet
        }
    }

$severityOrder = @{ High = 0; Medium = 1; Low = 2 }
$distinctFindings = $distinctFindings | Sort-Object File, @{Expression = { $severityOrder[$_.Severity] } }, Line

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

$summary = $distinctFindings | Group-Object Severity | ForEach-Object { [pscustomobject]@{ Severity = $_.Name; Count = $_.Count } }
$highCount = ($distinctFindings | Where-Object { $_.Severity -eq 'High' }).Count
$mediumCount = ($distinctFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
$lowCount = ($distinctFindings | Where-Object { $_.Severity -eq 'Low' }).Count

function Write-ConsoleReport {
    param([System.Collections.Generic.List[object]]$Findings)

    Write-Host ""
    Write-Host "Files scanned: $fileCount" -ForegroundColor Cyan
    Write-Host "Findings: $($Findings.Count)  (High: $highCount, Medium: $mediumCount, Low: $lowCount)" -ForegroundColor Cyan
    Write-Host ""

    if ($Findings.Count -eq 0) {
        Write-Host "No likely N+1 patterns found." -ForegroundColor Green
        return
    }

    foreach ($group in ($Findings | Group-Object File)) {
        Write-Host "-- $($group.Name)" -ForegroundColor Yellow
        foreach ($f in $group.Group) {
            $color = switch ($f.Severity) { 'High' { 'Red' } 'Medium' { 'DarkYellow' } default { 'Gray' } }
            Write-Host ("  [{0,-6}] line {1,-5} {2}" -f $f.Severity, $f.Line, $f.Pattern) -ForegroundColor $color
            Write-Host ("           {0}" -f $f.Snippet) -ForegroundColor DarkGray
        }
        Write-Host ""
    }
}

function Get-MarkdownReport {
    param([System.Collections.Generic.List[object]]$Findings)

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("# N+1 Query Scan Report")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("- Repo: ``$RepoPath``")
    [void]$sb.AppendLine("- Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine("- Files scanned: $fileCount")
    [void]$sb.AppendLine("- Findings: $($Findings.Count) (High: $highCount, Medium: $mediumCount, Low: $lowCount)")
    [void]$sb.AppendLine("")

    if ($Findings.Count -eq 0) {
        [void]$sb.AppendLine("No likely N+1 patterns found.")
        return $sb.ToString()
    }

    foreach ($group in ($Findings | Group-Object File)) {
        [void]$sb.AppendLine("## $($group.Name)")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("| Severity | Line | Pattern | Snippet |")
        [void]$sb.AppendLine("|---|---|---|---|")
        foreach ($f in $group.Group) {
            $snippet = ($f.Snippet -replace '\|', '\|')
            [void]$sb.AppendLine("| $($f.Severity) | $($f.Line) | $($f.Pattern) | ``$snippet`` |")
        }
        [void]$sb.AppendLine("")
    }

    [void]$sb.AppendLine("## Pattern reference")
    [void]$sb.AppendLine("")
    foreach ($key in $patternCatalog.Keys) {
        [void]$sb.AppendLine("- **$key** ($($patternCatalog[$key].Severity)): $($patternCatalog[$key].Description)")
    }

    return $sb.ToString()
}

switch ($OutputFormat) {
    'Console' {
        Write-ConsoleReport -Findings $distinctFindings
        if ($OutputPath) {
            (Get-MarkdownReport -Findings $distinctFindings) | Out-File -LiteralPath $OutputPath -Encoding utf8NoBOM
            Write-Host "Report also written to $OutputPath" -ForegroundColor Cyan
        }
    }
    'Markdown' {
        $md = Get-MarkdownReport -Findings $distinctFindings
        if ($OutputPath) {
            $md | Out-File -LiteralPath $OutputPath -Encoding utf8NoBOM
            Write-Host "Markdown report written to $OutputPath" -ForegroundColor Cyan
        }
        else {
            Write-Output $md
        }
    }
    'Json' {
        $jsonObj = [pscustomobject]@{
            repo         = $RepoPath
            generatedAt  = (Get-Date -Format 'o')
            filesScanned = $fileCount
            summary      = @{ total = $distinctFindings.Count; high = $highCount; medium = $mediumCount; low = $lowCount }
            findings     = $distinctFindings
        }
        $json = $jsonObj | ConvertTo-Json -Depth 6
        if ($OutputPath) {
            $json | Out-File -LiteralPath $OutputPath -Encoding utf8NoBOM
            Write-Host "JSON report written to $OutputPath" -ForegroundColor Cyan
        }
        else {
            Write-Output $json
        }
    }
}

if ($FailOnHigh -and $highCount -gt 0) {
    exit 1
}
exit 0