<#
.SYNOPSIS
    Build, test and release entry point for pc-powershelltools.

.DESCRIPTION
    One script that CI and a developer's machine both call, so "it passed
    locally" and "it passed in CI" mean the same thing.

.PARAMETER Task
    Test     - run the Pester suite (syntax, manifest, unit).
    Analyze  - run PSScriptAnalyzer against every script and module file.
    Release  - stage release artifacts into out/ and write SHA256SUMS.
    All      - Test, then Analyze.

.EXAMPLE
    ./build/Invoke-Build.ps1 -Task All
#>
[CmdletBinding()]
param(
    [ValidateSet('Test', 'Analyze', 'Release', 'Checksum', 'All')]
    [string]$Task = 'All',

    [string]$Version,

    # Warnings above this fail the build, so the count can only go down.
    # 146 is what the repository carries today: mostly
    # PSUseShouldProcessForStateChangingFunctions firing on the shell's
    # internal UI helpers, where the rule does not apply but is worth keeping
    # enabled for the module's actual cmdlets. Lower it as findings are fixed;
    # raising it should be a deliberate, reviewed decision.
    [int]$MaxWarning = 146
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot

function Write-Step {
    param([string]$Message)
    Write-Host ''
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Get-SourceFile {
    Get-ChildItem -Path $RepoRoot -Recurse -Include '*.ps1', '*.psm1', '*.psd1' -File |
        Where-Object { $_.FullName -notmatch '[\\/](out|dist|\.git)[\\/]' }
}

function Invoke-TestTask {
    Write-Step 'Running Pester suite'

    $pester = Get-Module -ListAvailable Pester |
        Where-Object { $_.Version -ge [version]'5.5.0' } |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if (-not $pester) {
        throw 'Pester 5.5.0 or later is required. Install-Module Pester -MinimumVersion 5.5.0 -Force -SkipPublisherCheck'
    }

    Import-Module $pester.Path -Force

    $config = New-PesterConfiguration
    $config.Run.Path = Join-Path $RepoRoot 'tests'
    $config.Run.Throw = $true
    $config.Output.Verbosity = 'Detailed'
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputPath = Join-Path $RepoRoot 'testResults.xml'

    Invoke-Pester -Configuration $config
}

function Invoke-AnalyzeTask {
    Write-Step 'Running PSScriptAnalyzer'

    if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) {
        throw 'PSScriptAnalyzer is required. Install-Module PSScriptAnalyzer -Force'
    }
    Import-Module PSScriptAnalyzer -Force

    $settings = Join-Path $RepoRoot 'PSScriptAnalyzerSettings.psd1'
    $results = Invoke-ScriptAnalyzer -Path $RepoRoot -Recurse -Settings $settings |
        Where-Object { $_.ScriptPath -notmatch '[\\/](out|dist)[\\/]' }

    if (-not $results) {
        Write-Host 'PSScriptAnalyzer: clean.' -ForegroundColor Green
        return
    }

    # Summarise by rule first. A flat list of a thousand findings is unreadable,
    # and the useful question is always "which rule, and how often".
    Write-Host ''
    Write-Host 'Findings by rule:'
    $results | Group-Object RuleName | Sort-Object Count -Descending | ForEach-Object {
        Write-Host ('  {0,5}  {1}' -f $_.Count, $_.Name)
    }

    $errors = @($results | Where-Object Severity -eq 'Error')
    $warnings = @($results | Where-Object Severity -eq 'Warning')

    if ($errors.Count -gt 0) {
        Write-Host ''
        $errors | Format-Table -AutoSize -Property ScriptName, Line, RuleName, Message | Out-String | Write-Host
        throw "PSScriptAnalyzer reported $($errors.Count) error(s)."
    }

    if ($warnings.Count -gt 0) {
        Write-Host ''
        $warnings | Format-Table -AutoSize -Property ScriptName, Line, RuleName, Message | Out-String | Write-Host
    }

    # A warning budget keeps the analyzer honest. Errors always fail; warnings
    # fail once they exceed what the repository has agreed to carry, so the
    # count can only go down.
    if ($warnings.Count -gt $MaxWarning) {
        throw "PSScriptAnalyzer reported $($warnings.Count) warning(s), over the budget of $MaxWarning. Fix them, or raise -MaxWarning deliberately."
    }

    Write-Host ("PSScriptAnalyzer: {0} warning(s), no errors (budget {1})." -f $warnings.Count, $MaxWarning) -ForegroundColor Yellow
}

function Invoke-ReleaseTask {
    Write-Step 'Staging release artifacts'

    if (-not $Version) {
        $manifestPath = Join-Path $RepoRoot 'src/PCTools/PCTools.psd1'
        $Version = (Import-PowerShellDataFile $manifestPath).ModuleVersion
    }
    Write-Host "Version: $Version"

    $outDir = Join-Path $RepoRoot 'out'
    if (Test-Path $outDir) { Remove-Item $outDir -Recurse -Force }
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null

    # The legacy single-file tools, which existing README links point at and
    # which people still pipe into iex. Shipped loose so those URLs keep working.
    Get-ChildItem -Path $RepoRoot -Filter '*.ps1' -File |
        Copy-Item -Destination $outDir

    # The current toolkit. The GUI needs the module beside it, so this ships as
    # a layout rather than as loose scripts.
    $stage = Join-Path $RepoRoot 'obj/pc-tools'
    if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
    New-Item -ItemType Directory -Path $stage -Force | Out-Null

    Copy-Item (Join-Path $RepoRoot 'pc-tools.ps1') -Destination $stage
    Copy-Item (Join-Path $RepoRoot 'src') -Destination $stage -Recurse
    foreach ($doc in 'README.md', 'CHANGELOG.md', 'LICENSE') {
        $path = Join-Path $RepoRoot $doc
        if (Test-Path $path) { Copy-Item $path -Destination $stage }
    }

    Compress-Archive -Path (Join-Path $stage '*') `
        -DestinationPath (Join-Path $outDir "pc-tools-$Version.zip") -Force

    # The module on its own, for people who only want the cmdlets.
    $moduleSrc = Join-Path $RepoRoot 'src/PCTools'
    if (Test-Path $moduleSrc) {
        Compress-Archive -Path $moduleSrc -DestinationPath (Join-Path $outDir "PCTools-$Version.zip") -Force
    }

    Remove-Item $stage -Recurse -Force

    Invoke-ChecksumTask

    Write-Host "Artifacts staged in $outDir" -ForegroundColor Green
}

function Invoke-ChecksumTask {
    <#
        Kept separate from Release because Authenticode signing rewrites the
        files it signs. Checksums generated before signing would not match what
        the user downloads, which is worse than publishing none at all.
    #>
    Write-Step 'Writing SHA256SUMS'

    $outDir = Join-Path $RepoRoot 'out'
    if (-not (Test-Path $outDir)) {
        throw "No staged artifacts found in $outDir. Run -Task Release first."
    }

    $sumsPath = Join-Path $outDir 'SHA256SUMS'
    if (Test-Path $sumsPath) { Remove-Item $sumsPath -Force }

    $sums = Get-ChildItem -Path $outDir -File | Sort-Object Name | ForEach-Object {
        '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
    }
    $sums | Set-Content -Path $sumsPath -Encoding UTF8

    Write-Host ''
    $sums | ForEach-Object { Write-Host "  $_" }
    Write-Host ''
}

switch ($Task) {
    'Test'     { Invoke-TestTask }
    'Analyze'  { Invoke-AnalyzeTask }
    'Release'  { Invoke-ReleaseTask }
    'Checksum' { Invoke-ChecksumTask }
    'All'      { Invoke-TestTask; Invoke-AnalyzeTask }
}

Write-Host ''
Write-Host "Build task '$Task' completed." -ForegroundColor Green
