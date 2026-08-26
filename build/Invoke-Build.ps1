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
    [ValidateSet('Test', 'Analyze', 'Release', 'All')]
    [string]$Task = 'All',

    [string]$Version
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

    if ($results) {
        $results | Format-Table -AutoSize -Property Severity, ScriptName, Line, RuleName, Message | Out-String | Write-Host

        $errors = @($results | Where-Object Severity -eq 'Error')
        if ($errors.Count -gt 0) {
            throw "PSScriptAnalyzer reported $($errors.Count) error(s)."
        }

        Write-Host "PSScriptAnalyzer reported $($results.Count) warning(s), no errors." -ForegroundColor Yellow
    }
    else {
        Write-Host 'PSScriptAnalyzer: clean.' -ForegroundColor Green
    }
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

    # Standalone entry points people download or pipe into iex.
    Get-ChildItem -Path $RepoRoot -Filter '*.ps1' -File |
        Copy-Item -Destination $outDir

    # The module, zipped for manual install.
    $moduleSrc = Join-Path $RepoRoot 'src/PCTools'
    if (Test-Path $moduleSrc) {
        Compress-Archive -Path $moduleSrc -DestinationPath (Join-Path $outDir "PCTools-$Version.zip") -Force
    }

    Write-Step 'Writing SHA256SUMS'
    $sums = Get-ChildItem -Path $outDir -File | Sort-Object Name | ForEach-Object {
        '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.Name
    }
    $sumsPath = Join-Path $outDir 'SHA256SUMS'
    $sums | Set-Content -Path $sumsPath -Encoding UTF8

    Write-Host ''
    $sums | ForEach-Object { Write-Host "  $_" }
    Write-Host ''
    Write-Host "Artifacts staged in $outDir" -ForegroundColor Green
}

switch ($Task) {
    'Test'    { Invoke-TestTask }
    'Analyze' { Invoke-AnalyzeTask }
    'Release' { Invoke-ReleaseTask }
    'All'     { Invoke-TestTask; Invoke-AnalyzeTask }
}

Write-Host ''
Write-Host "Build task '$Task' completed." -ForegroundColor Green
