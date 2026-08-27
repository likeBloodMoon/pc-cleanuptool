#requires -Version 5.1
<#
.SYNOPSIS
    Launches PC Tools.

.DESCRIPTION
    The entry point for the current toolkit. Finds the PCTools module and the
    GUI shell next to this script, then starts the shell.

    The older single-file scripts (pc-cleanuptool.ps1, pc-netdiag.ps1) are still
    present and still work, but they are frozen: new work goes into the module
    and this shell. See MIGRATION.md.

.PARAMETER Theme
    Dark or Light. Defaults to Dark.

.PARAMETER NoGui
    Import the PCTools module into the current session and exit, instead of
    opening the window. Use this to drive the actions from the console.

.EXAMPLE
    .\pc-tools.ps1

.EXAMPLE
    .\pc-tools.ps1 -NoGui
    Invoke-PCMaintenance -ProfileName Quick -WhatIf

.LINK
    https://github.com/likeBloodMoon/pc-powershelltools
#>
[CmdletBinding()]
param(
    [ValidateSet('Dark', 'Light')]
    [string]$Theme = 'Dark',

    [switch]$NoGui
)

$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
if (-not $root) { $root = Split-Path -Parent $MyInvocation.MyCommand.Path }

if (-not $root) {
    throw @'
PC Tools cannot locate its own folder.

This usually means the script was piped into iex from the network. The GUI
needs the PCTools module alongside it, so download the release archive and run
pc-tools.ps1 from disk instead:

    https://github.com/likeBloodMoon/pc-powershelltools/releases/latest
'@
}

$modulePath = Join-Path $root 'src\PCTools\PCTools.psd1'
if (-not (Test-Path -LiteralPath $modulePath)) {
    throw "The PCTools module is missing. Expected it at: $modulePath"
}

Import-Module $modulePath -Force

if ($NoGui) {
    Write-Host ''
    Write-Host "PCTools $((Get-Module PCTools).Version) loaded." -ForegroundColor Green
    Write-Host ''
    Write-Host '  Get-Command -Module PCTools          list every action'
    Write-Host '  Get-PCMaintenanceProfile             show the built-in profiles'
    Write-Host '  Invoke-PCMaintenance -WhatIf         preview without changing anything'
    Write-Host '  Get-PCNetworkReport | Format-List    diagnose the network'
    Write-Host ''
    if (-not (Test-PCAdmin)) {
        Write-Warning 'This session is not elevated. Repair and network actions will fail.'
    }
    return
}

$shellPath = Join-Path $root 'src\Shell\Start-PCToolsShell.ps1'
if (-not (Test-Path -LiteralPath $shellPath)) {
    throw "The PC Tools shell is missing. Expected it at: $shellPath"
}

& $shellPath -Theme $Theme
