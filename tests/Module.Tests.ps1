#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
    Contract tests for the PCTools module: the manifest agrees with the files
    on disk, the public surface follows PowerShell conventions, and the
    destructive actions actually support -WhatIf.
#>

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:ModulePath = Join-Path $script:RepoRoot 'src/PCTools/PCTools.psd1'
    $script:ModuleRoot = Split-Path -Parent $script:ModulePath

    Import-Module $script:ModulePath -Force
    $script:Module = Get-Module PCTools
    $script:Manifest = Import-PowerShellDataFile -Path $script:ModulePath
}

AfterAll {
    Remove-Module PCTools -Force -ErrorAction SilentlyContinue
}

Describe 'Module manifest' {

    It 'is a valid manifest' {
        { Test-ModuleManifest -Path $script:ModulePath -ErrorAction Stop } | Should -Not -Throw
    }

    It 'targets PowerShell 5.1, the runtime the GUIs require' {
        $script:Manifest.PowerShellVersion | Should -Be '5.1'
    }

    It 'exports every function file under Public' {
        $onDisk = Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Public') -Recurse -Filter '*.ps1' -File |
            ForEach-Object BaseName | Sort-Object

        $declared = $script:Manifest.FunctionsToExport | Sort-Object

        # A file added without a manifest entry fails here rather than silently
        # shipping an unexported function.
        Compare-Object -ReferenceObject $onDisk -DifferenceObject $declared |
            Should -BeNullOrEmpty
    }

    It 'exports exactly what the manifest declares' {
        $exported = $script:Module.ExportedFunctions.Keys | Sort-Object
        $declared = $script:Manifest.FunctionsToExport | Sort-Object

        Compare-Object -ReferenceObject $exported -DifferenceObject $declared |
            Should -BeNullOrEmpty
    }

    It 'keeps no private helper in the public surface' {
        $privateNames = Get-ChildItem -Path (Join-Path $script:ModuleRoot 'Private') -Recurse -Filter '*.ps1' -File |
            ForEach-Object BaseName

        foreach ($name in $privateNames) {
            $script:Module.ExportedFunctions.Keys | Should -Not -Contain $name
        }
    }
}

Describe 'Public function conventions' {

    BeforeDiscovery {
        $modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'src/PCTools/PCTools.psd1'
        Import-Module $modulePath -Force
        $script:PublicFunctions = (Get-Module PCTools).ExportedFunctions.Values |
            ForEach-Object { @{ Name = $_.Name; Command = $_ } }
    }

    It '<Name> uses an approved verb' -ForEach $script:PublicFunctions {
        $verb = ($Name -split '-')[0]
        # Get-Verb is the authority; the original scripts used Flush-, Run-,
        # Create-, Load- and Require-, all of which warn on Import-Module.
        (Get-Verb).Verb | Should -Contain $verb
    }

    It '<Name> uses the PC noun prefix' -ForEach $script:PublicFunctions {
        $noun = ($Name -split '-', 2)[1]
        $noun | Should -Match '^PC' -Because 'the prefix keeps these from colliding with built-ins such as Clear-RecycleBin'
    }

    It '<Name> has comment-based help with a synopsis' -ForEach $script:PublicFunctions {
        $help = Get-Help -Name $Name -ErrorAction Stop
        $help.Synopsis | Should -Not -BeNullOrEmpty
        $help.Synopsis | Should -Not -Match '^\s*$'
    }

    It '<Name> declares CmdletBinding' -ForEach $script:PublicFunctions {
        $Command.CmdletBinding | Should -BeTrue
    }
}

Describe 'Destructive actions support -WhatIf' {

    BeforeDiscovery {
        # Every action that changes machine state must be previewable. This list
        # is the contract; adding a mutating action without ShouldProcess fails.
        $script:MutatingActions = @(
            'Clear-PCBrowserCache', 'Clear-PCDnsCache', 'Clear-PCPrefetchCache'
            'Clear-PCRecycleBin', 'Clear-PCTempFile', 'Clear-PCWindowsUpdateCache'
            'Install-PCApplication', 'Invoke-PCMaintenance', 'New-PCRestorePoint'
            'Repair-PCSystemFile', 'Repair-PCSystemImage', 'Reset-PCNetworkStack'
            'Restart-PCExplorer', 'Set-PCDhcp', 'Set-PCDnsServer'
            'Set-PCNetworkAddress', 'Set-PCPreference', 'Test-PCDisk'
        ) | ForEach-Object { @{ Name = $_ } }
    }

    It '<Name> supports ShouldProcess' -ForEach $script:MutatingActions {
        $command = Get-Command -Name $Name -Module PCTools -ErrorAction Stop
        $command.Parameters.Keys | Should -Contain 'WhatIf'
        $command.Parameters.Keys | Should -Contain 'Confirm'
    }
}

Describe 'Reset-PCNetworkStack is marked high impact' {

    It 'declares ConfirmImpact High, so it prompts by default' {
        $command = Get-Command Reset-PCNetworkStack -Module PCTools
        $metadata = [System.Management.Automation.CommandMetadata]::new($command)

        # Winsock reset removes third-party LSPs and requires a restart. It must
        # never run silently as part of an unattended batch.
        $metadata.ConfirmImpact | Should -Be 'High'
    }
}
