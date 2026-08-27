@{
    RootModule        = 'PCTools.psm1'
    ModuleVersion     = '0.4.0'
    GUID              = '6f3c0a58-1d2e-4a7b-9c34-8e5f2b7d41a9'
    Author            = 'likeBloodMoon'
    CompanyName       = 'likeBloodMoon'
    Copyright         = '(c) 2025 likeBloodMoon. Released under the MIT License.'

    Description       = 'Windows maintenance, repair and network diagnostic actions. The shared engine behind the pc-powershelltools GUIs: every action supports -WhatIf and returns a structured result rather than writing to a log box.'

    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        # Cleanup
        'Clear-PCBrowserCache'
        'Clear-PCPrefetchCache'
        'Clear-PCRecycleBin'
        'Clear-PCTempFile'
        'Clear-PCWindowsUpdateCache'

        # Repair
        'New-PCRestorePoint'
        'Repair-PCSystemFile'
        'Repair-PCSystemImage'
        'Test-PCDisk'

        # Network
        'Clear-PCDnsCache'
        'Export-PCNetworkProfile'
        'Get-PCNetworkAdapter'
        'Get-PCNetworkProfile'
        'Get-PCNetworkReport'
        'Get-PCWirelessStatus'
        'Import-PCNetworkProfile'
        'Reset-PCNetworkStack'
        'Set-PCDhcp'
        'Set-PCDnsServer'
        'Set-PCNetworkAddress'
        'Test-PCConnectivity'
        'Test-PCMtu'
        'Test-PCRoute'

        # Preferences
        'Get-PCPreference'
        'Restart-PCExplorer'
        'Set-PCPreference'

        # Software
        'Install-PCApplication'

        # Orchestration and reporting
        'Export-PCReport'
        'Get-PCMaintenanceProfile'
        'Import-PCConfiguration'
        'Invoke-PCMaintenance'

        # Host integration
        'Format-PCByteSize'
        'Get-PCLogPath'
        'Register-PCLogSink'
        'Test-PCAdmin'
        'Unregister-PCLogSink'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    # Windows-only: the GUI needs WinForms, and the actions call Windows-only
    # cmdlets. Declaring it keeps the module out of Linux and macOS search
    # results on the Gallery rather than failing at import for those users.
    CompatiblePSEditions = @('Desktop', 'Core')

    PrivateData = @{
        PSData = @{
            Tags         = @(
                'Windows', 'Maintenance', 'Cleanup', 'Network', 'Diagnostics',
                'Optimization', 'Repair', 'DISM', 'SFC', 'GUI',
                'PSEdition_Desktop', 'PSEdition_Core'
            )
            LicenseUri   = 'https://github.com/likeBloodMoon/pc-powershelltools/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/likeBloodMoon/pc-powershelltools'
            ReleaseNotes = @'
Every action supports -WhatIf and returns a structured result.

See the full changelog:
https://github.com/likeBloodMoon/pc-powershelltools/blob/main/CHANGELOG.md
'@
            RequireLicenseAcceptance = $false
        }
    }
}
