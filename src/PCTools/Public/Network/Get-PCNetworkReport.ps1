function Get-PCNetworkReport {
    <#
    .SYNOPSIS
        Builds a full network diagnostic report.

    .DESCRIPTION
        The module-side replacement for Net Diag's Run-QuickDiagnostics and
        Start-FullDiagnosticsWorker. Both of those ran on the UI thread; this
        returns data and leaves scheduling to the caller, which is what lets the
        GUI run it on a background runspace.

    .PARAMETER Full
        Also capture ipconfig /all, route print, netsh interface config, the
        WinHTTP proxy, firewall profiles and wireless interface state. Slower.

    .PARAMETER TimeoutSeconds
        Per-command timeout for the external tools in a full report.

    .EXAMPLE
        Get-PCNetworkReport -Full | Export-PCReport -Path ~\Desktop

    .OUTPUTS
        pscustomobject
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [switch]$Full,

        [ValidateRange(5, 300)]
        [int]$TimeoutSeconds = 30
    )

    Write-PCLog -Level INFO -Message "Building $(if ($Full) { 'full' } else { 'quick' }) network report"

    $adapters = @(Get-PCNetworkAdapter)
    $tests = @(Test-PCConnectivity)

    $routes = @()
    try {
        $routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop |
            Sort-Object RouteMetric |
            Select-Object -First 25 DestinationPrefix, NextHop, InterfaceAlias, RouteMetric)
    }
    catch {
        Write-PCLog -Level DEBUG -Message "Get-NetRoute failed: $($_.Exception.Message)"
    }

    $report = [pscustomobject]@{
        PSTypeName   = 'PCTools.NetworkReport'
        ComputerName = $env:COMPUTERNAME
        User         = "$env:USERDOMAIN\$env:USERNAME"
        IsAdmin      = Test-PCAdmin
        Timestamp    = Get-Date
        Adapters     = $adapters
        Routes       = $routes
        Tests        = $tests
        Verdict      = Get-PCConnectivityVerdict -TestResult $tests
        Full         = $null
    }

    if ($Full) {
        $commands = [ordered]@{
            IpconfigAll          = @{ File = 'ipconfig.exe'; Args = @('/all') }
            RoutePrint           = @{ File = 'route.exe';    Args = @('print') }
            NetshInterfaceConfig = @{ File = 'netsh.exe';    Args = @('interface', 'ip', 'show', 'config') }
            WinHttpProxy         = @{ File = 'netsh.exe';    Args = @('winhttp', 'show', 'proxy') }
            FirewallProfiles     = @{ File = 'netsh.exe';    Args = @('advfirewall', 'show', 'allprofiles') }
            WlanInterfaces       = @{ File = 'netsh.exe';    Args = @('wlan', 'show', 'interfaces') }
        }

        $extras = [ordered]@{}
        foreach ($key in $commands.Keys) {
            $command = $commands[$key]
            Write-PCLog -Level INFO -Message "Capturing $key"
            $run = Invoke-PCProcess -FilePath $command.File -ArgumentList $command.Args -TimeoutSeconds $TimeoutSeconds
            $extras[$key] = $run.Output
        }

        $report.Full = [pscustomobject]$extras
    }

    $report
}
