function Get-PCConnectivityVerdict {
    <#
    .SYNOPSIS
        Turns a set of connectivity test results into a single diagnosis.

    .DESCRIPTION
        The layered tests are ordered from the adapter outwards, so the first
        failing layer is the diagnosis. This is what the GUI's summary banner
        shows, and it is the piece Net Diag never had: it displayed pass/fail
        rows and left the user to interpret them.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$TestResult
    )

    $byLayer = $TestResult | Group-Object Layer -AsHashTable -AsString
    $layerPassed = {
        param($Layer)
        $rows = @($byLayer[$Layer])
        $rows.Count -gt 0 -and @($rows | Where-Object Success).Count -gt 0
    }

    $adapter  = & $layerPassed 'Adapter'
    $gateway  = & $layerPassed 'Gateway'
    $internet = & $layerPassed 'Internet'
    $dns      = & $layerPassed 'DNS'
    $tcp      = & $layerPassed 'TCP'

    $verdict, $advice = if (-not $adapter) {
        'No network adapter', 'No adapter is up. Check the cable, or enable the adapter in Network Connections.'
    }
    elseif (-not $gateway) {
        'No route to the router', 'The adapter is up but the router does not reply. Check Wi-Fi association or the cable, and restart the router.'
    }
    elseif (-not $internet) {
        'No internet access', 'The router replies but the internet does not. This is almost always upstream: check the modem or the ISP.'
    }
    elseif (-not $dns) {
        'DNS is not resolving', 'Routing works but name resolution fails. Try Set-PCDnsServer -Preset Cloudflare, then Clear-PCDnsCache.'
    }
    elseif (-not $tcp) {
        'Traffic is being blocked', 'DNS resolves but connections fail. A firewall, proxy or security product is filtering traffic.'
    }
    else {
        'Healthy', 'All layers responded normally.'
    }

    $failed = @($TestResult | Where-Object { -not $_.Success })

    [pscustomobject]@{
        PSTypeName  = 'PCTools.ConnectivityVerdict'
        Verdict     = $verdict
        Healthy     = $verdict -eq 'Healthy'
        Advice      = $advice
        Passed      = @($TestResult | Where-Object Success).Count
        Failed      = $failed.Count
        FailedTests = $failed
    }
}
