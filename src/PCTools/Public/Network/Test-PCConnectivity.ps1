function Test-PCConnectivity {
    <#
    .SYNOPSIS
        Runs layered connectivity tests: gateway, internet, DNS and TCP.

    .DESCRIPTION
        Consolidates Net Diag's Test-Ping, Test-DnsResolve and Test-TcpPort into
        one graded check, and orders the results so the first failure identifies
        the layer at fault: adapter, then gateway, then internet routing, then
        DNS resolution, then TCP reachability.

        That ordering is the whole point. "The internet is down" and "DNS is
        broken" produce very different first failures, and the original printed
        the results in whatever order the tests were written.

    .PARAMETER DnsName
        Names to resolve. Defaults to two well-known hosts.

    .PARAMETER TimeoutSeconds
        Per-test timeout.

    .EXAMPLE
        Test-PCConnectivity | Format-Table Layer, Target, Success, Detail

    .OUTPUTS
        pscustomobject
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [string[]]$DnsName = @('www.google.com', 'www.cloudflare.com'),

        [ValidateRange(1, 120)]
        [int]$TimeoutSeconds = 5
    )

    $emit = {
        param($Layer, $Target, $Success, $Detail, $LatencyMs)
        [pscustomobject]@{
            PSTypeName = 'PCTools.ConnectivityTest'
            Layer      = $Layer
            Target     = $Target
            Success    = [bool]$Success
            Detail     = $Detail
            LatencyMs  = $LatencyMs
        }
    }

    # 1. Adapter
    $connected = @(Get-PCNetworkAdapter -ConnectedOnly)
    & $emit 'Adapter' 'Local adapters' ($connected.Count -gt 0) `
        $(if ($connected.Count -gt 0) { "$($connected.Count) adapter(s) up: $(($connected.Name) -join ', ')" }
          else { 'No adapter is up' }) $null

    # 2. Gateway
    $gateway = ($connected | Where-Object Gateway | Select-Object -First 1).Gateway
    if ($gateway) { $gateway = ($gateway -split ',')[0].Trim() }

    if ($gateway) {
        $reply = Test-PCPing -Target $gateway -TimeoutSeconds $TimeoutSeconds
        & $emit 'Gateway' $gateway $reply.Success $reply.Detail $reply.LatencyMs
    }
    else {
        & $emit 'Gateway' '(none)' $false 'No default gateway is configured' $null
    }

    # 3. Internet routing, by IP so DNS cannot mask a routing failure
    foreach ($target in @('1.1.1.1', '8.8.8.8')) {
        $reply = Test-PCPing -Target $target -TimeoutSeconds $TimeoutSeconds
        & $emit 'Internet' $target $reply.Success $reply.Detail $reply.LatencyMs
    }

    # 4. DNS resolution
    foreach ($name in $DnsName) {
        $resolved = $null
        try {
            $records = Resolve-DnsName -Name $name -Type A -DnsOnly -ErrorAction Stop |
                Where-Object { $_.IPAddress }
            $resolved = ($records.IPAddress) -join ', '
        }
        catch {
            try {
                $resolved = ([System.Net.Dns]::GetHostAddresses($name) |
                    Where-Object AddressFamily -eq 'InterNetwork' |
                    ForEach-Object IPAddressToString) -join ', '
            }
            catch { $resolved = $null }
        }

        & $emit 'DNS' $name ([bool]$resolved) `
            $(if ($resolved) { "Resolved to $resolved" } else { 'Resolution failed' }) $null
    }

    # 5. TCP reachability
    foreach ($endpoint in @(@{ Host = 'www.google.com'; Port = 443 }, @{ Host = '1.1.1.1'; Port = 53 })) {
        $result = Test-PCTcpPort -TargetHost $endpoint.Host -Port $endpoint.Port -TimeoutSeconds $TimeoutSeconds
        & $emit 'TCP' "$($endpoint.Host):$($endpoint.Port)" $result.Success $result.Detail $result.LatencyMs
    }
}
