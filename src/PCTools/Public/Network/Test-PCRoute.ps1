function Test-PCRoute {
    <#
    .SYNOPSIS
        Traces the path to a host, reporting per-hop latency.

    .DESCRIPTION
        New in the module. Net Diag could tell you the internet was unreachable
        but not where it stopped being reachable, which is the question that
        distinguishes "my router" from "my ISP".

        Implemented over System.Net.NetworkInformation.Ping with an increasing
        TTL rather than by shelling out to tracert.exe, so each hop honours the
        timeout and the results come back as objects.

    .PARAMETER Target
        The host or address to trace to.

    .PARAMETER MaxHops
        Stop after this many hops.

    .PARAMETER TimeoutSeconds
        Per-hop timeout.

    .EXAMPLE
        Test-PCRoute -Target 1.1.1.1 | Format-Table Hop, Address, LatencyMs, Status

    .OUTPUTS
        pscustomobject
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)]
        [string]$Target = '1.1.1.1',

        [ValidateRange(1, 64)]
        [int]$MaxHops = 20,

        [ValidateRange(1, 30)]
        [int]$TimeoutSeconds = 3
    )

    Write-PCLog -Level INFO -Message "Tracing route to $Target"

    $ping = [System.Net.NetworkInformation.Ping]::new()
    $buffer = [byte[]]::new(32)

    try {
        for ($ttl = 1; $ttl -le $MaxHops; $ttl++) {
            $options = [System.Net.NetworkInformation.PingOptions]::new($ttl, $true)

            $reply = $null
            $status = 'Unknown'
            $address = '*'
            $latency = $null

            try {
                $reply = $ping.Send($Target, $TimeoutSeconds * 1000, $buffer, $options)
                $status = $reply.Status.ToString()

                if ($reply.Address) { $address = $reply.Address.ToString() }
                if ($reply.Status -in 'Success', 'TtlExpired') { $latency = $reply.RoundtripTime }
            }
            catch {
                $status = 'Error'
            }

            [pscustomobject]@{
                PSTypeName = 'PCTools.RouteHop'
                Hop        = $ttl
                Address    = $address
                LatencyMs  = $latency
                Status     = $status
            }

            # Reaching the destination ends the trace; TtlExpired is an
            # intermediate hop and means keep going.
            if ($reply -and $reply.Status -eq 'Success') { break }
        }
    }
    finally {
        $ping.Dispose()
    }
}
