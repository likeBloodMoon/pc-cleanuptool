function Test-PCMtu {
    <#
    .SYNOPSIS
        Finds the largest packet that reaches a host without fragmenting.

    .DESCRIPTION
        New in the module, and the diagnostic for a specific and confusing
        failure: a connection where DNS resolves, small requests succeed, and
        large transfers or HTTPS handshakes hang. That is a path MTU problem,
        usually a PPPoE or VPN link, and no amount of DNS flushing fixes it.

        Binary-searches the payload size with the don't-fragment flag set. The
        reported MTU adds the 28-byte IPv4 and ICMP header overhead back on.

    .PARAMETER Target
        The host to probe.

    .PARAMETER TimeoutSeconds
        Per-probe timeout.

    .EXAMPLE
        Test-PCMtu -Target 1.1.1.1

    .OUTPUTS
        pscustomobject
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0)]
        [string]$Target = '1.1.1.1',

        [ValidateRange(1, 30)]
        [int]$TimeoutSeconds = 3
    )

    Write-PCLog -Level INFO -Message "Probing path MTU to $Target"

    $ping = [System.Net.NetworkInformation.Ping]::new()
    $dontFragment = [System.Net.NetworkInformation.PingOptions]::new(64, $true)

    $probe = {
        param($PayloadSize)
        $buffer = [byte[]]::new($PayloadSize)
        try {
            $reply = $ping.Send($Target, $TimeoutSeconds * 1000, $buffer, $dontFragment)
            return $reply.Status -eq 'Success'
        }
        catch {
            return $false
        }
    }

    try {
        # 1472 = 1500 - 28, the largest payload that fits a standard Ethernet MTU.
        $low = 0
        $high = 1472

        if (& $probe $high) {
            return [pscustomobject]@{
                PSTypeName  = 'PCTools.MtuProbe'
                Target      = $Target
                PayloadSize = $high
                Mtu         = $high + 28
                Standard    = $true
                Detail      = 'Full 1500-byte MTU path; no fragmentation issue.'
            }
        }

        if (-not (& $probe 0)) {
            return [pscustomobject]@{
                PSTypeName  = 'PCTools.MtuProbe'
                Target      = $Target
                PayloadSize = $null
                Mtu         = $null
                Standard    = $false
                Detail      = "$Target does not answer ICMP at all, so the MTU cannot be probed this way."
            }
        }

        while ($high - $low -gt 1) {
            $middle = [int](($low + $high) / 2)
            if (& $probe $middle) { $low = $middle } else { $high = $middle }
        }

        $mtu = $low + 28

        [pscustomobject]@{
            PSTypeName  = 'PCTools.MtuProbe'
            Target      = $Target
            PayloadSize = $low
            Mtu         = $mtu
            Standard    = $false
            Detail      = "Path MTU is $mtu, below the standard 1500. Large transfers and TLS handshakes can stall on a path like this; a PPPoE or VPN link is the usual cause."
        }
    }
    finally {
        $ping.Dispose()
    }
}
