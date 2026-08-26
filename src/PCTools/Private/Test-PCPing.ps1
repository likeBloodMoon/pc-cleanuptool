function Test-PCPing {
    <#
    .SYNOPSIS
        Pings a target and reports latency.

    .DESCRIPTION
        Uses System.Net.NetworkInformation.Ping rather than Test-Connection so
        the timeout is honoured exactly. Test-Connection's own timeout is
        per-attempt and coarse, which is why Net Diag's quick scan could sit for
        far longer than its stated budget on an unreachable host.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Target,

        [int]$Count = 2,

        [ValidateRange(1, 120)]
        [int]$TimeoutSeconds = 5
    )

    $ping = [System.Net.NetworkInformation.Ping]::new()
    $latencies = [System.Collections.Generic.List[long]]::new()
    $lastError = $null

    try {
        for ($i = 0; $i -lt $Count; $i++) {
            try {
                $reply = $ping.Send($Target, $TimeoutSeconds * 1000)
                if ($reply.Status -eq 'Success') {
                    $latencies.Add($reply.RoundtripTime)
                }
                else {
                    $lastError = $reply.Status.ToString()
                }
            }
            catch {
                # No null-coalescing operator: this module must parse on
                # Windows PowerShell 5.1.
                $lastError = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message }
                             else { $_.Exception.Message }
            }
        }
    }
    finally {
        $ping.Dispose()
    }

    $success = $latencies.Count -gt 0
    $average = if ($success) { [math]::Round(($latencies | Measure-Object -Average).Average, 1) } else { $null }

    [pscustomobject]@{
        Target    = $Target
        Success   = $success
        Sent      = $Count
        Received  = $latencies.Count
        LatencyMs = $average
        Detail    = if ($success) { "$($latencies.Count)/$Count replies, ${average} ms average" }
                    else { "No reply ($lastError)" }
    }
}
