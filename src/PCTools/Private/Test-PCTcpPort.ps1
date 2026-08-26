function Test-PCTcpPort {
    <#
    .SYNOPSIS
        Tests whether a TCP port accepts a connection.

    .DESCRIPTION
        Uses an async connect with an explicit wait so the timeout is honoured.
        A bare TcpClient.Connect blocks on the OS connect timeout - around 21
        seconds on Windows - regardless of any value the caller asks for, which
        is why Net Diag's "quick" scan was not quick against a filtered port.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$TargetHost,

        [Parameter(Mandatory)]
        [ValidateRange(1, 65535)]
        [int]$Port,

        [ValidateRange(1, 120)]
        [int]$TimeoutSeconds = 5
    )

    $client = New-Object System.Net.Sockets.TcpClient
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $success = $false
    $detail = ''

    try {
        $async = $client.BeginConnect($TargetHost, $Port, $null, $null)

        if ($async.AsyncWaitHandle.WaitOne([timespan]::FromSeconds($TimeoutSeconds))) {
            try {
                $client.EndConnect($async)
                $success = $client.Connected
                $detail = if ($success) { 'Connected' } else { 'Connection refused' }
            }
            catch {
                $detail = $_.Exception.InnerException.Message
                if (-not $detail) { $detail = $_.Exception.Message }
            }
        }
        else {
            $detail = "Timed out after $TimeoutSeconds seconds"
        }
    }
    catch {
        $detail = $_.Exception.Message
    }
    finally {
        $stopwatch.Stop()
        try { $client.Close() } catch { }
        if ($client -is [System.IDisposable]) { $client.Dispose() }
    }

    [pscustomobject]@{
        TargetHost = $TargetHost
        Port       = $Port
        Success    = $success
        LatencyMs  = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 1)
        Detail     = $detail
    }
}
