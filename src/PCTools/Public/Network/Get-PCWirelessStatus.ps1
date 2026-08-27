function Get-PCWirelessStatus {
    <#
    .SYNOPSIS
        Reports the current Wi-Fi association: SSID, signal, band and rate.

    .DESCRIPTION
        New in the module. Net Diag captured `netsh wlan show interfaces` into
        the full report as raw text; this parses it into an object and grades
        the signal, so "the internet is slow" can be answered with a number.

    .EXAMPLE
        Get-PCWirelessStatus

    .OUTPUTS
        pscustomobject
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $run = Invoke-PCProcess -FilePath 'netsh.exe' -ArgumentList @('wlan', 'show', 'interfaces') -TimeoutSeconds 20

    if ($run.TimedOut -or $run.Output -match 'no wireless interface') {
        return [pscustomobject]@{
            PSTypeName = 'PCTools.WirelessStatus'
            Connected  = $false
            Detail     = 'No wireless interface is present.'
        }
    }

    $field = {
        param($Label)
        $match = [regex]::Match($run.Output, "(?m)^\s*$Label\s*:\s*(.+?)\s*$")
        if ($match.Success) { $match.Groups[1].Value } else { $null }
    }

    $state = & $field 'State'
    if ($state -ne 'connected') {
        return [pscustomobject]@{
            PSTypeName = 'PCTools.WirelessStatus'
            Connected  = $false
            Detail     = "Wireless adapter is present but not connected (state: $state)."
        }
    }

    $signalText = & $field 'Signal'
    $signal = if ($signalText -match '(\d+)') { [int]$Matches[1] } else { $null }

    $grade, $advice = if ($null -eq $signal) {
        'Unknown', ''
    }
    elseif ($signal -ge 75) {
        'Good', ''
    }
    elseif ($signal -ge 50) {
        'Fair', 'Usable, but throughput will drop under load.'
    }
    else {
        'Poor', 'Move closer to the access point or switch band; a weak signal looks exactly like a slow connection.'
    }

    [pscustomobject]@{
        PSTypeName    = 'PCTools.WirelessStatus'
        Connected     = $true
        Ssid          = & $field 'SSID'
        Bssid         = & $field 'BSSID'
        Radio         = & $field 'Radio type'
        Band          = & $field 'Band'
        Channel       = & $field 'Channel'
        SignalPercent = $signal
        SignalGrade   = $grade
        ReceiveRate   = & $field 'Receive rate \(Mbps\)'
        TransmitRate  = & $field 'Transmit rate \(Mbps\)'
        Authentication = & $field 'Authentication'
        Detail        = if ($advice) { "Signal $signal% ($grade). $advice" } else { "Signal $signal% ($grade)." }
    }
}
