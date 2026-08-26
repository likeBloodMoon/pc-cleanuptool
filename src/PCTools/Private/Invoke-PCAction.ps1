function Invoke-PCAction {
    <#
    .SYNOPSIS
        Runs an action body and turns whatever happens into a PCTools.ActionResult.

    .DESCRIPTION
        Every public action wraps its work in this. It gives the whole module one
        behaviour for timing, logging, and failure: an action that throws produces
        a Failed result rather than a terminating error, so a batch run reports
        every step instead of stopping at the first problem.

        The body returns a hashtable of result fields; anything it omits is
        defaulted.

    .PARAMETER Name
        The action name recorded in the result.

    .PARAMETER Body
        The work to perform. Returns a hashtable with any of Status, Detail,
        BytesFreed, RebootRequired, Data.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$Body
    )

    Write-PCLog -Level INFO -Message "$Name : starting"
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $outcome = & $Body

        if ($outcome -isnot [hashtable]) {
            $outcome = @{ Status = 'Success'; Detail = [string]$outcome }
        }

        $stopwatch.Stop()

        $params = @{
            Action   = $Name
            Status   = if ($outcome.ContainsKey('Status')) { $outcome.Status } else { 'Success' }
            Detail   = if ($outcome.ContainsKey('Detail')) { $outcome.Detail } else { '' }
            Duration = $stopwatch.Elapsed
        }
        if ($outcome.ContainsKey('BytesFreed')) { $params['BytesFreed'] = [long]$outcome.BytesFreed }
        if ($outcome.ContainsKey('Data')) { $params['Data'] = $outcome.Data }
        if ($outcome.ContainsKey('RebootRequired') -and $outcome.RebootRequired) { $params['RebootRequired'] = $true }

        $result = New-PCActionResult @params
        Write-PCLog -Level INFO -Message "$Name : $($result.Status) - $($result.Detail)"
        return $result
    }
    catch {
        $stopwatch.Stop()
        Write-PCLog -Level ERROR -Message "$Name : failed - $($_.Exception.Message)"
        return New-PCActionResult -Action $Name -Status Failed `
            -Detail $_.Exception.Message -Duration $stopwatch.Elapsed -ErrorRecord $_
    }
}
