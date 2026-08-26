function New-PCActionResult {
    <#
    .SYNOPSIS
        Builds the single result object every PCTools action returns.

    .DESCRIPTION
        The whole module speaks one shape. The GUI renders it, the console host
        formats it, and Export-PCReport serialises it - none of them need to know
        which action produced it. This is what replaced "write a line to the log
        box and return nothing".

    .PARAMETER Action
        The action name, e.g. 'Clear-PCTempFile'.

    .PARAMETER Status
        Success, Warning, Failed or Skipped.

    .PARAMETER Detail
        Human-readable outcome, shown in the UI.

    .PARAMETER BytesFreed
        Disk space reclaimed, if the action reclaims any.

    .PARAMETER Duration
        How long the action took.

    .PARAMETER RebootRequired
        Whether the change only takes full effect after a restart.

    .PARAMETER Error
        The terminating error, when Status is Failed.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$Action,

        [Parameter(Mandatory)]
        [ValidateSet('Success', 'Warning', 'Failed', 'Skipped')]
        [string]$Status,

        [string]$Detail = '',

        [long]$BytesFreed = 0,

        [timespan]$Duration = [timespan]::Zero,

        [switch]$RebootRequired,

        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [hashtable]$Data
    )

    $result = [pscustomobject]@{
        PSTypeName     = 'PCTools.ActionResult'
        Action         = $Action
        Status         = $Status
        Detail         = $Detail
        BytesFreed     = $BytesFreed
        Duration       = $Duration
        RebootRequired = [bool]$RebootRequired
        Timestamp      = Get-Date
        ErrorRecord    = $ErrorRecord
        Data           = $Data
    }

    Add-Member -InputObject $result -MemberType ScriptProperty -Name FreedDisplay -Value {
        Format-PCByteSize -Bytes $this.BytesFreed
    }

    $result
}
