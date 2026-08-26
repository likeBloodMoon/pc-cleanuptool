function Unregister-PCLogSink {
    <#
    .SYNOPSIS
        Removes a log sink registered with Register-PCLogSink.

    .PARAMETER Id
        The sink id returned by Register-PCLogSink. Omit -Id and pass -All to
        clear every sink.

    .PARAMETER All
        Remove all registered sinks.
    #>
    [CmdletBinding(DefaultParameterSetName = 'ById')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'ById')]
        [guid]$Id,

        [Parameter(Mandatory, ParameterSetName = 'All')]
        [switch]$All
    )

    if ($All) {
        $script:PCLogSinkTable.Clear()
    }
    elseif ($script:PCLogSinkTable.ContainsKey($Id)) {
        $script:PCLogSinkTable.Remove($Id)
    }

    $script:PCLogSinks = @($script:PCLogSinkTable.Values)
}
