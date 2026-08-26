function Register-PCLogSink {
    <#
    .SYNOPSIS
        Routes PCTools log lines to a caller-supplied scriptblock.

    .DESCRIPTION
        The module writes to its log file unconditionally. A host that also wants
        the lines - to append to a ListView, colour a console, or collect them in
        a test - registers a sink here.

        The sink receives one object per line with Timestamp, Level, Message and
        a preformatted Line property.

        A sink must not block. If it marshals to a UI thread, it should post
        rather than wait.

    .PARAMETER Sink
        The scriptblock to invoke per log line.

    .EXAMPLE
        Register-PCLogSink { param($entry) $listBox.Items.Add($entry.Line) }

    .OUTPUTS
        System.Guid - the sink id, for Unregister-PCLogSink.
    #>
    [CmdletBinding()]
    [OutputType([guid])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [scriptblock]$Sink
    )

    $id = [guid]::NewGuid()
    $script:PCLogSinkTable[$id] = $Sink
    $script:PCLogSinks = @($script:PCLogSinkTable.Values)
    $id
}
