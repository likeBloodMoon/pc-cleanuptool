function Format-PCByteSize {
    <#
    .SYNOPSIS
        Formats a byte count for display.

    .EXAMPLE
        Format-PCByteSize -Bytes 4509715660
        4.2 GB
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        [System.Nullable[long]]$Bytes
    )

    process {
        if ($null -eq $Bytes) { return '-' }

        $abs = [math]::Abs($Bytes)
        $units = @(
            @{ Limit = 1PB; Suffix = 'PB'; Divisor = 1PB },
            @{ Limit = 1TB; Suffix = 'TB'; Divisor = 1TB },
            @{ Limit = 1GB; Suffix = 'GB'; Divisor = 1GB },
            @{ Limit = 1MB; Suffix = 'MB'; Divisor = 1MB },
            @{ Limit = 1KB; Suffix = 'KB'; Divisor = 1KB }
        )

        foreach ($unit in $units) {
            if ($abs -ge $unit.Limit) {
                return '{0:N1} {1}' -f ($Bytes / $unit.Divisor), $unit.Suffix
            }
        }

        '{0} B' -f $Bytes
    }
}
