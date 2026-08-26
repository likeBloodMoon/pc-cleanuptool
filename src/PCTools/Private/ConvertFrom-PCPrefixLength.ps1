function ConvertFrom-PCPrefixLength {
    <#
    .SYNOPSIS
        Converts a CIDR prefix length to a dotted subnet mask.

    .EXAMPLE
        ConvertFrom-PCPrefixLength -PrefixLength 24
        255.255.255.0
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateRange(0, 32)]
        [int]$PrefixLength
    )

    $bits = ('1' * $PrefixLength).PadRight(32, '0')
    $octets = for ($i = 0; $i -lt 32; $i += 8) {
        [Convert]::ToInt32($bits.Substring($i, 8), 2)
    }

    $octets -join '.'
}
