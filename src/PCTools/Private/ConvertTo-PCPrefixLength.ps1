function ConvertTo-PCPrefixLength {
    <#
    .SYNOPSIS
        Converts a dotted subnet mask to a CIDR prefix length.

    .DESCRIPTION
        Rejects non-contiguous masks such as 255.0.255.0, which are invalid but
        which the original tool would have passed straight to netsh.

    .EXAMPLE
        ConvertTo-PCPrefixLength -SubnetMask 255.255.255.0
        24
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$SubnetMask
    )

    $parsed = [System.Net.IPAddress]::Parse($SubnetMask)
    $bytes = $parsed.GetAddressBytes()

    if ($bytes.Count -ne 4) {
        throw "'$SubnetMask' is not an IPv4 subnet mask."
    }

    $bits = ($bytes | ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, '0') }) -join ''

    if ($bits -notmatch '^1*0*$') {
        throw "'$SubnetMask' is not a valid subnet mask: the one-bits must be contiguous."
    }

    # @() matters: with a /0 mask the pipeline yields nothing, and .Count on
    # $null is a terminating error under Set-StrictMode.
    @($bits.ToCharArray() | Where-Object { $_ -eq '1' }).Count
}
