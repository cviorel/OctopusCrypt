. (Join-Path $PSScriptRoot 'OctopusCrypt.Class.ps1' -Resolve)

$script:OctopusCrypt = New-Object OctopusCrypt

function ConvertTo-OctopusEncryptedValue {
    param($Password, $Value)
    $OctopusCrypt.Encrypt($Password, $Value)
}
function ConvertFrom-OctopusEncryptedValue {
    param($Password, $Value)
    $OctopusCrypt.Decrypt($Password, $Value)
}
function Get-OctopusHashedValue {
    param($Value)
    $OctopusCrypt.Hash($Value)
}