#Requires -Version 5.1

<#
.SYNOPSIS
Removes one explicitly confirmed disposable OpenVPN LAN Party identity.

.DESCRIPTION
This destructive acceptance helper refuses broad or inferred deletion. The
profile must contain one exact disposable player marker, enrollment ID,
technical certificate CN, immutable security mode and cryptoapicert thumbprint.
All four caller confirmations must match before the script inspects and removes
the associated CurrentUser CNG key container and leaf certificate.

The OpenVPN profile and Companion files are deliberately retained so the
key-loss recovery test can prove that the old profile no longer connects and
that re-enrollment preserves companion.json.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ProfilePath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^DisposableTest-[A-Za-z0-9][A-Za-z0-9_.-]{0,38}$')]
    [string]$DisposablePlayerName,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedEnrollmentId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^vpn-player:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')]
    [string]$ExpectedCertificateCn,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{40}$')]
    [string]$ExpectedThumbprint
)

$ErrorActionPreference = 'Stop'

function Read-SingleProfileValue {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $matches = [regex]::Matches($Text, $Pattern)
    if ($matches.Count -ne 1) {
        throw "The profile must contain exactly one $Description."
    }
    return $matches[0].Groups[1].Value
}

function Get-ReadOnlySha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    # Get-FileHash delegates path resolution to a provider cmdlet that honours
    # the caller's -WhatIf preference. That makes a read-only audit skip its
    # hash and return null. Use .NET directly so -WhatIf remains informative
    # while still preventing every mutating operation.
    $stream = $null
    $sha256 = $null
    try {
        $stream = [IO.FileStream]::new(
            $Path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        )
        $sha256 = [Security.Cryptography.SHA256]::Create()
        return ([BitConverter]::ToString($sha256.ComputeHash($stream))).Replace('-', '')
    }
    finally {
        if ($sha256) { $sha256.Dispose() }
        if ($stream) { $stream.Dispose() }
    }
}

if (Get-Process -Name openvpn -ErrorAction SilentlyContinue) {
    throw 'Stop every OpenVPN process before deleting the disposable identity.'
}

$profileItem = Get-Item -LiteralPath $ProfilePath -ErrorAction Stop
if (($profileItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The disposable OpenVPN profile must not be a reparse point.'
}
$resolvedProfile = $profileItem.FullName
$profileHashBefore = Get-ReadOnlySha256 -Path $resolvedProfile
$companionPath = Join-Path $env:LOCALAPPDATA 'OpenVPN LAN Party Companion\companion.json'
$companionPresent = Test-Path -LiteralPath $companionPath -PathType Leaf
$companionHashBefore = if ($companionPresent) {
    Get-ReadOnlySha256 -Path $companionPath
} else { $null }
$profile = [IO.File]::ReadAllText($resolvedProfile)
$player = Read-SingleProfileValue -Text $profile `
    -Pattern '(?im)^# openvpn-lan-party-player: ([A-Za-z0-9][A-Za-z0-9_.-]{0,63})\s*$' `
    -Description 'disposable player marker'
$enrollmentId = Read-SingleProfileValue -Text $profile `
    -Pattern '(?im)^# openvpn-lan-party-enrollment-id: ([a-f0-9]{64})\s*$' `
    -Description 'enrollment ID marker'
$certificateCn = Read-SingleProfileValue -Text $profile `
    -Pattern '(?im)^# openvpn-lan-party-certificate-cn: (vpn-player:[0-9a-f-]{36})\s*$' `
    -Description 'certificate CN marker'
$securityMode = Read-SingleProfileValue -Text $profile `
    -Pattern '(?im)^# openvpn-lan-party-security-mode: (high-assurance|compatible)\s*$' `
    -Description 'security-mode marker'
$thumbprint = Read-SingleProfileValue -Text $profile `
    -Pattern '(?im)^\s*cryptoapicert\s+"THUMB:([A-F0-9]{40})"\s*$' `
    -Description 'strict cryptoapicert selector'

if ($player -cne $DisposablePlayerName) {
    throw 'The confirmed disposable player does not match the profile.'
}
if ($enrollmentId -cne $ExpectedEnrollmentId.ToLowerInvariant()) {
    throw 'The confirmed enrollment ID does not match the profile.'
}
if ($certificateCn -cne $ExpectedCertificateCn) {
    throw 'The confirmed certificate CN does not match the profile.'
}
$thumbprint = $thumbprint.ToUpperInvariant()
if ($thumbprint -cne $ExpectedThumbprint.ToUpperInvariant()) {
    throw 'The confirmed certificate thumbprint does not match the profile.'
}

$providerName = if ($securityMode -eq 'high-assurance') {
    'Microsoft Platform Crypto Provider'
} else {
    'Microsoft Software Key Storage Provider'
}
$certificatePath = "Cert:\CurrentUser\My\$thumbprint"
$certificate = Get-Item -LiteralPath $certificatePath -ErrorAction Stop
if ($certificate.Subject -cne "CN=$certificateCn" -or -not $certificate.HasPrivateKey) {
    throw 'The selected certificate does not match the confirmed identity or lacks its private key.'
}
if ($certificate.PublicKey.Oid.Value -ne '1.2.840.10045.2.1') {
    throw 'The selected certificate is not an EC certificate.'
}

$privateKey = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($certificate)
if (-not $privateKey -or -not ($privateKey -is [Security.Cryptography.ECDsaCng])) {
    if ($privateKey) { $privateKey.Dispose() }
    throw 'The selected private key is not a Windows CNG ECDSA key.'
}
try {
    if ($privateKey.Key.Provider.Provider -cne $providerName) {
        throw "The selected private key is not held by '$providerName'."
    }
    if ($privateKey.Key.AlgorithmGroup -ne [Security.Cryptography.CngAlgorithmGroup]::ECDsa -or
        $privateKey.KeySize -ne 256) {
        throw 'The selected private key is not ECDSA P-256.'
    }
    $keyContainer = $privateKey.Key.KeyName
    if ($keyContainer -cnotmatch '^OpenVPN-LAN-Party-[0-9a-f]{32}$') {
        throw 'The CNG key container was not created by the enrollment client.'
    }
}
finally { $privateKey.Dispose() }
$certificate.Reset()

$target = "$player / $certificateCn / $thumbprint / $keyContainer"
if (-not $PSCmdlet.ShouldProcess($target, 'Permanently delete the disposable CNG private key and leaf certificate')) {
    [pscustomobject]@{
        schema = 1
        action = 'planned'
        player = $player
        enrollment_id = $enrollmentId
        certificate_cn = $certificateCn
        certificate_thumbprint = $thumbprint
        provider = $providerName
        key_container = $keyContainer
        profile_sha256 = $profileHashBefore
        companion_present = $companionPresent
        profile_retained = $true
    } | ConvertTo-Json
    return
}

$certutilOutput = @(& certutil.exe -user -csp $providerName -delkey $keyContainer 2>&1)
$certutilExit = $LASTEXITCODE
if ($certutilExit -ne 0) {
    $certutilDetail = (($certutilOutput | ForEach-Object { [string]$_ }) -join ' | ').Trim()
    if ($certutilDetail.Length -gt 2048) {
        $certutilDetail = $certutilDetail.Substring(0, 2048)
    }
    throw "certutil failed to delete the exact CNG key container (exit $certutilExit): $certutilDetail"
}
Remove-Item -Path $certificatePath

$provider = New-Object Security.Cryptography.CngProvider($providerName)
if ([Security.Cryptography.CngKey]::Exists(
        $keyContainer, $provider, [Security.Cryptography.CngKeyOpenOptions]::UserKey)) {
    throw 'The disposable CNG key container still exists after deletion.'
}
if (Test-Path -LiteralPath $certificatePath) {
    throw 'The disposable certificate still exists after deletion.'
}
if (-not (Test-Path -LiteralPath $resolvedProfile -PathType Leaf) -or
    (Get-ReadOnlySha256 -Path $resolvedProfile) -cne $profileHashBefore) {
    throw 'The OpenVPN profile changed unexpectedly during identity deletion.'
}
$companionPresentAfter = Test-Path -LiteralPath $companionPath -PathType Leaf
if ($companionPresentAfter -ne $companionPresent -or
    ($companionPresent -and
     (Get-ReadOnlySha256 -Path $companionPath) -cne $companionHashBefore)) {
    throw 'companion.json changed unexpectedly during identity deletion.'
}

[pscustomobject]@{
    schema = 1
    action = 'deleted'
    player = $player
    enrollment_id = $enrollmentId
    certificate_cn = $certificateCn
    certificate_thumbprint = $thumbprint
    provider = $providerName
    key_container_deleted = $true
    certificate_deleted = $true
    profile_sha256 = $profileHashBefore
    companion_present = $companionPresent
    profile_retained = $true
    companion_untouched = $true
} | ConvertTo-Json
