#Requires -Version 5.1

<#
.SYNOPSIS
Removes the current user's OpenVPN LAN Party credential and local application.

.DESCRIPTION
Use only after the server administrator has run vpn-enrollment-admin offboard.
The script validates the exact managed profile, disconnects only
OpenVPN-LAN-Party, deletes its non-exportable CNG key and certificate, removes
the profile and product shortcuts, then optionally removes the local Companion
identity. It never targets another OpenVPN profile.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$ProfilePath = "$env:USERPROFILE\OpenVPN\config\OpenVPN-LAN-Party.ovpn",
    [switch]$RemoveCompanion
)

$ErrorActionPreference = 'Stop'
$profileCandidates = @(
    $ProfilePath,
    "$env:USERPROFILE\Documents\OpenVPN\config\OpenVPN-LAN-Party.ovpn"
) | Select-Object -Unique
$profileItem = $null
foreach ($candidate in $profileCandidates) {
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        $profileItem = Get-Item -LiteralPath $candidate -Force
        break
    }
}
if (-not $profileItem) { throw 'The OpenVPN-LAN-Party profile was not found.' }
if (($profileItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The profile must not be a symbolic link or reparse point.'
}

$profile = [IO.File]::ReadAllText($profileItem.FullName)
$thumbprintMatch = [regex]::Match(
    $profile, '(?im)^\s*cryptoapicert\s+"THUMB:([A-F0-9]{40})"\s*$'
)
$modeMatch = [regex]::Match(
    $profile, '(?im)^# openvpn-lan-party-security-mode: (high-assurance|compatible)\s*$'
)
if (-not $thumbprintMatch.Success -or -not $modeMatch.Success) {
    throw 'The selected file is not a managed OpenVPN LAN Party profile.'
}
$thumbprint = $thumbprintMatch.Groups[1].Value.ToUpperInvariant()
$certificatePath = "Cert:\CurrentUser\My\$thumbprint"
$certificate = Get-Item -LiteralPath $certificatePath -ErrorAction Stop
if (-not $certificate.HasPrivateKey) { throw 'The managed certificate has no private key.' }
$privateKey = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($certificate)
if (-not $privateKey -or -not ($privateKey -is [Security.Cryptography.ECDsaCng])) {
    if ($privateKey) { $privateKey.Dispose() }
    throw 'The managed certificate is not bound to a CNG ECDSA key.'
}
try {
    $provider = $privateKey.Key.Provider.Provider
    $container = $privateKey.Key.UniqueName
    $expectedProvider = if ($modeMatch.Groups[1].Value -eq 'high-assurance') {
        'Microsoft Platform Crypto Provider'
    } else {
        'Microsoft Software Key Storage Provider'
    }
    if ($provider -cne $expectedProvider -or
        $container -cnotmatch '^OpenVPN-LAN-Party-[0-9a-f]{32}$') {
        throw 'The certificate key does not match the managed provider and container policy.'
    }
}
finally { $privateKey.Dispose() }
$certificate.Reset()

$target = "$($profileItem.FullName) / $thumbprint / $provider / $container"
if (-not $PSCmdlet.ShouldProcess($target, 'Permanently remove the local OpenVPN LAN Party identity')) {
    return
}

$gui = "$env:ProgramFiles\OpenVPN\bin\openvpn-gui.exe"
if (Test-Path -LiteralPath $gui -PathType Leaf) {
    Start-Process -FilePath $gui -ArgumentList '--command disconnect OpenVPN-LAN-Party' `
        -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -Seconds 2
}

& certutil.exe -user -csp $provider -delkey $container 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "The exact CNG key container could not be deleted (exit $LASTEXITCODE)." }
Remove-Item -LiteralPath $certificatePath -Force
$cngProvider = New-Object Security.Cryptography.CngProvider($provider)
if ([Security.Cryptography.CngKey]::Exists(
        $container, $cngProvider, [Security.Cryptography.CngKeyOpenOptions]::UserKey)) {
    throw 'The managed CNG key still exists after deletion.'
}
if (Test-Path -LiteralPath $certificatePath) {
    throw 'The managed certificate still exists after deletion.'
}
Remove-Item -LiteralPath $profileItem.FullName -Force

$shortcutPaths = @(
    (Join-Path ([Environment]::GetFolderPath('Desktop')) 'LAN Party Companion.lnk'),
    (Join-Path ([Environment]::GetFolderPath('Startup')) 'LAN Party Companion.lnk'),
    (Join-Path ([Environment]::GetFolderPath('Startup')) 'OpenVPN LAN Party.lnk'),
    (Join-Path ([Environment]::GetFolderPath('Programs')) 'OpenVPN LAN Party.lnk')
)
foreach ($shortcut in $shortcutPaths) {
    if (Test-Path -LiteralPath $shortcut -PathType Leaf) {
        Remove-Item -LiteralPath $shortcut -Force
    }
}

$companionRemoved = $false
if ($RemoveCompanion) {
    $companionRoot = Join-Path $env:LOCALAPPDATA 'OpenVPN LAN Party Companion'
    if (Test-Path -LiteralPath $companionRoot -PathType Container) {
        $companionScript = Join-Path $companionRoot 'LAN-Party-Companion.ps1'
        Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -and $_.CommandLine.IndexOf(
                $companionScript, [StringComparison]::OrdinalIgnoreCase) -ge 0 } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $companionRoot -Recurse -Force
        $companionRemoved = $true
    }
}

[pscustomobject]@{
    schema = 1
    action = 'local-identity-removed'
    certificate_thumbprint = $thumbprint
    security_mode = $modeMatch.Groups[1].Value
    profile_removed = $true
    key_container_deleted = $true
    certificate_deleted = $true
    companion_removed = $companionRemoved
} | ConvertTo-Json
