#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
Performs the Windows key and connection acceptance checks for a player profile.

.DESCRIPTION
Checks the exact cryptoapicert identity, the CNG provider selected by the
profile's immutable security mode, ECDSA P-256, non-exportable policy and real
private-key export refusal. Unless -SkipConnection is supplied, it also starts
OpenVPN Community 2.7.2+ and requires a fresh successful connection.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ProfilePath,

    [string]$OpenVpnExe = "$env:ProgramFiles\OpenVPN\bin\openvpn.exe",

    [ValidateRange(10, 300)]
    [int]$ConnectionTimeoutSeconds = 90,

    [switch]$KeepConnected,

    [switch]$SkipConnection
)

$ErrorActionPreference = 'Stop'

function Read-OpenVpnLog {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    $stream = $null
    $reader = $null
    try {
        # OpenVPN keeps the log open for writing. ReadAllText uses FileShare.Read
        # and therefore conflicts with that live writer on Windows.
        $stream = [IO.FileStream]::new(
            $Path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        )
        $reader = [IO.StreamReader]::new(
            $stream, [Text.UTF8Encoding]::new($false), $true, 4096, $true
        )
        return $reader.ReadToEnd()
    }
    catch [IO.IOException] {
        # A short-lived sharing race must be retried by the bounded caller.
        return ''
    }
    finally {
        if ($reader) { $reader.Dispose() }
        if ($stream) { $stream.Dispose() }
    }
}

$profile = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $ProfilePath))
$modeMarker = [regex]::Match(
    $profile, '(?im)^# openvpn-lan-party-security-mode: (high-assurance|compatible)\s*$'
)
if (-not $modeMarker.Success) { throw 'The profile lacks its credential security-mode marker.' }
$securityMode = $modeMarker.Groups[1].Value
$provider = if ($securityMode -eq 'high-assurance') {
    'Microsoft Platform Crypto Provider'
} else {
    'Microsoft Software Key Storage Provider'
}
$selector = [regex]::Match(
    $profile, '(?im)^\s*cryptoapicert\s+"THUMB:([A-F0-9]{40})"\s*$'
)
if (-not $selector.Success) { throw 'The profile has no strict cryptoapicert thumbprint selector.' }
if ($profile -match '(?im)^\s*(key|pkcs12)\s+') {
    throw 'The profile unexpectedly references exportable private-key material.'
}
foreach ($block in @('ca', 'tls-crypt-v2')) {
    if ($profile -notmatch "(?is)<$block>.+?</$block>") {
        throw "The profile lacks the required <$block> block."
    }
}

$thumbprint = $selector.Groups[1].Value.ToUpperInvariant()
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\$thumbprint" -ErrorAction Stop
if (-not $certificate.HasPrivateKey) { throw 'The selected certificate has no private key.' }
if ($certificate.PublicKey.Oid.Value -ne '1.2.840.10045.2.1') {
    throw 'The selected certificate is not an EC certificate.'
}

$privateKey = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($certificate)
if (-not $privateKey -or -not ($privateKey -is [Security.Cryptography.ECDsaCng])) {
    if ($privateKey) { $privateKey.Dispose() }
    throw 'The selected key is not a Windows CNG ECDSA key.'
}
$exportRefused = $false
try {
    if ($privateKey.Key.Provider.Provider -cne $provider) {
        throw "The private key is not held by '$provider'."
    }
    if ($privateKey.Key.AlgorithmGroup -ne [Security.Cryptography.CngAlgorithmGroup]::ECDsa -or
        $privateKey.KeySize -ne 256) {
        throw 'The selected key is not ECDSA P-256.'
    }
    $forbidden = [Security.Cryptography.CngExportPolicies]::AllowExport -bor `
        [Security.Cryptography.CngExportPolicies]::AllowPlaintextExport
    if (($privateKey.Key.ExportPolicy -band $forbidden) -ne 0) {
        throw "The CNG key export policy is unsafe: $($privateKey.Key.ExportPolicy)."
    }
    try {
        $bytes = $privateKey.Key.Export([Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
        if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
    }
    catch [Security.Cryptography.CryptographicException] { $exportRefused = $true }
}
finally { $privateKey.Dispose() }
if (-not $exportRefused) { throw 'Critical failure: PKCS#8 private-key export succeeded.' }

if (-not (Test-Path -LiteralPath $OpenVpnExe -PathType Leaf)) {
    throw "OpenVPN Community executable not found: $OpenVpnExe"
}
$versionLine = (& $OpenVpnExe --version 2>&1 | Select-Object -First 1) -as [string]
if ($versionLine -notmatch 'OpenVPN\s+(\d+)\.(\d+)\.(\d+)') {
    throw 'Cannot determine the OpenVPN Community version.'
}
$version = [version]::new([int]$Matches[1], [int]$Matches[2], [int]$Matches[3])
if ($version -lt [version]'2.7.2') { throw "OpenVPN Community 2.7.2+ is required; found $version." }

$connected = $false
$logPath = Join-Path ([IO.Path]::GetTempPath()) ("openvpn-lan-party-acceptance-{0}.log" -f [guid]::NewGuid().ToString('N'))
$process = $null
try {
    if (-not $SkipConnection) {
        $process = Start-Process -FilePath $OpenVpnExe -ArgumentList @(
            '--config', ('"{0}"' -f (Resolve-Path -LiteralPath $ProfilePath)),
            '--log', ('"{0}"' -f $logPath), '--verb', '3'
        ) -WindowStyle Hidden -PassThru
        $deadline = [DateTime]::UtcNow.AddSeconds($ConnectionTimeoutSeconds)
        do {
            Start-Sleep -Milliseconds 500
            if (Test-Path -LiteralPath $logPath) {
                $log = Read-OpenVpnLog -Path $logPath
                if ($log -match 'Initialization Sequence Completed') { $connected = $true; break }
                if ($log -match 'AUTH_FAILED|TLS Error|Exiting due to fatal error') { break }
            }
        } while (-not $process.HasExited -and [DateTime]::UtcNow -lt $deadline)
        if (-not $connected) {
            throw "OpenVPN did not establish the tunnel; inspect $logPath before closing this session."
        }
    }

    [pscustomobject]@{
        schema = 1
        checked_at_utc = [DateTime]::UtcNow.ToString('o')
        profile = (Resolve-Path -LiteralPath $ProfilePath).Path
        certificate_thumbprint = $thumbprint
        provider = $provider
        security_mode = $securityMode
        algorithm = 'ECDSA_P256'
        private_key_export_refused = $exportRefused
        openvpn_version = $version.ToString()
        connection_tested = -not $SkipConnection
        connection_succeeded = $connected
        connection_kept_active = $connected -and $KeepConnected
        openvpn_process_id = if ($connected -and $KeepConnected) { $process.Id } else { $null }
        openvpn_log = if ($connected -and $KeepConnected) { $logPath } else { $null }
    } | ConvertTo-Json
}
finally {
    if ($process -and -not $process.HasExited -and (-not $connected -or -not $KeepConnected)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
    if (($connected -and -not $KeepConnected) -or $SkipConnection) {
        Remove-Item -LiteralPath $logPath -Force -ErrorAction SilentlyContinue
    }
}
