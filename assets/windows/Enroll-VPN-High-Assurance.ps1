#Requires -Version 5.1

<#
.SYNOPSIS
Enrols the current Windows user with the invitation-selected security mode.

.DESCRIPTION
Creates a non-exportable ECDSA P-256 key with either Microsoft Platform Crypto
Provider (high-assurance mode) or Microsoft Software Key Storage Provider
(compatible mode), submits only its PKCS#10 request, accepts the issued
certificate into CurrentUser\My, and writes an OpenVPN profile selecting it by
thumbprint. The server mode is immutable and authenticated by the pinned
enrolment endpoint; there is no automatic fallback between providers.

High-assurance mode requires an elevated Windows PowerShell console to query TPM
2.0 readiness. Compatible mode does not require a TPM or elevation. In both
modes the identity remains in the invoking user's store.

-WhatIf is deliberately side-effect free: it performs no TPM, certreq, HTTP,
certificate-store or file operation. It is suitable for packaging/CI tests.

This client verifies the key provider locally. It does not provide remote TPM
attestation; the server must not interpret a high-assurance CSR as hardware
attestation.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$')]
    [string]$PlayerName,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^https://')]
    [uri]$EnrollmentUri,

    [string]$InvitationToken,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$TlsCertificateSha256,

    [string]$OutputProfile = (Join-Path $env:USERPROFILE 'OpenVPN\config\OpenVPN-LAN-Party.ovpn'),

    [ValidateRange(1, 3600)]
    [int]$PollSeconds = 5,

    [ValidateRange(1, 240)]
    [int]$TimeoutMinutes = 15,

    [ValidateSet('high-assurance', 'compatible')]
    [string]$ExpectedSecurityMode,

    [scriptblock]$StatusCallback
)

$ErrorActionPreference = 'Stop'
$script:PlatformProvider = 'Microsoft Platform Crypto Provider'
$script:SoftwareProvider = 'Microsoft Software Key Storage Provider'
$script:KeyProvider = $null
$script:SecurityMode = $null
$script:Artifacts = New-Object System.Collections.Generic.List[string]
$script:TemporaryDirectories = New-Object System.Collections.Generic.List[string]
$script:KeyContainer = $null
$script:InstalledThumbprint = $null
$script:EnrollmentCompleted = $false
$script:TlsPin = $TlsCertificateSha256.ToUpperInvariant()
$script:TlsPinInstalled = $false
$script:CertificateCnPattern = '^vpn-player:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
$script:EnrollmentIdPattern = '^[0-9a-f]{64}$'

function Get-ExistingCompanionPlayer {
    $configPath = Join-Path $env:LOCALAPPDATA 'OpenVPN LAN Party Companion\companion.json'
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { return $null }
    $item = Get-Item -LiteralPath $configPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -gt 8192) {
        throw 'The existing Companion identity file is unsafe or too large.'
    }
    try { $config = [IO.File]::ReadAllText($configPath, [Text.Encoding]::UTF8) | ConvertFrom-Json }
    catch { throw 'The existing Companion identity file is invalid.' }
    $player = [string]$config.player
    if ([int]$config.version -ne 1 -or $player -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$') {
        throw 'The existing Companion identity file is invalid.'
    }
    return $player
}

function Assert-CompanionPlayerCompatibility {
    $existingPlayer = Get-ExistingCompanionPlayer
    if ($existingPlayer -and $existingPlayer -cne $PlayerName) {
        throw "This Windows profile already contains Companion identity '$existingPlayer'; refusing enrollment for '$PlayerName'."
    }
}

function Install-ProcessTlsPin {
    # A PowerShell scriptblock used directly as the certificate callback can be
    # invoked by Schannel on a worker thread without a PowerShell runspace. A
    # small in-memory .NET callback avoids that Windows PowerShell 5.1 failure.
    $source = @'
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public static class OpenVpnEnrollmentTlsPin
{
    private static readonly object Sync = new object();
    private static byte[] Expected;
    private static RemoteCertificateValidationCallback Previous;
    private static bool Installed;

    public static void Install(string hexadecimal)
    {
        if (hexadecimal == null || hexadecimal.Length != 64)
            throw new ArgumentException("A SHA-256 certificate pin is required.");
        byte[] parsed = new byte[32];
        for (int i = 0; i < parsed.Length; i++)
            parsed[i] = Convert.ToByte(hexadecimal.Substring(i * 2, 2), 16);
        lock (Sync)
        {
            if (Installed) throw new InvalidOperationException("TLS pin is already installed.");
            Expected = parsed;
            Previous = ServicePointManager.ServerCertificateValidationCallback;
            ServicePointManager.ServerCertificateValidationCallback = Validate;
            Installed = true;
        }
    }

    public static bool Validate(object sender, X509Certificate certificate,
        X509Chain chain, SslPolicyErrors errors)
    {
        if (certificate == null) return false;
        byte[] expected;
        lock (Sync)
        {
            if (!Installed || Expected == null) return false;
            expected = (byte[])Expected.Clone();
        }
        byte[] actual;
        using (SHA256 sha256 = SHA256.Create())
            actual = sha256.ComputeHash(certificate.GetRawCertData());
        int difference = actual.Length ^ expected.Length;
        int length = Math.Min(actual.Length, expected.Length);
        for (int i = 0; i < length; i++) difference |= actual[i] ^ expected[i];
        Array.Clear(actual, 0, actual.Length);
        Array.Clear(expected, 0, expected.Length);
        return difference == 0;
    }

    public static void Restore()
    {
        lock (Sync)
        {
            if (!Installed) return;
            ServicePointManager.ServerCertificateValidationCallback = Previous;
            if (Expected != null) Array.Clear(Expected, 0, Expected.Length);
            Expected = null;
            Previous = null;
            Installed = false;
        }
    }
}
'@
    if (-not ('OpenVpnEnrollmentTlsPin' -as [type])) {
        Add-Type -TypeDefinition $source -Language CSharp
    }
    [OpenVpnEnrollmentTlsPin]::Install($script:TlsPin)
    $script:TlsPinInstalled = $true
}

if ([string]::IsNullOrWhiteSpace($InvitationToken)) {
    if ($WhatIfPreference) {
        $InvitationToken = 'WHATIF-TOKEN'
    }
    else {
        $secureToken = Read-Host 'Paste the one-time invitation token' -AsSecureString
        $tokenPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
        try { $InvitationToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tokenPointer) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tokenPointer) }
        $secureToken.Dispose()
    }
}
if ([string]::IsNullOrWhiteSpace($InvitationToken)) {
    throw 'The one-time invitation token is required.'
}

function Write-Step {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "`n==> $Message" -ForegroundColor Cyan
    Publish-EnrollmentStatus -Event 'step' -Data @{ message = $Message }
}

function Publish-EnrollmentStatus {
    param(
        [Parameter(Mandatory = $true)][string]$Event,
        [hashtable]$Data = @{}
    )
    if ($StatusCallback) {
        & $StatusCallback $Event ([pscustomobject]$Data)
    }
}

function Remove-SensitiveArtifact {
    param([AllowNull()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if ($WhatIfPreference) { return }
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    }
}

function Remove-OrphanedCngKey {
    # A failed enrolment must not accumulate unusable CNG keys. The generated
    # container name is random and is never accepted from the server or caller.
    if ($WhatIfPreference -or $script:EnrollmentCompleted -or
        [string]::IsNullOrWhiteSpace($script:KeyContainer)) { return }
    & certutil.exe -user -csp $script:KeyProvider -delkey $script:KeyContainer 2>&1 | Out-Null
}

function Remove-OrphanedCertificate {
    if ($WhatIfPreference -or $script:EnrollmentCompleted -or
        [string]::IsNullOrWhiteSpace($script:InstalledThumbprint)) { return }
    $path = "Cert:\CurrentUser\My\$($script:InstalledThumbprint)"
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}

function Assert-PrivateKeyNonExportable {
    param([Parameter(Mandatory = $true)]$Certificate)
    if ($WhatIfPreference) { return }
    $privateKey = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($Certificate)
    if (-not $privateKey -or -not ($privateKey -is [Security.Cryptography.ECDsaCng])) {
        if ($privateKey) { $privateKey.Dispose() }
        throw 'The accepted certificate does not expose the expected Windows CNG ECDSA key.'
    }
    try {
        if ($privateKey.Key.Provider.Provider -cne $script:KeyProvider) {
            throw "The private key is not held by '$($script:KeyProvider)'."
        }
        if ($privateKey.Key.AlgorithmGroup -ne [Security.Cryptography.CngAlgorithmGroup]::ECDsa -or
            $privateKey.KeySize -ne 256) {
            throw 'The private key is not ECDSA P-256.'
        }
        $policy = $privateKey.Key.ExportPolicy
        $forbidden = [Security.Cryptography.CngExportPolicies]::AllowExport -bor `
            [Security.Cryptography.CngExportPolicies]::AllowPlaintextExport
        if (($policy -band $forbidden) -ne 0) {
            throw "The private key has an exportable CNG policy ($policy)."
        }
        $exportSucceeded = $false
        try {
            $discard = $privateKey.Key.Export([Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
            $exportSucceeded = $true
            if ($discard) { [Array]::Clear($discard, 0, $discard.Length) }
        }
        catch [Security.Cryptography.CryptographicException] {
            # Expected: both supported providers refuse private-key export.
        }
        if ($exportSucceeded) {
            throw 'Critical policy failure: the private key was exported.'
        }
    }
    finally { $privateKey.Dispose() }
}

function Assert-StrictTpm20 {
    if ($WhatIfPreference) {
        return [pscustomobject]@{ TpmPresent = $true; TpmReady = $true; ManufacturerVersion = 'WHATIF-TPM-2.0' }
    }
    $command = Get-Command Get-Tpm -ErrorAction SilentlyContinue
    if (-not $command) { throw 'Get-Tpm is unavailable; TPM 2.0 readiness cannot be verified.' }
    try { $tpm = Get-Tpm -ErrorAction Stop }
    catch { throw "TPM 2.0 readiness could not be queried: $($_.Exception.Message)" }
    if (-not $tpm.TpmPresent -or -not $tpm.TpmReady -or $tpm.LockedOut) {
        throw 'A ready, unlocked TPM 2.0 is required. Software-key fallback is forbidden.'
    }
    # Provider availability is verified without locale-sensitive command output:
    # certreq must create the key with the named provider, and the accepted CNG
    # key is checked directly through ECDsaCng before enrolment can complete.
    return $tpm
}

function Assert-SupportedWindows {
    if ($WhatIfPreference) {
        return [pscustomobject]@{ Build = 22631; DisplayVersion = '23H2' }
    }
    $os = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $build = 0
    if (-not [int]::TryParse([string]$os.CurrentBuildNumber, [ref]$build)) {
        throw 'The Windows build number could not be determined.'
    }
    $displayVersion = [string]$os.DisplayVersion
    if ($script:SecurityMode -eq 'high-assurance') {
        if ($build -lt 22000) {
            throw 'High-assurance mode requires Windows 11 and a ready TPM 2.0.'
        }
    }
    elseif ($build -eq 19045) {
        if ($displayVersion -cne '22H2') {
            throw 'Compatible mode supports Windows 10 only at release 22H2 (build 19045).'
        }
    }
    elseif ($build -lt 22000) {
        throw 'Compatible mode requires Windows 10 22H2 (build 19045) or Windows 11.'
    }
    return [pscustomobject]@{ Build = $build; DisplayVersion = $displayVersion }
}

function Assert-SecurityModePrerequisites {
    $windows = Assert-SupportedWindows
    if ($script:SecurityMode -eq 'compatible') {
        return [pscustomobject]@{
            SecurityMode = 'compatible'; TpmRequired = $false
            WindowsBuild = $windows.Build; DisplayVersion = $windows.DisplayVersion
        }
    }
    if (-not $WhatIfPreference) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'High-assurance mode requires an elevated Windows PowerShell console to verify TPM 2.0 readiness.'
        }
    }
    $tpm = Assert-StrictTpm20
    return [pscustomobject]@{
        SecurityMode = 'high-assurance'; TpmRequired = $true
        WindowsBuild = $windows.Build; DisplayVersion = $windows.DisplayVersion
        Tpm = $tpm
    }
}

function New-Pkcs10Request {
    param([Parameter(Mandatory = $true)][string]$CommonName)

    if ($WhatIfPreference) {
        return [pscustomobject]@{
            CsrPath = '<what-if>/player.req'
            CsrPem = "-----BEGIN CERTIFICATE REQUEST-----`nWHATIF-PKCS10-ECDSA-P256`n-----END CERTIFICATE REQUEST-----"
        }
    }

    $work = Join-Path ([IO.Path]::GetTempPath()) ("openvpn-lan-party-{0}" -f [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($work) | Out-Null
    $script:TemporaryDirectories.Add($work)
    $script:KeyContainer = "OpenVPN-LAN-Party-{0}" -f [guid]::NewGuid().ToString('N')
    $infPath = Join-Path $work 'request.inf'
    $csrPath = Join-Path $work 'player.req'
    $script:Artifacts.Add($infPath)
    $script:Artifacts.Add($csrPath)

    # The server-assigned certificate CN was constrained to a UUID-only pattern,
    # so it cannot inject another INF directive or subject component.
    $inf = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "CN=$CommonName"
KeyAlgorithm = ECDSA_P256
ProviderName = "$($script:KeyProvider)"
KeyContainer = "$($script:KeyContainer)"
Exportable = FALSE
MachineKeySet = FALSE
RequestType = PKCS10
HashAlgorithm = SHA256
SuppressDefaults = TRUE
Silent = TRUE
"@
    [IO.File]::WriteAllText($infPath, $inf, (New-Object Text.UTF8Encoding($false)))
    & certreq.exe -new -q $infPath $csrPath | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $csrPath -PathType Leaf)) {
        throw "certreq failed to create the non-exportable PKCS#10 request (exit $LASTEXITCODE)."
    }

    $inspection = & certutil.exe -dump $csrPath 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or $inspection -notmatch 'ECDSA_P256|1\.2\.840\.10045\.3\.1\.7') {
        throw 'The generated CSR is not an ECDSA P-256 request.'
    }
    $csrBytes = [IO.File]::ReadAllBytes($csrPath)
    if ($csrBytes.Length -eq 0 -or $csrBytes.Length -gt 65536) {
        throw 'The generated PKCS#10 request has an invalid size.'
    }
    $ascii = [Text.Encoding]::ASCII.GetString($csrBytes)
    $pemMatch = [regex]::Match(
        $ascii,
        '(?s)-----BEGIN (?:NEW )?CERTIFICATE REQUEST-----\s*(?<body>[A-Za-z0-9+/=\s]+?)\s*-----END (?:NEW )?CERTIFICATE REQUEST-----'
    )
    if ($pemMatch.Success) {
        try { $der = [Convert]::FromBase64String(($pemMatch.Groups['body'].Value -replace '\s', '')) }
        catch { throw 'certreq produced a malformed PEM PKCS#10 request.' }
    }
    elseif ($csrBytes[0] -eq 0x30) {
        # certreq commonly writes PKCS#10 as DER even when the destination uses
        # a .req suffix. Canonicalise it before sending JSON to the portal.
        $der = $csrBytes
    }
    else {
        throw 'certreq produced an unsupported PKCS#10 encoding.'
    }
    $base64 = [Convert]::ToBase64String($der)
    $lines = New-Object System.Collections.Generic.List[string]
    for ($offset = 0; $offset -lt $base64.Length; $offset += 64) {
        $length = [Math]::Min(64, $base64.Length - $offset)
        $lines.Add($base64.Substring($offset, $length))
    }
    $csrPem = "-----BEGIN CERTIFICATE REQUEST-----`n$($lines -join "`n")`n-----END CERTIFICATE REQUEST-----"
    return [pscustomobject]@{ CsrPath = $csrPath; CsrPem = $csrPem }
}

function ConvertFrom-BoundedJsonResponse {
    param(
        [Parameter(Mandatory = $true)]$Response,
        [Parameter(Mandatory = $true)][ValidateRange(1, 2097152)][int]$MaximumBytes
    )
    $declaredLength = $Response.Headers['Content-Length']
    if ($declaredLength -and [long]$declaredLength -gt $MaximumBytes) {
        throw "Enrollment response exceeds the $MaximumBytes-byte limit."
    }
    $content = [string]$Response.Content
    if ([Text.Encoding]::UTF8.GetByteCount($content) -gt $MaximumBytes) {
        throw "Enrollment response exceeds the $MaximumBytes-byte limit."
    }
    if ([string]::IsNullOrWhiteSpace($content)) { throw 'Enrollment server returned an empty response.' }
    try { return $content | ConvertFrom-Json }
    catch { throw "Enrollment server returned invalid JSON: $($_.Exception.Message)" }
}

function Invoke-BoundedJsonRequest {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Get', 'Post')][string]$Method,
        [Parameter(Mandatory = $true)][uri]$Uri,
        [Parameter(Mandatory = $true)][hashtable]$Headers,
        [AllowNull()][string]$Body,
        [Parameter(Mandatory = $true)][int]$MaximumBytes
    )
    if ($Uri.Scheme -cne 'https') { throw 'Enrollment requests require HTTPS.' }
    # PowerShell 5.1 can otherwise negotiate legacy protocols depending on the
    # host configuration. This process-local setting requires TLS 1.2 and blocks
    # all older protocol versions supported by Windows PowerShell 5.1.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $parameters = @{ Method = $Method; Uri = $Uri; Headers = $Headers; UseBasicParsing = $true }
    if ($Method -eq 'Post') {
        $parameters.ContentType = 'application/json'
        $parameters.Body = $Body
    }
    $response = Invoke-WebRequest @parameters
    return ConvertFrom-BoundedJsonResponse -Response $response -MaximumBytes $MaximumBytes
}

function Invoke-EnrollmentHttp {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Challenge', 'Submit', 'Collect')][string]$Operation,
        [Parameter(Mandatory = $true)][uri]$BaseUri,
        [Parameter(Mandatory = $true)][string]$Token,
        [AllowNull()][string]$CsrPem,
        [AllowNull()][string]$EnrollmentId
    )
    if ($WhatIfPreference) {
        if ($Operation -eq 'Challenge') {
            return [pscustomobject]@{
                player = $PlayerName
                enrollment_id = ('a' * 64)
                credential_id = '01234567-89ab-4cde-8fab-0123456789ab'
                certificate_cn = 'vpn-player:01234567-89ab-4cde-8fab-0123456789ab'
                security_mode = if ($ExpectedSecurityMode) { $ExpectedSecurityMode } else { 'high-assurance' }
            }
        }
        if ($Operation -eq 'Submit') {
            return [pscustomobject]@{
                request_id = 'what-if-request'; state = 'csr-submitted'
                spki_sha256 = ('b' * 64); comparison_code = 'bbbb-bbbb'
            }
        }
        return [pscustomobject]@{
            request_id = 'what-if-request'; state = 'approved'
            enrollment_id = ('a' * 64)
            credential_id = '01234567-89ab-4cde-8fab-0123456789ab'
            certificate_cn = 'vpn-player:01234567-89ab-4cde-8fab-0123456789ab'
            certificate_pem = 'WHATIF-CERTIFICATE'; ca_pem = 'WHATIF-CA'
            tls_crypt_v2 = 'WHATIF-TLS-CRYPT-V2'; openvpn_config = "client`ndev tap`n"
            security_mode = if ($ExpectedSecurityMode) { $ExpectedSecurityMode } else { 'high-assurance' }
            companion_provisioning = 'preserved-existing'
        }
    }

    $headers = @{ Authorization = "Bearer $Token"; Accept = 'application/json' }
    $root = $BaseUri.AbsoluteUri.TrimEnd('/')
    if ($Operation -eq 'Challenge') {
        return Invoke-BoundedJsonRequest -Method Get -Uri "$root/api/v2/enrollments/challenge" -Headers $headers -MaximumBytes 16384
    }
    if ($Operation -eq 'Submit') {
        $body = @{
            enrollment_id = $EnrollmentId
            csr = $CsrPem
        } |
            ConvertTo-Json -Depth 4
        return Invoke-BoundedJsonRequest -Method Post -Uri "$root/api/v2/enrollments" -Headers $headers -Body $body -MaximumBytes 32768
    }
    return Invoke-BoundedJsonRequest -Method Get -Uri "$root/api/v2/enrollments/result" -Headers $headers -MaximumBytes 1048576
}

function Assert-EnrollmentChallenge {
    param([Parameter(Mandatory = $true)]$Challenge)
    if ([string]$Challenge.player -cne $PlayerName) {
        throw 'The invitation player does not exactly match the requested player.'
    }
    if ([string]$Challenge.enrollment_id -cnotmatch $script:EnrollmentIdPattern) {
        throw 'The challenge contains an invalid enrollment_id.'
    }
    if ([string]$Challenge.certificate_cn -cnotmatch $script:CertificateCnPattern) {
        throw 'The challenge contains an invalid technical certificate_cn.'
    }
    $credentialId = [string]$Challenge.credential_id
    $expectedCredentialId = ([string]$Challenge.certificate_cn).Substring('vpn-player:'.Length)
    if ($credentialId -cne $expectedCredentialId) {
        throw 'The challenge credential_id and certificate_cn are inconsistent.'
    }
    $mode = [string]$Challenge.security_mode
    if ($mode -notin @('high-assurance', 'compatible')) {
        throw 'The challenge contains an invalid security mode.'
    }
    if ($ExpectedSecurityMode -and $mode -cne $ExpectedSecurityMode) {
        throw "The server security mode '$mode' does not match expected mode '$ExpectedSecurityMode'."
    }
}

function Assert-CollectedCredential {
    param([Parameter(Mandatory = $true)]$Response, [Parameter(Mandatory = $true)]$Challenge)
    if ([string]$Response.credential_id -cne [string]$Challenge.credential_id -or
        [string]$Response.certificate_cn -cne [string]$Challenge.certificate_cn -or
        [string]$Response.security_mode -cne [string]$Challenge.security_mode) {
        throw 'Collected credential metadata does not match the original challenge.'
    }
    $fieldLimits = @{
        certificate_pem = 65536; ca_pem = 65536
        tls_crypt_v2 = 65536; openvpn_config = 262144
    }
    foreach ($field in $fieldLimits.Keys) {
        $value = [string]$Response.$field
        if ([string]::IsNullOrWhiteSpace($value)) { throw "Server response lacks '$field'." }
        if ([Text.Encoding]::UTF8.GetByteCount($value) -gt $fieldLimits[$field]) {
            throw "Server response field '$field' exceeds its size limit."
        }
    }
    $provisioning = [string]$Response.companion_provisioning
    if ($provisioning -notin @('included', 'preserved-existing')) {
        throw 'Server response contains an invalid Companion provisioning state.'
    }
    if ($provisioning -in @('included', 'preserved-existing') -and
        -not ($WhatIfPreference -and $provisioning -eq 'preserved-existing')) {
        foreach ($field in @('companion_script_b64', 'companion_launcher_b64', 'offboarding_script_b64')) {
            if ([string]::IsNullOrWhiteSpace([string]$Response.$field)) {
                throw "Server response lacks '$field'."
            }
        }
        if (([string]$Response.companion_script_b64).Length -gt 196608 -or
            ([string]$Response.companion_launcher_b64).Length -gt 4096 -or
            ([string]$Response.offboarding_script_b64).Length -gt 65536) {
            throw 'Server Companion bundle exceeds its size limit.'
        }
        if ($provisioning -eq 'included' -and
            ([string]::IsNullOrWhiteSpace([string]$Response.companion_config) -or
             [Text.Encoding]::UTF8.GetByteCount([string]$Response.companion_config) -gt 8192)) {
            throw 'Server Companion configuration is missing or exceeds its size limit.'
        }
    }
}

function Wait-EnrollmentApproval {
    param(
        [Parameter(Mandatory = $true)][uri]$BaseUri,
        [Parameter(Mandatory = $true)][string]$Token,
        [Parameter(Mandatory = $true)]$Challenge
    )
    if ($WhatIfPreference) {
        $result = Invoke-EnrollmentHttp -Operation Collect -BaseUri $BaseUri -Token $Token
        Assert-CollectedCredential -Response $result -Challenge $Challenge
        return $result
    }
    $deadline = [DateTime]::UtcNow.AddMinutes($TimeoutMinutes)
    do {
        $result = Invoke-EnrollmentHttp -Operation Collect -BaseUri $BaseUri -Token $Token
        switch ([string]$result.state) {
            'approved' {
                Assert-CollectedCredential -Response $result -Challenge $Challenge
                return $result
            }
            'rejected' { throw 'The administrator rejected this enrolment.' }
            'expired' { throw 'The enrolment invitation expired.' }
            'revoked' { throw 'The enrolment was revoked.' }
            { $_ -notin @('created', 'csr-submitted', 'pending') } { throw "Unexpected enrolment state: $_" }
        }
        Publish-EnrollmentStatus -Event 'waiting' -Data @{
            state = [string]$result.state
            seconds_remaining = [Math]::Max(0, [int]($deadline - [DateTime]::UtcNow).TotalSeconds)
        }
        Start-Sleep -Seconds $PollSeconds
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Timed out waiting for administrator approval.'
}

function Install-IssuedCertificate {
    param(
        [Parameter(Mandatory = $true)][string]$CertificatePem,
        [Parameter(Mandatory = $true)][string]$ExpectedCertificateCn
    )
    if ($WhatIfPreference) { return '0000000000000000000000000000000000000000' }
    $certificatePath = Join-Path ([IO.Path]::GetTempPath()) ("openvpn-lan-party-{0}.cer" -f [guid]::NewGuid().ToString('N'))
    $script:Artifacts.Add($certificatePath)
    [IO.File]::WriteAllText($certificatePath, $CertificatePem, (New-Object Text.ASCIIEncoding))
    $issued = New-Object Security.Cryptography.X509Certificates.X509Certificate2($certificatePath)
    $thumbprint = $issued.Thumbprint.ToUpperInvariant()
    if ($issued.Subject -cne "CN=$ExpectedCertificateCn") {
        throw "The issued certificate subject does not match the assigned technical identity."
    }
    $clientAuthOid = '1.3.6.1.5.5.7.3.2'
    $ekuOids = @($issued.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } |
        ForEach-Object { $_.EnhancedKeyUsages } | ForEach-Object { $_.Value })
    if ($clientAuthOid -notin $ekuOids) { throw 'The issued certificate lacks the clientAuth EKU.' }

    # certreq -accept requires the issuing CA to chain to a Windows trusted root.
    # This private VPN CA must not be added to Root. Bind the existing persisted
    # CNG key directly, then add only the resulting leaf to CurrentUser\My.
    $provider = New-Object Security.Cryptography.CngProvider($script:KeyProvider)
    $key = [Security.Cryptography.CngKey]::Open(
        $script:KeyContainer, $provider, [Security.Cryptography.CngKeyOpenOptions]::UserKey
    )
    $privateKey = New-Object Security.Cryptography.ECDsaCng($key)
    try {
        $bound = [Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::CopyWithPrivateKey(
            $issued, $privateKey
        )
        try {
            $script:InstalledThumbprint = $thumbprint
            $store = New-Object Security.Cryptography.X509Certificates.X509Store(
                'My', [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
            )
            try {
                $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $store.Add($bound)
            }
            finally { $store.Close() }
        }
        finally { $bound.Dispose() }
    }
    finally {
        $privateKey.Dispose()
        $key.Dispose()
        $issued.Dispose()
    }

    $stored = Get-Item -LiteralPath "Cert:\CurrentUser\My\$thumbprint" -ErrorAction Stop
    if (-not $stored.HasPrivateKey) { throw 'The accepted certificate is not bound to its private key.' }

    Assert-PrivateKeyNonExportable -Certificate $stored
    return $thumbprint
}

function New-OpenVpnProfile {
    param(
        [Parameter(Mandatory = $true)]$Response,
        [Parameter(Mandatory = $true)][string]$Thumbprint,
        [Parameter(Mandatory = $true)][string]$EnrollmentId,
        [Parameter(Mandatory = $true)][string]$CertificateCn
    )
    foreach ($required in @('openvpn_config', 'ca_pem', 'tls_crypt_v2')) {
        if ([string]::IsNullOrWhiteSpace([string]$Response.$required)) { throw "Server response lacks '$required'." }
    }
    $base = ([string]$Response.openvpn_config).Trim()
    if ($base -match '(?im)^\s*(cert|key|pkcs12|cryptoapicert|tls-crypt(?:-v2)?)\s') {
        throw 'Server-supplied OpenVPN configuration contains forbidden identity directives.'
    }
    return @"
# openvpn-lan-party-player: $PlayerName
# openvpn-lan-party-enrollment-id: $EnrollmentId
# openvpn-lan-party-certificate-cn: $CertificateCn
# openvpn-lan-party-security-mode: $($script:SecurityMode)
$base
cryptoapicert "THUMB:$Thumbprint"
<ca>
$(([string]$Response.ca_pem).Trim())
</ca>
<tls-crypt-v2>
$(([string]$Response.tls_crypt_v2).Trim())
</tls-crypt-v2>
"@
}

function Prepare-CompanionBundle {
    param([Parameter(Mandatory = $true)]$Response)
    $provisioning = [string]$Response.companion_provisioning
    if ($provisioning -notin @('included', 'preserved-existing')) { return $null }
    if ($WhatIfPreference -and $provisioning -eq 'preserved-existing') { return $null }
    $config = $null
    try {
        $scriptBytes = [Convert]::FromBase64String([string]$Response.companion_script_b64)
        $launcherBytes = [Convert]::FromBase64String([string]$Response.companion_launcher_b64)
        $offboardingBytes = [Convert]::FromBase64String([string]$Response.offboarding_script_b64)
        if ($provisioning -eq 'included') {
            $config = ([string]$Response.companion_config) | ConvertFrom-Json
        }
    }
    catch { throw "The Companion bundle is malformed: $($_.Exception.Message)" }
    if ($provisioning -eq 'included' -and
        ([string]$config.player -cne $PlayerName -or [int]$config.version -ne 1)) {
        throw 'The Companion configuration does not match the enrolled player.'
    }
    if ($provisioning -eq 'included') {
        $serverUri = $null
        if (-not [uri]::TryCreate([string]$config.server_url, [UriKind]::Absolute, [ref]$serverUri) -or
            $serverUri.Scheme -cne 'http' -or -not [string]::IsNullOrEmpty($serverUri.UserInfo) -or
            -not [string]::IsNullOrEmpty($serverUri.Query) -or -not [string]::IsNullOrEmpty($serverUri.Fragment)) {
            throw 'The Companion server URL is invalid.'
        }
    }
    if ($scriptBytes.Length -lt 1024 -or $scriptBytes.Length -gt 147456 -or
        $launcherBytes.Length -lt 32 -or $launcherBytes.Length -gt 3072 -or
        $offboardingBytes.Length -lt 1024 -or $offboardingBytes.Length -gt 49152) {
        throw 'The decoded Companion assets have invalid sizes.'
    }
    return [pscustomobject]@{
        Config = if ($provisioning -eq 'included') { [string]$Response.companion_config } else { $null }
        Script = $scriptBytes
        Launcher = $launcherBytes
        Offboarding = $offboardingBytes
        PreserveConfig = $provisioning -eq 'preserved-existing'
        ExpectedPlayer = $PlayerName
    }
}

function Write-CompanionAsset {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][byte[]]$Value)
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllBytes($temporary, $Value)
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            [IO.File]::Replace($temporary, $Path, $null, $true)
        }
        else { [IO.File]::Move($temporary, $Path) }
    }
    finally { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
}

function Install-CompanionBundle {
    param([Parameter(Mandatory = $true)]$Bundle)
    $destination = Join-Path $env:LOCALAPPDATA 'OpenVPN LAN Party Companion'
    $configPath = Join-Path $destination 'companion.json'
    $launcherPath = Join-Path $destination 'LAN-PARTY.cmd'
    $offboardingPath = Join-Path $destination 'Leave-OpenVPN-LAN-Party.ps1'
    $configExists = Test-Path -LiteralPath $configPath -PathType Leaf
    $existingPlayer = if ($configExists) { Get-ExistingCompanionPlayer } else { $null }
    if ($Bundle.PreserveConfig -and -not $configExists) {
        throw 'The server requested Companion identity preservation, but companion.json is missing.'
    }
    if ($configExists -and $existingPlayer -cne [string]$Bundle.ExpectedPlayer) {
        throw "The existing Companion identity belongs to '$existingPlayer', not '$($Bundle.ExpectedPlayer)'."
    }
    if ($configExists -and -not $Bundle.PreserveConfig) {
        throw 'The server issued a new Companion identity but this Windows profile already has one.'
    }
    if ($configExists) {
        Write-Warning "Existing Companion configuration preserved: $configPath"
    }
    [IO.Directory]::CreateDirectory($destination) | Out-Null
    $scriptPath = Join-Path $destination 'LAN-Party-Companion.ps1'
    Write-CompanionAsset -Path $scriptPath -Value $Bundle.Script
    Write-CompanionAsset -Path $launcherPath -Value $Bundle.Launcher
    Write-CompanionAsset -Path $offboardingPath -Value $Bundle.Offboarding
    if (-not $configExists) {
        if ([string]::IsNullOrWhiteSpace([string]$Bundle.Config)) {
            throw 'The initial Companion bundle does not contain companion.json.'
        }
        [IO.File]::WriteAllText($configPath, $Bundle.Config, (New-Object Text.UTF8Encoding($false)))
    }

    $companionShortcuts = Install-CompanionShortcuts -LauncherPath $launcherPath -Destination $destination
    if (-not $StatusCallback) {
        Start-Process -FilePath $launcherPath -ArgumentList '-StartMinimized' `
            -WorkingDirectory $destination -WindowStyle Hidden
    }
    Write-Host "Companion installed: $destination" -ForegroundColor Green
    Write-Host "Companion Desktop shortcut: $($companionShortcuts.Desktop)" -ForegroundColor Green
    Write-Host "Companion Startup shortcut: $($companionShortcuts.Startup)" -ForegroundColor Green
}

function Install-CompanionShortcuts {
    param(
        [Parameter(Mandatory = $true)][string]$LauncherPath,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    $shell = New-Object -ComObject WScript.Shell
    $shortcuts = @(
        [pscustomobject]@{
            Path = Join-Path ([Environment]::GetFolderPath('Startup')) 'OpenVPN LAN Party Companion.lnk'
            Arguments = '-StartMinimized'
            WindowStyle = 7
        },
        [pscustomobject]@{
            Path = Join-Path ([Environment]::GetFolderPath('Desktop')) 'LAN Party Companion.lnk'
            Arguments = ''
            WindowStyle = 1
        }
    )
    foreach ($definition in $shortcuts) {
        $parent = Split-Path -Parent $definition.Path
        if ([string]::IsNullOrWhiteSpace($parent) -or -not (Test-Path -LiteralPath $parent -PathType Container)) {
            throw "The Windows shortcut directory is unavailable: $parent"
        }
        $shortcut = $shell.CreateShortcut($definition.Path)
        $shortcut.TargetPath = $LauncherPath
        $shortcut.Arguments = $definition.Arguments
        $shortcut.WorkingDirectory = $Destination
        $shortcut.WindowStyle = $definition.WindowStyle
        $shortcut.Description = 'OpenVPN LAN Party Companion'
        $shortcut.Save()
        if (-not (Test-Path -LiteralPath $definition.Path -PathType Leaf)) {
            throw "The Companion shortcut was not created: $($definition.Path)"
        }
    }
    return [pscustomobject]@{
        Startup = [string]$shortcuts[0].Path
        Desktop = [string]$shortcuts[1].Path
    }
}

if (-not $WhatIfPreference) {
    Assert-CompanionPlayerCompatibility
}

if (-not $WhatIfPreference -and
    -not $PSCmdlet.ShouldProcess($PlayerName, 'Create and enrol a non-exportable OpenVPN LAN Party identity')) {
    return
}

try {
    if (-not $WhatIfPreference) {
        # Pin the exact leaf certificate delivered with the invitation. This
        # supports a self-signed portal without disabling TLS validation
        # globally or trusting an attacker-controlled CA. The callback is
        # process-local and restored in finally.
        Install-ProcessTlsPin
    }
    Write-Step 'Retrieving the server-assigned enrolment challenge'
    $challenge = Invoke-EnrollmentHttp -Operation Challenge -BaseUri $EnrollmentUri -Token $InvitationToken
    Assert-EnrollmentChallenge -Challenge $challenge
    $script:SecurityMode = [string]$challenge.security_mode
    $script:KeyProvider = if ($script:SecurityMode -eq 'high-assurance') {
        $script:PlatformProvider
    } else {
        $script:SoftwareProvider
    }
    if ($script:SecurityMode -eq 'high-assurance') {
        Write-Step 'Checking strict TPM 2.0 support'
    } else {
        Write-Step 'Using the non-exportable Windows software key provider (TPM not required)'
    }
    $prerequisites = Assert-SecurityModePrerequisites
    Write-Step 'Creating a non-exportable ECDSA P-256 key and PKCS#10 request'
    $request = New-Pkcs10Request -CommonName ([string]$challenge.certificate_cn)
    Write-Step 'Submitting the CSR for administrator approval'
    $submission = Invoke-EnrollmentHttp -Operation Submit -BaseUri $EnrollmentUri -Token $InvitationToken `
        -CsrPem $request.CsrPem -EnrollmentId ([string]$challenge.enrollment_id)
    if ([string]$submission.state -notin @('csr-submitted', 'pending')) {
        throw "The server did not accept the CSR (state: $($submission.state))."
    }
    $submittedSpki = [string]$submission.spki_sha256
    if ($submittedSpki -cnotmatch '^[0-9a-f]{64}$') {
        throw 'The server returned an invalid CSR SPKI SHA-256 fingerprint.'
    }
    $expectedComparisonCode = $submittedSpki.Substring(0, 4) + '-' + $submittedSpki.Substring(60, 4)
    if ([string]$submission.comparison_code -cne $expectedComparisonCode) {
        throw 'The server returned an inconsistent CSR comparison code.'
    }
    Write-Host "`nAdministrator approval is required." -ForegroundColor Yellow
    Write-Host "Enrollment ID: $([string]$challenge.enrollment_id)"
    Write-Host "CSR SPKI SHA-256: $submittedSpki"
    Write-Host "Comparison code: $expectedComparisonCode" -ForegroundColor Yellow
    Write-Host 'Send these values to the VPN administrator over your trusted channel.'
    Publish-EnrollmentStatus -Event 'approval-required' -Data @{
        enrollment_id = [string]$challenge.enrollment_id
        spki_sha256 = $submittedSpki
        comparison_code = $expectedComparisonCode
        certificate_cn = [string]$challenge.certificate_cn
        player = $PlayerName
    }
    Write-Step 'Waiting for and collecting the one-time response'
    $response = Wait-EnrollmentApproval -BaseUri $EnrollmentUri -Token $InvitationToken -Challenge $challenge
    $companionBundle = Prepare-CompanionBundle -Response $response
    Write-Step 'Binding the issued certificate to the non-exportable key'
    $thumbprint = Install-IssuedCertificate -CertificatePem ([string]$response.certificate_pem) `
        -ExpectedCertificateCn ([string]$challenge.certificate_cn)
    $profile = New-OpenVpnProfile -Response $response -Thumbprint $thumbprint `
        -EnrollmentId ([string]$challenge.enrollment_id) `
        -CertificateCn ([string]$challenge.certificate_cn)

    if ($WhatIfPreference) {
        [pscustomobject]@{
            Mode = 'WhatIf'; PlayerName = $PlayerName; Provider = $script:KeyProvider
            SecurityMode = $script:SecurityMode
            Algorithm = 'ECDSA_P256'; Exportable = $false; Store = 'CurrentUser\My'
            CertificateCn = [string]$challenge.certificate_cn
            EnrollmentId = [string]$challenge.enrollment_id
            Thumbprint = $thumbprint; OutputProfile = $OutputProfile; NetworkCalls = 0
        }
    }
    else {
        $parent = Split-Path -Parent $OutputProfile
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
            [IO.Directory]::CreateDirectory($parent) | Out-Null
        }
        [IO.File]::WriteAllText($OutputProfile, $profile, (New-Object Text.UTF8Encoding($false)))
        if ($companionBundle) {
            try { Install-CompanionBundle -Bundle $companionBundle }
            catch { Write-Warning "VPN enrollment succeeded, but Companion installation failed: $($_.Exception.Message)" }
        }
        elseif ([string]$response.companion_provisioning -eq 'preserved-existing') {
            Write-Host 'Existing Companion identity preserved.' -ForegroundColor Yellow
        }
        Write-Host "`nOpenVPN LAN Party profile created ($($script:SecurityMode)): $OutputProfile" -ForegroundColor Green
        Write-Host "Certificate selector: cryptoapicert `"THUMB:$thumbprint`""
        Publish-EnrollmentStatus -Event 'completed' -Data @{
            profile = $OutputProfile
            thumbprint = $thumbprint
            security_mode = $script:SecurityMode
        }
    }
    $script:EnrollmentCompleted = $true
}
finally {
    if (-not $WhatIfPreference -and $script:TlsPinInstalled) {
        [OpenVpnEnrollmentTlsPin]::Restore()
        $script:TlsPinInstalled = $false
    }
    # CSR and issued certificate are public, but removing transient copies keeps
    # the enrolment surface small. The enrolled private key is intentionally retained.
    foreach ($artifact in $script:Artifacts) { Remove-SensitiveArtifact -Path $artifact }
    foreach ($directory in $script:TemporaryDirectories) {
        if (-not $WhatIfPreference -and (Test-Path -LiteralPath $directory -PathType Container)) {
            Remove-Item -LiteralPath $directory -Force -Recurse -ErrorAction SilentlyContinue
        }
    }
    Remove-OrphanedCngKey
    Remove-OrphanedCertificate
    $InvitationToken = $null
}
