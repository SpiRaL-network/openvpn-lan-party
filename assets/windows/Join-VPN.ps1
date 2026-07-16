#Requires -Version 5.1

<#
.SYNOPSIS
One-window OpenVPN LAN Party onboarding for Windows 10 and Windows 11.

.DESCRIPTION
Validates the invitation bundle, obtains administrator rights without placing
the invitation token on a process command line, installs a signed OpenVPN
Community package with TAP-Windows6 when necessary, runs the mode-bound
enrolment, performs the separate acceptance test, and starts the Companion.
#>
[CmdletBinding()]
param(
    [string]$BundleDirectory = (Split-Path -Parent $PSCommandPath),
    [switch]$Elevated,
    [string]$OriginalSid
)

$ErrorActionPreference = 'Stop'
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Quote-ProcessArgument {
    param([Parameter(Mandatory = $true)][string]$Value)
    return '"' + $Value.Replace('"', '\"') + '"'
}

$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if (-not (Test-Administrator)) {
    $arguments = @(
        '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Quote-ProcessArgument $PSCommandPath), '-BundleDirectory',
        (Quote-ProcessArgument ([IO.Path]::GetFullPath($BundleDirectory))),
        '-Elevated', '-OriginalSid', $currentSid
    ) -join ' '
    try {
        Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -Verb RunAs | Out-Null
    }
    catch { throw 'Administrator rights are required to install and test OpenVPN.' }
    return
}
if ($Elevated -and $OriginalSid -and $currentSid -cne $OriginalSid) {
    throw 'Elevation changed the Windows user. Sign in with an administrator account and run the invitation as that same user.'
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

$isFrench = [Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName -eq 'fr'
$text = if ($isFrench) {
    @{
        Title='Rejoindre OpenVPN LAN Party'; Intro='Cette invitation installe OpenVPN si nécessaire, crée votre identité VPN puis teste la connexion.'
        Password='Mot de passe de l''archive'; Token='Jeton à usage unique'; Start='Installer et rejoindre'; Close='Fermer'; Copy='Copier les valeurs'; Ready='Prêt à commencer.'
        Installing='Vérification et installation d''OpenVPN Community avec TAP-Windows6…'; InstallerBusy='Windows Installer est occupé ; nouvelle tentative dans quelques secondes…'; Enrolling='Création de votre identité VPN…'
        Approval='Validation de l''administrateur requise'; Waiting='Laissez cette fenêtre ouverte pendant que l''administrateur valide ces valeurs.'
        Testing='Test isolé de la connexion VPN…'; Persistent='Connexion validée ; démarrage de la session persistante OpenVPN GUI…'; Companion='VPN connecté ; démarrage du Companion…'; Success='Configuration terminée. OpenVPN GUI maintient la connexion indépendamment du Companion.'
        CredentialsRequired='Saisissez le mot de passe de l''archive et collez le jeton à usage unique.'; Failed='La configuration a échoué'
        BundleExpired='Cette invitation a expiré. Demandez-en une nouvelle à l''administrateur.'
    }
} else {
    @{
        Title='Join OpenVPN LAN Party'; Intro='This invitation installs OpenVPN when needed, creates your VPN identity, and tests the connection.'
        Password='Archive password'; Token='One-time token'; Start='Install and join'; Close='Close'; Copy='Copy values'; Ready='Ready to begin.'
        Installing='Checking and installing OpenVPN Community with TAP-Windows6…'; InstallerBusy='Windows Installer is busy; retrying in a few seconds…'; Enrolling='Creating your VPN identity…'
        Approval='Administrator approval required'; Waiting='Keep this window open while the administrator verifies these values.'
        Testing='Running the isolated VPN connection test…'; Persistent='Connection validated; starting the persistent OpenVPN GUI session…'; Companion='VPN connected; starting the Companion…'; Success='Setup complete. OpenVPN GUI keeps the VPN connected independently of the Companion.'
        CredentialsRequired='Enter the archive password and paste the one-time token.'; Failed='Setup failed'
        BundleExpired='This invitation has expired. Ask the administrator for a new one.'
    }
}

function Assert-CompanionPlayerCompatibility {
    param([Parameter(Mandatory = $true)][string]$ExpectedPlayer)
    $configPath=Join-Path $env:LOCALAPPDATA 'OpenVPN LAN Party Companion\companion.json'
    if(-not (Test-Path -LiteralPath $configPath -PathType Leaf)){return}
    $item=Get-Item -LiteralPath $configPath -Force
    if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -gt 8192){
        throw 'The existing Companion identity file is unsafe or too large.'
    }
    try{$existing=[IO.File]::ReadAllText($configPath,[Text.Encoding]::UTF8) | ConvertFrom-Json}
    catch{throw 'The existing Companion identity file is invalid.'}
    $existingPlayer=[string]$existing.player
    if([int]$existing.version -ne 1 -or $existingPlayer -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$'){
        throw 'The existing Companion identity file is invalid.'
    }
    if($existingPlayer -cne $ExpectedPlayer){
        if($isFrench){
            throw "Ce PC est déjà associé au joueur '$existingPlayer' dans le Companion. L'invitation '$ExpectedPlayer' est refusée pour préserver cette identité."
        }
        throw "This PC is already associated with Companion player '$existingPlayer'. Invitation '$ExpectedPlayer' is refused to preserve that identity."
    }
}

function Assert-SafeBundleFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { return }
    throw "Unsafe invitation path: $Path"
}

$bundleRoot = [IO.Path]::GetFullPath($BundleDirectory).TrimEnd('\')
$rootItem = Get-Item -LiteralPath $bundleRoot -Force
if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The invitation directory is invalid or is a symbolic link.'
}
$bundleManifestPath = Join-Path $bundleRoot 'bundle.json'
Assert-SafeBundleFile $bundleManifestPath
$bundleManifest = [IO.File]::ReadAllText($bundleManifestPath, [Text.Encoding]::UTF8) | ConvertFrom-Json
if ([int]$bundleManifest.schema -ne 1 -or
    [string]$bundleManifest.format -cne 'openvpn-lan-party-protected-invitation' -or
    [string]$bundleManifest.payload -cne 'invitation.vpninvite' -or
    [string]$bundleManifest.payload_sha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'The invitation bundle manifest is invalid.'
}
$requiredFiles = @('JOIN-VPN.cmd','Join-VPN.ps1')
foreach ($name in $requiredFiles) {
    $path = Join-Path $bundleRoot $name
    Assert-SafeBundleFile $path
    $expected = [string]$bundleManifest.files.$name
    if ($expected -notmatch '^[0-9a-f]{64}$') { throw "Missing SHA-256 for $name." }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    if ($actual -cne $expected.ToUpperInvariant()) { throw "Invitation file integrity failure: $name" }
}
$protectedPayloadPath = Join-Path $bundleRoot 'invitation.vpninvite'
Assert-SafeBundleFile $protectedPayloadPath
if ((Get-FileHash -LiteralPath $protectedPayloadPath -Algorithm SHA256).Hash -cne
    ([string]$bundleManifest.payload_sha256).ToUpperInvariant()) {
    throw 'The protected invitation payload failed its SHA-256 check.'
}

function Read-ProtectedInvitation {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Password
    )
    $value = [IO.File]::ReadAllBytes($Path)
    if ($value.Length -lt 72 -or [Text.Encoding]::ASCII.GetString($value,0,8) -cne 'Salted__') {
        throw 'The protected invitation payload is invalid.'
    }
    $encryptedLength = $value.Length - 32
    $encrypted = New-Object byte[] $encryptedLength
    [Array]::Copy($value,0,$encrypted,0,$encryptedLength)
    $providedMac = New-Object byte[] 32
    [Array]::Copy($value,$encryptedLength,$providedMac,0,32)
    $salt = New-Object byte[] 16
    [Array]::Copy($encrypted,8,$salt,0,16)
    $derive = [Security.Cryptography.Rfc2898DeriveBytes]::new(
        $Password,$salt,200000,[Security.Cryptography.HashAlgorithmName]::SHA256
    )
    $derived = $derive.GetBytes(80); $derive.Dispose()
    $macKey = New-Object byte[] 32
    [Array]::Copy($derived,48,$macKey,0,32)
    $hmac = [Security.Cryptography.HMACSHA256]::new($macKey)
    $expectedMac = $hmac.ComputeHash($encrypted); $hmac.Dispose()
    $difference = 0
    for($index=0;$index -lt 32;$index++){ $difference = $difference -bor ($expectedMac[$index] -bxor $providedMac[$index]) }
    if($difference -ne 0){ [Array]::Clear($derived,0,$derived.Length); throw 'The invitation password is incorrect or the payload was modified.' }
    $aes = [Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize=256; $aes.Mode=[Security.Cryptography.CipherMode]::CBC
        $aes.Padding=[Security.Cryptography.PaddingMode]::PKCS7
        $key=New-Object byte[] 32; $iv=New-Object byte[] 16
        [Array]::Copy($derived,0,$key,0,32); [Array]::Copy($derived,32,$iv,0,16)
        $aes.Key=$key; $aes.IV=$iv
        $decryptor=$aes.CreateDecryptor()
        try { $plain=$decryptor.TransformFinalBlock($encrypted,24,$encrypted.Length-24) }
        finally { $decryptor.Dispose() }
        try { return ([Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json) }
        finally { [Array]::Clear($plain,0,$plain.Length) }
    }
    catch [Security.Cryptography.CryptographicException] {
        throw 'The invitation password is incorrect or the payload was modified.'
    }
    finally { [Array]::Clear($derived,0,$derived.Length); $aes.Dispose() }
}

function Expand-ProtectedScripts {
    param([Parameter(Mandatory = $true)]$PrivatePayload)
    if([int]$PrivatePayload.schema -ne 1){ throw 'The protected invitation schema is invalid.' }
    $invitation = $PrivatePayload.invitation
    if ([int]$invitation.schema -ne 1 -or [string]$invitation.player -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$' -or
        [string]$invitation.enrollment_id -notmatch '^[0-9a-f]{64}$' -or
        [string]$invitation.tls_certificate_sha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$invitation.security_mode -notin @('high-assurance','compatible')) {
        throw 'The protected invitation manifest is invalid.'
    }
    $uri=$null
    if(-not [uri]::TryCreate([string]$invitation.enrollment_uri,[UriKind]::Absolute,[ref]$uri) -or
        $uri.Scheme -cne 'https' -or -not [string]::IsNullOrEmpty($uri.UserInfo)){
        throw 'The invitation portal URL is invalid.'
    }
    $expiry=[DateTimeOffset]::Parse([string]$invitation.expires_at,[Globalization.CultureInfo]::InvariantCulture)
    if($expiry -le [DateTimeOffset]::UtcNow){ throw $text.BundleExpired }
    $temporaryRoot=Join-Path ([IO.Path]::GetTempPath()) ('openvpn-lan-party-invitation-'+[guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
    $expanded=$false
    try {
        foreach($name in @('Enroll-VPN-High-Assurance.ps1','Test-VPN-High-Assurance.ps1')){
            try { $bytes=[Convert]::FromBase64String([string]$PrivatePayload.scripts.$name) }
            catch { throw "The protected invitation script is malformed: $name" }
            try {
                if((Get-FileHashBytes $bytes) -cne [string]$invitation.files.$name){ throw "Protected script integrity failure: $name" }
                [IO.File]::WriteAllBytes((Join-Path $temporaryRoot $name),$bytes)
            }
            finally { if($bytes){ [Array]::Clear($bytes,0,$bytes.Length) } }
        }
        $expanded=$true
        return [pscustomobject]@{ Invitation=$invitation; Uri=$uri; Directory=$temporaryRoot }
    }
    finally {
        if(-not $expanded){ Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Get-FileHashBytes {
    param([byte[]]$Value)
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Value))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function ConvertTo-OpenVpnVersion {
    param([AllowNull()][string]$Value, [switch]$MsiProductVersion)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $match = [regex]::Match($Value, '(?<!\d)(\d+)\.(\d+)(?:\.(\d+))?')
    if (-not $match.Success) { return $null }
    $patch = if ($match.Groups[3].Success) { [int]$match.Groups[3].Value } else { 0 }
    if ($MsiProductVersion -and $patch -ge 100) { $patch = [Math]::Floor($patch / 100) }
    return [version]::new([int]$match.Groups[1].Value, [int]$match.Groups[2].Value, $patch)
}

function Get-OpenVpnVersion {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $line = (& $Path --version 2>$null | Select-Object -First 1) -as [string]
    return ConvertTo-OpenVpnVersion $line
}

function Get-MsiProductVersion {
    param([Parameter(Mandatory = $true)][string]$Path)
    $installer=$null; $database=$null; $view=$null; $record=$null
    try {
        $installer=New-Object -ComObject WindowsInstaller.Installer
        $database=$installer.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$installer,@($Path,0))
        $view=$database.GetType().InvokeMember('OpenView','InvokeMethod',$null,$database,
            "SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = 'ProductVersion'")
        $null=$view.GetType().InvokeMember('Execute','InvokeMethod',$null,$view,$null)
        $record=$view.GetType().InvokeMember('Fetch','InvokeMethod',$null,$view,$null)
        if (-not $record) { throw 'The OpenVPN MSI has no ProductVersion.' }
        $raw=$record.GetType().InvokeMember('StringData','GetProperty',$null,$record,1)
        return ConvertTo-OpenVpnVersion ([string]$raw) -MsiProductVersion
    }
    finally {
        foreach($item in @($record,$view,$database,$installer)) {
            if($item){ [void][Runtime.InteropServices.Marshal]::ReleaseComObject($item) }
        }
    }
}

function Get-TapAdapter {
    return Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceDescription -match 'TAP-Windows' } | Select-Object -First 1
}

function Install-OpenVpnCommunity {
    param([scriptblock]$Progress)
    $openVpnExe = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'OpenVPN\bin\openvpn.exe'
    $openVpnGuiExe = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'OpenVPN\bin\openvpn-gui.exe'
    $minimum = [version]'2.7.2'
    $installed = Get-OpenVpnVersion $openVpnExe
    if ($installed -and $installed -ge $minimum -and (Get-TapAdapter) -and
        (Test-Path -LiteralPath $openVpnGuiExe -PathType Leaf)) { return $openVpnExe }
    & $Progress $text.Installing
    $architecture = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $installerArchitecture = switch ($architecture.ToUpperInvariant()) {
        'AMD64' {'amd64'}; 'ARM64' {'arm64'}; 'X86' {'x86'}; default { throw "Unsupported Windows architecture: $architecture" }
    }
    $url = "https://build.openvpn.net/downloads/releases/latest/openvpn-latest-stable-$installerArchitecture.msi"
    $msi = Join-Path ([IO.Path]::GetTempPath()) ("openvpn-latest-stable-{0}-{1}.msi" -f $installerArchitecture,[guid]::NewGuid().ToString('N'))
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing
        $signature = Get-AuthenticodeSignature -FilePath $msi
        if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
            $signature.SignerCertificate.Subject -notmatch 'OpenVPN') {
            throw 'The downloaded OpenVPN installer does not have a valid OpenVPN digital signature.'
        }
        $packageVersion = Get-MsiProductVersion $msi
        if (-not $packageVersion -or $packageVersion -lt $minimum) { throw 'The official OpenVPN package is too old.' }
        Get-Process -Name openvpn,openvpn-gui -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        $arguments = @('/i',('"{0}"' -f $msi),'/qn','/norestart','ADDLOCAL=OpenVPN,OpenVPN.GUI,Drivers,Drivers.TAPWindows6')
        $exitCode = $null
        for ($attempt=0; $attempt -lt 12; $attempt++) {
            $result = Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments -Wait -PassThru
            $exitCode = $result.ExitCode
            if ($exitCode -ne 1618) { break }
            & $Progress $text.InstallerBusy
            Start-Sleep -Seconds 10
        }
        if ($exitCode -notin @(0,3010)) { throw "OpenVPN installation failed with MSI error code $exitCode." }
        for ($attempt=0; $attempt -lt 90; $attempt++) {
            $active = Get-OpenVpnVersion $openVpnExe
            if ($active -and $active -ge $minimum -and (Get-TapAdapter) -and
                (Test-Path -LiteralPath $openVpnGuiExe -PathType Leaf)) { return $openVpnExe }
            Start-Sleep -Seconds 1
        }
        throw 'OpenVPN or the TAP-Windows6 adapter did not become ready.'
    }
    finally { Remove-Item -LiteralPath $msi -Force -ErrorAction SilentlyContinue }
}

function Read-SharedOpenVpnLog {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return '' }
    $stream=$null; $reader=$null
    try {
        $stream=[IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,
            ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false),$true,4096,$true)
        return $reader.ReadToEnd()
    }
    catch [IO.IOException] { return '' }
    finally {
        if($reader){$reader.Dispose()}
        if($stream){$stream.Dispose()}
    }
}

function Get-LanPartyOpenVpnProcesses {
    param([Parameter(Mandatory = $true)][string]$ProfilePath)
    $fullPath=[IO.Path]::GetFullPath($ProfilePath)
    $knownProfiles=@(
        $fullPath,
        'OpenVPN-LAN-Party.ovpn'
    ) | Select-Object -Unique
    return @(Get-CimInstance Win32_Process -Filter "Name='openvpn.exe'" -ErrorAction SilentlyContinue |
        Where-Object {
            if(-not $_.CommandLine){return $false}
            foreach($knownProfile in $knownProfiles){
                if($_.CommandLine.IndexOf($knownProfile,[StringComparison]::OrdinalIgnoreCase) -ge 0){
                    return $true
                }
            }
            return $false
        })
}

function Invoke-OpenVpnGuiUserCommand {
    param(
        [Parameter(Mandatory = $true)][string]$OpenVpnGuiExe,
        [Parameter(Mandatory = $true)][string]$Arguments
    )
    # The onboarding wizard is elevated, but OpenVPN GUI belongs on the user's
    # interactive desktop. Explorer's shell broker starts it at normal user
    # integrity so its tray icon and later commands share the same session.
    $shell=New-Object -ComObject Shell.Application
    $shell.ShellExecute(
        $OpenVpnGuiExe,
        $Arguments,
        (Split-Path -Parent $OpenVpnGuiExe),
        'open',
        1
    )
    Start-Sleep -Milliseconds 750
}

function Stop-ExistingLanPartyTunnel {
    param(
        [Parameter(Mandatory = $true)][string]$OpenVpnGuiExe,
        [Parameter(Mandatory = $true)][string]$ProfilePath
    )
    if(Test-Path -LiteralPath $OpenVpnGuiExe -PathType Leaf){
        Invoke-OpenVpnGuiUserCommand -OpenVpnGuiExe $OpenVpnGuiExe `
            -Arguments '--command disconnect OpenVPN-LAN-Party'
    }
    for($attempt=0;$attempt -lt 20;$attempt++){
        $processes=Get-LanPartyOpenVpnProcesses -ProfilePath $ProfilePath
        if($processes.Count -eq 0){return}
        Start-Sleep -Milliseconds 500
    }
    foreach($process in (Get-LanPartyOpenVpnProcesses -ProfilePath $ProfilePath)){
        Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

function New-OpenVpnGuiShortcut {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$OpenVpnGuiExe
    )
    $parent=Split-Path -Parent $Path
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    $shell=New-Object -ComObject WScript.Shell
    $shortcut=$shell.CreateShortcut($Path)
    $shortcut.TargetPath=$OpenVpnGuiExe
    $shortcut.Arguments='--command connect OpenVPN-LAN-Party'
    $shortcut.WorkingDirectory=Split-Path -Parent $OpenVpnGuiExe
    $shortcut.WindowStyle=1
    $shortcut.IconLocation="$OpenVpnGuiExe,0"
    $shortcut.Description='Connect OpenVPN LAN Party'
    $shortcut.Save()
}

function New-CompanionDesktopShortcut {
    param([Parameter(Mandatory = $true)][string]$LauncherPath)
    $destination=Split-Path -Parent $LauncherPath
    $desktop=[Environment]::GetFolderPath('Desktop')
    if([string]::IsNullOrWhiteSpace($desktop) -or -not (Test-Path -LiteralPath $desktop -PathType Container)){
        throw 'The current Windows Desktop folder is unavailable.'
    }
    $shortcutPath=Join-Path $desktop 'LAN Party Companion.lnk'
    $shell=New-Object -ComObject WScript.Shell
    $shortcut=$shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath=$LauncherPath
    $shortcut.Arguments=''
    $shortcut.WorkingDirectory=$destination
    $shortcut.WindowStyle=1
    $shortcut.Description='OpenVPN LAN Party Companion'
    $shortcut.Save()
    if(-not (Test-Path -LiteralPath $shortcutPath -PathType Leaf)){
        throw "The Companion Desktop shortcut was not created: $shortcutPath"
    }
    return $shortcutPath
}

function Start-PersistentOpenVpnGuiTunnel {
    param(
        [Parameter(Mandatory = $true)][string]$OpenVpnGuiExe,
        [Parameter(Mandatory = $true)][string]$ProfilePath,
        [ValidateRange(10,300)][int]$TimeoutSeconds=120
    )
    if(-not (Test-Path -LiteralPath $OpenVpnGuiExe -PathType Leaf)){
        throw "OpenVPN GUI executable not found: $OpenVpnGuiExe"
    }
    $expectedProfile=[IO.Path]::GetFullPath((Join-Path $env:USERPROFILE 'OpenVPN\config\OpenVPN-LAN-Party.ovpn'))
    if([IO.Path]::GetFullPath($ProfilePath) -cne $expectedProfile){
        throw 'The persistent OpenVPN GUI profile is outside the expected user configuration directory.'
    }
    $startupShortcut=Join-Path ([Environment]::GetFolderPath('Startup')) 'OpenVPN LAN Party.lnk'
    $programsShortcut=Join-Path ([Environment]::GetFolderPath('Programs')) 'OpenVPN LAN Party.lnk'
    New-OpenVpnGuiShortcut -Path $startupShortcut -OpenVpnGuiExe $OpenVpnGuiExe
    New-OpenVpnGuiShortcut -Path $programsShortcut -OpenVpnGuiExe $OpenVpnGuiExe

    $logDirectory=Join-Path $env:USERPROFILE 'OpenVPN\log'
    [IO.Directory]::CreateDirectory($logDirectory) | Out-Null
    $logPath=Join-Path $logDirectory 'OpenVPN-LAN-Party.log'
    # A successful line must belong to this exact connection attempt. Removing
    # the profile-specific old log avoids accepting a stale successful session.
    for($attempt=0;$attempt -lt 20 -and (Test-Path -LiteralPath $logPath -PathType Leaf);$attempt++){
        Remove-Item -LiteralPath $logPath -Force -ErrorAction SilentlyContinue
        if(Test-Path -LiteralPath $logPath -PathType Leaf){Start-Sleep -Milliseconds 250}
    }
    if(Test-Path -LiteralPath $logPath -PathType Leaf){
        throw "The previous OpenVPN GUI log could not be cleared: $logPath"
    }
    $startedAt=[DateTime]::UtcNow.AddSeconds(-2)
    Invoke-OpenVpnGuiUserCommand -OpenVpnGuiExe $OpenVpnGuiExe `
        -Arguments '--command rescan'
    Invoke-OpenVpnGuiUserCommand -OpenVpnGuiExe $OpenVpnGuiExe `
        -Arguments '--command connect OpenVPN-LAN-Party'

    $deadline=[DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do{
        Start-Sleep -Milliseconds 500
        if(Test-Path -LiteralPath $logPath -PathType Leaf){
            $logItem=Get-Item -LiteralPath $logPath
            if($logItem.LastWriteTimeUtc -ge $startedAt){
                $log=Read-SharedOpenVpnLog -Path $logPath
                $successIndex=$log.LastIndexOf('Initialization Sequence Completed',[StringComparison]::Ordinal)
                $failureIndex=-1
                foreach($failureMarker in @('AUTH_FAILED','TLS Error','Exiting due to fatal error','process exiting')){
                    $markerIndex=$log.LastIndexOf($failureMarker,[StringComparison]::OrdinalIgnoreCase)
                    if($markerIndex -gt $failureIndex){$failureIndex=$markerIndex}
                }
                # OpenVPN GUI may delegate the tunnel to its Windows service,
                # whose process command line does not expose the profile path.
                # The fresh, exact-profile log is the authoritative signal.
                if($successIndex -ge 0 -and $successIndex -gt $failureIndex){
                    return [pscustomobject]@{ Gui=$OpenVpnGuiExe; Log=$logPath; Startup=$startupShortcut }
                }
            }
        }
    }while([DateTime]::UtcNow -lt $deadline)
    throw "OpenVPN GUI did not establish the persistent tunnel; inspect $logPath."
}

$form = New-Object Windows.Forms.Form
$form.Text = $text.Title; $form.Size = New-Object Drawing.Size(700,665)
$form.StartPosition='CenterScreen'; $form.FormBorderStyle='FixedDialog'; $form.MaximizeBox=$false
$title = New-Object Windows.Forms.Label
$title.Text=$text.Title; $title.Font=New-Object Drawing.Font('Segoe UI',17,[Drawing.FontStyle]::Bold)
$title.SetBounds(24,20,640,38); $form.Controls.Add($title)
$intro = New-Object Windows.Forms.Label
$intro.Text=$text.Intro; $intro.SetBounds(26,67,630,42); $form.Controls.Add($intro)
$summary = New-Object Windows.Forms.Label
$summary.Text=if($isFrench){'Invitation protégée'}else{'Protected invitation'}
$summary.SetBounds(26,112,630,25); $form.Controls.Add($summary)
$passwordLabel = New-Object Windows.Forms.Label
$passwordLabel.Text=$text.Password; $passwordLabel.SetBounds(26,145,220,22); $form.Controls.Add($passwordLabel)
$passwordBox = New-Object Windows.Forms.TextBox
$passwordBox.UseSystemPasswordChar=$true; $passwordBox.SetBounds(26,170,630,28); $form.Controls.Add($passwordBox)
$tokenLabel = New-Object Windows.Forms.Label
$tokenLabel.Text=$text.Token; $tokenLabel.SetBounds(26,210,200,22); $form.Controls.Add($tokenLabel)
$tokenBox = New-Object Windows.Forms.TextBox
$tokenBox.UseSystemPasswordChar=$true; $tokenBox.SetBounds(26,235,630,28); $form.Controls.Add($tokenBox)
$startButton = New-Object Windows.Forms.Button
$startButton.Text=$text.Start; $startButton.SetBounds(26,279,180,36); $form.Controls.Add($startButton)
$copyButton = New-Object Windows.Forms.Button
$copyButton.Text=$text.Copy; $copyButton.SetBounds(216,279,170,36); $copyButton.Enabled=$false; $form.Controls.Add($copyButton)
$closeButton = New-Object Windows.Forms.Button
$closeButton.Text=$text.Close; $closeButton.SetBounds(516,279,140,36); $form.Controls.Add($closeButton)
$progress = New-Object Windows.Forms.ProgressBar
$progress.Style='Marquee'; $progress.MarqueeAnimationSpeed=0; $progress.SetBounds(26,333,630,18); $form.Controls.Add($progress)
$status = New-Object Windows.Forms.Label
$status.Text=$text.Ready; $status.SetBounds(26,364,630,42); $form.Controls.Add($status)
$approvalTitle = New-Object Windows.Forms.Label
$approvalTitle.Text=$text.Approval; $approvalTitle.Font=New-Object Drawing.Font('Segoe UI',10,[Drawing.FontStyle]::Bold)
$approvalTitle.SetBounds(26,411,630,24); $approvalTitle.Visible=$false; $form.Controls.Add($approvalTitle)
$approvalBox = New-Object Windows.Forms.TextBox
$approvalBox.Multiline=$true; $approvalBox.ReadOnly=$true; $approvalBox.ScrollBars='Vertical'; $approvalBox.SetBounds(26,439,630,130)
$approvalBox.Visible=$false; $form.Controls.Add($approvalBox)
$detail = New-Object Windows.Forms.Label
$detail.Text=''; $detail.SetBounds(26,577,630,30); $form.Controls.Add($detail)

$script:approvalText=''; $script:busy=$false
function Set-WizardStatus {
    param([string]$Message)
    $status.Text=$Message; $status.Refresh(); [Windows.Forms.Application]::DoEvents()
}
$copyButton.Add_Click({ if($script:approvalText){ [Windows.Forms.Clipboard]::SetText($script:approvalText) } })
$closeButton.Add_Click({ if(-not $script:busy){ $form.Close() } })
$form.Add_FormClosing({ param($sender,$eventArgs); if($script:busy){ $eventArgs.Cancel=$true } })

$startButton.Add_Click({
    if([string]::IsNullOrWhiteSpace($passwordBox.Text) -or [string]::IsNullOrWhiteSpace($tokenBox.Text)){
        [Windows.Forms.MessageBox]::Show($text.CredentialsRequired,$text.Title,'OK','Warning') | Out-Null; return
    }
    $script:busy=$true; $startButton.Enabled=$false; $closeButton.Enabled=$false
    $progress.MarqueeAnimationSpeed=30; $token=$tokenBox.Text; $password=$passwordBox.Text
    $tokenBox.Text=''; $passwordBox.Text=''; $tokenBox.Enabled=$false; $passwordBox.Enabled=$false
    $temporaryRoot=$null
    try {
        Set-WizardStatus $(if($isFrench){'Ouverture et vérification de l''invitation…'}else{'Opening and verifying the invitation…'})
        $privatePayload=Read-ProtectedInvitation -Path $protectedPayloadPath -Password $password
        $password=$null
        $expanded=Expand-ProtectedScripts -PrivatePayload $privatePayload; $privatePayload=$null
        $manifest=$expanded.Invitation; $enrollmentUri=$expanded.Uri; $temporaryRoot=$expanded.Directory
        $playerLabel=if($isFrench){'Joueur'}else{'Player'}
        $summary.Text=("{0}: {1}    |    Mode: {2}" -f $playerLabel,$manifest.player,$manifest.security_mode)
        Assert-CompanionPlayerCompatibility -ExpectedPlayer ([string]$manifest.player)
        $openVpnExe = Install-OpenVpnCommunity -Progress ${function:Set-WizardStatus}
        Set-WizardStatus $text.Enrolling
        $profilePath = Join-Path $env:USERPROFILE 'OpenVPN\config\OpenVPN-LAN-Party.ovpn'
        $callback = {
            param($eventName,$data)
            if($eventName -eq 'step'){ Set-WizardStatus ([string]$data.message) }
            elseif($eventName -eq 'approval-required'){
                $script:approvalText = "Enrollment ID: $($data.enrollment_id)`r`nCSR SPKI SHA-256: $($data.spki_sha256)`r`nComparison code: $($data.comparison_code)"
                $approvalBox.Text=$script:approvalText; $approvalTitle.Visible=$true; $approvalBox.Visible=$true; $copyButton.Enabled=$true
                Set-WizardStatus $text.Waiting
            }
            elseif($eventName -eq 'waiting'){ [Windows.Forms.Application]::DoEvents() }
        }
        $enroll = Join-Path $temporaryRoot 'Enroll-VPN-High-Assurance.ps1'
        & $enroll -PlayerName ([string]$manifest.player) -EnrollmentUri $enrollmentUri `
            -InvitationToken $token -TlsCertificateSha256 ([string]$manifest.tls_certificate_sha256) `
            -ExpectedSecurityMode ([string]$manifest.security_mode) -OutputProfile $profilePath `
            -TimeoutMinutes 60 -StatusCallback $callback -Confirm:$false
        $token=$null
        $companionLauncher = Join-Path $env:LOCALAPPDATA 'OpenVPN LAN Party Companion\LAN-PARTY.cmd'
        if(-not (Test-Path -LiteralPath $companionLauncher -PathType Leaf)){
            throw "The Companion launcher is missing after enrolment: $companionLauncher"
        }
        $companionShortcutPath=New-CompanionDesktopShortcut -LauncherPath $companionLauncher
        Set-WizardStatus $text.Testing
        $openVpnGuiExe=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'OpenVPN\bin\openvpn-gui.exe'
        Stop-ExistingLanPartyTunnel -OpenVpnGuiExe $openVpnGuiExe -ProfilePath $profilePath
        $acceptance = & (Join-Path $temporaryRoot 'Test-VPN-High-Assurance.ps1') -ProfilePath $profilePath `
            -OpenVpnExe $openVpnExe -ConnectionTimeoutSeconds 120 | ConvertFrom-Json
        if(-not $acceptance.connection_succeeded){ throw 'The final OpenVPN connection test did not succeed.' }
        Set-WizardStatus $text.Persistent
        $persistent=Start-PersistentOpenVpnGuiTunnel -OpenVpnGuiExe $openVpnGuiExe `
            -ProfilePath $profilePath -TimeoutSeconds 120
        Set-WizardStatus $text.Companion
        $companionScript = Join-Path $env:LOCALAPPDATA 'OpenVPN LAN Party Companion\LAN-Party-Companion.ps1'
        $running = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -and $_.CommandLine.IndexOf($companionScript,[StringComparison]::OrdinalIgnoreCase) -ge 0 })
        foreach($process in $running){ Stop-Process -Id $process.ProcessId -Force -ErrorAction SilentlyContinue }
        if($running.Count -gt 0){ Start-Sleep -Milliseconds 500 }
        Start-Process -FilePath $companionLauncher -WorkingDirectory (Split-Path $companionLauncher)
        $progress.MarqueeAnimationSpeed=0; $progress.Value=100; Set-WizardStatus $text.Success
        $detail.Text=("OpenVPN GUI {0}  |  {1}  |  persistent  |  {2}" -f `
            $acceptance.openvpn_version,$acceptance.security_mode,(Split-Path -Leaf $companionShortcutPath))
        $closeButton.Enabled=$true
        [Windows.Forms.MessageBox]::Show($text.Success,$text.Title,'OK','Information') | Out-Null
    }
    catch {
        $token=$null; $progress.MarqueeAnimationSpeed=0
        Set-WizardStatus ("{0}: {1}" -f $text.Failed,$_.Exception.Message)
        $closeButton.Enabled=$true; $startButton.Enabled=$true; $tokenBox.Enabled=$true; $passwordBox.Enabled=$true
        [Windows.Forms.MessageBox]::Show($_.Exception.Message,$text.Failed,'OK','Error') | Out-Null
    }
    finally {
        $token=$null; $password=$null
        if($temporaryRoot -and (Test-Path -LiteralPath $temporaryRoot -PathType Container)){
            Remove-Item -LiteralPath $temporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
        $script:busy=$false
    }
})

[void]$form.ShowDialog()
