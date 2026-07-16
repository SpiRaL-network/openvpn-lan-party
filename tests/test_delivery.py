from __future__ import annotations

import base64
from pathlib import Path
import re
import unittest


REPOSITORY = Path(__file__).resolve().parents[1]


class DeliveryTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (REPOSITORY / relative).read_text(encoding="utf-8-sig")

    def test_fresh_installer_supports_per_invitation_security_modes(self) -> None:
        installer = self.read("install-vpn-server.sh")
        self.assertNotIn("--security-mode", installer)
        self.assertNotIn("/etc/openvpn-lan-party/security-mode", installer)
        admin = self.read("assets/vpn-enrollment-admin.py")
        self.assertIn('create_p.add_argument("--security-mode"', admin)
        self.assertIn('choices=("high-assurance", "compatible")', admin)
        self.assertIn("--ack-compatible-risk", admin)
        self.assertIn("Debian 13 only", installer)
        self.assertIn("EASYRSA_REQ_CN='OPENVPN LAN PARTY'", installer)
        self.assertIn("EASYRSA_ALGO=ec EASYRSA_CURVE=prime256v1", installer)
        self.assertIn("miniupnpc", installer)
        self.assertIn("vpn-enrollment-admin create --player PLAYER", installer)

    def test_fresh_installer_waits_for_the_portal_listener(self) -> None:
        installer = self.read("install-vpn-server.sh")
        self.assertIn("PORTAL_READY=false", installer)
        self.assertIn("for _attempt in {1..50}", installer)
        self.assertIn("systemctl is-active --quiet vpn-enrollment-portal.service", installer)
        self.assertIn("[[ $PORTAL_READY == true ]]", installer)

    def test_installer_contains_only_the_supported_delivery_path(self) -> None:
        installer = self.read("install-vpn-server.sh")
        for forbidden in (
            "add-vpn-player", "create-vpn-invitation", "vpn-profile-portal",
            "openvpn-clients", "client-template.ovpn", "Install-VPN.ps1",
            "7zip-standalone", "tls-crypt.key",
        ):
            self.assertNotIn(forbidden, installer)
        self.assertFalse((REPOSITORY / "install-lan-party-companion.sh").exists())

    def test_server_requires_tls_crypt_v2_metadata_and_modern_ciphers(self) -> None:
        server = self.read("assets/server.conf.in")
        self.assertIn("tls-crypt-v2 tls-crypt-v2-server.key force-cookie", server)
        self.assertIn(
            "tls-crypt-v2-verify /usr/local/libexec/verify-tls-crypt-v2-player",
            server,
        )
        self.assertIn("script-security 2", server)
        self.assertIn("AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", server)
        self.assertNotRegex(server, r"(?m)^\s*tls-crypt\s")
        self.assertNotIn("BF-CBC", server)

    def test_windows_enrollment_is_mode_bound_and_never_exports_keys(self) -> None:
        client = self.read("assets/windows/Enroll-VPN-High-Assurance.ps1")
        acceptance = self.read("assets/windows/Test-VPN-High-Assurance.ps1")
        for provider in (
            "Microsoft Platform Crypto Provider",
            "Microsoft Software Key Storage Provider",
        ):
            self.assertIn(provider, client)
            self.assertIn(provider, acceptance)
        self.assertIn("Exportable = FALSE", client)
        self.assertIn("SuppressDefaults = TRUE", client)
        self.assertIn("$tpm.LockedOut", client)
        self.assertIn("ExpectedSecurityMode", client)
        self.assertIn("Assert-SupportedWindows", client)
        self.assertIn("CurrentBuildNumber", client)
        self.assertIn("build 19045", client)
        self.assertIn("Windows 11", client)
        self.assertIn("openvpn-lan-party-security-mode", client)
        self.assertIn("openvpn-lan-party-security-mode", acceptance)
        self.assertIn("Pkcs8PrivateBlob", client)
        self.assertIn("Pkcs8PrivateBlob", acceptance)
        self.assertNotIn("Exportable = TRUE", client)
        self.assertNotIn("BEGIN PRIVATE KEY", client)
        self.assertNotIn("certreq.exe -accept", client)
        self.assertIn('cryptoapicert "THUMB:$Thumbprint"', client)
        self.assertIn("# openvpn-lan-party-player: $PlayerName", client)
        self.assertIn("# openvpn-lan-party-enrollment-id: $EnrollmentId", client)
        self.assertIn("# openvpn-lan-party-certificate-cn: $CertificateCn", client)
        self.assertIn("Assert-CompanionPlayerCompatibility", client)
        self.assertIn("ExpectedPlayer = $PlayerName", client)

    def test_windows_one_window_onboarding_is_bundled_and_fail_closed(self) -> None:
        wizard = self.read("assets/windows/Join-VPN.ps1")
        launcher = self.read("assets/windows/JOIN-VPN.cmd")
        admin = self.read("assets/vpn-enrollment-admin.py")
        portal = self.read("assets/vpn-enrollment-portal.py")
        installer = self.read("install-vpn-server.sh")
        for marker in (
            "System.Windows.Forms", "Get-AuthenticodeSignature", "OpenVPN",
            "Drivers.TAPWindows6", "openvpn-latest-stable-", "1618",
            "ConvertTo-OpenVpnVersion", "MsiProductVersion", "[Math]::Floor",
            "Test-VPN-High-Assurance.ps1", "Start-PersistentOpenVpnGuiTunnel",
            "openvpn-gui.exe", "Stop-ExistingLanPartyTunnel",
            "Invoke-OpenVpnGuiUserCommand", "--command connect OpenVPN-LAN-Party",
            "--command disconnect OpenVPN-LAN-Party",
            "OpenVPN LAN Party.lnk",
            "$env:USERPROFILE 'OpenVPN\\config\\OpenVPN-LAN-Party.ovpn'",
            "The fresh, exact-profile log is the authoritative signal",
            "$successIndex -gt $failureIndex", "$text.Persistent", "$text.Companion",
            "Read-ProtectedInvitation", "HMACSHA256", "Aes]::Create",
            "Rfc2898DeriveBytes", "OriginalSid", "StatusCallback",
            "Assert-CompanionPlayerCompatibility", "déjà associé au joueur",
        ):
            self.assertIn(marker, wizard)
        self.assertIn("Join-VPN.ps1", launcher)
        self.assertIn('-BundleDirectory "%~dp0."', launcher)
        self.assertNotIn('-BundleDirectory "%~dp0"', launcher)
        self.assertNotIn("InvitationToken $token", launcher)
        self.assertNotIn("-KeepConnected", wizard)
        self.assertNotIn("GetFolderPath('MyDocuments')", wizard)
        self.assertNotIn("OpenVPN.GUI.OnLogon", wizard)
        self.assertIn("IndexOf($companionScript", wizard)
        self.assertIn("The Companion Desktop shortcut was not created", wizard)
        self.assertLess(wizard.index("New-CompanionDesktopShortcut -LauncherPath"),
                        wizard.index("Set-WizardStatus $text.Testing"))
        self.assertIn("Stop-Process -Id $process.ProcessId", wizard)
        self.assertNotIn("Stop-Process -Name powershell", wizard)
        self.assertNotRegex(wizard, "[‘’“”]")
        self.assertIn("protect_payload", admin)
        self.assertIn("invitation_zip", admin)
        self.assertIn("bundle_b64", portal)
        self.assertIn("/invitations/", portal)
        self.assertIn("windows/Join-VPN.ps1", installer)
        self.assertIn("default=3600", admin)

    def test_admin_has_guided_approval_and_link_only_optional_email(self) -> None:
        admin = self.read("assets/vpn-enrollment-admin.py")
        for marker in (
            "OPENVPN LAN PARTY - APPROVAL", "Comparison code",
            "Approve and sign? [Y/N]", "--email-to", "send_invitation_email",
            "The archive password and one-time token will be sent separately.",
            "OPENVPN LAN PARTY - WINDOWS INVITATION", "--json", "--no-wait",
            "OPENVPN LAN PARTY - APPROVAL POOL", "pending_requests",
        ):
            self.assertIn(marker, admin)
        self.assertTrue(admin.isascii())
        for forbidden in ("Joueur", "Approuver", "[O/N]", "Demande", "Sélection", "Téléchargez"):
            self.assertNotIn(forbidden, admin)

    def test_windows_wizard_distinguishes_archive_password_from_one_time_token(self) -> None:
        wizard = self.read("assets/windows/Join-VPN.ps1")
        for marker in (
            "Password='Mot de passe de l''archive'",
            "Token='Jeton à usage unique'",
            "Password='Archive password'",
            "Token='One-time token'",
        ):
            self.assertIn(marker, wizard)
        self.assertNotIn("Password='Mot de passe de l''invitation'", wizard)
        self.assertNotIn("Password='Invitation password'", wizard)

    def test_disposable_key_loss_helper_is_exact_and_fail_closed(self) -> None:
        helper = self.read("assets/windows/Remove-VPN-Disposable-Identity.ps1")
        client = self.read("assets/windows/Enroll-VPN-High-Assurance.ps1")
        installer = self.read("install-vpn-server.sh")
        builder = self.read("build-release.sh")
        self.assertIn("^DisposableTest-", helper)
        for confirmation in (
            "DisposablePlayerName", "ExpectedEnrollmentId",
            "ExpectedCertificateCn", "ExpectedThumbprint",
        ):
            self.assertIn(confirmation, helper)
        for guard in (
            "SupportsShouldProcess = $true", "$PSCmdlet.ShouldProcess(",
            "Get-Process -Name openvpn", "Microsoft Platform Crypto Provider",
            "Microsoft Software Key Storage Provider", "ECDSA P-256",
            "^OpenVPN-LAN-Party-[0-9a-f]{32}$", "CngKey]::Exists",
            "FileAttributes]::ReparsePoint", "profileHashBefore",
            "companionHashBefore",
            "profile_retained = $true", "companion_untouched = $true",
        ):
            self.assertIn(guard, helper)
        self.assertIn("-delkey $keyContainer", helper)
        self.assertNotIn("certutil.exe -user -f -csp", helper)
        self.assertNotIn("certutil.exe -user -f -csp", client)
        self.assertIn("certutilDetail", helper)
        self.assertIn('$certificate.Subject -cne "CN=$certificateCn"', helper)
        self.assertIn("$certificate.Reset()", helper)
        self.assertIn("function Get-ReadOnlySha256", helper)
        self.assertIn("[Security.Cryptography.SHA256]::Create()", helper)
        self.assertNotIn("Get-FileHash -LiteralPath", helper)
        self.assertEqual(1, helper.count("Remove-Item -Path $certificatePath"))
        self.assertNotIn("Get-ChildItem -Path Cert:", helper)
        self.assertNotIn("Remove-Item -Recurse", helper)
        self.assertIn("Remove-VPN-Disposable-Identity.ps1", installer)
        self.assertIn("Remove-VPN-Disposable-Identity.ps1", builder)

    def test_player_offboarding_is_exact_and_separate_from_other_profiles(self) -> None:
        helper = self.read("assets/windows/Leave-OpenVPN-LAN-Party.ps1")
        for marker in (
            "SupportsShouldProcess = $true", "ConfirmImpact = 'High'",
            "OpenVPN-LAN-Party.ovpn", "--command disconnect OpenVPN-LAN-Party",
            "Microsoft Platform Crypto Provider",
            "Microsoft Software Key Storage Provider", "-delkey $container",
            "$RemoveCompanion", "companion_removed", "CngKey]::Exists",
            "$container = $privateKey.Key.KeyName",
        ):
            self.assertIn(marker, helper)
        self.assertNotIn("$privateKey.Key.UniqueName", helper)
        self.assertNotIn("Stop-Process -Name openvpn", helper)
        self.assertNotIn("Get-ChildItem -Path Cert:", helper)
        installer = self.read("install-vpn-server.sh")
        admin = self.read("assets/vpn-enrollment-admin.py")
        self.assertIn("Leave-OpenVPN-LAN-Party.ps1", installer)
        self.assertIn("offboarding_script_b64", admin)

    def test_companion_is_provisioned_inside_the_one_time_response(self) -> None:
        admin = self.read("assets/vpn-enrollment-admin.py")
        engine = self.read("assets/vpn-player-enrollment.py")
        client = self.read("assets/windows/Enroll-VPN-High-Assurance.ps1")
        companion = self.read("assets/lan-party-companion.py")
        self.assertIn("companion_token=secrets.token_urlsafe(32)", engine)
        self.assertIn('client_material.pop("companion_token", None)', admin)
        self.assertIn("ensure_player_registration", admin)
        self.assertIn("existing-different", companion)
        self.assertIn("preserved-existing", admin)
        self.assertIn("OpenVPN LAN Party Companion.lnk", client)
        self.assertIn("LAN Party Companion.lnk", client)
        self.assertIn("GetFolderPath('Desktop')", client)
        self.assertIn("Arguments = '-StartMinimized'", client)
        self.assertIn("Existing Companion configuration preserved", client)
        self.assertIn("Write-CompanionAsset", client)
        self.assertIn("PreserveConfig", client)

    def test_real_companion_assets_fit_the_bounded_admin_protocol(self) -> None:
        script = (REPOSITORY / "assets/windows/LAN-Party-Companion.ps1").read_bytes()
        launcher = (REPOSITORY / "assets/windows/LAN-PARTY.cmd").read_bytes()
        encoded_size = len(base64.b64encode(script)) + len(base64.b64encode(launcher))
        # Leaves ample room below MAX_ADMIN=256 KiB for certs and configuration.
        self.assertLess(encoded_size, 180 * 1024)
        self.assertIn("MAX_ADMIN = 256 * 1024", self.read("assets/vpn-enrollment-portal.py"))

    def test_companion_client_remains_bilingual_and_feature_complete(self) -> None:
        client = self.read("assets/windows/LAN-Party-Companion.ps1")
        for marker in (
            "presence_duration", "join_instructions", "ready_check",
            "lobby_phases", "lobby_lock", "host_transfer", "lobby_revisions",
        ):
            self.assertIn(marker, client)
        self.assertRegex(client, r"(?m)^\s*en = @\{")
        self.assertRegex(client, r"(?m)^\s*fr = @\{")
        self.assertIn("Connected time", client)
        self.assertIn("Temps de connexion", client)
        self.assertIn("Host latency", client)
        self.assertIn("Latence vers l’hôte", client)
        self.assertIn("Quit Companion and disconnect VPN", client)
        self.assertIn("Quitter le Companion et déconnecter le VPN", client)
        self.assertIn("Disconnect-LanPartyOpenVpn", client)
        self.assertIn("Connect-LanPartyOpenVpn", client)
        self.assertIn("Test-CompanionTcpEndpoint", client)
        self.assertIn("Get-ManagedLanPartyProfile", client)
        self.assertIn("ValidateSet('rescan', 'connect', 'disconnect')", client)
        self.assertIn("$arguments += 'OpenVPN-LAN-Party'", client)
        self.assertIn("WaitForExit(5000)", client)
        self.assertNotIn("-WindowStyle Hidden -Wait -PassThru", client)
        self.assertIn("OpenVPN\\config\\OpenVPN-LAN-Party.ovpn", client)
        self.assertIn("Documents\\OpenVPN\\config\\OpenVPN-LAN-Party.ovpn", client)
        self.assertIn("FileAttributes]::ReparsePoint", client)
        self.assertIn("openvpn-lan-party-security-mode", client)
        self.assertIn("openvpn-lan-party-player", client)
        self.assertIn("AddSeconds(60)", client)
        self.assertIn("vpn_connecting", client)
        self.assertIn("vpn_connect_failed", client)
        self.assertNotIn("Stop-Process -Name openvpn", client)

    def test_companion_translations_have_identical_keys(self) -> None:
        client = self.read("assets/windows/LAN-Party-Companion.ps1")
        english_start = client.index("    en = @{")
        french_start = client.index("    fr = @{")
        catalog_end = client.index("\n    }\n}\n\n$script:MessageColors", french_start)
        pattern = re.compile(r"(?m)^        ([a-z0-9_]+)\s*=")
        english_keys = pattern.findall(client[english_start:french_start])
        french_keys = pattern.findall(client[french_start:catalog_end])
        self.assertEqual(len(english_keys), len(set(english_keys)))
        self.assertEqual(len(french_keys), len(set(french_keys)))
        self.assertEqual(set(english_keys), set(french_keys))

    def test_audit_checks_mode_permissions_and_no_shared_tls_key(self) -> None:
        audit = self.read("assets/audit-openvpn-lan-party")
        self.assertIn("credential security policies are valid", audit)
        self.assertNotIn("MODE_FILE=", audit)
        self.assertIn("a shared tls-crypt compatibility key is configured", audit)
        self.assertIn("runuser -u vpnportal", audit)
        self.assertIn("runuser -u nobody", audit)
        self.assertIn("BEGIN (RSA |EC |)PRIVATE KEY", audit)

    def test_release_builder_requires_a_clean_exact_tag_and_excludes_secrets(self) -> None:
        builder = self.read("build-release.sh")
        self.assertIn("git status --porcelain=v1", builder)
        self.assertIn("git cat-file -t", builder)
        self.assertIn("git archive --format=zip", builder)
        self.assertIn("companion\\.json", builder)
        self.assertIn("sha256sum -c", builder)

    def test_no_removed_v1_asset_is_still_tracked(self) -> None:
        removed = (
            "assets/add-vpn-player", "assets/create-vpn-invitation",
            "assets/client-template.ovpn.in", "assets/vpn-profile-portal.py",
            "assets/windows/Install-VPN.ps1", "assets/send-vpn-profile.py",
        )
        for relative in removed:
            self.assertFalse((REPOSITORY / relative).exists(), relative)


if __name__ == "__main__":
    unittest.main()
