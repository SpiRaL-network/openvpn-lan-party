import importlib.util
import base64
import hashlib
import datetime as dt
import io
import json
from pathlib import Path
import socket
import socketserver
import tempfile
import threading
import unittest
import zipfile
from unittest import mock


SOURCE = Path(__file__).parents[1] / "assets" / "vpn-enrollment-admin.py"
SPEC = importlib.util.spec_from_file_location("enrollment_admin", SOURCE)
admin = importlib.util.module_from_spec(SPEC); assert SPEC.loader; SPEC.loader.exec_module(admin)


IDENT = "a" * 64
SPKI = "b" * 64
CSR = "-----BEGIN CERTIFICATE REQUEST-----\nTEST\n-----END CERTIFICATE REQUEST-----\n"


class FakeEngine:
    class Store:
        def __init__(self, path): self.path = path
    class EnrollmentError(RuntimeError): pass
    def __init__(self): self.calls = []; self.state = "created"
    def create(self, store, player, ttl, security_mode):
        return {"id": IDENT, "token": "secret", "expires_at": "2030-01-02T03:04:05Z", "player": player,
                "player_id": "player-id", "credential_id": "credential-id", "certificate_cn": "vpn-player:credential-id",
                "security_mode": security_mode}
    def validate_csr(self, csr, cn, openssl): self.calls.append(("validate", csr, cn)); return SPKI
    def import_portal_submission(self, store, ident, csr, expected_spki, openssl):
        self.calls.append(("import", ident, expected_spki)); self.state="csr-submitted"; return {"spki_sha256": SPKI}
    def approve(self, *args, **kwargs): self.calls.append(("approve", args[2:])); self.state="approved"; return {"collect_token": "collect"}
    def publication_bundle(self, store, ident):
        self.calls.append(("bundle", ident)); return {"player":"Arthur", "certificate_pem":"CERT", "tls_crypt_v2":"TLS",
            "certificate_cn":"vpn-player:credential-id", "credential_id":"credential-id", "player_id":"player-id", "serial":"AB", "kid":"kid",
            "security_mode":"high-assurance", "companion_token":"companion-secret-token-1234567890"}
    def canonical_json(self,value): return json.dumps(value,sort_keys=True,separators=(",",":"))
    def finalize_publication(self,store,ident,digest): self.calls.append(("finalize",digest)); self.state="collected"
    def terminal(self, store, ident, target, reason): return {"id":ident,"state":target,"reason":reason}
    def begin_revoke(self, store, ident, reason): self.state="revoking"; return {"id":ident,"state":"revoking","pki_name":"credential-id","serial":"AB"}
    def finalize_revoke(self, store, ident): self.state="revoked"; return {"id":ident,"state":"revoked"}
    def atomic_write(self,path,data,mode): path.write_bytes(data)
    def confirm_connection(self,store,ident): return {"id":ident,"state":"collected"}
    def public_status(self, store, ident): return {"id":ident,"state":self.state,"spki_sha256":SPKI,
                                                   "certificate_cn":"vpn-player:credential-id"}
    def player_enrollments(self, store, player):
        return [{"id":IDENT,"player":player,"player_id":"player-id",
                 "credential_id":"credential-id","certificate_cn":"vpn-player:credential-id",
                 "security_mode":"high-assurance","state":"collected"}]
    def retire_player(self, store, player):
        self.calls.append(("retire-player", player))
        return {"player":player,"player_id":"player-id","retired":True}


class FakePortal:
    def __init__(self): self.calls=[]; self.spki=SPKI; self.state="created"; self.statuses=[]
    def request(self, command, **values):
        self.calls.append((command, values))
        if command == "register": return {"id":IDENT,"state":"created"}
        if command == "inspect": return {"id":IDENT,"player":"Arthur","certificate_cn":"vpn-player:credential-id",
            "expires_at":1893553445,"csr":CSR,"spki_sha256":self.spki}
        if command == "status":
            state=self.statuses.pop(0) if self.statuses else self.state
            return {"id":IDENT,"player":"Arthur","certificate_cn":"vpn-player:credential-id",
                    "expires_at":1893553445,"security_mode":"high-assurance","state":state}
        if command == "pending":
            requests=[] if self.state != "pending" else [{
                "id":IDENT,"player":"Arthur","certificate_cn":"vpn-player:credential-id",
                "expires_at":1893553445,"submitted_at":1893553000,
                "security_mode":"high-assurance","spki_sha256":self.spki,
                "comparison_code":self.spki[:4]+"-"+self.spki[-4:],
            }]
            return {"requests":requests,"total":len(requests)}
        if command == "publish": return {"id":IDENT,"state":"approved"}
        if command == "cancel": return {"id":IDENT,"state":"cancelled"}
        raise AssertionError(command)


class FakeCompanion:
    def __init__(self): self.registration = "created"; self.calls = []
    def load_config(self, path):
        return {"players_file": str(path.with_name("players.json")),
                "bind_host": "10.44.0.1", "port": 8787}
    def ensure_player_registration(self, path, player, token):
        self.calls.append((path, player, token)); return self.registration
    def update_player_registration(self, path, player, token):
        self.calls.append((path, player, token)); return True


class Handler(socketserver.StreamRequestHandler):
    response = {"ok": True, "result": {"state": "created"}}
    def handle(self):
        self.server.received = self.rfile.readline(admin.MAX_MESSAGE + 1)
        self.wfile.write(json.dumps(self.response).encode() + b"\n")


class AdminTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.ca=self.root/"ca.crt"; self.ca.write_text("CA\n")
        self.portal_cert=self.root/"portal.crt"
        self.portal_cert.write_text(
            "-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n"
        )
        (self.root/"pki").mkdir()
        self.companion_script=self.root/"LAN-Party-Companion.ps1"; self.companion_script.write_bytes(b"script")
        self.companion_launcher=self.root/"LAN-PARTY.cmd"; self.companion_launcher.write_bytes(b"launcher")
        self.join_script=self.root/"Join-VPN.ps1"; self.join_script.write_bytes(b"join-script")
        self.join_launcher=self.root/"JOIN-VPN.cmd"; self.join_launcher.write_bytes(b"join-launcher")
        self.enroll_script=self.root/"Enroll-VPN-High-Assurance.ps1"; self.enroll_script.write_bytes(b"enroll-script")
        self.test_script=self.root/"Test-VPN-High-Assurance.ps1"; self.test_script.write_bytes(b"test-script")
        self.leave_script=self.root/"Leave-OpenVPN-LAN-Party.ps1"; self.leave_script.write_bytes(b"leave-script")
        self.companion=FakeCompanion()
        self.engine=FakeEngine(); self.portal=FakePortal()
        self.subject=admin.Administrator(self.engine,object(),self.portal,public_url="https://vpn.test/enroll",
            ca_cert=self.ca,ca_key=self.root/"ca.key",tls_server_key=self.root/"tls.key",
            portal_tls_cert=self.portal_cert,
            remote="vpn.example.test",port=1194,proto="udp",openssl="openssl",openvpn="openvpn",
            pki_dir=self.root/"pki",easyrsa="easyrsa",deployed_crl=self.root/"crl.pem",
            openvpn_service="openvpn-test.service",status_file=self.root/"status.log",
            companion=self.companion,
            companion_config=self.root/"companion-config.json",
            companion_script=self.companion_script,
            companion_launcher=self.companion_launcher,
            windows_join_script=self.join_script,
            windows_join_launcher=self.join_launcher,
            windows_enroll_script=self.enroll_script,
            windows_test_script=self.test_script,
            windows_leave_script=self.leave_script)
    def tearDown(self): self.temp.cleanup()
    def test_load_engine_accepts_extensionless_installed_script(self):
        engine = self.root / "extensionless-engine"
        engine.write_text("MARKER = 'loaded'\n", encoding="utf-8")
        self.assertEqual("loaded", admin.load_engine(engine).MARKER)
    def test_noninteractive_mode_defaults_high_and_requires_compatible_ack(self):
        with mock.patch.object(admin.sys.stdin, "isatty", return_value=False), \
             mock.patch.object(admin.sys.stderr, "isatty", return_value=False):
            self.assertEqual("high-assurance", admin.select_security_mode(None, False))
            with self.assertRaisesRegex(admin.AdminError, "ack-compatible-risk"):
                admin.select_security_mode("compatible", False)
            self.assertEqual("compatible", admin.select_security_mode("compatible", True))
    def test_create_registers_epoch_and_returns_secret_once(self):
        value=self.subject.create("Arthur",900,"high-assurance"); invitation=self.portal.calls[0][1]["invitation"]
        self.assertEqual(1893553445,invitation["expires_at"]); self.assertEqual("secret",value["token"])
        self.assertEqual("player-id",invitation["player_id"])
        self.assertEqual("credential-id",invitation["credential_id"])
        self.assertEqual("high-assurance", invitation["security_mode"])
        self.assertEqual("https://vpn.test/enroll",value["url"]); self.assertEqual("aaaa-aaaa",value["challenge"])
        self.assertEqual(hashlib.sha256(b"a").hexdigest(), value["tls_certificate_sha256"])
        self.assertIn("/invitations/", value["download_url"])
        self.assertNotEqual(value["token"], value["archive_password"])

    def test_create_publishes_native_zip_with_protected_tokenless_payload(self):
        value=self.subject.create("Arthur",900,"high-assurance")
        registration=self.portal.calls[0][1]
        archive=base64.b64decode(registration["bundle_b64"],validate=True)
        self.assertEqual(hashlib.sha256(archive).hexdigest(),registration["bundle_sha256"])
        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            self.assertEqual({"JOIN-VPN.cmd","Join-VPN.ps1","bundle.json",
                              "invitation.vpninvite"},set(bundle.namelist()))
            manifest=json.loads(bundle.read("bundle.json"))
            protected=bundle.read("invitation.vpninvite")
            self.assertEqual("openvpn-lan-party-protected-invitation",manifest["format"])
            self.assertEqual(hashlib.sha256(protected).hexdigest(),manifest["payload_sha256"])
            self.assertTrue(protected.startswith(b"Salted__"))
            self.assertNotIn(b"secret",archive)
            for name,digest in manifest["files"].items():
                self.assertEqual(digest,hashlib.sha256(bundle.read(name)).hexdigest())
        self.assertRegex(value["archive_password"],r"^[A-Za-z0-9_-]{20,}$")

    @mock.patch.object(admin.subprocess, "run")
    def test_optional_email_contains_link_but_no_credentials(self, run):
        output={"email_subject":"Invitation","email_body":"Download: https://vpn.test/file.zip"}
        admin.send_invitation_email(output,"arthur@example.test",Path("/bin/true"))
        message=run.call_args.kwargs["input"].decode("utf-8")
        self.assertIn("https://vpn.test/file.zip",message)
        self.assertNotIn("archive_password",message)
        self.assertNotIn("one-time token:",message.lower())
        with self.assertRaises(admin.AdminError):
            admin.send_invitation_email(output,"bad\nBcc:x@example.test",Path("/bin/true"))
    def test_inspect_revalidates_and_rejects_fingerprint_change(self):
        self.assertEqual("bbbb-bbbb",self.subject.inspect(IDENT)["comparison_code"])
        self.portal.spki="c"*64
        with self.assertRaisesRegex(admin.AdminError,"mismatch"): self.subject.inspect(IDENT)

    @mock.patch.object(admin.time, "sleep")
    def test_wait_for_request_polls_only_its_invitation_then_revalidates_csr(self, sleep):
        self.portal.statuses=["created","pending"]
        pending=self.subject.wait_for_request(IDENT,"2030-01-02T03:04:05Z",poll_seconds=1)
        self.assertEqual(SPKI,pending["spki_sha256"])
        self.assertEqual(1,sleep.call_count)
        self.assertEqual(["status","status","inspect"],
                         [command for command,_values in self.portal.calls])

    def test_pending_pool_is_secret_free_and_validated(self):
        self.portal.state="pending"
        requests=self.subject.pending_requests()
        self.assertEqual([IDENT],[request["id"] for request in requests])
        self.assertNotIn("csr",requests[0])
        self.portal.spki="invalid"
        with self.assertRaisesRegex(admin.AdminError,"fingerprint"):
            self.subject.pending_requests()

    def test_interactive_pool_selects_by_number_and_never_requires_an_identifier(self):
        class Tty(io.StringIO):
            def isatty(self): return True
        self.portal.state="pending"
        stdin=Tty(); stderr=Tty()
        with mock.patch.object(admin.sys,"stdin",stdin), mock.patch.object(admin.sys,"stderr",stderr), \
             mock.patch("builtins.input",side_effect=["1","y","q"]):
            self.assertEqual(0,admin.interactive_approval_pool(self.subject,poll_seconds=1))
        self.assertIn("[1] Arthur",stderr.getvalue())
        self.assertIn("Approved:",stderr.getvalue())
    def test_approve_imports_before_signing_and_publishes_complete_bundle(self):
        result=self.subject.approve(IDENT,SPKI); self.assertEqual("approved",result["state"])
        self.assertEqual(["validate","import","approve","bundle","finalize"],[item[0] for item in self.engine.calls])
        publish=next(values for command,values in self.portal.calls if command=="publish")
        response=publish["response"]; self.assertEqual("CA\n",response["ca_pem"])
        self.assertEqual("high-assurance", response["security_mode"])
        self.assertEqual("included", response["companion_provisioning"])
        self.assertNotIn("companion_token", response)
        self.assertIn("companion_script_b64", response)
        self.assertIn("remote vpn.example.test 1194",response["openvpn_config"])
        self.assertNotIn("persist-key", response["openvpn_config"])
        self.assertNotIn("data-ciphers-fallback", response["openvpn_config"])
        self.assertNotIn("<key>",response["openvpn_config"]); self.assertEqual(SPKI,publish["spki_sha256"])

    def test_reenrollment_preserves_existing_companion_identity(self):
        self.companion.registration = "existing-different"
        self.subject.approve(IDENT, SPKI)
        publish=next(values for command,values in self.portal.calls if command=="publish")
        self.assertEqual("preserved-existing", publish["response"]["companion_provisioning"])
        self.assertNotIn("companion_config", publish["response"])
        self.assertIn("companion_script_b64", publish["response"])
        self.assertIn("companion_launcher_b64", publish["response"])
    def test_missing_import_boundary_fails_closed_before_ca(self):
        delattr(FakeEngine,"import_portal_submission")
        try:
            with self.assertRaisesRegex(admin.AdminError,"import_portal_submission"): self.subject.approve(IDENT,SPKI)
            self.assertNotIn("approve",[item[0] for item in self.engine.calls])
        finally:
            FakeEngine.import_portal_submission=lambda self,store,ident,csr,expected_spki,openssl: {"spki_sha256":SPKI}
    def test_reject_revoke_status_and_invalid_identifiers(self):
        self.assertEqual("rejected",self.subject.reject(IDENT,"denied")["state"])
        self.assertEqual("created",self.subject.status(IDENT)["engine"]["state"])
        with self.assertRaises(admin.AdminError): self.subject.status("../bad")

    def test_offboard_revokes_every_credential_and_removes_companion_access(self):
        with mock.patch.object(self.subject, "_revoke_pki_name") as revoke_pki:
            result = self.subject.offboard("Arthur", "left the trusted group")
        self.assertEqual("offboarded", result["state"])
        self.assertEqual([IDENT], result["revoked"])
        self.assertTrue(result["companion_removed"])
        revoke_pki.assert_called_once_with("credential-id", "AB")
        self.assertIn(("cancel", {"id": IDENT}), self.portal.calls)
        self.assertIn(("retire-player", "Arthur"), self.engine.calls)
        self.assertEqual("Arthur", self.companion.calls[-1][1])
        self.assertIsNone(self.companion.calls[-1][2])

    @mock.patch.object(admin.subprocess, "run")
    def test_revoke_updates_shared_crl_and_cuts_sessions_before_finalizing(self, run):
        issued=self.root/"pki"/"issued"; issued.mkdir(parents=True)
        (issued/"credential-id.crt").write_text("CERT")
        (self.root/"pki"/"index.txt").write_text("V\t300101000000Z\t\tAB\tunknown\t/CN=test\n")
        (self.root/"pki"/"crl.pem").write_text("CRL")
        def result(command, **_kwargs):
            if command[1] == "x509": return mock.Mock(stdout=b"serial=AB\n")
            if command[1] == "crl": return mock.Mock(stdout=b"nextUpdate=Jan  1 00:00:00 2099 GMT\n")
            return mock.Mock(stdout=b"")
        run.side_effect=result
        self.assertEqual("revoked",self.subject.revoke(IDENT,"lost device")["state"])
        commands=[call.args[0] for call in run.call_args_list]
        self.assertIn(["easyrsa","revoke","credential-id"],commands)
        self.assertIn(["openssl","crl","-in",str(self.root/"pki"/"crl.pem"),"-noout","-nextupdate"],commands)
        self.assertFalse(any("-checkend" in command for command in commands))
        self.assertIn(["systemctl","restart","openvpn-test.service"],commands)
        self.assertEqual(b"CRL",(self.root/"crl.pem").read_bytes())

    @mock.patch.object(admin.subprocess, "run")
    def test_revoke_resumes_after_easyrsa_already_moved_certificate(self, run):
        (self.root/"pki"/"index.txt").write_text(
            "R\t300101000000Z\t260101000000Z\tAB\tunknown\t/CN=test\n"
        )
        (self.root/"pki"/"crl.pem").write_text("CRL")
        def result(command, **_kwargs):
            if command[1] == "crl": return mock.Mock(stdout=b"nextUpdate=Jan  1 00:00:00 2099 GMT\n")
            return mock.Mock(stdout=b"")
        run.side_effect=result
        self.assertEqual("revoked",self.subject.revoke(IDENT,"retry")['state'])
        commands=[call.args[0] for call in run.call_args_list]
        self.assertNotIn(["easyrsa","revoke","credential-id"],commands)
        self.assertIn(["systemctl","restart","openvpn-test.service"],commands)

    def test_crl_next_update_is_timezone_aware_and_strict(self):
        parsed=admin.openssl_next_update("nextUpdate=Jul 13 01:28:35 2036 GMT")
        self.assertEqual(dt.timezone.utc,parsed.tzinfo)
        with self.assertRaisesRegex(admin.AdminError,"invalid CRL nextUpdate"):
            admin.openssl_next_update("not-a-date")

    def test_socket_protocol_is_newline_bounded(self):
        path=self.root/"admin.sock"; server=socketserver.UnixStreamServer(str(path),Handler)
        thread=threading.Thread(target=server.handle_request); thread.start()
        value=admin.PortalClient(path).request("register",invitation={"id":IDENT})
        thread.join(2); server.server_close(); self.assertEqual("created",value["state"])
        self.assertLessEqual(len(server.received),admin.MAX_MESSAGE)
    def test_safe_static_openvpn_configuration(self):
        self.assertIn("remote-cert-tls server",self.subject.openvpn_config())
        self.assertIn("dev tap",self.subject.openvpn_config())
        self.assertIn("verify-x509-name server name",self.subject.openvpn_config())
        self.assertIn("allow-compression no",self.subject.openvpn_config())
        self.assertNotIn("dev tun",self.subject.openvpn_config())
        self.subject.remote="bad host"
        with self.assertRaises(admin.AdminError): self.subject.openvpn_config()

    @mock.patch.object(admin.time, "sleep")
    def test_connection_confirmation_supports_v2_v3_and_waits_for_exact_cn(self, sleep):
        self.engine.state="collected"
        (self.root/"status.log").write_text("TITLE,OpenVPN 2.7\nCLIENT_LIST,vpn-player:credential-id,198.51.100.2:1\n")
        self.assertEqual("collected",self.subject.confirm_connection(IDENT)["state"])
        (self.root/"status.log").write_text("CLIENT_LIST,Arthur,198.51.100.2:1\n")
        sleep.side_effect=lambda _seconds: (self.root/"status.log").write_text(
            "TITLE\tOpenVPN 2.7\nCLIENT_LIST\tvpn-player:credential-id\t198.51.100.2:1\n"
        )
        self.assertEqual("collected",self.subject.confirm_connection(IDENT)["state"])
        self.assertEqual(1,sleep.call_count)
        sleep.reset_mock(side_effect=True)
        (self.root/"status.log").write_text("CLIENT_LIST\tArthur\t198.51.100.2:1\n")
        with self.assertRaisesRegex(admin.AdminError,"not currently connected"):
            self.subject.confirm_connection(IDENT)
        self.assertEqual(admin.CONNECTION_STATUS_ATTEMPTS - 1,sleep.call_count)

    def test_approve_requires_full_matching_spki(self):
        with self.assertRaisesRegex(admin.AdminError,"confirmed SPKI"):
            self.subject.approve(IDENT,"0"*64)


if __name__ == "__main__": unittest.main()
