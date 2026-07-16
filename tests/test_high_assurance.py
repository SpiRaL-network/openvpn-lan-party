import importlib.util
import base64
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor


SOURCE = Path(__file__).parents[1] / "assets" / "vpn-player-enrollment.py"
SPEC = importlib.util.spec_from_file_location("enrollment", SOURCE)
enrollment = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(enrollment)
VALIDATOR_SOURCE = Path(__file__).parents[1] / "assets" / "vpn-enrollment-csr.py"
VALIDATOR_SPEC = importlib.util.spec_from_file_location("public_csr_validator", VALIDATOR_SOURCE)
validator = importlib.util.module_from_spec(VALIDATOR_SPEC)
assert VALIDATOR_SPEC.loader
VALIDATOR_SPEC.loader.exec_module(validator)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL unavailable")
class HighAssuranceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = enrollment.Store(self.root / "state")
        self.ca_key = self.root / "ca.key"
        self.ca_cert = self.root / "ca.crt"
        self.key = self.root / "player.key"
        self.csr = self.root / "player.csr"
        self.commands = []
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-subj", "/CN=Test CA", "-keyout", str(self.ca_key), "-out", str(self.ca_cert),
                        "-days", "1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def tearDown(self): self.temp.cleanup()

    def make_csr(self, subject, curve="P-256", extensions=None):
        command = ["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", f"ec_paramgen_curve:{curve}",
                   "-nodes", "-subj", subject, "-keyout", str(self.key), "-out", str(self.csr)]
        if extensions: command += ["-addext", extensions]
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return self.csr.read_bytes()

    def invite(self): return enrollment.create(self.store, "Arthur", 900)

    def race_twice(self, operation):
        barrier = threading.Barrier(2)
        def run_one():
            barrier.wait()
            try:
                return "ok", operation()
            except enrollment.EnrollmentError as exc:
                return "error", str(exc)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: run_one(), range(2)))
        self.assertEqual(1, sum(kind == "ok" for kind, _ in results), results)
        self.assertEqual(1, sum(kind == "error" for kind, _ in results), results)
        return next(value for kind, value in results if kind == "ok")

    def submit(self):
        invitation = self.invite()
        enrollment.submit(self.store, invitation["id"], invitation["token"],
                          self.make_csr(f"/CN={invitation['certificate_cn']}"), "openssl")
        return invitation

    def fake_runner(self, command, input_data=None):
        self.commands.append(command)
        if "tls-crypt-v2-client" in command:
            Path(command[command.index("tls-crypt-v2-client") + 1]).write_text("-----BEGIN OpenVPN tls-crypt-v2 client key-----\nTEST\n")
            return b""
        return enrollment.run(command, input_data=input_data)

    def test_complete_atomic_flow_and_replays(self):
        invitation = self.submit()
        approved = enrollment.approve(self.store, invitation["id"], self.ca_cert, self.ca_key,
                                      self.root / "server.key", "openssl", "openvpn", self.fake_runner)
        result = enrollment.collect(self.store, invitation["id"], approved["collect_token"])
        self.assertIn("BEGIN CERTIFICATE", result["certificate_pem"])
        self.assertIn("tls-crypt-v2", result["tls_crypt_v2"])
        self.assertEqual("collected", enrollment.public_status(self.store, invitation["id"])["state"])
        self.assertEqual(invitation["certificate_cn"], result["certificate_cn"])
        self.assertNotEqual("Arthur", result["certificate_cn"])
        registry = self.store.registry()["credentials"][approved["kid"]]
        self.assertEqual("active", registry["state"])
        self.assertEqual(invitation["credential_id"], registry["credential_id"])
        with self.assertRaises(enrollment.EnrollmentError):
            enrollment.collect(self.store, invitation["id"], approved["collect_token"])
        state = json.loads(self.store.path(invitation["id"]).read_text())
        self.assertNotIn(invitation["token"], self.store.path(invitation["id"]).read_text())
        self.assertNotIn("certificate_pem", state)
        self.assertEqual(0o600, self.store.path(invitation["id"]).stat().st_mode & 0o777)
        self.assertEqual(0o700, self.store.root.stat().st_mode & 0o777)

    def test_publication_is_not_consumed_before_ack_and_can_resume(self):
        invitation = self.submit()
        enrollment.approve(
            self.store, invitation["id"], self.ca_cert, self.ca_key,
            self.root / "server.key", "openssl", "openvpn", self.fake_runner
        )
        first = enrollment.publication_bundle(self.store, invitation["id"])
        second = enrollment.publication_bundle(self.store, invitation["id"])
        self.assertEqual(first, second)
        self.assertEqual("approved", enrollment.public_status(self.store, invitation["id"])["state"])
        bundle_hash = __import__("hashlib").sha256(
            enrollment.canonical_json(first).encode()
        ).hexdigest()
        with self.assertRaises(enrollment.EnrollmentError):
            enrollment.finalize_publication(self.store, invitation["id"], "0" * 64)
        enrollment.finalize_publication(self.store, invitation["id"], bundle_hash)
        self.assertEqual("collected", enrollment.public_status(self.store, invitation["id"])["state"])

    def test_wrong_token_and_submission_replay(self):
        invitation = self.invite(); csr = self.make_csr(f"/CN={invitation['certificate_cn']}")
        with self.assertRaises(enrollment.EnrollmentError):
            enrollment.submit(self.store, invitation["id"], "wrong", csr, "openssl")
        enrollment.submit(self.store, invitation["id"], invitation["token"], csr, "openssl")
        with self.assertRaises(enrollment.EnrollmentError):
            enrollment.submit(self.store, invitation["id"], invitation["token"], csr, "openssl")

    def test_security_mode_is_per_credential_and_cannot_change_in_place(self):
        first = enrollment.create(self.store, "Arthur", 900, "high-assurance")
        with self.assertRaisesRegex(enrollment.EnrollmentError, "another security mode"):
            enrollment.create(self.store, "Arthur", 900, "compatible")
        enrollment.terminal(self.store, first["id"], "rejected", "policy replacement")
        second = enrollment.create(self.store, "Arthur", 900, "compatible")
        self.assertEqual("compatible", second["security_mode"])
        self.assertEqual(first["player_id"], second["player_id"])
        enrollment.terminal(self.store, second["id"], "rejected", "player retired")
        retired = enrollment.retire_player(self.store, "Arthur")
        self.assertTrue(retired["retired"])
        replacement = enrollment.create(self.store, "Arthur", 900, "high-assurance")
        self.assertNotEqual(first["player_id"], replacement["player_id"])

    def test_concurrent_submit_approve_and_collect_are_single_winner(self):
        invitation = self.invite()
        csr = self.make_csr(f"/CN={invitation['certificate_cn']}")
        self.race_twice(lambda: enrollment.submit(
            self.store, invitation["id"], invitation["token"], csr, "openssl"
        ))
        approved = self.race_twice(lambda: enrollment.approve(
            self.store, invitation["id"], self.ca_cert, self.ca_key,
            self.root / "server.key", "openssl", "openvpn", self.fake_runner
        ))
        collected = self.race_twice(lambda: enrollment.collect(
            self.store, invitation["id"], approved["collect_token"]
        ))
        self.assertEqual(invitation["credential_id"], collected["credential_id"])
        self.assertEqual("collected", enrollment.public_status(
            self.store, invitation["id"]
        )["state"])

    def test_privileged_portal_import_binds_exact_spki(self):
        invitation = self.invite()
        csr = self.make_csr(f"/CN={invitation['certificate_cn']}")
        spki = enrollment.validate_csr(csr, invitation["certificate_cn"], "openssl")
        imported = enrollment.import_portal_submission(
            self.store, invitation["id"], csr, spki, "openssl"
        )
        self.assertEqual("csr-submitted", imported["state"])
        state = json.loads(self.store.path(invitation["id"]).read_text())
        self.assertEqual("enrollment-portal", state["imported_from"])
        other = self.invite()
        other_csr = self.make_csr(f"/CN={other['certificate_cn']}")
        with self.assertRaisesRegex(enrollment.EnrollmentError, "fingerprint mismatch"):
            enrollment.import_portal_submission(
                self.store, other["id"], other_csr, "0" * 64, "openssl"
            )

    def test_duplicate_public_key_rejected_across_invitations(self):
        first = self.invite(); csr = self.make_csr(f"/CN={first['certificate_cn']}")
        enrollment.submit(self.store, first["id"], first["token"], csr, "openssl")
        second = self.invite()
        # The same key with the second assigned technical identity is still a replay.
        subprocess.run(["openssl", "req", "-new", "-key", str(self.key), "-subj",
                        f"/CN={second['certificate_cn']}", "-out", str(self.csr)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with self.assertRaisesRegex(enrollment.EnrollmentError, "already"):
            enrollment.submit(self.store, second["id"], second["token"], self.csr.read_bytes(), "openssl")

    def test_subject_extensions_and_curve_rejected(self):
        for kind in ("wrong", "extra", "curve", "extension"):
            with self.subTest(kind=kind):
                invitation = self.invite(); cn = invitation["certificate_cn"]
                subject = "/CN=Mallory" if kind == "wrong" else f"/CN={cn}"
                if kind == "extra": subject += "/O=Injected"
                curve = "P-384" if kind == "curve" else "P-256"
                extension = "subjectAltName=DNS:evil" if kind == "extension" else None
                with self.assertRaises(enrollment.EnrollmentError):
                    enrollment.submit(self.store, invitation["id"], invitation["token"],
                                      self.make_csr(subject, curve, extension), "openssl")

    def test_public_and_privileged_csr_validators_enforce_identical_policy(self):
        invitation = self.invite()
        cn = invitation["certificate_cn"]
        valid = self.make_csr(f"/CN={cn}")
        self.assertEqual(
            enrollment.validate_csr(valid, cn), validator.validate_csr(valid, cn)
        )
        invalid_requests = (
            self.make_csr("/CN=wrong"),
            self.make_csr(f"/CN={cn}", curve="P-384"),
            self.make_csr(f"/CN={cn}", extensions="subjectAltName=DNS:evil"),
        )
        for request in invalid_requests:
            with self.assertRaises(enrollment.EnrollmentError):
                enrollment.validate_csr(request, cn)
            with self.assertRaises(validator.EnrollmentError):
                validator.validate_csr(request, cn)

    def test_expiry_rejection_and_revocation(self):
        invitation = self.submit()
        enrollment.terminal(self.store, invitation["id"], "rejected", "administrator denied request")
        self.assertEqual("rejected", enrollment.public_status(self.store, invitation["id"])["state"])
        other = self.submit()
        approved = enrollment.approve(self.store, other["id"], self.ca_cert, self.ca_key,
                                      self.root / "server.key", "openssl", "openvpn", self.fake_runner)
        enrollment.terminal(self.store, other["id"], "revoked", "device lost")
        self.assertEqual("revoked", self.store.registry()["credentials"].get(approved["kid"], {}).get("state", "revoked"))
        with self.assertRaises(enrollment.EnrollmentError):
            enrollment.collect(self.store, other["id"], approved["collect_token"])

    def test_invalid_names_and_ttl(self):
        for player in ("", "../root", "é", "a" * 65):
            with self.assertRaises(enrollment.EnrollmentError): enrollment.create(self.store, player, 900)
        with self.assertRaises(enrollment.EnrollmentError): enrollment.create(self.store, "Arthur", 10)

    def test_player_uuid_is_stable_and_credential_uuid_rotates(self):
        first = self.invite()
        second = self.invite()
        self.assertEqual(first["player_id"], second["player_id"])
        self.assertNotEqual(first["credential_id"], second["credential_id"])
        self.assertNotEqual(first["certificate_cn"], second["certificate_cn"])

    def approved_and_collected(self):
        invitation = self.submit()
        approved = enrollment.approve(self.store, invitation["id"], self.ca_cert, self.ca_key,
                                      self.root / "server.key", "openssl", "openvpn", self.fake_runner)
        enrollment.collect(self.store, invitation["id"], approved["collect_token"])
        state = json.loads(self.store.path(invitation["id"]).read_text())
        return invitation, approved, state

    def test_tls_command_uses_positional_base64_canonical_metadata(self):
        invitation = self.submit()
        approved = enrollment.approve(self.store, invitation["id"], self.ca_cert, self.ca_key,
                                      self.root / "server.key", "openssl", "openvpn", self.fake_runner)
        command = next(item for item in self.commands if "tls-crypt-v2-client" in item)
        self.assertNotIn("--tls-crypt-v2-meta", command)
        self.assertEqual(7, len(command))
        metadata = base64.b64decode(command[-1], validate=True).decode()
        self.assertEqual(metadata, enrollment.canonical_json(json.loads(metadata)))
        self.assertEqual({"iat", "kid", "serial", "v"}, set(json.loads(metadata)))
        self.assertEqual(approved["kid"], json.loads(metadata)["kid"])
        self.assertRegex(approved["serial"], r"^[0-9A-F]+$")

    def test_real_openvpn_generates_wrapped_client_key_when_available(self):
        openvpn = shutil.which("openvpn")
        if openvpn is None and Path("/usr/sbin/openvpn").is_file():
            openvpn = "/usr/sbin/openvpn"
        if openvpn is None:
            self.skipTest("OpenVPN binary unavailable")
        server_key = self.root / "tls-crypt-v2-server.key"
        subprocess.run(
            [openvpn, "--genkey", "tls-crypt-v2-server", str(server_key)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        invitation = self.submit()
        approved = enrollment.approve(
            self.store, invitation["id"], self.ca_cert, self.ca_key,
            server_key, "openssl", openvpn,
        )
        result = enrollment.collect(
            self.store, invitation["id"], approved["collect_token"]
        )
        self.assertIn(
            "BEGIN OpenVPN tls-crypt-v2 client key", result["tls_crypt_v2"]
        )

    @unittest.skipUnless(Path("/usr/share/easy-rsa/easyrsa").is_file(), "Easy-RSA unavailable")
    def test_production_signing_uses_shared_easyrsa_database(self):
        pki = self.root / "pki"
        environment = {**__import__("os").environ, "EASYRSA_BATCH": "1", "EASYRSA_PKI": str(pki)}
        easyrsa = "/usr/share/easy-rsa/easyrsa"
        subprocess.run([easyrsa, "init-pki"], check=True, env=environment,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (pki / "x509-types").mkdir()
        shutil.copy2(Path(__file__).parents[1] / "assets/x509-types/vpn-player",
                     pki / "x509-types/vpn-player")
        environment["EASYRSA_REQ_CN"] = "Test shared CA"
        subprocess.run([easyrsa, "build-ca", "nopass"], check=True, env=environment,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        invitation = self.submit()
        approved = enrollment.approve(
            self.store, invitation["id"], pki / "ca.crt", pki / "private/ca.key",
            self.root / "server.key", "openssl", "openvpn", self.fake_runner,
            pki_dir=pki, easyrsa=easyrsa,
        )
        state = json.loads(self.store.path(invitation["id"]).read_text())
        self.assertEqual(invitation["credential_id"], state["pki_name"])
        self.assertTrue((pki / "issued" / f"{invitation['credential_id']}.crt").is_file())
        self.assertIn(approved["serial"], (pki / "index.txt").read_text())

    def test_metadata_unknown_modified_and_revoked_are_rejected(self):
        invitation, approved, state = self.approved_and_collected()
        metadata_file = self.root / "metadata.json"
        metadata_file.write_text(state["tls_metadata"])
        self.assertEqual("active", enrollment.verify_metadata_file(self.store, metadata_file, "0")["state"])
        value = json.loads(state["tls_metadata"])
        value["kid"] = base64.urlsafe_b64encode(b"unknown-kid-0000").rstrip(b"=").decode()
        metadata_file.write_text(enrollment.canonical_json(value))
        with self.assertRaises(enrollment.EnrollmentError):
            enrollment.verify_metadata_file(self.store, metadata_file, "0")
        metadata_file.write_text(state["tls_metadata"] + "\n")
        with self.assertRaisesRegex(enrollment.EnrollmentError, "canonical"):
            enrollment.verify_metadata_file(self.store, metadata_file, "0")
        metadata_file.write_text(state["tls_metadata"])
        enrollment.terminal(self.store, invitation["id"], "revoked", "device retired")
        with self.assertRaises(enrollment.EnrollmentError):
            enrollment.verify_metadata_file(self.store, metadata_file, "0")
        self.assertEqual("revoked", self.store.registry()["credentials"][approved["kid"]]["state"])

    def test_minimal_verification_snapshot_contains_no_player_or_token(self):
        snapshot = self.root / "verification.json"
        store = enrollment.Store(self.root / "snapshot-state", snapshot)
        invitation = enrollment.create(store, "SecretDisplayName", 900)
        csr = self.make_csr(f"/CN={invitation['certificate_cn']}")
        enrollment.submit(store, invitation["id"], invitation["token"], csr, "openssl")
        approved = enrollment.approve(
            store, invitation["id"], self.ca_cert, self.ca_key,
            self.root / "server.key", "openssl", "openvpn", self.fake_runner
        )
        enrollment.collect(store, invitation["id"], approved["collect_token"])
        content = snapshot.read_text()
        self.assertNotIn("SecretDisplayName", content)
        self.assertNotIn("token", content)
        metadata = json.loads(store.path(invitation["id"]).read_text())["tls_metadata"]
        metadata_file = self.root / "snapshot-metadata.json"
        metadata_file.write_text(metadata)
        self.assertEqual(
            "active",
            enrollment.verify_metadata_file(store, metadata_file, "0", snapshot)["state"],
        )
        self.assertEqual(0o640, snapshot.stat().st_mode & 0o777)

    def test_metadata_rejects_wrong_type_and_symlink(self):
        _, _, state = self.approved_and_collected()
        metadata_file = self.root / "metadata.json"; metadata_file.write_text(state["tls_metadata"])
        with self.assertRaises(enrollment.EnrollmentError):
            enrollment.verify_metadata_file(self.store, metadata_file, "1")
        link = self.root / "link"; link.symlink_to(metadata_file)
        with self.assertRaises(enrollment.EnrollmentError):
            enrollment.verify_metadata_file(self.store, link, "0")


if __name__ == "__main__": unittest.main()
