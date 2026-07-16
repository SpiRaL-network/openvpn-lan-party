#!/usr/bin/env python3
"""Root-only orchestration for the OpenVPN LAN Party enrolment boundary.

Root exchanges public request material with the broker over its bounded Unix socket.
CA and OpenVPN key paths are accepted exclusively from this local CLI.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import contextlib
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
import fcntl
import grp
import hashlib
import hmac
import importlib.machinery
import importlib.util
import json
import io
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from typing import Any
import zipfile


MAX_MESSAGE = 256 * 1024
CONNECTION_STATUS_ATTEMPTS = 35
CONNECTION_STATUS_DELAY = 0.2
ID_RE = re.compile(r"[0-9a-f]{64}\Z")
SAFE_HOST_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}\Z")
EMAIL_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,189}\Z")


class AdminError(RuntimeError):
    pass


def load_engine(path: Path):
    module_name = "vpn_enrollment_engine"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if not spec or not spec.loader:
        loader = importlib.machinery.SourceFileLoader(module_name, str(path))
        spec = importlib.util.spec_from_loader(module_name, loader)
    if not spec or not spec.loader:
        raise AdminError("cannot load enrollment engine")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expiry_epoch(value: str) -> int:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise AdminError("engine returned an invalid expiry") from exc
    if parsed.tzinfo is None:
        raise AdminError("engine returned an expiry without timezone")
    return int(parsed.timestamp())


def openssl_next_update(value: str) -> dt.datetime:
    prefix = "nextUpdate="
    if not value.startswith(prefix):
        raise AdminError("OpenSSL returned an invalid CRL nextUpdate")
    try:
        parsed = parsedate_to_datetime(value.removeprefix(prefix))
    except (TypeError, ValueError) as exc:
        raise AdminError("OpenSSL returned an invalid CRL nextUpdate") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def safe_bundle_player(value: str) -> str:
    result = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip(".-")
    return (result or "Player")[:48]


def protect_payload(value: bytes, password: str, openssl: str) -> bytes:
    """AES-256-CBC encrypt and HMAC-authenticate a Windows invitation payload."""
    password_bytes = password.encode("ascii")
    if not 12 <= len(password_bytes) <= 128 or len(value) > 256 * 1024:
        raise AdminError("invalid invitation payload or password")
    password_path: str | None = None
    try:
        fd, password_path = tempfile.mkstemp(prefix=".vpn-invitation-password-")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(password_bytes + b"\n"); stream.flush(); os.fsync(stream.fileno())
        encrypted = subprocess.run(
            [openssl, "enc", "-aes-256-cbc", "-salt", "-saltlen", "16", "-pbkdf2",
             "-iter", "200000", "-md", "sha256", "-pass", f"file:{password_path}"],
            input=value, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AdminError("cannot protect the Windows invitation payload") from exc
    finally:
        if password_path:
            with contextlib.suppress(FileNotFoundError): os.unlink(password_path)
    if not encrypted.startswith(b"Salted__") or len(encrypted) < 40:
        raise AdminError("OpenSSL returned an invalid invitation payload")
    salt = encrypted[8:24]
    derived = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, 200000, 80)
    authentication = hmac.new(derived[48:80], encrypted, hashlib.sha256).digest()
    return encrypted + authentication


def invitation_zip(entries: dict[str, bytes]) -> bytes:
    if not entries or len(entries) > 8:
        raise AdminError("invalid invitation archive entry count")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, value in entries.items():
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", name):
                raise AdminError("invalid invitation archive filename")
            if len(value) > 300 * 1024:
                raise AdminError("invitation archive entry is too large")
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, value)
    result = output.getvalue()
    if len(result) > 170 * 1024:
        raise AdminError("invitation archive exceeds the portal size limit")
    return result


def send_invitation_email(output: dict[str, Any], recipient: str, sendmail: Path) -> None:
    """Optionally mail only the public portal link; credentials remain out-of-band."""
    if not EMAIL_RE.fullmatch(recipient) or ".." in recipient:
        raise AdminError("invalid invitation email recipient")
    if not sendmail.is_file() or not os.access(sendmail, os.X_OK):
        raise AdminError(f"sendmail-compatible executable is unavailable: {sendmail}")
    message = EmailMessage()
    message["From"] = "OpenVPN LAN Party <openvpn-lan-party@localhost>"
    message["To"] = recipient
    message["Subject"] = output["email_subject"]
    message.set_content(output["email_body"] + "\n")
    try:
        subprocess.run([str(sendmail), "-t", "-oi"], input=message.as_bytes(),
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                       timeout=30, check=True)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise AdminError("the invitation email could not be handed to the local mail service") from exc


class PortalClient:
    def __init__(self, path: Path, timeout: float = 5.0):
        self.path = path
        self.timeout = timeout

    def request(self, command: str, **values: Any) -> dict[str, Any]:
        request = {"command": command, **values}
        encoded = (json.dumps(request, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(encoded) > MAX_MESSAGE:
            raise AdminError("portal request exceeds the size limit")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(self.timeout)
                client.connect(str(self.path))
                client.sendall(encoded)
                stream = client.makefile("rb")
                raw = stream.readline(MAX_MESSAGE + 1)
                if len(raw) > MAX_MESSAGE or not raw.endswith(b"\n"):
                    raise AdminError("portal response is missing or exceeds the size limit")
        except AdminError:
            raise
        except OSError as exc:
            raise AdminError("cannot communicate with enrollment portal") from exc
        try:
            answer = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise AdminError("portal returned invalid JSON") from exc
        if not isinstance(answer, dict) or answer.get("ok") is not True or not isinstance(answer.get("result"), dict):
            detail = answer.get("error") if isinstance(answer, dict) else None
            raise AdminError(f"portal rejected request: {detail or 'unspecified error'}")
        return answer["result"]


class Administrator:
    def __init__(self, engine: Any, store: Any, portal: Any, *, public_url: str,
                 ca_cert: Path, ca_key: Path, tls_server_key: Path,
                 portal_tls_cert: Path, remote: str, port: int, proto: str,
                 openssl: str, openvpn: str, pki_dir: Path,
                 easyrsa: str, deployed_crl: Path, openvpn_service: str,
                 status_file: Path, companion: Any,
                 companion_config: Path, companion_script: Path,
                 companion_launcher: Path,
                 windows_join_script: Path = Path("/usr/local/share/vpn-manager/windows/Join-VPN.ps1"),
                 windows_join_launcher: Path = Path("/usr/local/share/vpn-manager/windows/JOIN-VPN.cmd"),
                 windows_enroll_script: Path = Path("/usr/local/share/vpn-manager/windows/Enroll-VPN-High-Assurance.ps1"),
                 windows_test_script: Path = Path("/usr/local/share/vpn-manager/windows/Test-VPN-High-Assurance.ps1"),
                 windows_leave_script: Path = Path("/usr/local/share/vpn-manager/windows/Leave-OpenVPN-LAN-Party.ps1")):
        self.engine = engine
        self.store = store
        self.portal = portal
        self.public_url = public_url.rstrip("/")
        self.ca_cert = ca_cert
        self.ca_key = ca_key
        self.tls_server_key = tls_server_key
        self.portal_tls_cert = portal_tls_cert
        self.remote = remote
        self.port = port
        self.proto = proto
        self.openssl = openssl
        self.openvpn = openvpn
        self.pki_dir = pki_dir
        self.easyrsa = easyrsa
        self.deployed_crl = deployed_crl
        self.openvpn_service = openvpn_service
        self.status_file = status_file
        self.companion = companion
        self.companion_config = companion_config
        self.companion_script = companion_script
        self.companion_launcher = companion_launcher
        self.windows_join_script = windows_join_script
        self.windows_join_launcher = windows_join_launcher
        self.windows_enroll_script = windows_enroll_script
        self.windows_test_script = windows_test_script
        self.windows_leave_script = windows_leave_script

    @contextlib.contextmanager
    def pki_locked(self):
        lock_path = self.pki_dir / ".operation.lock"
        try:
            fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        except OSError as exc:
            raise AdminError("cannot open the shared PKI operation lock") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    @staticmethod
    def require_id(enrollment_id: str) -> None:
        if not isinstance(enrollment_id, str) or not ID_RE.fullmatch(enrollment_id):
            raise AdminError("invalid enrollment identifier")

    def create(self, player: str, ttl: int, security_mode: str) -> dict[str, Any]:
        if security_mode not in {"high-assurance", "compatible"}:
            raise AdminError("invalid credential security mode")
        invitation = self.engine.create(self.store, player, ttl, security_mode)
        try:
            pem = self.portal_tls_cert.read_text(encoding="ascii")
            match = re.search(
                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                pem, re.DOTALL,
            )
            if not match:
                raise ValueError
            tls_sha256 = hashlib.sha256(
                ssl.PEM_cert_to_DER_cert(match.group(0))
            ).hexdigest()
        except (OSError, UnicodeError, ValueError) as exc:
            raise AdminError("cannot fingerprint enrollment portal TLS certificate") from exc

        bootstrap_assets = {
            "JOIN-VPN.cmd": self.windows_join_launcher,
            "Join-VPN.ps1": self.windows_join_script,
        }
        protected_assets = {
            "Enroll-VPN-High-Assurance.ps1": self.windows_enroll_script,
            "Test-VPN-High-Assurance.ps1": self.windows_test_script,
        }
        try:
            bootstrap = {name: path.read_bytes() for name, path in bootstrap_assets.items()}
            protected_scripts = {name: path.read_bytes() for name, path in protected_assets.items()}
        except OSError as exc:
            raise AdminError("cannot read the installed Windows invitation assets") from exc
        invitation_manifest = {
            "schema": 1,
            "player": invitation["player"],
            "enrollment_id": invitation["id"],
            "enrollment_uri": self.public_url,
            "tls_certificate_sha256": tls_sha256,
            "security_mode": invitation["security_mode"],
            "expires_at": invitation["expires_at"],
            "files": {name: sha256_bytes(value) for name, value in protected_scripts.items()},
        }
        archive_password = secrets.token_urlsafe(18)
        private_payload = {
            "schema": 1,
            "invitation": invitation_manifest,
            "scripts": {
                name: base64.b64encode(value).decode("ascii")
                for name, value in protected_scripts.items()
            },
        }
        protected = protect_payload(
            (json.dumps(private_payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii"),
            archive_password, self.openssl,
        )
        bundle_manifest = {
            "schema": 1,
            "format": "openvpn-lan-party-protected-invitation",
            "payload": "invitation.vpninvite",
            "payload_sha256": sha256_bytes(protected),
            "files": {name: sha256_bytes(value) for name, value in bootstrap.items()},
        }
        archive_entries = dict(bootstrap)
        archive_entries["bundle.json"] = (
            json.dumps(bundle_manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("ascii")
        archive_entries["invitation.vpninvite"] = protected
        archive = invitation_zip(archive_entries)
        archive_name = f"OpenVPN-LAN-Party-{safe_bundle_player(invitation['player'])}.zip"
        registered = self.portal.request("register", invitation={
            "id": invitation["id"], "token": invitation["token"],
            "player": invitation["player"], "certificate_cn": invitation["certificate_cn"],
            "player_id": invitation["player_id"],
            "credential_id": invitation["credential_id"],
            "security_mode": invitation["security_mode"],
            "expires_at": expiry_epoch(invitation["expires_at"]),
        }, bundle_b64=base64.b64encode(archive).decode("ascii"),
            bundle_sha256=sha256_bytes(archive), bundle_filename=archive_name)
        download_url = f"{self.public_url}/invitations/{invitation['id']}/{archive_name}"
        return {
            "id": invitation["id"], "state": registered["state"],
            "url": self.public_url, "token": invitation["token"],
            "expires_at": invitation["expires_at"], "player": invitation["player"],
            "player_id": invitation["player_id"], "credential_id": invitation["credential_id"],
            "certificate_cn": invitation["certificate_cn"],
            "security_mode": invitation["security_mode"],
            "challenge": f"{invitation['id'][:4]}-{invitation['id'][-4:]}",
            "tls_certificate_sha256": tls_sha256,
            "download_url": download_url,
            "archive_password": archive_password,
            "archive_sha256": sha256_bytes(archive),
            "email_subject": f"OpenVPN LAN Party invitation - {invitation['player']}",
            "email_body": (
                f"Download your OpenVPN LAN Party invitation:\n{download_url}\n\n"
                "The archive password and one-time token will be sent separately.\n"
                "Extract the archive, then double-click JOIN-VPN.cmd."
            ),
        }

    def inspect(self, enrollment_id: str) -> dict[str, Any]:
        self.require_id(enrollment_id)
        pending = self.portal.request("inspect", id=enrollment_id)
        csr = pending.get("csr")
        if not isinstance(csr, str) or len(csr.encode("utf-8")) > 64 * 1024:
            raise AdminError("portal supplied an invalid CSR")
        fingerprint = self.engine.validate_csr(csr.encode("ascii"), pending["certificate_cn"], self.openssl)
        if fingerprint != pending.get("spki_sha256"):
            raise AdminError("portal CSR fingerprint mismatch")
        return {**pending, "spki_sha256": fingerprint,
                "comparison_code": fingerprint[:4] + "-" + fingerprint[-4:]}

    def wait_for_request(self, enrollment_id: str, expires_at: str,
                         poll_seconds: float = 2.0) -> dict[str, Any]:
        """Wait for the CSR belonging to one known invitation, without signing it."""
        self.require_id(enrollment_id)
        deadline = expiry_epoch(expires_at)
        if poll_seconds <= 0:
            raise AdminError("invalid enrollment polling interval")
        while int(time.time()) < deadline:
            status = self.portal.request("status", id=enrollment_id)
            if status.get("id") != enrollment_id:
                raise AdminError("portal returned a different enrollment identifier")
            state = status.get("state")
            if state == "pending":
                return self.inspect(enrollment_id)
            if state != "created":
                raise AdminError(f"enrollment entered terminal state {state or 'unknown'}")
            remaining = deadline - time.time()
            if remaining > 0:
                time.sleep(min(poll_seconds, remaining))
        raise AdminError("enrollment expired before the player submitted a request")

    def pending_requests(self) -> list[dict[str, Any]]:
        """Read and validate the root-only, secret-free approval queue."""
        result = self.portal.request("pending")
        requests = result.get("requests")
        total = result.get("total")
        if not isinstance(requests, list) or not isinstance(total, int) or total < len(requests):
            raise AdminError("portal returned an invalid approval queue")
        validated = []
        for request in requests:
            if not isinstance(request, dict):
                raise AdminError("portal returned an invalid approval request")
            enrollment_id = request.get("id")
            fingerprint = request.get("spki_sha256")
            self.require_id(enrollment_id)
            if not re.fullmatch(r"[0-9a-f]{64}", fingerprint or ""):
                raise AdminError("portal returned an invalid pending CSR fingerprint")
            if request.get("comparison_code") != fingerprint[:4] + "-" + fingerprint[-4:]:
                raise AdminError("portal returned an invalid comparison code")
            if request.get("state") not in {None, "pending"}:
                raise AdminError("portal returned a non-pending approval request")
            validated.append(request)
        return validated

    def _import(self, enrollment_id: str, csr: bytes, expected_spki: str) -> dict[str, Any]:
        importer = getattr(self.engine, "import_portal_submission", None)
        if importer is None:
            raise AdminError(
                "engine integration missing: add import_portal_submission(store, enrollment_id, csr_pem, "
                "expected_spki, openssl); "
                "it must lock the store, require state 'created', validate the CSR against the assigned CN, "
                "reject SPKI replay, and atomically transition to 'csr-submitted' without accepting a token")
        return importer(self.store, enrollment_id, csr, expected_spki, self.openssl)

    def openvpn_config(self) -> str:
        if not SAFE_HOST_RE.fullmatch(self.remote):
            raise AdminError("invalid OpenVPN remote host")
        if not 1 <= self.port <= 65535 or self.proto not in {"udp", "udp4", "udp6", "tcp-client"}:
            raise AdminError("invalid OpenVPN connection parameters")
        return (
            "client\ndev tap\nproto " + self.proto + "\nremote " + self.remote + " " + str(self.port) +
            "\nresolv-retry infinite\nnobind\npersist-tun"
            "\nremote-cert-tls server\nverify-x509-name server name"
            "\ntls-version-min 1.2\nauth SHA256"
            "\ndata-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"
            "\nallow-compression no\nverb 3\n"
        )

    def companion_bundle(self, material: dict[str, Any]) -> dict[str, Any]:
        token = material.get("companion_token")
        if not isinstance(token, str):
            raise AdminError("engine omitted the sealed Companion token")
        try:
            config = self.companion.load_config(self.companion_config)
            registration = self.companion.ensure_player_registration(
                Path(config["players_file"]), material["player"], token
            )
            assets = {
                "companion_script_b64": base64.b64encode(
                    self.companion_script.read_bytes()
                ).decode("ascii"),
                "companion_launcher_b64": base64.b64encode(
                    self.companion_launcher.read_bytes()
                ).decode("ascii"),
                "offboarding_script_b64": base64.b64encode(
                    self.windows_leave_script.read_bytes()
                ).decode("ascii"),
            }
            if registration == "existing-different":
                return {"companion_provisioning": "preserved-existing", **assets}
            client_config = {
                "version": 1,
                "player": material["player"],
                "server_url": f"http://{config['bind_host']}:{config['port']}",
                "token": token,
            }
            return {
                "companion_provisioning": "included",
                "companion_config": self.engine.canonical_json(client_config),
                **assets,
            }
        except (OSError, UnicodeError, ValueError) as exc:
            raise AdminError("Companion provisioning failed before publication") from exc

    def approve(self, enrollment_id: str, expected_spki: str) -> dict[str, Any]:
        engine_public = self.engine.public_status(self.store, enrollment_id)
        engine_state = engine_public["state"]
        if engine_state == "approved":
            inspected = {"spki_sha256": engine_public["spki_sha256"]}
        else:
            inspected = self.inspect(enrollment_id)
        if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_spki or "") or not secrets.compare_digest(
                inspected["spki_sha256"].lower(), expected_spki.lower()):
            raise AdminError("the confirmed SPKI fingerprint does not match the pending CSR")
        if engine_state == "created":
            imported = self._import(enrollment_id, inspected["csr"].encode("ascii"), inspected["spki_sha256"])
            if imported.get("spki_sha256") != inspected["spki_sha256"]:
                raise AdminError("engine imported a different CSR fingerprint")
            engine_state = "csr-submitted"
        if engine_state == "csr-submitted":
            with self.pki_locked():
                self.engine.approve(self.store, enrollment_id, self.ca_cert, self.ca_key,
                                    self.tls_server_key, self.openssl, self.openvpn,
                                    pki_dir=self.pki_dir, easyrsa=self.easyrsa)
        elif engine_state != "approved":
            raise AdminError(f"enrollment cannot be published from engine state {engine_state}")
        material = self.engine.publication_bundle(self.store, enrollment_id)
        try:
            ca_pem = self.ca_cert.read_text(encoding="ascii")
        except (OSError, UnicodeError) as exc:
            raise AdminError("cannot read CA certificate") from exc
        companion = self.companion_bundle(material)
        client_material = dict(material)
        client_material.pop("companion_token", None)
        response = {**client_material, **companion, "ca_pem": ca_pem,
                    "openvpn_config": self.openvpn_config()}
        bundle_sha256 = hashlib.sha256(
            self.engine.canonical_json(material).encode("utf-8")
        ).hexdigest()
        published = self.portal.request("publish", id=enrollment_id, response=response,
                                        spki_sha256=inspected["spki_sha256"])
        self.engine.finalize_publication(self.store, enrollment_id, bundle_sha256)
        return {"id": enrollment_id, "state": published["state"], "player": material["player"],
                "credential_id": material["credential_id"], "serial": material["serial"],
                "kid": material["kid"], "spki_sha256": inspected["spki_sha256"]}

    def reject(self, enrollment_id: str, reason: str) -> dict[str, Any]:
        self.require_id(enrollment_id)
        self.portal.request("cancel", id=enrollment_id)
        return self.engine.terminal(self.store, enrollment_id, "rejected", reason)

    def _revoke_pki_name(self, pki_name: str, expected_serial: str | None = None) -> None:
        environment = os.environ.copy()
        environment.update({"LC_ALL": "C", "LANG": "C", "EASYRSA_BATCH": "1",
                            "EASYRSA_PKI": str(self.pki_dir), "EASYRSA_CRL_DAYS": "3650"})
        try:
            if expected_serial is not None:
                if not re.fullmatch(r"[0-9A-Fa-f]+", expected_serial):
                    raise AdminError("credential has an invalid X.509 serial")
                status = expected_serial.upper()
            else:
                issued = self.pki_dir / "issued" / f"{pki_name}.crt"
                status = subprocess.run(
                    [self.openssl, "x509", "-in", str(issued), "-serial", "-noout"],
                    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
                ).stdout.decode("ascii").strip().removeprefix("serial=")
            index = (self.pki_dir / "index.txt").read_text(encoding="ascii")
            if re.search(rf"^V\t[^\n]*\t{re.escape(status)}\t", index, re.MULTILINE):
                subprocess.run([self.easyrsa, "revoke", pki_name], check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
            elif not re.search(rf"^R\t[^\n]*\t{re.escape(status)}\t", index, re.MULTILINE):
                raise AdminError("credential serial is absent from the Easy-RSA index")
            subprocess.run([self.easyrsa, "gen-crl"], check=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, env=environment)
            crl = self.pki_dir / "crl.pem"
            next_update_raw = subprocess.run(
                [self.openssl, "crl", "-in", str(crl), "-noout", "-nextupdate"],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
            ).stdout.decode("ascii").strip()
            if openssl_next_update(next_update_raw) <= dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1):
                raise AdminError("generated CRL expires in less than one day")
            self.engine.atomic_write(self.deployed_crl, crl.read_bytes(), 0o644)
            subprocess.run(["systemctl", "restart", self.openvpn_service], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
            subprocess.run(["systemctl", "is-active", "--quiet", self.openvpn_service],
                           check=True, env=environment)
        except (OSError, UnicodeError, subprocess.CalledProcessError) as exc:
            raise AdminError("X.509 revocation or OpenVPN session cutoff failed; retry revoke") from exc

    def revoke(self, enrollment_id: str, reason: str) -> dict[str, Any]:
        self.require_id(enrollment_id)
        pending = self.engine.begin_revoke(self.store, enrollment_id, reason)
        with self.pki_locked():
            self._revoke_pki_name(pending["pki_name"], pending["serial"])
        return self.engine.finalize_revoke(self.store, enrollment_id)

    def confirm_connection(self, enrollment_id: str) -> dict[str, Any]:
        self.require_id(enrollment_id)
        expected = self.engine.public_status(self.store, enrollment_id).get("certificate_cn")
        read_succeeded = False
        last_error: OSError | UnicodeError | None = None
        for attempt in range(CONNECTION_STATUS_ATTEMPTS):
            try:
                lines = self.status_file.read_text(encoding="utf-8").splitlines()
                read_succeeded = True
            except (OSError, UnicodeError) as exc:
                last_error = exc
                lines = []
            connected = set()
            for line in lines:
                separator = "\t" if line.startswith("CLIENT_LIST\t") else ","
                fields = line.split(separator, 2)
                if len(fields) >= 2 and fields[0] == "CLIENT_LIST":
                    connected.add(fields[1])
            if expected in connected:
                return self.engine.confirm_connection(self.store, enrollment_id)
            if attempt + 1 < CONNECTION_STATUS_ATTEMPTS:
                time.sleep(CONNECTION_STATUS_DELAY)
        if not read_succeeded:
            raise AdminError("OpenVPN status file is unavailable") from last_error
        raise AdminError("the certificate is not currently connected")

    def status(self, enrollment_id: str) -> dict[str, Any]:
        self.require_id(enrollment_id)
        result = {"engine": self.engine.public_status(self.store, enrollment_id)}
        try:
            result["portal"] = self.portal.request("status", id=enrollment_id)
        except AdminError as exc:
            result["portal"] = {"available": False, "detail": str(exc)}
        return result

    def offboard(self, player: str, reason: str) -> dict[str, Any]:
        """Revoke every credential and remove the player's Companion access."""
        inventory = self.engine.player_enrollments(self.store, player)
        if not inventory:
            raise AdminError("unknown player or no enrollment history")
        revoked: list[str] = []
        rejected: list[str] = []
        already_terminal: list[str] = []
        for item in inventory:
            enrollment_id = item["id"]
            state = item["state"]
            if state in {"approved", "collected", "revoking"}:
                self.portal.request("cancel", id=enrollment_id)
                self.revoke(enrollment_id, reason)
                revoked.append(enrollment_id)
            elif state in {"created", "csr-submitted"}:
                self.portal.request("cancel", id=enrollment_id)
                self.engine.terminal(self.store, enrollment_id, "rejected", reason)
                rejected.append(enrollment_id)
            else:
                already_terminal.append(enrollment_id)
                self.portal.request("cancel", id=enrollment_id)
        try:
            config = self.companion.load_config(self.companion_config)
            companion_removed = self.companion.update_player_registration(
                Path(config["players_file"]), player, None
            )
        except (OSError, UnicodeError, ValueError) as exc:
            raise AdminError("credentials were revoked but Companion offboarding failed") from exc
        retirement = self.engine.retire_player(self.store, player)
        return {
            "player": player,
            "player_id": retirement.get("player_id"),
            "state": "offboarded",
            "revoked": revoked,
            "rejected": rejected,
            "already_terminal": already_terminal,
            "companion_removed": bool(companion_removed),
        }


def interactive_approval(admin: Administrator, enrollment_id: str,
                         pending: dict[str, Any] | None = None) -> str:
    """Show the complete request and return its SPKI after a simple yes/no decision."""
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise AdminError("interactive approval requires a terminal; otherwise use --spki-sha256")
    pending = pending or admin.inspect(enrollment_id)
    expires = dt.datetime.fromtimestamp(
        int(pending["expires_at"]), dt.timezone.utc
    ).isoformat().replace("+00:00", "Z")
    print("\nOPENVPN LAN PARTY - APPROVAL", file=sys.stderr)
    print(f"Player           : {pending['player']}", file=sys.stderr)
    print(f"Enrollment ID    : {pending['id']}", file=sys.stderr)
    print(f"Certificate CN   : {pending['certificate_cn']}", file=sys.stderr)
    print(f"Expires UTC      : {expires}", file=sys.stderr)
    print(f"CSR SPKI SHA-256 : {pending['spki_sha256']}", file=sys.stderr)
    print(f"Comparison code  : {pending['comparison_code']}", file=sys.stderr)
    print(
        "\nCheck the player name and, when possible, compare the short code with the player's screen.",
        file=sys.stderr,
    )
    confirmation = input("Approve and sign? [Y/N]: ").strip().lower()
    if confirmation not in {"y", "yes"}:
        admin.reject(enrollment_id, "administrator rejected request")
        raise AdminError("request rejected; nothing was signed")
    return pending["spki_sha256"]


def interactive_approval_pool(admin: Administrator, poll_seconds: float = 2.0) -> int:
    """Monitor and process all pending enrollments without copying identifiers."""
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise AdminError("the approval pool requires an interactive terminal")
    if poll_seconds < 0.25 or poll_seconds > 30:
        raise AdminError("approval pool polling interval must be between 0.25 and 30 seconds")
    seen: set[str] = set()
    waiting_displayed = False
    print(
        "\nOPENVPN LAN PARTY - APPROVAL POOL\n"
        "Ctrl+C or Q exits without cancelling invitations.",
        file=sys.stderr,
    )
    try:
        while True:
            requests = admin.pending_requests()
            identifiers = {request["id"] for request in requests}
            arrivals = identifiers - seen
            if arrivals:
                print("\a\nNew request(s) received.", file=sys.stderr)
            seen = identifiers
            if not requests:
                if not waiting_displayed:
                    print(
                        "Waiting for player requests...",
                        file=sys.stderr,
                        flush=True,
                    )
                    waiting_displayed = True
                time.sleep(poll_seconds)
                continue

            waiting_displayed = False
            print("\nPending requests:", file=sys.stderr)
            for index, request in enumerate(requests, 1):
                submitted = dt.datetime.fromtimestamp(
                    int(request.get("submitted_at", 0)), dt.timezone.utc
                ).isoformat().replace("+00:00", "Z")
                print(
                    f"  [{index}] {request['player']} | {request['comparison_code']} | "
                    f"{request['security_mode']} | {submitted}",
                    file=sys.stderr,
                )
            choice = input("Select a number, R to refresh, Q to quit: ").strip().lower()
            if choice in {"q", "quit"}:
                return 0
            if choice in {"r", "refresh", ""}:
                continue
            try:
                selected = requests[int(choice) - 1]
            except (ValueError, IndexError):
                print("Invalid selection.", file=sys.stderr)
                continue
            try:
                pending = admin.inspect(selected["id"])
                if not secrets.compare_digest(pending["spki_sha256"], selected["spki_sha256"]):
                    raise AdminError("approval queue fingerprint changed")
                expected_spki = interactive_approval(admin, selected["id"], pending)
                approved = admin.approve(selected["id"], expected_spki)
                print(
                    f"\nApproved: {approved['player']} ({approved['state']})",
                    file=sys.stderr,
                )
            except AdminError as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
    except KeyboardInterrupt:
        print(
            "\nApproval pool stopped; pending invitations remain valid.",
            file=sys.stderr,
        )
        return 0


def select_security_mode(requested: str | None, acknowledge_compatible: bool) -> str:
    """Choose one credential policy without allowing a silent weak fallback."""
    mode = requested
    interactive = sys.stdin.isatty() and sys.stderr.isatty()
    if mode is None and interactive:
        print(
            "\nChoose this invitation's security mode:\n"
            "  [1] high-assurance - Windows 11, TPM 2.0-backed key (recommended)\n"
            "  [2] compatible     - Windows 10 22H2/11, software-backed key",
            file=sys.stderr,
        )
        choice = input("Security mode [1]: ").strip().lower()
        if choice in {"", "1", "high-assurance"}:
            mode = "high-assurance"
        elif choice in {"2", "compatible"}:
            mode = "compatible"
        else:
            raise AdminError("invalid security mode selection")
    mode = mode or "high-assurance"
    if mode == "compatible" and not acknowledge_compatible:
        if not interactive:
            raise AdminError("compatible mode requires --ack-compatible-risk")
        print(
            "\nWARNING: compatible mode has no TPM hardware isolation. The administrator "
            "is responsible for admitting only a maintained and fully patched Windows endpoint.",
            file=sys.stderr,
        )
        if input("Create this compatible invitation? [Y/N]: ").strip().lower() not in {"y", "yes"}:
            raise AdminError("compatible invitation cancelled")
    return mode


def confirm_offboarding(admin: Administrator, player: str) -> None:
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise AdminError("non-interactive offboarding requires --yes")
    inventory = admin.engine.player_enrollments(admin.store, player)
    if not inventory:
        raise AdminError("unknown player or no enrollment history")
    print(f"\nOPENVPN LAN PARTY - OFFBOARD {player}", file=sys.stderr)
    for item in inventory:
        print(
            f"  {item['id']} | {item['state']} | {item.get('security_mode', 'unknown')} | "
            f"{item['certificate_cn']}",
            file=sys.stderr,
        )
    print(
        "\nThis revokes every active certificate, invalidates pending invitations, "
        "disconnects VPN sessions and removes Companion access. Audit records are retained.",
        file=sys.stderr,
    )
    if input("Offboard this player? [Y/N]: ").strip().lower() not in {"y", "yes"}:
        raise AdminError("offboarding cancelled; nothing was changed")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--engine", type=Path, default=Path("/usr/local/libexec/vpn-player-enrollment"))
    result.add_argument("--state-dir", type=Path, default=Path("/var/lib/openvpn-lan-party/enrollment"))
    result.add_argument("--verification-registry", type=Path,
                        default=Path("/var/lib/openvpn/credential-registry.json"))
    result.add_argument("--admin-socket", type=Path,
                        default=Path("/run/openvpn-lan-party/enrollment-portal-admin.sock"))
    result.add_argument("--public-url", default="https://10.44.0.1:8790")
    result.add_argument("--ca-cert", type=Path, default=Path("/root/openvpn-pki/ca.crt"))
    result.add_argument("--ca-key", type=Path, default=Path("/root/openvpn-pki/private/ca.key"))
    result.add_argument("--tls-server-key", type=Path, default=Path("/etc/openvpn/server/tls-crypt-v2-server.key"))
    result.add_argument("--portal-tls-cert", type=Path,
                        default=Path("/etc/openvpn-lan-party/tls.crt"))
    result.add_argument("--remote", required=True)
    result.add_argument("--port", type=int, default=1194)
    result.add_argument("--proto", default="udp")
    result.add_argument("--openssl", default=os.environ.get("VPN_OPENSSL_BIN", "openssl"))
    result.add_argument("--openvpn", default=os.environ.get("VPN_OPENVPN_BIN", "openvpn"))
    result.add_argument("--pki-dir", type=Path, default=Path("/root/openvpn-pki"))
    result.add_argument("--easyrsa", default="/usr/share/easy-rsa/easyrsa")
    result.add_argument("--deployed-crl", type=Path, default=Path("/etc/openvpn/server/crl.pem"))
    result.add_argument("--openvpn-service", default="openvpn-server@server.service")
    result.add_argument("--status-file", type=Path,
                        default=Path("/run/openvpn-server/status.log"))
    result.add_argument("--companion-engine", type=Path,
                        default=Path("/usr/local/libexec/lan-party-companion"))
    result.add_argument("--companion-config", type=Path,
                        default=Path("/etc/openvpn-lan-companion/config.json"))
    result.add_argument("--companion-script", type=Path,
                        default=Path("/usr/local/share/vpn-manager/windows/LAN-Party-Companion.ps1"))
    result.add_argument("--companion-launcher", type=Path,
                        default=Path("/usr/local/share/vpn-manager/windows/LAN-PARTY.cmd"))
    commands = result.add_subparsers(dest="command", required=True)
    create_p = commands.add_parser("create"); create_p.add_argument("--player", required=True); create_p.add_argument("--ttl", type=int, default=3600)
    create_p.add_argument("--security-mode", choices=("high-assurance", "compatible"))
    create_p.add_argument("--ack-compatible-risk", action="store_true",
                          help="confirm responsibility for a maintained compatible endpoint")
    create_p.add_argument("--email-to")
    create_p.add_argument("--sendmail", type=Path, default=Path("/usr/sbin/sendmail"))
    create_p.add_argument("--json", action="store_true", help="emit machine-readable JSON without waiting")
    create_p.add_argument("--no-wait", action="store_true",
                          help="return after creating the invitation instead of waiting for its CSR")
    for name in ("inspect", "status", "confirm-connection"):
        item = commands.add_parser(name); item.add_argument("id")
    approve_p = commands.add_parser("approve"); approve_p.add_argument("id")
    approve_p.add_argument("--spki-sha256")
    pool_p = commands.add_parser("pool", help="monitor and approve all pending player requests")
    pool_p.add_argument("--poll-seconds", type=float, default=2.0)
    for name in ("reject", "revoke"):
        item = commands.add_parser(name); item.add_argument("id"); item.add_argument("--reason", required=True)
    offboard_p = commands.add_parser("offboard", help="revoke all credentials and remove Companion access")
    offboard_p.add_argument("--player", required=True)
    offboard_p.add_argument("--reason", required=True)
    offboard_p.add_argument("--yes", action="store_true", help="confirm non-interactively")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        engine = load_engine(args.engine)
        try:
            verification_gid = grp.getgrnam("nogroup").gr_gid
        except KeyError as exc:
            raise AdminError("required OpenVPN group 'nogroup' does not exist") from exc
        store = engine.Store(args.state_dir, args.verification_registry, verification_gid)
        companion = load_engine(args.companion_engine)
        admin = Administrator(engine, store, PortalClient(args.admin_socket),
                              public_url=args.public_url, ca_cert=args.ca_cert, ca_key=args.ca_key,
                              tls_server_key=args.tls_server_key,
                              portal_tls_cert=args.portal_tls_cert,
                              remote=args.remote, port=args.port,
                              proto=args.proto, openssl=args.openssl, openvpn=args.openvpn,
                              pki_dir=args.pki_dir, easyrsa=args.easyrsa,
                              deployed_crl=args.deployed_crl,
                              openvpn_service=args.openvpn_service,
                              status_file=args.status_file, companion=companion,
                              companion_config=args.companion_config,
                              companion_script=args.companion_script,
                              companion_launcher=args.companion_launcher)
        if args.command == "create":
            if args.email_to and (not args.sendmail.is_file() or not os.access(args.sendmail, os.X_OK)):
                raise AdminError(f"sendmail-compatible executable is unavailable: {args.sendmail}")
            security_mode = select_security_mode(
                args.security_mode, args.ack_compatible_risk
            )
            output = admin.create(args.player, args.ttl, security_mode)
            if args.email_to:
                try:
                    send_invitation_email(output, args.email_to, args.sendmail)
                    output["email_sent_to"] = args.email_to
                except AdminError as exc:
                    output["email_error"] = str(exc)
        elif args.command == "inspect": output = admin.inspect(args.id)
        elif args.command == "pool":
            return interactive_approval_pool(admin, args.poll_seconds)
        elif args.command == "approve":
            expected_spki = args.spki_sha256
            if expected_spki is None:
                expected_spki = interactive_approval(admin, args.id)
            output = admin.approve(args.id, expected_spki)
        elif args.command == "reject": output = admin.reject(args.id, args.reason)
        elif args.command == "revoke": output = admin.revoke(args.id, args.reason)
        elif args.command == "offboard":
            if not args.yes:
                confirm_offboarding(admin, args.player)
            output = admin.offboard(args.player, args.reason)
        elif args.command == "confirm-connection": output = admin.confirm_connection(args.id)
        else: output = admin.status(args.id)
    except (AdminError, OSError, UnicodeError, ValueError, getattr(locals().get("engine", object), "EnrollmentError", RuntimeError)) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if args.command == "create" and not args.json:
        print("\nOPENVPN LAN PARTY - WINDOWS INVITATION")
        print(f"Player                : {output['player']}")
        print(f"Security mode         : {output['security_mode']}")
        print(f"Expires               : {output['expires_at']}")
        print(f"Enrollment ID         : {output['id']}")
        print(f"Download URL          : {output['download_url']}")
        print(f"Archive password      : {output['archive_password']}")
        print(f"One-time token        : {output['token']}")
        print(f"Archive SHA-256       : {output['archive_sha256']}")
        if output.get("email_sent_to"):
            print(f"Link-only email sent  : {output['email_sent_to']}")
        if output.get("email_error"):
            print(f"EMAIL ERROR            : {output['email_error']}")
        print("\nSend the download link by email if desired.")
        print("Transmit the archive password and one-time token separately over a trusted channel.")
        if not args.no_wait and sys.stdin.isatty() and sys.stderr.isatty():
            print(
                "\nWaiting for the player's request; Ctrl+C stops monitoring only.",
                flush=True,
            )
            try:
                pending = admin.wait_for_request(output["id"], output["expires_at"])
                print("\a\nRequest received.", flush=True)
                expected_spki = interactive_approval(admin, output["id"], pending)
                approved = admin.approve(output["id"], expected_spki)
                print(
                    f"\nApproved: {approved['player']} "
                    f"({approved['state']})"
                )
            except KeyboardInterrupt:
                print(
                    "\nMonitoring stopped; the invitation remains valid.",
                    file=sys.stderr,
                )
                return 0
            except (AdminError, OSError, UnicodeError, ValueError) as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return 1
        elif not args.no_wait and not args.json:
            print(
                "\nNo interactive terminal detected; monitoring was not started."
            )
    else:
        print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
