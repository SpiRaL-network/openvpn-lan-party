#!/usr/bin/env python3
"""OpenVPN LAN Party player enrolment state machine.

The client private key never reaches this program.  Persistent state contains
only a SHA-256 token digest and public enrolment material.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import uuid
from typing import Any, Callable


SCHEMA = 1
STATES = {"created", "csr-submitted", "approved", "collected", "rejected", "revoking", "revoked"}
PLAYER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z")
HEX_RE = re.compile(r"[0-9a-f]{64}\Z")
KID_RE = re.compile(r"[A-Za-z0-9_-]{22}\Z")
SECURITY_MODES = {"high-assurance", "compatible"}


class EnrollmentError(RuntimeError):
    pass


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def stamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_stamp(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


class Store:
    def __init__(self, root: Path, verification_registry: Path | None = None,
                 verification_gid: int | None = None):
        self.root = root
        self.items = root / "enrollments"
        self.lock_path = root / ".lock"
        self.registry_path = root / "credential-registry.json"
        self.verification_registry = verification_registry
        self.verification_gid = verification_gid

    def prepare(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.items.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.items, 0o700)

    @contextlib.contextmanager
    def locked(self):
        self.prepare()
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def path(self, enrollment_id: str) -> Path:
        if not HEX_RE.fullmatch(enrollment_id):
            raise EnrollmentError("invalid enrolment identifier")
        return self.items / f"{enrollment_id}.json"

    def load(self, enrollment_id: str) -> dict[str, Any]:
        try:
            state = json.loads(self.path(enrollment_id).read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise EnrollmentError("unknown enrolment") from exc
        if state.get("schema") != SCHEMA or state.get("state") not in STATES:
            raise EnrollmentError("invalid enrolment state")
        return state

    def save(self, state: dict[str, Any]) -> None:
        data = (json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n").encode()
        atomic_write(self.path(state["id"]), data, 0o600)

    def registry(self) -> dict[str, Any]:
        try:
            value = json.loads(self.registry_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            value = {"schema": SCHEMA, "players": {}, "credentials": {}}
        value.setdefault("players", {})
        if (value.get("schema") != SCHEMA
                or not isinstance(value.get("players"), dict)
                or not isinstance(value.get("credentials"), dict)):
            raise EnrollmentError("invalid credential registry")
        return value

    def save_registry(self, registry: dict[str, Any]) -> None:
        atomic_write(self.registry_path, (canonical_json(registry) + "\n").encode(), 0o600)
        if self.verification_registry is not None:
            public = {
                "schema": SCHEMA,
                "credentials": {
                    kid: {
                        "serial": value.get("serial"),
                        "credential_id": value.get("credential_id"),
                        "state": value.get("state"),
                    }
                    for kid, value in registry["credentials"].items()
                },
            }
            atomic_write(
                self.verification_registry,
                (canonical_json(public) + "\n").encode(),
                0o640,
            )
            if self.verification_gid is not None and os.geteuid() == 0:
                os.chown(self.verification_registry, 0, self.verification_gid)


def require_state(state: dict[str, Any], expected: str) -> None:
    if state["state"] != expected:
        raise EnrollmentError(f"expected state {expected}, found {state['state']}")
    if parse_stamp(state["expires_at"]) <= utcnow():
        raise EnrollmentError("enrolment expired")


def require_token(state: dict[str, Any], token: str) -> None:
    if not secrets.compare_digest(state["token_sha256"], digest(token)):
        raise EnrollmentError("invalid enrolment token")


def run(command: list[str], *, input_data: bytes | None = None) -> bytes:
    try:
        environment = os.environ.copy()
        environment.update({"LC_ALL": "C", "LANG": "C"})
        result = subprocess.run(command, input=input_data, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=True, env=environment)
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", b"").decode("utf-8", "replace").strip()
        raise EnrollmentError(f"command failed: {command[0]}{': ' + detail if detail else ''}") from exc
    return result.stdout


def openssl_text(openssl: str, csr: Path, *arguments: str) -> str:
    return run([openssl, "req", "-in", str(csr), *arguments]).decode("utf-8", "strict")


def validate_csr(csr_pem: bytes, expected_cn: str, openssl: str = "openssl") -> str:
    if len(csr_pem) > 64 * 1024 or b"BEGIN CERTIFICATE REQUEST" not in csr_pem:
        raise EnrollmentError("invalid PKCS#10 encoding")
    with tempfile.TemporaryDirectory() as directory:
        csr = Path(directory) / "request.pem"
        csr.write_bytes(csr_pem)
        openssl_text(openssl, csr, "-verify", "-noout")
        subject = openssl_text(openssl, csr, "-subject", "-nameopt", "RFC2253", "-noout").strip()
        if subject != f"subject=CN={expected_cn}":
            raise EnrollmentError("CSR subject must contain only the assigned common name")
        request_text = openssl_text(openssl, csr, "-text", "-noout")
        if not re.search(r"Public Key Algorithm:\s+(?:id-ecPublicKey|X9\.62 id-ecPublicKey)", request_text):
            raise EnrollmentError("CSR key is not EC")
        if not re.search(r"ASN1 OID:\s+(?:prime256v1|secp256r1)", request_text):
            raise EnrollmentError("CSR key is not ECDSA P-256")
        extension = re.search(r"Requested Extensions:\s*(.*?)(?:\n\s*Signature Algorithm:)",
                              request_text, re.S)
        if extension and extension.group(1).strip() not in {"", "<EMPTY>"}:
            raise EnrollmentError("CSR requested extensions are forbidden")
        public_key = run([openssl, "req", "-in", str(csr), "-pubkey", "-noout"])
        der = run([openssl, "pkey", "-pubin", "-outform", "DER"], input_data=public_key)
    return hashlib.sha256(der).hexdigest()


def validate_certificate(certificate: Path, ca_cert: Path, expected_cn: str,
                         openssl: str, runner: Callable[..., bytes]) -> None:
    runner([openssl, "verify", "-purpose", "sslclient", "-CAfile", str(ca_cert), str(certificate)])
    subject = runner([openssl, "x509", "-in", str(certificate), "-subject", "-nameopt",
                      "RFC2253", "-noout"]).decode("utf-8", "strict").strip()
    if subject != f"subject=CN={expected_cn}":
        raise EnrollmentError("issued certificate subject violates policy")
    text = runner([openssl, "x509", "-in", str(certificate), "-text", "-noout"]).decode("utf-8", "strict")
    if not re.search(r"Basic Constraints: critical\s*\n\s*CA:FALSE", text):
        raise EnrollmentError("issued certificate is not explicitly CA:FALSE")
    key_usage = re.search(r"Key Usage: critical\s*\n\s*([^\n]+)", text)
    if not key_usage or key_usage.group(1).strip() != "Digital Signature":
        raise EnrollmentError("issued certificate has invalid key usage")
    extended = re.search(r"Extended Key Usage:\s*\n\s*([^\n]+)", text)
    if not extended or extended.group(1).strip() != "TLS Web Client Authentication":
        raise EnrollmentError("issued certificate has invalid extended key usage")


def metadata_value(kid: str, serial: str, issued_at: int) -> str:
    value = {"v": 1, "kid": kid, "serial": serial, "iat": issued_at}
    return canonical_json(value)


def load_verification_registry(path: Path) -> dict[str, Any]:
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise EnrollmentError("verification registry permissions are unsafe")
        value = json.loads(path.read_text(encoding="utf-8"))
    except EnrollmentError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EnrollmentError("verification registry is unavailable") from exc
    if value.get("schema") != SCHEMA or not isinstance(value.get("credentials"), dict):
        raise EnrollmentError("invalid verification registry")
    return value


def verify_metadata_file(store: Store, metadata_path: Path, metadata_type: str,
                         verification_registry: Path | None = None) -> dict[str, str]:
    if metadata_type != "0":
        raise EnrollmentError("unsupported OpenVPN metadata type")
    try:
        fd = os.open(metadata_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 256:
                raise EnrollmentError("metadata must be a regular non-symlink file of at most 256 bytes")
            raw = os.read(fd, 257)
        finally:
            os.close(fd)
        if len(raw) > 256 or b"\x00" in raw:
            raise ValueError
        text = raw.decode("utf-8")
        value = json.loads(text)
    except EnrollmentError:
        raise
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise EnrollmentError("invalid metadata JSON") from exc
    if not isinstance(value, dict) or set(value) != {"v", "kid", "serial", "iat"}:
        raise EnrollmentError("metadata schema mismatch")
    if canonical_json(value) != text:
        raise EnrollmentError("metadata is not canonical JSON")
    if value["v"] != 1 or not isinstance(value["iat"], int) or isinstance(value["iat"], bool):
        raise EnrollmentError("invalid metadata version or issuance time")
    if not isinstance(value["kid"], str) or not KID_RE.fullmatch(value["kid"]):
        raise EnrollmentError("invalid metadata key identifier")
    if not isinstance(value["serial"], str) or not re.fullmatch(r"[0-9A-F]+", value["serial"]):
        raise EnrollmentError("invalid metadata serial")
    if verification_registry is None:
        with store.locked():
            credential = store.registry()["credentials"].get(value["kid"])
    else:
        credential = load_verification_registry(verification_registry)["credentials"].get(value["kid"])
    if not credential or credential.get("state") != "active" or credential.get("serial") != value["serial"]:
        raise EnrollmentError("unknown, mismatched or inactive credential")
    return {"state": "active", "credential_id": credential["credential_id"]}


def create(store: Store, player: str, ttl: int, security_mode: str = "high-assurance") -> dict[str, str]:
    if not PLAYER_RE.fullmatch(player):
        raise EnrollmentError("player name must use 1-32 ASCII letters, digits, _ or -")
    if ttl < 60 or ttl > 86400:
        raise EnrollmentError("TTL must be between 60 and 86400 seconds")
    if security_mode not in SECURITY_MODES:
        raise EnrollmentError("invalid credential security mode")
    token = secrets.token_urlsafe(32)
    enrollment_id = secrets.token_hex(32)
    credential_id = str(uuid.uuid4())
    now = utcnow()
    with store.locked():
        registry = store.registry()
        for path in store.items.glob("*.json"):
            existing = json.loads(path.read_text(encoding="utf-8"))
            if (existing.get("player") == player
                    and existing.get("state") not in {"rejected", "revoked"}
                    and existing.get("security_mode") != security_mode):
                raise EnrollmentError(
                    "the player has a credential or invitation in another security mode; "
                    "reject or revoke it before creating a replacement"
                )
        player_id = registry["players"].get(player)
        if player_id is None:
            player_id = str(uuid.uuid4())
            registry["players"][player] = player_id
            store.save_registry(registry)
        certificate_cn = f"vpn-player:{credential_id}"
        state = {"schema": SCHEMA, "id": enrollment_id, "player": player, "player_id": player_id,
                 "credential_id": credential_id, "certificate_cn": certificate_cn, "state": "created",
                 "created_at": stamp(now), "expires_at": stamp(now + dt.timedelta(seconds=ttl)),
                 "security_mode": security_mode, "token_sha256": digest(token),
                 "events": [{"at": stamp(now), "state": "created"}]}
        store.save(state)
    return {"id": enrollment_id, "token": token, "expires_at": state["expires_at"],
            "player": player, "player_id": player_id, "credential_id": credential_id,
            "certificate_cn": certificate_cn, "security_mode": security_mode}


def submit(store: Store, enrollment_id: str, token: str, csr_pem: bytes, openssl: str) -> dict[str, str]:
    with store.locked():
        state = store.load(enrollment_id)
        require_state(state, "created")
        require_token(state, token)
        fingerprint = validate_csr(csr_pem, state["certificate_cn"], openssl)
        for path in store.items.glob("*.json"):
            other = json.loads(path.read_text(encoding="utf-8"))
            if other.get("spki_sha256") == fingerprint and other.get("state") not in {"rejected", "revoked"}:
                raise EnrollmentError("public key has already been submitted")
        state.update(state="csr-submitted", csr_pem=csr_pem.decode("ascii"), spki_sha256=fingerprint)
        state["events"].append({"at": stamp(utcnow()), "state": "csr-submitted"})
        store.save(state)
    return {"id": enrollment_id, "state": "csr-submitted", "spki_sha256": fingerprint,
            "comparison_code": fingerprint[:4] + "-" + fingerprint[-4:]}


def import_portal_submission(store: Store, enrollment_id: str, csr_pem: bytes,
                             expected_spki: str, openssl: str) -> dict[str, str]:
    """Import the immutable CSR inspected by root through the broker socket.

    This privileged transition deliberately does not accept the public bearer
    token.  The unprivileged portal already consumed that token when accepting
    the CSR; root binds the exact inspected bytes to the independently
    recomputed SPKI fingerprint before the CA boundary is crossed.
    """
    if not HEX_RE.fullmatch(expected_spki):
        raise EnrollmentError("invalid broker SPKI fingerprint")
    with store.locked():
        state = store.load(enrollment_id)
        require_state(state, "created")
        fingerprint = validate_csr(csr_pem, state["certificate_cn"], openssl)
        if not secrets.compare_digest(fingerprint, expected_spki):
            raise EnrollmentError("broker CSR fingerprint mismatch")
        for path in store.items.glob("*.json"):
            other = json.loads(path.read_text(encoding="utf-8"))
            if other.get("spki_sha256") == fingerprint and other.get("state") not in {"rejected", "revoked"}:
                raise EnrollmentError("public key has already been submitted")
        state.update(state="csr-submitted", csr_pem=csr_pem.decode("ascii"),
                     spki_sha256=fingerprint, imported_from="enrollment-portal")
        state["events"].append({"at": stamp(utcnow()), "state": "csr-submitted",
                                "source": "enrollment-portal"})
        store.save(state)
    return {"id": enrollment_id, "state": "csr-submitted", "spki_sha256": fingerprint,
            "comparison_code": fingerprint[:4] + "-" + fingerprint[-4:]}


def approve(store: Store, enrollment_id: str, ca_cert: Path, ca_key: Path,
            tls_server_key: Path, openssl: str, openvpn: str,
            runner: Callable[..., bytes] = run, pki_dir: Path | None = None,
            easyrsa: str | None = None) -> dict[str, str]:
    with store.locked():
        state = store.load(enrollment_id)
        require_state(state, "csr-submitted")
        # Revalidate at the privileged boundary, immediately before signing.
        if validate_csr(state["csr_pem"].encode("ascii"), state["certificate_cn"], openssl) != state["spki_sha256"]:
            raise EnrollmentError("CSR fingerprint changed")
        kid = base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csr, cert, extensions, tls_key = (root / name for name in ("request.pem", "cert.pem", "extensions.cnf", "tls.key"))
            csr.write_text(state["csr_pem"], encoding="ascii")
            if pki_dir is not None and easyrsa is not None:
                name = state["credential_id"]
                request_path = pki_dir / "reqs" / f"{name}.req"
                issued_path = pki_dir / "issued" / f"{name}.crt"
                environment = ["env", "EASYRSA_BATCH=1", f"EASYRSA_PKI={pki_dir}", "EASYRSA_CERT_EXPIRE=365"]
                if not request_path.exists() and not issued_path.exists():
                    runner(environment + [easyrsa, "import-req", str(csr), name])
                if not issued_path.exists():
                    runner(environment + [easyrsa, "sign-req", "vpn-player", name])
                cert.write_bytes(issued_path.read_bytes())
            else:
                serial = secrets.randbits(159) | (1 << 158)
                extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n", encoding="ascii")
                runner([openssl, "x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
                        "-set_serial", str(serial), "-days", "365", "-sha256", "-extfile", str(extensions), "-out", str(cert)])
            validate_certificate(cert, ca_cert, state["certificate_cn"], openssl, runner)
            serial_hex = runner([openssl, "x509", "-in", str(cert), "-serial", "-noout"]).decode("ascii").strip()
            if not re.fullmatch(r"serial=[0-9A-F]+", serial_hex):
                raise EnrollmentError("issued certificate has invalid serial")
            serial_hex = serial_hex.removeprefix("serial=")
            metadata = metadata_value(kid, serial_hex, int(utcnow().timestamp()))
            metadata_b64 = base64.b64encode(metadata.encode("utf-8")).decode("ascii")
            runner([openvpn, "--tls-crypt-v2", str(tls_server_key), "--genkey", "tls-crypt-v2-client", str(tls_key),
                    metadata_b64])
            certificate = cert.read_text(encoding="ascii")
            tls_material = tls_key.read_text(encoding="ascii")
        collect_token = secrets.token_urlsafe(32)
        state.update(state="approved", serial=serial_hex, kid=kid, certificate_pem=certificate,
                     pki_name=state["credential_id"] if pki_dir is not None else None,
                     tls_crypt_v2=tls_material, tls_metadata=metadata,
                     companion_token=secrets.token_urlsafe(32),
                     token_sha256=digest(collect_token), approved_at=stamp(utcnow()))
        state["events"].append({"at": stamp(utcnow()), "state": "approved"})
        store.save(state)
    return {"id": enrollment_id, "state": "approved", "collect_token": collect_token,
            "serial": state["serial"], "kid": state["kid"]}


def collect(store: Store, enrollment_id: str, token: str) -> dict[str, str]:
    with store.locked():
        state = store.load(enrollment_id)
        require_state(state, "approved")
        require_token(state, token)
        response = {"player": state["player"], "certificate_pem": state["certificate_pem"],
                    "player_id": state["player_id"], "credential_id": state["credential_id"],
                    "certificate_cn": state["certificate_cn"], "tls_crypt_v2": state["tls_crypt_v2"],
                    "serial": state["serial"], "kid": state["kid"],
                    "security_mode": state["security_mode"]}
        registry = store.registry()
        registry["credentials"][state["kid"]] = {
            "kid": state["kid"], "serial": state["serial"],
            "credential_id": state["credential_id"], "player_id": state["player_id"],
            "state": "active", "activated_at": stamp(utcnow())}
        store.save_registry(registry)
        state["state"] = "collected"
        state["token_sha256"] = digest(secrets.token_urlsafe(32))
        state.pop("certificate_pem", None)
        state.pop("tls_crypt_v2", None)
        state.pop("companion_token", None)
        state["events"].append({"at": stamp(utcnow()), "state": "collected"})
        store.save(state)
    return response


def publication_bundle(store: Store, enrollment_id: str) -> dict[str, str]:
    """Return an approved bundle to root without consuming it.

    The bundle remains sealed in the root-owned store until the broker has
    acknowledged an idempotent publication and finalize_publication() commits
    activation. This makes interruption recovery deterministic.
    """
    with store.locked():
        state = store.load(enrollment_id)
        require_state(state, "approved")
        return {
            "player": state["player"], "certificate_pem": state["certificate_pem"],
            "player_id": state["player_id"], "credential_id": state["credential_id"],
            "certificate_cn": state["certificate_cn"],
            "tls_crypt_v2": state["tls_crypt_v2"], "serial": state["serial"],
            "kid": state["kid"], "security_mode": state["security_mode"],
            "companion_token": state["companion_token"],
        }


def finalize_publication(store: Store, enrollment_id: str,
                         expected_bundle_sha256: str) -> dict[str, str]:
    if not HEX_RE.fullmatch(expected_bundle_sha256):
        raise EnrollmentError("invalid publication bundle digest")
    with store.locked():
        state = store.load(enrollment_id)
        require_state(state, "approved")
        bundle = {
            "player": state["player"], "certificate_pem": state["certificate_pem"],
            "player_id": state["player_id"], "credential_id": state["credential_id"],
            "certificate_cn": state["certificate_cn"],
            "tls_crypt_v2": state["tls_crypt_v2"], "serial": state["serial"],
            "kid": state["kid"], "security_mode": state["security_mode"],
            "companion_token": state["companion_token"],
        }
        actual = hashlib.sha256(canonical_json(bundle).encode()).hexdigest()
        if not secrets.compare_digest(actual, expected_bundle_sha256):
            raise EnrollmentError("publication bundle digest mismatch")
        registry = store.registry()
        registry["credentials"][state["kid"]] = {
            "kid": state["kid"], "serial": state["serial"],
            "credential_id": state["credential_id"], "player_id": state["player_id"],
            "state": "active", "activated_at": stamp(utcnow())}
        store.save_registry(registry)
        state["state"] = "collected"
        state["token_sha256"] = digest(secrets.token_urlsafe(32))
        state["published_bundle_sha256"] = actual
        state.pop("certificate_pem", None)
        state.pop("tls_crypt_v2", None)
        state.pop("companion_token", None)
        state["events"].append({"at": stamp(utcnow()), "state": "collected",
                                "source": "portal-publication-ack"})
        store.save(state)
    return {"id": enrollment_id, "state": "collected", "kid": state["kid"]}


def terminal(store: Store, enrollment_id: str, target: str, reason: str) -> dict[str, str]:
    if target not in {"rejected", "revoked"} or not reason.strip() or len(reason) > 500:
        raise EnrollmentError("a concise reason is required")
    with store.locked():
        state = store.load(enrollment_id)
        allowed = {"rejected": {"created", "csr-submitted"}, "revoked": {"approved", "collected"}}
        if state["state"] not in allowed[target]:
            raise EnrollmentError(f"cannot mark {state['state']} as {target}")
        state.update(state=target, token_sha256=digest(secrets.token_urlsafe(32)))
        if target == "revoked" and "kid" in state:
            registry = store.registry()
            credential = registry["credentials"].get(state["kid"])
            if credential:
                credential["state"] = "revoked"
                credential["revoked_at"] = stamp(utcnow())
                store.save_registry(registry)
        state.pop("certificate_pem", None)
        state.pop("tls_crypt_v2", None)
        state.pop("companion_token", None)
        state["events"].append({"at": stamp(utcnow()), "state": target, "reason": reason.strip()})
        store.save(state)
    return {"id": enrollment_id, "state": target}


def begin_revoke(store: Store, enrollment_id: str, reason: str) -> dict[str, str]:
    if not reason.strip() or len(reason) > 500:
        raise EnrollmentError("a concise reason is required")
    with store.locked():
        state = store.load(enrollment_id)
        if state["state"] == "revoking":
            return {"id": enrollment_id, "state": "revoking", "pki_name": state["pki_name"],
                    "serial": state["serial"]}
        if state["state"] not in {"approved", "collected"} or not state.get("pki_name"):
            raise EnrollmentError("credential is not backed by the revocable PKI")
        state["state"] = "revoking"
        state["revocation_reason"] = reason.strip()
        registry = store.registry()
        credential = registry["credentials"].get(state["kid"])
        if credential:
            credential.update(state="revoking", revoking_at=stamp(utcnow()))
            store.save_registry(registry)
        state["events"].append({"at": stamp(utcnow()), "state": "revoking", "reason": reason.strip()})
        store.save(state)
    return {"id": enrollment_id, "state": "revoking", "pki_name": state["pki_name"],
            "serial": state["serial"]}


def finalize_revoke(store: Store, enrollment_id: str) -> dict[str, str]:
    with store.locked():
        state = store.load(enrollment_id)
        if state["state"] != "revoking":
            raise EnrollmentError(f"expected state revoking, found {state['state']}")
        registry = store.registry()
        credential = registry["credentials"].get(state["kid"])
        if credential:
            credential.update(state="revoked", revoked_at=stamp(utcnow()))
            store.save_registry(registry)
        state.update(state="revoked", token_sha256=digest(secrets.token_urlsafe(32)))
        state.pop("certificate_pem", None)
        state.pop("tls_crypt_v2", None)
        state.pop("companion_token", None)
        state["events"].append({"at": stamp(utcnow()), "state": "revoked"})
        store.save(state)
    return {"id": enrollment_id, "state": "revoked"}


def confirm_connection(store: Store, enrollment_id: str) -> dict[str, str]:
    with store.locked():
        state = store.load(enrollment_id)
        if state["state"] != "collected":
            raise EnrollmentError("only an active collected credential can be confirmed")
        state["connection_confirmed_at"] = stamp(utcnow())
        state["events"].append({"at": state["connection_confirmed_at"],
                                "state": "connection-confirmed"})
        store.save(state)
    return {"id": enrollment_id, "state": "collected",
            "certificate_cn": state["certificate_cn"],
            "connection_confirmed_at": state["connection_confirmed_at"]}


def public_status(store: Store, enrollment_id: str) -> dict[str, Any]:
    with store.locked():
        state = store.load(enrollment_id)
    return {key: state[key] for key in ("id", "player", "player_id", "credential_id", "certificate_cn",
                                        "security_mode", "state", "created_at", "expires_at",
                                        "spki_sha256", "serial", "kid")
            if key in state}


def player_enrollments(store: Store, player: str) -> list[dict[str, Any]]:
    """Return the root-only credential inventory for one exact player name."""
    if not PLAYER_RE.fullmatch(player):
        raise EnrollmentError("invalid player name")
    with store.locked():
        result = []
        for path in store.items.glob("*.json"):
            state = json.loads(path.read_text(encoding="utf-8"))
            if state.get("schema") != SCHEMA or state.get("state") not in STATES:
                raise EnrollmentError("invalid enrolment state")
            if state.get("player") == player:
                result.append({key: state[key] for key in (
                    "id", "player", "player_id", "credential_id", "certificate_cn",
                    "security_mode", "state", "created_at", "expires_at", "serial", "kid"
                ) if key in state})
    return sorted(result, key=lambda value: (value.get("created_at", ""), value["id"]))


def retire_player(store: Store, player: str) -> dict[str, Any]:
    """Forget the stable player mapping only after every credential is terminal."""
    if not PLAYER_RE.fullmatch(player):
        raise EnrollmentError("invalid player name")
    with store.locked():
        for path in store.items.glob("*.json"):
            state = json.loads(path.read_text(encoding="utf-8"))
            if state.get("player") == player and state.get("state") not in {"rejected", "revoked"}:
                raise EnrollmentError("player still has a non-terminal credential or invitation")
        registry = store.registry()
        player_id = registry["players"].pop(player, None)
        store.save_registry(registry)
    return {"player": player, "player_id": player_id, "retired": player_id is not None}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--state-dir", type=Path, default=Path("/var/lib/openvpn-lan-party/enrollment"))
    result.add_argument("--openssl", default=os.environ.get("VPN_OPENSSL_BIN", "openssl"))
    result.add_argument("--openvpn", default=os.environ.get("VPN_OPENVPN_BIN", "openvpn"))
    result.add_argument("--verification-registry", type=Path)
    result.add_argument("--verification-gid", type=int)
    commands = result.add_subparsers(dest="command", required=True)
    create_p = commands.add_parser("create"); create_p.add_argument("player"); create_p.add_argument("--ttl", type=int, default=900)
    submit_p = commands.add_parser("submit"); submit_p.add_argument("id"); submit_p.add_argument("token"); submit_p.add_argument("csr", type=Path)
    import_p = commands.add_parser("import-portal-submission"); import_p.add_argument("id")
    import_p.add_argument("csr", type=Path); import_p.add_argument("--spki-sha256", required=True)
    approve_p = commands.add_parser("approve"); approve_p.add_argument("id"); approve_p.add_argument("--ca-cert", type=Path, required=True); approve_p.add_argument("--ca-key", type=Path, required=True); approve_p.add_argument("--tls-server-key", type=Path, required=True)
    collect_p = commands.add_parser("collect"); collect_p.add_argument("id"); collect_p.add_argument("token")
    for name in ("reject", "revoke"):
        item = commands.add_parser(name); item.add_argument("id"); item.add_argument("--reason", required=True)
    status_p = commands.add_parser("status"); status_p.add_argument("id")
    verify_p = commands.add_parser("verify-metadata")
    verify_p.add_argument("--metadata-file", type=Path)
    verify_p.add_argument("--metadata-type")
    return result


def main() -> int:
    args = parser().parse_args()
    store = Store(args.state_dir, args.verification_registry, args.verification_gid)
    try:
        if args.command == "create": output = create(store, args.player, args.ttl)
        elif args.command == "submit": output = submit(store, args.id, args.token, args.csr.read_bytes(), args.openssl)
        elif args.command == "import-portal-submission": output = import_portal_submission(
            store, args.id, args.csr.read_bytes(), args.spki_sha256, args.openssl)
        elif args.command == "approve": output = approve(store, args.id, args.ca_cert, args.ca_key, args.tls_server_key, args.openssl, args.openvpn)
        elif args.command == "collect": output = collect(store, args.id, args.token)
        elif args.command == "reject": output = terminal(store, args.id, "rejected", args.reason)
        elif args.command == "revoke": output = terminal(store, args.id, "revoked", args.reason)
        elif args.command == "status": output = public_status(store, args.id)
        else:
            metadata_file = args.metadata_file or (Path(os.environ["metadata_file"])
                                                    if os.environ.get("metadata_file") else None)
            metadata_type = args.metadata_type if args.metadata_type is not None else os.environ.get("metadata_type", "")
            if metadata_file is None:
                raise EnrollmentError("OpenVPN metadata_file is required")
            output = verify_metadata_file(
                store, metadata_file, metadata_type, args.verification_registry
            )
    except (EnrollmentError, OSError, UnicodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr); return 1
    print(json.dumps(output, sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
