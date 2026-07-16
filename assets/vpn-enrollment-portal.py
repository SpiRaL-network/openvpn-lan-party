#!/usr/bin/env python3
"""Unprivileged HTTPS broker for OpenVPN LAN Party enrolment.

The HTTP process owns only a public spool. A root administrator exchanges
public CSRs and signed response bundles over the broker-owned Unix socket; this
process never receives a CA path, CA key, or permission to execute a signer.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socketserver
import ssl
import stat
import tempfile
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit


ID_RE = re.compile(r"[0-9a-f]{64}\Z")
MAX_JSON = 70 * 1024
MAX_CSR = 64 * 1024
MAX_ADMIN = 256 * 1024
MAX_BUNDLE = 170 * 1024
BUNDLE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\.zip\Z")


class PortalError(RuntimeError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message); self.status = status


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".portal-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(canonical(value)); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError): os.unlink(temporary)


def atomic_blob(path: Path, value: bytes) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".bundle-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(value); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError): os.unlink(temporary)


class PublicStore:
    """Broker-owned state containing no private key or CA material."""
    def __init__(self, root: Path, validator_path: Path):
        self.root = root; self.validator_path = validator_path; self.lock = threading.RLock()
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True); os.chmod(self.root, 0o700)
        spec = importlib.util.spec_from_file_location("vpn_enrollment_csr", validator_path)
        if not spec or not spec.loader: raise RuntimeError("cannot load enrolment validation engine")
        self.validator = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.validator)

    def _path(self, enrollment_id: str) -> Path:
        if not ID_RE.fullmatch(enrollment_id): raise PortalError("invalid enrollment_id")
        return self.root / f"{enrollment_id}.json"

    def _bundle_path(self, enrollment_id: str) -> Path:
        if not ID_RE.fullmatch(enrollment_id): raise PortalError("invalid enrollment_id")
        return self.root / f"{enrollment_id}.zip"

    def _load(self, enrollment_id: str) -> dict[str, Any]:
        try: value = json.loads(self._path(enrollment_id).read_text("utf-8"))
        except FileNotFoundError as exc: raise PortalError("unknown enrollment", 404) from exc
        if value.get("schema") != 1: raise PortalError("invalid broker state", 500)
        return value

    def _by_token(self, token: str) -> dict[str, Any]:
        wanted = token_digest(token); found = None
        with self.lock:
            for path in self.root.glob("*.json"):
                value = json.loads(path.read_text("utf-8"))
                if secrets.compare_digest(value.get("token_sha256", ""), wanted): found = value
        if found is None: raise PortalError("invalid bearer token", 401)
        if found["expires_at"] <= int(time.time()): raise PortalError("enrollment expired", 410)
        return found

    def register(self, invitation: dict[str, Any], bundle_b64: str,
                 bundle_sha256: str, bundle_filename: str) -> dict[str, Any]:
        required = {"id", "token", "player", "player_id", "credential_id",
                    "certificate_cn", "expires_at", "security_mode"}
        if not required <= invitation.keys() or not ID_RE.fullmatch(str(invitation["id"])):
            raise PortalError("invalid invitation")
        expiry = int(invitation["expires_at"])
        if expiry <= int(time.time()) or expiry > int(time.time()) + 86400: raise PortalError("invalid expiry")
        security_mode = str(invitation["security_mode"])
        if security_mode not in {"high-assurance", "compatible"}:
            raise PortalError("invalid security mode")
        if not isinstance(bundle_b64, str) or not re.fullmatch(r"[0-9a-f]{64}", bundle_sha256 or ""):
            raise PortalError("invalid invitation bundle")
        if not isinstance(bundle_filename, str) or not BUNDLE_NAME_RE.fullmatch(bundle_filename):
            raise PortalError("invalid invitation bundle filename")
        try:
            bundle = base64.b64decode(bundle_b64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise PortalError("invalid invitation bundle encoding") from exc
        if not 22 <= len(bundle) <= MAX_BUNDLE or not bundle.startswith(b"PK\x03\x04"):
            raise PortalError("invalid invitation bundle size or format")
        if not secrets.compare_digest(hashlib.sha256(bundle).hexdigest(), bundle_sha256):
            raise PortalError("invitation bundle digest mismatch")
        state = {"schema": 1, "id": invitation["id"], "player": str(invitation["player"])[:64],
                 "player_id": str(invitation["player_id"]),
                 "credential_id": str(invitation["credential_id"]),
                 "certificate_cn": str(invitation["certificate_cn"])[:128], "expires_at": expiry,
                 "security_mode": security_mode,
                 "bundle_filename": bundle_filename, "bundle_sha256": bundle_sha256,
                 "token_sha256": token_digest(str(invitation["token"])), "state": "created"}
        with self.lock:
            if self._path(state["id"]).exists() or os.path.lexists(self._bundle_path(state["id"])):
                raise PortalError("enrollment already registered", 409)
            bundle_path = self._bundle_path(state["id"])
            try:
                atomic_blob(bundle_path, bundle)
                atomic_write(self._path(state["id"]), state)
            except Exception:
                with contextlib.suppress(FileNotFoundError): bundle_path.unlink()
                raise
        return {"id": state["id"], "state": state["state"]}

    def download_bundle(self, enrollment_id: str, requested_filename: str) -> tuple[str, bytes]:
        with self.lock:
            state = self._load(enrollment_id)
            if state["expires_at"] <= int(time.time()): raise PortalError("invitation expired", 410)
            if state.get("bundle_filename") != requested_filename:
                raise PortalError("not found", 404)
            bundle_path = self._bundle_path(enrollment_id)
            try:
                metadata = bundle_path.lstat()
                if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
                    raise PortalError("invitation bundle is unsafe", 500)
                bundle = bundle_path.read_bytes()
            except FileNotFoundError as exc: raise PortalError("invitation bundle unavailable", 410) from exc
        if not secrets.compare_digest(hashlib.sha256(bundle).hexdigest(), state["bundle_sha256"]):
            raise PortalError("invitation bundle integrity failure", 500)
        return state["bundle_filename"], bundle

    def challenge(self, token: str) -> dict[str, Any]:
        state = self._by_token(token)
        return {
            "enrollment_id": state["id"],
            **{key: state[key] for key in (
                "player", "player_id", "credential_id", "certificate_cn", "expires_at",
                "security_mode"
            )},
        }

    def submit(self, enrollment_id: str, token: str, csr: str) -> dict[str, Any]:
        if not isinstance(enrollment_id, str) or not isinstance(csr, str):
            raise PortalError("enrollment_id and csr must be strings")
        if len(csr.encode("utf-8")) > MAX_CSR: raise PortalError("CSR is too large", 413)
        with self.lock:
            state = self._by_token(token)
            if state["id"] != enrollment_id: raise PortalError("token does not match enrollment", 403)
            if state["state"] != "created": raise PortalError("CSR already submitted", 409)
            try: fingerprint = self.validator.validate_csr(csr.encode("ascii"), state["certificate_cn"])
            except (UnicodeError, self.validator.EnrollmentError) as exc: raise PortalError(str(exc)) from exc
            state.update(state="pending", csr=csr, spki_sha256=fingerprint, submitted_at=int(time.time()))
            atomic_write(self._path(enrollment_id), state)
        return {"id": enrollment_id, "state": "pending", "spki_sha256": fingerprint,
                "comparison_code": fingerprint[:4] + "-" + fingerprint[-4:]}

    def inspect(self, enrollment_id: str) -> dict[str, Any]:
        with self.lock:
            state = self._load(enrollment_id)
        if state["state"] != "pending": raise PortalError("enrollment is not pending", 409)
        return {key: state[key] for key in ("id", "player", "certificate_cn", "expires_at", "csr", "spki_sha256")}

    def status(self, enrollment_id: str) -> dict[str, Any]:
        with self.lock:
            state = self._load(enrollment_id)
        result = {key: state[key] for key in (
            "id", "player", "certificate_cn", "expires_at", "security_mode", "state"
        )}
        if state.get("spki_sha256"):
            result["spki_sha256"] = state["spki_sha256"]
            result["comparison_code"] = state["spki_sha256"][:4] + "-" + state["spki_sha256"][-4:]
        return result

    def pending_requests(self) -> dict[str, Any]:
        """Return a bounded, secret-free approval queue to the root-only admin socket."""
        now = int(time.time())
        requests = []
        with self.lock:
            for path in self.root.glob("*.json"):
                state = json.loads(path.read_text("utf-8"))
                if state.get("schema") != 1 or state.get("state") != "pending":
                    continue
                if int(state.get("expires_at", 0)) <= now:
                    continue
                fingerprint = state.get("spki_sha256")
                if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
                    raise PortalError("invalid pending enrollment state", 500)
                requests.append({
                    "id": state["id"],
                    "player": state["player"],
                    "certificate_cn": state["certificate_cn"],
                    "expires_at": state["expires_at"],
                    "security_mode": state["security_mode"],
                    "submitted_at": state.get("submitted_at", 0),
                    "spki_sha256": fingerprint,
                    "comparison_code": fingerprint[:4] + "-" + fingerprint[-4:],
                })
        requests.sort(key=lambda value: (int(value["submitted_at"]), value["id"]))
        return {"requests": requests[:256], "total": len(requests)}

    def cancel(self, enrollment_id: str) -> dict[str, Any]:
        """Invalidate a public invitation or response through the root-only socket."""
        with self.lock:
            state = self._load(enrollment_id)
            state["state"] = "cancelled"
            state["token_sha256"] = token_digest(secrets.token_urlsafe(32))
            for field in ("csr", "response", "response_sha256", "spki_sha256"):
                state.pop(field, None)
            atomic_write(self._path(enrollment_id), state)
            with contextlib.suppress(FileNotFoundError):
                self._bundle_path(enrollment_id).unlink()
        return {"id": enrollment_id, "state": "cancelled"}

    def publish(self, enrollment_id: str, response: dict[str, Any], expected_spki: str) -> dict[str, Any]:
        encoded = canonical(response)
        response_sha256 = hashlib.sha256(encoded).hexdigest()
        if len(encoded) > MAX_ADMIN: raise PortalError("response bundle is too large", 413)
        required = {"certificate_pem", "tls_crypt_v2", "certificate_cn", "credential_id",
                    "player_id", "serial", "kid", "security_mode"}
        if not required <= response.keys(): raise PortalError("incomplete approved response")
        with self.lock:
            state = self._load(enrollment_id)
            if state["state"] == "approved":
                if secrets.compare_digest(state.get("response_sha256", ""), response_sha256):
                    return {"id": enrollment_id, "state": "approved",
                            "response_sha256": response_sha256}
                raise PortalError("different response already published", 409)
            if state["state"] != "pending": raise PortalError("enrollment is not pending", 409)
            if not secrets.compare_digest(state["spki_sha256"], expected_spki):
                raise PortalError("CSR fingerprint changed", 409)
            if response["certificate_cn"] != state["certificate_cn"]: raise PortalError("certificate identity mismatch")
            if response["security_mode"] != state["security_mode"]: raise PortalError("security mode mismatch")
            state.update(state="approved", response=response,
                         response_sha256=response_sha256, approved_at=int(time.time()))
            state.pop("csr", None); atomic_write(self._path(enrollment_id), state)
        return {"id": enrollment_id, "state": "approved",
                "response_sha256": response_sha256}

    def result(self, token: str) -> dict[str, Any]:
        with self.lock:
            state = self._by_token(token)
            if state["state"] in {"created", "pending"}: return {"id": state["id"], "state": "pending"}
            if state["state"] == "collected": raise PortalError("result already collected", 410)
            if state["state"] != "approved": raise PortalError("enrollment unavailable", 410)
            result = dict(state["response"])
            result.update(enrollment_id=state["id"], state="approved")
            state["state"] = "collected"
            state.pop("response", None); atomic_write(self._path(state["id"]), state)
            with contextlib.suppress(FileNotFoundError): self._bundle_path(state["id"]).unlink()
            return result


class RateLimiter:
    def __init__(self, limit: int, window: int): self.limit=limit; self.window=window; self.values={}; self.lock=threading.Lock()
    def allow(self, key: str) -> bool:
        now=time.monotonic()
        with self.lock:
            values=[item for item in self.values.get(key, []) if item > now-self.window]
            if len(values) >= self.limit: self.values[key]=values; return False
            values.append(now); self.values[key]=values; return True


class PortalHandler(BaseHTTPRequestHandler):
    server_version = "VPNEnrollmentPortal/2"; sys_version = ""
    def log_message(self, format: str, *args: Any) -> None: pass
    def _headers(self, status: int, length: int) -> None:
        self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(length)); self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache"); self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "no-referrer"); self.send_header("Strict-Transport-Security", "max-age=31536000")
    def _reply(self, status: int, value: dict[str, Any]) -> None:
        data=canonical(value); self._headers(status, len(data)); self.end_headers(); self.wfile.write(data)
    def _reply_bundle(self, filename: str, data: bytes) -> None:
        self.send_response(200); self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(len(data))); self.send_header("Cache-Control", "private, no-store")
        self.send_header("Pragma", "no-cache"); self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.end_headers(); self.wfile.write(data)
    def _token(self) -> str:
        value=self.headers.get("Authorization", "")
        if not value.startswith("Bearer ") or len(value) > 512: raise PortalError("bearer token required", 401)
        return value[7:]
    def _dispatch(self) -> None:
        if not self.server.limiter.allow(self.client_address[0]): raise PortalError("rate limit exceeded", 429)
        path=urlsplit(self.path).path
        bundle_match = re.fullmatch(r"/invitations/([0-9a-f]{64})/([A-Za-z0-9][A-Za-z0-9_.-]{0,95}\.zip)", path)
        if self.command == "GET" and bundle_match:
            filename, data = self.server.store.download_bundle(bundle_match.group(1), bundle_match.group(2))
            self._reply_bundle(filename, data); return
        token=self._token()
        if self.command == "GET" and path == "/api/v2/enrollments/challenge": result=self.server.store.challenge(token)
        elif self.command == "GET" and path == "/api/v2/enrollments/result": result=self.server.store.result(token)
        elif self.command == "POST" and path == "/api/v2/enrollments":
            try: length=int(self.headers.get("Content-Length", ""))
            except ValueError as exc: raise PortalError("Content-Length required", 411) from exc
            if length < 2 or length > MAX_JSON: raise PortalError("request body is too large", 413)
            if self.headers.get("Content-Type", "").split(";",1)[0].strip() != "application/json": raise PortalError("application/json required", 415)
            try: body=json.loads(self.rfile.read(length))
            except (UnicodeError, json.JSONDecodeError) as exc: raise PortalError("invalid JSON") from exc
            if not isinstance(body, dict) or set(body) != {"enrollment_id", "csr"}: raise PortalError("invalid request schema")
            result=self.server.store.submit(body["enrollment_id"], token, body["csr"])
        else: raise PortalError("not found", 404)
        self._reply(200, result)
    def do_GET(self) -> None:
        try: self._dispatch()
        except PortalError as exc: self._reply(exc.status, {"error": str(exc)})
    def do_POST(self) -> None: self.do_GET()


class AdminHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        raw=self.rfile.readline(MAX_ADMIN+1)
        try:
            if len(raw)>MAX_ADMIN: raise PortalError("admin request too large", 413)
            request=json.loads(raw); command=request.get("command")
            if command=="register": result=self.server.store.register(
                request["invitation"], request["bundle_b64"], request["bundle_sha256"],
                request["bundle_filename"])
            elif command=="inspect": result=self.server.store.inspect(request["id"])
            elif command=="status": result=self.server.store.status(request["id"])
            elif command=="pending": result=self.server.store.pending_requests()
            elif command=="cancel": result=self.server.store.cancel(request["id"])
            elif command=="publish": result=self.server.store.publish(request["id"], request["response"], request["spki_sha256"])
            else: raise PortalError("unknown admin command")
            answer={"ok":True,"result":result}
        except (KeyError, TypeError, json.JSONDecodeError, PortalError) as exc: answer={"ok":False,"error":str(exc)}
        self.wfile.write(canonical(answer))


class AdminServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads=True
    def __init__(self, path: str, store: PublicStore):
        self.store=store; super().__init__(path, AdminHandler); os.chmod(path, 0o600)


def build_servers(config: dict[str, Any]) -> tuple[ThreadingHTTPServer, AdminServer]:
    store=PublicStore(Path(config["spool_dir"]), Path(config["validator_path"]))
    http=ThreadingHTTPServer((config["listen_address"], int(config["listen_port"])), PortalHandler)
    http.store=store; http.limiter=RateLimiter(int(config.get("rate_limit",30)), int(config.get("rate_window_seconds",60)))
    socket_path=Path(config["admin_socket"]); socket_path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(FileNotFoundError): socket_path.unlink()
    admin=AdminServer(str(socket_path), store); os.chmod(socket_path, 0o600)
    return http, admin


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument("--config", type=Path, required=True)
    args=parser.parse_args(); config=json.loads(args.config.read_text("utf-8")); http,admin=build_servers(config)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(config["tls_certificate"], config["tls_private_key"])
    http.socket=context.wrap_socket(http.socket, server_side=True)
    thread=threading.Thread(target=admin.serve_forever, daemon=True); thread.start()
    try: http.serve_forever()
    finally: http.server_close(); admin.shutdown(); admin.server_close()
    return 0


if __name__ == "__main__": raise SystemExit(main())
