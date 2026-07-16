#!/usr/bin/env python3

"""Issue, validate, deploy, and renew short-lived Let's Encrypt IP certificates."""

from __future__ import annotations

import argparse
import fcntl
import grp
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


PRODUCTION_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory"
STAGING_DIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"
ALLOWED_DIRECTORIES = {PRODUCTION_DIRECTORY, STAGING_DIRECTORY}
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$"
)
MAPPING_PATTERN = re.compile(
    r"(?m)^[^\n]*\bTCP\s+80->(?P<address>[0-9.]+):(?P<port>[0-9]+)\b"
    r"(?P<details>[^\n]*)$"
)
MINIMUM_LEGO_VERSION = (4, 35, 0)


class ManagerError(RuntimeError):
    """Expected operational failure."""


def fail(message: str) -> None:
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_config(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            fail(f"ACME configuration must be a regular file: {path}")
        if metadata.st_uid != os.geteuid():
            fail("ACME configuration must be owned by the account running the manager")
        mode = stat.S_IMODE(metadata.st_mode)
        if mode & 0o077:
            fail(f"ACME configuration must be root-only (0600), current mode is {mode:04o}")
        with path.open("r", encoding="utf-8") as handle:
            config = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"could not read ACME configuration {path}: {exc}")

    required = {
        "version",
        "public_ip",
        "lan_ip",
        "account_email",
        "acme_directory",
        "state_directory",
        "deploy_certificate",
        "deploy_private_key",
        "portal_group",
        "portal_service",
        "upnp_enabled",
    }
    missing = sorted(required.difference(config))
    if missing:
        fail(f"ACME configuration is missing: {', '.join(missing)}")
    if config["version"] != 1:
        fail("unsupported ACME configuration version")

    try:
        public_ip = ipaddress.ip_address(str(config["public_ip"]))
        lan_ip = ipaddress.ip_address(str(config["lan_ip"]))
    except ValueError as exc:
        fail(f"invalid ACME IP address: {exc}")
    if public_ip.version != 4 or not public_ip.is_global:
        fail("Let's Encrypt IP mode requires a globally routable public IPv4 address")
    if lan_ip.version != 4:
        fail("the ACME challenge LAN address must be IPv4")
    config["public_ip"] = str(public_ip)
    config["lan_ip"] = str(lan_ip)

    email = str(config["account_email"])
    if not EMAIL_PATTERN.fullmatch(email):
        fail("the ACME account email address is invalid")
    config["account_email"] = email
    if config["acme_directory"] not in ALLOWED_DIRECTORIES:
        fail("only the official Let's Encrypt production or staging directory is allowed")
    if type(config["upnp_enabled"]) is not bool:  # noqa: E721 - reject truthy strings
        fail("upnp_enabled must be a JSON boolean")

    try:
        config["challenge_internal_port"] = int(
            config.get("challenge_internal_port", 9080)
        )
        config["mapping_lease_seconds"] = int(config.get("mapping_lease_seconds", 600))
        config["renew_before_seconds"] = int(config.get("renew_before_seconds", 259200))
    except (TypeError, ValueError):
        fail("ACME numeric configuration values are invalid")
    if not 1024 <= config["challenge_internal_port"] <= 65535:
        fail("the internal ACME challenge port must be between 1024 and 65535")
    if not 120 <= config["mapping_lease_seconds"] <= 3600:
        fail("the UPnP ACME mapping lease must be between 120 and 3600 seconds")
    if not 3600 <= config["renew_before_seconds"] <= 432000:
        fail("renew_before_seconds must be between one hour and five days")

    for key in (
        "state_directory",
        "deploy_certificate",
        "deploy_private_key",
        "portal_config",
        "lock_file",
    ):
        if key not in config:
            continue
        candidate = Path(str(config[key]))
        if not candidate.is_absolute():
            fail(f"{key} must be an absolute path")
        config[key] = str(candidate)
    config.setdefault("portal_config", "/etc/openvpn-lan-party/enrollment-portal.json")
    if type(config.get("update_portal_trust", True)) is not bool:
        fail("update_portal_trust must be a JSON boolean")
    config.setdefault("update_portal_trust", True)
    config.setdefault("lock_file", "/run/lock/vpn-enrollment-acme.lock")
    return config


def executable(environment_name: str, default_name: str) -> str:
    configured = os.environ.get(environment_name)
    if configured:
        path = Path(configured)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
        raise ManagerError(f"{environment_name} is not executable: {configured}")
    found = shutil.which(default_name)
    if not found:
        raise ManagerError(f"required command was not found: {default_name}")
    return found


def run(
    arguments: list[str],
    *,
    capture: bool = False,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            arguments,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture else None,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ManagerError(
            f"command timed out after {timeout} seconds: {arguments[0]}"
        ) from exc
    if result.returncode != 0:
        detail = f": {result.stdout.strip()}" if capture and result.stdout else ""
        raise ManagerError(
            f"command failed with exit code {result.returncode}: {arguments[0]}{detail}"
        )
    return result


def openssl_output(arguments: list[str]) -> bytes:
    openssl = executable("VPN_OPENSSL_BIN", "openssl")
    result = subprocess.run(
        [openssl, *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise ManagerError(f"OpenSSL validation failed: {message}")
    return result.stdout


def certificate_paths(config: dict[str, Any]) -> tuple[Path, Path, Path]:
    certificate_dir = Path(config["state_directory"]) / "certificates"
    public_ip = config["public_ip"]
    return (
        certificate_dir / f"{public_ip}.crt",
        certificate_dir / f"{public_ip}.key",
        certificate_dir / f"{public_ip}.issuer.crt",
    )


def certificate_fingerprint(path: Path) -> str:
    pem = path.read_text(encoding="ascii")
    first_certificate = re.search(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.DOTALL
    )
    if not first_certificate:
        raise ManagerError(f"no PEM certificate was found in {path}")
    import ssl

    der = ssl.PEM_cert_to_DER_cert(first_certificate.group(0))
    return hashlib.sha256(der).hexdigest()


def validate_certificate(
    config: dict[str, Any],
    certificate: Path,
    private_key: Path,
    issuer: Path,
    minimum_remaining_seconds: int,
) -> dict[str, str]:
    for path in (certificate, private_key):
        if not path.is_file() or path.is_symlink():
            raise ManagerError(f"certificate material is missing or unsafe: {path}")
    openssl_output(
        ["x509", "-in", str(certificate), "-noout", "-checkip", config["public_ip"]]
    )
    openssl_output(
        [
            "x509",
            "-in",
            str(certificate),
            "-noout",
            "-checkend",
            str(minimum_remaining_seconds),
        ]
    )
    certificate_public_key = openssl_output(
        ["x509", "-in", str(certificate), "-pubkey", "-noout"]
    )
    private_public_key = openssl_output(
        ["pkey", "-in", str(private_key), "-pubout"]
    )
    if not secrets.compare_digest(
        hashlib.sha256(certificate_public_key).digest(),
        hashlib.sha256(private_public_key).digest(),
    ):
        raise ManagerError("the certificate and private key do not match")

    if config["acme_directory"] == PRODUCTION_DIRECTORY:
        if not issuer.is_file() or issuer.is_symlink():
            raise ManagerError("the Let's Encrypt issuer certificate is missing")
        openssl_output(
            [
                "verify",
                "-CApath",
                "/etc/ssl/certs",
                "-untrusted",
                str(issuer),
                str(certificate),
            ]
        )

    end_date = openssl_output(
        ["x509", "-in", str(certificate), "-noout", "-enddate"]
    ).decode("ascii").strip()
    issuer_name = openssl_output(
        ["x509", "-in", str(certificate), "-noout", "-issuer"]
    ).decode("utf-8", errors="replace").strip()
    return {
        "fingerprint": certificate_fingerprint(certificate),
        "not_after": end_date.removeprefix("notAfter="),
        "issuer": issuer_name.removeprefix("issuer="),
    }


def deployed_material_valid(
    config: dict[str, Any], minimum_remaining_seconds: int
) -> dict[str, str]:
    _source_certificate, _source_key, issuer = certificate_paths(config)
    return validate_certificate(
        config,
        Path(config["deploy_certificate"]),
        Path(config["deploy_private_key"]),
        issuer,
        minimum_remaining_seconds,
    )


def check_lego_version(lego: str) -> None:
    result = run([lego, "--version"], capture=True, timeout=10)
    match = re.search(r"\bversion\s+(\d+)\.(\d+)\.(\d+)\b", result.stdout)
    if not match:
        raise ManagerError("could not determine the lego version")
    version = tuple(int(component) for component in match.groups())
    if version < MINIMUM_LEGO_VERSION:
        required = ".".join(str(component) for component in MINIMUM_LEGO_VERSION)
        actual = ".".join(str(component) for component in version)
        raise ManagerError(f"lego {required} or newer is required, found {actual}")


def upnp_listing(upnpc: str) -> str:
    return run([upnpc, "-l"], capture=True, timeout=20).stdout


def external_address(listing: str) -> str | None:
    match = re.search(r"ExternalIPAddress\s*=\s*([0-9.]+)", listing)
    return match.group(1) if match else None


@contextmanager
def temporary_mapping(config: dict[str, Any]) -> Iterator[None]:
    if not config["upnp_enabled"]:
        print(
            "UPnP is disabled: expecting an existing manual TCP 80 mapping to "
            f"{config['lan_ip']}:{config['challenge_internal_port']}.",
            flush=True,
        )
        yield
        return

    upnpc = executable("VPN_UPNPC_BIN", "upnpc")
    listing = upnp_listing(upnpc)
    detected_external = external_address(listing)
    if detected_external != config["public_ip"]:
        raise ManagerError(
            "the router external IPv4 does not match the configured public IP "
            f"({detected_external or 'unknown'} != {config['public_ip']})"
        )

    mappings = list(MAPPING_PATTERN.finditer(listing))
    expected = (config["lan_ip"], config["challenge_internal_port"])
    mapping_created = False
    try:
        if mappings:
            current = (mappings[0].group("address"), int(mappings[0].group("port")))
            if current != expected:
                raise ManagerError(
                    "public TCP port 80 is already mapped to "
                    f"{current[0]}:{current[1]}; refusing to replace it"
                )
        else:
            run(
                [
                    upnpc,
                    "-e",
                    "OpenVPN-LAN-ACME",
                    "-a",
                    config["lan_ip"],
                    str(config["challenge_internal_port"]),
                    "80",
                    "TCP",
                    str(config["mapping_lease_seconds"]),
                ],
                timeout=20,
            )
            mapping_created = True
            created_listing = upnp_listing(upnpc)
            created_mappings = list(MAPPING_PATTERN.finditer(created_listing))
            if not created_mappings:
                raise ManagerError(
                    "the temporary public TCP port 80 mapping was not created"
                )
            created = created_mappings[0]
            created_target = (created.group("address"), int(created.group("port")))
            if (
                created_target != expected
                or "OpenVPN-LAN-ACME" not in created.group("details")
            ):
                mapping_created = False
                raise ManagerError(
                    "the router did not confirm ownership of the temporary TCP 80 mapping"
                )
        yield
    finally:
        if mapping_created:
            mapping_still_owned = False
            try:
                final_mappings = list(MAPPING_PATTERN.finditer(upnp_listing(upnpc)))
                if final_mappings:
                    current = final_mappings[0]
                    mapping_still_owned = (
                        (current.group("address"), int(current.group("port")))
                        == expected
                        and "OpenVPN-LAN-ACME" in current.group("details")
                    )
            except ManagerError:
                pass
            if mapping_still_owned:
                result = subprocess.run(
                    [upnpc, "-d", "80", "TCP"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=20,
                    check=False,
                )
            else:
                result = None
            if result is None or result.returncode != 0:
                print(
                    "Warning: the temporary TCP 80 UPnP mapping could not be safely "
                    "removed; its lease is limited to "
                    f"{config['mapping_lease_seconds']} seconds.",
                    file=sys.stderr,
                )


def ensure_challenge_port_available(config: dict[str, Any]) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("0.0.0.0", config["challenge_internal_port"]))
    except OSError as exc:
        raise ManagerError(
            f"the local ACME challenge port {config['challenge_internal_port']} "
            f"is unavailable: {exc}"
        ) from exc


def lego_base(config: dict[str, Any], lego: str) -> list[str]:
    return [
        lego,
        "--server",
        config["acme_directory"],
        "--accept-tos",
        "--email",
        config["account_email"],
        "--domains",
        config["public_ip"],
        "--path",
        config["state_directory"],
        "--key-type",
        "ec256",
        "--disable-cn",
        "--http",
        "--http.port",
        f":{config['challenge_internal_port']}",
    ]


def private_state_directory(config: dict[str, Any], *, create: bool) -> Path:
    state_directory = Path(config["state_directory"])
    if create:
        state_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        metadata = state_directory.lstat()
    except FileNotFoundError as exc:
        raise ManagerError("the ACME state directory does not exist") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or state_directory.is_symlink()
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ManagerError(
            "the ACME state directory must be private, real, and owned by the manager"
        )
    return state_directory


def obtain_certificate(config: dict[str, Any]) -> None:
    lego = executable("VPN_LEGO_BIN", "lego")
    check_lego_version(lego)
    state_directory = private_state_directory(config, create=True)
    certificate, _key, _issuer = certificate_paths(config)
    ensure_challenge_port_available(config)

    with temporary_mapping(config):
        if certificate.is_file():
            command = [
                *lego_base(config, lego),
                "renew",
                "--days",
                "7",
                "--ari-disable",
                "--no-random-sleep",
                "--profile",
                "shortlived",
            ]
        else:
            command = [
                *lego_base(config, lego),
                "run",
                "--profile",
                "shortlived",
            ]
        run(command, timeout=300)


def portal_active(config: dict[str, Any]) -> bool:
    systemctl = executable("VPN_SYSTEMCTL_BIN", "systemctl")
    result = subprocess.run(
        [systemctl, "is-active", "--quiet", config["portal_service"]],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def portal_action(config: dict[str, Any], action: str) -> None:
    systemctl = executable("VPN_SYSTEMCTL_BIN", "systemctl")
    run([systemctl, action, config["portal_service"]], timeout=30)


def atomic_write(path: Path, content: bytes, mode: int, uid: int, gid: int) -> None:
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            fd = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary_name, uid, gid)
        os.replace(temporary_name, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def update_portal_trust(config: dict[str, Any], trust: str) -> None:
    path = Path(config["portal_config"])
    if not path.is_file() or path.is_symlink():
        raise ManagerError(f"portal configuration is missing or unsafe: {path}")
    with path.open("r", encoding="utf-8") as handle:
        portal_config = json.load(handle)
    portal_config["tls_trust"] = trust
    content = (json.dumps(portal_config, indent=2, sort_keys=True) + "\n").encode()
    group = grp.getgrnam(config["portal_group"])
    atomic_write(path, content, 0o640, 0, group.gr_gid)


def deploy_certificate(config: dict[str, Any], material: dict[str, str]) -> None:
    source_certificate, source_key, _issuer = certificate_paths(config)
    destination_certificate = Path(config["deploy_certificate"])
    destination_key = Path(config["deploy_private_key"])
    group = grp.getgrnam(config["portal_group"])
    certificate_content = source_certificate.read_bytes()
    key_content = source_key.read_bytes()
    old_certificate = (
        destination_certificate.read_bytes() if destination_certificate.is_file() else None
    )
    old_key = destination_key.read_bytes() if destination_key.is_file() else None
    was_active = portal_active(config)
    if was_active:
        portal_action(config, "stop")
    try:
        atomic_write(destination_certificate, certificate_content, 0o644, 0, group.gr_gid)
        atomic_write(destination_key, key_content, 0o640, 0, group.gr_gid)
        trust = (
            "public-ca"
            if config["acme_directory"] == PRODUCTION_DIRECTORY
            else "staging-ca"
        )
        if config["update_portal_trust"]:
            update_portal_trust(config, trust)
    except BaseException:
        if old_certificate is not None:
            atomic_write(destination_certificate, old_certificate, 0o644, 0, group.gr_gid)
        else:
            destination_certificate.unlink(missing_ok=True)
        if old_key is not None:
            atomic_write(destination_key, old_key, 0o640, 0, group.gr_gid)
        else:
            destination_key.unlink(missing_ok=True)
        raise
    finally:
        if was_active:
            portal_action(config, "start")
    print(
        "Deployed portal certificate "
        f"sha256={material['fingerprint']} expires={material['not_after']}"
    )


def source_material(config: dict[str, Any], minimum: int) -> dict[str, str]:
    private_state_directory(config, create=False)
    certificate, key, issuer = certificate_paths(config)
    return validate_certificate(config, certificate, key, issuer, minimum)


def ensure(config: dict[str, Any], minimum: int) -> dict[str, str]:
    try:
        return deployed_material_valid(config, minimum)
    except (ManagerError, OSError, json.JSONDecodeError):
        pass
    try:
        material = source_material(config, minimum)
    except (ManagerError, OSError):
        obtain_certificate(config)
        material = source_material(config, minimum)
    deploy_certificate(config, material)
    return material


def renew(config: dict[str, Any]) -> dict[str, str]:
    try:
        material = source_material(config, config["renew_before_seconds"])
    except (ManagerError, OSError):
        obtain_certificate(config)
        material = source_material(config, config["renew_before_seconds"])
    try:
        deployed = deployed_material_valid(config, config["renew_before_seconds"])
        if deployed["fingerprint"] == material["fingerprint"]:
            print(
                "Portal certificate does not need renewal: "
                f"sha256={material['fingerprint']} expires={material['not_after']}"
            )
            return material
    except (ManagerError, OSError, json.JSONDecodeError):
        pass
    deploy_certificate(config, material)
    return material


@contextmanager
def exclusive_lock(config: dict[str, Any]) -> Iterator[None]:
    lock_path = Path(config["lock_file"])
    lock_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor = os.open(
        lock_path,
        os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise ManagerError("the ACME lock file is unsafe")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("issue")
    subparsers.add_parser("renew")
    ensure_parser = subparsers.add_parser("ensure")
    ensure_parser.add_argument("--minimum-valid-seconds", type=int, default=7200)
    subparsers.add_parser("status")
    args = parser.parse_args()
    config = load_config(args.config)

    try:
        if args.command == "status":
            material = deployed_material_valid(config, 0)
            print(f"Mode        : Let's Encrypt IP")
            print(f"Public IP   : {config['public_ip']}")
            print(f"Issuer      : {material['issuer']}")
            print(f"Expires     : {material['not_after']}")
            print(f"SHA-256     : {material['fingerprint']}")
            return
        if os.geteuid() != 0:
            raise ManagerError("certificate operations must run as root")
        with exclusive_lock(config):
            if args.command == "renew":
                renew(config)
            elif args.command == "issue":
                ensure(config, config["renew_before_seconds"])
            else:
                if not 900 <= args.minimum_valid_seconds <= 518400:
                    raise ManagerError(
                        "minimum-valid-seconds must be between 900 and 518400"
                    )
                ensure(config, args.minimum_valid_seconds)
    except (ManagerError, OSError, KeyError, grp.error, json.JSONDecodeError) as exc:
        fail(str(exc))


if __name__ == "__main__":
    main()
