#!/usr/bin/env python3

from __future__ import annotations

import grp
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY = Path(__file__).resolve().parents[1]
ACME_HELPER = REPOSITORY / "assets" / "vpn-profile-acme.py"


def load_acme_module():
    spec = importlib.util.spec_from_file_location("vpn_profile_acme", ACME_HELPER)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the ACME manager module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ACME = load_acme_module()


class AcmeManagerTests(unittest.TestCase):
    public_ip = "8.8.8.8"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.source_cert = self.root / "source.crt"
        self.source_key = self.root / "source.key"
        self._generate_certificate()
        self.lego_log = self.root / "lego.log"
        self.upnp_log = self.root / "upnp.log"
        self.upnp_state = self.root / "upnp.state"
        self.lego = self._script(
            "lego",
            """#!/usr/bin/env python3
import os
import pathlib
import shutil
import sys

if "--version" in sys.argv:
    print("lego version 4.35.2 linux/amd64")
    raise SystemExit(0)
arguments = sys.argv[1:]
state = pathlib.Path(arguments[arguments.index("--path") + 1])
address = arguments[arguments.index("--domains") + 1]
certificates = state / "certificates"
certificates.mkdir(parents=True, exist_ok=True)
shutil.copyfile(os.environ["FAKE_CERT"], certificates / f"{address}.crt")
shutil.copyfile(os.environ["FAKE_KEY"], certificates / f"{address}.key")
shutil.copyfile(os.environ["FAKE_CERT"], certificates / f"{address}.issuer.crt")
with open(os.environ["FAKE_LEGO_LOG"], "a", encoding="utf-8") as handle:
    handle.write(" ".join(arguments) + "\\n")
""",
        )
        self.upnpc = self._script(
            "upnpc",
            """#!/usr/bin/env python3
import os
import pathlib
import sys

arguments = sys.argv[1:]
state = pathlib.Path(os.environ["FAKE_UPNP_STATE"])
log = pathlib.Path(os.environ["FAKE_UPNP_LOG"])
external = os.environ.get("FAKE_UPNP_EXTERNAL", "8.8.8.8")
if arguments == ["-l"]:
    print("Found valid IGD : http://192.0.2.1/rootDesc.xml")
    print(f"ExternalIPAddress = {external}")
    if os.environ.get("FAKE_UPNP_CONFLICT") == "1":
        print(" 0 TCP 80->192.0.2.99:8080 'Existing-Web' '' 0")
    elif state.exists():
        print(" 0 TCP 80->192.0.2.10:19080 'OpenVPN-LAN-ACME' '' 600")
elif "-a" in arguments:
    state.touch()
    with log.open("a", encoding="utf-8") as handle:
        handle.write("add\\n")
elif arguments == ["-d", "80", "TCP"]:
    state.unlink(missing_ok=True)
    with log.open("a", encoding="utf-8") as handle:
        handle.write("delete\\n")
else:
    raise SystemExit(2)
""",
        )
        self.systemctl = self._script(
            "systemctl",
            """#!/usr/bin/env python3
import sys

raise SystemExit(3 if "is-active" in sys.argv else 0)
""",
        )
        self.portal_config = self.root / "portal.json"
        self.portal_config.write_text(
            json.dumps({"tls_trust": "self-signed"}), encoding="utf-8"
        )
        os.chmod(self.portal_config, 0o640)
        self.config_path = self.root / "acme.json"
        current_group = grp.getgrgid(os.getgid()).gr_name
        self.raw_config = {
            "version": 1,
            "public_ip": self.public_ip,
            "lan_ip": "192.0.2.10",
            "account_email": "acme-test@example.com",
            "acme_directory": ACME.STAGING_DIRECTORY,
            "state_directory": str(self.root / "state"),
            "deploy_certificate": str(self.root / "deployed.crt"),
            "deploy_private_key": str(self.root / "deployed.key"),
            "portal_config": str(self.portal_config),
            "portal_group": current_group,
            "portal_service": "vpn-profile-portal.service",
            "upnp_enabled": True,
            "challenge_internal_port": 19080,
            "mapping_lease_seconds": 600,
            "renew_before_seconds": 259200,
            "lock_file": str(self.root / "acme.lock"),
        }
        self.config_path.write_text(json.dumps(self.raw_config), encoding="utf-8")
        os.chmod(self.config_path, 0o600)
        self.config = ACME.load_config(self.config_path)
        self.environment = mock.patch.dict(
            os.environ,
            {
                "VPN_LEGO_BIN": str(self.lego),
                "VPN_UPNPC_BIN": str(self.upnpc),
                "VPN_SYSTEMCTL_BIN": str(self.systemctl),
                "FAKE_CERT": str(self.source_cert),
                "FAKE_KEY": str(self.source_key),
                "FAKE_LEGO_LOG": str(self.lego_log),
                "FAKE_UPNP_LOG": str(self.upnp_log),
                "FAKE_UPNP_STATE": str(self.upnp_state),
            },
            clear=False,
        )
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temporary.cleanup()

    def _generate_certificate(self) -> None:
        result = subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-days",
                "7",
                "-subj",
                "/CN=ACME IP test",
                "-addext",
                f"subjectAltName=IP:{self.public_ip}",
                "-keyout",
                str(self.source_key),
                "-out",
                str(self.source_cert),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        self.assertEqual(result.returncode, 0, "could not generate the ACME test cert")

    def _script(self, name: str, content: str) -> Path:
        path = self.bin_dir / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)
        return path

    def test_issue_maps_port_deploys_full_ip_filename_and_cleans_up(self) -> None:
        with mock.patch.object(ACME.os, "chown"):
            material = ACME.ensure(self.config, 3600)

        self.assertTrue((self.root / "deployed.crt").is_file())
        self.assertTrue((self.root / "deployed.key").is_file())
        self.assertTrue(
            (self.root / "state" / "certificates" / f"{self.public_ip}.crt").is_file()
        )
        self.assertEqual(self.upnp_log.read_text(encoding="utf-8"), "add\ndelete\n")
        self.assertFalse(self.upnp_state.exists())
        portal = json.loads(self.portal_config.read_text(encoding="utf-8"))
        self.assertEqual(portal["tls_trust"], "staging-ca")
        self.assertEqual(len(material["fingerprint"]), 64)
        lego_arguments = self.lego_log.read_text(encoding="utf-8")
        self.assertIn("--disable-cn", lego_arguments)
        self.assertIn("--profile shortlived", lego_arguments)

    def test_valid_deployed_certificate_does_not_contact_acme_again(self) -> None:
        with mock.patch.object(ACME.os, "chown"):
            first = ACME.ensure(self.config, 3600)
            lego_before = self.lego_log.read_text(encoding="utf-8")
            upnp_before = self.upnp_log.read_text(encoding="utf-8")
            second = ACME.ensure(self.config, 3600)

        self.assertEqual(first["fingerprint"], second["fingerprint"])
        self.assertEqual(self.lego_log.read_text(encoding="utf-8"), lego_before)
        self.assertEqual(self.upnp_log.read_text(encoding="utf-8"), upnp_before)

    def test_router_public_ip_mismatch_is_rejected_without_mapping(self) -> None:
        with mock.patch.dict(os.environ, {"FAKE_UPNP_EXTERNAL": "1.1.1.1"}):
            with self.assertRaisesRegex(ACME.ManagerError, "does not match"):
                ACME.obtain_certificate(self.config)
        self.assertFalse(self.upnp_state.exists())
        self.assertFalse(self.upnp_log.exists())

    def test_existing_public_port_80_mapping_is_not_replaced(self) -> None:
        with mock.patch.dict(os.environ, {"FAKE_UPNP_CONFLICT": "1"}):
            with self.assertRaisesRegex(ACME.ManagerError, "already mapped"):
                ACME.obtain_certificate(self.config)
        self.assertFalse(self.upnp_state.exists())
        self.assertFalse(self.upnp_log.exists())

    def test_configuration_must_be_root_only(self) -> None:
        os.chmod(self.config_path, 0o644)
        with self.assertRaises(SystemExit):
            ACME.load_config(self.config_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
