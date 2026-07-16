#!/usr/bin/env python3
"""Public-only PKCS#10 policy validator for the unprivileged portal.

This module intentionally contains no CA, certificate-signing, revocation or
OpenVPN key-generation operation. It is safe to load in the Internet-facing
enrolment broker, which receives only public CSR material.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess
import tempfile


class EnrollmentError(RuntimeError):
    pass


def run(command: list[str], *, input_data: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            command, input=input_data, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=True,
            env={"LC_ALL": "C", "LANG": "C", "PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise EnrollmentError("CSR cryptographic validation failed") from exc
    return result.stdout


def openssl_text(openssl: str, csr: Path, *arguments: str) -> str:
    return run([openssl, "req", "-in", str(csr), *arguments]).decode(
        "utf-8", "strict"
    )


def validate_csr(csr_pem: bytes, expected_cn: str,
                 openssl: str = "/usr/bin/openssl") -> str:
    if (len(csr_pem) > 64 * 1024
            or b"BEGIN CERTIFICATE REQUEST" not in csr_pem):
        raise EnrollmentError("invalid PKCS#10 encoding")
    with tempfile.TemporaryDirectory() as directory:
        csr = Path(directory) / "request.pem"
        csr.write_bytes(csr_pem)
        openssl_text(openssl, csr, "-verify", "-noout")
        subject = openssl_text(
            openssl, csr, "-subject", "-nameopt", "RFC2253", "-noout"
        ).strip()
        if subject != f"subject=CN={expected_cn}":
            raise EnrollmentError(
                "CSR subject must contain only the assigned common name"
            )
        request_text = openssl_text(openssl, csr, "-text", "-noout")
        if not re.search(
                r"Public Key Algorithm:\s+(?:id-ecPublicKey|X9\.62 id-ecPublicKey)",
                request_text):
            raise EnrollmentError("CSR key is not EC")
        if not re.search(
                r"ASN1 OID:\s+(?:prime256v1|secp256r1)", request_text):
            raise EnrollmentError("CSR key is not ECDSA P-256")
        extension = re.search(
            r"Requested Extensions:\s*(.*?)(?:\n\s*Signature Algorithm:)",
            request_text, re.S,
        )
        if extension and extension.group(1).strip() not in {"", "<EMPTY>"}:
            raise EnrollmentError("CSR requested extensions are forbidden")
        public_key = run(
            [openssl, "req", "-in", str(csr), "-pubkey", "-noout"]
        )
        der = run(
            [openssl, "pkey", "-pubin", "-outform", "DER"],
            input_data=public_key,
        )
    return hashlib.sha256(der).hexdigest()
