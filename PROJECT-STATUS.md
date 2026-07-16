# Project status

Version: `1.0.1`

## Delivered architecture

- Fresh Debian 13 installer with official OpenVPN Community 2.7.2+ packages.
- EC P-256 CA named `OPENVPN LAN PARTY`, individual certificates, CRL and
  individual `tls-crypt-v2` metadata.
- Per-invitation `high-assurance` and `compatible` modes on one server.
- Client-side non-exportable Windows CNG keys; no player private key on Debian.
- Protected portal ZIP, bilingual one-window setup and persistent OpenVPN GUI.
- Root-only approval pool supporting simultaneous invitations.
- Single administration interface: `vpn-enrollment-admin`.
- Complete player offboarding and exact Windows local cleanup helper.
- Bilingual Companion with presence, chat and full game-lobby workflow.
- miniupnpc and optional ACME portal certificate automation.

## Validation gates

- Python unit and integration tests must pass.
- PowerShell scripts must parse under Windows PowerShell 5.1.
- Shell scripts must pass `bash -n`, `shellcheck` and `git diff --check`.
- Fresh Debian installation must pass `audit-openvpn-lan-party`.
- Real Windows 11 TPM enrollment, persistent connection, Companion launch,
  revocation and re-enrollment require acceptance evidence.
- Compatible mode requires a real Windows 10 22H2 build 19045 acceptance run
  before it is advertised as hardware-validated.

## Acceptance evidence — 2026-07-16

Confirmed against the 1.0.x implementation:

- all 91 automated repository tests pass;
- the 1.0.1 archive was built from its exact annotated tag, downloaded again
  from GitHub and verified against SHA-256;
- Windows 11 high-assurance enrollment creates an ECDSA P-256 key with
  Microsoft Platform Crypto Provider, refuses private-key export, connects with
  OpenVPN Community 2.7.5 and hands the persistent tunnel to OpenVPN GUI;
- exact Windows key-loss cleanup, failed reuse of the removed identity and
  re-enrollment for the same Companion player were exercised successfully;
- Windows 10 22H2 compatible-mode installation, enrollment and VPN connection
  were confirmed on real hardware.

Still required for complete product acceptance:

- real game traffic over the compatible Windows 10 tunnel;
- a simultaneous high-assurance and compatible client test on the same server;
- a complete install and all-PASS audit on a fresh Debian 13 host;
- a real compatible-mode Windows offboarding run.

The current Debian test machine intentionally preserves its historical RSA CA
and existing identities. Its application services are operational, but its CA
cannot satisfy the fresh-install EC P-256 audit and must not be cited as that
acceptance evidence.

The repository must never contain generated invitation bundles, profiles,
private keys, bearer tokens, credential registries or `companion.json`.
