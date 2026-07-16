# Project status

Version: `1.0.0`

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

The repository must never contain generated invitation bundles, profiles,
private keys, bearer tokens, credential registries or `companion.json`.
