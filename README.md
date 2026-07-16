# OpenVPN LAN Party

OpenVPN LAN Party deploys a self-hosted Ethernet-style VPN on Debian 13 for a
small group of trusted players. It includes secure Windows enrollment and a
bilingual Companion for presence, chat and game lobbies.

All VPN members share one virtual LAN and must be trusted. This project is not a
public multi-tenant VPN and does not isolate players from one another.

## What it provides

- OpenVPN Community 2.7.2+ in TAP mode with modern AEAD ciphers;
- an EC P-256 CA named `OPENVPN LAN PARTY` and individual client certificates;
- client-side, non-exportable Windows CNG private keys;
- administrator-approved CSR enrollment and immediate CRL revocation;
- an individual `tls-crypt-v2` key for every credential;
- a password-protected Windows invitation downloaded from the portal;
- automatic OpenVPN/TAP installation and a bilingual Windows join wizard;
- a persistent OpenVPN GUI connection independent from the Companion;
- presence, connection duration, host latency, chat and game lobbies;
- optional miniupnpc port mapping and optional public portal TLS automation.

## Security modes

The administrator chooses a mode for each invitation. Both modes can coexist on
the same server and use the same CA, VPN, CRL and modern cipher policy.

| Mode | Windows client | Private-key provider | TPM |
|---|---|---|---|
| `high-assurance` | Windows 11 | Microsoft Platform Crypto Provider | ready, unlocked TPM 2.0 required |
| `compatible` | Windows 10 22H2 build 19045 or Windows 11 | Microsoft Software Key Storage Provider | not required |

`high-assurance` is always the default. Compatible mode never activates as a
fallback: the administrator must choose and acknowledge it explicitly. It keeps
the key non-exportable but does not provide hardware isolation. The
administrator is responsible for admitting only maintained and fully patched
compatible endpoints.

A credential's mode is immutable. To change mode, revoke the existing
credential and perform a fresh enrollment.

## Install the server

Requirements:

- a fresh Debian 13 host or VM with root access;
- a public IPv4 address or DNS name;
- UDP 1194 and TCP 8790 forwarded to the Debian host;
- trusted players only.

Run:

```bash
sudo ./install-vpn-server.sh
```

The installer refuses to overwrite an existing PKI, OpenVPN server or Companion
configuration. It asks before package installation and can configure miniupnpc.

Validate the result:

```bash
sudo audit-openvpn-lan-party
sudo systemctl status openvpn-server@server.service
sudo systemctl status vpn-enrollment-portal.service
sudo systemctl status lan-party-companion.service
```

## Add a player

Run the single administration command:

```bash
sudo vpn-enrollment-admin create --player Arthur
```

The terminal proposes:

1. `high-assurance` (default);
2. `compatible` with an explicit risk confirmation.

For controlled non-interactive creation:

```bash
sudo vpn-enrollment-admin create \
  --player Arthur \
  --security-mode compatible \
  --ack-compatible-risk \
  --no-wait
```

The output contains a portal download URL, archive password and one-time token.
The token is not stored in the ZIP or URL. Send the download link normally, but
send the archive password and token through a separate trusted channel.

If a local sendmail-compatible service is configured, this sends only the link:

```bash
sudo vpn-enrollment-admin create \
  --player Arthur \
  --email-to arthur@example.net
```

### Windows player workflow

The player:

1. downloads and extracts the ZIP with Windows Explorer;
2. double-clicks `JOIN-VPN.cmd`;
3. accepts elevation;
4. enters the archive password and one-time token;
5. leaves the wizard open while the administrator approves the request.

The wizard verifies the invitation, installs or updates the signed OpenVPN
Community MSI with TAP-Windows6 when needed, creates the non-exportable key,
submits the CSR, installs the certificate and profile, tests the tunnel, hands
the persistent connection to OpenVPN GUI and starts the Companion.

The profile is `%USERPROFILE%\OpenVPN\config\OpenVPN-LAN-Party.ovpn`. Closing
the Companion does not disconnect the VPN. Startup and Start Menu shortcuts
reconnect without another enrollment.

### Administrator approval

The `create` terminal detects the CSR, rings and displays the player, exact CN,
full SPKI SHA-256 and short comparison code. Verify the player and compare the
code with the Windows screen when possible, then answer `Y` or `N`.

For several simultaneous invitations:

```bash
sudo vpn-enrollment-admin create --player Arthur --no-wait
sudo vpn-enrollment-admin create --player Beatrice --no-wait
sudo vpn-enrollment-admin pool
```

The pool shows a numbered queue and revalidates the selected CSR immediately
before signing. Server administration prompts are English-only.

## Renew or replace a credential

Create another invitation with the same player name. The technical credential
UUID and certificate rotate; the stable player identity and existing
`companion.json` are preserved. Revoke the old enrollment after confirming the
new connection:

```bash
sudo vpn-enrollment-admin confirm-connection ENROLLMENT_ID
sudo vpn-enrollment-admin revoke ENROLLMENT_ID --reason "replaced credential"
```

## Offboard a player

Server offboarding is authoritative:

```bash
sudo vpn-enrollment-admin offboard \
  --player Arthur \
  --reason "left the group"
```

The command inventories the player's records, asks for confirmation, revokes
every active certificate, updates the CRL and `tls-crypt-v2` registry, cuts
active sessions, invalidates pending invitations, removes Companion access and
retires the player mapping. Revoked records remain available for audit.

On the retired Windows PC, run the local cleanup after server offboarding:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File "$env:LOCALAPPDATA\OpenVPN LAN Party Companion\Leave-OpenVPN-LAN-Party.ps1" `
  -RemoveCompanion
```

It validates and removes only `OpenVPN-LAN-Party`: its exact profile,
certificate, non-exportable CNG key, shortcuts and—only with
`-RemoveCompanion`—the local Companion identity. It never targets another VPN
profile.

## Companion

The Companion listens only on the VPN address, normally
`http://10.44.0.1:8787`. It offers bilingual English/French UI, authenticated
presence, VPN address, connection duration, host latency, public/private chat,
and lobbies with host-supplied game address, port and connection instructions.
Lobby state includes capacity, ready checks, gathering/in-game phases, lock,
host transfer and revision conflict protection.

The Companion token is independent from a VPN certificate. Credential renewal
preserves it; complete player offboarding removes it.

## Security boundaries

- CA and server keys: `/root/openvpn-pki`, root only.
- Enrollment state: `/var/lib/openvpn-lan-party/enrollment`, root only.
- Public credential snapshot: `/var/lib/openvpn/credential-registry.json`.
- Portal configuration and TLS: `/etc/openvpn-lan-party`.
- Companion configuration: `/etc/openvpn-lan-companion`.

The Internet-facing portal runs as `vpnportal`, cannot read the CA key and can
process only bounded public CSR material. Root performs an independent CSR
validation before signing. Never publish generated profiles, private keys,
invitation payloads or a real `companion.json`.

See [HIGH-ASSURANCE.md](HIGH-ASSURANCE.md), [SECURITY.md](SECURITY.md),
[COMPANION.md](COMPANION.md) and [ACCEPTANCE.md](ACCEPTANCE.md).

## Development

```bash
python3 -m unittest discover -s tests -v
git diff --check
shellcheck install-vpn-server.sh assets/vpn-enrollment-admin.in \
  assets/audit-openvpn-lan-party
```

`build-release.sh` requires a clean worktree and an annotated tag matching
`VERSION`. It rejects generated secrets, profiles, invitations and
`companion.json`.

---

# OpenVPN LAN Party — Français

OpenVPN LAN Party déploie sur Debian 13 un LAN virtuel Ethernet auto-hébergé
pour un petit groupe de joueurs de confiance. Il fournit un enrôlement Windows
sécurisé et un Companion bilingue pour la présence, les messages et les salons.

Tous les membres partagent le même LAN virtuel et doivent être des tiers de
confiance. Ce projet n'est pas un VPN public multi-tenant et ne cloisonne pas les
joueurs entre eux.

## Modes de sécurité

Le mode est choisi pour chaque invitation ; les deux modes coexistent sur le
même serveur.

| Mode | Client | Protection de la clé | TPM |
|---|---|---|---|
| `high-assurance` | Windows 11 | Microsoft Platform Crypto Provider | TPM 2.0 prêt et déverrouillé obligatoire |
| `compatible` | Windows 10 22H2 build 19045 ou Windows 11 | Microsoft Software Key Storage Provider | inutile |

`high-assurance` est le choix par défaut. Le mode compatible exige une décision
et un avertissement explicites de l'administrateur. La clé reste non exportable,
mais sans isolation matérielle. L'administrateur doit s'assurer que le poste est
maintenu et entièrement corrigé. Aucun basculement automatique n'existe.

Le mode d'un credential ne se modifie pas : il faut révoquer puis ré-enrôler.

## Installation Debian

Sur une Debian 13 vierge :

```bash
sudo ./install-vpn-server.sh
sudo audit-openvpn-lan-party
```

Le script installe OpenVPN Community 2.7.2+, Easy-RSA, miniupnpc, le portail
d'enrôlement et le Companion. Il crée la CA `OPENVPN LAN PARTY`, la CRL et la
clé serveur `tls-crypt-v2`, sans jamais générer de clé privée de joueur.

## Ajouter un joueur

```bash
sudo vpn-enrollment-admin create --player Arthur
```

Choisissez le mode proposé. Envoyez le lien du portail normalement, puis le mot
de passe de l'archive et le jeton à usage unique par un autre canal de confiance.

Le joueur extrait le ZIP, double-clique sur `JOIN-VPN.cmd`, accepte l'élévation,
saisit les deux secrets et garde la fenêtre ouverte. L'assistant vérifie le
bundle, installe OpenVPN/TAP si nécessaire, crée la clé CNG non exportable et
attend l'approbation.

Le terminal Debian affiche automatiquement le joueur, le CN, l'empreinte SPKI
complète et le code court. Comparez le code avec l'écran Windows puis répondez
`Y` ou `N`. Pour plusieurs demandes :

```bash
sudo vpn-enrollment-admin pool
```

Après approbation, l'assistant installe
`%USERPROFILE%\OpenVPN\config\OpenVPN-LAN-Party.ovpn`, teste la connexion,
confie la session persistante à OpenVPN GUI et démarre le Companion. Quitter le
Companion ne coupe pas le VPN.

## Renouvellement et révocation

Une nouvelle invitation avec le même nom renouvelle le credential sans changer
l'identité Companion. Confirmez la nouvelle connexion, puis révoquez l'ancienne :

```bash
sudo vpn-enrollment-admin confirm-connection IDENTIFIANT
sudo vpn-enrollment-admin revoke IDENTIFIANT --reason "credential remplacé"
```

## Départ complet d'un joueur

```bash
sudo vpn-enrollment-admin offboard \
  --player Arthur \
  --reason "départ du groupe"
```

La commande affiche l'inventaire et demande confirmation. Elle révoque tous les
certificats actifs, invalide les invitations, régénère la CRL, coupe les
sessions, retire l'accès Companion et conserve les traces d'audit.

Sur l'ancien PC, après cette révocation serveur :

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File "$env:LOCALAPPDATA\OpenVPN LAN Party Companion\Leave-OpenVPN-LAN-Party.ps1" `
  -RemoveCompanion
```

Le helper ne supprime que l'identité `OpenVPN-LAN-Party` vérifiée. L'option
`-RemoveCompanion` est obligatoire pour supprimer aussi l'identité locale
Companion ; les autres profils VPN restent intacts.

## Companion et confiance

Le Companion, accessible uniquement depuis le VPN, affiche présence, adresse,
temps de connexion et latence vers l'hôte. Il fournit messages publics/privés et
salons avec adresse, port, instructions, capacité, ready-check, phases, verrou
et transfert d'hôte.

Ne publiez jamais une vraie configuration `companion.json`, une invitation, un
profil `.ovpn` ni une clé. Les membres admis sur le VPN doivent rester des tiers
de confiance.
