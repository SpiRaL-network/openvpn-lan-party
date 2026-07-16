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
[COMPANION.md](COMPANION.md), [ACCEPTANCE.md](ACCEPTANCE.md),
[SECURITY-ROADMAP.md](SECURITY-ROADMAP.md) and [TODO.md](TODO.md).

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

## Fonctionnalités fournies

- OpenVPN Community 2.7.2+ en mode TAP avec des chiffrements AEAD modernes ;
- une CA EC P-256 nommée `OPENVPN LAN PARTY` et des certificats clients
  individuels ;
- des clés privées Windows CNG non exportables créées côté client ;
- un enrôlement CSR approuvé par l'administrateur et une révocation CRL
  immédiate ;
- une clé `tls-crypt-v2` individuelle pour chaque credential ;
- une invitation Windows protégée par mot de passe et téléchargée depuis le
  portail ;
- l'installation automatique d'OpenVPN/TAP et un assistant Windows bilingue ;
- une connexion OpenVPN GUI persistante et indépendante du Companion ;
- la présence, la durée de connexion, la latence vers l'hôte, les messages et
  les salons de jeu ;
- le mapping de ports miniupnpc facultatif et l'automatisation TLS publique
  facultative du portail.

## Modes de sécurité

L'administrateur choisit un mode pour chaque invitation. Les deux modes peuvent
coexister sur le même serveur et utilisent la même CA, le même VPN, la même CRL
et la même politique de chiffrement moderne.

| Mode | Client | Protection de la clé | TPM |
|---|---|---|---|
| `high-assurance` | Windows 11 | Microsoft Platform Crypto Provider | TPM 2.0 prêt et déverrouillé obligatoire |
| `compatible` | Windows 10 22H2 build 19045 ou Windows 11 | Microsoft Software Key Storage Provider | inutile |

`high-assurance` est le choix par défaut. Le mode compatible exige une décision
et un avertissement explicites de l'administrateur. La clé reste non exportable,
mais sans isolation matérielle. L'administrateur doit s'assurer que le poste est
maintenu et entièrement corrigé. Aucun basculement automatique n'existe.

Le mode d'un credential ne se modifie pas : il faut révoquer puis ré-enrôler.

## Installer le serveur

Prérequis :

- un hôte ou une VM Debian 13 vierge avec accès root ;
- une adresse IPv4 publique ou un nom DNS ;
- les ports UDP 1194 et TCP 8790 redirigés vers l'hôte Debian ;
- uniquement des joueurs de confiance.

Exécutez :

```bash
sudo ./install-vpn-server.sh
```

L'installateur refuse d'écraser une PKI, un serveur OpenVPN ou une configuration
Companion existants. Il demande confirmation avant d'installer des paquets et
peut configurer miniupnpc.

Validez le résultat :

```bash
sudo audit-openvpn-lan-party
sudo systemctl status openvpn-server@server.service
sudo systemctl status vpn-enrollment-portal.service
sudo systemctl status lan-party-companion.service
```

## Ajouter un joueur

Exécutez l'unique commande d'administration :

```bash
sudo vpn-enrollment-admin create --player Arthur
```

Le terminal propose :

1. `high-assurance` (par défaut) ;
2. `compatible` avec une confirmation explicite du risque.

Pour une création non interactive contrôlée :

```bash
sudo vpn-enrollment-admin create \
  --player Arthur \
  --security-mode compatible \
  --ack-compatible-risk \
  --no-wait
```

La sortie contient une URL de téléchargement du portail, le mot de passe de
l'archive et un jeton à usage unique. Le jeton n'est stocké ni dans le ZIP ni
dans l'URL. Envoyez le lien normalement, mais transmettez le mot de passe de
l'archive et le jeton par un canal de confiance séparé.

Si un service local compatible sendmail est configuré, cette commande envoie
uniquement le lien :

```bash
sudo vpn-enrollment-admin create \
  --player Arthur \
  --email-to arthur@example.net
```

### Parcours du joueur Windows

Le joueur :

1. télécharge et extrait le ZIP avec l'Explorateur Windows ;
2. double-clique sur `JOIN-VPN.cmd` ;
3. accepte l'élévation ;
4. saisit le mot de passe de l'archive et le jeton à usage unique ;
5. laisse l'assistant ouvert pendant l'approbation de l'administrateur.

L'assistant vérifie l'invitation, installe ou met à jour le MSI OpenVPN Community
signé avec TAP-Windows6 si nécessaire, crée la clé non exportable, soumet la
CSR, installe le certificat et le profil, teste le tunnel, confie la connexion
persistante à OpenVPN GUI et démarre le Companion.

Le profil est `%USERPROFILE%\OpenVPN\config\OpenVPN-LAN-Party.ovpn`. Fermer le
Companion ne déconnecte pas le VPN. Les raccourcis de démarrage et du menu
Démarrer reconnectent le VPN sans nouvel enrôlement.

### Approbation de l'administrateur

Le terminal Debian affiche automatiquement le joueur, le CN, l'empreinte SPKI
complète et le code court. Comparez le code avec l'écran Windows puis répondez
`Y` ou `N`.

Pour plusieurs invitations simultanées :

```bash
sudo vpn-enrollment-admin create --player Arthur --no-wait
sudo vpn-enrollment-admin create --player Beatrice --no-wait
sudo vpn-enrollment-admin pool
```

La file affiche une liste numérotée et revalide la CSR sélectionnée juste avant
la signature. Les invites d'administration du serveur sont uniquement en
anglais.

## Renouveler ou remplacer un credential

Créez une autre invitation avec le même nom de joueur. L'UUID technique du
credential et le certificat sont renouvelés ; l'identité stable du joueur et le
`companion.json` existant sont préservés. Révoquez l'ancien enrôlement après
avoir confirmé la nouvelle connexion :

```bash
sudo vpn-enrollment-admin confirm-connection ENROLLMENT_ID
sudo vpn-enrollment-admin revoke ENROLLMENT_ID --reason "credential remplacé"
```

## Retirer complètement un joueur

L'offboarding serveur fait autorité :

```bash
sudo vpn-enrollment-admin offboard \
  --player Arthur \
  --reason "départ du groupe"
```

La commande inventorie les enregistrements du joueur, demande confirmation,
révoque chaque certificat actif, met à jour la CRL et le registre
`tls-crypt-v2`, coupe les sessions actives, invalide les invitations en attente,
retire l'accès Companion et désactive le mapping du joueur. Les enregistrements
révoqués restent disponibles pour l'audit.

Sur le PC Windows retiré, exécutez le nettoyage local après l'offboarding
serveur :

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File "$env:LOCALAPPDATA\OpenVPN LAN Party Companion\Leave-OpenVPN-LAN-Party.ps1" `
  -RemoveCompanion
```

Le helper valide et supprime uniquement `OpenVPN-LAN-Party` : son profil exact,
son certificat, sa clé CNG non exportable, ses raccourcis et — uniquement avec
`-RemoveCompanion` — l'identité Companion locale. Il ne cible jamais un autre
profil VPN.

## Companion

Le Companion écoute uniquement sur l'adresse VPN, normalement
`http://10.44.0.1:8787`. Son interface Windows bilingue anglais/français fournit
la présence authentifiée, l'adresse VPN, la durée de connexion, la latence vers
l'hôte, les messages publics/privés et des salons contenant l'adresse de jeu,
le port facultatif et les instructions fournis par l'hôte. L'état d'un salon
comprend capacité, ready checks, phases rassemblement/en jeu, verrou, transfert
d'hôte et protection des conflits par révision.

Le jeton Companion est indépendant du certificat VPN. Le renouvellement d'un
credential le préserve ; l'offboarding complet du joueur le supprime.

## Frontières de sécurité

- Clés de la CA et du serveur : `/root/openvpn-pki`, root uniquement.
- État d'enrôlement : `/var/lib/openvpn-lan-party/enrollment`, root uniquement.
- Snapshot public des credentials :
  `/var/lib/openvpn/credential-registry.json`.
- Configuration et TLS du portail : `/etc/openvpn-lan-party`.
- Configuration Companion : `/etc/openvpn-lan-companion`.

Le portail exposé à Internet s'exécute sous `vpnportal`, ne peut pas lire la clé
de la CA et ne peut traiter que du matériel CSR public et borné. Root effectue
une validation CSR indépendante avant la signature. Ne publiez jamais de
profils générés, de clés privées, de payloads d'invitation ni un vrai
`companion.json`.

Consultez [HIGH-ASSURANCE.md](HIGH-ASSURANCE.md), [SECURITY.md](SECURITY.md),
[COMPANION.md](COMPANION.md), [ACCEPTANCE.md](ACCEPTANCE.md),
[SECURITY-ROADMAP.md](SECURITY-ROADMAP.md) et [TODO.md](TODO.md).

## Développement

```bash
python3 -m unittest discover -s tests -v
git diff --check
shellcheck install-vpn-server.sh assets/vpn-enrollment-admin.in \
  assets/audit-openvpn-lan-party
```

`build-release.sh` exige une arborescence de travail propre et un tag annoté
correspondant à `VERSION`. Il refuse les secrets générés, profils, invitations
et `companion.json`.
