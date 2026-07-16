# Project status

Version: `1.0.1`

## Delivered architecture

- Fresh Debian 13 installer with official OpenVPN Community 2.7.2+ packages.
- EC P-256 CA named `OPENVPN LAN PARTY`, individual certificates, CRL and
  individual `tls-crypt-v2` metadata.
- Per-invitation `high-assurance` and `compatible` modes on one server.
- Client-side non-exportable Windows CNG keys; no player private key on Debian.
- Protected portal ZIP, bilingual one-window setup, persistent OpenVPN GUI and
  exact-profile reconnect when the Companion starts.
- Root-only approval pool supporting simultaneous invitations.
- Single administration interface: `vpn-enrollment-admin`.
- Complete player offboarding and exact Windows local cleanup helper.
- Bilingual Companion with presence, chat and full game-lobby workflow.
- miniupnpc and optional ACME portal certificate automation.

## Validation gates

- Python unit and integration tests must pass.
- PowerShell scripts must parse under Windows PowerShell 5.1.
- Shell scripts must pass `bash -n`, `shellcheck` and `git diff --check`.
- Public documentation must contain complete English first, then complete
  French with equivalent sections, lists, commands, warnings and status.
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
- Compatible-mode offboarding and exact local cleanup completed on Windows 11
  after OpenVPN GUI and the Companion had been closed normally.

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

---

# État du projet — Français

Version : `1.0.1`

## Architecture livrée

- Installateur Debian 13 neuf avec les paquets officiels OpenVPN Community
  2.7.2+.
- CA EC P-256 nommée `OPENVPN LAN PARTY`, certificats individuels, CRL et
  métadonnées `tls-crypt-v2` individuelles.
- Modes `high-assurance` et `compatible` par invitation sur un même serveur.
- Clés Windows CNG non exportables créées côté client ; aucune clé privée de
  joueur sur Debian.
- ZIP protégé sur le portail, assistant bilingue à fenêtre unique, OpenVPN GUI
  persistant et reconnexion du profil exact au lancement du Companion.
- File d'approbation root prenant en charge les invitations simultanées.
- Interface d'administration unique : `vpn-enrollment-admin`.
- Offboarding complet du joueur et helper de nettoyage Windows exact.
- Companion bilingue avec présence, messages et workflow complet de salons.
- miniupnpc et automatisation facultative du certificat ACME du portail.

## Barrières de validation

- Les tests unitaires et d'intégration Python doivent réussir.
- Les scripts PowerShell doivent se parser sous Windows PowerShell 5.1.
- Les scripts shell doivent réussir `bash -n`, `shellcheck` et
  `git diff --check`.
- La documentation publique doit contenir d'abord l'anglais complet, puis le
  français complet avec des sections, listes, commandes, avertissements et
  statuts équivalents.
- Une installation Debian neuve doit réussir `audit-openvpn-lan-party`.
- L'enrôlement TPM Windows 11 réel, la connexion persistante, le lancement du
  Companion, la révocation et le ré-enrôlement exigent des preuves de recette.
- Le mode compatible exige une recette réelle Windows 10 22H2 build 19045 avant
  d'être annoncé comme validé sur matériel.

## Preuves de recette — 16 juillet 2026

Confirmé avec l'implémentation 1.0.x :

- les 91 tests automatisés du dépôt réussissent ;
- l'archive 1.0.1 a été construite depuis son tag annoté exact, retéléchargée
  depuis GitHub et vérifiée par SHA-256 ;
- l'enrôlement Windows 11 haute assurance crée une clé ECDSA P-256 avec
  Microsoft Platform Crypto Provider, refuse l'export de la clé privée, se
  connecte avec OpenVPN Community 2.7.5 et confie le tunnel persistant à OpenVPN
  GUI ;
- le nettoyage Windows exact après perte de clé, l'échec de réutilisation de
  l'identité supprimée et le ré-enrôlement du même joueur Companion ont réussi ;
- l'installation, l'enrôlement et la connexion VPN en mode compatible sous
  Windows 10 22H2 ont été confirmés sur matériel réel.
- l'offboarding compatible et le nettoyage local exact ont réussi sous Windows
  11 après la fermeture normale d'OpenVPN GUI et du Companion.

Encore requis pour une recette produit complète :

- trafic d'un vrai jeu sur le tunnel compatible Windows 10 ;
- test simultané d'un client high-assurance et d'un client compatible sur le
  même serveur ;
- installation complète et audit entièrement PASS sur un hôte Debian 13 neuf ;
- offboarding réel du mode compatible sous Windows 10.

La machine Debian de test actuelle conserve intentionnellement son ancienne CA
RSA et ses identités existantes. Ses services applicatifs fonctionnent, mais sa
CA ne peut pas satisfaire l'audit EC P-256 d'une installation fraîche et ne doit
pas être citée comme cette preuve de recette.

Le dépôt ne doit jamais contenir de bundles d'invitation, profils, clés privées,
bearer tokens, registres de credentials ou `companion.json` générés.
