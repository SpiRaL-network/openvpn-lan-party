# Operational TODO

This is the actionable tracker. `SECURITY-ROADMAP.md` records strategic
direction, while `ACCEPTANCE.md` defines the normative test procedure. Mark an
item complete only when reproducible evidence exists and contains no deployment
secret or player identity.

## P0 — acceptance completion

- [ ] Test real game traffic through a Windows 10 22H2 compatible tunnel,
  including direct-IP connection and LAN discovery where the game supports it.
- [ ] Connect one high-assurance Windows 11 client and one compatible client at
  the same time; verify VPN traffic, Companion presence and game reachability.
- [ ] Install on a fresh Debian 13 host and obtain only PASS results from
  `audit-openvpn-lan-party` with the `OPENVPN LAN PARTY` EC P-256 CA.
- [ ] Offboard a compatible identity on real Windows 10 hardware and verify
  immediate server cutoff plus exact local cleanup.

## P1 — operational hardening

- [ ] Document, encrypt and exercise backup/restore of the CA, CRL, enrollment
  state, credential registry and Companion server identity.
- [ ] Add a richer revocation and certificate-expiry inventory with scheduled
  administrator notifications.
- [ ] Design Companion token rotation and recovery independently from VPN
  certificate renewal.
- [ ] Produce signed Windows packaging with reproducible provenance.
- [ ] Expand the real-hardware test matrix across maintained Windows 11 builds
  and explicitly accepted Windows 10 22H2 environments.

## P2 — research

- [ ] Re-evaluate remote TPM attestation only if Windows and OpenVPN integration
  can remain reliable and fail closed.

## Completed baseline

- [x] Windows 11 TPM-backed high-assurance enrollment and persistent connection.
- [x] Non-exportable ECDSA P-256 key verification and failed export test.
- [x] Exact key-loss cleanup, revoked-profile failure and re-enrollment.
- [x] Windows 10 22H2 compatible installation, enrollment and VPN connection.
- [x] Bilingual protected invitation, guided approval pool and persistent
  OpenVPN GUI handoff.
- [x] Complete server-side player offboarding and exact Windows cleanup tooling.

---

# Suivi opérationnel — Français

Ce fichier est le suivi des actions concrètes. `SECURITY-ROADMAP.md` consigne
l'orientation stratégique, tandis que `ACCEPTANCE.md` définit la procédure de
recette normative. Une tâche ne doit être marquée comme terminée que lorsqu'une
preuve reproductible existe et ne contient aucun secret de déploiement ni
identité de joueur.

## P0 — terminer la recette

- [ ] Tester le trafic d'un vrai jeu à travers un tunnel compatible Windows 10
  22H2, avec connexion directe par IP et découverte LAN lorsque le jeu la prend
  en charge.
- [ ] Connecter simultanément un client Windows 11 high-assurance et un client
  compatible ; vérifier le trafic VPN, la présence Companion et l'accès au jeu.
- [ ] Installer sur un hôte Debian 13 neuf et obtenir uniquement des résultats
  PASS avec `audit-openvpn-lan-party` et la CA EC P-256
  `OPENVPN LAN PARTY`.
- [ ] Offboarder une identité compatible sur du vrai matériel Windows 10 et
  vérifier la coupure serveur immédiate ainsi que le nettoyage local exact.

## P1 — durcissement opérationnel

- [ ] Documenter, chiffrer et tester la sauvegarde/restauration de la CA, de la
  CRL, de l'état d'enrôlement, du registre des credentials et de l'identité du
  serveur Companion.
- [ ] Ajouter un inventaire de révocation et d'expiration des certificats plus
  riche, avec notifications administrateur planifiées.
- [ ] Concevoir la rotation et la récupération des jetons Companion
  indépendamment du renouvellement des certificats VPN.
- [ ] Produire un paquet Windows signé avec provenance reproductible.
- [ ] Étendre la matrice de test sur matériel réel aux builds Windows 11
  maintenus et aux environnements Windows 10 22H2 explicitement acceptés.

## P2 — recherche

- [ ] Réévaluer l'attestation TPM distante uniquement si l'intégration Windows
  et OpenVPN peut rester fiable et fail-closed.

## Base terminée

- [x] Enrôlement Windows 11 haute assurance adossé au TPM et connexion
  persistante.
- [x] Vérification de la clé ECDSA P-256 non exportable et échec d'un export
  réel.
- [x] Nettoyage exact après perte de clé, échec du profil révoqué et
  ré-enrôlement.
- [x] Installation, enrôlement et connexion VPN compatibles sous Windows 10
  22H2.
- [x] Invitation protégée bilingue, file d'approbation guidée et transfert
  persistant vers OpenVPN GUI.
- [x] Offboarding serveur complet du joueur et outil de nettoyage Windows exact.
