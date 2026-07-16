# Operational TODO / Suivi opérationnel

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

## Français

Ce fichier est la liste d'actions concrètes. La priorité P0 consiste à valider
un vrai jeu sous Windows 10, la coexistence simultanée des deux modes,
l'installation avec audit complet sur une Debian 13 neuve et l'offboarding réel
du mode compatible.

La priorité P1 couvre la sauvegarde/restauration chiffrée, les alertes
d'expiration, la rotation des jetons Companion, la signature reproductible du
paquet Windows et l'élargissement de la matrice matérielle. L'attestation TPM
distante reste une recherche P2. Une case ne doit être cochée qu'avec une preuve
reproductible ne contenant aucun secret ni identité de joueur.
