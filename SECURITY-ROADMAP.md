# Security roadmap

## Current baseline

- client-side non-exportable ECDSA P-256 keys;
- TPM-backed high-assurance mode and explicit software-backed compatible mode;
- full-SPKI administrator approval;
- individual certificate, CRL and `tls-crypt-v2` key per credential;
- bounded unprivileged portal separated from the root CA boundary;
- immediate credential revocation and complete player offboarding;
- no shared `tls-crypt`, compression or legacy cipher fallback.

## Validation status

Validated on real Windows hardware:

- Windows 11 high-assurance enrollment, non-exportable TPM key, persistent VPN
  connection and Companion startup;
- exact key-loss cleanup, revocation behavior and re-enrollment;
- Windows 10 22H2 compatible installation, enrollment and VPN connection.

Not yet validated as a complete matrix:

- real game traffic on the Windows 10 compatible endpoint;
- simultaneous high-assurance and compatible clients;
- compatible-mode offboarding on Windows 10;
- a fresh Debian 13 installation with an all-PASS security audit.

## Prioritized candidates

### P0 — complete acceptance

- finish the four open real-system tests listed above;
- record reproducible acceptance evidence without committing player identities,
  profiles, tokens, public addresses or TPM/CNG identifiers.

### P1 — operational security

- encrypted, documented backup and restore drills for CA and root-only state;
- richer revocation inventory and scheduled certificate-expiry notifications;
- Companion token rotation and recovery independent from VPN enrollment;
- signed Windows application packaging with reproducible provenance;
- a broader real-hardware matrix across maintained Windows editions.

### P2 — additional assurance

- optional remote TPM attestation where Windows and OpenVPN interoperability is
  demonstrably reliable and does not create a fragile enrollment dependency.

These items must not weaken the fail-closed behavior, introduce automatic
security-mode fallback or allow in-place conversion of a credential's key
provider.

## Recorded decisions

- ECDSA P-256 remains the required curve because it has the strongest verified
  interoperability across Windows CNG, TPM providers and OpenVPN Community.
- P-521 is not a security objective by itself and will not replace P-256 without
  cross-provider hardware evidence and a demonstrated system-level benefit.
- Unknown or mutually hostile players remain outside the threat model; adding
  network isolation would be a separate multi-tenant product.

---

## Feuille de route — Français

La base actuelle impose des clés P-256 CNG non exportables, l'approbation SPKI,
un certificat et une clé `tls-crypt-v2` par credential, une CRL et un portail
non privilégié séparé de la CA root.

Les parcours Windows 11 haute assurance, perte de clé/ré-enrôlement et Windows
10 22H2 compatible sont validés sur matériel réel. Restent prioritaires le test
avec un vrai jeu, la coexistence simultanée des deux modes, l'offboarding
compatible et l'audit d'une Debian 13 neuve.

Viennent ensuite les exercices chiffrés de sauvegarde/restauration, l'inventaire
de révocation et les alertes d'expiration, la rotation des jetons Companion, la
signature reproductible de l'application Windows et une matrice matérielle plus
large. L'attestation TPM distante reste exploratoire.

P-256 demeure le choix obligatoire pour l'interopérabilité vérifiée. P-521 ne
sera pas adopté sans preuve matérielle multi-fournisseur et bénéfice global
démontré. Aucun changement ne doit créer de fallback automatique, convertir un
credential existant ou transformer ce LAN de tiers de confiance en service
public multi-tenant.
