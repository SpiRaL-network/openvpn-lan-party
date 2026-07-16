# Security roadmap

## Current baseline

- client-side non-exportable ECDSA P-256 keys;
- TPM-backed high-assurance mode and explicit software-backed compatible mode;
- full-SPKI administrator approval;
- individual certificate, CRL and `tls-crypt-v2` key per credential;
- bounded unprivileged portal separated from the root CA boundary;
- immediate credential revocation and complete player offboarding;
- no shared `tls-crypt`, compression or legacy cipher fallback.

## Candidates

- signed Windows application packaging with reproducible provenance;
- optional remote TPM attestation where Windows and OpenVPN interoperability is
  demonstrably reliable;
- Companion token rotation and recovery independent from VPN enrollment;
- encrypted, documented backup and restore drills for CA and root-only state;
- richer revocation inventory and scheduled certificate-expiry notifications;
- real-hardware compatible-mode test matrix across maintained Windows editions.

These items must not weaken the fail-closed behavior, introduce automatic
security-mode fallback or allow in-place conversion of a credential's key
provider.

---

## Feuille de route — Français

La base actuelle impose des clés P-256 CNG non exportables, l'approbation SPKI,
un certificat et une clé `tls-crypt-v2` par credential, une CRL et un portail
non privilégié séparé de la CA root.

Les recherches futures concernent la signature reproductible de l'application
Windows, l'attestation TPM distante si elle devient fiable, la rotation séparée
des jetons Companion, les exercices de sauvegarde/restauration et une matrice
matérielle plus large. Aucun changement ne doit créer de fallback automatique
ni convertir un credential existant d'un fournisseur de clé vers un autre.
