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
- Windows 11 compatible-mode offboarding and exact local cleanup with the VPN
  and Companion applications already closed.

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

# Feuille de route sécurité — Français

## Base actuelle

- clés ECDSA P-256 non exportables créées côté client ;
- mode haute assurance adossé au TPM et mode compatible logiciel explicite ;
- approbation administrateur de l'empreinte SPKI complète ;
- certificat, CRL et clé `tls-crypt-v2` individuels par credential ;
- portail non privilégié et borné, séparé de la frontière de la CA root ;
- révocation immédiate du credential et offboarding complet du joueur ;
- aucun `tls-crypt` partagé, compression ou fallback vers un chiffrement ancien.

## État de validation

Validé sur du vrai matériel Windows :

- enrôlement Windows 11 haute assurance, clé TPM non exportable, connexion VPN
  persistante et démarrage du Companion ;
- nettoyage exact après perte de clé, comportement de révocation et
  ré-enrôlement ;
- installation, enrôlement et connexion VPN compatibles sous Windows 10 22H2.
- offboarding compatible et nettoyage local exact sous Windows 11 avec les
  applications VPN et Companion déjà fermées.

Pas encore validé comme matrice complète :

- trafic d'un vrai jeu sur le poste compatible Windows 10 ;
- clients high-assurance et compatible connectés simultanément ;
- offboarding compatible sous Windows 10 ;
- installation Debian 13 neuve avec audit de sécurité entièrement PASS.

## Candidats priorisés

### P0 — terminer la recette

- terminer les quatre tests sur systèmes réels listés ci-dessus ;
- consigner des preuves de recette reproductibles sans commiter d'identités de
  joueurs, profils, jetons, adresses publiques ni identifiants TPM/CNG.

### P1 — sécurité opérationnelle

- exercices chiffrés et documentés de sauvegarde/restauration de la CA et de
  l'état réservé à root ;
- inventaire de révocation enrichi et notifications planifiées d'expiration des
  certificats ;
- rotation et récupération des jetons Companion indépendamment de l'enrôlement
  VPN ;
- paquet applicatif Windows signé avec provenance reproductible ;
- matrice matérielle réelle plus large sur les éditions Windows maintenues.

### P2 — assurance supplémentaire

- attestation TPM distante facultative lorsque l'interopérabilité Windows et
  OpenVPN est démontrée comme fiable et sans dépendance d'enrôlement fragile.

Ces éléments ne doivent ni affaiblir le comportement fail-closed, ni introduire
un fallback automatique du mode de sécurité, ni permettre la conversion en
place du fournisseur de clé d'un credential.

## Décisions enregistrées

- ECDSA P-256 reste la courbe obligatoire car elle offre la meilleure
  interopérabilité vérifiée entre Windows CNG, les fournisseurs TPM et OpenVPN
  Community.
- P-521 n'est pas un objectif de sécurité en soi et ne remplacera pas P-256 sans
  preuve matérielle multi-fournisseur et bénéfice système démontré.
- Les joueurs inconnus ou mutuellement hostiles restent hors du modèle de
  menace ; l'ajout d'une isolation réseau constituerait un produit multi-tenant
  distinct.
