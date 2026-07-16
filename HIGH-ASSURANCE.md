# Security architecture / Architecture de sécurité

## Trust model

OpenVPN LAN Party serves one small group of trusted peers. It protects access
to that virtual LAN; it does not isolate admitted players from one another.

## Enrollment boundary

1. Root creates an invitation with a stable player ID, new credential UUID,
   exact certificate CN, security mode, expiry and one-time token.
2. The public portal stores the token only as SHA-256 and serves a bounded ZIP.
3. Windows decrypts the invitation, verifies every script hash and creates an
   ECDSA P-256 key locally.
4. Windows submits only a PKCS#10 CSR. The private key never leaves CNG.
5. The root-only approval tool revalidates the CN, algorithm, curve, extensions
   and full SPKI fingerprint before signing.
6. Easy-RSA issues the certificate and OpenVPN creates an individual
   `tls-crypt-v2` client key with canonical credential metadata.
7. The one-time response is removed after collection; only public certificate
   identity and revocation metadata remain.

The portal runs as `vpnportal` under a restricted systemd unit. It cannot read
the CA key or invoke the root administration command. The CA operation is
serialized by a root-only lock and reached through a bounded Unix socket.

## Per-credential policy

- `high-assurance`: Windows 11, TPM 2.0, Microsoft Platform Crypto Provider.
- `compatible`: Windows 10 22H2 build 19045 or Windows 11, Microsoft Software
  Key Storage Provider.

Both use non-exportable ECDSA P-256 keys, exact thumbprint selection, individual
certificates, CRL enforcement, `tls-crypt-v2`, TLS 1.2 minimum and AEAD data
ciphers. Compatible mode lacks hardware key isolation. No fallback occurs.

The official client verifies the local provider, algorithm, key size and actual
export refusal. The server does not implement remote TPM attestation; an altered
client could lie about its local provider. This is accepted only within the
trusted-peer model.

## Revocation and offboarding

Credential revocation is two-phase: mark revoking, revoke in the shared
Easy-RSA database, generate and validate a fresh CRL, deploy it atomically,
restart OpenVPN to cut sessions, then mark the credential revoked in the
`tls-crypt-v2` verification registry.

Player offboarding applies that process to every active credential, cancels all
pending invitations and one-time responses, removes Companion authentication
and retires the player mapping. Historical enrollment records and revoked PKI
entries remain for audit. Windows local cleanup is a separate, explicit action.

## Cryptographic scope

P-256 is intentionally used for broad Windows CNG, TPM and OpenVPN Community
interoperability. AES-256-GCM is preferred for the data channel; AES-128-GCM and
ChaCha20-Poly1305 remain modern negotiated alternatives. Larger curve numbers
do not automatically improve the system if provider support or operational
reliability decreases.

`tls-crypt-v2` authenticates and hides the control channel before normal TLS
authentication and binds per-credential metadata. It does not replace X.509,
the CRL or the trusted-peer requirement.

---

## Architecture — Français

OpenVPN LAN Party protège l'accès à un LAN virtuel partagé par un petit groupe
de confiance. Il ne cloisonne pas les joueurs déjà admis.

La clé ECDSA P-256 est créée sur Windows et reste non exportable dans CNG. Seule
la CSR PKCS#10 atteint le portail. L'outil root revalide le CN, la courbe, les
extensions et l'empreinte SPKI complète avant signature. Chaque credential
reçoit son certificat et sa clé `tls-crypt-v2` individuels.

Le mode `high-assurance` exige Windows 11, un TPM 2.0 prêt et Microsoft Platform
Crypto Provider. Le mode `compatible` accepte Windows 10 22H2 build 19045 ou
Windows 11 avec Microsoft Software Key Storage Provider. Les deux modes
coexistent sur le serveur, mais aucun credential ne change de mode en place et
aucun fallback automatique n'est autorisé.

La révocation régénère la CRL, invalide les métadonnées `tls-crypt-v2` et coupe
les sessions. L'offboarding applique cette révocation à toutes les identités du
joueur, invalide les invitations et supprime son accès Companion, tout en
conservant les preuves d'audit.
