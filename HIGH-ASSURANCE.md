# Security architecture

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

# Architecture de sécurité — Français

## Modèle de confiance

OpenVPN LAN Party protège l'accès à un LAN virtuel partagé par un petit groupe
de pairs de confiance. Il protège l'accès à ce LAN virtuel ; il ne cloisonne pas
les joueurs déjà admis.

## Frontière d'enrôlement

1. Root crée une invitation avec un identifiant de joueur stable, un nouvel UUID
   de credential, le CN exact du certificat, le mode de sécurité, l'expiration
   et un jeton à usage unique.
2. Le portail public ne stocke que le SHA-256 du jeton et fournit un ZIP borné.
3. Windows déchiffre l'invitation, vérifie le hash de chaque script et crée
   localement une clé ECDSA P-256.
4. Windows soumet uniquement une CSR PKCS#10. La clé privée ne quitte jamais
   CNG.
5. L'outil d'approbation root revalide le CN, l'algorithme, la courbe, les
   extensions et l'empreinte SPKI complète avant la signature.
6. Easy-RSA émet le certificat et OpenVPN crée une clé cliente
   `tls-crypt-v2` individuelle avec les métadonnées canoniques du credential.
7. La réponse à usage unique est supprimée après sa collecte ; seules
   l'identité publique du certificat et les métadonnées de révocation restent.

Le portail s'exécute sous `vpnportal` dans une unité systemd restreinte. Il ne
peut ni lire la clé de la CA ni invoquer la commande d'administration root.
L'opération de CA est sérialisée par un verrou root et accessible par une socket
Unix bornée.

## Politique par credential

- `high-assurance` : Windows 11, TPM 2.0, Microsoft Platform Crypto Provider.
- `compatible` : Windows 10 22H2 build 19045 ou Windows 11, Microsoft Software
  Key Storage Provider.

Les deux utilisent des clés ECDSA P-256 non exportables, la sélection par
empreinte exacte, des certificats individuels, l'application de la CRL,
`tls-crypt-v2`, TLS 1.2 minimum et des chiffrements de données AEAD. Le mode
compatible ne fournit pas d'isolation matérielle de la clé. Aucun fallback ne
se produit.

Le client officiel vérifie le fournisseur local, l'algorithme, la taille de clé
et le refus réel d'export. Le serveur n'implémente pas d'attestation TPM
distante ; un client altéré pourrait mentir sur son fournisseur local. Cette
limite n'est acceptée que dans le modèle de pairs de confiance.

## Révocation et offboarding

La révocation d'un credential s'effectue en deux phases : marquage en cours de
révocation, révocation dans la base Easy-RSA partagée, génération et validation
d'une nouvelle CRL, déploiement atomique, redémarrage d'OpenVPN pour couper les
sessions, puis marquage du credential comme révoqué dans le registre de
vérification `tls-crypt-v2`.

L'offboarding d'un joueur applique ce processus à chaque credential actif,
annule toutes les invitations et réponses à usage unique en attente, supprime
l'authentification Companion et désactive le mapping du joueur. L'historique des
enrôlements et les entrées PKI révoquées restent disponibles pour l'audit. Le
nettoyage local Windows est une action explicite et séparée.

## Périmètre cryptographique

P-256 est choisi intentionnellement pour sa large interopérabilité avec Windows
CNG, les TPM et OpenVPN Community. AES-256-GCM est préféré pour le canal de
données ; AES-128-GCM et ChaCha20-Poly1305 restent des alternatives modernes
négociées. Une courbe portant un nombre supérieur n'améliore pas
automatiquement le système si la compatibilité des fournisseurs ou la fiabilité
opérationnelle diminuent.

`tls-crypt-v2` authentifie et masque le canal de contrôle avant l'authentification
TLS normale et lie les métadonnées par credential. Il ne remplace ni X.509, ni
la CRL, ni l'exigence de pairs de confiance.
