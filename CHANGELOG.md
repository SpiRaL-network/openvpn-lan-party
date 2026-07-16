# Changelog

## 1.0.2

- Fix compatible-mode cleanup to use the logical CNG key container name.
- Make Companion removal wait for its PowerShell and command-launcher processes,
  retry locked-directory deletion and recover after a partial cleanup.
- Reconnect the exact managed VPN profile automatically when the Companion
  starts while its service is unreachable.

## 1.0.1

- Clarify that the first Windows onboarding secret is the archive password.
- Keep the archive password distinct from the one-time enrollment token in
  both English and French.

## 1.0.0

- Debian 13 OpenVPN LAN deployment with TAP-Windows6 clients.
- Client-side non-exportable ECDSA P-256 credentials.
- Per-invitation high-assurance and compatible security policies.
- Protected portal invitations and guided administrator approval pool.
- Individual `tls-crypt-v2` keys, CRL revocation and immediate session cutoff.
- Automated bilingual Windows enrollment and persistent OpenVPN GUI connection.
- Bilingual Companion with authenticated presence, chat and game lobbies.
- Complete server and Windows offboarding procedures.
- miniupnpc and optional public portal TLS automation.

---

# Journal des modifications — Français

## 1.0.2

- Correction du nettoyage compatible pour utiliser le nom logique du conteneur
  de clé CNG.
- Attente des processus PowerShell et du lanceur de commandes lors de la
  suppression du Companion, nouvelles tentatives si le dossier est verrouillé
  et reprise possible après un nettoyage partiel.
- Reconnexion automatique du profil VPN géré exact lorsque le Companion démarre
  alors que son service est injoignable.

## 1.0.1

- Clarification : le premier secret demandé par l'assistant Windows est le mot
  de passe de l'archive.
- Distinction explicite entre le mot de passe de l'archive et le jeton
  d'enrôlement à usage unique, en anglais comme en français.

## 1.0.0

- Déploiement d'un LAN OpenVPN sur Debian 13 avec des clients TAP-Windows6.
- Credentials ECDSA P-256 non exportables créés côté client.
- Politiques de sécurité high-assurance et compatible choisies par invitation.
- Invitations protégées sur le portail et file d'approbation administrateur
  guidée.
- Clés `tls-crypt-v2` individuelles, révocation CRL et coupure immédiate des
  sessions.
- Enrôlement Windows bilingue automatisé et connexion OpenVPN GUI persistante.
- Companion bilingue avec présence authentifiée, messages et salons de jeu.
- Procédures complètes d'offboarding serveur et Windows.
- miniupnpc et automatisation TLS publique facultative du portail.
