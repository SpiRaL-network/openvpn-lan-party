# OpenVPN LAN Party 1.0.0

This release delivers a complete Debian 13 OpenVPN LAN server, protected
Windows enrollment and a bilingual LAN Party Companion.

Highlights:

- per-invitation TPM-backed high-assurance or software-backed compatible keys;
- both client policies coexist on one OpenVPN server;
- administrator-approved SPKI enrollment with one-time protected invitations;
- per-credential certificate, CRL and `tls-crypt-v2` protection;
- automatic OpenVPN Community and TAP-Windows6 setup;
- persistent OpenVPN GUI connection and Companion shortcuts;
- presence, latency, chat and game lobbies;
- complete player revocation and local Windows cleanup.

Compatible mode requires Windows 10 22H2 build 19045 or Windows 11 and carries
no TPM hardware isolation. The administrator must explicitly accept that policy
for each compatible invitation.

---

# OpenVPN LAN Party 1.0.0 — Français

Cette version fournit un serveur OpenVPN LAN complet pour Debian 13, un
enrôlement Windows protégé et un LAN Party Companion bilingue.

Points principaux : modes haute assurance TPM ou compatible choisis par
invitation sur le même serveur, approbation SPKI, certificat et
`tls-crypt-v2` individuels, installation automatique OpenVPN/TAP, connexion
persistante, présence, latence, messages, salons et offboarding complet.

Le mode compatible exige Windows 10 22H2 build 19045 ou Windows 11 et ne fournit
pas d'isolation TPM. L'administrateur doit l'accepter explicitement pour chaque
invitation.
