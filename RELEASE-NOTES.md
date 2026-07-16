# OpenVPN LAN Party 1.0.2

This corrective release improves Windows cleanup and Companion startup:

- compatible-mode cleanup uses the logical CNG key container name and its
  partial-cleanup recovery is validated on Windows 10;
- Companion removal waits for its PowerShell and command-launcher processes,
  retries transient directory locks and can resume after a partial cleanup;
- launching the Companion reconnects only the exact managed
  `OpenVPN-LAN-Party` profile when its VPN service is unreachable;
- public documentation now contains complete English followed by complete
  French with automated structural-parity checks.

Automatic VPN reconnection validates the exact managed profile, rejects
ambiguous or reparse-point paths, waits at most 60 seconds and remains
non-blocking after failure. It never creates a new credential or targets another
VPN profile.

Real-hardware automatic reconnect remains an explicit acceptance task for
Windows 10 and Windows 11.

No PKI, enrollment protocol, archive format, certificate policy or VPN profile
format changes in this release. Existing 1.0.1 identities remain compatible and
do not require re-enrollment.

---

# OpenVPN LAN Party 1.0.2 — Français

Cette version corrective améliore le nettoyage Windows et le démarrage du
Companion :

- le nettoyage compatible utilise le nom logique du conteneur de clé CNG et sa
  reprise après nettoyage partiel est validée sous Windows 10 ;
- la suppression du Companion attend ses processus PowerShell et son lanceur de
  commandes, réessaie les verrouillages transitoires du dossier et peut reprendre
  après un nettoyage partiel ;
- lancer le Companion reconnecte uniquement le profil géré exact
  `OpenVPN-LAN-Party` lorsque son service VPN est injoignable ;
- la documentation publique contient désormais l'anglais complet suivi du
  français complet, avec contrôle automatisé de parité structurelle.

La reconnexion VPN automatique valide le profil géré exact, refuse les chemins
ambigus ou de type reparse point, attend au maximum 60 secondes et reste non
bloquante après un échec. Elle ne crée jamais de nouveau credential et ne cible
aucun autre profil VPN.

La reconnexion automatique sur matériel réel reste une tâche de recette
explicite sous Windows 10 et Windows 11.

Cette version ne modifie ni la PKI, ni le protocole d'enrôlement, ni le format de
l'archive, ni la politique de certificat, ni le format du profil VPN. Les
identités 1.0.1 existantes restent compatibles et ne nécessitent aucun
ré-enrôlement.
