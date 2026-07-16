# LAN Party Companion

The Companion is an authenticated coordination tool available only inside the
VPN, normally at `http://10.44.0.1:8787`.

## Identity

The enrollment response provisions a random Companion token on first enrollment.
The server stores only its SHA-256 hash. The Windows client stores its identity
in `%LOCALAPPDATA%\OpenVPN LAN Party Companion\companion.json`.

VPN credential renewal for the same player preserves this file and token.
Enrollment for another player is rejected before key creation. Complete server
offboarding removes the token; local deletion of `companion.json` occurs only
through the explicit Windows offboarding helper with `-RemoveCompanion`.

Never publish, replace or casually delete a real `companion.json`.

## Features

- authenticated presence derived from the VPN source address;
- connection duration and latency to the Companion host;
- bilingual English/French Windows interface;
- public and private messages with server-derived sender identity;
- lobbies with game, address, optional port and connection instructions;
- capacity, membership, ready check, gathering/in-game phases and lock;
- host transfer, reconnect grace and revision-based conflict protection;
- tray actions to quit the Companion with or without disconnecting the exact
  `OpenVPN-LAN-Party` profile.

The host enters game connection details. Automatic game command-line discovery
is outside the current product scope.

## Operational behavior

OpenVPN GUI owns the persistent tunnel. Closing the Companion leaves the VPN
connected. **Quit Companion and disconnect VPN** targets only the managed
OpenVPN GUI profile and never terminates unrelated VPN processes.

The server reloads its player registry when it changes, so offboarding removes
access without restarting the Companion service. Lobby locks are application
controls, not firewalls.

---

## Français

Le Companion est un outil de coordination authentifié, accessible uniquement
depuis le VPN. Il affiche présence, adresse VPN, temps de connexion et latence,
puis fournit messagerie et salons de jeu.

Le premier enrôlement crée un jeton aléatoire ; le serveur n'en conserve que le
hash SHA-256. Un renouvellement VPN pour le même joueur préserve
`companion.json`. Une invitation au nom d'un autre joueur est refusée. Seul
l'offboarding complet retire l'accès serveur ; la suppression locale exige
explicitement `Leave-OpenVPN-LAN-Party.ps1 -RemoveCompanion`.

Quitter le Companion ne coupe pas le VPN. L'action **Quitter le Companion et
déconnecter le VPN** déconnecte uniquement `OpenVPN-LAN-Party`. Le verrou d'un
salon n'est pas un pare-feu : tous les membres du VPN restent des tiers de
confiance.
