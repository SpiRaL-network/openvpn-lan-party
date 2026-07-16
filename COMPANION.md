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

# LAN Party Companion — Français

Le Companion est un outil de coordination authentifié, accessible uniquement
depuis le VPN, normalement à l'adresse `http://10.44.0.1:8787`.

## Identité

La réponse d'enrôlement fournit un jeton Companion aléatoire lors du premier
enrôlement. Le serveur ne stocke que son hash SHA-256. Le client Windows stocke
son identité dans
`%LOCALAPPDATA%\OpenVPN LAN Party Companion\companion.json`.

Le renouvellement du credential VPN pour le même joueur préserve ce fichier et
ce jeton. L'enrôlement d'un autre joueur est refusé avant la création de clé.
L'offboarding serveur complet supprime le jeton ; la suppression locale de
`companion.json` n'a lieu qu'avec le helper d'offboarding Windows explicite et
l'option `-RemoveCompanion`.

Ne publiez, ne remplacez et ne supprimez jamais sans raison un vrai
`companion.json`.

## Fonctionnalités

- présence authentifiée à partir de l'adresse source VPN ;
- durée de connexion et latence vers l'hôte Companion ;
- interface Windows bilingue anglais/français ;
- messages publics et privés avec identité de l'expéditeur dérivée du serveur ;
- salons avec jeu, adresse, port facultatif et instructions de connexion ;
- capacité, membres, ready check, phases rassemblement/en jeu et verrou ;
- transfert d'hôte, délai de reconnexion et protection des conflits par
  révision ;
- actions de la zone de notification pour quitter le Companion avec ou sans
  déconnecter le profil exact `OpenVPN-LAN-Party`.

L'hôte saisit les informations de connexion au jeu. La détection automatique
des lignes de commande des jeux est hors du périmètre actuel du produit.

## Comportement opérationnel

Quitter le Companion ne coupe pas le VPN. L'action **Quitter le Companion et
déconnecter le VPN** cible uniquement le profil OpenVPN GUI géré et ne termine
jamais les processus VPN sans rapport.

Le serveur recharge son registre des joueurs lorsqu'il change ; l'offboarding
retire donc l'accès sans redémarrer le service Companion. Les verrous de salon
sont des contrôles applicatifs, pas des pare-feu.
