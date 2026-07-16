#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'companion.json'),
    [switch]$StartMinimized
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

$script:ClientVersion = '1.0.2'
$script:StatusIds = @('online', 'afk', 'busy')
$script:RequiredServerFeatures = @(
    'presence_duration',
    'manual_availability',
    'join_instructions',
    'ready_check',
    'lobby_phases',
    'lobby_lock',
    'host_transfer',
    'lobby_revisions'
)
$script:ColorIds = @('blue', 'green', 'orange', 'purple', 'pink', 'teal', 'gold', 'gray')
$script:Texts = @{
    en = @{
        app_title = 'LAN Party Companion'
        language = 'Language:'
        player = 'Player:'
        status = 'Status:'
        apply = 'Apply'
        latency = 'Host latency'
        diagnostics = 'Diagnostics'
        diagnostic_client = 'Client version'
        diagnostic_server = 'Server version'
        diagnostic_server_url = 'Server address'
        diagnostic_connection = 'Service status'
        diagnostic_api = 'API version'
        diagnostic_player = 'Player'
        diagnostic_vpn_ip = 'VPN address'
        diagnostic_session = 'Connected time'
        diagnostic_lobby = 'Current lobby'
        diagnostic_latency = 'Host latency probe'
        enabled = 'Enabled'
        disabled = 'Disabled'
        reachable = 'Reachable'
        unreachable = 'Unreachable'
        none = 'None'
        players = 'Players'
        messages = 'Messages'
        lobbies = 'Lobbies'
        pseudo = 'Player'
        vpn_ip = 'VPN address'
        ping = 'Ping'
        last_seen = 'Connection / last seen'
        target = 'Recipient:'
        everyone = 'Everyone'
        message_color = 'Color:'
        send = 'Send'
        game = 'Game:'
        lobby_name = 'Lobby name:'
        join_instructions = 'How to join:'
        connection_info = 'Connection info'
        no_instructions = 'No additional instructions.'
        port_known = 'Port known'
        port = 'Port'
        capacity = 'Capacity:'
        publish_lobby = 'Publish / update'
        join_lobby = 'Join lobby'
        copy_address = 'Copy connection info'
        lobby = 'Lobby'
        host = 'Host'
        address = 'VPN address'
        occupancy = 'Players'
        lobby_state = 'State'
        phase_gathering = 'Gathering'
        phase_in_game = 'In game'
        access_open = 'Open'
        access_locked = 'Locked'
        members = 'Members'
        ready_column = 'Ready'
        ready_short = '{0} ready'
        role_column = 'Role'
        role_host = 'Host'
        role_member = 'Member'
        ready_yes = 'Yes'
        ready_no = 'No'
        mark_ready = 'I am ready'
        mark_not_ready = 'Not ready'
        start_game = 'Start game'
        resume_gathering = 'Return to lobby'
        lock_lobby = 'Lock'
        lock_hint = 'Blocks new Companion members; this is not a network firewall.'
        unlock_lobby = 'Unlock'
        transfer_host = 'Transfer host'
        transfer_target_required = 'Select the new host.'
        confirm_transfer_host = 'Transfer host rights to {0}?'
        copy_connection = 'Copy connection info'
        lobby_chat = 'Lobby chat'
        time_column = 'Time'
        sender_column = 'Sender'
        message_column = 'Message'
        status_column = 'Status'
        game_column = 'Game'
        lobby_name_column = 'Lobby name'
        leave_lobby = 'Leave lobby'
        close_lobby = 'Close lobby'
        confirm_leave_lobby = 'Leave this lobby?'
        confirm_close_lobby = 'Close this lobby for every member?'
        open_app = 'Open'
        quit_menu = 'Quit...'
        exit_app = 'Quit Companion'
        exit_and_disconnect_vpn = 'Quit Companion and disconnect VPN'
        confirm_disconnect_vpn = 'Disconnect OpenVPN LAN Party and quit the Companion?'
        vpn_disconnect_failed = 'OpenVPN LAN Party could not be disconnected: {0}'
        vpn_connecting = 'Connecting OpenVPN LAN Party…'
        vpn_connect_failed = 'OpenVPN LAN Party could not be connected automatically: {0}'
        vpn_profile_missing = 'The managed OpenVPN-LAN-Party profile was not found.'
        vpn_profile_ambiguous = 'More than one managed OpenVPN-LAN-Party profile exists.'
        vpn_profile_invalid = 'The OpenVPN-LAN-Party profile is not a valid managed profile.'
        vpn_gui_missing = 'OpenVPN GUI is not installed in the expected location.'
        vpn_connect_timeout = 'The VPN did not become reachable within 60 seconds.'
        connected = 'Connected to LAN Party Companion'
        connected_details = 'Connected — server v{0} — session {1}'
        activity_lobby = 'In lobby'
        activity_game = 'In game'
        offline = 'Offline'
        never_seen = 'Never seen'
        just_now = 'Just now'
        minutes_ago = '{0} min ago'
        hours_ago = '{0} h ago'
        unavailable = 'Unavailable'
        selected_required = 'Select a lobby first.'
        game_required = 'Enter a game name.'
        lobby_name_required = 'Enter a lobby name.'
        address_unavailable = 'This lobby host is temporarily offline.'
        address_copied = 'Connection info copied.'
        launch_hint = 'Open the game and use its direct-connect or LAN screen.'
        hidden_to_tray = 'The application remains active near the Windows clock.'
        already_running = 'LAN Party Companion is already running.'
        start_failed = 'LAN Party Companion cannot start:'
        request_failed = 'Operation failed: {0}'
        message_not_sent = 'Message not sent: {0}'
        lobby_message_not_sent = 'Lobby message not sent: {0}'
        member_joined = '{0} joined the lobby.'
        member_left = '{0} left the lobby.'
        game_started = '{0} started the game.'
        gathering_resumed = '{0} returned the lobby to gathering.'
        lobby_locked = '{0} locked the lobby.'
        lobby_unlocked = '{0} unlocked the lobby.'
        host_transferred = '{0} is now the lobby host.'
        server_restarted = 'The Companion service restarted; ephemeral lobbies may have closed.'
        status_online = 'Online'
        status_ready = 'Ready'
        status_afk = 'AFK'
        status_busy = 'Busy'
        status_in_game = 'In game'
        status_offline = 'Offline'
        color_blue = 'Blue'
        color_green = 'Green'
        color_orange = 'Orange'
        color_purple = 'Purple'
        color_pink = 'Pink'
        color_teal = 'Teal'
        color_gold = 'Gold'
        color_gray = 'Gray'
        error_lobby_full = 'This lobby is full.'
        error_already_in_lobby = 'Leave your current lobby first.'
        error_lobby_not_found = 'This lobby no longer exists.'
        error_lobby_not_gathering = 'Ready state can be changed only while gathering.'
        error_lobby_locked = 'This lobby is locked by its host.'
        error_lobby_revision_conflict = 'The lobby changed in the meantime; its latest data has been reloaded.'
        error_not_lobby_host = 'Only the lobby host can perform this action.'
        error_invalid_transfer_target = 'The new host must be another lobby member.'
        error_transfer_target_offline = 'The new host must be online.'
        error_invalid_lobby_ready = 'The ready state is invalid.'
        error_invalid_lobby_phase = 'The lobby phase is invalid.'
        error_invalid_lobby_locked = 'The lobby lock state is invalid.'
        error_invalid_lobby_revision = 'The lobby revision is invalid.'
        error_invalid_join_instructions = 'The connection instructions are invalid.'
        error_not_in_lobby = 'Join a lobby before using its chat.'
        error_capacity_below_occupancy = 'Capacity cannot be lower than the current occupancy.'
        error_message_rate_limited = 'Too many messages; wait a few seconds.'
        error_lobby_action_rate_limited = 'Too many lobby actions; wait a few seconds.'
        error_invalid_message_color = 'This message color is not allowed.'
        error_invalid_lobby_capacity = 'Capacity must be between 2 and 128.'
        error_invalid_lobby_port = 'The port must be between 1 and 65535 or omitted.'
        error_incompatible_api = 'The server is not compatible with this client.'
        error_invalid_lobby_id = 'The selected lobby identifier is invalid.'
        error_invalid_status = 'This player status is invalid.'
        error_player_offline = 'Your player is not currently present on the Companion service.'
        error_invalid_message_target = 'The selected message recipient is invalid.'
        error_message_target_not_found = 'This message recipient no longer exists.'
        error_invalid_game = 'The game name is invalid.'
        error_invalid_lobby_name = 'The lobby name is invalid.'
        error_invalid_message = 'The message is invalid.'
        error_network_error = 'The Companion service is unreachable.'
        error_auth_rate_limited = 'Too many failed sign-in attempts from this VPN address; wait one minute.'
        error_status_rate_limited = 'Too many status changes; wait a few seconds.'
        error_state_rate_limited = 'The client refreshed too quickly; synchronization will resume automatically.'
        error_request_error = 'The Companion service rejected this request.'
        error_source_outside_vpn = 'Connect OpenVPN before using LAN Party Companion.'
        error_missing_token = 'The Companion identity file is incomplete; reinstall the player package.'
        error_invalid_token = 'This Companion identity is invalid or revoked; ask the administrator for a new player package.'
        error_json_required = 'The client request format is incompatible with the server.'
        error_length_required = 'The client request format is incomplete.'
        error_request_too_large = 'The request is larger than the server allows.'
        error_invalid_json = 'The client sent data the server could not read.'
        error_invalid_json_root = 'The client request format is invalid.'
        error_invalid_since = 'The message synchronization cursor is invalid.'
        error_endpoint_not_found = 'This feature requires a newer Companion service on the VPN server.'
        error_internal_error = 'The Companion service encountered an internal error.'
    }
    fr = @{
        app_title = 'LAN Party Companion'
        language = 'Langue :'
        player = 'Joueur :'
        status = 'Statut :'
        apply = 'Appliquer'
        latency = "Latence vers l’hôte"
        diagnostics = 'Diagnostic'
        diagnostic_client = 'Version du client'
        diagnostic_server = 'Version du serveur'
        diagnostic_server_url = 'Adresse du serveur'
        diagnostic_connection = 'État du service'
        diagnostic_api = "Version de l’API"
        diagnostic_player = 'Joueur'
        diagnostic_vpn_ip = 'Adresse VPN'
        diagnostic_session = 'Temps de connexion'
        diagnostic_lobby = 'Salon actuel'
        diagnostic_latency = "Mesure de latence vers l’hôte"
        enabled = 'Activée'
        disabled = 'Désactivée'
        reachable = 'Joignable'
        unreachable = 'Injoignable'
        none = 'Aucun'
        players = 'Joueurs'
        messages = 'Messages'
        lobbies = 'Salons'
        pseudo = 'Pseudo'
        vpn_ip = 'Adresse VPN'
        ping = 'Ping'
        last_seen = 'Connexion / dernière présence'
        target = 'Destinataire :'
        everyone = 'Tout le monde'
        message_color = 'Couleur :'
        send = 'Envoyer'
        game = 'Jeu :'
        lobby_name = 'Nom du salon :'
        join_instructions = 'Comment rejoindre :'
        connection_info = 'Informations de connexion'
        no_instructions = 'Aucune instruction supplémentaire.'
        port_known = 'Port connu'
        port = 'Port'
        capacity = 'Capacité :'
        publish_lobby = 'Publier / mettre à jour'
        join_lobby = 'Rejoindre le salon'
        copy_address = 'Copier les infos de connexion'
        lobby = 'Salon'
        host = 'Hôte'
        address = 'Adresse VPN'
        occupancy = 'Joueurs'
        lobby_state = 'État'
        phase_gathering = 'Rassemblement'
        phase_in_game = 'En jeu'
        access_open = 'Ouvert'
        access_locked = 'Verrouillé'
        members = 'Membres'
        ready_column = 'Prêt'
        ready_short = '{0} prêt(s)'
        role_column = 'Rôle'
        role_host = 'Hôte'
        role_member = 'Membre'
        ready_yes = 'Oui'
        ready_no = 'Non'
        mark_ready = 'Je suis prêt'
        mark_not_ready = 'Plus prêt'
        start_game = 'Démarrer la partie'
        resume_gathering = 'Retour au salon'
        lock_lobby = 'Verrouiller'
        lock_hint = "Bloque les nouveaux membres du Companion ; ce n’est pas un pare-feu réseau."
        unlock_lobby = 'Déverrouiller'
        transfer_host = "Transférer l’hôte"
        transfer_target_required = 'Sélectionnez le nouvel hôte.'
        confirm_transfer_host = "Transférer les droits d’hôte à {0} ?"
        copy_connection = 'Copier les infos de connexion'
        lobby_chat = 'Chat du salon'
        time_column = 'Heure'
        sender_column = 'Auteur'
        message_column = 'Message'
        status_column = 'Statut'
        game_column = 'Jeu'
        lobby_name_column = 'Nom du salon'
        leave_lobby = 'Quitter le salon'
        close_lobby = 'Fermer le salon'
        confirm_leave_lobby = 'Quitter ce salon ?'
        confirm_close_lobby = 'Fermer ce salon pour tous les membres ?'
        open_app = 'Ouvrir'
        quit_menu = 'Quitter...'
        exit_app = 'Quitter le Companion'
        exit_and_disconnect_vpn = 'Quitter le Companion et déconnecter le VPN'
        confirm_disconnect_vpn = 'Déconnecter OpenVPN LAN Party et quitter le Companion ?'
        vpn_disconnect_failed = 'Impossible de déconnecter OpenVPN LAN Party : {0}'
        vpn_connecting = 'Connexion à OpenVPN LAN Party…'
        vpn_connect_failed = 'Impossible de connecter automatiquement OpenVPN LAN Party : {0}'
        vpn_profile_missing = 'Le profil OpenVPN-LAN-Party géré est introuvable.'
        vpn_profile_ambiguous = 'Plusieurs profils OpenVPN-LAN-Party gérés existent.'
        vpn_profile_invalid = "Le profil OpenVPN-LAN-Party n’est pas un profil géré valide."
        vpn_gui_missing = "OpenVPN GUI n’est pas installé à l’emplacement attendu."
        vpn_connect_timeout = "Le VPN n’est pas devenu joignable dans les 60 secondes."
        connected = 'Connecté à LAN Party Companion'
        connected_details = 'Connecté — serveur v{0} — session {1}'
        activity_lobby = 'Dans un salon'
        activity_game = 'En jeu'
        offline = 'Hors ligne'
        never_seen = 'Jamais connecté'
        just_now = "À l’instant"
        minutes_ago = 'Il y a {0} min'
        hours_ago = 'Il y a {0} h'
        unavailable = 'Indisponible'
        selected_required = "Sélectionnez d’abord un salon."
        game_required = 'Indiquez le nom du jeu.'
        lobby_name_required = 'Indiquez le nom du salon.'
        address_unavailable = "L’hôte de ce salon est temporairement hors ligne."
        address_copied = 'Informations de connexion copiées.'
        launch_hint = 'Ouvrez le jeu puis son écran de connexion directe ou LAN.'
        hidden_to_tray = "L’application reste active près de l’horloge Windows."
        already_running = 'LAN Party Companion est déjà lancé.'
        start_failed = 'LAN Party Companion ne peut pas démarrer :'
        request_failed = 'Opération impossible : {0}'
        message_not_sent = 'Message non envoyé : {0}'
        lobby_message_not_sent = 'Message du salon non envoyé : {0}'
        member_joined = '{0} a rejoint le salon.'
        member_left = '{0} a quitté le salon.'
        game_started = '{0} a démarré la partie.'
        gathering_resumed = '{0} a remis le salon en rassemblement.'
        lobby_locked = '{0} a verrouillé le salon.'
        lobby_unlocked = '{0} a déverrouillé le salon.'
        host_transferred = "{0} est maintenant l’hôte du salon."
        server_restarted = 'Le service Companion a redémarré ; les salons éphémères ont pu être fermés.'
        status_online = 'En ligne'
        status_ready = 'Prêt'
        status_afk = 'AFK'
        status_busy = 'Occupé'
        status_in_game = 'En jeu'
        status_offline = 'Hors ligne'
        color_blue = 'Bleu'
        color_green = 'Vert'
        color_orange = 'Orange'
        color_purple = 'Violet'
        color_pink = 'Rose'
        color_teal = 'Turquoise'
        color_gold = 'Or'
        color_gray = 'Gris'
        error_lobby_full = 'Ce salon est complet.'
        error_already_in_lobby = "Quittez d’abord votre salon actuel."
        error_lobby_not_found = "Ce salon n’existe plus."
        error_lobby_not_gathering = "L’état prêt se modifie uniquement pendant le rassemblement."
        error_lobby_locked = "Ce salon est verrouillé par son hôte."
        error_lobby_revision_conflict = 'Le salon a changé entre-temps ; ses données à jour ont été rechargées.'
        error_not_lobby_host = "Seul l’hôte du salon peut effectuer cette action."
        error_invalid_transfer_target = "Le nouvel hôte doit être un autre membre du salon."
        error_transfer_target_offline = 'Le nouvel hôte doit être en ligne.'
        error_invalid_lobby_ready = "L’état prêt est invalide."
        error_invalid_lobby_phase = 'La phase du salon est invalide.'
        error_invalid_lobby_locked = 'Le verrouillage du salon est invalide.'
        error_invalid_lobby_revision = 'La révision du salon est invalide.'
        error_invalid_join_instructions = 'Les instructions de connexion sont invalides.'
        error_not_in_lobby = "Rejoignez un salon avant d’utiliser son chat."
        error_capacity_below_occupancy = 'La capacité ne peut pas être inférieure au nombre de membres.'
        error_message_rate_limited = 'Trop de messages ; patientez quelques secondes.'
        error_lobby_action_rate_limited = "Trop d’actions sur les salons ; patientez quelques secondes."
        error_invalid_message_color = "Cette couleur de message n’est pas autorisée."
        error_invalid_lobby_capacity = 'La capacité doit être comprise entre 2 et 128.'
        error_invalid_lobby_port = 'Le port doit être compris entre 1 et 65535 ou rester vide.'
        error_incompatible_api = "Le serveur n’est pas compatible avec ce client."
        error_invalid_lobby_id = "L’identifiant du salon sélectionné est invalide."
        error_invalid_status = 'Ce statut de joueur est invalide.'
        error_player_offline = "Votre joueur n’est pas actuellement présent sur le service Companion."
        error_invalid_message_target = 'Le destinataire sélectionné est invalide.'
        error_message_target_not_found = "Ce destinataire n’existe plus."
        error_invalid_game = 'Le nom du jeu est invalide.'
        error_invalid_lobby_name = 'Le nom du salon est invalide.'
        error_invalid_message = 'Le message est invalide.'
        error_network_error = 'Le service Companion est injoignable.'
        error_auth_rate_limited = "Trop d’échecs d’authentification depuis cette adresse VPN ; attendez une minute."
        error_status_rate_limited = 'Trop de changements de statut ; patientez quelques secondes.'
        error_state_rate_limited = 'Le client a actualisé trop vite ; la synchronisation reprendra automatiquement.'
        error_request_error = 'Le service Companion a refusé cette requête.'
        error_source_outside_vpn = "Connectez OpenVPN avant d’utiliser LAN Party Companion."
        error_missing_token = "Le fichier d’identité Companion est incomplet ; réinstallez le paquet joueur."
        error_invalid_token = "Cette identité Companion est invalide ou révoquée ; demandez un nouveau paquet joueur à l’administrateur."
        error_json_required = 'Le format de la requête client est incompatible avec le serveur.'
        error_length_required = 'Le format de la requête client est incomplet.'
        error_request_too_large = 'La requête dépasse la taille autorisée par le serveur.'
        error_invalid_json = "Le client a envoyé des données que le serveur n’a pas pu lire."
        error_invalid_json_root = 'Le format de la requête client est invalide.'
        error_invalid_since = 'Le curseur de synchronisation des messages est invalide.'
        error_endpoint_not_found = 'Cette fonction nécessite un service Companion plus récent sur le serveur VPN.'
        error_internal_error = 'Le service Companion a rencontré une erreur interne.'
    }
}

$script:MessageColors = @{
    blue = [Drawing.Color]::FromArgb(30, 90, 180)
    green = [Drawing.Color]::FromArgb(20, 125, 70)
    orange = [Drawing.Color]::FromArgb(190, 95, 0)
    purple = [Drawing.Color]::FromArgb(115, 65, 175)
    pink = [Drawing.Color]::FromArgb(185, 45, 105)
    teal = [Drawing.Color]::FromArgb(0, 125, 135)
    gold = [Drawing.Color]::FromArgb(145, 110, 0)
    gray = [Drawing.Color]::FromArgb(90, 90, 90)
}

$script:StatusColors = @{
    online = [Drawing.Color]::FromArgb(30, 100, 190)
    ready = [Drawing.Color]::FromArgb(25, 135, 65)
    in_game = [Drawing.Color]::FromArgb(120, 65, 175)
    afk = [Drawing.Color]::FromArgb(200, 115, 0)
    busy = [Drawing.Color]::FromArgb(190, 45, 45)
    offline = [Drawing.Color]::FromArgb(110, 110, 110)
}

function T {
    param(
        [Parameter(Mandatory = $true)][string]$Key,
        [object[]]$Arguments = @()
    )

    $language = $script:Settings.language
    $catalog = $script:Texts[$language]
    if (-not $catalog.ContainsKey($Key)) { $catalog = $script:Texts.en }
    $value = [string]$catalog[$Key]
    if ($Arguments.Count -gt 0) { return $value -f $Arguments }
    return $value
}

function Read-CompanionConfig {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Companion configuration not found: $Path"
    }
    $config = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($config.version -ne 1) { throw 'Invalid Companion configuration version.' }
    if ([string]$config.player -notmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$') {
        throw 'Invalid Companion player name.'
    }
    if ([string]$config.token -notmatch '^[A-Za-z0-9_-]{32,128}$') {
        throw 'Invalid Companion token.'
    }
    $serverUri = $null
    if (-not [Uri]::TryCreate(
            [string]$config.server_url,
            [UriKind]::Absolute,
            [ref]$serverUri
        ) -or $serverUri.Scheme -ne 'http' -or
        $serverUri.AbsolutePath -ne '/' -or
        -not [string]::IsNullOrEmpty($serverUri.Query) -or
        -not [string]::IsNullOrEmpty($serverUri.Fragment) -or
        -not [string]::IsNullOrEmpty($serverUri.UserInfo)) {
        throw 'Invalid Companion server address.'
    }
    return $config
}

function Read-CompanionSettings {
    param([Parameter(Mandatory = $true)][string]$Path)

    $defaultLanguage = 'en'
    if ([Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName -eq 'fr') {
        $defaultLanguage = 'fr'
    }
    $settings = [ordered]@{
        version = 1
        language = $defaultLanguage
        message_color = 'blue'
        latency_enabled = $false
    }
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        try {
            $saved = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
            $properties = $saved.PSObject.Properties
            if ($properties['version'] -and $saved.version -eq 1) {
                if ($properties['language'] -and
                    [string]$saved.language -in @('en', 'fr')) {
                    $settings.language = [string]$saved.language
                }
                if ($properties['message_color'] -and
                    [string]$saved.message_color -in $script:ColorIds) {
                    $settings.message_color = [string]$saved.message_color
                }
                if ($properties['latency_enabled'] -and
                    $saved.latency_enabled -is [bool]) {
                    $settings.latency_enabled = [bool]$saved.latency_enabled
                }
            }
        }
        catch {
            # A corrupt non-secret preference file must not block VPN communication.
        }
    }
    return $settings
}

function Save-CompanionSettings {
    $settingsPath = $script:SettingsPath
    $parent = Split-Path -Parent $settingsPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $document = [ordered]@{
        version = 1
        language = $script:Settings.language
        message_color = $script:Settings.message_color
        latency_enabled = [bool]$script:Settings.latency_enabled
    }
    $temporary = "$settingsPath.$([Guid]::NewGuid().ToString('N')).tmp"
    $utf8NoBom = New-Object Text.UTF8Encoding($false)
    try {
        [IO.File]::WriteAllText(
            $temporary,
            ($document | ConvertTo-Json -Depth 3),
            $utf8NoBom
        )
        if (Test-Path -LiteralPath $settingsPath -PathType Leaf) {
            [IO.File]::Replace($temporary, $settingsPath, $null, $true)
        }
        else {
            [IO.File]::Move($temporary, $settingsPath)
        }
    }
    catch {
        # Preferences are best-effort and must never block VPN communication.
    }
    finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-CompanionApi {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('GET', 'POST', 'DELETE')][string]$Method,
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowNull()][hashtable]$Body
    )

    $request = [Net.HttpWebRequest]::Create("$script:ServerUrl$Path")
    $request.Method = $Method
    $request.Proxy = $null
    $request.KeepAlive = $false
    $request.Timeout = 1500
    $request.ReadWriteTimeout = 1500
    $request.Accept = 'application/json'
    $request.UserAgent = "OpenVPN-LAN-Party-Companion/$($script:ClientVersion)"
    $request.Headers.Add(
        [Net.HttpRequestHeader]::Authorization,
        "Bearer $($script:Config.token)"
    )

    if ($null -ne $Body) {
        $json = $Body | ConvertTo-Json -Compress -Depth 6
        $bytes = [Text.Encoding]::UTF8.GetBytes($json)
        $request.ContentType = 'application/json; charset=utf-8'
        $request.ContentLength = $bytes.Length
        $requestStream = $request.GetRequestStream()
        try { $requestStream.Write($bytes, 0, $bytes.Length) }
        finally { $requestStream.Dispose() }
    }

    $response = $null
    try {
        $response = [Net.HttpWebResponse]$request.GetResponse()
        $stream = $response.GetResponseStream()
        $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::UTF8)
        try { $content = $reader.ReadToEnd() }
        finally {
            $reader.Dispose()
            $stream.Dispose()
        }
        if ([string]::IsNullOrWhiteSpace($content)) { return $null }
        return $content | ConvertFrom-Json
    }
    catch [Net.WebException] {
        $errorMessage = $_.Exception.Message
        $errorCode = 'network_error'
        if ($_.Exception.Response) {
            $errorResponse = [Net.HttpWebResponse]$_.Exception.Response
            $errorStream = $errorResponse.GetResponseStream()
            $errorReader = New-Object IO.StreamReader($errorStream, [Text.Encoding]::UTF8)
            try {
                $errorContent = $errorReader.ReadToEnd()
                if (-not [string]::IsNullOrWhiteSpace($errorContent)) {
                    try {
                        $errorObject = $errorContent | ConvertFrom-Json
                        if ($errorObject.PSObject.Properties['error'] -and
                            $errorObject.error) {
                            $errorMessage = [string]$errorObject.error
                        }
                        if ($errorObject.PSObject.Properties['code'] -and
                            $errorObject.code) {
                            $errorCode = [string]$errorObject.code
                        }
                    }
                    catch { $errorMessage = $errorContent }
                }
            }
            finally {
                $errorReader.Dispose()
                $errorStream.Dispose()
                $errorResponse.Dispose()
            }
        }
        $apiException = New-Object InvalidOperationException($errorMessage)
        $apiException.Data['CompanionCode'] = $errorCode
        throw $apiException
    }
    finally {
        if ($response) { $response.Dispose() }
    }
}

function Get-ErrorText {
    param([Parameter(Mandatory = $true)][Exception]$Exception)

    $code = [string]$Exception.Data['CompanionCode']
    if (-not [string]::IsNullOrWhiteSpace($code)) {
        $key = "error_$code"
        if ($script:Texts[$script:Settings.language].ContainsKey($key) -or
            $script:Texts.en.ContainsKey($key)) {
            return T $key
        }
    }
    return $Exception.Message
}

function Format-CompanionDuration {
    param([int]$Seconds)
    $duration = [TimeSpan]::FromSeconds([Math]::Max(0, $Seconds))
    if ($duration.TotalHours -ge 1) {
        return '{0}h {1}m' -f [int]$duration.TotalHours, $duration.Minutes
    }
    return '{0}m {1}s' -f $duration.Minutes, $duration.Seconds
}

function Test-CompanionTcpEndpoint {
    $uri = [Uri]$script:ServerUrl
    $port = if ($uri.IsDefaultPort) { 80 } else { $uri.Port }
    $client = New-Object Net.Sockets.TcpClient
    $pending = $null
    try {
        $pending = $client.BeginConnect($uri.DnsSafeHost, $port, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne(500, $false)) { return $false }
        $client.EndConnect($pending)
        return $client.Connected
    }
    catch { return $false }
    finally {
        if ($pending) { $pending.AsyncWaitHandle.Close() }
        $client.Close()
    }
}

function Get-ManagedLanPartyProfile {
    $candidates = @(
        (Join-Path $env:USERPROFILE 'OpenVPN\config\OpenVPN-LAN-Party.ovpn'),
        (Join-Path $env:USERPROFILE 'Documents\OpenVPN\config\OpenVPN-LAN-Party.ovpn')
    ) | Select-Object -Unique
    $profiles = @($candidates | ForEach-Object {
        if (Test-Path -LiteralPath $_ -PathType Leaf) {
            Get-Item -LiteralPath $_ -Force
        }
    })
    if ($profiles.Count -eq 0) { throw (T 'vpn_profile_missing') }
    if ($profiles.Count -ne 1) { throw (T 'vpn_profile_ambiguous') }
    $profileItem = $profiles[0]
    if (($profileItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $profileItem.Length -gt 262144) {
        throw (T 'vpn_profile_invalid')
    }
    $profile = [IO.File]::ReadAllText($profileItem.FullName)
    $playerPattern = [regex]::Escape([string]$script:Config.player)
    if ($profile -notmatch '(?im)^# openvpn-lan-party-security-mode: (high-assurance|compatible)\s*$' -or
        $profile -notmatch '(?im)^\s*cryptoapicert\s+"THUMB:[A-F0-9]{40}"\s*$' -or
        $profile -notmatch "(?m)^# openvpn-lan-party-player: $playerPattern\s*`$") {
        throw (T 'vpn_profile_invalid')
    }
    return $profileItem
}

function Get-LanPartyOpenVpnGui {
    $openVpnGui = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'OpenVPN\bin\openvpn-gui.exe'
    if (-not (Test-Path -LiteralPath $openVpnGui -PathType Leaf)) {
        throw (T 'vpn_gui_missing')
    }
    return $openVpnGui
}

function Invoke-LanPartyOpenVpnGuiCommand {
    param(
        [Parameter(Mandatory = $true)][string]$OpenVpnGui,
        [Parameter(Mandatory = $true)][ValidateSet('rescan', 'connect', 'disconnect')][string]$Command
    )
    $arguments = @('--command', $Command)
    if ($Command -ne 'rescan') { $arguments += 'OpenVPN-LAN-Party' }
    $process = Start-Process -FilePath $OpenVpnGui -ArgumentList $arguments `
        -WindowStyle Hidden -PassThru
    try {
        # A newly started GUI becomes the resident tray process and must not be
        # waited on indefinitely. A command sent to an existing GUI exits fast.
        if ($process.WaitForExit(5000) -and $process.ExitCode -ne 0) {
            throw "openvpn-gui.exe returned exit code $($process.ExitCode)"
        }
    }
    finally { $process.Dispose() }
}

function Connect-LanPartyOpenVpn {
    if (Test-CompanionTcpEndpoint) { return }
    [void](Get-ManagedLanPartyProfile)
    $openVpnGui = Get-LanPartyOpenVpnGui
    Invoke-LanPartyOpenVpnGuiCommand -OpenVpnGui $openVpnGui -Command rescan
    Start-Sleep -Milliseconds 750
    Invoke-LanPartyOpenVpnGuiCommand -OpenVpnGui $openVpnGui -Command connect
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        if ($script:ExitRequested) { return }
        if (Test-CompanionTcpEndpoint) { return }
        [Windows.Forms.Application]::DoEvents()
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw (T 'vpn_connect_timeout')
}

function Disconnect-LanPartyOpenVpn {
    $openVpnGui = Get-LanPartyOpenVpnGui
    Invoke-LanPartyOpenVpnGuiCommand -OpenVpnGui $openVpnGui -Command disconnect
}

function Exit-CompanionOnly {
    $script:ExitRequested = $true
    $script:PollTimer.Stop()
    $script:Form.Close()
}

function Exit-CompanionAndVpn {
    $answer = [Windows.Forms.MessageBox]::Show(
        (T 'confirm_disconnect_vpn'),
        (T 'app_title'),
        [Windows.Forms.MessageBoxButtons]::YesNo,
        [Windows.Forms.MessageBoxIcon]::Warning
    )
    if ($answer -ne [Windows.Forms.DialogResult]::Yes) { return }
    try { Disconnect-LanPartyOpenVpn }
    catch {
        [Windows.Forms.MessageBox]::Show(
            (T 'vpn_disconnect_failed' @($_.Exception.Message)),
            (T 'app_title'),
            [Windows.Forms.MessageBoxButtons]::OK,
            [Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
        return
    }
    Exit-CompanionOnly
}

function Format-MessageTime {
    param([long]$UnixTime)
    $epoch = [DateTime]::SpecifyKind([DateTime]'1970-01-01', [DateTimeKind]::Utc)
    return $epoch.AddSeconds($UnixTime).ToLocalTime().ToString('HH:mm:ss')
}

function Format-LastSeen {
    param($Player, [long]$ServerTime)
    if ($Player.online) { return (T 'just_now') }
    if ($null -eq $Player.last_seen_at) { return (T 'never_seen') }
    $seconds = [Math]::Max(0, $ServerTime - [long]$Player.last_seen_at)
    if ($seconds -lt 120) { return (T 'just_now') }
    if ($seconds -lt 7200) { return (T 'minutes_ago' @([int]($seconds / 60))) }
    return (T 'hours_ago' @([int]($seconds / 3600)))
}

function Get-StatusText {
    param([string]$Status)
    $key = "status_$Status"
    if ($script:Texts.en.ContainsKey($key)) { return T $key }
    return $Status
}

function Get-MessageColor {
    param([AllowNull()][string]$ColorId)
    if ($ColorId -and $script:MessageColors.ContainsKey($ColorId)) {
        return $script:MessageColors[$ColorId]
    }
    return $script:MessageColors.blue
}

function Add-ChatMessage {
    param(
        [Parameter(Mandatory = $true)][Windows.Forms.ListView]$List,
        [Parameter(Mandatory = $true)]$Message,
        [switch]$Lobby
    )

    while ($List.Items.Count -ge 500) { $List.Items.RemoveAt(0) }
    $time = Format-MessageTime -UnixTime ([long]$Message.created_at)
    $sender = ''
    $text = ''
    $color = $script:MessageColors.gray
    $kind = 'message'
    if ($Message.PSObject.Properties['kind']) { $kind = [string]$Message.kind }
    if ($Lobby -and $kind -ne 'message') {
        $eventKey = switch ($kind) {
            'member_joined' { 'member_joined' }
            'member_left' { 'member_left' }
            'game_started' { 'game_started' }
            'gathering_resumed' { 'gathering_resumed' }
            'lobby_locked' { 'lobby_locked' }
            'lobby_unlocked' { 'lobby_unlocked' }
            'host_transferred' { 'host_transferred' }
            default { $null }
        }
        if ($eventKey) { $text = T $eventKey @([string]$Message.actor) }
        else { $text = $kind }
    }
    else {
        $sender = [string]$Message.sender
        if (-not $Lobby -and $Message.target) {
            $sender = '{0} → {1}' -f $sender, [string]$Message.target
        }
        $text = [string]$Message.text
        if ($Message.PSObject.Properties['color']) {
            $color = Get-MessageColor -ColorId ([string]$Message.color)
        }
    }
    $item = New-Object Windows.Forms.ListViewItem($time)
    [void]$item.SubItems.Add($sender)
    [void]$item.SubItems.Add($text)
    $item.Tag = [pscustomobject]@{
        message = $Message
        lobby = [bool]$Lobby
    }
    $item.ForeColor = $color
    [void]$List.Items.Add($item)
    if ($List.Items.Count -gt 0) { $List.EnsureVisible($List.Items.Count - 1) }

    $isUnread = -not $script:InitialPoll -and
        $kind -eq 'message' -and
        $Message.sender -ne $script:Config.player -and
        (-not $script:Form.Visible -or
            $script:Form.WindowState -eq [Windows.Forms.FormWindowState]::Minimized -or
            ($Lobby -and $script:Tabs.SelectedTab -ne $script:LobbiesTab) -or
            (-not $Lobby -and $script:Tabs.SelectedTab -ne $script:ChatTab))
    if ($isUnread) {
        if ($Lobby) { $script:LobbyUnread++ }
        else { $script:PublicUnread++ }
        Update-TabTitles
    }

    if ($kind -eq 'message' -and
        $Message.sender -ne $script:Config.player -and
        (-not $script:Form.Visible -or
            $script:Form.WindowState -eq [Windows.Forms.FormWindowState]::Minimized)) {
        $notificationText = $text
        if ($notificationText.Length -gt 240) {
            $notificationText = $notificationText.Substring(0, 239) + '…'
        }
        $script:NotifyIcon.BalloonTipTitle = [string]$Message.sender
        $script:NotifyIcon.BalloonTipText = $notificationText
        $script:NotifyIcon.ShowBalloonTip(4000)
    }
}

function Show-CompanionWindow {
    $script:Form.Show()
    $script:Form.WindowState = [Windows.Forms.FormWindowState]::Normal
    $script:Form.Activate()
    if ($script:Tabs.SelectedTab -eq $script:ChatTab) { $script:PublicUnread = 0 }
    if ($script:Tabs.SelectedTab -eq $script:LobbiesTab) { $script:LobbyUnread = 0 }
    Update-TabTitles
}

function Assert-CompatibleState {
    param([Parameter(Mandatory = $true)]$State)

    if ($State.api_version -ne 2 -or -not $State.PSObject.Properties['features']) {
        throw (T 'error_incompatible_api')
    }
    $available = @($State.features | ForEach-Object { [string]$_ })
    foreach ($required in $script:RequiredServerFeatures) {
        if ($required -notin $available) { throw (T 'error_incompatible_api') }
    }
}

function Get-LobbyPhaseText {
    param([AllowNull()][string]$Phase)
    if ($Phase -eq 'in_game') { return T 'phase_in_game' }
    return T 'phase_gathering'
}

function Update-TabTitles {
    if (-not (Get-Variable -Name ChatTab -Scope Script -ErrorAction SilentlyContinue)) {
        return
    }
    $chatSuffix = if ($script:PublicUnread -gt 0) { " ($($script:PublicUnread))" } else { '' }
    $lobbySuffix = if ($script:LobbyUnread -gt 0) { " ($($script:LobbyUnread))" } else { '' }
    $script:PlayersTab.Text = T 'players'
    $script:ChatTab.Text = "$(T 'messages')$chatSuffix"
    $script:LobbiesTab.Text = "$(T 'lobbies')$lobbySuffix"
}

function Update-ConnectionSummary {
    if (-not $script:IsConnected -or -not $script:LastState) { return }
    $selfPlayer = @($script:LastState.players | Where-Object {
        $_.pseudo -eq $script:Config.player
    } | Select-Object -First 1)
    $duration = if ($selfPlayer.Count -gt 0) {
        Format-CompanionDuration -Seconds ([int]$selfPlayer[0].connected_for_seconds)
    }
    else { '—' }
    $script:ConnectionLabel.Text = T 'connected_details' @(
        [string]$script:LastState.server_version,
        $duration
    )
    $script:ConnectionLabel.ForeColor = [Drawing.Color]::DarkGreen

    $script:ActivityLabel.Text = ''
    if ($null -ne $script:LastState.current_lobby) {
        $script:ActivityLabel.Text = if ($script:LastState.current_lobby.phase -eq 'in_game') {
            T 'activity_game'
        }
        else { T 'activity_lobby' }
    }
}

function Apply-Language {
    $script:Form.Text = '{0} — {1}' -f (T 'app_title'), $script:Config.player
    $script:IdentityLabel.Text = '{0} {1}' -f (T 'player'), $script:Config.player
    $script:LanguageLabel.Text = T 'language'
    $script:StatusLabel.Text = T 'status'
    $script:StatusButton.Text = T 'apply'
    $script:LatencyCheckBox.Text = T 'latency'
    Update-TabTitles
    $script:PlayersGrid.Columns['Pseudo'].HeaderText = T 'pseudo'
    $script:PlayersGrid.Columns['VpnIp'].HeaderText = T 'vpn_ip'
    $script:PlayersGrid.Columns['Status'].HeaderText = T 'status_column'
    $script:PlayersGrid.Columns['Ping'].HeaderText = T 'ping'
    $script:PlayersGrid.Columns['LastSeen'].HeaderText = T 'last_seen'
    $script:TargetLabel.Text = T 'target'
    $script:ColorLabel.Text = T 'message_color'
    $script:SendButton.Text = T 'send'
    $script:LobbiesGrid.Columns['Game'].HeaderText = T 'game_column'
    $script:LobbiesGrid.Columns['LobbyName'].HeaderText = T 'lobby_name_column'
    $script:LobbiesGrid.Columns['Host'].HeaderText = T 'host'
    $script:LobbiesGrid.Columns['Address'].HeaderText = T 'address'
    $script:LobbiesGrid.Columns['Port'].HeaderText = T 'port'
    $script:LobbiesGrid.Columns['Occupancy'].HeaderText = T 'occupancy'
    $script:LobbiesGrid.Columns['State'].HeaderText = T 'lobby_state'
    $script:GameLabel.Text = T 'game'
    $script:LobbyNameLabel.Text = T 'lobby_name'
    $script:JoinInstructionsLabel.Text = T 'join_instructions'
    $script:PortKnownCheckBox.Text = T 'port_known'
    $script:CapacityLabel.Text = T 'capacity'
    $script:PublishButton.Text = T 'publish_lobby'
    $script:JoinButton.Text = T 'join_lobby'
    $script:CopyAddressButton.Text = T 'copy_address'
    $script:DiagnosticsButton.Text = T 'diagnostics'
    $script:QuitButton.Text = T 'quit_menu'
    $script:LobbyInstructionsLabel.Text = T 'join_instructions'
    $script:CopyCurrentInfoButton.Text = T 'copy_connection'
    $script:TransferHostButton.Text = T 'transfer_host'
    $script:ToolTip.SetToolTip($script:LockButton, (T 'lock_hint'))
    $script:LobbyMembersLabel.Text = T 'members'
    $script:LobbyChatLabel.Text = T 'lobby_chat'
    $script:LobbySendButton.Text = T 'send'
    $script:MessageList.Columns[0].Text = T 'time_column'
    $script:MessageList.Columns[1].Text = T 'sender_column'
    $script:MessageList.Columns[2].Text = T 'message_column'
    $script:LobbyMessageList.Columns[0].Text = T 'time_column'
    $script:LobbyMessageList.Columns[1].Text = T 'sender_column'
    $script:LobbyMessageList.Columns[2].Text = T 'message_column'
    $script:LobbyMembersList.Columns[0].Text = T 'pseudo'
    $script:LobbyMembersList.Columns[1].Text = T 'status_column'
    $script:LobbyMembersList.Columns[2].Text = T 'ready_column'
    $script:LobbyMembersList.Columns[3].Text = T 'role_column'
    $script:OpenMenu.Text = T 'open_app'
    $script:ExitMenu.Text = T 'exit_app'
    $script:ExitAndDisconnectMenu.Text = T 'exit_and_disconnect_vpn'
    $script:QuitOnlyButtonMenu.Text = T 'exit_app'
    $script:QuitAndDisconnectButtonMenu.Text = T 'exit_and_disconnect_vpn'

    foreach ($item in $script:LobbyMessageList.Items) {
        if (-not $item.Tag -or -not $item.Tag.lobby) { continue }
        $message = $item.Tag.message
        switch ([string]$message.kind) {
            'member_joined' { $item.SubItems[2].Text = T 'member_joined' @([string]$message.actor) }
            'member_left' { $item.SubItems[2].Text = T 'member_left' @([string]$message.actor) }
            'game_started' { $item.SubItems[2].Text = T 'game_started' @([string]$message.actor) }
            'gathering_resumed' { $item.SubItems[2].Text = T 'gathering_resumed' @([string]$message.actor) }
            'lobby_locked' { $item.SubItems[2].Text = T 'lobby_locked' @([string]$message.actor) }
            'lobby_unlocked' { $item.SubItems[2].Text = T 'lobby_unlocked' @([string]$message.actor) }
            'host_transferred' { $item.SubItems[2].Text = T 'host_transferred' @([string]$message.actor) }
        }
    }

    if ($script:IsConnected) {
        Update-ConnectionSummary
    }
    elseif ($script:LastConnectionException) {
        $script:ConnectionLabel.Text = '{0}: {1}' -f (
            T 'offline'
        ), (Get-ErrorText $script:LastConnectionException)
        $script:ConnectionLabel.ForeColor = [Drawing.Color]::DarkRed
    }
    else {
        $script:ConnectionLabel.Text = T 'offline'
        $script:ConnectionLabel.ForeColor = [Drawing.Color]::DimGray
    }

    $statusIndex = $script:StatusCombo.SelectedIndex
    $script:StatusCombo.Items.Clear()
    foreach ($statusId in $script:StatusIds) {
        [void]$script:StatusCombo.Items.Add((Get-StatusText $statusId))
    }
    if ($statusIndex -lt 0) { $statusIndex = 0 }
    $script:StatusCombo.SelectedIndex = $statusIndex

    $colorIndex = [Array]::IndexOf($script:ColorIds, [string]$script:Settings.message_color)
    if ($colorIndex -lt 0) { $colorIndex = 0 }
    $script:ColorCombo.Items.Clear()
    foreach ($colorId in $script:ColorIds) {
        [void]$script:ColorCombo.Items.Add((T "color_$colorId"))
    }
    $script:ColorCombo.SelectedIndex = $colorIndex

    if ($script:LastState) {
        Update-PlayerGrid -State $script:LastState
        Update-LobbyGrid -State $script:LastState
        Update-LobbyPanel -State $script:LastState
    }
}

function Update-LatencyProbe {
    if ($script:PingTask) {
        if ($script:PingTask.IsCompleted) {
            $available = $false
            $milliseconds = $null
            try {
                $reply = $script:PingTask.GetAwaiter().GetResult()
                if ($reply.Status -eq [Net.NetworkInformation.IPStatus]::Success) {
                    $available = $true
                    $milliseconds = [int]$reply.RoundtripTime
                }
            }
            catch { }
            finally {
                $script:PingClient.Dispose()
                $script:PingClient = $null
                $script:PingTask = $null
            }
            $previousLatency = $script:LatencyResults[$script:PingPlayer]
            if ($available -and $previousLatency -and
                $previousLatency.available -and
                $previousLatency.ip -eq $script:PingAddress) {
                $milliseconds = [int][Math]::Round(
                    (0.65 * [double]$previousLatency.milliseconds) +
                    (0.35 * [double]$milliseconds)
                )
            }
            $script:LatencyResults[$script:PingPlayer] = [pscustomobject]@{
                available = $available
                milliseconds = $milliseconds
                checked_at = [DateTime]::UtcNow
                ip = $script:PingAddress
            }
            $script:PingPlayer = $null
            $script:PingAddress = $null
        }
        return
    }
    if (-not $script:Settings.latency_enabled -or -not $script:LastState) { return }
    if ([DateTime]::UtcNow -lt $script:NextPingAt) { return }

    $hostName = $null
    if ($null -ne $script:LastState.current_lobby) {
        $hostName = [string]$script:LastState.current_lobby.host
    }
    else {
        $selectedLobby = Get-SelectedLobby
        if ($selectedLobby) { $hostName = [string]$selectedLobby.host }
    }
    if ([string]::IsNullOrWhiteSpace($hostName) -or
        $hostName -eq $script:Config.player) { return }

    $eligible = @()
    foreach ($player in @($script:LastState.players)) {
        if (-not $player.online -or
            $player.pseudo -ne $hostName -or
            [string]::IsNullOrWhiteSpace([string]$player.vpn_ip)) { continue }
        $last = $script:LatencyResults[[string]$player.pseudo]
        if ($last -and $last.ip -eq $player.vpn_ip -and
            ([DateTime]::UtcNow - $last.checked_at).TotalSeconds -lt 15) { continue }
        $eligible += $player
    }
    if ($eligible.Count -eq 0) {
        $script:NextPingAt = [DateTime]::UtcNow.AddSeconds(1)
        return
    }
    $target = $eligible | Sort-Object {
        $last = $script:LatencyResults[[string]$_.pseudo]
        if ($last) { $last.checked_at } else { [DateTime]::MinValue }
    } | Select-Object -First 1
    $script:PingPlayer = [string]$target.pseudo
    $script:PingAddress = [string]$target.vpn_ip
    $script:PingClient = New-Object Net.NetworkInformation.Ping
    $script:PingTask = $script:PingClient.SendPingAsync($script:PingAddress, 800)
    $script:NextPingAt = [DateTime]::UtcNow.AddMilliseconds((Get-Random -Minimum 1000 -Maximum 2001))
}

function Update-PlayerGrid {
    param([Parameter(Mandatory = $true)]$State)

    $latencyHostName = $null
    if ($null -ne $State.current_lobby) {
        $latencyHostName = [string]$State.current_lobby.host
    }
    else {
        $selectedLobby = Get-SelectedLobby
        if ($selectedLobby) { $latencyHostName = [string]$selectedLobby.host }
    }
    $selectedTarget = if ($script:TargetCombo.SelectedIndex -gt 0) {
        [string]$script:TargetCombo.SelectedItem
    } else { $null }
    $script:PlayersGrid.Rows.Clear()
    $targets = New-Object Collections.Generic.List[string]
    $targets.Add((T 'everyone'))
    foreach ($player in @($State.players)) {
        $pingText = '—'
        $pingColor = $script:StatusColors.offline
        if ($script:Settings.latency_enabled -and
            $player.online -and
            $player.pseudo -eq $latencyHostName -and
            $player.pseudo -ne $script:Config.player) {
            $latency = $script:LatencyResults[[string]$player.pseudo]
            if ($latency -and $latency.ip -eq $player.vpn_ip) {
                if ($latency.available) {
                    $pingText = '{0} ms' -f $latency.milliseconds
                    if ($latency.milliseconds -le 60) { $pingColor = $script:StatusColors.ready }
                    elseif ($latency.milliseconds -le 130) { $pingColor = $script:StatusColors.afk }
                    else { $pingColor = $script:StatusColors.busy }
                }
                else { $pingText = T 'unavailable' }
            }
            else { $pingText = '…' }
        }
        $vpnIp = if ($player.online) { [string]$player.vpn_ip } else { '—' }
        $presenceText = if ($player.online) {
            Format-CompanionDuration -Seconds ([int]$player.connected_for_seconds)
        }
        else { Format-LastSeen -Player $player -ServerTime ([long]$State.server_time) }
        $index = $script:PlayersGrid.Rows.Add(
            $player.pseudo,
            $vpnIp,
            (Get-StatusText ([string]$player.status)),
            $pingText,
            $presenceText
        )
        $row = $script:PlayersGrid.Rows[$index]
        $row.Tag = $player
        $statusColor = $script:StatusColors[[string]$player.status]
        if (-not $statusColor) { $statusColor = $script:StatusColors.offline }
        $row.Cells['Status'].Style.ForeColor = $statusColor
        $row.Cells['Ping'].Style.ForeColor = $pingColor
        if (-not $player.online) { $row.DefaultCellStyle.ForeColor = $script:StatusColors.offline }
        if ($player.pseudo -ne $script:Config.player) {
            $targets.Add([string]$player.pseudo)
        }
    }
    $script:TargetCombo.Items.Clear()
    foreach ($target in $targets) { [void]$script:TargetCombo.Items.Add($target) }
    if ($selectedTarget -and $targets.Contains($selectedTarget)) {
        $script:TargetCombo.SelectedItem = $selectedTarget
    }
    else { $script:TargetCombo.SelectedIndex = 0 }
}

function Update-LobbyGrid {
    param([Parameter(Mandatory = $true)]$State)
    $selectedId = $null
    if ($script:LobbiesGrid.SelectedRows.Count -gt 0 -and
        $script:LobbiesGrid.SelectedRows[0].Tag) {
        $selectedId = [string]$script:LobbiesGrid.SelectedRows[0].Tag.id
    }
    $script:LobbiesGrid.Rows.Clear()
    foreach ($lobby in @($State.lobbies)) {
        $address = if ($lobby.host_ip) { [string]$lobby.host_ip } else { '—' }
        $port = if ($null -ne $lobby.port) { [string]$lobby.port } else { '—' }
        $occupancy = '{0}/{1} · {2}' -f
            $lobby.member_count, $lobby.capacity, (T 'ready_short' @($lobby.ready_count))
        $access = if ($lobby.locked) { T 'access_locked' } else { T 'access_open' }
        $stateText = '{0} · {1}' -f (Get-LobbyPhaseText ([string]$lobby.phase)), $access
        $index = $script:LobbiesGrid.Rows.Add(
            $lobby.game,
            $lobby.lobby_name,
            $lobby.host,
            $address,
            $port,
            $occupancy,
            $stateText
        )
        $row = $script:LobbiesGrid.Rows[$index]
        $row.Tag = $lobby
        if ($lobby.member_count -ge $lobby.capacity -or $lobby.locked) {
            $row.DefaultCellStyle.ForeColor = $script:StatusColors.offline
        }
        elseif ($lobby.phase -eq 'in_game') {
            $row.Cells['State'].Style.ForeColor = $script:StatusColors.in_game
        }
        if ($selectedId -and $lobby.id -eq $selectedId) { $row.Selected = $true }
    }
    Update-LobbyActionAvailability
}

function Set-LobbyPanelVisible {
    param([bool]$Visible)
    if ($Visible -eq $script:LobbyExpanded) { return }
    $script:LobbyExpanded = $Visible
    if ($Visible) {
        $script:CollapsedWindowWidth = $script:Form.Width
        $script:OuterLayout.ColumnStyles[1].Width = 450
        $script:LobbyPanel.Visible = $true
        $workingWidth = [Windows.Forms.Screen]::FromControl($script:Form).WorkingArea.Width
        $script:Form.MinimumSize = New-Object Drawing.Size([Math]::Min(1120, $workingWidth), 520)
        $script:Form.Width = [Math]::Min($script:CollapsedWindowWidth + 450, $workingWidth)
    }
    else {
        $script:LobbyPanel.Visible = $false
        $script:OuterLayout.ColumnStyles[1].Width = 0
        $script:Form.MinimumSize = New-Object Drawing.Size(760, 520)
        $script:Form.Width = [Math]::Max(760, $script:CollapsedWindowWidth)
    }
}

function Update-LobbyPanel {
    param([Parameter(Mandatory = $true)]$State)
    $lobby = $State.current_lobby
    if ($null -eq $lobby) {
        Set-LobbyPanelVisible -Visible $false
        return
    }
    Set-LobbyPanelVisible -Visible $true
    $script:LobbyTitleLabel.Text = [string]$lobby.lobby_name
    $port = if ($null -ne $lobby.port) { ":$($lobby.port)" } else { '' }
    $address = if ($lobby.host_ip) { "$($lobby.host_ip)$port" } else { '—' }
    $access = if ($lobby.locked) { T 'access_locked' } else { T 'access_open' }
    $script:LobbyInfoLabel.Text = '{0} — {1}/{2} — {3} — {4} · {5}' -f
        $lobby.game, $lobby.member_count, $lobby.capacity, $address,
        (Get-LobbyPhaseText ([string]$lobby.phase)), $access
    $script:LobbyInstructionsTextBox.Text = if (
        [string]::IsNullOrWhiteSpace([string]$lobby.join_instructions)
    ) { T 'no_instructions' } else { [string]$lobby.join_instructions }
    $script:CopyCurrentInfoButton.Enabled = [bool]$lobby.host_ip
    $script:LobbyMembersList.Items.Clear()
    foreach ($member in @($lobby.members)) {
        $item = New-Object Windows.Forms.ListViewItem([string]$member.pseudo)
        [void]$item.SubItems.Add((Get-StatusText ([string]$member.status)))
        [void]$item.SubItems.Add($(if ($member.ready) { T 'ready_yes' } else { T 'ready_no' }))
        [void]$item.SubItems.Add($(if ($member.role -eq 'host') { T 'role_host' } else { T 'role_member' }))
        $statusColor = $script:StatusColors[[string]$member.status]
        if ($statusColor) { $item.ForeColor = $statusColor }
        [void]$script:LobbyMembersList.Items.Add($item)
    }
    $selfMember = @($lobby.members | Where-Object {
        $_.pseudo -eq $script:Config.player
    } | Select-Object -First 1)
    $selfReady = $selfMember.Count -gt 0 -and [bool]$selfMember[0].ready
    $script:ReadyButton.Text = if ($selfReady) { T 'mark_not_ready' } else { T 'mark_ready' }
    $script:ReadyButton.Enabled = $script:IsConnected -and $lobby.phase -eq 'gathering'
    $script:LobbyMessageTextBox.Enabled = $script:IsConnected
    $script:LobbySendButton.Enabled = $script:IsConnected
    $script:LeaveLobbyButton.Enabled = $script:IsConnected
    $isHost = $lobby.host -eq $script:Config.player
    $script:PhaseButton.Visible = $isHost
    $script:LockButton.Visible = $isHost
    $script:PhaseButton.Enabled = $script:IsConnected
    $script:LockButton.Enabled = $script:IsConnected
    $script:TransferHostCombo.Visible = $isHost
    $script:TransferHostButton.Visible = $isHost
    if ($isHost) {
        $script:LeaveLobbyButton.Text = T 'close_lobby'
        $script:PhaseButton.Text = if ($lobby.phase -eq 'in_game') {
            T 'resume_gathering'
        }
        else { T 'start_game' }
        $script:LockButton.Text = if ($lobby.locked) { T 'unlock_lobby' } else { T 'lock_lobby' }
        $selectedTransfer = [string]$script:TransferHostCombo.SelectedItem
        $script:TransferHostCombo.Items.Clear()
        foreach ($member in @($lobby.members)) {
            if ($member.pseudo -ne $script:Config.player -and $member.online) {
                [void]$script:TransferHostCombo.Items.Add([string]$member.pseudo)
            }
        }
        if ($selectedTransfer -and $script:TransferHostCombo.Items.Contains($selectedTransfer)) {
            $script:TransferHostCombo.SelectedItem = $selectedTransfer
        }
        elseif ($script:TransferHostCombo.Items.Count -gt 0) {
            $script:TransferHostCombo.SelectedIndex = 0
        }
        $script:TransferHostButton.Enabled = $script:IsConnected -and
            $script:TransferHostCombo.Items.Count -gt 0
    }
    else { $script:LeaveLobbyButton.Text = T 'leave_lobby' }
}

function Refresh-CompanionState {
    param([switch]$Force)
    if (-not $Force -and [DateTime]::UtcNow -lt $script:NextRefreshAt) { return }
    try {
        $state = Invoke-CompanionApi -Method GET -Path (
            '/api/v2/state?since={0}' -f $script:LastMessageSequence
        ) -Body $null
        Assert-CompatibleState -State $state
        $serverRestarted = $false
        if ($script:ServerInstanceId -and
            $script:ServerInstanceId -ne [string]$state.instance_id) {
            $serverRestarted = $true
            $script:LastMessageSequence = 0L
            $script:MessageList.Items.Clear()
            $script:LobbyMessageList.Items.Clear()
            $script:PublicUnread = 0
            $script:LobbyUnread = 0
            Update-TabTitles
            $state = Invoke-CompanionApi -Method GET -Path '/api/v2/state?since=0' -Body $null
            Assert-CompatibleState -State $state
        }
        $script:ServerInstanceId = [string]$state.instance_id
        $script:LastState = $state
        $script:IsConnected = $true

        $newLobbyId = $null
        if ($null -ne $state.current_lobby) {
            $newLobbyId = [string]$state.current_lobby.id
        }
        $lobbyChanged = $newLobbyId -ne $script:CurrentLobbyId
        $isHostNow = $null -ne $state.current_lobby -and
            $state.current_lobby.host -eq $script:Config.player
        $becameHost = $isHostNow -and -not $script:WasLobbyHost
        if ($lobbyChanged) {
            $script:LobbyMessageList.Items.Clear()
            $script:LobbyUnread = 0
            Update-TabTitles
            $script:CurrentLobbyId = $newLobbyId
        }
        if (($lobbyChanged -or $becameHost) -and $isHostNow) {
            $script:GameTextBox.Text = [string]$state.current_lobby.game
            $script:LobbyNameTextBox.Text = [string]$state.current_lobby.lobby_name
            $script:JoinInstructionsTextBox.Text = [string]$state.current_lobby.join_instructions
            $script:CapacityInput.Value = [decimal]$state.current_lobby.capacity
            $script:PortKnownCheckBox.Checked = $null -ne $state.current_lobby.port
            if ($null -ne $state.current_lobby.port) {
                $script:PortInput.Value = [decimal]$state.current_lobby.port
            }
        }
        $script:WasLobbyHost = $isHostNow

        Update-PlayerGrid -State $state
        Update-LobbyGrid -State $state
        foreach ($message in @($state.messages)) {
            Add-ChatMessage -List $script:MessageList -Message $message
        }
        foreach ($message in @($state.lobby_messages)) {
            Add-ChatMessage -List $script:LobbyMessageList -Message $message -Lobby
        }
        Update-LobbyPanel -State $state
        $script:LastMessageSequence = [int64]$state.message_sequence
        $script:LastConnectionException = $null
        $script:StatusButton.Enabled = $true
        $script:SendButton.Enabled = $true
        $script:MessageTextBox.Enabled = $true
        $selfPlayer = @($state.players | Where-Object {
            $_.pseudo -eq $script:Config.player
        } | Select-Object -First 1)
        if ($selfPlayer.Count -gt 0) {
            $availability = if ($selfPlayer[0].PSObject.Properties['availability_status']) {
                [string]$selfPlayer[0].availability_status
            }
            else { [string]$selfPlayer[0].status }
            $statusIndex = [Array]::IndexOf($script:StatusIds, $availability)
            if ($statusIndex -ge 0) { $script:StatusCombo.SelectedIndex = $statusIndex }
        }
        Update-ConnectionSummary
        $script:RefreshFailures = 0
        $script:NextRefreshAt = [DateTime]::UtcNow
        if ($serverRestarted) {
            $script:NotifyIcon.BalloonTipTitle = T 'app_title'
            $script:NotifyIcon.BalloonTipText = T 'server_restarted'
            $script:NotifyIcon.ShowBalloonTip(4000)
        }
        $script:InitialPoll = $false
    }
    catch {
        $script:RefreshFailures = [Math]::Min(5, $script:RefreshFailures + 1)
        $delayMilliseconds = [Math]::Min(
            30000,
            2000 * [Math]::Pow(2, $script:RefreshFailures - 1)
        ) + (Get-Random -Minimum 0 -Maximum 1001)
        $script:NextRefreshAt = [DateTime]::UtcNow.AddMilliseconds($delayMilliseconds)
        $script:IsConnected = $false
        $script:LastConnectionException = $_.Exception
        $script:ActivityLabel.Text = ''
        $script:StatusButton.Enabled = $false
        $script:SendButton.Enabled = $false
        $script:MessageTextBox.Enabled = $false
        $script:PublishButton.Enabled = $false
        $script:JoinButton.Enabled = $false
        $script:ReadyButton.Enabled = $false
        $script:PhaseButton.Enabled = $false
        $script:LockButton.Enabled = $false
        $script:TransferHostButton.Enabled = $false
        $script:LeaveLobbyButton.Enabled = $false
        $script:LobbyMessageTextBox.Enabled = $false
        $script:LobbySendButton.Enabled = $false
        $script:ConnectionLabel.Text = '{0}: {1}' -f (T 'offline'), (Get-ErrorText $_.Exception)
        $script:ConnectionLabel.ForeColor = [Drawing.Color]::DarkRed
    }
}

function Send-CompanionMessage {
    $text = $script:MessageTextBox.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return }
    $target = $null
    if ($script:TargetCombo.SelectedIndex -gt 0) {
        $target = [string]$script:TargetCombo.SelectedItem
    }
    try {
        [void](Invoke-CompanionApi -Method POST -Path '/api/v2/message' -Body @{
            target = $target
            text = $text
            color = $script:Settings.message_color
        })
        $script:MessageTextBox.Clear()
        Refresh-CompanionState -Force
    }
    catch {
        [Windows.Forms.MessageBox]::Show(
            (T 'message_not_sent' @((Get-ErrorText $_.Exception))),
            (T 'app_title'),
            [Windows.Forms.MessageBoxButtons]::OK,
            [Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
    }
}

function Send-LobbyMessage {
    $text = $script:LobbyMessageTextBox.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return }
    try {
        [void](Invoke-CompanionApi -Method POST -Path '/api/v2/lobby/message' -Body @{
            text = $text
            color = $script:Settings.message_color
        })
        $script:LobbyMessageTextBox.Clear()
        Refresh-CompanionState -Force
    }
    catch {
        [Windows.Forms.MessageBox]::Show(
            (T 'lobby_message_not_sent' @((Get-ErrorText $_.Exception))),
            (T 'app_title'),
            [Windows.Forms.MessageBoxButtons]::OK,
            [Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
    }
}

function Set-CompanionStatus {
    if ($script:StatusCombo.SelectedIndex -lt 0) { return }
    $status = $script:StatusIds[$script:StatusCombo.SelectedIndex]
    try {
        [void](Invoke-CompanionApi -Method POST -Path '/api/v2/status' -Body @{
            status = $status
        })
        Refresh-CompanionState -Force
    }
    catch { $script:ConnectionLabel.Text = Get-ErrorText $_.Exception }
}

function Publish-Lobby {
    $game = $script:GameTextBox.Text.Trim()
    $lobbyName = $script:LobbyNameTextBox.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($game)) {
        [Windows.Forms.MessageBox]::Show((T 'game_required'), (T 'app_title')) | Out-Null
        return
    }
    if ([string]::IsNullOrWhiteSpace($lobbyName)) {
        [Windows.Forms.MessageBox]::Show((T 'lobby_name_required'), (T 'app_title')) | Out-Null
        return
    }
    $port = $null
    if ($script:PortKnownCheckBox.Checked) { $port = [int]$script:PortInput.Value }
    $expectedRevision = $null
    if ($script:LastState -and
        $null -ne $script:LastState.current_lobby -and
        $script:LastState.current_lobby.host -eq $script:Config.player) {
        $expectedRevision = [int]$script:LastState.current_lobby.revision
    }
    try {
        [void](Invoke-CompanionApi -Method POST -Path '/api/v2/lobby' -Body @{
            game = $game
            lobby_name = $lobbyName
            join_instructions = $script:JoinInstructionsTextBox.Text.Trim()
            port = $port
            capacity = [int]$script:CapacityInput.Value
            expected_revision = $expectedRevision
        })
        Refresh-CompanionState -Force
    }
    catch {
        [Windows.Forms.MessageBox]::Show(
            (T 'request_failed' @((Get-ErrorText $_.Exception))),
            (T 'app_title')
        ) | Out-Null
    }
}

function Get-SelectedLobby {
    if ($script:LobbiesGrid.SelectedRows.Count -eq 0) { return $null }
    return $script:LobbiesGrid.SelectedRows[0].Tag
}

function Update-LobbyActionAvailability {
    $lobby = Get-SelectedLobby
    $hasCurrentLobby = $script:LastState -and
        $null -ne $script:LastState.current_lobby
    $isFull = $lobby -and $lobby.member_count -ge $lobby.capacity
    $isLocked = $lobby -and [bool]$lobby.locked
    $script:JoinButton.Enabled = [bool](
        $script:IsConnected -and $lobby -and -not $hasCurrentLobby -and
        -not $isFull -and -not $isLocked
    )
    $script:CopyAddressButton.Enabled = [bool]$lobby
    $script:PublishButton.Enabled = [bool](
        $script:IsConnected -and (
            -not $hasCurrentLobby -or
            $script:LastState.current_lobby.host -eq $script:Config.player
        )
    )
}

function Join-SelectedLobby {
    $lobby = Get-SelectedLobby
    if (-not $lobby) {
        [Windows.Forms.MessageBox]::Show((T 'selected_required'), (T 'app_title')) | Out-Null
        return
    }
    try {
        [void](Invoke-CompanionApi -Method POST -Path '/api/v2/lobby/join' -Body @{
            lobby_id = [string]$lobby.id
        })
        Refresh-CompanionState -Force
    }
    catch {
        [Windows.Forms.MessageBox]::Show(
            (T 'request_failed' @((Get-ErrorText $_.Exception))),
            (T 'app_title')
        ) | Out-Null
    }
}

function Leave-CurrentLobby {
    if (-not $script:LastState -or $null -eq $script:LastState.current_lobby) { return }
    $isHost = $script:LastState.current_lobby.host -eq $script:Config.player
    $confirmationKey = if ($isHost) { 'confirm_close_lobby' } else { 'confirm_leave_lobby' }
    $answer = [Windows.Forms.MessageBox]::Show(
        (T $confirmationKey),
        (T 'app_title'),
        [Windows.Forms.MessageBoxButtons]::YesNo,
        [Windows.Forms.MessageBoxIcon]::Question,
        [Windows.Forms.MessageBoxDefaultButton]::Button2
    )
    if ($answer -ne [Windows.Forms.DialogResult]::Yes) { return }
    try {
        if ($isHost) {
            [void](Invoke-CompanionApi -Method DELETE -Path '/api/v2/lobby' -Body $null)
        }
        else {
            [void](Invoke-CompanionApi -Method POST -Path '/api/v2/lobby/leave' -Body @{})
        }
        $script:LobbyMessageList.Items.Clear()
        Refresh-CompanionState -Force
    }
    catch {
        [Windows.Forms.MessageBox]::Show(
            (T 'request_failed' @((Get-ErrorText $_.Exception))),
            (T 'app_title'),
            [Windows.Forms.MessageBoxButtons]::OK,
            [Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
    }
}

function Get-LobbyConnectionInfo {
    param([Parameter(Mandatory = $true)]$Lobby)

    $address = if ($Lobby.host_ip) { [string]$Lobby.host_ip } else { '—' }
    if ($Lobby.host_ip -and $null -ne $Lobby.port) {
        $address = '{0}:{1}' -f $address, $Lobby.port
    }
    $instructions = if (
        [string]::IsNullOrWhiteSpace([string]$Lobby.join_instructions)
    ) { T 'no_instructions' } else { [string]$Lobby.join_instructions }
    return @(
        [string]$Lobby.lobby_name
        "$(T 'game') $($Lobby.game)"
        "$(T 'host'): $($Lobby.host)"
        "$(T 'address'): $address"
        "$(T 'occupancy'): $($Lobby.member_count)/$($Lobby.capacity)"
        "$(T 'join_instructions') $instructions"
    ) -join [Environment]::NewLine
}

function Copy-LobbyConnectionInfo {
    param([Parameter(Mandatory = $true)]$Lobby)

    if (-not $Lobby.host_ip) {
        [Windows.Forms.MessageBox]::Show((T 'address_unavailable'), (T 'app_title')) | Out-Null
        return
    }
    try {
        [Windows.Forms.Clipboard]::SetText((Get-LobbyConnectionInfo -Lobby $Lobby))
    }
    catch {
        [Windows.Forms.MessageBox]::Show(
            (T 'request_failed' @($_.Exception.Message)),
            (T 'app_title'),
            [Windows.Forms.MessageBoxButtons]::OK,
            [Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        return
    }
    [Windows.Forms.MessageBox]::Show(
        "$(T 'address_copied')`n`n$(T 'launch_hint')",
        (T 'app_title'),
        [Windows.Forms.MessageBoxButtons]::OK,
        [Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
}

function Copy-SelectedLobbyAddress {
    $lobby = Get-SelectedLobby
    if (-not $lobby) {
        [Windows.Forms.MessageBox]::Show((T 'selected_required'), (T 'app_title')) | Out-Null
        return
    }
    Copy-LobbyConnectionInfo -Lobby $lobby
}

function Invoke-CurrentLobbyMutation {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][hashtable]$Body
    )
    try {
        [void](Invoke-CompanionApi -Method POST -Path $Path -Body $Body)
        Refresh-CompanionState -Force
    }
    catch {
        [Windows.Forms.MessageBox]::Show(
            (T 'request_failed' @((Get-ErrorText $_.Exception))),
            (T 'app_title'),
            [Windows.Forms.MessageBoxButtons]::OK,
            [Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
        Refresh-CompanionState -Force
    }
}

function Set-LobbyReady {
    if (-not $script:LastState -or $null -eq $script:LastState.current_lobby) { return }
    $selfMember = @($script:LastState.current_lobby.members | Where-Object {
        $_.pseudo -eq $script:Config.player
    } | Select-Object -First 1)
    if ($selfMember.Count -eq 0) { return }
    Invoke-CurrentLobbyMutation -Path '/api/v2/lobby/ready' -Body @{
        ready = -not [bool]$selfMember[0].ready
    }
}

function Toggle-LobbyPhase {
    if (-not $script:LastState -or $null -eq $script:LastState.current_lobby) { return }
    $lobby = $script:LastState.current_lobby
    $phase = if ($lobby.phase -eq 'in_game') { 'gathering' } else { 'in_game' }
    Invoke-CurrentLobbyMutation -Path '/api/v2/lobby/phase' -Body @{
        phase = $phase
        expected_revision = [int]$lobby.revision
    }
}

function Toggle-LobbyLock {
    if (-not $script:LastState -or $null -eq $script:LastState.current_lobby) { return }
    $lobby = $script:LastState.current_lobby
    Invoke-CurrentLobbyMutation -Path '/api/v2/lobby/lock' -Body @{
        locked = -not [bool]$lobby.locked
        expected_revision = [int]$lobby.revision
    }
}

function Transfer-LobbyHost {
    if (-not $script:LastState -or $null -eq $script:LastState.current_lobby -or
        $script:TransferHostCombo.SelectedIndex -lt 0) {
        [Windows.Forms.MessageBox]::Show(
            (T 'transfer_target_required'),
            (T 'app_title')
        ) | Out-Null
        return
    }
    $target = [string]$script:TransferHostCombo.SelectedItem
    $answer = [Windows.Forms.MessageBox]::Show(
        (T 'confirm_transfer_host' @($target)),
        (T 'app_title'),
        [Windows.Forms.MessageBoxButtons]::YesNo,
        [Windows.Forms.MessageBoxIcon]::Question,
        [Windows.Forms.MessageBoxDefaultButton]::Button2
    )
    if ($answer -ne [Windows.Forms.DialogResult]::Yes) { return }
    Invoke-CurrentLobbyMutation -Path '/api/v2/lobby/transfer' -Body @{
        target = $target
        expected_revision = [int]$script:LastState.current_lobby.revision
    }
}

function Show-CompanionDiagnostics {
    $serverVersion = '—'
    $apiVersion = '—'
    $vpnIp = '—'
    $session = '—'
    $lobbyName = T 'none'
    if ($script:LastState) {
        $serverVersion = [string]$script:LastState.server_version
        $apiVersion = [string]$script:LastState.api_version
        $selfPlayer = @($script:LastState.players | Where-Object {
            $_.pseudo -eq $script:Config.player
        } | Select-Object -First 1)
        if ($selfPlayer.Count -gt 0) {
            if ($selfPlayer[0].vpn_ip) { $vpnIp = [string]$selfPlayer[0].vpn_ip }
            $session = Format-CompanionDuration -Seconds ([int]$selfPlayer[0].connected_for_seconds)
        }
        if ($null -ne $script:LastState.current_lobby) {
            $lobbyName = '{0} ({1})' -f
                $script:LastState.current_lobby.lobby_name,
                (Get-LobbyPhaseText ([string]$script:LastState.current_lobby.phase))
        }
    }
    $latencyState = if ($script:Settings.latency_enabled) { T 'enabled' } else { T 'disabled' }
    $connectionState = if ($script:IsConnected) { T 'reachable' } else { T 'unreachable' }
    $details = @(
        "$(T 'diagnostic_client'): $($script:ClientVersion)"
        "$(T 'diagnostic_server'): $serverVersion"
        "$(T 'diagnostic_api'): $apiVersion"
        "$(T 'diagnostic_server_url'): $($script:ServerUrl)"
        "$(T 'diagnostic_connection'): $connectionState"
        "$(T 'diagnostic_player'): $($script:Config.player)"
        "$(T 'diagnostic_vpn_ip'): $vpnIp"
        "$(T 'diagnostic_session'): $session"
        "$(T 'diagnostic_lobby'): $lobbyName"
        "$(T 'diagnostic_latency'): $latencyState"
    ) -join [Environment]::NewLine
    [Windows.Forms.MessageBox]::Show(
        $details,
        (T 'diagnostics'),
        [Windows.Forms.MessageBoxButtons]::OK,
        [Windows.Forms.MessageBoxIcon]::Information
    ) | Out-Null
}

try {
    $script:Config = Read-CompanionConfig -Path $ConfigPath
    $script:ServerUrl = ([string]$script:Config.server_url).TrimEnd('/')
    $script:SettingsPath = Join-Path (Split-Path -Parent $ConfigPath) 'settings.json'
    $script:Settings = Read-CompanionSettings -Path $script:SettingsPath
    $script:LastMessageSequence = 0L
    $script:ServerInstanceId = $null
    $script:LastState = $null
    $script:CurrentLobbyId = $null
    $script:WasLobbyHost = $false
    $script:InitialPoll = $true
    $script:IsConnected = $false
    $script:LastConnectionException = $null
    $script:ExitRequested = $false
    $script:LobbyExpanded = $false
    $script:CollapsedWindowWidth = 850
    $script:PublicUnread = 0
    $script:LobbyUnread = 0
    $script:LatencyResults = @{}
    $script:PingTask = $null
    $script:PingClient = $null
    $script:PingPlayer = $null
    $script:PingAddress = $null
    $script:NextPingAt = [DateTime]::UtcNow
    $script:NextRefreshAt = [DateTime]::UtcNow
    $script:RefreshFailures = 0
    $script:Initializing = $true

    $mutexCreated = $false
    $mutexName = 'Local\OpenVPNLanPartyCompanion-{0}' -f $script:Config.player
    $script:InstanceMutex = New-Object Threading.Mutex($true, $mutexName, [ref]$mutexCreated)
    if (-not $mutexCreated) {
        [Windows.Forms.MessageBox]::Show((T 'already_running'), (T 'app_title')) | Out-Null
        exit 0
    }

    $script:Form = New-Object Windows.Forms.Form
    $script:Form.Size = New-Object Drawing.Size(850, 650)
    $script:Form.MinimumSize = New-Object Drawing.Size(760, 520)
    $script:Form.StartPosition = [Windows.Forms.FormStartPosition]::CenterScreen
    $script:Form.Icon = [Drawing.SystemIcons]::Application
    $script:ToolTip = New-Object Windows.Forms.ToolTip

    $script:OuterLayout = New-Object Windows.Forms.TableLayoutPanel
    $script:OuterLayout.Dock = [Windows.Forms.DockStyle]::Fill
    $script:OuterLayout.ColumnCount = 2
    $script:OuterLayout.RowCount = 1
    [void]$script:OuterLayout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 100)))
    [void]$script:OuterLayout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Absolute, 0)))

    $rootLayout = New-Object Windows.Forms.TableLayoutPanel
    $rootLayout.Dock = [Windows.Forms.DockStyle]::Fill
    $rootLayout.RowCount = 3
    $rootLayout.ColumnCount = 1
    [void]$rootLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 72)))
    [void]$rootLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, 100)))
    [void]$rootLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 28)))

    $topPanel = New-Object Windows.Forms.FlowLayoutPanel
    $topPanel.Dock = [Windows.Forms.DockStyle]::Fill
    $topPanel.Padding = New-Object Windows.Forms.Padding(8, 7, 8, 3)
    $script:IdentityLabel = New-Object Windows.Forms.Label
    $script:IdentityLabel.AutoSize = $true
    $script:IdentityLabel.Margin = New-Object Windows.Forms.Padding(0, 6, 14, 0)
    $topPanel.Controls.Add($script:IdentityLabel)
    $script:StatusLabel = New-Object Windows.Forms.Label
    $script:StatusLabel.AutoSize = $true
    $script:StatusLabel.Margin = New-Object Windows.Forms.Padding(0, 6, 3, 0)
    $topPanel.Controls.Add($script:StatusLabel)
    $script:StatusCombo = New-Object Windows.Forms.ComboBox
    $script:StatusCombo.DropDownStyle = [Windows.Forms.ComboBoxStyle]::DropDownList
    $script:StatusCombo.Width = 100
    $topPanel.Controls.Add($script:StatusCombo)
    $script:StatusButton = New-Object Windows.Forms.Button
    $script:StatusButton.AutoSize = $true
    $script:StatusButton.Add_Click({ Set-CompanionStatus })
    $topPanel.Controls.Add($script:StatusButton)
    $script:ActivityLabel = New-Object Windows.Forms.Label
    $script:ActivityLabel.AutoSize = $true
    $script:ActivityLabel.ForeColor = $script:StatusColors.in_game
    $script:ActivityLabel.Margin = New-Object Windows.Forms.Padding(8, 6, 4, 0)
    $topPanel.Controls.Add($script:ActivityLabel)
    $script:LatencyCheckBox = New-Object Windows.Forms.CheckBox
    $script:LatencyCheckBox.AutoSize = $true
    $script:LatencyCheckBox.Checked = [bool]$script:Settings.latency_enabled
    $script:LatencyCheckBox.Margin = New-Object Windows.Forms.Padding(10, 5, 8, 0)
    $script:LatencyCheckBox.Add_CheckedChanged({
        if (-not $script:Initializing) {
            $script:Settings.latency_enabled = $script:LatencyCheckBox.Checked
            Save-CompanionSettings
        }
    })
    $topPanel.Controls.Add($script:LatencyCheckBox)
    $script:LanguageLabel = New-Object Windows.Forms.Label
    $script:LanguageLabel.AutoSize = $true
    $script:LanguageLabel.Margin = New-Object Windows.Forms.Padding(6, 6, 3, 0)
    $topPanel.Controls.Add($script:LanguageLabel)
    $script:LanguageCombo = New-Object Windows.Forms.ComboBox
    $script:LanguageCombo.DropDownStyle = [Windows.Forms.ComboBoxStyle]::DropDownList
    $script:LanguageCombo.Width = 82
    [void]$script:LanguageCombo.Items.AddRange(@('Français', 'English'))
    $script:LanguageCombo.SelectedIndex = if ($script:Settings.language -eq 'fr') { 0 } else { 1 }
    $script:LanguageCombo.Add_SelectedIndexChanged({
        if (-not $script:Initializing) {
            $script:Settings.language = if ($script:LanguageCombo.SelectedIndex -eq 0) { 'fr' } else { 'en' }
            Save-CompanionSettings
            Apply-Language
        }
    })
    $topPanel.Controls.Add($script:LanguageCombo)
    $script:DiagnosticsButton = New-Object Windows.Forms.Button
    $script:DiagnosticsButton.AutoSize = $true
    $script:DiagnosticsButton.Margin = New-Object Windows.Forms.Padding(8, 1, 0, 0)
    $script:DiagnosticsButton.Add_Click({ Show-CompanionDiagnostics })
    $topPanel.Controls.Add($script:DiagnosticsButton)
    $script:QuitButton = New-Object Windows.Forms.Button
    $script:QuitButton.AutoSize = $true
    $script:QuitButton.Margin = New-Object Windows.Forms.Padding(8, 1, 0, 0)
    $script:QuitButton.Add_Click({
        $script:QuitContextMenu.Show(
            $script:QuitButton,
            (New-Object Drawing.Point(0, $script:QuitButton.Height))
        )
    })
    $topPanel.Controls.Add($script:QuitButton)

    $script:Tabs = New-Object Windows.Forms.TabControl
    $script:Tabs.Dock = [Windows.Forms.DockStyle]::Fill

    $script:PlayersTab = New-Object Windows.Forms.TabPage
    $script:PlayersGrid = New-Object Windows.Forms.DataGridView
    $script:PlayersGrid.Dock = [Windows.Forms.DockStyle]::Fill
    $script:PlayersGrid.ReadOnly = $true
    $script:PlayersGrid.AllowUserToAddRows = $false
    $script:PlayersGrid.AllowUserToDeleteRows = $false
    $script:PlayersGrid.AutoSizeColumnsMode = [Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
    $script:PlayersGrid.SelectionMode = [Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
    [void]$script:PlayersGrid.Columns.Add('Pseudo', '')
    [void]$script:PlayersGrid.Columns.Add('VpnIp', '')
    [void]$script:PlayersGrid.Columns.Add('Status', '')
    [void]$script:PlayersGrid.Columns.Add('Ping', '')
    [void]$script:PlayersGrid.Columns.Add('LastSeen', '')
    $script:PlayersTab.Controls.Add($script:PlayersGrid)
    [void]$script:Tabs.TabPages.Add($script:PlayersTab)

    $script:ChatTab = New-Object Windows.Forms.TabPage
    $chatLayout = New-Object Windows.Forms.TableLayoutPanel
    $chatLayout.Dock = [Windows.Forms.DockStyle]::Fill
    $chatLayout.RowCount = 3
    $chatLayout.ColumnCount = 1
    [void]$chatLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 40)))
    [void]$chatLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, 100)))
    [void]$chatLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 42)))
    $targetPanel = New-Object Windows.Forms.FlowLayoutPanel
    $targetPanel.Dock = [Windows.Forms.DockStyle]::Fill
    $targetPanel.Padding = New-Object Windows.Forms.Padding(5)
    $script:TargetLabel = New-Object Windows.Forms.Label
    $script:TargetLabel.AutoSize = $true
    $script:TargetLabel.Margin = New-Object Windows.Forms.Padding(0, 6, 3, 0)
    $targetPanel.Controls.Add($script:TargetLabel)
    $script:TargetCombo = New-Object Windows.Forms.ComboBox
    $script:TargetCombo.DropDownStyle = [Windows.Forms.ComboBoxStyle]::DropDownList
    $script:TargetCombo.Width = 160
    $targetPanel.Controls.Add($script:TargetCombo)
    $script:ColorLabel = New-Object Windows.Forms.Label
    $script:ColorLabel.AutoSize = $true
    $script:ColorLabel.Margin = New-Object Windows.Forms.Padding(15, 6, 3, 0)
    $targetPanel.Controls.Add($script:ColorLabel)
    $script:ColorCombo = New-Object Windows.Forms.ComboBox
    $script:ColorCombo.DropDownStyle = [Windows.Forms.ComboBoxStyle]::DropDownList
    $script:ColorCombo.Width = 110
    $script:ColorCombo.Add_SelectedIndexChanged({
        if (-not $script:Initializing -and $script:ColorCombo.SelectedIndex -ge 0) {
            $script:Settings.message_color = $script:ColorIds[$script:ColorCombo.SelectedIndex]
            Save-CompanionSettings
        }
    })
    $targetPanel.Controls.Add($script:ColorCombo)
    $chatLayout.Controls.Add($targetPanel, 0, 0)
    $script:MessageList = New-Object Windows.Forms.ListView
    $script:MessageList.Dock = [Windows.Forms.DockStyle]::Fill
    $script:MessageList.View = [Windows.Forms.View]::Details
    $script:MessageList.FullRowSelect = $true
    [void]$script:MessageList.Columns.Add('', 75)
    [void]$script:MessageList.Columns.Add('', 140)
    [void]$script:MessageList.Columns.Add('', 500)
    $chatLayout.Controls.Add($script:MessageList, 0, 1)
    $messagePanel = New-Object Windows.Forms.TableLayoutPanel
    $messagePanel.Dock = [Windows.Forms.DockStyle]::Fill
    $messagePanel.ColumnCount = 2
    [void]$messagePanel.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 100)))
    [void]$messagePanel.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Absolute, 105)))
    $script:MessageTextBox = New-Object Windows.Forms.TextBox
    $script:MessageTextBox.Dock = [Windows.Forms.DockStyle]::Fill
    $script:MessageTextBox.MaxLength = 500
    $script:MessageTextBox.Margin = New-Object Windows.Forms.Padding(4, 8, 4, 6)
    $script:MessageTextBox.Add_KeyDown({
        param($sender, $eventArgs)
        if ($eventArgs.KeyCode -eq [Windows.Forms.Keys]::Enter) {
            $eventArgs.SuppressKeyPress = $true
            Send-CompanionMessage
        }
    })
    $messagePanel.Controls.Add($script:MessageTextBox, 0, 0)
    $script:SendButton = New-Object Windows.Forms.Button
    $script:SendButton.Dock = [Windows.Forms.DockStyle]::Fill
    $script:SendButton.Margin = New-Object Windows.Forms.Padding(4, 6, 4, 4)
    $script:SendButton.Add_Click({ Send-CompanionMessage })
    $messagePanel.Controls.Add($script:SendButton, 1, 0)
    $chatLayout.Controls.Add($messagePanel, 0, 2)
    $script:ChatTab.Controls.Add($chatLayout)
    [void]$script:Tabs.TabPages.Add($script:ChatTab)

    $script:LobbiesTab = New-Object Windows.Forms.TabPage
    $lobbiesLayout = New-Object Windows.Forms.TableLayoutPanel
    $lobbiesLayout.Dock = [Windows.Forms.DockStyle]::Fill
    $lobbiesLayout.RowCount = 2
    $lobbiesLayout.ColumnCount = 1
    [void]$lobbiesLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, 50)))
    [void]$lobbiesLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, 50)))
    $script:LobbiesGrid = New-Object Windows.Forms.DataGridView
    $script:LobbiesGrid.Dock = [Windows.Forms.DockStyle]::Fill
    $script:LobbiesGrid.ReadOnly = $true
    $script:LobbiesGrid.AllowUserToAddRows = $false
    $script:LobbiesGrid.AllowUserToDeleteRows = $false
    $script:LobbiesGrid.AutoSizeColumnsMode = [Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
    $script:LobbiesGrid.SelectionMode = [Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
    $script:LobbiesGrid.MultiSelect = $false
    $script:LobbiesGrid.Add_SelectionChanged({ Update-LobbyActionAvailability })
    [void]$script:LobbiesGrid.Columns.Add('Game', '')
    [void]$script:LobbiesGrid.Columns.Add('LobbyName', '')
    [void]$script:LobbiesGrid.Columns.Add('Host', '')
    [void]$script:LobbiesGrid.Columns.Add('Address', '')
    [void]$script:LobbiesGrid.Columns.Add('Port', '')
    [void]$script:LobbiesGrid.Columns.Add('Occupancy', '')
    [void]$script:LobbiesGrid.Columns.Add('State', '')
    $lobbiesLayout.Controls.Add($script:LobbiesGrid, 0, 0)
    $editor = New-Object Windows.Forms.TableLayoutPanel
    $editor.Dock = [Windows.Forms.DockStyle]::Fill
    $editor.ColumnCount = 4
    $editor.RowCount = 4
    [void]$editor.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Absolute, 100)))
    [void]$editor.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 55)))
    [void]$editor.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Absolute, 110)))
    [void]$editor.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 45)))
    [void]$editor.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 32)))
    [void]$editor.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 32)))
    [void]$editor.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, 100)))
    [void]$editor.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 40)))
    $script:GameLabel = New-Object Windows.Forms.Label
    $script:GameLabel.TextAlign = [Drawing.ContentAlignment]::MiddleRight
    $editor.Controls.Add($script:GameLabel, 0, 0)
    $script:GameTextBox = New-Object Windows.Forms.TextBox
    $script:GameTextBox.Dock = [Windows.Forms.DockStyle]::Fill
    $script:GameTextBox.MaxLength = 80
    $editor.Controls.Add($script:GameTextBox, 1, 0)
    $script:PortKnownCheckBox = New-Object Windows.Forms.CheckBox
    $script:PortKnownCheckBox.TextAlign = [Drawing.ContentAlignment]::MiddleRight
    $script:PortKnownCheckBox.Checked = $false
    $script:PortKnownCheckBox.Add_CheckedChanged({
        $script:PortInput.Enabled = $script:PortKnownCheckBox.Checked
    })
    $editor.Controls.Add($script:PortKnownCheckBox, 2, 0)
    $script:PortInput = New-Object Windows.Forms.NumericUpDown
    $script:PortInput.Minimum = 1
    $script:PortInput.Maximum = 65535
    $script:PortInput.Value = 27960
    $script:PortInput.Enabled = $false
    $script:PortInput.Dock = [Windows.Forms.DockStyle]::Fill
    $editor.Controls.Add($script:PortInput, 3, 0)
    $script:LobbyNameLabel = New-Object Windows.Forms.Label
    $script:LobbyNameLabel.TextAlign = [Drawing.ContentAlignment]::MiddleRight
    $editor.Controls.Add($script:LobbyNameLabel, 0, 1)
    $script:LobbyNameTextBox = New-Object Windows.Forms.TextBox
    $script:LobbyNameTextBox.Dock = [Windows.Forms.DockStyle]::Fill
    $script:LobbyNameTextBox.MaxLength = 80
    $editor.Controls.Add($script:LobbyNameTextBox, 1, 1)
    $script:CapacityLabel = New-Object Windows.Forms.Label
    $script:CapacityLabel.TextAlign = [Drawing.ContentAlignment]::MiddleRight
    $editor.Controls.Add($script:CapacityLabel, 2, 1)
    $script:CapacityInput = New-Object Windows.Forms.NumericUpDown
    $script:CapacityInput.Minimum = 2
    $script:CapacityInput.Maximum = 128
    $script:CapacityInput.Value = 8
    $script:CapacityInput.Dock = [Windows.Forms.DockStyle]::Fill
    $editor.Controls.Add($script:CapacityInput, 3, 1)
    $script:JoinInstructionsLabel = New-Object Windows.Forms.Label
    $script:JoinInstructionsLabel.TextAlign = [Drawing.ContentAlignment]::MiddleRight
    $editor.Controls.Add($script:JoinInstructionsLabel, 0, 2)
    $script:JoinInstructionsTextBox = New-Object Windows.Forms.TextBox
    $script:JoinInstructionsTextBox.Dock = [Windows.Forms.DockStyle]::Fill
    $script:JoinInstructionsTextBox.Multiline = $true
    $script:JoinInstructionsTextBox.ScrollBars = [Windows.Forms.ScrollBars]::Vertical
    $script:JoinInstructionsTextBox.MaxLength = 600
    $editor.Controls.Add($script:JoinInstructionsTextBox, 1, 2)
    $editor.SetColumnSpan($script:JoinInstructionsTextBox, 3)
    $buttons = New-Object Windows.Forms.FlowLayoutPanel
    $buttons.Dock = [Windows.Forms.DockStyle]::Fill
    $script:PublishButton = New-Object Windows.Forms.Button
    $script:PublishButton.AutoSize = $true
    $script:PublishButton.Add_Click({ Publish-Lobby })
    $buttons.Controls.Add($script:PublishButton)
    $script:JoinButton = New-Object Windows.Forms.Button
    $script:JoinButton.AutoSize = $true
    $script:JoinButton.Enabled = $false
    $script:JoinButton.Add_Click({ Join-SelectedLobby })
    $buttons.Controls.Add($script:JoinButton)
    $script:CopyAddressButton = New-Object Windows.Forms.Button
    $script:CopyAddressButton.AutoSize = $true
    $script:CopyAddressButton.Enabled = $false
    $script:CopyAddressButton.Add_Click({ Copy-SelectedLobbyAddress })
    $buttons.Controls.Add($script:CopyAddressButton)
    $editor.Controls.Add($buttons, 0, 3)
    $editor.SetColumnSpan($buttons, 4)
    $lobbiesLayout.Controls.Add($editor, 0, 1)
    $script:LobbiesTab.Controls.Add($lobbiesLayout)
    [void]$script:Tabs.TabPages.Add($script:LobbiesTab)
    $script:Tabs.Add_SelectedIndexChanged({
        if ($script:Tabs.SelectedTab -eq $script:ChatTab) { $script:PublicUnread = 0 }
        if ($script:Tabs.SelectedTab -eq $script:LobbiesTab) { $script:LobbyUnread = 0 }
        Update-TabTitles
    })

    $script:ConnectionLabel = New-Object Windows.Forms.Label
    $script:ConnectionLabel.Dock = [Windows.Forms.DockStyle]::Fill
    $script:ConnectionLabel.Padding = New-Object Windows.Forms.Padding(8, 5, 4, 2)
    $rootLayout.Controls.Add($topPanel, 0, 0)
    $rootLayout.Controls.Add($script:Tabs, 0, 1)
    $rootLayout.Controls.Add($script:ConnectionLabel, 0, 2)
    $script:OuterLayout.Controls.Add($rootLayout, 0, 0)

    $script:LobbyPanel = New-Object Windows.Forms.Panel
    $script:LobbyPanel.Dock = [Windows.Forms.DockStyle]::Fill
    $script:LobbyPanel.Padding = New-Object Windows.Forms.Padding(8)
    $script:LobbyPanel.BorderStyle = [Windows.Forms.BorderStyle]::FixedSingle
    $lobbyPanelLayout = New-Object Windows.Forms.TableLayoutPanel
    $lobbyPanelLayout.Dock = [Windows.Forms.DockStyle]::Fill
    $lobbyPanelLayout.RowCount = 10
    $lobbyPanelLayout.ColumnCount = 1
    [void]$lobbyPanelLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 34)))
    [void]$lobbyPanelLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 44)))
    [void]$lobbyPanelLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 28)))
    [void]$lobbyPanelLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 68)))
    [void]$lobbyPanelLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 24)))
    [void]$lobbyPanelLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, 30)))
    [void]$lobbyPanelLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 72)))
    [void]$lobbyPanelLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 24)))
    [void]$lobbyPanelLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, 70)))
    [void]$lobbyPanelLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 44)))
    $script:LobbyTitleLabel = New-Object Windows.Forms.Label
    $script:LobbyTitleLabel.Dock = [Windows.Forms.DockStyle]::Fill
    $script:LobbyTitleLabel.Font = New-Object Drawing.Font($script:Form.Font.FontFamily, 13, [Drawing.FontStyle]::Bold)
    $lobbyPanelLayout.Controls.Add($script:LobbyTitleLabel, 0, 0)
    $script:LobbyInfoLabel = New-Object Windows.Forms.Label
    $script:LobbyInfoLabel.Dock = [Windows.Forms.DockStyle]::Fill
    $script:LobbyInfoLabel.AutoEllipsis = $true
    $lobbyPanelLayout.Controls.Add($script:LobbyInfoLabel, 0, 1)
    $instructionHeader = New-Object Windows.Forms.FlowLayoutPanel
    $instructionHeader.Dock = [Windows.Forms.DockStyle]::Fill
    $instructionHeader.Margin = New-Object Windows.Forms.Padding(0)
    $script:LobbyInstructionsLabel = New-Object Windows.Forms.Label
    $script:LobbyInstructionsLabel.AutoSize = $true
    $script:LobbyInstructionsLabel.Margin = New-Object Windows.Forms.Padding(0, 6, 8, 0)
    $instructionHeader.Controls.Add($script:LobbyInstructionsLabel)
    $script:CopyCurrentInfoButton = New-Object Windows.Forms.Button
    $script:CopyCurrentInfoButton.AutoSize = $true
    $script:CopyCurrentInfoButton.Margin = New-Object Windows.Forms.Padding(0)
    $script:CopyCurrentInfoButton.Add_Click({
        if ($script:LastState -and $null -ne $script:LastState.current_lobby) {
            Copy-LobbyConnectionInfo -Lobby $script:LastState.current_lobby
        }
    })
    $instructionHeader.Controls.Add($script:CopyCurrentInfoButton)
    $lobbyPanelLayout.Controls.Add($instructionHeader, 0, 2)
    $script:LobbyInstructionsTextBox = New-Object Windows.Forms.TextBox
    $script:LobbyInstructionsTextBox.Dock = [Windows.Forms.DockStyle]::Fill
    $script:LobbyInstructionsTextBox.Multiline = $true
    $script:LobbyInstructionsTextBox.ReadOnly = $true
    $script:LobbyInstructionsTextBox.ScrollBars = [Windows.Forms.ScrollBars]::Vertical
    $script:LobbyInstructionsTextBox.BackColor = [Drawing.SystemColors]::Window
    $lobbyPanelLayout.Controls.Add($script:LobbyInstructionsTextBox, 0, 3)
    $script:LobbyMembersLabel = New-Object Windows.Forms.Label
    $script:LobbyMembersLabel.Dock = [Windows.Forms.DockStyle]::Fill
    $lobbyPanelLayout.Controls.Add($script:LobbyMembersLabel, 0, 4)
    $script:LobbyMembersList = New-Object Windows.Forms.ListView
    $script:LobbyMembersList.Dock = [Windows.Forms.DockStyle]::Fill
    $script:LobbyMembersList.View = [Windows.Forms.View]::Details
    $script:LobbyMembersList.FullRowSelect = $true
    [void]$script:LobbyMembersList.Columns.Add('', 115)
    [void]$script:LobbyMembersList.Columns.Add('', 90)
    [void]$script:LobbyMembersList.Columns.Add('', 65)
    [void]$script:LobbyMembersList.Columns.Add('', 85)
    $lobbyPanelLayout.Controls.Add($script:LobbyMembersList, 0, 5)
    $lobbyAdminActions = New-Object Windows.Forms.FlowLayoutPanel
    $lobbyAdminActions.Dock = [Windows.Forms.DockStyle]::Fill
    $lobbyAdminActions.WrapContents = $true
    $lobbyAdminActions.Margin = New-Object Windows.Forms.Padding(0)
    $script:ReadyButton = New-Object Windows.Forms.Button
    $script:ReadyButton.AutoSize = $true
    $script:ReadyButton.Add_Click({ Set-LobbyReady })
    $lobbyAdminActions.Controls.Add($script:ReadyButton)
    $script:PhaseButton = New-Object Windows.Forms.Button
    $script:PhaseButton.AutoSize = $true
    $script:PhaseButton.Add_Click({ Toggle-LobbyPhase })
    $lobbyAdminActions.Controls.Add($script:PhaseButton)
    $script:LockButton = New-Object Windows.Forms.Button
    $script:LockButton.AutoSize = $true
    $script:LockButton.Add_Click({ Toggle-LobbyLock })
    $lobbyAdminActions.Controls.Add($script:LockButton)
    $script:LeaveLobbyButton = New-Object Windows.Forms.Button
    $script:LeaveLobbyButton.AutoSize = $true
    $script:LeaveLobbyButton.Add_Click({ Leave-CurrentLobby })
    $lobbyAdminActions.Controls.Add($script:LeaveLobbyButton)
    $script:TransferHostCombo = New-Object Windows.Forms.ComboBox
    $script:TransferHostCombo.DropDownStyle = [Windows.Forms.ComboBoxStyle]::DropDownList
    $script:TransferHostCombo.Width = 120
    $lobbyAdminActions.Controls.Add($script:TransferHostCombo)
    $script:TransferHostButton = New-Object Windows.Forms.Button
    $script:TransferHostButton.AutoSize = $true
    $script:TransferHostButton.Add_Click({ Transfer-LobbyHost })
    $lobbyAdminActions.Controls.Add($script:TransferHostButton)
    $lobbyPanelLayout.Controls.Add($lobbyAdminActions, 0, 6)
    $script:LobbyChatLabel = New-Object Windows.Forms.Label
    $script:LobbyChatLabel.Dock = [Windows.Forms.DockStyle]::Fill
    $lobbyPanelLayout.Controls.Add($script:LobbyChatLabel, 0, 7)
    $script:LobbyMessageList = New-Object Windows.Forms.ListView
    $script:LobbyMessageList.Dock = [Windows.Forms.DockStyle]::Fill
    $script:LobbyMessageList.View = [Windows.Forms.View]::Details
    $script:LobbyMessageList.FullRowSelect = $true
    [void]$script:LobbyMessageList.Columns.Add('', 65)
    [void]$script:LobbyMessageList.Columns.Add('', 90)
    [void]$script:LobbyMessageList.Columns.Add('', 250)
    $lobbyPanelLayout.Controls.Add($script:LobbyMessageList, 0, 8)
    $lobbyActions = New-Object Windows.Forms.TableLayoutPanel
    $lobbyActions.Dock = [Windows.Forms.DockStyle]::Fill
    $lobbyActions.RowCount = 1
    $lobbyActions.ColumnCount = 2
    [void]$lobbyActions.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 100)))
    [void]$lobbyActions.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Absolute, 100)))
    $script:LobbyMessageTextBox = New-Object Windows.Forms.TextBox
    $script:LobbyMessageTextBox.Dock = [Windows.Forms.DockStyle]::Fill
    $script:LobbyMessageTextBox.MaxLength = 500
    $script:LobbyMessageTextBox.Add_KeyDown({
        param($sender, $eventArgs)
        if ($eventArgs.KeyCode -eq [Windows.Forms.Keys]::Enter) {
            $eventArgs.SuppressKeyPress = $true
            Send-LobbyMessage
        }
    })
    $lobbyActions.Controls.Add($script:LobbyMessageTextBox, 0, 0)
    $script:LobbySendButton = New-Object Windows.Forms.Button
    $script:LobbySendButton.Dock = [Windows.Forms.DockStyle]::Fill
    $script:LobbySendButton.Add_Click({ Send-LobbyMessage })
    $lobbyActions.Controls.Add($script:LobbySendButton, 1, 0)
    $lobbyPanelLayout.Controls.Add($lobbyActions, 0, 9)
    $script:LobbyPanel.Controls.Add($lobbyPanelLayout)
    $script:LobbyPanel.Visible = $false
    $script:OuterLayout.Controls.Add($script:LobbyPanel, 1, 0)
    $script:Form.Controls.Add($script:OuterLayout)

    $script:NotifyIcon = New-Object Windows.Forms.NotifyIcon
    $script:NotifyIcon.Icon = [Drawing.SystemIcons]::Application
    $script:NotifyIcon.Text = "LAN Party Companion — $($script:Config.player)"
    $script:NotifyIcon.Visible = $true
    $trayMenu = New-Object Windows.Forms.ContextMenuStrip
    $script:OpenMenu = $trayMenu.Items.Add('Open')
    $script:OpenMenu.Add_Click({ Show-CompanionWindow })
    $script:ExitMenu = $trayMenu.Items.Add('Exit')
    $script:ExitMenu.Add_Click({ Exit-CompanionOnly })
    $script:ExitAndDisconnectMenu = $trayMenu.Items.Add('Exit and disconnect VPN')
    $script:ExitAndDisconnectMenu.Add_Click({ Exit-CompanionAndVpn })
    $script:QuitContextMenu = New-Object Windows.Forms.ContextMenuStrip
    $script:QuitOnlyButtonMenu = $script:QuitContextMenu.Items.Add('Exit')
    $script:QuitOnlyButtonMenu.Add_Click({ Exit-CompanionOnly })
    $script:QuitAndDisconnectButtonMenu = $script:QuitContextMenu.Items.Add('Exit and disconnect VPN')
    $script:QuitAndDisconnectButtonMenu.Add_Click({ Exit-CompanionAndVpn })
    $script:NotifyIcon.ContextMenuStrip = $trayMenu
    $script:NotifyIcon.Add_DoubleClick({ Show-CompanionWindow })
    $script:Form.Add_FormClosing({
        param($sender, $eventArgs)
        if ($eventArgs.CloseReason -in @(
                [Windows.Forms.CloseReason]::WindowsShutDown,
                [Windows.Forms.CloseReason]::ApplicationExitCall,
                [Windows.Forms.CloseReason]::TaskManagerClosing
            )) {
            $script:ExitRequested = $true
            return
        }
        if (-not $script:ExitRequested) {
            $eventArgs.Cancel = $true
            $script:Form.Hide()
            $script:NotifyIcon.BalloonTipTitle = T 'app_title'
            $script:NotifyIcon.BalloonTipText = T 'hidden_to_tray'
            $script:NotifyIcon.ShowBalloonTip(2500)
        }
    })
    $script:Form.Add_Shown({ if ($StartMinimized) { $script:Form.Hide() } })

    Apply-Language
    $script:Initializing = $false
    $script:PollTimer = New-Object Windows.Forms.Timer
    $script:PollTimer.Interval = 2500
    $script:PollTimer.Add_Tick({
        Update-LatencyProbe
        Refresh-CompanionState
    })
    $script:VpnAutoConnectTimer = New-Object Windows.Forms.Timer
    $script:VpnAutoConnectTimer.Interval = 250
    $script:VpnAutoConnectTimer.Add_Tick({
        $script:VpnAutoConnectTimer.Stop()
        if (Test-CompanionTcpEndpoint) {
            Refresh-CompanionState -Force
            return
        }
        $script:PollTimer.Stop()
        $script:ConnectionLabel.Text = T 'vpn_connecting'
        $script:ConnectionLabel.ForeColor = [Drawing.Color]::DarkOrange
        try { Connect-LanPartyOpenVpn }
        catch {
            $script:NotifyIcon.BalloonTipTitle = T 'app_title'
            $script:NotifyIcon.BalloonTipText = (T 'vpn_connect_failed' @($_.Exception.Message))
            $script:NotifyIcon.ShowBalloonTip(5000)
        }
        finally {
            if (-not $script:ExitRequested) {
                $script:NextRefreshAt = [DateTime]::UtcNow
                Refresh-CompanionState -Force
                $script:PollTimer.Start()
            }
        }
    })
    $script:PollTimer.Start()
    $script:VpnAutoConnectTimer.Start()
    [Windows.Forms.Application]::Run($script:Form)
}
catch {
    $language = if (
        [Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName -eq 'fr'
    ) { 'fr' } else { 'en' }
    if ((Get-Variable -Name Settings -Scope Script -ErrorAction SilentlyContinue) -and
        $script:Settings -and $script:Settings.language) {
        $language = $script:Settings.language
    }
    $message = if ($language -eq 'fr') {
        "LAN Party Companion ne peut pas démarrer :`n$($_.Exception.Message)"
    }
    else { "LAN Party Companion cannot start:`n$($_.Exception.Message)" }
    [Windows.Forms.MessageBox]::Show(
        $message,
        'LAN Party Companion',
        [Windows.Forms.MessageBoxButtons]::OK,
        [Windows.Forms.MessageBoxIcon]::Error
    ) | Out-Null
    exit 1
}
finally {
    if (Get-Variable -Name PollTimer -Scope Script -ErrorAction SilentlyContinue) {
        $script:PollTimer.Stop()
        $script:PollTimer.Dispose()
    }
    if (Get-Variable -Name VpnAutoConnectTimer -Scope Script -ErrorAction SilentlyContinue) {
        $script:VpnAutoConnectTimer.Stop()
        $script:VpnAutoConnectTimer.Dispose()
    }
    if (Get-Variable -Name ToolTip -Scope Script -ErrorAction SilentlyContinue) {
        $script:ToolTip.Dispose()
    }
    if (Get-Variable -Name NotifyIcon -Scope Script -ErrorAction SilentlyContinue) {
        $script:NotifyIcon.Visible = $false
        $script:NotifyIcon.Dispose()
    }
    if ((Get-Variable -Name PingClient -Scope Script -ErrorAction SilentlyContinue) -and
        $script:PingClient) {
        $script:PingClient.Dispose()
    }
    if (Get-Variable -Name InstanceMutex -Scope Script -ErrorAction SilentlyContinue) {
        try { $script:InstanceMutex.ReleaseMutex() } catch { }
        $script:InstanceMutex.Dispose()
    }
}
