#!/usr/bin/env python3

"""Lightweight presence, messaging and game-room service for the VPN LAN."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import stat
import sys
import tempfile
import threading
import time
import unicodedata
from collections import defaultdict, deque
from contextlib import contextmanager
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised by the Windows test runner
    fcntl = None  # type: ignore[assignment]
    import msvcrt


APP_VERSION = "1.0.0"
PLAYER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
TOKEN_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
LOBBY_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,64}$")
ALLOWED_STATUSES = {"online", "ready", "afk", "busy", "in_game"}
LOBBY_PHASES = {"gathering", "in_game"}
MESSAGE_COLORS = {
    "blue",
    "green",
    "orange",
    "purple",
    "pink",
    "teal",
    "gold",
    "gray",
}
BIDI_CONTROL_CHARACTERS = {
    "\u061c",
    "\u200e",
    "\u200f",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
}


@contextmanager
def exclusive_file_lock(handle: Any):
    """Lock the one-byte registry lock file on Debian and Windows test hosts."""
    if fcntl is not None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return

    handle.seek(0, os.SEEK_END)
    if handle.tell() == 0:
        handle.write("\0")
        handle.flush()
    handle.seek(0)
    msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
    try:
        yield
    finally:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


class CompanionError(Exception):
    """Expected request or configuration error."""

    def __init__(self, status: HTTPStatus, message: str, code: str = "request_error"):
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code


def fail(message: str) -> None:
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(1)


def normalize_plain_text(
    value: Any,
    field: str,
    minimum: int,
    maximum: int,
    *,
    allow_whitespace_controls: bool = False,
) -> str:
    if not isinstance(value, str):
        raise CompanionError(
            HTTPStatus.BAD_REQUEST,
            f"{field} must be text",
            f"invalid_{field}",
        )
    normalized = unicodedata.normalize("NFKC", value).strip()
    if not minimum <= len(normalized) <= maximum:
        raise CompanionError(
            HTTPStatus.BAD_REQUEST,
            f"{field} must contain {minimum} to {maximum} characters",
            f"invalid_{field}",
        )
    allowed_controls = "\r\n\t" if allow_whitespace_controls else ""
    if any(
        (
            unicodedata.category(character) in {"Cc", "Cs"}
            and character not in allowed_controls
        )
        or character in BIDI_CONTROL_CHARACTERS
        for character in normalized
    ):
        raise CompanionError(
            HTTPStatus.BAD_REQUEST,
            f"{field} contains control characters",
            f"invalid_{field}",
        )
    return normalized


def read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read valid JSON from {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return data


def write_json_atomic(path: Path, data: dict[str, Any], mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing_stat = None
    try:
        existing_stat = path.stat()
    except FileNotFoundError:
        pass

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

        if existing_stat is not None:
            os.chmod(temporary, stat.S_IMODE(existing_stat.st_mode))
            if hasattr(os, "chown"):
                os.chown(temporary, existing_stat.st_uid, existing_stat.st_gid)
        elif mode is not None:
            os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_config(path: Path) -> dict[str, Any]:
    config = read_json(path)
    required = {
        "bind_host",
        "port",
        "allowed_subnet",
        "players_file",
        "presence_ttl_seconds",
        "message_retention",
        "max_request_bytes",
    }
    missing = sorted(required - config.keys())
    if missing:
        raise ValueError(f"missing companion configuration fields: {', '.join(missing)}")

    bind_address = ipaddress.ip_address(config["bind_host"])
    allowed_network = ipaddress.ip_network(config["allowed_subnet"], strict=True)
    if bind_address.version != 4 or allowed_network.version != 4:
        raise ValueError("the companion MVP supports IPv4 only")
    if bind_address not in allowed_network:
        raise ValueError("bind_host must belong to allowed_subnet")

    port = config["port"]
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    for field, minimum, maximum in (
        ("presence_ttl_seconds", 5, 120),
        ("message_retention", 20, 2000),
        ("max_request_bytes", 1024, 65536),
    ):
        value = config[field]
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not minimum <= value <= maximum
        ):
            raise ValueError(f"{field} must be between {minimum} and {maximum}")

    lobby_grace = config.get("lobby_disconnect_grace_seconds", 30)
    if (
        not isinstance(lobby_grace, int)
        or isinstance(lobby_grace, bool)
        or not config["presence_ttl_seconds"] <= lobby_grace <= 300
    ):
        raise ValueError(
            "lobby_disconnect_grace_seconds must be between presence TTL and 300"
        )
    config["lobby_disconnect_grace_seconds"] = lobby_grace

    config["players_file"] = str(Path(config["players_file"]).resolve())
    config["allowed_subnet"] = str(allowed_network)
    config["bind_host"] = str(bind_address)
    return config


def empty_players_document() -> dict[str, Any]:
    return {"version": 1, "players": {}}


def validate_players_document(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if document.get("version") != 1 or not isinstance(document.get("players"), dict):
        raise ValueError("players file must contain version 1 and a players object")
    players: dict[str, dict[str, Any]] = {}
    seen_hashes: set[str] = set()
    for player, entry in document["players"].items():
        if not isinstance(player, str) or not PLAYER_PATTERN.fullmatch(player):
            raise ValueError(f"invalid player name in players file: {player!r}")
        if not isinstance(entry, dict):
            raise ValueError(f"invalid player entry: {player}")
        token_hash = entry.get("token_sha256")
        if not isinstance(token_hash, str) or not TOKEN_HASH_PATTERN.fullmatch(token_hash):
            raise ValueError(f"invalid token hash for player: {player}")
        if token_hash in seen_hashes:
            raise ValueError("duplicate token hash in players file")
        seen_hashes.add(token_hash)
        players[player] = dict(entry)
    return players


def update_player_registration(
    players_path: Path,
    player: str,
    token: str | None,
) -> bool:
    if not PLAYER_PATTERN.fullmatch(player):
        raise ValueError("player name must use 1 to 32 letters, digits, _ or -")
    lock_path = players_path.with_name(f".{players_path.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock_handle:
        with exclusive_file_lock(lock_handle):
            if players_path.exists():
                document = read_json(players_path)
            else:
                document = empty_players_document()
            players = validate_players_document(document)

            if token is None:
                if player not in players:
                    return False
                del document["players"][player]
            else:
                if not TOKEN_PATTERN.fullmatch(token):
                    raise ValueError("generated companion token has an invalid format")
                if player in players:
                    raise ValueError(
                        f"companion identity already exists for player: {player}"
                    )
                token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
                if any(
                    hmac.compare_digest(token_hash, entry["token_sha256"])
                    for entry in players.values()
                ):
                    raise ValueError(
                        "generated companion token collides with an existing token"
                    )
                document["players"][player] = {
                    "token_sha256": token_hash,
                    "created_at": int(time.time()),
                }

            write_json_atomic(players_path, document, mode=0o640)
            return True


def ensure_player_registration(players_path: Path, player: str, token: str) -> str:
    """Register a token idempotently without rotating an existing identity.

    Returns ``created``, ``existing-same`` or ``existing-different``. The last
    result lets VPN credential renewal preserve the player's Companion identity.
    """
    if not PLAYER_PATTERN.fullmatch(player):
        raise ValueError("player name must use 1 to 32 letters, digits, _ or -")
    if not TOKEN_PATTERN.fullmatch(token):
        raise ValueError("generated companion token has an invalid format")
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    lock_path = players_path.with_name(f".{players_path.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock_handle:
        with exclusive_file_lock(lock_handle):
            document = read_json(players_path) if players_path.exists() else empty_players_document()
            players = validate_players_document(document)
            existing = players.get(player)
            if existing is not None:
                if hmac.compare_digest(existing["token_sha256"], token_hash):
                    return "existing-same"
                return "existing-different"
            if any(hmac.compare_digest(token_hash, entry["token_sha256"])
                   for entry in players.values()):
                raise ValueError("generated companion token collides with an existing token")
            document["players"][player] = {
                "token_sha256": token_hash,
                "created_at": int(time.time()),
            }
            write_json_atomic(players_path, document, mode=0o640)
            return "created"


def issue_player(config_path: Path, player: str, output: Path) -> None:
    config = load_config(config_path)
    if output.exists():
        raise ValueError(f"refusing to overwrite companion client configuration: {output}")
    token = secrets.token_urlsafe(32)
    players_path = Path(config["players_file"])
    update_player_registration(players_path, player, token)
    try:
        client_config = {
            "version": 1,
            "player": player,
            "server_url": f"http://{config['bind_host']}:{config['port']}",
            "token": token,
        }
        write_json_atomic(output, client_config, mode=0o600)
    except Exception:
        update_player_registration(players_path, player, None)
        raise


class CompanionState:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.players_path = Path(config["players_file"])
        self.allowed_network = ipaddress.ip_network(config["allowed_subnet"])
        self.presence_ttl = config["presence_ttl_seconds"]
        self.lobby_disconnect_grace = config["lobby_disconnect_grace_seconds"]
        self.message_retention = config["message_retention"]
        self.lock = threading.RLock()
        self.instance_id = secrets.token_urlsafe(12)
        self.players_signature: tuple[int, int, int] | None = None
        self.players_by_name: dict[str, dict[str, Any]] = {}
        self.players_by_hash: dict[str, str] = {}
        self.presence: dict[str, dict[str, Any]] = {}
        self.messages: deque[dict[str, Any]] = deque(maxlen=self.message_retention)
        self.lobby_messages: deque[dict[str, Any]] = deque(
            maxlen=self.message_retention
        )
        self.lobbies: dict[str, dict[str, Any]] = {}
        self.player_lobby: dict[str, str] = {}
        self.message_sequence = 0
        self.message_rates: dict[str, deque[float]] = defaultdict(deque)
        self.status_rates: dict[str, deque[float]] = defaultdict(deque)
        self.action_rates: dict[str, deque[float]] = defaultdict(deque)
        self.poll_rates: dict[str, deque[float]] = defaultdict(deque)
        self.failed_auth_rates: dict[str, deque[float]] = defaultdict(deque)
        self._reload_players(force=True)

    def _reload_players(self, force: bool = False) -> None:
        try:
            players_stat = self.players_path.stat()
        except FileNotFoundError as exc:
            raise ValueError(f"players file is missing: {self.players_path}") from exc
        current_signature = (
            players_stat.st_ino,
            players_stat.st_mtime_ns,
            players_stat.st_size,
        )
        if not force and current_signature == self.players_signature:
            return
        document = read_json(self.players_path)
        players = validate_players_document(document)
        self.players_by_name = players
        self.players_by_hash = {
            entry["token_sha256"]: player for player, entry in players.items()
        }
        self.players_signature = current_signature
        active_names = set(players)
        self.presence = {
            name: entry for name, entry in self.presence.items() if name in active_names
        }
        for lobby_id in list(self.lobbies):
            lobby = self.lobbies[lobby_id]
            if lobby["host"] not in active_names:
                self._close_lobby_locked(lobby_id)
                continue
            for member in list(lobby["members"]):
                if member not in active_names:
                    self._remove_member_locked(lobby_id, member, announce=True)
        self.message_rates = defaultdict(
            deque,
            {
                name: rate
                for name, rate in self.message_rates.items()
                if name in active_names
            },
        )
        self.status_rates = defaultdict(
            deque,
            {
                name: rate
                for name, rate in self.status_rates.items()
                if name in active_names
            },
        )
        self.action_rates = defaultdict(
            deque,
            {
                name: rate
                for name, rate in self.action_rates.items()
                if name in active_names
            },
        )
        self.poll_rates = defaultdict(
            deque,
            {
                name: rate
                for name, rate in self.poll_rates.items()
                if name in active_names
            },
        )

    def authenticate(self, token: str) -> str | None:
        if not TOKEN_PATTERN.fullmatch(token):
            return None
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        with self.lock:
            self._reload_players()
            return self.players_by_hash.get(token_hash)

    def source_allowed(self, address: str) -> bool:
        try:
            source = ipaddress.ip_address(address)
        except ValueError:
            return False
        return source in self.allowed_network

    def enforce_auth_source(self, address: str) -> None:
        """Temporarily reject a VPN source after repeated failed credentials."""
        now = time.time()
        with self.lock:
            recent = self.failed_auth_rates.get(address)
            if not recent:
                return
            while recent and now - recent[0] > 60:
                recent.popleft()
            if not recent:
                self.failed_auth_rates.pop(address, None)
                return
            if len(recent) >= 10:
                raise CompanionError(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    "too many failed authentication attempts",
                    "auth_rate_limited",
                )

    def record_auth_failure(self, address: str) -> None:
        now = time.time()
        with self.lock:
            recent = self.failed_auth_rates[address]
            while recent and now - recent[0] > 60:
                recent.popleft()
            recent.append(now)
            if len(recent) in {1, 5, 10}:
                logging.info(
                    "companion authentication failure source=%s attempts=%d",
                    address,
                    len(recent),
                )

            # The service normally sees a small /24. Keep this map bounded even
            # if a larger routed subnet is configured later.
            if len(self.failed_auth_rates) > 1024:
                stale = [
                    source
                    for source, attempts in self.failed_auth_rates.items()
                    if not attempts or now - attempts[-1] > 60
                ]
                for source in stale:
                    self.failed_auth_rates.pop(source, None)
                while len(self.failed_auth_rates) > 1024:
                    oldest = min(
                        self.failed_auth_rates,
                        key=lambda source: self.failed_auth_rates[source][-1],
                    )
                    self.failed_auth_rates.pop(oldest, None)

    def touch(self, player: str, address: str) -> None:
        now = time.time()
        with self.lock:
            previous = self.presence.get(player)
            previous_address = previous.get("vpn_ip") if previous else None
            previous_last_seen = previous.get("last_seen", 0) if previous else 0
            if (
                previous
                and now - previous_last_seen > self.lobby_disconnect_grace
                and player in self.player_lobby
            ):
                lobby_id = self.player_lobby[player]
                lobby = self.lobbies.get(lobby_id)
                if lobby and lobby["host"] == player:
                    self._close_lobby_locked(lobby_id)
                else:
                    self._remove_member_locked(lobby_id, player, announce=True)
            new_session = (
                previous is None
                or now - previous_last_seen > self.presence_ttl
            )
            if new_session:
                previous = {
                    "first_seen": now,
                    "status": "online",
                    "manual_status": "online",
                }
            elif "manual_status" not in previous:
                legacy_status = previous.get("status", "online")
                previous["manual_status"] = (
                    "online" if legacy_status in {"ready", "in_game"} else legacy_status
                )
            previous["vpn_ip"] = address
            previous["last_seen"] = now
            self.presence[player] = previous
            if new_session or previous_address != address:
                logging.info("companion presence player=%s source=%s", player, address)

    def set_status(self, player: str, status_value: str) -> None:
        if status_value not in ALLOWED_STATUSES:
            raise CompanionError(
                HTTPStatus.BAD_REQUEST,
                "invalid player status",
                "invalid_status",
            )
        with self.lock:
            self._enforce_rate_locked(
                self.status_rates,
                player,
                limit=20,
                window=10,
                code="status_rate_limited",
            )
            if player not in self.presence:
                raise CompanionError(
                    HTTPStatus.CONFLICT,
                    "player is not present",
                    "player_offline",
                )
            self.presence[player]["status"] = status_value
            self.presence[player]["manual_status"] = status_value

    def _effective_status_locked(self, player: str, online: bool) -> str:
        if not online:
            return "offline"
        lobby_id = self.player_lobby.get(player)
        lobby = self.lobbies.get(lobby_id) if lobby_id else None
        if lobby and lobby.get("phase") == "in_game":
            return "in_game"
        presence = self.presence[player]
        return str(presence.get("manual_status", presence.get("status", "online")))

    def _online_names(self, now: float) -> set[str]:
        return {
            player
            for player, entry in self.presence.items()
            if now - entry["last_seen"] <= self.presence_ttl
        }

    def _append_lobby_event_locked(
        self,
        lobby_id: str,
        kind: str,
        actor: str,
    ) -> dict[str, Any]:
        self.message_sequence += 1
        message = {
            "id": self.message_sequence,
            "lobby_id": lobby_id,
            "kind": kind,
            "actor": actor,
            "sender": None,
            "text": None,
            "color": "gray",
            "created_at": int(time.time()),
        }
        self.lobby_messages.append(message)
        return message

    def _close_lobby_locked(self, lobby_id: str) -> bool:
        lobby = self.lobbies.pop(lobby_id, None)
        if lobby is None:
            return False
        for member in list(lobby["members"]):
            self.player_lobby.pop(member, None)
        return True

    def _remove_member_locked(
        self,
        lobby_id: str,
        player: str,
        *,
        announce: bool,
    ) -> bool:
        lobby = self.lobbies.get(lobby_id)
        if lobby is None or player not in lobby["members"]:
            return False
        lobby["members"].pop(player, None)
        self.player_lobby.pop(player, None)
        lobby["updated_at"] = int(time.time())
        lobby["revision"] += 1
        if announce:
            self._append_lobby_event_locked(lobby_id, "member_left", player)
        return True

    def _cleanup(self, now: float) -> set[str]:
        online_names = self._online_names(now)
        for lobby_id in list(self.lobbies):
            lobby = self.lobbies.get(lobby_id)
            if lobby is None:
                continue
            host_presence = self.presence.get(lobby["host"])
            if (
                host_presence is None
                or now - host_presence["last_seen"] > self.lobby_disconnect_grace
            ):
                self._close_lobby_locked(lobby_id)
                continue
            for member in list(lobby["members"]):
                if member == lobby["host"]:
                    continue
                member_presence = self.presence.get(member)
                if (
                    member_presence is None
                    or now - member_presence["last_seen"]
                    > self.lobby_disconnect_grace
                ):
                    self._remove_member_locked(
                        lobby_id,
                        member,
                        announce=True,
                    )
        return online_names

    def _visible_messages_locked(self, player: str, since: int) -> list[dict[str, Any]]:
        return [
            message
            for message in self.messages
            if message["id"] > since
            and (
                message["target"] is None
                or message["sender"] == player
                or message["target"] == player
            )
        ][-100:]

    def _serialize_player_locked(
        self,
        name: str,
        online_names: set[str],
        now: float,
    ) -> dict[str, Any]:
        entry = self.presence.get(name)
        online = name in online_names and entry is not None
        availability_status = (
            str(entry.get("manual_status", entry.get("status", "online")))
            if online
            else "offline"
        )
        return {
            "pseudo": name,
            "online": online,
            "vpn_ip": entry["vpn_ip"] if online else None,
            "status": self._effective_status_locked(name, online),
            "availability_status": availability_status,
            "connected_since_at": int(entry["first_seen"]) if online else None,
            "connected_for_seconds": (
                max(0, int(now - entry["first_seen"])) if online else 0
            ),
            "last_seen_at": int(entry["last_seen"]) if entry else None,
            "lobby_id": self.player_lobby.get(name) if online else None,
        }

    def _serialize_lobby_locked(
        self,
        lobby: dict[str, Any],
        online_names: set[str],
        now: float,
    ) -> dict[str, Any]:
        members = []
        for member in sorted(lobby["members"], key=str.casefold):
            presence = self.presence.get(member)
            online = member in online_names and presence is not None
            membership = lobby["members"][member]
            if not isinstance(membership, dict):
                membership = {
                    "joined_at": int(membership),
                    "ready": False,
                    "ready_updated_at": None,
                }
            members.append(
                {
                    "pseudo": member,
                    "online": online,
                    "status": self._effective_status_locked(member, online),
                    "ready": bool(membership.get("ready", False)),
                    "joined_at": int(membership.get("joined_at", lobby["created_at"])),
                    "role": "host" if member == lobby["host"] else "member",
                }
            )
        host_presence = self.presence.get(lobby["host"])
        return {
            "id": lobby["id"],
            "host": lobby["host"],
            "host_ip": (
                host_presence["vpn_ip"]
                if lobby["host"] in online_names and host_presence
                else None
            ),
            "game": lobby["game"],
            "lobby_name": lobby["lobby_name"],
            "join_instructions": lobby.get("join_instructions", ""),
            "port": lobby["port"],
            "capacity": lobby["capacity"],
            "phase": lobby.get("phase", "gathering"),
            "locked": bool(lobby.get("locked", False)),
            "revision": int(lobby.get("revision", 1)),
            "member_count": len(lobby["members"]),
            "ready_count": sum(
                1 for member in members if member["online"] and member["ready"]
            ),
            "all_ready": bool(members)
            and all(member["online"] and member["ready"] for member in members),
            "members": members,
            "created_at": lobby["created_at"],
            "updated_at": lobby["updated_at"],
        }

    def snapshot_v2(self, player: str, since: int) -> dict[str, Any]:
        now = time.time()
        with self.lock:
            self._reload_players()
            online_names = self._cleanup(now)
            players = [
                self._serialize_player_locked(name, online_names, now)
                for name in sorted(self.players_by_name, key=str.casefold)
            ]
            lobbies = [
                self._serialize_lobby_locked(lobby, online_names, now)
                for lobby in sorted(
                    self.lobbies.values(),
                    key=lambda item: item["updated_at"],
                    reverse=True,
                )
            ]
            lobby_id = self.player_lobby.get(player)
            current_lobby = self.lobbies.get(lobby_id) if lobby_id else None
            visible_lobby_messages = [
                message
                for message in self.lobby_messages
                if message["id"] > since and message["lobby_id"] == lobby_id
            ][-100:]
            return {
                "api_version": 2,
                "server_version": APP_VERSION,
                "minimum_client_version": "0.2.0",
                "features": [
                    "presence_duration",
                    "manual_availability",
                    "join_instructions",
                    "ready_check",
                    "lobby_phases",
                    "lobby_lock",
                    "host_transfer",
                    "lobby_revisions",
                ],
                "instance_id": self.instance_id,
                "server_time": int(now),
                "self": player,
                "message_sequence": self.message_sequence,
                "players": players,
                "messages": self._visible_messages_locked(player, since),
                "lobbies": lobbies,
                "current_lobby": (
                    self._serialize_lobby_locked(current_lobby, online_names, now)
                    if current_lobby
                    else None
                ),
                "lobby_messages": visible_lobby_messages,
            }

    def snapshot_v1(self, player: str, since: int) -> dict[str, Any]:
        now = time.time()
        with self.lock:
            self._reload_players()
            online_names = self._cleanup(now)
            players = []
            for name in sorted(online_names, key=str.casefold):
                entry = self.presence[name]
                players.append(
                    {
                        "pseudo": name,
                        "vpn_ip": entry["vpn_ip"],
                        "status": self._effective_status_locked(name, True),
                        "connected_for_seconds": max(
                            0, int(now - entry["first_seen"])
                        ),
                    }
                )
            rooms = []
            for lobby in self.lobbies.values():
                host_presence = self.presence.get(lobby["host"])
                if lobby["port"] is None or lobby["host"] not in online_names:
                    continue
                rooms.append(
                    {
                        "host": lobby["host"],
                        "host_ip": host_presence["vpn_ip"],
                        "game": lobby["game"],
                        "port": lobby["port"],
                        "max_players": lobby["capacity"],
                        "notes": lobby["lobby_name"],
                        "created_at": lobby["created_at"],
                        "updated_at": lobby["updated_at"],
                    }
                )
            return {
                "version": 1,
                "server_version": APP_VERSION,
                "server_time": int(now),
                "self": player,
                "message_sequence": self.message_sequence,
                "players": players,
                "messages": self._visible_messages_locked(player, since),
                "rooms": sorted(
                    rooms, key=lambda room: room["updated_at"], reverse=True
                ),
            }

    def _enforce_rate_locked(
        self,
        rates: dict[str, deque[float]],
        player: str,
        *,
        limit: int,
        window: float,
        code: str,
    ) -> None:
        now = time.time()
        recent = rates[player]
        while recent and now - recent[0] > window:
            recent.popleft()
        if len(recent) >= limit:
            raise CompanionError(
                HTTPStatus.TOO_MANY_REQUESTS,
                "rate limit exceeded",
                code,
            )
        recent.append(now)

    def enforce_poll_rate(self, player: str) -> None:
        with self.lock:
            self._enforce_rate_locked(
                self.poll_rates,
                player,
                limit=40,
                window=10,
                code="state_rate_limited",
            )

    def _validate_color(self, color: Any) -> str:
        if color is None:
            return "blue"
        if not isinstance(color, str) or color not in MESSAGE_COLORS:
            raise CompanionError(
                HTTPStatus.BAD_REQUEST,
                "invalid message color",
                "invalid_message_color",
            )
        return color

    def send_message(
        self,
        sender: str,
        target: str | None,
        text: str,
        color: Any = None,
    ) -> dict[str, Any]:
        normalized = normalize_plain_text(
            text,
            "message",
            1,
            500,
            allow_whitespace_controls=True,
        )
        validated_color = self._validate_color(color)
        if target is not None:
            if not isinstance(target, str) or not PLAYER_PATTERN.fullmatch(target):
                raise CompanionError(
                    HTTPStatus.BAD_REQUEST,
                    "invalid message target",
                    "invalid_message_target",
                )
            with self.lock:
                self._reload_players()
                if target not in self.players_by_name:
                    raise CompanionError(
                        HTTPStatus.NOT_FOUND,
                        "message target does not exist",
                        "message_target_not_found",
                    )

        now = time.time()
        with self.lock:
            self._enforce_rate_locked(
                self.message_rates,
                sender,
                limit=5,
                window=10,
                code="message_rate_limited",
            )
            self.message_sequence += 1
            message = {
                "id": self.message_sequence,
                "sender": sender,
                "target": target,
                "text": normalized,
                "color": validated_color,
                "created_at": int(now),
            }
            self.messages.append(message)
            return message

    @staticmethod
    def _new_membership(now: int) -> dict[str, Any]:
        return {
            "joined_at": now,
            "ready": False,
            "ready_updated_at": None,
        }

    @staticmethod
    def _expected_revision(payload: dict[str, Any]) -> int | None:
        expected = payload.get("expected_revision")
        if expected is None:
            return None
        if not isinstance(expected, int) or isinstance(expected, bool) or expected < 1:
            raise CompanionError(
                HTTPStatus.BAD_REQUEST,
                "expected_revision must be a positive integer",
                "invalid_lobby_revision",
            )
        return expected

    @staticmethod
    def _check_revision(lobby: dict[str, Any], expected: int | None) -> None:
        if expected is not None and expected != lobby.get("revision", 1):
            raise CompanionError(
                HTTPStatus.CONFLICT,
                "lobby was modified by another request",
                "lobby_revision_conflict",
            )

    @staticmethod
    def _reset_ready_locked(lobby: dict[str, Any]) -> None:
        for member, membership in list(lobby["members"].items()):
            if not isinstance(membership, dict):
                membership = CompanionState._new_membership(int(membership))
                lobby["members"][member] = membership
            membership["ready"] = False
            membership["ready_updated_at"] = None

    def upsert_lobby(
        self,
        player: str,
        address: str,
        payload: dict[str, Any],
        *,
        legacy: bool = False,
    ) -> dict[str, Any]:
        game = normalize_plain_text(payload.get("game"), "game", 1, 80)
        raw_lobby_name = (
            payload.get("notes") if legacy else payload.get("lobby_name")
        )
        if legacy and (not isinstance(raw_lobby_name, str) or not raw_lobby_name.strip()):
            raw_lobby_name = game
        lobby_name = normalize_plain_text(
            raw_lobby_name,
            "lobby_name",
            1,
            80,
        )
        raw_instructions = "" if legacy else payload.get("join_instructions", "")
        if raw_instructions in (None, ""):
            join_instructions = ""
        else:
            join_instructions = normalize_plain_text(
                raw_instructions,
                "join_instructions",
                1,
                600,
                allow_whitespace_controls=True,
            )
        port = payload.get("port")
        if port in (None, ""):
            port = None
        elif not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise CompanionError(
                HTTPStatus.BAD_REQUEST,
                "lobby port must be between 1 and 65535 or omitted",
                "invalid_lobby_port",
            )
        capacity = (
            payload.get("max_players", 8) if legacy else payload.get("capacity")
        )
        if (
            not isinstance(capacity, int)
            or isinstance(capacity, bool)
            or not 2 <= capacity <= 128
        ):
            raise CompanionError(
                HTTPStatus.BAD_REQUEST,
                "lobby capacity must be between 2 and 128",
                "invalid_lobby_capacity",
            )

        now = int(time.time())
        expected_revision = self._expected_revision(payload)
        with self.lock:
            self._enforce_rate_locked(
                self.action_rates,
                player,
                limit=20,
                window=10,
                code="lobby_action_rate_limited",
            )
            online_names = self._cleanup(time.time())
            current_id = self.player_lobby.get(player)
            current = self.lobbies.get(current_id) if current_id else None
            if current and current["host"] != player:
                raise CompanionError(
                    HTTPStatus.CONFLICT,
                    "leave the current lobby before hosting another",
                    "already_in_lobby",
                )
            if current and capacity < len(current["members"]):
                raise CompanionError(
                    HTTPStatus.CONFLICT,
                    "capacity cannot be lower than current occupancy",
                    "capacity_below_occupancy",
                )
            if current:
                self._check_revision(current, expected_revision)
                critical_change = any(
                    (
                        current.get("game") != game,
                        current.get("port") != port,
                        current.get("join_instructions", "") != join_instructions,
                        current.get("capacity") != capacity,
                    )
                )
                current.update(
                    {
                        "game": game,
                        "lobby_name": lobby_name,
                        "join_instructions": join_instructions,
                        "port": port,
                        "capacity": capacity,
                        "updated_at": now,
                        "revision": current.get("revision", 1) + 1,
                    }
                )
                if critical_change:
                    self._reset_ready_locked(current)
                    current["phase"] = "gathering"
                return self._serialize_lobby_locked(current, online_names, time.time())

            lobby_id = secrets.token_urlsafe(16)
            while lobby_id in self.lobbies:
                lobby_id = secrets.token_urlsafe(16)
            lobby = {
                "id": lobby_id,
                "host": player,
                "game": game,
                "lobby_name": lobby_name,
                "join_instructions": join_instructions,
                "port": port,
                "capacity": capacity,
                "members": {player: self._new_membership(now)},
                "phase": "gathering",
                "locked": False,
                "revision": 1,
                "created_at": now,
                "updated_at": now,
            }
            self.lobbies[lobby_id] = lobby
            self.player_lobby[player] = lobby_id
            if player in self.presence:
                self.presence[player]["vpn_ip"] = address
            return self._serialize_lobby_locked(lobby, online_names, time.time())

    def join_lobby(self, player: str, lobby_id: Any) -> dict[str, Any]:
        if not isinstance(lobby_id, str) or not LOBBY_ID_PATTERN.fullmatch(lobby_id):
            raise CompanionError(
                HTTPStatus.BAD_REQUEST,
                "invalid lobby identifier",
                "invalid_lobby_id",
            )
        with self.lock:
            self._enforce_rate_locked(
                self.action_rates,
                player,
                limit=20,
                window=10,
                code="lobby_action_rate_limited",
            )
            now = time.time()
            online_names = self._cleanup(now)
            current_id = self.player_lobby.get(player)
            if current_id == lobby_id and lobby_id in self.lobbies:
                return self._serialize_lobby_locked(
                    self.lobbies[lobby_id], online_names, now
                )
            if current_id is not None:
                raise CompanionError(
                    HTTPStatus.CONFLICT,
                    "leave the current lobby before joining another",
                    "already_in_lobby",
                )
            lobby = self.lobbies.get(lobby_id)
            if lobby is None:
                raise CompanionError(
                    HTTPStatus.NOT_FOUND,
                    "lobby does not exist",
                    "lobby_not_found",
                )
            if len(lobby["members"]) >= lobby["capacity"]:
                raise CompanionError(
                    HTTPStatus.CONFLICT,
                    "lobby is full",
                    "lobby_full",
                )
            if lobby.get("locked", False):
                raise CompanionError(
                    HTTPStatus.CONFLICT,
                    "lobby is locked",
                    "lobby_locked",
                )
            lobby["members"][player] = self._new_membership(int(now))
            lobby["updated_at"] = int(now)
            lobby["revision"] = lobby.get("revision", 1) + 1
            self.player_lobby[player] = lobby_id
            self._append_lobby_event_locked(lobby_id, "member_joined", player)
            return self._serialize_lobby_locked(lobby, online_names, now)

    def set_lobby_ready(self, player: str, ready: Any) -> dict[str, Any]:
        if not isinstance(ready, bool):
            raise CompanionError(
                HTTPStatus.BAD_REQUEST,
                "ready must be a boolean",
                "invalid_lobby_ready",
            )
        with self.lock:
            self._enforce_rate_locked(
                self.action_rates,
                player,
                limit=20,
                window=10,
                code="lobby_action_rate_limited",
            )
            lobby_id = self.player_lobby.get(player)
            lobby = self.lobbies.get(lobby_id) if lobby_id else None
            if lobby is None or player not in lobby["members"]:
                raise CompanionError(
                    HTTPStatus.FORBIDDEN,
                    "join a lobby before changing ready state",
                    "not_in_lobby",
                )
            if lobby.get("phase", "gathering") != "gathering":
                raise CompanionError(
                    HTTPStatus.CONFLICT,
                    "ready state is available only while gathering",
                    "lobby_not_gathering",
                )
            membership = lobby["members"][player]
            if not isinstance(membership, dict):
                membership = self._new_membership(int(membership))
                lobby["members"][player] = membership
            membership["ready"] = ready
            membership["ready_updated_at"] = int(time.time())
            lobby["updated_at"] = int(time.time())
            lobby["revision"] = lobby.get("revision", 1) + 1
            return self._serialize_lobby_locked(
                lobby, self._online_names(time.time()), time.time()
            )

    def set_lobby_phase(
        self,
        player: str,
        phase: Any,
        expected_revision: Any = None,
    ) -> dict[str, Any]:
        if not isinstance(phase, str) or phase not in LOBBY_PHASES:
            raise CompanionError(
                HTTPStatus.BAD_REQUEST,
                "invalid lobby phase",
                "invalid_lobby_phase",
            )
        expected = self._expected_revision({"expected_revision": expected_revision})
        with self.lock:
            self._enforce_rate_locked(
                self.action_rates,
                player,
                limit=20,
                window=10,
                code="lobby_action_rate_limited",
            )
            lobby_id = self.player_lobby.get(player)
            lobby = self.lobbies.get(lobby_id) if lobby_id else None
            if lobby is None or lobby["host"] != player:
                raise CompanionError(
                    HTTPStatus.FORBIDDEN,
                    "only the lobby host may change its phase",
                    "not_lobby_host",
                )
            self._check_revision(lobby, expected)
            lobby["phase"] = phase
            lobby["updated_at"] = int(time.time())
            lobby["revision"] = lobby.get("revision", 1) + 1
            if phase == "gathering":
                self._reset_ready_locked(lobby)
            self._append_lobby_event_locked(
                lobby["id"],
                "game_started" if phase == "in_game" else "gathering_resumed",
                player,
            )
            return self._serialize_lobby_locked(
                lobby, self._online_names(time.time()), time.time()
            )

    def set_lobby_locked(
        self,
        player: str,
        locked: Any,
        expected_revision: Any = None,
    ) -> dict[str, Any]:
        if not isinstance(locked, bool):
            raise CompanionError(
                HTTPStatus.BAD_REQUEST,
                "locked must be a boolean",
                "invalid_lobby_locked",
            )
        expected = self._expected_revision({"expected_revision": expected_revision})
        with self.lock:
            self._enforce_rate_locked(
                self.action_rates,
                player,
                limit=20,
                window=10,
                code="lobby_action_rate_limited",
            )
            lobby_id = self.player_lobby.get(player)
            lobby = self.lobbies.get(lobby_id) if lobby_id else None
            if lobby is None or lobby["host"] != player:
                raise CompanionError(
                    HTTPStatus.FORBIDDEN,
                    "only the lobby host may lock it",
                    "not_lobby_host",
                )
            self._check_revision(lobby, expected)
            lobby["locked"] = locked
            lobby["updated_at"] = int(time.time())
            lobby["revision"] = lobby.get("revision", 1) + 1
            self._append_lobby_event_locked(
                lobby["id"],
                "lobby_locked" if locked else "lobby_unlocked",
                player,
            )
            return self._serialize_lobby_locked(
                lobby, self._online_names(time.time()), time.time()
            )

    def transfer_lobby(
        self,
        player: str,
        target: Any,
        expected_revision: Any = None,
    ) -> dict[str, Any]:
        if not isinstance(target, str) or not PLAYER_PATTERN.fullmatch(target):
            raise CompanionError(
                HTTPStatus.BAD_REQUEST,
                "invalid transfer target",
                "invalid_transfer_target",
            )
        expected = self._expected_revision({"expected_revision": expected_revision})
        with self.lock:
            self._enforce_rate_locked(
                self.action_rates,
                player,
                limit=20,
                window=10,
                code="lobby_action_rate_limited",
            )
            lobby_id = self.player_lobby.get(player)
            lobby = self.lobbies.get(lobby_id) if lobby_id else None
            if lobby is None or lobby["host"] != player:
                raise CompanionError(
                    HTTPStatus.FORBIDDEN,
                    "only the lobby host may transfer it",
                    "not_lobby_host",
                )
            self._check_revision(lobby, expected)
            if target == player or target not in lobby["members"]:
                raise CompanionError(
                    HTTPStatus.CONFLICT,
                    "new host must be another lobby member",
                    "invalid_transfer_target",
                )
            if target not in self._online_names(time.time()):
                raise CompanionError(
                    HTTPStatus.CONFLICT,
                    "new host must be online",
                    "transfer_target_offline",
                )
            lobby["host"] = target
            lobby["updated_at"] = int(time.time())
            lobby["revision"] = lobby.get("revision", 1) + 1
            self._append_lobby_event_locked(lobby["id"], "host_transferred", target)
            return self._serialize_lobby_locked(
                lobby, self._online_names(time.time()), time.time()
            )

    def leave_lobby(self, player: str) -> dict[str, Any]:
        with self.lock:
            self._enforce_rate_locked(
                self.action_rates,
                player,
                limit=20,
                window=10,
                code="lobby_action_rate_limited",
            )
            lobby_id = self.player_lobby.get(player)
            if lobby_id is None:
                return {"left": False, "closed": False}
            lobby = self.lobbies.get(lobby_id)
            if lobby is None:
                self.player_lobby.pop(player, None)
                return {"left": False, "closed": False}
            if lobby["host"] == player:
                self._close_lobby_locked(lobby_id)
                return {"left": True, "closed": True}
            self._remove_member_locked(lobby_id, player, announce=True)
            return {"left": True, "closed": False}

    def send_lobby_message(
        self,
        sender: str,
        text: Any,
        color: Any = None,
    ) -> dict[str, Any]:
        normalized = normalize_plain_text(
            text,
            "message",
            1,
            500,
            allow_whitespace_controls=True,
        )
        validated_color = self._validate_color(color)
        with self.lock:
            lobby_id = self.player_lobby.get(sender)
            lobby = self.lobbies.get(lobby_id) if lobby_id else None
            if lobby is None or sender not in lobby["members"]:
                raise CompanionError(
                    HTTPStatus.FORBIDDEN,
                    "join a lobby before using its chat",
                    "not_in_lobby",
                )
            self._enforce_rate_locked(
                self.message_rates,
                sender,
                limit=5,
                window=10,
                code="message_rate_limited",
            )
            self.message_sequence += 1
            message = {
                "id": self.message_sequence,
                "lobby_id": lobby_id,
                "kind": "message",
                "actor": None,
                "sender": sender,
                "text": normalized,
                "color": validated_color,
                "created_at": int(time.time()),
            }
            self.lobby_messages.append(message)
            return message

    def upsert_room(
        self,
        player: str,
        address: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        lobby = self.upsert_lobby(player, address, payload, legacy=True)
        return {
            "host": lobby["host"],
            "host_ip": lobby["host_ip"],
            "game": lobby["game"],
            "port": lobby["port"],
            "max_players": lobby["capacity"],
            "notes": lobby["lobby_name"],
            "created_at": lobby["created_at"],
            "updated_at": lobby["updated_at"],
        }

    def close_room(self, player: str) -> bool:
        with self.lock:
            lobby_id = self.player_lobby.get(player)
            lobby = self.lobbies.get(lobby_id) if lobby_id else None
            if lobby is None or lobby["host"] != player:
                return False
            return self._close_lobby_locked(lobby_id)


class CompanionHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], state: CompanionState):
        super().__init__(address, CompanionRequestHandler)
        self.state = state


class CompanionRequestHandler(BaseHTTPRequestHandler):
    server: CompanionHTTPServer
    protocol_version = "HTTP/1.1"
    server_version = f"OpenVPN-LAN-Companion/{APP_VERSION}"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, message_format: str, *arguments: Any) -> None:
        logging.debug("%s %s", self.client_address[0], message_format % arguments)

    def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _error(self, error: CompanionError) -> None:
        self._send_json(
            error.status,
            {"ok": False, "code": error.code, "error": error.message},
        )

    def _authenticate(self) -> tuple[str, str]:
        address = self.client_address[0]
        if not self.server.state.source_allowed(address):
            raise CompanionError(
                HTTPStatus.FORBIDDEN,
                "source address is outside the VPN",
                "source_outside_vpn",
            )
        self.server.state.enforce_auth_source(address)
        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            self.server.state.record_auth_failure(address)
            raise CompanionError(
                HTTPStatus.UNAUTHORIZED,
                "missing bearer token",
                "missing_token",
            )
        token = authorization[7:]
        player = self.server.state.authenticate(token)
        if player is None:
            self.server.state.record_auth_failure(address)
            raise CompanionError(
                HTTPStatus.UNAUTHORIZED,
                "invalid bearer token",
                "invalid_token",
            )
        self.server.state.touch(player, address)
        return player, address

    def _read_object(self) -> dict[str, Any]:
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("application/json"):
            raise CompanionError(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                "JSON is required",
                "json_required",
            )
        try:
            content_length = int(self.headers.get("Content-Length", ""))
        except ValueError as exc:
            raise CompanionError(
                HTTPStatus.LENGTH_REQUIRED,
                "Content-Length is required",
                "length_required",
            ) from exc
        maximum = self.server.state.config["max_request_bytes"]
        if not 1 <= content_length <= maximum:
            raise CompanionError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "request body is too large",
                "request_too_large",
            )
        raw_body = self.rfile.read(content_length)
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CompanionError(
                HTTPStatus.BAD_REQUEST,
                "request body is not valid JSON",
                "invalid_json",
            ) from exc
        if not isinstance(payload, dict):
            raise CompanionError(
                HTTPStatus.BAD_REQUEST,
                "JSON root must be an object",
                "invalid_json_root",
            )
        return payload

    def do_GET(self) -> None:  # noqa: N802
        try:
            parsed = urlsplit(self.path)
            if parsed.path == "/healthz":
                self._send_json(
                    HTTPStatus.OK,
                    {"ok": True, "service": "lan-party-companion", "version": APP_VERSION},
                )
                return
            if parsed.path not in {"/api/v1/state", "/api/v2/state"}:
                raise CompanionError(
                    HTTPStatus.NOT_FOUND,
                    "endpoint not found",
                    "endpoint_not_found",
                )
            player, _ = self._authenticate()
            self.server.state.enforce_poll_rate(player)
            query = parse_qs(parsed.query, keep_blank_values=True)
            raw_since = query.get("since", ["0"])[0]
            try:
                since = int(raw_since)
            except ValueError as exc:
                raise CompanionError(
                    HTTPStatus.BAD_REQUEST,
                    "since must be an integer",
                    "invalid_since",
                ) from exc
            if since < 0:
                raise CompanionError(
                    HTTPStatus.BAD_REQUEST,
                    "since must be positive",
                    "invalid_since",
                )
            if parsed.path == "/api/v2/state":
                state = self.server.state.snapshot_v2(player, since)
            else:
                state = self.server.state.snapshot_v1(player, since)
            self._send_json(HTTPStatus.OK, state)
        except CompanionError as error:
            self._error(error)
        except (OSError, ValueError) as error:
            logging.exception("companion request failed")
            self._error(
                CompanionError(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "internal server error",
                    "internal_error",
                )
            )

    def do_POST(self) -> None:  # noqa: N802
        try:
            parsed = urlsplit(self.path)
            player, address = self._authenticate()
            payload = self._read_object()
            if parsed.path in {"/api/v1/message", "/api/v2/message"}:
                target = payload.get("target")
                if target == "":
                    target = None
                text = payload.get("text")
                if not isinstance(text, str):
                    raise CompanionError(
                        HTTPStatus.BAD_REQUEST,
                        "message text is required",
                        "invalid_message",
                    )
                message = self.server.state.send_message(
                    player,
                    target,
                    text,
                    payload.get("color"),
                )
                self._send_json(HTTPStatus.CREATED, {"ok": True, "message": message})
                return
            if parsed.path in {"/api/v1/status", "/api/v2/status"}:
                status_value = payload.get("status")
                if not isinstance(status_value, str):
                    raise CompanionError(
                        HTTPStatus.BAD_REQUEST,
                        "status is required",
                        "invalid_status",
                    )
                self.server.state.set_status(player, status_value)
                self._send_json(HTTPStatus.OK, {"ok": True})
                return
            if parsed.path == "/api/v1/room":
                room = self.server.state.upsert_room(player, address, payload)
                self._send_json(HTTPStatus.OK, {"ok": True, "room": room})
                return
            if parsed.path == "/api/v2/lobby":
                lobby = self.server.state.upsert_lobby(player, address, payload)
                self._send_json(HTTPStatus.OK, {"ok": True, "lobby": lobby})
                return
            if parsed.path == "/api/v2/lobby/join":
                lobby = self.server.state.join_lobby(player, payload.get("lobby_id"))
                self._send_json(HTTPStatus.OK, {"ok": True, "lobby": lobby})
                return
            if parsed.path == "/api/v2/lobby/leave":
                result = self.server.state.leave_lobby(player)
                self._send_json(HTTPStatus.OK, {"ok": True, **result})
                return
            if parsed.path == "/api/v2/lobby/ready":
                lobby = self.server.state.set_lobby_ready(
                    player,
                    payload.get("ready"),
                )
                self._send_json(HTTPStatus.OK, {"ok": True, "lobby": lobby})
                return
            if parsed.path == "/api/v2/lobby/phase":
                lobby = self.server.state.set_lobby_phase(
                    player,
                    payload.get("phase"),
                    payload.get("expected_revision"),
                )
                self._send_json(HTTPStatus.OK, {"ok": True, "lobby": lobby})
                return
            if parsed.path == "/api/v2/lobby/lock":
                lobby = self.server.state.set_lobby_locked(
                    player,
                    payload.get("locked"),
                    payload.get("expected_revision"),
                )
                self._send_json(HTTPStatus.OK, {"ok": True, "lobby": lobby})
                return
            if parsed.path == "/api/v2/lobby/transfer":
                lobby = self.server.state.transfer_lobby(
                    player,
                    payload.get("target"),
                    payload.get("expected_revision"),
                )
                self._send_json(HTTPStatus.OK, {"ok": True, "lobby": lobby})
                return
            if parsed.path == "/api/v2/lobby/message":
                message = self.server.state.send_lobby_message(
                    player,
                    payload.get("text"),
                    payload.get("color"),
                )
                self._send_json(
                    HTTPStatus.CREATED,
                    {"ok": True, "message": message},
                )
                return
            raise CompanionError(
                HTTPStatus.NOT_FOUND,
                "endpoint not found",
                "endpoint_not_found",
            )
        except CompanionError as error:
            self._error(error)
        except (OSError, ValueError) as error:
            logging.exception("companion request failed")
            self._error(
                CompanionError(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "internal server error",
                    "internal_error",
                )
            )

    def do_DELETE(self) -> None:  # noqa: N802
        try:
            parsed = urlsplit(self.path)
            player, _ = self._authenticate()
            if parsed.path == "/api/v2/lobby":
                result = self.server.state.leave_lobby(player)
                self._send_json(HTTPStatus.OK, {"ok": True, **result})
                return
            if parsed.path != "/api/v1/room":
                raise CompanionError(
                    HTTPStatus.NOT_FOUND,
                    "endpoint not found",
                    "endpoint_not_found",
                )
            removed = self.server.state.close_room(player)
            self._send_json(HTTPStatus.OK, {"ok": True, "removed": removed})
        except CompanionError as error:
            self._error(error)
        except (OSError, ValueError) as error:
            logging.exception("companion request failed")
            self._error(
                CompanionError(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    "internal server error",
                    "internal_error",
                )
            )


def serve(config_path: Path) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    config = load_config(config_path)
    state = CompanionState(config)
    address = (config["bind_host"], config["port"])
    server = CompanionHTTPServer(address, state)
    logging.info("LAN companion listening on http://%s:%d", *address)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def validate_deployment(config_path: Path) -> None:
    """Validate configuration and player state without opening a socket."""
    config = load_config(config_path)
    CompanionState(config)
    print(f"LAN Party Companion {APP_VERSION}: configuration is valid")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=APP_VERSION)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("/etc/openvpn-lan-companion/config.json"),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("serve", help="run the companion HTTP service")
    subparsers.add_parser(
        "validate",
        help="validate configuration and registered players without listening",
    )

    issue_parser = subparsers.add_parser(
        "issue-player", help="create and register a player companion identity"
    )
    issue_parser.add_argument("--player", required=True)
    issue_parser.add_argument("--output", type=Path, required=True)

    remove_parser = subparsers.add_parser(
        "remove-player", help="remove a player companion identity"
    )
    remove_parser.add_argument("--player", required=True)

    args = parser.parse_args()
    try:
        if args.command == "serve":
            serve(args.config)
        elif args.command == "validate":
            validate_deployment(args.config)
        elif args.command == "issue-player":
            issue_player(args.config, args.player, args.output)
        elif args.command == "remove-player":
            config = load_config(args.config)
            update_player_registration(Path(config["players_file"]), args.player, None)
    except (OSError, ValueError) as exc:
        fail(str(exc))


if __name__ == "__main__":
    main()
