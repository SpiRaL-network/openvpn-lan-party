#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
COMPANION_HELPER = REPOSITORY / "assets" / "lan-party-companion.py"


def load_companion_module():
    spec = importlib.util.spec_from_file_location("lan_party_companion", COMPANION_HELPER)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the LAN companion module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


COMPANION = load_companion_module()


class CompanionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.players_path = self.root / "players.json"
        self.players_path.write_text(
            json.dumps(COMPANION.empty_players_document()), encoding="utf-8"
        )
        os.chmod(self.players_path, 0o640)
        self.config_path = self.root / "config.json"
        self.config = {
            "allowed_subnet": "127.0.0.0/8",
            "bind_host": "127.0.0.1",
            "max_request_bytes": 8192,
            "message_retention": 200,
            "players_file": str(self.players_path),
            "port": 8787,
            "presence_ttl_seconds": 10,
        }
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")
        self.tokens: dict[str, str] = {}
        for player in ("Arthur", "Beatrice", "Charles"):
            client_path = self.root / f"{player}.json"
            COMPANION.issue_player(self.config_path, player, client_path)
            self.tokens[player] = json.loads(client_path.read_text())["token"]

        state = COMPANION.CompanionState(COMPANION.load_config(self.config_path))
        self.server = COMPANION.CompanionHTTPServer(("127.0.0.1", 0), state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temporary.cleanup()

    def request(
        self,
        method: str,
        path: str,
        player: str | None = None,
        payload: dict | None = None,
    ) -> tuple[int, dict]:
        data = None
        headers = {}
        if player is not None:
            headers["Authorization"] = f"Bearer {self.tokens[player]}"
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def test_issued_identity_stores_only_a_hash_and_refuses_duplicates(self) -> None:
        players_text = self.players_path.read_text(encoding="utf-8")
        self.assertNotIn(self.tokens["Arthur"], players_text)
        if os.name != "nt":
            self.assertEqual(self.players_path.stat().st_mode & 0o777, 0o640)
            self.assertEqual((self.root / "Arthur.json").stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(ValueError, "already exists"):
            COMPANION.issue_player(
                self.config_path, "Arthur", self.root / "Arthur-duplicate.json"
            )

    def test_idempotent_enrollment_preserves_existing_companion_identity(self) -> None:
        token = "A" * 43
        self.assertEqual(
            "created",
            COMPANION.ensure_player_registration(self.players_path, "Diane", token),
        )
        self.assertEqual(
            "existing-same",
            COMPANION.ensure_player_registration(self.players_path, "Diane", token),
        )
        self.assertEqual(
            "existing-different",
            COMPANION.ensure_player_registration(self.players_path, "Diane", "B" * 43),
        )
        document = json.loads(self.players_path.read_text(encoding="utf-8"))
        self.assertNotIn(token, self.players_path.read_text(encoding="utf-8"))
        self.assertIn("Diane", document["players"])

    def test_authenticated_presence_uses_server_identity_and_source_ip(self) -> None:
        status, state = self.request("GET", "/api/v1/state", "Arthur")
        self.assertEqual(status, 200)
        self.assertEqual(state["self"], "Arthur")
        self.assertEqual(
            state["players"],
            [
                {
                    "connected_for_seconds": 0,
                    "pseudo": "Arthur",
                    "status": "online",
                    "vpn_ip": "127.0.0.1",
                }
            ],
        )

        status, error = self.request("GET", "/api/v1/state")
        self.assertEqual(status, 401)
        self.assertEqual(error["error"], "missing bearer token")
        self.assertEqual(error["code"], "missing_token")

        status, state_v2 = self.request("GET", "/api/v2/state", "Arthur")
        self.assertEqual(status, 200)
        self.assertEqual(state_v2["api_version"], 2)
        players = {entry["pseudo"]: entry for entry in state_v2["players"]}
        self.assertTrue(players["Arthur"]["online"])
        self.assertEqual(players["Arthur"]["vpn_ip"], "127.0.0.1")
        self.assertFalse(players["Beatrice"]["online"])
        self.assertIsNone(players["Beatrice"]["vpn_ip"])
        self.assertEqual(players["Beatrice"]["status"], "offline")

    def test_v2_state_handles_thirty_two_registered_players(self) -> None:
        for index in range(29):
            player = f"Player{index:02d}"
            COMPANION.issue_player(
                self.config_path,
                player,
                self.root / f"{player}.json",
            )
        status, state = self.request("GET", "/api/v2/state", "Arthur")
        self.assertEqual(status, 200)
        self.assertEqual(len(state["players"]), 32)
        players = {entry["pseudo"]: entry for entry in state["players"]}
        self.assertTrue(players["Arthur"]["online"])
        self.assertFalse(players["Player28"]["online"])
        self.assertIsNone(players["Player28"]["vpn_ip"])

    def test_presence_duration_resets_after_a_real_disconnect(self) -> None:
        self.assertEqual(self.request("GET", "/api/v1/state", "Arthur")[0], 200)
        self.assertEqual(
            self.request(
                "POST",
                "/api/v2/lobby",
                "Arthur",
                {
                    "game": "Quake III Arena",
                    "lobby_name": "q3dm17",
                    "port": None,
                    "capacity": 8,
                },
            )[0],
            200,
        )
        with self.server.state.lock:
            self.server.state.presence["Arthur"]["last_seen"] = time.time() - 40
            self.server.state.presence["Arthur"]["status"] = "ready"

        state = self.request("GET", "/api/v1/state", "Arthur")[1]
        self.assertEqual(state["players"][0]["connected_for_seconds"], 0)
        self.assertEqual(state["players"][0]["status"], "online")
        self.assertEqual(state["rooms"], [])

    def test_lobby_survives_short_host_loss_then_closes_after_grace(self) -> None:
        for player in ("Arthur", "Beatrice"):
            self.request("GET", "/api/v2/state", player)
        lobby = self.request(
            "POST",
            "/api/v2/lobby",
            "Arthur",
            {
                "game": "Quake III Arena",
                "lobby_name": "Reconnect grace",
                "port": 27960,
                "capacity": 4,
            },
        )[1]["lobby"]
        self.assertEqual(
            self.request(
                "POST",
                "/api/v2/lobby/join",
                "Beatrice",
                {"lobby_id": lobby["id"]},
            )[0],
            200,
        )

        with self.server.state.lock:
            self.server.state.presence["Arthur"]["last_seen"] = time.time() - 15
        transient = self.request("GET", "/api/v2/state", "Beatrice")[1]
        self.assertEqual(len(transient["lobbies"]), 1)
        self.assertEqual(transient["lobbies"][0]["member_count"], 2)
        self.assertIsNone(transient["lobbies"][0]["host_ip"])

        with self.server.state.lock:
            self.server.state.presence["Arthur"]["last_seen"] = time.time() - 31
        expired = self.request("GET", "/api/v2/state", "Beatrice")[1]
        self.assertEqual(expired["lobbies"], [])
        self.assertIsNone(expired["current_lobby"])

    def test_v2_lobby_uses_server_identity_optional_port_and_required_capacity(self) -> None:
        self.request("GET", "/api/v2/state", "Arthur")
        status, result = self.request(
            "POST",
            "/api/v2/lobby",
            "Arthur",
            {
                "host": "Charles",
                "host_ip": "203.0.113.10",
                "member_count": 99,
                "game": "Quake III Arena",
                "lobby_name": "  Rockets only  ",
                "port": None,
                "capacity": 8,
            },
        )
        self.assertEqual(status, 200)
        lobby = result["lobby"]
        self.assertEqual(lobby["host"], "Arthur")
        self.assertEqual(lobby["host_ip"], "127.0.0.1")
        self.assertEqual(lobby["lobby_name"], "Rockets only")
        self.assertIsNone(lobby["port"])
        self.assertEqual(lobby["capacity"], 8)
        self.assertEqual(lobby["member_count"], 1)
        self.assertEqual([member["pseudo"] for member in lobby["members"]], ["Arthur"])

        status, error = self.request(
            "POST",
            "/api/v2/lobby",
            "Beatrice",
            {"game": "Q3", "lobby_name": "No capacity", "port": None},
        )
        self.assertEqual(status, 400)
        self.assertEqual(error["code"], "invalid_lobby_capacity")

    def test_plain_text_rejects_spoofing_controls_but_keeps_normal_unicode(self) -> None:
        self.request("GET", "/api/v2/state", "Arthur")
        status, error = self.request(
            "POST",
            "/api/v2/lobby",
            "Arthur",
            {
                "game": "Quake III Arena",
                "lobby_name": "safe\u202etxt",
                "port": None,
                "capacity": 8,
            },
        )
        self.assertEqual(status, 400)
        self.assertEqual(error["code"], "invalid_lobby_name")

        status, error = self.request(
            "POST",
            "/api/v2/message",
            "Arthur",
            {"text": "hello\u2066spoof", "color": "blue"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(error["code"], "invalid_message")
        status, result = self.request(
            "POST",
            "/api/v2/message",
            "Arthur",
            {"text": "Team 👨‍👩‍👧‍👦 ready", "color": "green"},
        )
        self.assertEqual(status, 201)
        self.assertEqual(result["message"]["text"], "Team 👨‍👩‍👧‍👦 ready")

    def test_lobby_last_place_is_atomic_and_join_is_idempotent(self) -> None:
        for player in ("Arthur", "Beatrice", "Charles"):
            self.request("GET", "/api/v2/state", player)
        lobby = self.request(
            "POST",
            "/api/v2/lobby",
            "Arthur",
            {
                "game": "BFME2",
                "lobby_name": "Final slot",
                "port": None,
                "capacity": 2,
            },
        )[1]["lobby"]

        barrier = threading.Barrier(3)
        results: list[tuple[int, dict]] = []

        def join(player: str) -> None:
            barrier.wait()
            results.append(
                self.request(
                    "POST",
                    "/api/v2/lobby/join",
                    player,
                    {"lobby_id": lobby["id"]},
                )
            )

        threads = [
            threading.Thread(target=join, args=(player,))
            for player in ("Beatrice", "Charles")
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)

        self.assertEqual(sorted(status for status, _ in results), [200, 409])
        rejection = next(payload for status, payload in results if status == 409)
        self.assertEqual(rejection["code"], "lobby_full")
        accepted_player = next(
            player
            for player in ("Beatrice", "Charles")
            if self.server.state.player_lobby.get(player) == lobby["id"]
        )
        status, repeated = self.request(
            "POST",
            "/api/v2/lobby/join",
            accepted_player,
            {"lobby_id": lobby["id"]},
        )
        self.assertEqual(status, 200)
        self.assertEqual(repeated["lobby"]["member_count"], 2)

        state = self.request("GET", "/api/v2/state", "Arthur")[1]
        self.assertEqual(state["lobbies"][0]["member_count"], 2)
        self.assertEqual(state["lobbies"][0]["capacity"], 2)

    def test_lobby_chat_is_member_only_and_colors_are_allowlisted(self) -> None:
        for player in ("Arthur", "Beatrice", "Charles"):
            self.request("GET", "/api/v2/state", player)
        lobby = self.request(
            "POST",
            "/api/v2/lobby",
            "Arthur",
            {
                "game": "Quake III Arena",
                "lobby_name": "Private team chat",
                "port": 27960,
                "capacity": 3,
            },
        )[1]["lobby"]
        self.assertEqual(
            self.request(
                "POST",
                "/api/v2/lobby/join",
                "Beatrice",
                {"lobby_id": lobby["id"]},
            )[0],
            200,
        )

        status, sent = self.request(
            "POST",
            "/api/v2/lobby/message",
            "Beatrice",
            {"text": "Attack left", "color": "purple"},
        )
        self.assertEqual(status, 201)
        message_id = sent["message"]["id"]
        self.assertEqual(sent["message"]["color"], "purple")

        member_state = self.request("GET", "/api/v2/state?since=0", "Arthur")[1]
        self.assertIn(
            message_id,
            [message["id"] for message in member_state["lobby_messages"]],
        )
        outsider_state = self.request("GET", "/api/v2/state?since=0", "Charles")[1]
        self.assertIsNone(outsider_state["current_lobby"])
        self.assertEqual(outsider_state["lobby_messages"], [])

        status, error = self.request(
            "POST",
            "/api/v2/lobby/message",
            "Charles",
            {"text": "Let me in", "color": "green"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(error["code"], "not_in_lobby")
        status, error = self.request(
            "POST",
            "/api/v2/message",
            "Charles",
            {"text": "unsafe color", "color": "#ffffff"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(error["code"], "invalid_message_color")

    def test_leave_updates_occupancy_and_member_cannot_edit_host_lobby(self) -> None:
        for player in ("Arthur", "Beatrice"):
            self.request("GET", "/api/v2/state", player)
        lobby = self.request(
            "POST",
            "/api/v2/lobby",
            "Arthur",
            {
                "game": "BFME2",
                "lobby_name": "Two versus two",
                "port": None,
                "capacity": 4,
            },
        )[1]["lobby"]
        self.request(
            "POST",
            "/api/v2/lobby/join",
            "Beatrice",
            {"lobby_id": lobby["id"]},
        )
        status, error = self.request(
            "POST",
            "/api/v2/lobby",
            "Beatrice",
            {
                "game": "Changed",
                "lobby_name": "Spoofed",
                "port": 1234,
                "capacity": 8,
            },
        )
        self.assertEqual(status, 409)
        self.assertEqual(error["code"], "already_in_lobby")

        status, left = self.request(
            "POST", "/api/v2/lobby/leave", "Beatrice", {}
        )
        self.assertEqual(status, 200)
        self.assertTrue(left["left"])
        self.assertFalse(left["closed"])
        state = self.request("GET", "/api/v2/state", "Arthur")[1]
        self.assertEqual(state["lobbies"][0]["member_count"], 1)

    def test_v3_state_exposes_connection_and_lobby_capabilities(self) -> None:
        state = self.request("GET", "/api/v2/state", "Arthur")[1]
        self.assertEqual(state["server_version"], "1.0.1")
        self.assertEqual(state["minimum_client_version"], "0.2.0")
        self.assertIn("presence_duration", state["features"])
        self.assertIn("manual_availability", state["features"])
        self.assertIn("ready_check", state["features"])
        self.assertIsInstance(state["players"][0]["connected_since_at"], int)

        status, result = self.request(
            "POST",
            "/api/v2/lobby",
            "Arthur",
            {
                "game": "Quake III Arena",
                "lobby_name": "Soirée entre amis",
                "join_instructions": "Multijoueur > Direct IP\nPuis saisir l'adresse de l'hôte.",
                "port": 27960,
                "capacity": 8,
            },
        )
        self.assertEqual(status, 200)
        lobby = result["lobby"]
        self.assertEqual(lobby["phase"], "gathering")
        self.assertFalse(lobby["locked"])
        self.assertEqual(lobby["revision"], 1)
        self.assertEqual(lobby["ready_count"], 0)
        self.assertFalse(lobby["all_ready"])
        self.assertIn("Direct IP", lobby["join_instructions"])
        self.assertEqual(lobby["members"][0]["role"], "host")
        self.assertFalse(lobby["members"][0]["ready"])

    def test_ready_check_phase_and_manual_status_are_coherent(self) -> None:
        for player in ("Arthur", "Beatrice"):
            self.request("GET", "/api/v2/state", player)
        self.request(
            "POST", "/api/v2/status", "Arthur", {"status": "busy"}
        )
        lobby = self.request(
            "POST",
            "/api/v2/lobby",
            "Arthur",
            {
                "game": "Age of Empires II",
                "lobby_name": "Partie privée",
                "join_instructions": "Rejoindre 127.0.0.1 dans le navigateur LAN.",
                "port": None,
                "capacity": 4,
            },
        )[1]["lobby"]
        joined = self.request(
            "POST",
            "/api/v2/lobby/join",
            "Beatrice",
            {"lobby_id": lobby["id"]},
        )[1]["lobby"]

        for player in ("Arthur", "Beatrice"):
            ready = self.request(
                "POST", "/api/v2/lobby/ready", player, {"ready": True}
            )[1]["lobby"]
        self.assertTrue(ready["all_ready"])
        self.assertEqual(ready["ready_count"], 2)

        started = self.request(
            "POST",
            "/api/v2/lobby/phase",
            "Arthur",
            {"phase": "in_game", "expected_revision": ready["revision"]},
        )[1]["lobby"]
        self.assertEqual(started["phase"], "in_game")
        state = self.request("GET", "/api/v2/state", "Beatrice")[1]
        statuses = {player["pseudo"]: player["status"] for player in state["players"]}
        availability = {
            player["pseudo"]: player["availability_status"]
            for player in state["players"]
        }
        self.assertEqual(statuses["Arthur"], "in_game")
        self.assertEqual(statuses["Beatrice"], "in_game")
        self.assertEqual(availability["Arthur"], "busy")
        self.assertEqual(availability["Beatrice"], "online")
        status, error = self.request(
            "POST", "/api/v2/lobby/ready", "Beatrice", {"ready": False}
        )
        self.assertEqual(status, 409)
        self.assertEqual(error["code"], "lobby_not_gathering")

        gathering = self.request(
            "POST",
            "/api/v2/lobby/phase",
            "Arthur",
            {"phase": "gathering", "expected_revision": started["revision"]},
        )[1]["lobby"]
        self.assertEqual(gathering["ready_count"], 0)
        state = self.request("GET", "/api/v2/state", "Arthur")[1]
        statuses = {player["pseudo"]: player["status"] for player in state["players"]}
        self.assertEqual(statuses["Arthur"], "busy")
        self.assertEqual(statuses["Beatrice"], "online")

    def test_lobby_revision_lock_and_host_transfer_are_enforced(self) -> None:
        for player in ("Arthur", "Beatrice", "Charles"):
            self.request("GET", "/api/v2/state", player)
        lobby = self.request(
            "POST",
            "/api/v2/lobby",
            "Arthur",
            {
                "game": "Warcraft III",
                "lobby_name": "Trusted group",
                "join_instructions": "Choisir Réseau local.",
                "port": 6112,
                "capacity": 4,
            },
        )[1]["lobby"]
        lobby = self.request(
            "POST",
            "/api/v2/lobby/join",
            "Beatrice",
            {"lobby_id": lobby["id"]},
        )[1]["lobby"]
        stale_revision = lobby["revision"]
        locked = self.request(
            "POST",
            "/api/v2/lobby/lock",
            "Arthur",
            {"locked": True, "expected_revision": stale_revision},
        )[1]["lobby"]
        self.assertTrue(locked["locked"])

        status, error = self.request(
            "POST",
            "/api/v2/lobby/join",
            "Charles",
            {"lobby_id": lobby["id"]},
        )
        self.assertEqual(status, 409)
        self.assertEqual(error["code"], "lobby_locked")
        status, error = self.request(
            "POST",
            "/api/v2/lobby/phase",
            "Arthur",
            {"phase": "in_game", "expected_revision": stale_revision},
        )
        self.assertEqual(status, 409)
        self.assertEqual(error["code"], "lobby_revision_conflict")

        transferred = self.request(
            "POST",
            "/api/v2/lobby/transfer",
            "Arthur",
            {"target": "Beatrice", "expected_revision": locked["revision"]},
        )[1]["lobby"]
        self.assertEqual(transferred["host"], "Beatrice")
        status, error = self.request(
            "POST",
            "/api/v2/lobby/lock",
            "Arthur",
            {"locked": False, "expected_revision": transferred["revision"]},
        )
        self.assertEqual(status, 403)
        self.assertEqual(error["code"], "not_lobby_host")
        status, result = self.request(
            "POST",
            "/api/v2/lobby/lock",
            "Beatrice",
            {"locked": False, "expected_revision": transferred["revision"]},
        )
        self.assertEqual(status, 200)
        self.assertFalse(result["lobby"]["locked"])

    def test_offline_member_does_not_count_as_ready_during_reconnect_grace(self) -> None:
        for player in ("Arthur", "Beatrice"):
            self.request("GET", "/api/v2/state", player)
        lobby = self.request(
            "POST",
            "/api/v2/lobby",
            "Arthur",
            {
                "game": "OpenTTD",
                "lobby_name": "Reconnect ready check",
                "join_instructions": "Use the LAN server list.",
                "port": 3979,
                "capacity": 4,
            },
        )[1]["lobby"]
        self.request(
            "POST",
            "/api/v2/lobby/join",
            "Beatrice",
            {"lobby_id": lobby["id"]},
        )
        for player in ("Arthur", "Beatrice"):
            self.request(
                "POST", "/api/v2/lobby/ready", player, {"ready": True}
            )

        with self.server.state.lock:
            self.server.state.presence["Beatrice"]["last_seen"] = time.time() - 15
        current = self.request("GET", "/api/v2/state", "Arthur")[1][
            "current_lobby"
        ]
        self.assertEqual(current["ready_count"], 1)
        self.assertFalse(current["all_ready"])
        beatrice = next(
            member for member in current["members"] if member["pseudo"] == "Beatrice"
        )
        self.assertFalse(beatrice["online"])
        self.assertTrue(beatrice["ready"])

        self.request("GET", "/api/v2/state", "Beatrice")
        current = self.request("GET", "/api/v2/state", "Arthur")[1][
            "current_lobby"
        ]
        self.assertEqual(current["ready_count"], 2)
        self.assertTrue(current["all_ready"])

    def test_critical_lobby_edit_resets_ready_and_phase(self) -> None:
        self.request("GET", "/api/v2/state", "Arthur")
        lobby = self.request(
            "POST",
            "/api/v2/lobby",
            "Arthur",
            {
                "game": "Factorio",
                "lobby_name": "Usine",
                "join_instructions": "Connexion directe.",
                "port": 34197,
                "capacity": 8,
            },
        )[1]["lobby"]
        lobby = self.request(
            "POST", "/api/v2/lobby/ready", "Arthur", {"ready": True}
        )[1]["lobby"]
        lobby = self.request(
            "POST",
            "/api/v2/lobby/phase",
            "Arthur",
            {"phase": "in_game", "expected_revision": lobby["revision"]},
        )[1]["lobby"]
        status, result = self.request(
            "POST",
            "/api/v2/lobby",
            "Arthur",
            {
                "game": "Factorio",
                "lobby_name": "Usine - nouvelle carte",
                "join_instructions": "Connexion directe, mot de passe communiqué vocalement.",
                "port": 34198,
                "capacity": 8,
                "expected_revision": lobby["revision"],
            },
        )
        self.assertEqual(status, 200)
        updated = result["lobby"]
        self.assertEqual(updated["phase"], "gathering")
        self.assertEqual(updated["ready_count"], 0)
        self.assertEqual(updated["port"], 34198)

        status, error = self.request(
            "POST",
            "/api/v2/lobby",
            "Arthur",
            {
                "game": "Factorio",
                "lobby_name": "Stale update",
                "join_instructions": "Connexion directe.",
                "port": 34197,
                "capacity": 8,
                "expected_revision": lobby["revision"],
            },
        )
        self.assertEqual(status, 409)
        self.assertEqual(error["code"], "lobby_revision_conflict")

    def test_public_and_private_messages_cannot_spoof_the_sender(self) -> None:
        for player in ("Arthur", "Beatrice", "Charles"):
            self.assertEqual(self.request("GET", "/api/v1/state", player)[0], 200)

        status, public = self.request(
            "POST",
            "/api/v1/message",
            "Arthur",
            {"sender": "Charles", "target": None, "text": "Ready?"},
        )
        self.assertEqual(status, 201)
        self.assertEqual(public["message"]["sender"], "Arthur")

        status, private = self.request(
            "POST",
            "/api/v1/message",
            "Arthur",
            {"target": "Beatrice", "text": "Host the next game"},
        )
        self.assertEqual(status, 201)
        private_id = private["message"]["id"]

        beatrice_state = self.request("GET", "/api/v1/state?since=0", "Beatrice")[1]
        self.assertIn(private_id, [message["id"] for message in beatrice_state["messages"]])
        charles_state = self.request("GET", "/api/v1/state?since=0", "Charles")[1]
        self.assertNotIn(private_id, [message["id"] for message in charles_state["messages"]])

    def test_room_host_and_address_are_derived_by_the_server(self) -> None:
        self.request("GET", "/api/v1/state", "Arthur")
        status, result = self.request(
            "POST",
            "/api/v1/room",
            "Arthur",
            {
                "host": "Charles",
                "host_ip": "203.0.113.10",
                "game": "Quake III Arena",
                "port": 27960,
                "max_players": 8,
                "notes": "q3dm17",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["room"]["host"], "Arthur")
        self.assertEqual(result["room"]["host_ip"], "127.0.0.1")
        state = self.request("GET", "/api/v1/state", "Beatrice")[1]
        self.assertEqual(state["rooms"][0]["host"], "Arthur")
        self.assertEqual(state["rooms"][0]["port"], 27960)

        status, closed = self.request("DELETE", "/api/v1/room", "Arthur")
        self.assertEqual(status, 200)
        self.assertTrue(closed["removed"])

    def test_revocation_is_reloaded_without_restarting_the_service(self) -> None:
        self.assertEqual(self.request("GET", "/api/v1/state", "Arthur")[0], 200)
        removed = COMPANION.update_player_registration(
            self.players_path, "Arthur", None
        )
        self.assertTrue(removed)
        status, error = self.request("GET", "/api/v1/state", "Arthur")
        self.assertEqual(status, 401)
        self.assertEqual(error["error"], "invalid bearer token")
        self.assertEqual(error["code"], "invalid_token")

    def test_revocation_removes_members_and_host_lobby_immediately(self) -> None:
        for player in ("Arthur", "Beatrice", "Charles"):
            self.request("GET", "/api/v2/state", player)
        lobby = self.request(
            "POST",
            "/api/v2/lobby",
            "Arthur",
            {
                "game": "Quake III Arena",
                "lobby_name": "Revocation test",
                "port": None,
                "capacity": 3,
            },
        )[1]["lobby"]
        self.request(
            "POST",
            "/api/v2/lobby/join",
            "Beatrice",
            {"lobby_id": lobby["id"]},
        )

        self.assertTrue(
            COMPANION.update_player_registration(
                self.players_path,
                "Beatrice",
                None,
            )
        )
        state = self.request("GET", "/api/v2/state", "Arthur")[1]
        self.assertEqual(state["lobbies"][0]["member_count"], 1)
        self.assertNotIn("Beatrice", self.server.state.player_lobby)

        self.assertTrue(
            COMPANION.update_player_registration(
                self.players_path,
                "Arthur",
                None,
            )
        )
        state = self.request("GET", "/api/v2/state", "Charles")[1]
        self.assertEqual(state["lobbies"], [])
        self.assertEqual(self.server.state.player_lobby, {})

    def test_message_rate_limit_and_request_size_are_enforced(self) -> None:
        self.request("GET", "/api/v1/state", "Arthur")
        for index in range(5):
            status, _ = self.request(
                "POST",
                "/api/v1/message",
                "Arthur",
                {"text": f"message {index}"},
            )
            self.assertEqual(status, 201)
        status, error = self.request(
            "POST", "/api/v1/message", "Arthur", {"text": "too fast"}
        )
        self.assertEqual(status, 429)
        self.assertEqual(error["code"], "message_rate_limited")

        status, error = self.request(
            "POST", "/api/v1/message", "Beatrice", {"text": "x" * 9000}
        )
        self.assertEqual(status, 413)
        self.assertEqual(error["error"], "request body is too large")
        self.assertEqual(error["code"], "request_too_large")

    def test_status_and_failed_authentication_are_rate_limited(self) -> None:
        self.request("GET", "/api/v2/state", "Arthur")
        statuses = ("online", "ready", "afk", "busy", "in_game")
        for index in range(20):
            status, _ = self.request(
                "POST",
                "/api/v2/status",
                "Arthur",
                {"status": statuses[index % len(statuses)]},
            )
            self.assertEqual(status, 200)
        status, error = self.request(
            "POST", "/api/v2/status", "Arthur", {"status": "online"}
        )
        self.assertEqual(status, 429)
        self.assertEqual(error["code"], "status_rate_limited")

        self.tokens["Beatrice"] = "A" * 32
        for _ in range(9):
            status, _ = self.request("GET", "/api/v2/state", "Beatrice")
            self.assertEqual(status, 401)
        status, _ = self.request("GET", "/api/v2/state")
        self.assertEqual(status, 401)
        status, error = self.request("GET", "/api/v2/state", "Beatrice")
        self.assertEqual(status, 429)
        self.assertEqual(error["code"], "auth_rate_limited")

    def test_state_polling_is_rate_limited_per_player(self) -> None:
        for _ in range(40):
            status, _ = self.request("GET", "/api/v2/state", "Arthur")
            self.assertEqual(status, 200)
        status, error = self.request("GET", "/api/v2/state", "Arthur")
        self.assertEqual(status, 429)
        self.assertEqual(error["code"], "state_rate_limited")


if __name__ == "__main__":
    unittest.main()
