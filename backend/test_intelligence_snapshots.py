"""Tests for OSV and Kaspersky persistent intelligence snapshots."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ktip_actor_snapshots
import persistent_snapshot
import pocindex_mod


class IntelligenceSnapshotTests(unittest.TestCase):
    def setUp(self):
        ktip_actor_snapshots._LAST_KEY = ""

    def test_kaspersky_actor_list_uses_server_snapshot(self):
        live = {"items": [{"id": "actor-1", "name": "Example Actor"}]}
        with tempfile.TemporaryDirectory() as folder, patch.object(
            persistent_snapshot, "DATA_DIR", folder
        ), patch.object(ktip_actor_snapshots, "query_tip_actors", return_value=live) as fetch:
            first = ktip_actor_snapshots.actors("test-token", force_refresh=True)
            second = ktip_actor_snapshots.actors("test-token")

        self.assertEqual(fetch.call_count, 1)
        self.assertEqual(first["_snapshot"]["mode"], "live")
        self.assertEqual(second["_snapshot"]["mode"], "cache")
        self.assertEqual(second["items"][0]["id"], "actor-1")

    def test_kaspersky_failure_keeps_last_successful_snapshot(self):
        live = {"items": [{"id": "actor-1"}]}
        with tempfile.TemporaryDirectory() as folder, patch.object(
            persistent_snapshot, "DATA_DIR", folder
        ), patch.object(ktip_actor_snapshots, "query_tip_actors", return_value=live):
            ktip_actor_snapshots.actors("test-token", force_refresh=True)
        # Keep the temporary directory alive for both calls.
        with tempfile.TemporaryDirectory() as folder, patch.object(
            persistent_snapshot, "DATA_DIR", folder
        ):
            persistent_snapshot.save("kaspersky_threat_actors", {"kind": "actors", "identity": "all"}, live)
            with patch.object(ktip_actor_snapshots, "query_tip_actors", return_value={"error": "offline"}):
                fallback = ktip_actor_snapshots.actors("test-token", force_refresh=True)
        self.assertEqual(fallback["_snapshot"]["mode"], "stale")
        self.assertEqual(fallback["items"][0]["id"], "actor-1")

    def test_api_token_is_not_written_to_snapshot(self):
        secret = "very-secret-kaspersky-token"
        with tempfile.TemporaryDirectory() as folder, patch.object(
            persistent_snapshot, "DATA_DIR", folder
        ), patch.object(ktip_actor_snapshots, "query_tip_actors", return_value={"items": []}):
            ktip_actor_snapshots.actors(secret, force_refresh=True)
            text = "\n".join(path.read_text(encoding="utf-8") for path in Path(folder).rglob("*.json"))
        self.assertNotIn(secret, text)

    def test_osv_snapshot_helper_falls_back_after_error(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(
            persistent_snapshot, "DATA_DIR", folder
        ):
            pocindex_mod._osv_snapshot_finish("osv_recent", "default", {"items": [{"id": "MAL-1"}]})
            fallback = pocindex_mod._osv_snapshot_finish("osv_recent", "default", {"error": "offline"})
        self.assertEqual(fallback["_snapshot"]["mode"], "stale")
        self.assertEqual(fallback["items"][0]["id"], "MAL-1")


if __name__ == "__main__":
    unittest.main()
