"""Focused tests for persistent Ransomware Intelligence snapshots."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ransomware_monitor


class _Response:
    status_code = 200
    encoding = "utf-8"
    text = "ok"

    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


class RansomwareSnapshotTests(unittest.TestCase):
    def setUp(self):
        ransomware_monitor._CACHE.clear()
        ransomware_monitor._PROVIDER_STATE.clear()

    def test_provider_snapshot_is_used_when_network_fails(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(
            ransomware_monitor, "SNAPSHOT_DIR", folder
        ):
            with patch.object(ransomware_monitor.requests, "get", return_value=_Response({"items": [1]})):
                live = ransomware_monitor._http_get("Test Provider", "https://example.test", "/feed")
            self.assertEqual(live, {"items": [1]})

            ransomware_monitor._CACHE.clear()
            with patch.object(ransomware_monitor.requests, "get", side_effect=OSError("offline")):
                offline = ransomware_monitor._http_get("Test Provider", "https://example.test", "/feed")

            self.assertEqual(offline, live)
            self.assertEqual(ransomware_monitor._PROVIDER_STATE["Test Provider"]["status"], "snapshot")

    def test_snapshot_files_do_not_contain_api_keys(self):
        secret = "super-secret-rwlive-key"
        with tempfile.TemporaryDirectory() as folder, patch.object(
            ransomware_monitor, "SNAPSHOT_DIR", folder
        ):
            with patch.object(ransomware_monitor.requests, "get", return_value=_Response([{"id": 1}])):
                ransomware_monitor._http_get(
                    "Ransomware.live", "https://example.test", "/groups",
                    headers={"X-API-KEY": secret},
                )
            combined = "\n".join(path.read_text(encoding="utf-8") for path in Path(folder).rglob("*.json"))
            self.assertNotIn(secret, combined)

    def test_page_navigation_reads_saved_result_without_rebuilding(self):
        calls = []

        def builder(_page, _params):
            return lambda: calls.append("built") or {"sources": [], "items": ["snapshot"]}

        with tempfile.TemporaryDirectory() as folder, patch.object(
            ransomware_monitor, "SNAPSHOT_DIR", folder
        ), patch.object(ransomware_monitor, "_page_builder", side_effect=builder):
            first = ransomware_monitor.serve_page("overview", {"days": 30})
            second = ransomware_monitor.serve_page("overview", {"days": 30})

        self.assertEqual(calls, ["built"])
        self.assertEqual(first["_snapshot"]["mode"], "live")
        self.assertEqual(second["_snapshot"]["mode"], "cache")
        self.assertEqual(second["items"], ["snapshot"])


if __name__ == "__main__":
    unittest.main()
