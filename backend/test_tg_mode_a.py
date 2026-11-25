"""Focused tests for the MATKAP-style Telegram Mode A controller flow."""

import os
import sys
import threading
import types
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import tg_intel


class _FakeClient:
    sent = []

    def __init__(self, *_args, **_kwargs):
        pass

    async def connect(self):
        return None

    async def disconnect(self):
        return None

    async def is_user_authorized(self):
        return True

    async def get_me(self):
        return types.SimpleNamespace(id=123456)

    async def send_message(self, target, message):
        self.sent.append((target, message))


class TgModeATests(unittest.TestCase):
    def test_native_registration_requires_target_operator_chat(self):
        with patch.object(tg_intel, "init_db"):
            result = tg_intel.add_bot("123456:abcdefghijklmnopqrstuvwxyzABCDEFGHI", transport="native")
        self.assertIn("operator chat ID", result["error"])

    def test_bootstrap_sends_start_and_discovers_controller_chat(self):
        fake_telethon = types.ModuleType("telethon")
        fake_sessions = types.ModuleType("telethon.sessions")
        fake_telethon.TelegramClient = _FakeClient
        fake_sessions.StringSession = lambda value: value
        fake_asyncio = types.ModuleType("asyncio")

        def run_immediately(coroutine):
            try:
                coroutine.send(None)
            except StopIteration as done:
                return done.value
            raise AssertionError("Test coroutine unexpectedly suspended")

        fake_asyncio.run = run_immediately
        calls = []

        def bot_call(_token, method, params=None, **_kwargs):
            calls.append((method, params))
            if method == "deleteWebhook":
                return {"ok": True, "result": True}
            return {"ok": True, "result": [{
                "update_id": 77,
                "message": {"message_id": 4, "chat": {"id": 123456}},
            }]}

        env = {
            "TELEGRAM_STRING_SESSION": "session",
            "TELEGRAM_API_ID": "1234",
            "TELEGRAM_API_HASH": "hash",
        }
        _FakeClient.sent.clear()
        with patch.dict(sys.modules, {"telethon": fake_telethon, "telethon.sessions": fake_sessions, "asyncio": fake_asyncio}), \
                patch.dict(os.environ, env, clear=False), \
                patch.object(tg_intel, "_load_env"), \
                patch.object(tg_intel, "_bot_call", side_effect=bot_call):
            result = tg_intel._native_controller_bootstrap(
                "token", "example_bot", threading.Event()
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["controller_chat_id"], "123456")
        self.assertEqual(result["message_id"], 4)
        self.assertEqual(_FakeClient.sent, [("@example_bot", "/start")])
        self.assertEqual(calls[0], ("deleteWebhook", {"drop_pending_updates": False}))

    def test_native_dump_stores_forwarded_message_content(self):
        forwarded = {
            1: {"message_id": 101, "date": 1, "chat": {"id": 99}, "text": "first"},
            2: {"message_id": 102, "date": 2, "chat": {"id": 99}, "text": "second"},
        }

        def forward(_token, _source, _dest, message_id):
            return (True, forwarded[message_id]) if message_id in forwarded else (False, "not found")

        stored = []
        with patch.dict(os.environ, {
            "MANTIS_TG_NATIVE_MAX_MESSAGE_ID": "30",
            "MANTIS_TG_NATIVE_MISSING_LIMIT": "25",
        }), patch.object(tg_intel, "_forward_single", side_effect=forward), \
                patch.object(tg_intel, "_store_copied", side_effect=lambda _b, mid, _c, item, _db: stored.append((mid, item["text"])) or True), \
                patch.object(tg_intel, "_set_bot_fields"):
            conn = types.SimpleNamespace(commit=lambda: None)
            result = tg_intel._dump_native_history(
                "bot-1", "token", "operator", "destination", threading.Event(), conn
            )

        self.assertEqual(result["copied"], 2)
        self.assertEqual(stored, [(1, "first"), (2, "second")])


if __name__ == "__main__":
    unittest.main()
