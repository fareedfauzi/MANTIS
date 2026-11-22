"""Focused tests for Today's Intelligence structured AI responses."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ai_service
import todays_intelligence


class _FakeProvider:
    response = "{}"
    finish_reason = "stop"
    received_settings = None

    def __init__(self, settings):
        type(self).received_settings = settings
        self.last_finish_reason = type(self).finish_reason

    def generate(self, messages):
        return type(self).response


class TodaysIntelligenceAITests(unittest.TestCase):
    def setUp(self):
        _FakeProvider.response = "{}"
        _FakeProvider.finish_reason = "stop"
        _FakeProvider.received_settings = None
        self.settings = {
            "api_key": "test-key",
            "endpoint": "https://example.invalid/chat",
            "model": "test-model",
            "max_output_tokens": 2200,
        }

    def _brief(self):
        return todays_intelligence.ai_brief({"date": "2026-11-22"})

    def test_brief_accepts_fenced_json_and_raises_output_budget(self):
        _FakeProvider.response = """```json
        {
          "executive_summary": "Current evidence is limited.",
          "priority_items": ["Review the collected leads."],
          "watchlist": [],
          "recommended_actions": ["Validate the highest-confidence item."],
          "caveats": ["Collection is incomplete."]
        }
        ```"""
        with (
            patch.object(todays_intelligence.ai_service, "_settings_raw", return_value=self.settings),
            patch.object(todays_intelligence.ai_service, "AIProvider", _FakeProvider),
            patch.object(todays_intelligence.ai_service, "log_audit"),
        ):
            result = self._brief()

        self.assertEqual(result["executive_summary"], "Current evidence is limited.")
        self.assertEqual(result["priority_items"], ["Review the collected leads."])
        self.assertGreaterEqual(
            _FakeProvider.received_settings["max_output_tokens"],
            todays_intelligence.BRIEF_MIN_OUTPUT_TOKENS,
        )

    def test_brief_reports_token_limit_truncation(self):
        _FakeProvider.response = '{"executive_summary":"cut off'
        _FakeProvider.finish_reason = "length"
        with (
            patch.object(todays_intelligence.ai_service, "_settings_raw", return_value=self.settings),
            patch.object(todays_intelligence.ai_service, "AIProvider", _FakeProvider),
            patch.object(todays_intelligence.ai_service, "log_audit"),
        ):
            with self.assertRaisesRegex(ai_service.AIProviderError, "cut off at the 4000-token output limit"):
                self._brief()

    def test_brief_rejects_non_object_json(self):
        _FakeProvider.response = '["not", "an", "object"]'
        with (
            patch.object(todays_intelligence.ai_service, "_settings_raw", return_value=self.settings),
            patch.object(todays_intelligence.ai_service, "AIProvider", _FakeProvider),
            patch.object(todays_intelligence.ai_service, "log_audit"),
        ):
            with self.assertRaisesRegex(ai_service.AIProviderError, "malformed Today's Intelligence daily brief JSON"):
                self._brief()


if __name__ == "__main__":
    unittest.main()
