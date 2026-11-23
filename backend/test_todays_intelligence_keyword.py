"""Tests for Today's Intelligence keyword filtering."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import todays_intelligence


class TodaysIntelligenceKeywordTests(unittest.TestCase):
    def test_terms_support_quoted_phrases_and_bare_terms(self):
        self.assertEqual(
            todays_intelligence._keyword_terms('"Cobalt Strike" CVE-2026'),
            ["cobalt strike", "cve-2026"],
        )

    def test_nested_values_use_all_query_terms(self):
        row = {
            "title": "Cobalt Strike campaign",
            "indicators": [{"value": "CVE-2026-1234"}],
            "tags": ["malware", "intrusion-set"],
        }
        terms = todays_intelligence._keyword_terms('"cobalt strike" CVE-2026')
        self.assertTrue(todays_intelligence._matches_keyword(row, terms))
        self.assertFalse(todays_intelligence._matches_keyword(row, [*terms, "lockbit"]))

    def test_result_filter_preserves_metadata_and_updates_counts(self):
        result = {
            "source": "test",
            "note": "provider metadata",
            "total": 2,
            "items": [
                {"title": "LockBit victim in finance"},
                {"title": "Unrelated advisory"},
            ],
            "campaigns": [
                {"name": "LockBit finance campaign"},
                {"name": "Other activity"},
            ],
        }
        filtered = todays_intelligence._filter_keyword_result(result, ["lockbit"])
        self.assertEqual(filtered["source"], "test")
        self.assertEqual(filtered["note"], "provider metadata")
        self.assertEqual(filtered["total"], 1)
        self.assertEqual(len(filtered["items"]), 1)
        self.assertEqual(len(filtered["campaigns"]), 1)


if __name__ == "__main__":
    unittest.main()
