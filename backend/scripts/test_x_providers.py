"""Offline tests for X Monitor providers (stdlib unittest).

Run from backend/:  python3 -m unittest scripts.test_x_providers -v
"""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND)
os.environ.setdefault("MANTIS_X_MONITOR_DB", os.path.join(tempfile.mkdtemp(), "x.db"))

import requests  # noqa: E402
import x_providers as xp  # noqa: E402


class FakeResp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


X_TIMELINE = {
    "data": [
        {"id": "1001", "text": "Malware at https://evil.example/drop.exe #ransomware",
         "created_at": "2026-11-18T10:00:00.000Z", "lang": "en",
         "public_metrics": {"like_count": 3, "reply_count": 1, "retweet_count": 0, "quote_count": 0},
         "entities": {"urls": [{"url": "https://t.co/x", "expanded_url": "https://evil.example/drop.exe"}],
                      "hashtags": [{"tag": "ransomware"}]},
         "attachments": {"media_keys": ["m1"]}, "conversation_id": "1001", "author_id": "42"},
    ],
    "includes": {"users": [{"id": "42", "username": "CTIuser", "name": "CTI User", "profile_image_url": "https://img/x.jpg"}],
                 "media": [{"media_key": "m1", "type": "photo", "url": "https://pbs.twimg.com/media/a.jpg", "width": 800, "height": 600}]},
    "meta": {"result_count": 1, "next_token": "tok2"},
}


class TestOfficialX(unittest.TestCase):
    def setUp(self):
        xp._X_USER_IDS.clear()

    def _run(self, responses, **kw):
        calls = []

        def fake_get(url, headers=None, params=None, timeout=None):
            calls.append((url, headers, params))
            return responses.pop(0)

        with mock.patch.object(xp.requests, "get", side_effect=fake_get):
            out = xp.fetch_timeline_page("x_official", "CTIuser", "bearer-abc", **kw)
        return out, calls

    def test_maps_timeline_to_canonical_tweet(self):
        out, calls = self._run([FakeResp(200, {"data": {"id": "42", "username": "CTIuser"}}), FakeResp(200, X_TIMELINE)])
        self.assertNotIn("error", out)
        self.assertEqual(out["provider"], "x_official")
        self.assertEqual(out["pagination"], {"has_next_page": True, "next_cursor": "tok2"})
        self.assertEqual(out["diagnostics"]["provider_tweets"], 1)
        t = out["tweets"][0]
        self.assertEqual(t["id"], "1001")
        self.assertIn("evil.example", str(t))
        self.assertEqual(calls[0][1], {"Authorization": "Bearer bearer-abc"})
        self.assertIn("/users/by/username/CTIuser", calls[0][0])
        self.assertIn("/users/42/tweets", calls[1][0])
        self.assertEqual(calls[1][2]["exclude"], "replies")

    def test_user_id_is_cached(self):
        self._run([FakeResp(200, {"data": {"id": "42"}}), FakeResp(200, X_TIMELINE)])
        out, calls = self._run([FakeResp(200, X_TIMELINE)])
        self.assertEqual(len(calls), 1)
        self.assertIn("/users/42/tweets", calls[0][0])

    def test_error_mapping(self):
        cases = {401: "rejected the bearer token", 403: "plan may not include", 429: "rate limit"}
        for code, phrase in cases.items():
            xp._X_USER_IDS.clear()
            out, _ = self._run([FakeResp(code, {})])
            self.assertIn(phrase, out["error"], code)

    def test_missing_token_and_bad_username(self):
        self.assertIn("No Official X API bearer token", xp.fetch_timeline_page("x_official", "CTIuser", "")["error"])
        self.assertIn("Invalid X username", xp.fetch_timeline_page("x_official", "bad name!", "t")["error"])

    def test_unknown_user(self):
        out, _ = self._run([FakeResp(200, {})])
        self.assertIn("not found", out["error"])

    def test_timeout_is_reported(self):
        with mock.patch.object(xp.requests, "get", side_effect=requests.Timeout()):
            out = xp.fetch_timeline_page("x_official", "CTIuser", "t")
        self.assertEqual(out["error"], "X API timeout")


class TestDispatch(unittest.TestCase):
    def test_provider_normalization(self):
        self.assertEqual(xp.normalize_provider(""), "twitterapi")
        self.assertEqual(xp.normalize_provider("X_Official"), "x_official")
        self.assertEqual(xp.normalize_provider("rss"), "")
        self.assertEqual(xp.normalize_provider("playwright"), "")

    def test_requires_key_flags(self):
        self.assertTrue(xp.provider_requires_key("twitterapi"))
        self.assertTrue(xp.provider_requires_key("x_official"))

    def test_twitterapi_delegates(self):
        with mock.patch.object(xp, "query_twitter_user_tweets", return_value={"tweets": [], "pagination": {}}) as q:
            out = xp.fetch_timeline_page("twitterapi", "CTIuser", "k")
        self.assertEqual(out["provider"], "twitterapi")
        q.assert_called_once()

    def test_unknown_provider(self):
        self.assertIn("Unknown X collector", xp.fetch_timeline_page("bogus", "u", "")["error"])


if __name__ == "__main__":
    unittest.main()
