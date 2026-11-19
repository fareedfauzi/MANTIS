"""Threat Hunting Workbench: request/response contract and evidence appending.

BUG-33: the workbench frontend called investigation-scoped ingest routes and
sent payloads the API never accepted, so the first upload failed with
"Method Not Allowed" and every later step would have failed too. These tests
pin both sides of the contract.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
FRONTEND_DIR = BACKEND_DIR.parent / "frontend"
sys.path.insert(0, str(BACKEND_DIR))

_TMP_DB = tempfile.mkdtemp(prefix="mantis-th-test-")
os.environ["MANTIS_THREAT_HUNTING_DB"] = os.path.join(_TMP_DB, "threat_hunting.db")
os.environ.setdefault("MANTIS_MODE", "server")

import threat_hunting_db as th_db  # noqa: E402


def _new_investigation(content: str = "", source_type: str = "text") -> dict:
    return th_db.create_investigation(
        title="GreyGoblin report",
        source_type=source_type,
        raw_content=content,
        description="test",
    )


class TestAppendInvestigationContent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        th_db.init_db()

    def test_append_extends_content_instead_of_replacing(self):
        inv = _new_investigation("first source body")
        updated = th_db.append_investigation_content(
            inv["id"], "second source body", "file", {"filename": "a.pdf"}
        )
        self.assertIn("first source body", updated["raw_content"])
        self.assertIn("second source body", updated["raw_content"])
        self.assertIn("second source body", updated["normalized_content"])

    def test_source_type_becomes_multi_and_sources_are_recorded(self):
        inv = _new_investigation("body one", source_type="url")
        first = th_db.append_investigation_content(inv["id"], "body two", "file", {"filename": "b.pdf"})
        sources = first["source_metadata"]["sources"]
        self.assertEqual(first["source_type"], "multi")
        self.assertEqual(len(sources), 1)
        self.assertEqual(sources[0]["filename"], "b.pdf")
        self.assertEqual(sources[0]["source_type"], "file")
        self.assertEqual(sources[0]["chars"], len("body two"))

        second = th_db.append_investigation_content(inv["id"], "body three", "text", {"source_name": "Notes"})
        self.assertEqual(len(second["source_metadata"]["sources"]), 2)

    def test_single_source_keeps_its_type(self):
        inv = _new_investigation("", source_type="text")
        updated = th_db.append_investigation_content(inv["id"], "uploaded pdf text", "file", {})
        self.assertEqual(updated["source_type"], "file")

    def test_unknown_investigation_returns_none(self):
        self.assertIsNone(th_db.append_investigation_content("th-inv-missing", "text", "text", {}))

    def test_appending_does_not_corrupt_unicode_or_newlines(self):
        inv = _new_investigation("Ünïcode — 報告")
        updated = th_db.append_investigation_content(inv["id"], "second\nline", "text", {})
        self.assertIn("Ünïcode", updated["raw_content"])
        self.assertIn("second\nline", updated["raw_content"])


class TestFrontendApiContract(unittest.TestCase):
    """Every call the workbench makes must exist on the API with that method."""

    @classmethod
    def setUpClass(cls):
        import main as mantis_main  # noqa: E402

        cls.routes = set()
        for route in mantis_main.app.routes:
            path = getattr(route, "path", "")
            for method in getattr(route, "methods", set()) or set():
                cls.routes.add((method.upper(), path))

    def _calls(self):
        source = (FRONTEND_DIR / "threat-hunting.js").read_text(encoding="utf-8")
        pattern = re.compile(
            r"fetch\(\s*[`'\"](?P<path>/api/threat-hunting[^`'\"]*)[`'\"]\s*(?:,\s*\{(?P<opts>[^}]*))?",
            re.S,
        )
        for m in pattern.finditer(source):
            path = re.sub(r"\$\{[^}]*\}", "{param}", m.group("path").split("?")[0])
            opts = m.group("opts") or ""
            method = "GET"
            mm = re.search(r"method:\s*['\"]([A-Z]+)['\"]", opts)
            if mm:
                method = mm.group(1)
            yield method, path

    @staticmethod
    def _shape(path: str) -> str:
        """Collapse path parameters so {inv_id} and {param} compare equal."""
        return re.sub(r"\{[^/]*\}", "{}", path.split("?")[0].rstrip("/"))

    def test_every_frontend_call_matches_a_route(self):
        index = {(method, self._shape(path)) for method, path in self.routes}
        calls = list(self._calls())
        self.assertGreaterEqual(len(calls), 10, "frontend call extraction failed")
        missing = [f"{m} {p}" for m, p in calls if (m, self._shape(p)) not in index]
        self.assertEqual(missing, [], f"frontend calls with no matching API route: {missing}")

    def test_ingest_routes_are_investigation_scoped(self):
        expected = {
            "/api/threat-hunting/investigations/{inv_id}/ingest/file",
            "/api/threat-hunting/investigations/{inv_id}/ingest/url",
            "/api/threat-hunting/investigations/{inv_id}/ingest/text",
        }
        for path in expected:
            self.assertIn(("POST", path), self.routes, f"missing route {path}")


class TestAiKeyAliases(unittest.TestCase):
    def test_provider_aliases_resolve(self):
        import main as mantis_main  # noqa: E402

        req = mantis_main.ThreatHuntAnalyzeRequest(ai_provider="deepseek", ai_model="deepseek-chat")
        self.assertEqual(req.resolved(), ("deepseek", "deepseek-chat"))
        req2 = mantis_main.ThreatHuntAnalyzeRequest(provider="openai", model="gpt-4o")
        self.assertEqual(req2.resolved(), ("openai", "gpt-4o"))
        self.assertEqual(mantis_main.ThreatHuntAnalyzeRequest().resolved(), (None, None))

    def test_hypotheses_request_does_not_require_findings(self):
        import main as mantis_main  # noqa: E402

        req = mantis_main.ThreatHuntHypothesesRequest(ai_provider="deepseek")
        self.assertIsNone(req.findings)

    def test_generate_request_accepts_a_hypothesis_id(self):
        import main as mantis_main  # noqa: E402

        req = mantis_main.ThreatHuntGenerateQueryRequest(
            hypothesis_id="hyp-1", platform="splunk", schema_target='{"index": "main"}'
        )
        self.assertIsNone(req.hypothesis)
        self.assertEqual(req.hypothesis_id, "hyp-1")
        self.assertEqual(req.platform, "splunk")


if __name__ == "__main__":
    unittest.main()


class TestAiBudgetAndSilentFailures(unittest.TestCase):
    """BUG-34: a reasoning model spent the whole output budget on reasoning tokens
    and returned empty content; the workbench reported that as a successful
    analysis with zero findings."""

    def test_empty_content_at_length_limit_raises_instead_of_returning_blank(self):
        from unittest import mock
        from ai_service import AIProvider, AIProviderError

        fake = mock.Mock()
        fake.status_code = 200
        fake.raise_for_status = lambda: None
        fake.json.return_value = {
            "choices": [{"finish_reason": "length", "message": {"content": ""}}],
            "usage": {"completion_tokens_details": {"reasoning_tokens": 2200}},
        }
        provider = AIProvider({
            "provider": "deepseek", "model": "deepseek-flash",
            "endpoint": "https://api.deepseek.com/chat/completions", "api_key": "k",
            "max_output_tokens": 2200, "timeout_seconds": 30,
        })
        with mock.patch("ai_service.requests.post", return_value=fake):
            with self.assertRaises(AIProviderError) as ctx:
                provider.generate([{"role": "user", "content": "hi"}])
        message = str(ctx.exception)
        self.assertIn("2200", message)
        self.assertIn("reasoning tokens", message)

    def test_empty_content_with_stop_is_still_returned(self):
        from unittest import mock
        from ai_service import AIProvider

        fake = mock.Mock()
        fake.status_code = 200
        fake.raise_for_status = lambda: None
        fake.json.return_value = {"choices": [{"finish_reason": "stop", "message": {"content": "{}"}}]}
        provider = AIProvider({
            "provider": "deepseek", "model": "m", "endpoint": "https://example.invalid/x",
            "api_key": "k", "max_output_tokens": 100, "timeout_seconds": 5,
        })
        with mock.patch("ai_service.requests.post", return_value=fake):
            self.assertEqual(provider.generate([{"role": "user", "content": "hi"}]), "{}")

    def test_analysis_raises_when_every_chunk_fails(self):
        from unittest import mock
        import threat_hunting_engine as engine

        with mock.patch.object(engine, "_settings_available", return_value=True), \
             mock.patch.object(engine, "get_raw_ai_settings", return_value={
                 "provider": "deepseek", "model": "m", "endpoint": "https://x.invalid",
                 "api_key": "k", "max_output_tokens": 100, "timeout_seconds": 5}), \
             mock.patch.object(engine, "AIProvider") as ai_cls:
            ai_cls.return_value.generate.return_value = ""
            with self.assertRaises(engine.AIProviderError) as ctx:
                engine.analyze_report_content("ChronicleClient executed powershell -enc SQBFAFgA on host1")
        self.assertIn("returned no analysis", str(ctx.exception))

    def test_analysis_budget_and_timeout_are_raised_before_the_call(self):
        from unittest import mock
        import threat_hunting_engine as engine

        seen = {}

        class FakeAI:
            last_finish_reason = "stop"

            def __init__(self, settings):
                seen.update(settings)

            def generate(self, messages):
                return '{"summary": "ok", "findings": [{"title": "T", "attack_id": "T1059"}]}'

        with mock.patch.object(engine, "_settings_available", return_value=True), \
             mock.patch.object(engine, "get_raw_ai_settings", return_value={
                 "provider": "deepseek", "model": "m", "endpoint": "https://x.invalid",
                 "api_key": "k", "max_output_tokens": 2200, "timeout_seconds": 30}), \
             mock.patch.object(engine, "AIProvider", FakeAI):
            result = engine.analyze_report_content("Report body with T1059.001 PowerShell")
        self.assertGreaterEqual(seen["max_output_tokens"], engine.ANALYZE_MIN_OUTPUT_TOKENS)
        self.assertGreaterEqual(seen["timeout_seconds"], engine.JSON_OUTPUT_TIMEOUT_SECONDS)
        self.assertEqual(len(result["findings"]), 1)

    def test_hypotheses_report_empty_model_reply_instead_of_silence(self):
        from unittest import mock
        import threat_hunting_engine as engine

        class FakeAI:
            last_finish_reason = "length"

            def __init__(self, settings):
                pass

            def generate(self, messages):
                return ""

        with mock.patch.object(engine, "_settings_available", return_value=True), \
             mock.patch.object(engine, "get_raw_ai_settings", return_value={
                 "provider": "deepseek", "model": "m", "endpoint": "https://x.invalid",
                 "api_key": "k", "max_output_tokens": 100, "timeout_seconds": 5}), \
             mock.patch.object(engine, "AIProvider", FakeAI):
            with self.assertRaises(engine.AIProviderError) as ctx:
                engine.generate_hunting_hypotheses(findings=[{"title": "Encoded PowerShell"}])
        self.assertIn("no hypotheses", str(ctx.exception))
