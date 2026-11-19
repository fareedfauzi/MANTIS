"""Regression tests for bugs found in the application-wide audit.

Run from backend/:  python3 -m unittest scripts.test_audit_regressions -v
Offline: no provider keys, no network, isolated temp databases.
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("MANTIS_DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("MANTIS_OPENDIR_WATCH", "0")


class TestSigmaConditionSandbox(unittest.TestCase):
    """BUG-06: Sigma conditions were eval()'d; clearing __builtins__ is not a sandbox."""

    def setUp(self):
        import sigma_engine
        self.se = sigma_engine
        self.results = {"sel1": True, "sel2": False, "sel3": True}

    def test_normal_conditions_still_evaluate(self):
        cases = {
            "sel1": True,
            "sel1 and sel2": False,
            "sel1 or sel2": True,
            "not sel2": True,
            "sel1 and not sel2": True,
            "1 of sel*": True,
            "all of sel1": True,
            "sel1 and (sel2 or sel3)": True,
        }
        for cond, expected in cases.items():
            self.assertEqual(self.se._eval_condition_expr(cond, self.results), expected, cond)

    def test_class_traversal_payload_does_not_execute(self):
        payloads = [
            "().__class__.__bases__[0].__subclasses__()",
            "__import__('os').system('id')",
            "sel1.__class__.__mro__",
            "open('/etc/passwd').read()",
            "lambda: 1",
        ]
        for payload in payloads:
            # Falls back to the "any selection matched" heuristic; must not raise and must not run code.
            self.assertIn(self.se._eval_condition_expr(payload, self.results), (True, False), payload)

    def test_safe_bool_expr_rejects_non_boolean_nodes(self):
        with self.assertRaises(Exception):
            self.se._safe_bool_expr("().__class__")
        with self.assertRaises(Exception):
            self.se._safe_bool_expr("[1,2,3]")
        self.assertTrue(self.se._safe_bool_expr("True and not False"))


class TestAdminPasswordFromEnv(unittest.TestCase):
    """BUG-08: MANTIS_ADMIN_PASSWORD was validated then discarded in server mode."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._saved = {k: os.environ.get(k) for k in ("MANTIS_MODE", "MANTIS_ADMIN_PASSWORD")}
        os.environ["MANTIS_MODE"] = "server"
        os.environ["MANTIS_ADMIN_PASSWORD"] = "AuditPassw0rdx1"
        import importlib
        import auth_service
        self.auth = importlib.reload(auth_service)

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_env_password_is_used_on_server_startup(self):
        self.auth.init_users_db(rotate_admin=True)
        self.assertIsNotNone(self.auth.authenticate_user("admin", "AuditPassw0rdx1"))

    def test_wrong_password_still_rejected(self):
        self.auth.init_users_db(rotate_admin=True)
        self.assertIsNone(self.auth.authenticate_user("admin", "definitely-not-it"))


class TestSessionRevocation(unittest.TestCase):
    """BUG-09: logout and password changes left signed tokens valid for 7 days."""

    def setUp(self):
        import auth_service
        self.auth = auth_service
        self._saved_path = auth_service.USERS_DB_PATH
        self._saved_dir = auth_service.DATA_DIR
        tmp = tempfile.mkdtemp()
        auth_service.DATA_DIR = tmp
        auth_service.USERS_DB_PATH = os.path.join(tmp, "users.db")
        auth_service.init_users_db(rotate_admin=False)
        self.user = auth_service.create_user("revoke_test", "TestPassw0rd1", role="admin")

    def tearDown(self):
        self.auth.USERS_DB_PATH = self._saved_path
        self.auth.DATA_DIR = self._saved_dir

    def test_token_valid_before_logout(self):
        token = self.auth.create_session_token(self.user)
        self.assertIsNotNone(self.auth.verify_session_token(token))
        self.assertEqual(self.auth.verify_session_token(token)["id"], self.user["id"])

    def test_logout_revokes_the_token(self):
        token = self.auth.create_session_token(self.user)
        self.assertIsNotNone(self.auth.verify_session_token(token))
        self.assertTrue(self.auth.revoke_session(token))
        self.assertIsNone(self.auth.verify_session_token(token))

    def test_other_sessions_survive_a_logout(self):
        keep = self.auth.create_session_token(self.user)
        drop = self.auth.create_session_token(self.user)
        self.auth.revoke_session(drop)
        self.assertIsNotNone(self.auth.verify_session_token(keep))
        self.assertIsNone(self.auth.verify_session_token(drop))

    def test_password_change_invalidates_earlier_tokens(self):
        import time
        token = self.auth.create_session_token(self.user)
        time.sleep(1.05)  # token iat resolution is one second
        self.auth.set_user_password(self.user["id"], "NewPassw0rd2")
        self.assertIsNone(self.auth.verify_session_token(token))
        fresh = self.auth.create_session_token(self.user)
        self.assertIsNotNone(self.auth.verify_session_token(fresh))

    def test_garbage_token_is_rejected_without_raising(self):
        for bad in ("", "nope", "a.b", "....", "x" * 500):
            self.assertIsNone(self.auth.verify_session_token(bad), bad)
        self.assertFalse(self.auth.revoke_session("nope"))


class TestSansHttpErrorMapping(unittest.TestCase):
    """BUG-02: _b3_http_error was undefined, so non-200 SANS responses raised NameError."""

    def setUp(self):
        import intel_query
        self.iq = intel_query

    def _fake_response(self, status):
        class R:
            status_code = status
            headers = {}
            def json(self):
                return {}
        return R()

    def test_non_200_returns_error_card_not_nameerror(self):
        original = self.iq.requests.get
        try:
            for status in (403, 429, 500):
                self.iq.requests.get = lambda *a, **k: self._fake_response(status)
                ok, payload = self.iq._sans_get(f"ip/198.51.100.9?json&{status}")
                self.assertFalse(ok, status)
                self.assertIsInstance(payload, dict, status)
                self.assertIn("error", payload, status)
        finally:
            self.iq.requests.get = original


class TestImportableModules(unittest.TestCase):
    """BUG-01 / BUG-03: modules that previously could not be imported at all."""

    def test_sigma_ai_converter_imports(self):
        import sigma_ai_converter
        self.assertTrue(hasattr(sigma_ai_converter, "ai_convert_sigma"))

    def test_workspace_analysis_imports(self):
        import omni_idb.workspace_analysis  # noqa: F401


class TestServerModeAuthGate(unittest.TestCase):
    """BUG-15: server mode answered the whole API anonymously.

    Every route except the sign-in surface must require a session once
    MANTIS_MODE=server; workstation mode must keep working without one.
    """

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        cls._env = os.environ.get("MANTIS_MODE")
        os.environ["MANTIS_MODE"] = "server"
        from fastapi.testclient import TestClient
        import main
        cls.main = main
        cls.client = TestClient(main.app)

    @classmethod
    def tearDownClass(cls):
        if cls._env is None:
            os.environ.pop("MANTIS_MODE", None)
        else:
            os.environ["MANTIS_MODE"] = cls._env

    def test_anonymous_api_call_is_refused(self):
        r = self.client.get("/api/cti/articles")
        self.assertEqual(r.status_code, 401, r.text[:200])

    def test_anonymous_destructive_call_is_refused(self):
        r = self.client.delete("/api/infra-hunts/1")
        self.assertEqual(r.status_code, 401, r.text[:200])

    def test_login_surface_stays_open(self):
        for path in ("/api/meta/startup-progress", "/api/config/deployment"):
            r = self.client.get(path)
            self.assertNotEqual(r.status_code, 401, path)

    def test_workstation_mode_still_serves_without_a_session(self):
        os.environ["MANTIS_MODE"] = "workstation"
        try:
            r = self.client.get("/api/cti/articles")
            self.assertNotEqual(r.status_code, 401, r.text[:200])
        finally:
            os.environ["MANTIS_MODE"] = "server"

    def test_bad_bearer_token_is_refused(self):
        r = self.client.get("/api/cti/articles", headers={"Authorization": "Bearer not-a-token"})
        self.assertEqual(r.status_code, 401)


class TestYaraStatusDoesNotCompile(unittest.TestCase):
    """BUG-11: a status poll compiled the whole corpus (+829 MB)."""

    def test_engine_status_never_builds(self):
        import yara_repos
        # The deferred background build is a separate thread; kill-switch it so
        # this test only observes the synchronous path.
        os.environ["MANTIS_YARA_BG_BUILD"] = "0"
        calls = []
        original = yara_repos.ensure_built

        def _boom(repo_id):
            calls.append(repo_id)
            raise AssertionError("engine_status must not build the index")

        yara_repos.ensure_built = _boom
        try:
            out = yara_repos.engine_status()
        finally:
            yara_repos.ensure_built = original
            os.environ.pop("MANTIS_YARA_BG_BUILD", None)
        self.assertEqual(calls, [])
        self.assertIn("indexing_in_progress", out)


class TestTgSchemaBootstrap(unittest.TestCase):
    """BUG-16: bot routes returned 500 "no such table: tg_bots" on a fresh DB."""

    def test_helpers_create_schema_on_a_fresh_database(self):
        import importlib
        import tempfile
        import tg_intel

        with tempfile.TemporaryDirectory() as tmp:
            original = tg_intel.TG_DB_PATH
            tg_intel.TG_DB_PATH = os.path.join(tmp, "telegram_intel.db")
            tg_intel._READY = False
            try:
                self.assertEqual(tg_intel._job_token("nope"), "")
                self.assertIsNone(tg_intel._get_bot("nope"))
                out = tg_intel.stop_bot("nope", paused=True)
                self.assertIn("stopped", out)
                tg_intel.prune_old_messages(90)
            finally:
                tg_intel.TG_DB_PATH = original
                tg_intel._READY = False


class TestSsoSigninHeadless(unittest.TestCase):
    """BUG-20: browser-based SSO sign-in held the request open for 180s."""

    def test_headless_linux_is_refused_with_a_reason(self):
        import ai_service
        saved = {k: os.environ.pop(k, None) for k in ("DISPLAY", "WAYLAND_DISPLAY")}
        try:
            reason = ai_service.sso_signin_unsupported_reason()
            if sys.platform.startswith(("win", "darwin")):
                self.assertEqual(reason, "")
            else:
                self.assertIn("desktop session", reason)
            os.environ["DISPLAY"] = ":0"
            self.assertEqual(ai_service.sso_signin_unsupported_reason(), "")
        finally:
            for key, value in saved.items():
                os.environ.pop(key, None)
                if value is not None:
                    os.environ[key] = value
            os.environ.pop("DISPLAY", None)


class TestInfrastructurePageFanOut(unittest.TestCase):
    """BUG-21: one serial remote call per group held the page open for >180s."""

    def setUp(self):
        import ransomware_monitor
        self.mod = ransomware_monitor
        self._groups = ransomware_monitor.groups
        self._profile = ransomware_monitor.group_profile
        self.calls = []

    def tearDown(self):
        self.mod.groups = self._groups
        self.mod.group_profile = self._profile
        os.environ.pop("MANTIS_INFRA_PAGE_BUDGET_S", None)

    def _fake_groups(self, count=40):
        self.mod.groups = lambda days, key: (
            [{"name": f"group{i}"} for i in range(count)], [{"provider": "fake", "status": "ok"}])

    def test_unfiltered_page_stops_early(self):
        self._fake_groups(40)

        def _profile(name, key="", days=30):
            self.calls.append(name)
            return {"infrastructure": [{"group": name, "type": "c2", "address": f"1.2.3.{len(self.calls)}"}]}

        self.mod.group_profile = _profile
        out = self.mod.infrastructure_page({"page": 1, "page_size": 5})
        self.assertEqual(out["sources"][0]["provider"], "fake")
        self.assertLessEqual(len(out["infrastructure"]), 5)
        self.assertLess(len(self.calls), 40, "fan-out should stop once the page is full")

    def test_filters_still_consider_every_group(self):
        self._fake_groups(10)
        self.mod.group_profile = lambda name, key="", days=30: {
            "infrastructure": [{"group": name, "type": "c2", "address": "1.2.3.4"}]}
        out = self.mod.infrastructure_page({"q": "group9", "page": 1, "page_size": 50})
        self.assertTrue(all("group9" in (r["group"] or "") for r in out["infrastructure"]))

    def test_slow_provider_is_bounded_by_the_budget(self):
        self._fake_groups(40)

        def _slow(name, key="", days=30):
            time.sleep(0.5)
            return {"infrastructure": [{"group": name, "type": "c2", "address": "1.2.3.4"}]}

        self.mod.group_profile = _slow
        os.environ["MANTIS_INFRA_PAGE_BUDGET_S"] = "6"
        started = time.monotonic()
        out = self.mod.infrastructure_page({"q": "x", "page": 1, "page_size": 50})
        elapsed = time.monotonic() - started
        self.assertIn("infrastructure", out)
        self.assertLess(elapsed, 20, f"endpoint ran {elapsed:.1f}s despite a 6s budget")


class TestSessionCookieSecure(unittest.TestCase):
    """BUG-22: the session cookie was hard-coded Secure=False."""

    def setUp(self):
        self.saved = os.environ.pop("MANTIS_COOKIE_SECURE", None)

    def tearDown(self):
        os.environ.pop("MANTIS_COOKIE_SECURE", None)
        if self.saved is not None:
            os.environ["MANTIS_COOKIE_SECURE"] = self.saved

    def test_env_override_wins(self):
        import main
        os.environ["MANTIS_COOKIE_SECURE"] = "1"
        self.assertTrue(main._cookie_secure(None))
        os.environ["MANTIS_COOKIE_SECURE"] = "0"
        self.assertFalse(main._cookie_secure(None))

    def test_follows_the_request_scheme_by_default(self):
        import main
        os.environ.pop("MANTIS_COOKIE_SECURE", None)

        class Req:
            def __init__(self, scheme, headers=None):
                self.headers = headers or {}
                self.url = type("U", (), {"scheme": scheme})()

        self.assertFalse(main._cookie_secure(Req("http")))
        self.assertTrue(main._cookie_secure(Req("https")))
        self.assertTrue(main._cookie_secure(Req("http", {"x-forwarded-proto": "https"})))
        self.assertFalse(main._cookie_secure(Req("https", {"x-forwarded-proto": "http"})))


class TestEncryptionKeySplit(unittest.TestCase):
    """BUG-23: SECRET_KEY was both the session HMAC key and the AES-GCM key."""

    def setUp(self):
        self.saved = os.environ.pop("MANTIS_ENCRYPTION_KEY", None)

    def tearDown(self):
        os.environ.pop("MANTIS_ENCRYPTION_KEY", None)
        if self.saved is not None:
            os.environ["MANTIS_ENCRYPTION_KEY"] = self.saved

    def test_round_trip_with_a_dedicated_key(self):
        import auth_service
        os.environ["MANTIS_ENCRYPTION_KEY"] = "a" * 64
        blob, nonce = auth_service._encrypt_key("super-secret-token")
        self.assertNotIn("super-secret-token", blob)
        self.assertEqual(auth_service._decrypt_key(blob, nonce), "super-secret-token")

    def test_keys_written_before_the_split_still_decrypt(self):
        import auth_service
        os.environ.pop("MANTIS_ENCRYPTION_KEY", None)
        legacy_blob, legacy_nonce = auth_service._encrypt_key("old-key")
        os.environ["MANTIS_ENCRYPTION_KEY"] = "b" * 64
        self.assertEqual(auth_service._decrypt_key(legacy_blob, legacy_nonce), "old-key")

    def test_duplicate_candidates_are_collapsed(self):
        import auth_service
        os.environ["MANTIS_ENCRYPTION_KEY"] = auth_service.SECRET_KEY.hex()
        self.assertEqual(len(auth_service._encryption_keys()), 1)


class TestNoDeadFrontendRoutes(unittest.TestCase):
    """BUG-24: the Telegram UI called two endpoints that never existed."""

    def test_tg_frontend_no_longer_calls_missing_routes(self):
        frontend = Path(__file__).resolve().parents[2] / "frontend"
        app_js = (frontend / "app.js").read_text(encoding="utf-8", errors="replace")
        self.assertNotIn("/api/tg/export/", app_js)
        self.assertNotIn("/api/tg/investigations/seed-artifact", app_js)

    def test_startup_loader_does_not_cover_the_app(self):
        css = (Path(__file__).resolve().parents[2] / "frontend" / "startup-loader.css").read_text(encoding="utf-8")
        block = css.split(".startup-loader {", 1)[1].split("}", 1)[0]
        self.assertIn("pointer-events: none", block)
        self.assertNotIn("inset: 0", block)


class TestOutboundTimeoutDefault(unittest.TestCase):
    """BUG-25: provider calls without `timeout=` could pin a worker thread forever."""

    def setUp(self):
        import http_defaults
        self.mod = http_defaults
        self.saved = {k: os.environ.pop(k, None) for k in ("MANTIS_HTTP_DEFAULTS", "MANTIS_HTTP_TIMEOUT")}
        self.mod.uninstall()

    def tearDown(self):
        self.mod.uninstall()
        for key, value in self.saved.items():
            os.environ.pop(key, None)
            if value is not None:
                os.environ[key] = value

    def _record_send(self):
        """Install the patch, then capture what it forwards to the real send."""
        import requests
        self.assertTrue(self.mod.install())
        seen = {}
        original = self.mod._ORIGINAL_SEND
        self.mod._ORIGINAL_SEND = lambda sess, req, **kw: seen.update(kw) or "sent"
        return requests, seen

    def test_default_is_injected_when_the_caller_gives_none(self):
        requests, seen = self._record_send()
        requests.Session().send(requests.Request("GET", "http://example.invalid").prepare())
        self.assertEqual(seen.get("timeout"), self.mod.default_timeout())

    def test_explicit_timeout_is_never_overridden(self):
        requests, seen = self._record_send()
        requests.Session().send(
            requests.Request("GET", "http://example.invalid").prepare(), timeout=3)
        self.assertEqual(seen.get("timeout"), 3)

    def test_env_sets_connect_and_read(self):
        os.environ["MANTIS_HTTP_TIMEOUT"] = "4,9"
        self.assertEqual(self.mod.default_timeout(), (4.0, 9.0))
        os.environ["MANTIS_HTTP_TIMEOUT"] = "7"
        self.assertEqual(self.mod.default_timeout(), (7.0, 7.0))

    def test_kill_switch(self):
        os.environ["MANTIS_HTTP_DEFAULTS"] = "0"
        self.assertFalse(self.mod.install())


class TestCryptoPageFanOut(TestInfrastructurePageFanOut.__bases__[0]):
    """BUG-26: the crypto page made up to 100 remote detail calls serially."""

    def setUp(self):
        import ransomware_monitor
        self.mod = ransomware_monitor
        self._ransomlook = ransomware_monitor._ransomlook
        self.calls = []

    def tearDown(self):
        self.mod._ransomlook = self._ransomlook
        os.environ.pop("MANTIS_CRYPTO_PAGE_BUDGET_S", None)

    def test_slow_upstream_is_bounded_by_the_budget(self):
        def _ransomlook(path, params=None, ttl=600):
            # NB: the list endpoint is "/crypto/" itself, which startswith() would
            # also match - compare exactly or every call looks like a detail call.
            if path.strip("/") != "crypto" and path.startswith("/crypto/"):
                self.calls.append(path)
                time.sleep(0.4)
                return {"by_chain": {"btc": [{"address": "bc1x", "tx_count": 1}]}}
            return [{"name": f"g{i}"} for i in range(40)]

        self.mod._ransomlook = _ransomlook
        os.environ["MANTIS_CRYPTO_PAGE_BUDGET_S"] = "4"
        started = time.monotonic()
        out = self.mod.crypto_page({})
        elapsed = time.monotonic() - started
        self.assertIn("crypto_addresses", out)
        self.assertLess(elapsed, 20, f"crypto page ran {elapsed:.1f}s despite a 4s budget")
        self.assertGreater(len(self.calls), 1, "detail requests should run in parallel")

    def test_rows_keep_their_shape(self):
        def _ransomlook(path, params=None, ttl=600):
            if path.strip("/") != "crypto" and path.startswith("/crypto/"):
                return {"by_chain": {"btc": [{"address": "bc1x", "tx_count": 3}]}}
            return [{"name": "lockbit"}]

        self.mod._ransomlook = _ransomlook
        out = self.mod.crypto_page({})
        self.assertEqual(out["crypto_addresses"][0]["currency"], "btc")
        self.assertEqual(out["crypto_addresses"][0]["group"], "lockbit")


class TestCtiSchemaMigration(unittest.TestCase):
    """BUG-27: a database created before a column was added to SCHEMA never got
    it, because CREATE TABLE IF NOT EXISTS leaves existing tables alone. The
    result was a hard 500 from GET /api/cti/articles on every older install."""

    def setUp(self):
        import cti_db
        self.mod = cti_db

    def _old_database(self):
        import sqlite3
        path = os.path.join(tempfile.mkdtemp(), "cti_articles.db")
        conn = sqlite3.connect(path)
        conn.executescript(
            """
            CREATE TABLE articles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL DEFAULT '',
                url TEXT NOT NULL DEFAULT '',
                published_at TEXT DEFAULT '',
                content_text TEXT NOT NULL DEFAULT ''
            );
            """
        )
        conn.execute("INSERT INTO articles (title, url) VALUES ('kept', 'https://x/1')")
        conn.commit()
        conn.close()
        return path

    def test_missing_column_is_added_and_rows_kept(self):
        import sqlite3
        path = self._old_database()
        self.mod.init_db(path)
        conn = sqlite3.connect(path)
        columns = [r[1] for r in conn.execute("PRAGMA table_info(articles)")]
        self.assertIn("image_url", columns)
        # The exact projection that used to raise "no such column: a.image_url".
        rows = conn.execute("SELECT a.title, a.image_url FROM articles a").fetchall()
        self.assertEqual(rows, [("kept", "")])

    def test_migration_is_idempotent(self):
        import sqlite3
        path = self._old_database()
        self.mod.init_db(path)
        conn = sqlite3.connect(path)
        self.assertEqual(self.mod.ensure_columns(conn), [])
        self.assertEqual(self.mod.ensure_columns(conn), [])

    def test_expected_columns_covers_every_table_in_schema(self):
        columns = self.mod.expected_columns()
        for table in ("sources", "articles", "article_indicators", "cti_categories"):
            self.assertIn(table, columns)
        names = [name for name, _ in columns["articles"]]
        self.assertEqual(names[0], "id")
        self.assertIn("image_url", names)
        # No constraint lines may be mistaken for columns.
        for table, cols in columns.items():
            for name, _decl in cols:
                self.assertNotIn(name.upper(), ("UNIQUE", "PRIMARY", "FOREIGN", "CHECK", "CONSTRAINT"), table)

    def test_fresh_database_is_unaffected(self):
        import sqlite3
        path = os.path.join(tempfile.mkdtemp(), "fresh.db")
        self.mod.init_db(path)
        conn = sqlite3.connect(path)
        columns = [r[1] for r in conn.execute("PRAGMA table_info(articles)")]
        self.assertIn("image_url", columns)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0], 0)


class TestStoredProviderKeysReachQueries(unittest.TestCase):
    """BUG-28: a key typed into Settings was stored under the input's id
    ("vt"), but the query layer looked up "virustotal", so the key was saved
    and then never used. Four request fields had no mapping at all."""

    def setUp(self):
        import main
        self.main = main

    def test_every_request_key_field_has_a_mapping(self):
        fields = {name for name in self.main.IntelRequest.model_fields if name.endswith("_key")}
        missing = fields - set(self.main.INTEL_KEY_FIELDS)
        self.assertEqual(missing, set(), f"stored keys never reach these fields: {sorted(missing)}")

    def test_ui_short_ids_are_aliased(self):
        stored = {"vt": "k1", "ha": "k2", "cb": "k3", "rwlive": "k4",
                  "x_official": "k5", "misp_key": "k6", "tip": "k7", "abusech": "k8"}
        cases = {"virustotal": "k1", "hybrid_analysis": "k2", "cybercure": "k3",
                 "ransomware_live": "k4", "twitter": "k5", "misp": "k6",
                 "tip": "k7", "abusech": "k8"}
        for provider, expected in cases.items():
            self.assertEqual(self.main._stored_key(stored, provider), expected, provider)

    def test_canonical_id_still_wins_and_missing_is_empty(self):
        stored = {"virustotal": "long", "vt": "short"}
        self.assertEqual(self.main._stored_key(stored, "virustotal"), "long")
        self.assertEqual(self.main._stored_key({}, "virustotal"), "")

    def test_populate_fills_fields_from_aliases(self):
        req = self.main.IntelRequest(indicator="8.8.8.8")
        original = self.main.auth_service.get_all_user_api_keys
        self.main.auth_service.get_all_user_api_keys = lambda *a, **k: {
            "vt": "UI-VT", "tip": "UI-TIP", "abusech": "UI-AB", "ransomlook": "UI-RL"}
        try:
            filled = self.main._populate_user_keys(req, "user")
        finally:
            self.main.auth_service.get_all_user_api_keys = original
        self.assertEqual(filled.vt_key, "UI-VT")
        self.assertEqual(filled.tip_key, "UI-TIP")
        self.assertEqual(filled.abusech_key, "UI-AB")
        self.assertEqual(filled.ransomlook_key, "UI-RL")

    def test_explicit_request_value_is_not_overwritten(self):
        req = self.main.IntelRequest(indicator="8.8.8.8", vt_key="EXPLICIT")
        original = self.main.auth_service.get_all_user_api_keys
        self.main.auth_service.get_all_user_api_keys = lambda *a, **k: {"virustotal": "STORED"}
        try:
            filled = self.main._populate_user_keys(req, "user")
        finally:
            self.main.auth_service.get_all_user_api_keys = original
        self.assertEqual(filled.vt_key, "EXPLICIT")


if __name__ == "__main__":
    unittest.main()
