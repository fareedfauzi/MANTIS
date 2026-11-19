"""Offline tests for the Open Directory Hunting engine.

Run:  cd backend && python3 -m unittest scripts.test_opendir_hunt -v
The end-to-end crawl uses a local http.server on 127.0.0.1 with the test-only
allow_private seam; production code paths keep private addresses blocked.
"""
import datetime as dt
import http.server
import os
import socketserver
import sys
import tempfile
import threading
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND)
_TMP = tempfile.mkdtemp(prefix="opendir-test-")
os.environ["MANTIS_OPENDIR_DB"] = os.path.join(_TMP, "opendir.db")
os.environ.setdefault("MANTIS_OPENDIR_WATCH", "0")

import opendir_hunt as od  # noqa: E402

APACHE_PAGE = """<html><head><title>Index of /pub</title></head><body><h1>Index of /pub</h1>
<table><tr><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th></tr>
<tr><td><a href="/">Parent Directory</a></td></tr>
<tr><td><a href="loader.exe">loader.exe</a></td><td>2024-03-02 11:05</td><td>900K</td></tr>
<tr><td><a href="config.json">config.json</a></td><td>2024-03-02 11:00</td><td>4.2M</td></tr>
<tr><td><a href="sub/">sub/</a></td><td>2024-03-02 12:00</td><td>-</td></tr>
</table></body></html>"""

ARTICLE = "<html><title>Index of articles</title><body><p>Index of things we wrote about security.</p></body></html>"


class TestUrlSafety(unittest.TestCase):
    def test_normalizes_case_port_and_dot_segments(self):
        info = od.normalize_url("HTTP://Example.COM:80/a/../b/./c")
        self.assertEqual(info["url"], "http://example.com/b/c")

    def test_rejects_bad_schemes_and_credentials(self):
        for bad in ["file:///etc/passwd", "ftp://x/", "gopher://x/", "http://user:pw@x/", "http:///nohost"]:
            with self.assertRaises(od.UnsafeTarget, msg=bad):
                od.normalize_url(bad)

    def test_blocks_loopback_private_metadata_and_link_local(self):
        for host in ["127.0.0.1", "10.1.2.3", "192.168.0.5", "169.254.169.254", "0.0.0.0", "[::1]", "localhost"]:
            with self.assertRaises(od.UnsafeTarget, msg=host):
                od.resolve_destination(host.strip("[]"), 80)

    def test_public_literal_allowed(self):
        self.assertEqual(od.resolve_destination("93.184.216.34", 80), ["93.184.216.34"])


class TestDetection(unittest.TestCase):
    def test_apache_listing_detected_and_parsed(self):
        det = od.detect_listing(APACHE_PAGE, 200, "Apache/2.4")
        self.assertTrue(det["is_listing"])
        self.assertGreaterEqual(det["confidence"], 50)
        self.assertEqual(det["listing_type"], "apache")
        entries = od.parse_entries(APACHE_PAGE, "http://h.example/pub/")
        names = {e["name"]: e for e in entries}
        self.assertEqual(set(names), {"loader.exe", "config.json", "sub"})
        self.assertTrue(names["sub"]["is_dir"])
        self.assertEqual(names["loader.exe"]["size"], 900 * 1024)
        self.assertEqual(names["config.json"]["size"], int(4.2 * 1024 * 1024))
        self.assertEqual(names["loader.exe"]["modified_at"], "2024-03-02T11:05:00Z")

    def test_python_http_server_listing_detected(self):
        page = (
            '<!DOCTYPE HTML><html><head><title>Directory listing for /pub/</title></head>'
            '<body><h1>Directory listing for /pub/</h1><hr><ul>'
            '<li><a href="config.json">config.json</a></li>'
            '<li><a href="loader.exe">loader.exe</a></li>'
            '<li><a href="sub/">sub/</a></li></ul><hr></body></html>')
        det = od.detect_listing(page, 200, "SimpleHTTP/0.6 Python/3.12")
        self.assertTrue(det["is_listing"])
        self.assertEqual(det["listing_type"], "python-http-server")
        names = [e["name"] for e in od.parse_entries(page, "http://h.example/pub/")]
        self.assertEqual(names, ["config.json", "loader.exe", "sub"])

    def test_prose_mentioning_directory_listing_not_a_listing(self):
        page = '<html><title>Blog</title><h1>Directory listing for our product</h1><p>no links</p></html>'
        self.assertFalse(od.detect_listing(page, 200)["is_listing"])

    def test_article_mentioning_index_of_is_not_a_listing(self):
        self.assertFalse(od.detect_listing(ARTICLE, 200)["is_listing"])

    def test_non_200_never_listing(self):
        self.assertFalse(od.detect_listing(APACHE_PAGE, 404)["is_listing"])

    def test_external_and_sort_links_skipped(self):
        page = '<a href="https://other.example/x">x</a><a href="?C=N;O=A">n</a><a href="../">up</a><a href="a.zip">a.zip</a>'
        names = [e["name"] for e in od.parse_entries(page, "http://h.example/d/")]
        self.assertEqual(names, ["a.zip"])

    def test_size_ignores_year_in_timestamp(self):
        self.assertIsNone(od.parse_size("2024-03-02 11:00 -"))
        self.assertEqual(od.parse_size("2024-03-02 11:00 12,345"), 12345)


class TestScoring(unittest.TestCase):
    def test_explainable_reasons_and_threshold(self):
        files = [{"name": "loader.exe", "is_dir": False}, {"name": "run.ps1", "is_dir": False},
                 {"name": "c.json", "is_dir": False}]
        s = od.score_directory(files, "tools")
        rules = {r["rule"] for r in s["reasons"]}
        self.assertIn("suspicious_filename", rules)
        self.assertIn("executable_and_script", rules)
        self.assertIn("executable_and_config", rules)
        self.assertEqual(s["score"], sum(r["points"] for r in s["reasons"]))
        self.assertEqual(s["classification"], "medium")

    def test_score_capped_and_high(self):
        files = [{"name": "stealer.exe", "is_dir": False, "modified_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
                 {"name": "payload.ps1", "is_dir": False}, {"name": "loader.dll", "is_dir": False},
                 {"name": "backup.zip", "is_dir": False}, {"name": "x.json", "is_dir": False}]
        s = od.score_directory(files, "stealer_drop")
        self.assertLessEqual(s["score"], 100)
        self.assertEqual(s["classification"], "high")

    def test_directories_are_not_counted_as_files(self):
        s = od.score_directory([{"name": "loader.exe", "is_dir": True}], "x")
        self.assertEqual(s["counts"]["files"], 0)
        self.assertEqual(s["score"], 0)


class TestProviders(unittest.TestCase):
    def test_fofa_and_shodan_syntax(self):
        self.assertEqual(od._fofa_expr("title_index_of"), 'title="Index of /"')
        self.assertIn('&&', od._fofa_expr("body_name_and_modified"))
        self.assertEqual(od._shodan_expr("title_index_of"), 'http.title:"Index of /"')
        self.assertIn('http.html:"Parent Directory"', od._shodan_expr("body_parent_directory"))

    def test_censys_syntax_uses_v3_fields(self):
        self.assertEqual(od._censys_expr("title_index_of"), 'services.http.response.html_title: "Index of /"')

    def test_zoomeye_refuses_boolean_combo_rather_than_guess(self):
        self.assertIsNone(od._zoomeye_expr("body_name_and_modified"))
        with self.assertRaises(od.ProviderError) as ctx:
            od.ZoomEyeAdapter(api_key="k").translate_query("body_name_and_modified")
        self.assertEqual(ctx.exception.kind, "unsupported_query")

    def test_missing_key_is_reported_not_raised(self):
        for k in ("FOFA_API_KEY", "MANTIS_FOFA_KEY", "IOCINTEL_FOFA_KEY", "FOFA_KEY"):
            os.environ.pop(k, None)
        out = od.run_provider_search("fofa", "title_index_of", api_key="")
        self.assertFalse(out["ok"])
        self.assertEqual(out["error_kind"], "missing_key")

    def test_censys_requires_org_id(self):
        os.environ.pop("CENSYS_ORG_ID", None)
        os.environ.pop("CENSYS_ORGANIZATION_ID", None)
        out = od.run_provider_search("censys", "title_index_of", api_key="pat")
        self.assertEqual(out["error_kind"], "missing_config")

    def test_provider_status_never_returns_key(self):
        st = od.provider_status({"shodan": "SECRET-VALUE-123"})
        self.assertTrue(any(p["provider"] == "shodan" and p["configured"] for p in st))
        self.assertNotIn("SECRET-VALUE-123", repr(st))


class TestGlobalDiscoveryPatterns(unittest.TestCase):
    """BUG-32: a global hunt with no query sent an empty provider query, so
    Shodan answered HTTP 400 "Empty search query" and the job found nothing,
    although the UI promises built-in open-directory patterns."""

    def test_global_without_query_expands_to_builtin_patterns(self):
        self.assertEqual(od._discovery_patterns("global", ""), list(od.GLOBAL_PATTERNS))
        self.assertEqual(od._discovery_patterns("global", "   "), list(od.GLOBAL_PATTERNS))

    def test_explicit_query_is_used_verbatim(self):
        self.assertEqual(od._discovery_patterns("global", "http.title:\"hacked\""), ['http.title:"hacked"'])

    def test_every_global_pattern_is_a_known_neutral_pattern(self):
        self.assertTrue(od.GLOBAL_PATTERNS)
        for pattern in od.GLOBAL_PATTERNS:
            self.assertIn(pattern, od.NEUTRAL_PATTERNS)
            self.assertTrue(od._fofa_expr(pattern))
            self.assertTrue(od._shodan_expr(pattern))
            self.assertTrue(od._censys_expr(pattern))

    def test_shodan_rejects_an_empty_expression_before_the_request(self):
        with self.assertRaises(od.ProviderError) as ctx:
            od.ShodanAdapter(api_key="k").search("")
        self.assertEqual(ctx.exception.kind, "invalid_query")

    def test_provider_error_body_is_surfaced(self):
        class Resp:
            status_code = 400
            text = '{"error": "Empty search query"}'

            def json(self):
                return {"error": "Empty search query"}

        detail = od._error_detail(Resp())
        self.assertIn("Empty search query", detail)

        class Plain:
            status_code = 500
            text = "upstream exploded\nsecond line"

            def json(self):
                raise ValueError("not json")

        self.assertIn("upstream exploded", od._error_detail(Plain()))
        self.assertNotIn("\n", od._error_detail(Plain()))


class _Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


class _Server:
    """Tiny listing server with a known tree, plus a redirect to a private address."""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="opendir-srv-")
        os.makedirs(os.path.join(self.root, "pub", "sub", "deeper"))
        with open(os.path.join(self.root, "pub", "loader.exe"), "wb") as f:
            f.write(b"MZ")
        with open(os.path.join(self.root, "pub", "readme.txt"), "w") as f:
            f.write("hi")
        with open(os.path.join(self.root, "pub", "sub", "stealer.ps1"), "w") as f:
            f.write("x")
        with open(os.path.join(self.root, "pub", "sub", "deeper", "deep.bat"), "w") as f:
            f.write("x")
        handler = lambda *a, **k: _Handler(*a, directory=self.root, **k)  # noqa: E731
        socketserver.TCPServer.allow_reuse_address = True
        self.httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def url(self, path="/"):
        return f"http://127.0.0.1:{self.port}{path}"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = _Server()
        od.init_db()

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop()

    def opts(self, **kw):
        base = {"allow_private": True, "min_host_interval": 0, "timeout": 5}
        base.update(kw)
        return base

    def test_crawl_respects_depth_and_finds_nested_files(self):
        res = od.crawl(self.srv.url("/pub/"), self.opts(max_depth=1))
        self.assertEqual(res.root["status"], od.STATUS_VERIFIED)
        urls = {f["url"] for f in res.files}
        self.assertTrue(any(u.endswith("/pub/loader.exe") for u in urls))
        self.assertTrue(any(u.endswith("/pub/sub/stealer.ps1") for u in urls))
        # depth 1 means deeper/ (depth 2) is not enumerated
        self.assertFalse(any(u.endswith("deep.bat") for u in urls))

    def test_crawl_depth_two_reaches_deeper_files(self):
        res = od.crawl(self.srv.url("/pub/"), self.opts(max_depth=2))
        self.assertTrue(any(f["url"].endswith("deep.bat") for f in res.files))

    def test_file_cap_is_enforced(self):
        res = od.crawl(self.srv.url("/pub/"), self.opts(max_depth=2, max_files_per_dir=1))
        per_dir = {}
        for f in res.files:
            per_dir[f["parent_url"]] = per_dir.get(f["parent_url"], 0) + 1
        self.assertTrue(all(v <= 1 for v in per_dir.values()))

    def test_stored_directory_failing_reverification_is_recorded_not_crashed(self):
        # Regression: persisting a failed re-check of an already-stored directory used to set
        # last_seen to NULL (NOT NULL column) and fail the whole hunting job.
        root = self.srv.url("/pub/")
        res = od.crawl(root, self.opts(max_depth=0))
        conn = od.db()
        try:
            src = {"provider": "user", "query": root, "source_kind": "targeted"}
            od.persist_crawl(conn, root, res, source=src)
            conn.commit()
            before = conn.execute("SELECT id, last_seen FROM opendir_directories WHERE url=?", (od.dir_url(root),)).fetchone()
            failed = od.crawl(root, {"allow_private": False, "min_host_interval": 0})  # now rejected
            self.assertEqual(failed.root["status"], "rejected")
            od.persist_crawl(conn, root, failed, source=src)
            conn.commit()
            after = conn.execute("SELECT status, last_seen, error FROM opendir_directories WHERE id=?", (before["id"],)).fetchone()
            self.assertEqual(after["status"], "rejected")
            self.assertEqual(after["last_seen"], before["last_seen"])  # a failed check does not advance last_seen
            self.assertTrue(after["error"])
        finally:
            conn.close()

    def test_non_listing_root_is_rejected(self):
        res = od.crawl(self.srv.url("/nope/"), self.opts())
        self.assertIn(res.root["status"], (od.STATUS_INACCESSIBLE, od.STATUS_REJECTED))
        self.assertEqual(res.files, [])

    def test_private_address_refused_without_test_seam(self):
        res = od.crawl(self.srv.url("/pub/"), {"allow_private": False, "min_host_interval": 0})
        self.assertEqual(res.root["status"], od.STATUS_REJECTED)
        self.assertIn("loopback", res.root["error"])

    def test_cancel_stops_enumeration(self):
        res = od.crawl(self.srv.url("/pub/"), self.opts(max_depth=3), is_cancelled=lambda: True)
        self.assertTrue(res.cancelled)
        self.assertEqual(res.files, [])

    def test_persist_and_job_flow_and_removed_marking(self):
        conn = od.db()
        try:
            url = od.dir_url(self.srv.url("/pub/"))
            job_id = "job-test-1"
            conn.execute("""INSERT INTO opendir_hunting_jobs(id, mode, query, providers, options, dedupe_key, status, stage,
                            counters, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                         (job_id, "targeted", url, "[]", "{}", "k1", od.JOB_RUNNING, "queued", "{}", "t", od.utcnow()))
            od._crawl_and_persist(conn, job_id, url, self.opts(max_depth=2), "targeted", "user", url)
            conn.commit()
            row = conn.execute("SELECT * FROM opendir_directories WHERE url=?", (url,)).fetchone()
            self.assertEqual(row["status"], od.STATUS_VERIFIED)
            self.assertGreater(row["interest_score"], 0)
            self.assertTrue(conn.execute("SELECT 1 FROM opendir_files WHERE name='loader.exe' AND removed_at IS NULL").fetchone())
            # Second scan where loader.exe disappears -> marked removed, not deleted.
            os.remove(os.path.join(self.srv.root, "pub", "loader.exe"))
            od._crawl_and_persist(conn, job_id, url, self.opts(max_depth=2), "targeted", "user", url)
            conn.commit()
            gone = conn.execute("SELECT removed_at FROM opendir_files WHERE name='loader.exe'").fetchone()
            self.assertIsNotNone(gone["removed_at"])
            with open(os.path.join(self.srv.root, "pub", "loader.exe"), "wb") as f:
                f.write(b"MZ")
        finally:
            conn.close()

    def test_job_dedupe_and_unsafe_target_rejected(self):
        with self.assertRaises(od.UnsafeTarget):
            od.create_job("targeted", "file:///etc/", [], {}, "u1")
        with self.assertRaises(ValueError):
            od.create_job("global", "x", ["nope"], {}, "u1")


class TestWatchDiff(unittest.TestCase):
    def snap(self, status, entries):
        import json
        return {"status": status, "entries": json.dumps(entries)}

    def test_file_added_removed_size_changed(self):
        prev = self.snap("verified", [{"name": "a.exe", "url": "u/a.exe", "is_dir": False, "size": 1, "modified_at": None},
                                      {"name": "b.zip", "url": "u/b.zip", "is_dir": False, "size": 5, "modified_at": None}])
        cur = self.snap("verified", [{"name": "a.exe", "url": "u/a.exe", "is_dir": False, "size": 2, "modified_at": None},
                                     {"name": "c.ps1", "url": "u/c.ps1", "is_dir": False, "size": 3, "modified_at": None}])
        kinds = sorted(c["change_type"] for c in od.diff_snapshots(prev, cur))
        self.assertEqual(kinds, ["file_added", "file_removed", "size_changed"])

    def test_first_snapshot_has_no_changes(self):
        cur = self.snap("verified", [{"name": "a", "url": "u/a", "is_dir": False, "size": 1, "modified_at": None}])
        self.assertEqual(od.diff_snapshots(None, cur), [])

    def test_became_inaccessible(self):
        kinds = [c["change_type"] for c in od.diff_snapshots(self.snap("verified", []), self.snap("inaccessible", []))]
        self.assertEqual(kinds, ["became_inaccessible"])


class TestMigrationIdempotent(unittest.TestCase):
    def test_init_twice(self):
        od.init_db()
        od._db_ready = False
        od.init_db()
        conn = od.db()
        v = [r["version"] for r in conn.execute("SELECT version FROM opendir_schema_migrations ORDER BY version")]
        conn.close()
        self.assertEqual(v, [1, 2])


if __name__ == "__main__":
    unittest.main()
