"""Focused storage tests for cases, canonical IOCs, links, and activity."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
import ti_cases as store
from ti_cases_routes import CasePatch, build_router, validate_mwdb_url


class TICaseTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.old_db = store.DB
        store.DB = Path(self.folder.name) / "cases.db"
        store.init()

    def tearDown(self):
        store.DB = self.old_db
        self.folder.cleanup()

    def test_case_and_ioc_crud_and_shared_link(self):
        one = store.save_case({"name": "Campaign A", "notes": "# Evidence"}, "alice")
        two = store.save_case({"name": "Campaign B"}, "bob")
        self.assertEqual(one["case_id"], "TI-000001")
        ioc = store.save_ioc({"value": "EXAMPLE[.]COM", "assessment": "Malicious"}, "alice")
        duplicate = store.save_ioc({"value": "example.com", "references": ["https://example.org/report"]}, "bob")
        self.assertEqual(ioc["id"], duplicate["id"])
        self.assertEqual(duplicate["references"], ["https://example.org/report"])
        store.link_ioc(one["id"], ioc["id"], "alice", "Initial pivot")
        store.link_ioc(two["id"], ioc["id"], "bob")
        self.assertEqual(len(store.lookup("example.com", "domain")["related_cases"]), 2)
        self.assertEqual(store.list_cases(q="example.com")["total"], 2)
        self.assertEqual(store.case_detail(one["id"])["iocs"][0]["note"], "Initial pivot")
        store.unlink_ioc(one["id"], ioc["id"], "alice")
        self.assertEqual(len(store.ioc_detail(ioc["id"])["related_cases"]), 1)
        updated = store.save_case({"name": "Campaign A", "status": "Closed"}, "alice", one["id"])
        self.assertEqual(updated["status"], "Closed")
        self.assertEqual([a["action"] for a in updated["activity"]], ["updated", "unlinked IOC", "linked IOC", "created"])
        store.delete_case(one["id"], "alice")
        self.assertEqual(store.lookup("example.com")["id"], ioc["id"])

    def test_normalization_validation_and_samples(self):
        self.assertEqual(store.normalize("HXXPS://EXAMPLE[.]COM/path#fragment"),
                         ("https://EXAMPLE.COM/path#fragment", "url", "https://example.com/path"))
        self.assertEqual(store.normalize("2001:0db8::1")[2], "2001:db8::1")
        with self.assertRaises(ValueError):
            store.normalize("not an IP", "ip")
        case = store.save_case({"name": "Sample case"}, "alice")
        sample = {"sha256": "a" * 64, "filename": "sample.bin", "size": 4}
        store.link_sample(case["id"], sample, "alice")
        store.link_sample(case["id"], sample, "alice")
        self.assertEqual(len(store.case_detail(case["id"])["samples"]), 1)
        store.unlink_sample(case["id"], sample["sha256"], "local", "alice")
        self.assertEqual(len(store.case_detail(case["id"])["samples"]), 0)
        related = store.save_case({"name": "Related"}, "bob")
        store.relation(case["id"], related["id"], "Shared infrastructure", "alice")
        self.assertEqual(store.case_detail(related["id"])["related_cases"][0]["reason"], "Shared infrastructure")

    def test_bulk_relink_preserves_case_note_and_explicit_edit_can_clear(self):
        case = store.save_case({"name": "Investigation", "notes": "# Evidence"}, "alice")
        ioc = store.save_ioc({"value": "example.com", "assessment": "Malicious"}, "alice")
        store.link_ioc(case["id"], ioc["id"], "alice", "Original observation")
        # Bulk import links existing indicators without a note.
        store.link_ioc(case["id"], ioc["id"], "bob")
        self.assertEqual(store.case_detail(case["id"])["iocs"][0]["note"], "Original observation")
        self.assertEqual(store.ioc_detail(ioc["id"])["assessment"], "Malicious")
        store.update_case_ioc_note(case["id"], ioc["id"], "", "bob")
        self.assertEqual(store.case_detail(case["id"])["iocs"][0]["note"], "")

    def test_inline_case_edits_preserve_other_sections(self):
        case = store.save_case({"name": "Investigation", "notes": "# Evidence", "ttps": ["T1059"]}, "alice")
        router = build_router(lambda: {}, lambda: {})
        patch_case = next(r.endpoint for r in router.routes if r.path == "/api/ti/cases/{case_id}" and "PATCH" in r.methods)
        updated = patch_case(case["id"], CasePatch(notes="## Updated"), {"username": "bob"})
        self.assertEqual(updated["notes"], "## Updated")
        self.assertEqual(updated["ttps"], ["T1059"])
        self.assertEqual(store.list_cases(q=case["case_id"])["total"], 1)

    def test_bulk_pasted_urls_preserve_commas_and_link_to_case(self):
        case = store.save_case({"name": "URL investigation"}, "alice")
        router = build_router(lambda: {}, lambda: {})
        importer = next(r.endpoint for r in router.routes if r.path == "/api/ti/iocs/import")
        # The pasted-text branch has no awaits; run it without opening sockets in restricted Windows CI.
        with self.assertRaises(StopIteration) as complete:
            importer("https://example.com/a,b\nexample.org", None, case["id"], {"username": "alice"}).send(None)
        result = complete.exception.value
        self.assertEqual(result["imported"], 2)
        self.assertEqual(len(store.case_detail(case["id"])["iocs"]), 2)
        self.assertEqual(store.lookup("https://example.com/a,b")["value"], "https://example.com/a,b")

    def test_mwdb_metadata_link_without_automatic_download(self):
        case = store.save_case({"name": "MWDB sample"}, "alice")
        sha = "a" * 64
        router = build_router(lambda: {}, lambda: {})
        search = next(r.endpoint for r in router.routes if r.path == "/api/ti/mwdb/search/{sha256}")
        attach = next(r.endpoint for r in router.routes if r.path == "/api/ti/cases/{case_id}/mwdb/{sha256}" and "POST" in r.methods)
        response = type("Response", (), {"status_code": 200, "raise_for_status": lambda self: None,
                                         "json": lambda self: {"file_name": "test.exe", "file_size": 10}})()
        with patch("ti_cases_routes.auth_service.get_all_user_api_keys", return_value={
                "ti_mwdb_url": "https://mwdb.example", "ti_mwdb_key": "secret"}), \
             patch("ti_cases_routes.requests.get", return_value=response) as get:
            result = search(sha, {"id": "alice"})
            self.assertEqual(result["metadata"]["file_name"], "test.exe")
            attach(case["id"], sha, {"id": "alice", "username": "alice"})
            self.assertEqual(store.case_detail(case["id"])["samples"][0]["source"], "mwdb")
            self.assertEqual(get.call_count, 2)
            self.assertTrue(all("/download" not in call.args[0] for call in get.call_args_list))
        self.assertEqual(validate_mwdb_url("http://localhost:8080"), "http://localhost:8080")


if __name__ == "__main__":
    unittest.main()
