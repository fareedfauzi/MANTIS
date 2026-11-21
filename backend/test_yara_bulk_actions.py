"""Bulk Rule Explorer actions use an isolated repository and tombstone file."""

import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import yara_repos


class BulkRulesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.root = base / "rules"
        self.root.mkdir()
        (self.root / "mixed.yar").write_text(
            'import "pe"\n\nrule Good { condition: true }\n\nrule Bad { condition: false }\n',
            encoding="utf-8")
        repo = {"id": "test", "label": "Test", "path": str(self.root)}
        record = {"files": {"mixed.yar": {"index": [{"n": "Good", "v": True},
                                                  {"n": "Bad", "v": False}]}}}
        for name, value in (
            ("discover_repos", lambda: [repo]),
            ("discover_explorer_repos", lambda: [repo]),
            ("ensure_indexed", lambda _id: record),
            ("TOMBSTONES_FILE", str(base / "deleted.json")),
            ("_tombstones_cache", None),
        ):
            p = patch.object(yara_repos, name, value)
            p.start()
            self.addCleanup(p.stop)

    def test_export_only_valid_rule_from_mixed_file(self):
        path, count = yara_repos.export_valid_rules(["test"])
        self.addCleanup(lambda: Path(path).unlink(missing_ok=True))
        self.assertEqual(count, 1)
        with zipfile.ZipFile(path) as archive:
            self.assertEqual(archive.namelist(), ["test/mixed.yar"])
            source = archive.read("test/mixed.yar").decode()
            self.assertIn('import "pe"', source)
            self.assertIn("rule Good", source)
            self.assertNotIn("rule Bad", source)

    def test_delete_only_invalid_rule_and_record_tombstone(self):
        self.assertEqual(yara_repos.delete_invalid_rules(["test"]), {"deleted": 1})
        source = (self.root / "mixed.yar").read_text(encoding="utf-8")
        self.assertIn("rule Good", source)
        self.assertNotIn("rule Bad", source)
        tombstones = json.loads((Path(self.tmp.name) / "deleted.json").read_text(encoding="utf-8"))
        self.assertIn("test::Bad", tombstones)

    def test_unknown_or_hidden_repository_is_rejected(self):
        with self.assertRaises(ValueError):
            yara_repos.delete_invalid_rules(["hidden"])


if __name__ == "__main__":
    unittest.main()
