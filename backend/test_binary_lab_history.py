"""Focused tests for Binary Lab job history consumed by Binary Reversing."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import binary_lab


class BinaryLabHistoryTests(unittest.TestCase):
    def test_list_jobs_excludes_manual_reversing_note_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            jobs = root / "jobs"
            output = root / "output"
            jobs.mkdir()
            output.mkdir()
            job_id = "bl_0123456789abcdef"
            (jobs / f"{job_id}.json").write_text(json.dumps({
                "job_id": job_id,
                "status": "complete",
                "samples": [{"name": "sample.exe", "status": "complete"}],
            }), encoding="utf-8")
            (jobs / f"{job_id}_reversing_0.json").write_text(json.dumps({
                "401000": {"text": "Analyst note"},
            }), encoding="utf-8")

            with patch.object(binary_lab, "JOBS_DIR", jobs), patch.object(binary_lab, "OUTPUT_DIR", output):
                result = binary_lab.list_jobs(limit=100)

        self.assertEqual([job["job_id"] for job in result["jobs"]], [job_id])

    def test_delete_job_removes_workspace_upload_and_notes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            jobs = root / "jobs"
            output = root / "output"
            uploads = root / "uploads"
            job_id = "bl_0123456789abcdef"
            staged = uploads / "staged-upload"
            workspace = output / job_id
            jobs.mkdir()
            staged.mkdir(parents=True)
            workspace.mkdir(parents=True)
            sample = staged / "sample.exe"
            sample.write_bytes(b"MZ")
            (workspace / "functions.json").write_text("[]", encoding="utf-8")
            job_file = jobs / f"{job_id}.json"
            notes_file = jobs / f"{job_id}_reversing_0.json"
            job_file.write_text(json.dumps({
                "job_id": job_id,
                "status": "complete",
                "samples": [{"name": sample.name, "path": str(sample), "status": "complete"}],
            }), encoding="utf-8")
            notes_file.write_text(json.dumps({"401000": {"text": "Analyst note"}}), encoding="utf-8")

            with (
                patch.object(binary_lab, "JOBS_DIR", jobs),
                patch.object(binary_lab, "OUTPUT_DIR", output),
                patch.object(binary_lab, "UPLOADS_DIR", uploads),
            ):
                result = binary_lab.delete_job(job_id)

            self.assertEqual(result, {"deleted": True, "job_id": job_id})
            self.assertFalse(job_file.exists())
            self.assertFalse(notes_file.exists())
            self.assertFalse(workspace.exists())
            self.assertFalse(staged.exists())


if __name__ == "__main__":
    unittest.main()
