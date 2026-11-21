"""Offline Telegram harvester tests. Never opens the production credential database."""
import asyncio
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))


@pytest.fixture
def cs(tmp_path, monkeypatch):
    monkeypatch.setenv("MANTIS_CS_DB", str(tmp_path / "credential-test.db"))
    import credential_stealer
    credential_stealer.CS_DB_PATH = str(tmp_path / "credential-test.db")
    credential_stealer._db_initialized = False
    credential_stealer.init_db()
    yield credential_stealer
    credential_stealer._db_initialized = False


class Message:
    def __init__(self, mid, filename=None):
        self.id = mid
        self.message = ""
        self.document = types.SimpleNamespace(
            size=4, attributes=[types.SimpleNamespace(file_name=filename)]
        ) if filename else None


class FakeClient:
    messages = []
    visited = []
    downloads = []
    async def connect(self): pass
    async def disconnect(self): pass
    async def get_entity(self, username): return types.SimpleNamespace(title=username)
    async def iter_messages(self, entity, min_id=0, reverse=False, limit=None):
        assert reverse
        for msg in [m for m in self.messages if m.id > min_id][:limit]:
            self.visited.append(msg.id)
            yield msg
    async def get_messages(self, entity, limit=0, min_id=0):
        return types.SimpleNamespace(total=sum(m.id > min_id for m in self.messages))
    async def download_media(self, msg, file, progress_callback=None):
        self.downloads.append(msg.id)
        Path(file).write_bytes(b"data")
        if progress_callback:
            progress_callback(4, 4)


def run(cs, monkeypatch, messages, *, max_messages=0, settings=None, client_class=FakeClient):
    client_class.messages = messages
    client_class.visited = []
    client_class.downloads = []
    telethon = types.ModuleType("telethon")
    telethon.TelegramClient = lambda *a, **kw: client_class()
    sessions = types.ModuleType("telethon.sessions")
    sessions.StringSession = lambda value: value
    mtproto = types.ModuleType("tg_mtproto")
    mtproto.get_session = lambda: ("session", 123, "hash")
    monkeypatch.setitem(sys.modules, "telethon", telethon)
    monkeypatch.setitem(sys.modules, "telethon.sessions", sessions)
    monkeypatch.setitem(sys.modules, "tg_mtproto", mtproto)
    src = cs.add_tg_source("testchannel", max_messages=max_messages)
    job = cs._job_create("tg_sync", "@testchannel")
    defaults = dict(cs.get_settings())
    defaults.update(settings or {})
    monkeypatch.setattr(cs, "get_settings", lambda: defaults)
    monkeypatch.setattr(cs, "_ingest_directory_files", lambda *a, **kw: {"found": 0, "new": 0, "unparsed": 0})
    result = asyncio.run(cs._sync_tg_channel_coro(src, job))
    return result, cs.list_tg_sources()[0], cs.list_jobs(1)[0]


def test_unlimited_drains_150_oldest_first(cs, monkeypatch):
    result, source, job = run(cs, monkeypatch, [Message(i) for i in range(1, 151)])
    assert result["messages"] == 150 and source["last_message_id"] == 150
    assert FakeClient.visited == list(range(1, 151))
    assert job["files_processed"] == 150 and job["files_total"] == 150


def test_cursor_saved_on_failure_and_rerun(cs, monkeypatch):
    messages = [Message(i) for i in range(1, 151)]
    original = cs._extract_passwords_from_text
    def fail_on_105(text):
        # Text-only messages are given an id marker for this test.
        if text == "message 105":
            raise RuntimeError("scripted failure")
        return original(text)
    messages[104].message = "message 105"
    with patch.object(cs, "_extract_passwords_from_text", side_effect=fail_on_105):
        with pytest.raises(RuntimeError, match="scripted failure"):
            run(cs, monkeypatch, messages)
    assert cs.list_tg_sources()[0]["last_message_id"] == 104
    result, source, _ = run(cs, monkeypatch, messages)
    assert source["last_message_id"] == 150
    assert result["messages"] == 46
    assert FakeClient.visited[0] == 105


def test_file_budget_pauses_without_skipping_backlog(cs, monkeypatch):
    result, source, job = run(cs, monkeypatch, [Message(i, f"{i}.txt") for i in range(1, 11)],
                              settings={"max_files_per_sync": 3})
    assert result["files"] == 3 and source["last_message_id"] == 3
    assert source["status"] == "paused" and job["messages_remaining"] == 7
    assert job["files_downloaded"] == 3


def test_disk_floor_pauses_without_raising(cs, monkeypatch):
    monkeypatch.setattr(cs.shutil, "disk_usage", lambda path: types.SimpleNamespace(free=0))
    result, source, job = run(cs, monkeypatch, [Message(i, "sample.txt") for i in range(1, 5)])
    assert source["status"] == "paused" and source["last_message_id"] == 0
    assert job["messages_remaining"] == 4 and not FakeClient.downloads


def test_extra_extension_skip_and_download(cs, monkeypatch):
    messages = [Message(1, "dump.json")]
    result, source, job = run(cs, monkeypatch, messages, settings={"extra_extensions": []})
    assert result["skipped"] == 1 and result["files"] == 0
    assert "extension not allowed" in "\n".join(job["log_lines"])
    # Re-create the channel so that its new cursor starts from zero.
    conn = cs.connect_db()
    conn.execute("UPDATE cs_sources_tg SET last_message_id=0 WHERE id=?", (source["id"],))
    conn.commit(); conn.close()
    result, _, _ = run(cs, monkeypatch, messages, settings={"extra_extensions": [".json"]})
    assert result["files"] == 1


def test_mega_rejects_oversized_file(cs, monkeypatch, tmp_path):
    class FakeProcess:
        returncode = 0
        def __init__(self, *args, **kw):
            (tmp_path / "large.zip").write_bytes(b"x" * 20)
        def poll(self): return 0
    monkeypatch.setattr(cs.shutil, "which", lambda _: "megadl")
    monkeypatch.setattr(cs.subprocess, "Popen", FakeProcess)
    result = cs._download_external_link("https://mega.nz/file/id", str(tmp_path), 10, remaining_files=3)
    assert result == [] and not (tmp_path / "large.zip").exists()


def test_default_migration_only_changes_50(cs):
    conn = cs.connect_db()
    conn.execute("DELETE FROM cs_settings WHERE key='_tg_default_50_migrated'")
    conn.execute("INSERT INTO cs_sources_tg(username,max_messages,created_at) VALUES('old',50,'now')")
    conn.execute("INSERT INTO cs_sources_tg(username,max_messages,created_at) VALUES('chosen',500,'now')")
    conn.commit(); conn.close()
    cs.init_db()
    rows = {r["username"]: r["max_messages"] for r in cs.list_tg_sources()}
    assert rows["old"] == 0 and rows["chosen"] == 500
