"""Versioned, atomic persistence for Deep Analyzer sessions."""

import hashlib
import json
import os
import tempfile


SCHEMA_VERSION = 2


class SessionMismatch(ValueError):
    pass


def binary_fingerprint(path):
    """Return a bounded identity hash without loading a large binary in memory."""
    if not path or not os.path.isfile(path):
        return ""
    digest = hashlib.sha256()
    size = os.path.getsize(path)
    with open(path, "rb") as stream:
        digest.update(stream.read(1024 * 1024))
        if size > 1024 * 1024:
            stream.seek(max(0, size - 1024 * 1024))
            digest.update(stream.read(1024 * 1024))
    digest.update(str(size).encode("ascii"))
    return digest.hexdigest()


def envelope(entry_ea, binary_id, nodes, stage="discovery", metadata=None):
    return {
        "schema_version": SCHEMA_VERSION,
        "entry_ea": int(entry_ea),
        "binary_id": str(binary_id or ""),
        "stage": str(stage),
        "metadata": dict(metadata or {}),
        "nodes": list(nodes),
    }


def atomic_write_json(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".genesect-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        backup = path + ".bak"
        if os.path.exists(path):
            try:
                os.replace(path, backup)
            except OSError:
                pass
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_json_recover(path, expected_entry=None, expected_binary_id=None):
    errors = []
    for candidate in (path, path + ".bak"):
        if not os.path.exists(candidate):
            continue
        try:
            with open(candidate, "r", encoding="utf-8") as stream:
                data = json.load(stream)
            version = int(data.get("schema_version", 1))
            if version > SCHEMA_VERSION:
                raise SessionMismatch(f"session schema {version} is newer than supported schema {SCHEMA_VERSION}")
            if expected_entry is not None and int(data.get("entry_ea", 0)) != int(expected_entry):
                raise SessionMismatch("session belongs to a different entry point")
            stored_id = str(data.get("binary_id", ""))
            if expected_binary_id and stored_id and stored_id != expected_binary_id:
                raise SessionMismatch("session belongs to a different input binary")
            data["recovered_from_backup"] = candidate != path
            return data
        except SessionMismatch:
            raise
        except Exception as exc:
            errors.append(f"{os.path.basename(candidate)}: {exc}")
    if errors:
        raise ValueError("; ".join(errors))
    return None
