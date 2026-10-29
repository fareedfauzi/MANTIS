"""Persistent rename cache: reuse AI-chosen names across samples.

Functions are fingerprinted from their normalized pseudocode, so the same routine
in a second sample (a variant, a re-pack, a statically linked library) gets the
name the model chose last time without another request.

Two fingerprints are kept per function:

* ``exact``  - addresses, IDA auto-names and local variable names are masked, but
  string literals and constants are kept. Safe to trust for any non-trivial function.
* ``struct`` - additionally masks string literals and large constants. This lets a
  variant with a new C2 URL or XOR key still match, but it is only used for big
  functions and only when past results agree.

No IDA imports here; the module is plain Python plus ``sqlite3``.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

_TOKEN_RE = re.compile(
    r"(?P<str>\"(?:[^\"\\\n]|\\.)*\")"
    r"|(?P<hex>\b0x[0-9A-Fa-f]+(?:[uUlL]+|i64)?)"
    r"|(?P<id>[A-Za-z_][A-Za-z0-9_]*)"
)
_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
_AUTO_FN_RE = re.compile(r"^(?:sub|nullsub|j_sub|thunk_sub|j_nullsub)_[0-9A-Fa-f]+$")
_AUTO_DATA_RE = re.compile(
    r"^(?:loc|locret|off|unk|byte|word|dword|qword|xmmword|ymmword|flt|dbl|asc|stru|funcs|"
    r"stru|jpt|def|case|word|tbyte|oword)_[0-9A-Fa-f]+$"
)
_VALID_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{2,}$")
_AUTO_NAME_RE = re.compile(r"^(?:sub|loc|nullsub|j_sub|unk|off|byte|word|dword|qword)_[0-9A-Fa-f]+$")

MIN_EXACT_LINES, MIN_EXACT_CHARS = 4, 120
MIN_STRUCT_LINES, MIN_STRUCT_CHARS = 10, 350
STRUCT_CONSENSUS = 0.6


@dataclass
class Fingerprint:
    exact: str
    struct: str
    var_order: list = field(default_factory=list)
    chars: int = 0
    lines: int = 0

    @property
    def eligible_exact(self) -> bool:
        return self.lines >= MIN_EXACT_LINES and self.chars >= MIN_EXACT_CHARS

    @property
    def eligible_struct(self) -> bool:
        return self.lines >= MIN_STRUCT_LINES and self.chars >= MIN_STRUCT_CHARS

    @property
    def eligible(self) -> bool:
        return self.eligible_exact


def _normalize_pass(
    text: str,
    lvar_index: dict,
    var_order: list,
    user_functions: set,
    own_name: str,
    image_range: Optional[tuple],
    mask_literals: bool,
) -> str:
    def replace(match: "re.Match[str]") -> str:
        if match.group("str") is not None:
            return '"S"' if mask_literals else match.group("str")
        if match.group("hex") is not None:
            raw = match.group("hex")
            digits = re.match(r"0x[0-9A-Fa-f]+", raw).group(0)
            value = int(digits, 16)
            if image_range and image_range[0] <= value < image_range[1]:
                return "ADDR"
            if mask_literals and value >= 0x10:
                # Keys, seeds and magic numbers differ between variants.
                return "NUM"
            return digits.lower()
        name = match.group("id")
        if name in lvar_index:
            if name not in var_order:
                var_order.append(name)
            return "V%d" % var_order.index(name)
        if name == own_name or _AUTO_FN_RE.match(name) or name in user_functions:
            return "FN"
        if _AUTO_DATA_RE.match(name):
            return "GLOBAL"
        return name

    cleaned = _COMMENT_RE.sub(" ", text)
    replaced = _TOKEN_RE.sub(replace, cleaned)
    lines = []
    for line in replaced.splitlines():
        line = re.sub(r"[ \t]+", " ", line).strip()
        if line:
            lines.append(line)
    return "\n".join(lines)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:32]


def fingerprint(
    text: str,
    lvar_names: Iterable[str] = (),
    user_functions: Iterable[str] = (),
    own_name: str = "",
    image_range: Optional[tuple] = None,
) -> Fingerprint:
    """Fingerprint one function's pseudocode.

    ``lvar_names`` are the function's local variable names *as they appear in this
    text* (renamed or not); they are canonicalised by order of first appearance, so
    the fingerprint is the same before and after variable renaming.
    """
    lvars = {str(n): True for n in lvar_names if str(n)}
    functions = set(user_functions)
    var_order: list = []
    exact_text = _normalize_pass(text or "", lvars, var_order, functions, own_name, image_range, False)
    struct_text = _normalize_pass(text or "", lvars, [], functions, own_name, image_range, True)
    return Fingerprint(
        exact=_digest(exact_text),
        struct=_digest(struct_text),
        var_order=var_order,
        chars=len(exact_text),
        lines=exact_text.count("\n") + (1 if exact_text else 0),
    )


def is_cacheable_name(name: str) -> bool:
    return bool(name) and bool(_VALID_NAME_RE.match(name)) and not _AUTO_NAME_RE.match(name)


class RenameCache:
    """SQLite-backed store. One short-lived connection per IDA process."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(self.path), timeout=30)
        try:
            self._db.execute("PRAGMA journal_mode=WAL")
        except sqlite3.DatabaseError:
            pass
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS fn_names (
                kind TEXT NOT NULL, fp TEXT NOT NULL, name TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 1, hits INTEGER NOT NULL DEFAULT 0,
                first_sample TEXT, model TEXT, created REAL, updated REAL,
                PRIMARY KEY (kind, fp, name)
            );
            CREATE TABLE IF NOT EXISTS var_names (
                kind TEXT NOT NULL, fp TEXT NOT NULL, mapping TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 1, hits INTEGER NOT NULL DEFAULT 0,
                first_sample TEXT, model TEXT, created REAL, updated REAL,
                PRIMARY KEY (kind, fp, mapping)
            );
            """
        )
        self._db.commit()

    # ------------------------------------------------------------------ helpers
    def _consensus(self, rows: list, key_index: int):
        """Pick the winning row; ``struct`` hits must be a clear majority."""
        if not rows:
            return None
        total = sum(int(r[1]) for r in rows)
        top = max(rows, key=lambda r: int(r[1]))
        if total and int(top[1]) / total >= STRUCT_CONSENSUS:
            return top
        return None

    def _upsert(self, table: str, column: str, kind: str, fp: str, value: str, sample: str, model: str) -> None:
        now = time.time()
        cur = self._db.execute(
            "UPDATE %s SET count = count + 1, updated = ? WHERE kind = ? AND fp = ? AND %s = ?" % (table, column),
            (now, kind, fp, value),
        )
        if cur.rowcount == 0:
            self._db.execute(
                "INSERT INTO %s (kind, fp, %s, count, hits, first_sample, model, created, updated) "
                "VALUES (?, ?, ?, 1, 0, ?, ?, ?, ?)" % (table, column),
                (kind, fp, value, sample, model, now, now),
            )

    def _bump_hit(self, table: str, column: str, kind: str, fp: str, value: str) -> None:
        self._db.execute(
            "UPDATE %s SET hits = hits + 1 WHERE kind = ? AND fp = ? AND %s = ?" % (table, column),
            (kind, fp, value),
        )

    # ---------------------------------------------------------------- functions
    def lookup_function(self, fp: Fingerprint) -> Optional[tuple]:
        """Return ``(name, kind)`` for a known function, or ``None``."""
        if fp.eligible_exact:
            row = self._db.execute(
                "SELECT name, count FROM fn_names WHERE kind = 'exact' AND fp = ? "
                "ORDER BY count DESC, updated DESC LIMIT 1",
                (fp.exact,),
            ).fetchone()
            if row:
                self._bump_hit("fn_names", "name", "exact", fp.exact, row[0])
                return row[0], "exact"
        if fp.eligible_struct:
            rows = self._db.execute(
                "SELECT name, count FROM fn_names WHERE kind = 'struct' AND fp = ?", (fp.struct,)
            ).fetchall()
            top = self._consensus(rows, 0)
            if top:
                self._bump_hit("fn_names", "name", "struct", fp.struct, top[0])
                return top[0], "struct"
        return None

    def store_function(self, fp: Fingerprint, name: str, sample: str = "", model: str = "") -> bool:
        if not is_cacheable_name(name) or not fp.eligible_exact:
            return False
        self._upsert("fn_names", "name", "exact", fp.exact, name, sample, model)
        if fp.eligible_struct:
            self._upsert("fn_names", "name", "struct", fp.struct, name, sample, model)
        return True

    # ---------------------------------------------------------------- variables
    def lookup_variables(self, fp: Fingerprint) -> Optional[tuple]:
        """Return ``({canonical_index: new_name}, kind)`` or ``None``."""
        if fp.eligible_exact:
            row = self._db.execute(
                "SELECT mapping, count FROM var_names WHERE kind = 'exact' AND fp = ? "
                "ORDER BY count DESC, updated DESC LIMIT 1",
                (fp.exact,),
            ).fetchone()
            if row:
                self._bump_hit("var_names", "mapping", "exact", fp.exact, row[0])
                return _decode_mapping(row[0]), "exact"
        if fp.eligible_struct:
            rows = self._db.execute(
                "SELECT mapping, count FROM var_names WHERE kind = 'struct' AND fp = ?", (fp.struct,)
            ).fetchall()
            top = self._consensus(rows, 0)
            if top:
                self._bump_hit("var_names", "mapping", "struct", fp.struct, top[0])
                return _decode_mapping(top[0]), "struct"
        return None

    def store_variables(self, fp: Fingerprint, mapping: dict, sample: str = "", model: str = "") -> bool:
        clean = {
            int(idx): str(new)
            for idx, new in mapping.items()
            if isinstance(idx, int) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", str(new))
        }
        if not clean or not fp.eligible_exact:
            return False
        encoded = json.dumps({str(k): clean[k] for k in sorted(clean)}, sort_keys=True)
        self._upsert("var_names", "mapping", "exact", fp.exact, encoded, sample, model)
        if fp.eligible_struct:
            self._upsert("var_names", "mapping", "struct", fp.struct, encoded, sample, model)
        return True

    # -------------------------------------------------------------- bookkeeping
    def commit(self) -> None:
        self._db.commit()

    def stats(self) -> dict:
        def count(sql: str) -> int:
            return int(self._db.execute(sql).fetchone()[0] or 0)

        try:
            size = self.path.stat().st_size
        except OSError:
            size = 0
        return {
            "function_entries": count("SELECT COUNT(DISTINCT fp) FROM fn_names WHERE kind = 'exact'"),
            "variable_entries": count("SELECT COUNT(DISTINCT fp) FROM var_names WHERE kind = 'exact'"),
            "total_hits": count("SELECT COALESCE(SUM(hits), 0) FROM fn_names") +
                          count("SELECT COALESCE(SUM(hits), 0) FROM var_names"),
            "size_bytes": size,
        }

    def clear(self) -> None:
        self._db.execute("DELETE FROM fn_names")
        self._db.execute("DELETE FROM var_names")
        self._db.commit()
        self._db.execute("VACUUM")

    def close(self) -> None:
        try:
            self._db.commit()
        finally:
            self._db.close()

    def __enter__(self) -> "RenameCache":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


def _decode_mapping(text: str) -> dict:
    try:
        raw = json.loads(text)
    except ValueError:
        return {}
    return {int(k): str(v) for k, v in raw.items() if str(k).isdigit()}


def clear_cache_file(path) -> dict:
    """Used by the GUI: wipe the cache and return fresh stats."""
    with RenameCache(path) as cache:
        cache.clear()
        return cache.stats()


def cache_stats(path) -> Optional[dict]:
    path = Path(path)
    if not path.is_file():
        return None
    try:
        with RenameCache(path) as cache:
            return cache.stats()
    except sqlite3.DatabaseError:
        return None
