"""Local YARA rule repository: discovery, parsed index, in-memory compiled rules.

Layout (all in memory, nothing compiled is written to disk):
    Rule Repository
    ├── Parsed Rule Index -> Explorer / Workbench (lightweight metadata only)
    └── Compiled Rule Cache -> Scanner (live engine objects, reused across scans)

- The .yar/.yara files are the source of truth. Collections compile into
  memory once and the compiled rules are reused across scans; only a
  collection whose sources changed is recompiled.
- One namespace per repository (``custom::ShadowPad`` vs
  ``yara-forge::ShadowPad``), so duplicate rule names across repositories
  never conflict.
- A file that YARA-X rejects is retried on the classic engine before being
  recorded invalid; one bad file never blocks the rest of its repository.
"""

import json
import logging
import os
import re
import tempfile
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from yara_engine import (
    EngineCompileError,
    available_engines,
    get_engine,
    yara_x_available,
)

logger = logging.getLogger("mantis.yara.repos")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
YARA_RULES_ROOT = os.path.join(BASE_DIR, "data", "yara-rules")
YARA_CUSTOM_DIR = os.path.join(YARA_RULES_ROOT, "custom")
DEFAULT_CORPUS_DIR = os.path.join(BASE_DIR, "data", "yara-corpus")

REPO_LABELS = {
    "elastic": "Elastic",
    "yara-forge": "YARA Forge",
    "yaraify": "Yaraify",
    "malpedia": "Malpedia",
    "custom": "Custom",
}

EXPLORER_HIDDEN_REPO_RE = re.compile(r"(^|[._\-\s/\\])staging([._\-\s/\\]|$)", re.IGNORECASE)

# Filename stem -> collection display label; anything not listed falls back
# to a prettified stem.
COLLECTION_LABELS = {}

TOMBSTONES_FILE = os.path.join(BASE_DIR, "data", "yara_deleted_rules.json")
_tombstones_lock = threading.Lock()
_tombstones_cache: Optional[Dict[str, Any]] = None


def load_tombstones() -> Dict[str, Any]:
    global _tombstones_cache
    with _tombstones_lock:
        if _tombstones_cache is not None:
            return _tombstones_cache
        if not os.path.isfile(TOMBSTONES_FILE):
            _tombstones_cache = {}
            return _tombstones_cache
        try:
            with open(TOMBSTONES_FILE, "r", encoding="utf-8") as f:
                _tombstones_cache = json.load(f)
                if not isinstance(_tombstones_cache, dict):
                    _tombstones_cache = {}
        except Exception as e:
            logger.warning("Could not load YARA tombstones: %s", e)
            _tombstones_cache = {}
        return _tombstones_cache


def save_tombstones(data: Dict[str, Any]) -> None:
    global _tombstones_cache
    with _tombstones_lock:
        _tombstones_cache = data
        try:
            os.makedirs(os.path.dirname(TOMBSTONES_FILE), exist_ok=True)
            with open(TOMBSTONES_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error("Could not save YARA tombstones: %s", e)


def is_rule_deleted(repo_id: str, rule_name: str) -> bool:
    tombstones = load_tombstones()
    key = f"{repo_id}::{rule_name}"
    return key in tombstones or f"*::{rule_name}" in tombstones


def add_tombstone(repo_id: str, rule_name: str, file_rel: str = "") -> None:
    tombstones = dict(load_tombstones())
    key = f"{repo_id}::{rule_name}"
    tombstones[key] = {
        "repo": repo_id,
        "rule": rule_name,
        "file": file_rel,
        "deleted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    save_tombstones(tombstones)


def remove_tombstone(repo_id: str, rule_name: str) -> None:
    tombstones = dict(load_tombstones())
    key = f"{repo_id}::{rule_name}"
    removed = False
    if key in tombstones:
        del tombstones[key]
        removed = True
    if f"*::{rule_name}" in tombstones:
        del tombstones[f"*::{rule_name}"]
        removed = True
    if removed:
        save_tombstones(tombstones)


def collection_label(filename: str) -> str:
    """Collection display label for a rule file (e.g. Kaspersky APT)."""
    stem = (filename or "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if "." in stem:
        stem = stem.rsplit(".", 1)[0]
    key = stem.strip().lower()
    if key in COLLECTION_LABELS:
        return COLLECTION_LABELS[key]
    return stem.replace("_", " ").replace("-", " ").strip().title() or filename

MAX_FILES_PER_REPO = 5000
MAX_RULE_FILE_BYTES = 64 * 1024 * 1024

RULE_EXTS = (".yar", ".yara")
RULE_HEAD_RE = re.compile(
    r"(?m)^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?::\s*([^\{\r\n]*))?\s*\{"
)
META_ENTRY_RE = re.compile(
    r'(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*("(?:[^"\\\r\n]|\\.)*"|\d+|true|false)\s*$'
)
STRING_ID_RE = re.compile(r"(?m)^\s*(\$[A-Za-z_][A-Za-z0-9_]*)\s*=")
CONDITION_RE = re.compile(r"(?ms)^\s*condition\s*:(.*?)\}\s*(?://[^\r\n]*)?\s*$")
STRINGS_SEC_RE = re.compile(r"(?ms)^\s*strings\s*:(.*?)^\s*condition\s*:")
STRING_LITERAL_RE = re.compile(r'"((?:[^"\\\r\n]|\\.)*)"')
# Per-rule cap on captured string literals (search-only haystack, not source).
MAX_LITERALS_CHARS = 4000


def _rule_string_literals(block: str) -> List[str]:
    """Quoted text-string values from a rule's strings: section (best effort).

    Makes string *content* searchable (e.g. "This is a word") without storing
    full source in the index. Hex / regex strings have no quotes and are
    skipped; total length is capped to bound index memory.
    """
    sec = STRINGS_SEC_RE.search(block or "")
    if not sec:
        return []
    out: List[str] = []
    budget = MAX_LITERALS_CHARS
    for lit in STRING_LITERAL_RE.findall(sec.group(1)):
        if budget <= 0:
            break
        if not lit:
            continue
        out.append(lit[:budget])
        budget -= len(out[-1])
    return out


def _haystack_for(condition: str, meta_vals, string_ids, literals) -> str:
    """One lowered search blob per rule: condition + meta + identifiers +
    string literal values. Single place so both index builders agree."""
    return " ".join([
        str(condition or ""),
        " ".join(str(v) for v in (meta_vals or []) if isinstance(v, (str, int))),
        " ".join(string_ids or []),
        " ".join(literals or []),
    ]).lower()


def _repo_label(repo_id: str) -> str:
    if repo_id in REPO_LABELS:
        return REPO_LABELS[repo_id]
    if repo_id.startswith("extra::"):
        return repo_id.split("::", 1)[1].replace("_", " ").title()
    return repo_id.replace("_", " ").replace("-", " ").title()


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", (text or "").strip()).strip("._") or "repo"


def is_explorer_hidden_repo(repo: Dict[str, str]) -> bool:
    """Repositories used for staging/test rules should not appear in Explorer.

    They remain discoverable by lower-level scan/workbench paths so local rule
    QA workflows are not broken, but browse/search surfaces skip them.
    """
    if not isinstance(repo, dict):
        return False
    fields = [repo.get("id", ""), repo.get("label", ""), os.path.basename(repo.get("path", ""))]
    return any(EXPLORER_HIDDEN_REPO_RE.search(str(v or "")) for v in fields)


def discover_repos() -> List[Dict[str, str]]:
    """Configured local rule repositories (directories).

    The legacy ``kaspersky`` directory (formerly TIP-fetched) is excluded.
    """
    try:
        os.makedirs(YARA_CUSTOM_DIR, exist_ok=True)
    except OSError:
        pass
    repos: List[Dict[str, str]] = []
    seen = set()
    try:
        entries = sorted(os.listdir(YARA_RULES_ROOT))
    except OSError:
        entries = []
    for name in entries:
        if name == "kaspersky":
            continue
        path = os.path.join(YARA_RULES_ROOT, name)
        if os.path.isdir(path) and name not in seen:
            seen.add(name)
            repos.append({"id": name, "label": _repo_label(name), "path": path})
    # Extra repositories: MANTIS_YARA_EXTRA_REPOS="Label=/abs/path;Other=/x"
    for chunk in os.environ.get("MANTIS_YARA_EXTRA_REPOS", "").split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" in chunk:
            label, path = chunk.split("=", 1)
        else:
            label, path = os.path.basename(chunk.rstrip("/\\")), chunk
        path = os.path.abspath(os.path.expanduser(path.strip()))
        label = label.strip() or os.path.basename(path)
        repo_id = "extra::" + _slug(label)
        if repo_id not in seen and os.path.isdir(path):
            seen.add(repo_id)
            repos.append({"id": repo_id, "label": label, "path": path})
    return repos


def discover_explorer_repos() -> List[Dict[str, str]]:
    """Rule Explorer-visible repositories only."""
    return [r for r in discover_repos() if not is_explorer_hidden_repo(r)]


def _safe_join(root: str, rel: str) -> Optional[str]:
    """Resolve rel under root; None on traversal/symlink escape."""
    try:
        base = os.path.realpath(root)
        target = os.path.realpath(os.path.join(base, rel))
        if os.path.commonpath([base, target]) != base:
            return None
        return target
    except Exception:
        return None


def scan_repo_files(repo: Dict[str, str], use_cache: bool = True) -> List[str]:
    """Recursively list rule files (relative paths), safely.

    The directory walk is cached briefly so debounced searches don't
    re-walk the tree on every keystroke; workbench saves invalidate it.
    Freshness checks pass use_cache=False so externally added/removed files
    are never masked by the TTL cache.
    """
    now = time.monotonic()
    if use_cache:
        cached = _scan_cache.get(repo["id"])
        if cached and (now - cached[0]) < _SCAN_CACHE_TTL:
            return list(cached[1])
    out: List[str] = []
    root = repo["path"]
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # Prune symlinked dirs and cap depth implicitly via relpath check.
        dirnames[:] = [d for d in dirnames
                       if _safe_join(root, os.path.relpath(os.path.join(dirpath, d), root))]
        for fn in sorted(filenames):
            if not fn.lower().endswith(RULE_EXTS):
                continue
            rel = os.path.relpath(os.path.join(dirpath, fn), root)
            if _safe_join(root, rel) and len(out) < MAX_FILES_PER_REPO:
                out.append(rel)
    out = sorted(out)
    _scan_cache[repo["id"]] = (now, out)
    return list(out)


def parse_rule_index(source: str) -> List[Dict[str, Any]]:
    """Best-effort rule parser for the Explorer index (not a compiler)."""
    heads = list(RULE_HEAD_RE.finditer(source or ""))
    rules = []
    for i, m in enumerate(heads):
        block = source[m.start():heads[i + 1].start() if i + 1 < len(heads) else len(source)]
        name = m.group(1)
        tags = [t.strip() for t in (m.group(2) or "").split() if t.strip()]
        meta: Dict[str, Any] = {}
        meta_match = re.search(r"(?ms)^\s*meta\s*:(.*?)^\s*(?:strings|condition)\s*:", block)
        if meta_match:
            for k, v in META_ENTRY_RE.findall(meta_match.group(1)):
                if v.startswith('"'):
                    try:
                        meta[k] = json.loads(v)
                    except Exception:
                        meta[k] = v.strip('"')
                elif v in ("true", "false"):
                    meta[k] = (v == "true")
                else:
                    try:
                        meta[k] = int(v)
                    except ValueError:
                        meta[k] = v
        strings = STRING_ID_RE.findall(block)
        cond = CONDITION_RE.search(block)
        rules.append({
            "name": name,
            "tags": tags,
            "meta": meta,
            "strings": strings,
            "literals": _rule_string_literals(block),
            "condition": cond.group(1).strip()[:2000] if cond else "",
            "source": block.strip(),
        })
    return rules


# ---------------------------------------------------------------------------
# In-memory compiled rule cache (per repository; nothing touches disk)
# ---------------------------------------------------------------------------
_repo_locks: Dict[str, threading.Lock] = {}
_repo_locks_guard = threading.Lock()
_index_cache: Dict[str, Dict[str, Any]] = {}  # repo_id -> built record
_scan_cache: Dict[str, Tuple[float, List[str]]] = {}  # repo_id -> (ts, rels)
_SCAN_CACHE_TTL = 30.0
_FRESHNESS_CHECK_TTL = 300.0


def _repo_lock(repo_id: str) -> threading.Lock:
    with _repo_locks_guard:
        return _repo_locks.setdefault(repo_id, threading.RLock())


def _compile_file(repo_id: str, namespace: str, source: str) -> Tuple[str, Any, List[Dict[str, Any]]]:
    """Try YARA-X, then classic. Returns (engine_name, compiled, errors)."""
    errors: List[Dict[str, Any]] = []
    if yara_x_available():
        try:
            return "yarax", get_engine("yarax").compile({namespace: source}), []
        except EngineCompileError as e:
            errors.extend(e.errors)
        except Exception as e:  # pragma: no cover - defensive
            errors.append({"namespace": namespace, "line": None, "column": None,
                           "message": f"YARA-X: {type(e).__name__}: {e}"[:2000]})
    try:
        from yara_engine import classic_available
        if classic_available():
            try:
                return "classic", get_engine("classic").compile({namespace: source}), []
            except EngineCompileError as e:
                errors.extend(e.errors)
    except Exception as e:  # pragma: no cover - defensive
        errors.append({"namespace": namespace, "line": None, "column": None,
                       "message": f"classic: {type(e).__name__}: {e}"[:2000]})
    return "", None, errors


def _compile_blocks(repo_id: str, namespace: str,
                    blocks: List[Tuple[str, str]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Compile (rule_name, source) blocks; isolate failures per rule.

    Returns (outcomes, all_errors) where each outcome is
    {name, engine, compiled, errors}. One broken rule never blocks its
    file-mates: each block is retried on the classic engine when YARA-X
    rejects it.
    """
    outcomes: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    for name, src in blocks:
        engine, compiled, block_errors = _compile_file(repo_id, namespace, src)
        outcomes.append({"name": name, "engine": engine, "compiled": compiled,
                         "errors": block_errors})
        errors.extend([{**e, "rule": name} for e in block_errors])
    return outcomes, errors


def _build_repo(repo: Dict[str, str]) -> Dict[str, Any]:
    repo_id = repo["id"]
    namespace = repo_id
    t0 = time.monotonic()
    logger.info("building YARA repo %s (%s)", repo_id, repo["path"])
    rels = scan_repo_files(repo)
    files: Dict[str, Any] = {}
    artifacts: List[Tuple[str, str, Any]] = []  # (rel, engine, compiled live object)

    def build_one(rel: str):
        abs_path = _safe_join(repo["path"], rel)
        if not abs_path:
            return rel, None, [{"namespace": namespace, "line": None, "column": None,
                                "message": "path traversal or symlink escape blocked"}]
        try:
            size = os.path.getsize(abs_path)
            if size > MAX_RULE_FILE_BYTES:
                return rel, None, [{"namespace": namespace, "line": None, "column": None,
                                    "message": f"file too large ({size} bytes), skipped"}]
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                src = f.read()
        except OSError as e:
            return rel, None, [{"namespace": namespace, "line": None, "column": None,
                                "message": f"unreadable: {e}"}]
        parsed = parse_rule_index(src)
        all_count = len(parsed)
        parsed = [pr for pr in parsed if not is_rule_deleted(repo_id, pr.get("name", ""))]
        if len(parsed) < all_count:
            # One or more rules were deleted: rebuild source without deleted rules so updates never resurrect them
            src = "\n\n".join(r["source"] for r in parsed if r.get("source"))
        # Fast path: whole file at once. On failure, isolate per rule so one
        # broken rule does not poison its file-mates.
        engine, compiled, errors = _compile_file(repo_id, namespace, src)
        outcomes: List[Dict[str, Any]]
        if compiled is not None:
            outcomes = [{"name": r["name"], "engine": engine, "compiled": compiled,
                         "errors": []} for r in parsed]
            if not outcomes and not errors:
                errors = [{"namespace": namespace, "line": None, "column": None,
                           "message": "no parseable rules and no compiler output"}]
        else:
            blocks = [(r["name"], r["source"]) for r in parsed if r.get("source")]
            if blocks:
                outcomes, errors = _compile_blocks(repo_id, namespace, blocks)
            else:
                outcomes = []
            if not outcomes and not parsed:
                # No parseable rules (e.g. pure syntax garbage): keep file errors.
                pass
        by_name = {o["name"]: o for o in outcomes}
        for pr in parsed:
            o = by_name.get(pr["name"])
            pr["valid"] = bool(o and o["compiled"] is not None)
            pr["errors"] = list(o["errors"]) if o else list(errors)
        try:
            mtime = os.path.getmtime(abs_path)
        except OSError:
            mtime = 0.0
        return rel, (outcomes, errors, parsed, size, mtime), None

    with ThreadPoolExecutor(max_workers=min(8, (os.cpu_count() or 4)), thread_name_prefix="mantis-yara-build") as pool:
        futures = {pool.submit(build_one, rel): rel for rel in rels}
        results = {}
        for fut in as_completed(futures):
            rel = futures[fut]
            try:
                results[rel] = fut.result()
            except Exception as e:  # pragma: no cover - defensive
                results[rel] = (rel, None, [{"namespace": namespace, "line": None,
                                             "column": None, "message": f"build crashed: {e}"}])

    files: Dict[str, Any] = {}
    valid = invalid = n_rules = 0
    valid_rules = invalid_rules = 0
    for rel in rels:
        _, payload, fatal = results[rel]
        if fatal:
            files[rel] = {"errors": fatal, "rules": [], "engine": "",
                          "namespace": namespace, "mtime": 0, "size": 0,
                          "index": []}
            invalid += 1
            continue
        outcomes, errors, parsed, size, mtime = payload
        compiled_ok = [o for o in outcomes if o.get("compiled") is not None]
        rule_names = [r["name"] for r in parsed]
        n_rules += len(rule_names)
        rule_valid_count = sum(1 for r in parsed if r.get("valid"))
        rule_invalid_count = sum(1 for r in parsed if not r.get("valid"))
        valid_rules += rule_valid_count
        invalid_rules += rule_invalid_count
        engines = sorted({o["engine"] for o in compiled_ok if o.get("engine")})
        # The in-memory rule index keeps everything EXCEPT the full source
        # blocks (they stay in the .yar files; get_rule_source re-parses one
        # file on demand). No compiled artifacts are written anywhere.
        index_rules = []
        for r in parsed:
            meta = r.get("meta", {}) if isinstance(r.get("meta"), dict) else {}
            tags = r.get("tags", []) or []
            meta_vals = [str(v).lower() for v in meta.values() if isinstance(v, (str, int))]
            index_rules.append({
                "n": r["name"],
                "nl": str(r["name"]).lower(),
                "t": tags,
                "tl": [str(t).lower() for t in tags],
                "m": meta,
                "mv": meta_vals,
                "s": r.get("strings", []) or [],
                "h": _haystack_for(r.get("condition", ""), list(meta.values()),
                                   r.get("strings", []) or [], r.get("literals", []) or []),
                "v": bool(r.get("valid")),
                "e": list(r.get("errors", []) or []),
            })
        entry: Dict[str, Any] = {
            "rules": [{"name": r["name"], "valid": bool(r.get("valid"))} for r in parsed],
            "errors": errors,
            "rule_errors": {r["name"]: r.get("errors", []) for r in parsed if not r.get("valid")},
            "engines": engines,
            "engine": engines[0] if engines else "",
            "namespace": namespace, "mtime": mtime, "size": size,
            "index": index_rules,
        }
        # Deduplicate shared compiled objects (whole-file fast path) so each
        # ruleset is scanned exactly once. The valid-rule count travels with
        # the artifact so scans report exactly the rules they loaded.
        grouped: Dict[int, Dict[str, Any]] = {}
        for o in compiled_ok:
            key = id(o["compiled"])
            if key not in grouped:
                grouped[key] = {"engine": o["engine"], "compiled": o["compiled"], "rules": []}
            if o.get("name"):
                grouped[key]["rules"].append(o.get("name"))
        for grp in grouped.values():
            artifacts.append((rel, grp["engine"], grp["compiled"], len(grp["rules"])))
        if compiled_ok and rule_invalid_count == 0:
            valid += 1
        else:
            invalid += 1
        files[rel] = entry

    built_at = time.strftime("%Y-%m-%dT%H:%M:%S")
    record = {"repo": repo, "files": files, "artifacts": artifacts,
              "built_at": built_at,
              "checked_at": time.monotonic(),
              "stats": {"files": len(rels), "rules": n_rules,
                        "valid": valid_rules, "invalid": invalid_rules,
                        "valid_rules": valid_rules, "invalid_rules": invalid_rules,
                        "valid_files": valid, "invalid_files": invalid,
                        "build_s": round(time.monotonic() - t0, 2)}}
    _build_search_index(record)
    _index_cache[repo_id] = record
    logger.info("repo %s built in %.1fs: %d files (%d valid, %d invalid), %d rules (%d valid, %d invalid)",
                repo_id, time.monotonic() - t0, len(rels), valid, invalid, n_rules, valid_rules, invalid_rules)
    return record


def _build_repo_index_only(repo: Dict[str, str]) -> Dict[str, Any]:
    """Build the repo index with full rule compilation and validation."""
    return _build_repo(repo)


def _files_current(repo: Dict[str, str], files: Dict[str, Any]) -> bool:
    """True when the on-disk sources still match a built in-memory record."""
    current = scan_repo_files(repo, use_cache=False)
    if set(current) != set(files.keys()):
        return False
    # NOTE: rels come from our own validated scan, so plain join+stat here
    # (no per-file realpath) keeps this check at millisecond scale.
    for rel in current:
        try:
            st = os.stat(os.path.join(repo["path"], rel))
        except OSError:
            return False
        saved = files[rel]
        if st.st_mtime != saved.get("mtime") or st.st_size != saved.get("size"):
            return False
    return True


def ensure_repo_artifacts(repo_id: str) -> List[Tuple[str, str, Any, int]]:
    """Compiled rules for a repo: [(rel, engine, compiled, rule_count)].

    Rebuilt in memory only when sources changed. Explorer searches never
    touch this path; only scanners do.
    """
    rec = ensure_built(repo_id)
    if not rec:
        return []
    return list(rec.get("artifacts") or [])


# One corpus build at a time. A full index for every repository costs hundreds of
# MB; letting a status poll and a search build concurrently added their
# allocations together and pushed the process into the OOM killer.
_BUILD_GATE = threading.Semaphore(1)
_BG_LOCK = threading.Lock()
_BG_ACTIVE = False
_BG_LAST = 0.0
_BG_RETRY_S = 600


def schedule_background_build() -> bool:
    """Start a one-off background index build. Returns True when it started.

    Used by status endpoints so a page load never blocks on (or pays for) a full
    corpus compile: it reports what is already indexed and fills in the rest.
    """
    global _BG_ACTIVE, _BG_LAST
    if os.environ.get("MANTIS_YARA_BG_BUILD", "1").strip().lower() in ("0", "false", "no"):
        return False
    with _BG_LOCK:
        if _BG_ACTIVE:
            return False
        if time.time() - _BG_LAST < _BG_RETRY_S:
            # Do not restart the whole build on every status poll when a repo
            # keeps failing to index.
            return False
        _BG_ACTIVE = True
        _BG_LAST = time.time()

    def _run() -> None:
        global _BG_ACTIVE
        try:
            for repo in discover_repos():
                if _index_cache.get(repo["id"]) is not None:
                    continue
                try:
                    ensure_built(repo["id"])
                except Exception as e:  # pragma: no cover - defensive
                    logger.warning("background index build failed for %s: %s", repo["id"], e)
        finally:
            with _BG_LOCK:
                _BG_ACTIVE = False

    threading.Thread(target=_run, name="mantis-yara-index", daemon=True).start()
    return True


def index_snapshot(repo_id: str) -> Optional[Dict[str, Any]]:
    """Cached record for a repo, or None. Never builds."""
    return _index_cache.get(repo_id)


def ensure_built(repo_id: str) -> Optional[Dict[str, Any]]:
    """Return the built record for a repo, recompiling only on source change.

    Compiled rules live only in memory and are reused across scans; the
    .yar/.yara files on disk are the source of truth.
    """
    repos = {r["id"]: r for r in discover_repos()}
    repo = repos.get(repo_id)
    if not repo:
        return None
    with _repo_lock(repo_id):
        cached = _index_cache.get(repo_id)
        if cached is not None and not cached.get("index_only"):
            if (time.monotonic() - float(cached.get("checked_at", 0) or 0)) < _FRESHNESS_CHECK_TTL:
                return cached
            try:
                if _files_current(repo, cached.get("files", {})):
                    cached["checked_at"] = time.monotonic()
                    return cached
            except Exception:
                pass
        with _BUILD_GATE:
            # Another thread may have finished the build while we waited.
            cached = _index_cache.get(repo_id)
            if cached is not None:
                return cached
            return _build_repo(repo)


def ensure_indexed(repo_id: str) -> Optional[Dict[str, Any]]:
    """Ensure a repository has an index with verified rule compilation status."""
    return ensure_built(repo_id)


def ensure_all_built(max_workers: int = 4) -> Dict[str, Any]:
    repos = discover_repos()
    out = {}
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(repos) or 1)),
                            thread_name_prefix="mantis-yara-repos") as pool:
        futures = {pool.submit(ensure_built, r["id"]): r["id"] for r in repos}
        for fut in as_completed(futures):
            try:
                out[futures[fut]] = fut.result()
            except Exception as e:  # pragma: no cover - defensive
                logger.warning("repo build failed for %s: %s", futures[fut], e)
                out[futures[fut]] = None
    return out


def invalidate_repo(repo_id: str) -> None:
    with _repo_lock(repo_id):
        _index_cache.pop(repo_id, None)
        _scan_cache.pop(repo_id, None)


def get_record(repo_id: str) -> Optional[Dict[str, Any]]:
    return _index_cache.get(repo_id)


def engine_status(explorer_only: bool = False) -> Dict[str, Any]:
    repos = []
    totals = {"files": 0, "rules": 0, "valid": 0, "invalid": 0}
    last = ""
    discovered = discover_repos()
    visible = [r for r in discovered if not (explorer_only and is_explorer_hidden_repo(r))]
    for r in visible:
        # Cache only: reporting status must not compile the corpus.
        rec = index_snapshot(r["id"])
        st = rec["stats"] if rec else {"files": 0, "rules": 0, "valid": 0, "invalid": 0}
        for k in totals:
            totals[k] += int(st.get(k, 0))
        if rec and rec.get("built_at", "") > last:
            last = rec["built_at"]
        repos.append({"id": r["id"], "label": _repo_label(r["id"]), "path": r["path"],
                      "built": bool(rec), **{k: int(st.get(k, 0)) for k in ("files", "rules", "valid", "invalid")},
                      "last_compiled": rec.get("built_at", "") if rec else ""})
    pending = [r["id"] for r in visible if index_snapshot(r["id"]) is None]
    build_started = schedule_background_build() if pending else False
    return {
        "indexed_repositories": len(visible) - len(pending),
        "indexing_in_progress": build_started or bool(pending),
        "engine": "YARA-X" if yara_x_available() else "classic-libyara",
        "engines_available": available_engines(),
        "repositories": len(repos),
        "rule_files": totals["files"],
        "rules": totals["rules"],
        "valid": totals["valid"],
        "invalid": totals["invalid"],
        "last_compiled": last,
        "repos": repos,
        "hidden_repositories": len(discovered) - len(visible),
    }


# ---------------------------------------------------------------------------
# Explorer search (precomputed in-memory index; ranking mirrors Galaxy UX)
# ---------------------------------------------------------------------------
def _build_search_index(record: Dict[str, Any]) -> None:
    """Flatten a built record into a fast search index (lowered once)."""
    index = []
    repo = record.get("repo", {})
    repo_id = repo.get("id", "")
    repo_label = _repo_label(repo_id)
    for rel, entry in record.get("files", {}).items():
        rules = entry.get("index")
        if not rules:
            # No stored index (should not happen for fresh builds): parse once.
            abs_path = _safe_join(repo.get("path", ""), rel)
            try:
                with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                    parsed_rules = parse_rule_index(f.read())
            except OSError:
                parsed_rules = []
            rules = [{
                "n": pr.get("name", ""),
                "nl": str(pr.get("name", "")).lower(),
                "t": pr.get("tags", []) or [],
                "tl": [str(t).lower() for t in (pr.get("tags", []) or [])],
                "m": pr.get("meta", {}) if isinstance(pr.get("meta"), dict) else {},
                "mv": [str(v).lower() for v in (pr.get("meta", {}) if isinstance(pr.get("meta"), dict) else {}).values() if isinstance(v, (str, int))],
                "s": pr.get("strings", []) or [],
                "h": _haystack_for(pr.get("condition", ""),
                                   (pr.get("meta", {}) if isinstance(pr.get("meta"), dict) else {}).values(),
                                   pr.get("strings", []) or [], pr.get("literals", []) or []),
                "v": bool(pr.get("valid", True)),
                "e": list(pr.get("errors", []) or []),
            } for pr in parsed_rules]
        ns = entry.get("namespace", repo_id)
        file_lower = os.path.basename(rel).lower()
        for pr in rules:
            meta = pr.get("m", {}) if isinstance(pr.get("m"), dict) else {}
            index.append({
                "repo_id": repo_id,
                "repo_label": repo_label,
                "rel": rel,
                "file_lower": file_lower,
                "namespace": ns,
                "valid": bool(pr.get("v", True)),
                "errors": list(pr.get("e", []) or []),
                "name": pr.get("n", ""),
                "name_lower": pr.get("nl", ""),
                "tags": pr.get("t", []) or [],
                "tags_lower": pr.get("tl", []) or [],
                "meta": meta,
                "meta_vals_lower": pr.get("mv", []) or [],
                "strings": pr.get("s", []) or [],
                "haystack": pr.get("h", ""),
            })
    record["search_index"] = index


_QUERY_PHRASE_RE = re.compile(r'"([^"]+)"')


def _parse_search_query(query: str) -> List[str]:
    """Split a query into terms. Double-quoted spans stay literal phrases
    (spaces preserved, e.g. "This is a word"); the rest splits on
    whitespace. A stray unmatched quote is stripped, not searched."""
    terms: List[str] = []
    pos = 0
    for m in _QUERY_PHRASE_RE.finditer(query or ""):
        terms.extend(t.strip('"') for t in query[pos:m.start()].split())
        phrase = (m.group(1) or "").strip()
        if phrase:
            terms.append(phrase)
        pos = m.end()
    terms.extend(t.strip('"') for t in query[pos:].split())
    return [t for t in terms if t]


def _match_term_indexed(item: Dict[str, Any], term: str):
    """Rank one literal term (already lowered) against an index item."""
    return _rank_indexed(item, term)


def _match_term_regex(item: Dict[str, Any], rx) -> Optional[Tuple[int, str]]:
    """Rank one compiled regex against an index item (case-insensitive)."""
    if rx.search(item["name"] or ""):
        return 4, item["name"]
    for t in item["tags"]:
        if rx.search(t):
            return 5, t
    for raw in [str(v) for v in item["meta"].values() if isinstance(v, (str, int))]:
        if rx.search(raw):
            return 5, raw
    if rx.search(item["haystack"]):
        return 5, ""
    if rx.search(item["file_lower"]):
        return 5, os.path.basename(item["rel"])
    return None


def _rank_indexed(item: Dict[str, Any], q: str):
    nl = item["name_lower"]
    if q == nl:
        return 1, item["name"]
    for t, tl in zip(item["tags"], item["tags_lower"]):
        if q == tl:
            return 2, t
    for raw, low in zip([str(v) for v in item["meta"].values() if isinstance(v, (str, int))],
                        item["meta_vals_lower"]):
        if q == low:
            return 2, raw
    if nl.startswith(q):
        return 3, item["name"]
    if q in nl:
        return 4, item["name"]
    for t, tl in zip(item["tags"], item["tags_lower"]):
        if q in tl:
            return 5, t
    if q in item["haystack"]:
        return 5, ""
    if q in item["file_lower"]:
        return 5, os.path.basename(item["rel"])
    return None


def count_valid_rules(repo_id: str) -> int:
    """Number of compilable rules in a repo (what a scan actually covers)."""
    rec = ensure_built(repo_id)
    if not rec:
        return 0
    return sum(1 for item in (rec.get("search_index") or []) if item.get("valid"))


def search_rules(query: str, repo_id: str = "", limit: int = 100, offset: int = 0,
                 status: str = "all", repos: object = None,
                 use_regex: bool = False, include_hidden: bool = False) -> Dict[str, Any]:
    """Search the precomputed rule index (fast: no compiles, no reparsing).

    Query language: whitespace separates terms (AND); "double quoted" spans
    are literal phrases, spaces included. With use_regex=True every term is a
    case-insensitive regular expression instead of a literal substring.
    """
    try:
        limit = max(1, min(int(limit or 100), 500))
    except (TypeError, ValueError):
        limit = 100
    try:
        offset = max(0, int(offset or 0))
    except (TypeError, ValueError):
        offset = 0
    status = (status or "all").strip().lower()
    if status not in ("all", "valid", "invalid"):
        status = "all"
    terms = _parse_search_query(query)
    regexes = []
    if use_regex:
        for term in terms:
            try:
                regexes.append(re.compile(term, re.IGNORECASE))
            except re.error as e:
                return {"query": query, "total": 0, "results": [],
                        "error": f"Invalid regex {term!r}: {e}"}
    else:
        terms = [t.lower() for t in terms]
    # repos (multi-select) wins over the legacy single repo_id.
    wanted: Optional[set] = None
    if repos:
        wanted = {str(r).strip() for r in (repos if isinstance(repos, list) else str(repos).split(",")) if str(r).strip()}
    elif repo_id:
        wanted = {(repo_id or "").strip()}
    all_repos = discover_repos()
    visible_repos = all_repos if include_hidden else [r for r in all_repos if not is_explorer_hidden_repo(r)]
    if wanted is not None:
        all_ids = {r["id"] for r in all_repos}
        visible_ids = {r["id"] for r in visible_repos}
        hidden = sorted(w for w in wanted if w in all_ids and w not in visible_ids)
        if hidden:
            return {"query": query, "total": 0, "results": [],
                    "error": f"YARA repository is hidden from Rule Explorer: {hidden[0]}"}
        unknown = sorted(w for w in wanted if w not in all_ids)
        if unknown:
            return {"query": query, "total": 0, "results": [],
                    "error": f"Unknown YARA repository: {unknown[0]}"}
        targets = [r for r in visible_repos if r["id"] in wanted]
    else:
        targets = visible_repos
    hits = []
    for repo in targets:
        rec = ensure_indexed(repo["id"])
        if not rec:
            continue
        index = rec.get("search_index") or []
        for item in index:
            if is_rule_deleted(item.get("repo_id", repo["id"]), item.get("name", "")):
                continue
            if status == "valid" and not item["valid"]:
                continue
            if status == "invalid" and item["valid"]:
                continue
            if not terms:
                hits.append((8, "Browse", "", item))
                continue
            # Every term must match (AND); keep the best rank across terms so
            # exact name hits still sort above content hits.
            matchers = list(zip(terms, regexes)) if use_regex else [(t, None) for t in terms]
            best = None
            for term, rx in matchers:
                m = _match_term_regex(item, rx) if use_regex else _match_term_indexed(item, term)
                if m is None:
                    best = None
                    break
                if best is None or m[0] < best[0]:
                    best = m
            if best is None:
                continue
            rank_no, matched_value = best
            hits.append((rank_no,
                         {1: "Matched rule name", 2: "Matched tag/meta",
                          3: "Matched rule name", 4: "Matched rule name"}.get(rank_no, "Matched content"),
                         matched_value, item))
    hits.sort(key=lambda h: (h[0], h[3]["name"].lower()))
    results = []
    for rank_no, matched_on, matched_value, item in hits[offset:offset + limit]:
        results.append({
            "rule": item["name"],
            "repository": item["repo_id"],
            "repository_label": item["repo_label"],
            "collection": collection_label(item["rel"]),
            "namespace": item["namespace"],
            "file": item["rel"],
            "tags": item["tags"],
            "meta": item["meta"],
            "strings": item["strings"],
            "compile_status": "valid" if item["valid"] else "invalid",
            "compile_errors": item["errors"],
            "match_rank": rank_no,
            "matched_on": matched_on,
            "matched_value": matched_value,
        })
    return {"query": query, "total": len(hits), "limit": limit, "offset": offset,
            "status": status, "results": results}


def get_rule_source(repo_id: str, rule_name: str, namespace: str = "") -> Dict[str, Any]:
    if is_rule_deleted(repo_id, rule_name):
        return {"error": f"Rule '{rule_name}' has been deleted."}
    repos = {r["id"]: r for r in discover_repos()}
    if repo_id not in repos:
        return {"error": f"Unknown YARA repository: {repo_id}"}
    rec = ensure_indexed(repo_id)
    if not rec:
        return {"error": f"Repository unavailable: {repo_id}"}
    for rel, entry in rec["files"].items():
        if namespace and entry.get("namespace") != namespace:
            continue
        # Candidate check against the lean index first (no file I/O).
        names = {r.get("n") for r in (entry.get("index") or [])}
        if names and rule_name not in names:
            continue
        # Re-parse just this one file for the full source block.
        abs_path = _safe_join(repos[repo_id]["path"], rel)
        try:
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                parsed = parse_rule_index(f.read())
        except OSError:
            continue
        saved = {r.get("n"): r for r in (entry.get("index") or [])}
        for pr in parsed:
            if pr["name"] == rule_name:
                saved_rule = saved.get(rule_name, {})
                rule_valid = saved_rule.get("v", True)
                rule_errors = saved_rule.get("e", [])

                # On-demand authoritative compile validation of the single rule source
                src_to_check = pr.get("source", "").strip()
                if src_to_check:
                    _, comp, compile_errs = _compile_file(repo_id, entry.get("namespace", repo_id), src_to_check)
                    if comp is None:
                        rule_valid = False
                        rule_errors = compile_errs
                    else:
                        rule_valid = True
                        rule_errors = []

                return {
                    "rule": rule_name,
                    "repository": repo_id,
                    "repository_label": _repo_label(repo_id),
                    "collection": collection_label(rel),
                    "namespace": entry.get("namespace", repo_id),
                    "file": rel,
                    "tags": pr.get("tags", []),
                    "meta": pr.get("meta", {}),
                    "strings": pr.get("strings", []),
                    "condition": pr.get("condition", ""),
                    "source": pr.get("source", ""),
                    "compile_status": "valid" if rule_valid else "invalid",
                    "compile_errors": list(rule_errors or []),
                }
    return {"error": f"Rule not found: {rule_name}"}


def delete_rule(repo_id: str, rule_name: str, file_rel: str = "") -> Dict[str, Any]:
    """Permanently delete a rule from disk and record in tombstones so updates never add it back."""
    repos = {r["id"]: r for r in discover_repos()}
    if repo_id not in repos:
        return {"error": f"Unknown repository: {repo_id}", "status": 404}

    repo_path = repos[repo_id]["path"]
    target_rel = file_rel

    if not target_rel:
        rec = ensure_indexed(repo_id)
        if rec:
            for rel, entry in rec.get("files", {}).items():
                names = {r.get("n") for r in (entry.get("index") or [])}
                if rule_name in names:
                    target_rel = rel
                    break

    add_tombstone(repo_id, rule_name, target_rel or "")

    file_deleted = False
    rule_removed_from_file = False

    if target_rel:
        abs_path = _safe_join(repo_path, target_rel)
        if abs_path and os.path.isfile(abs_path):
            try:
                with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()

                heads = list(RULE_HEAD_RE.finditer(content))
                if len(heads) <= 1:
                    try:
                        os.remove(abs_path)
                        file_deleted = True
                    except OSError as e:
                        logger.warning("Could not delete file %s: %s", abs_path, e)
                else:
                    for i, m in enumerate(heads):
                        if m.group(1) == rule_name:
                            start = m.start()
                            end = heads[i + 1].start() if i + 1 < len(heads) else len(content)
                            new_content = content[:start].rstrip() + "\n\n" + content[end:].lstrip()
                            with open(abs_path, "w", encoding="utf-8", newline="\n") as f:
                                f.write(new_content)
                            rule_removed_from_file = True
                            break
            except Exception as e:
                logger.error("Error modifying rule file %s: %s", abs_path, e)

    invalidate_repo(repo_id)
    return {
        "ok": True,
        "repo": repo_id,
        "rule": rule_name,
        "file": target_rel,
        "file_deleted": file_deleted,
        "rule_removed": rule_removed_from_file,
        "tombstoned": True,
    }


def _explorer_targets(repo_ids: List[str]) -> List[Dict[str, str]]:
    visible = {r["id"]: r for r in discover_explorer_repos()}
    if not repo_ids:
        return list(visible.values())
    unknown = [r for r in repo_ids if r not in visible]
    if unknown:
        raise ValueError(f"Unknown or hidden YARA repository: {unknown[0]}")
    return [visible[r] for r in dict.fromkeys(repo_ids)]


def export_valid_rules(repo_ids: List[str]) -> Tuple[str, int]:
    """Build a ZIP containing only indexed, non-deleted rules that compile."""
    targets = _explorer_targets(repo_ids)
    tmp = tempfile.NamedTemporaryFile(prefix="mantis-yara-", suffix=".zip", delete=False)
    path = tmp.name
    tmp.close()
    count = 0
    try:
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            for repo in targets:
                with _repo_lock(repo["id"]):
                    invalidate_repo(repo["id"])
                    record = ensure_indexed(repo["id"])
                    if not record:
                        raise RuntimeError(f"Could not index repository: {repo['id']}")
                    for rel, entry in record["files"].items():
                        allowed = {r["n"] for r in entry.get("index", [])
                                   if r.get("v") and not is_rule_deleted(repo["id"], r["n"])}
                        if not allowed:
                            continue
                        source_path = _safe_join(repo["path"], rel)
                        if not source_path or not os.path.isfile(source_path):
                            raise RuntimeError(f"Rule file is unavailable: {repo['id']}/{rel}")
                        with open(source_path, "r", encoding="utf-8", errors="replace") as f:
                            source = f.read()
                        heads = list(RULE_HEAD_RE.finditer(source))
                        blocks = [source[head.start():heads[i + 1].start() if i + 1 < len(heads) else len(source)]
                                  for i, head in enumerate(heads) if head.group(1) in allowed]
                        if not blocks:
                            continue
                        # Preserve file-level imports and declarations before the first rule.
                        prefix = source[:heads[0].start()] if heads else ""
                        archive.writestr(f"{repo['id'].replace(':', '_')}/{rel.replace(os.sep, '/')}",
                                         prefix + "\n\n".join(blocks))
                        count += len(blocks)
        return path, count
    except Exception:
        os.unlink(path)
        raise


def delete_invalid_rules(repo_ids: List[str]) -> Dict[str, Any]:
    """Remove only rules marked invalid by a fresh compile of selected repositories."""
    targets = _explorer_targets(repo_ids)
    removed = 0
    for repo in targets:
        with _repo_lock(repo["id"]):
            invalidate_repo(repo["id"])
            record = ensure_indexed(repo["id"])
            if not record:
                raise RuntimeError(f"Could not index repository: {repo['id']}")
            pending = [(rel, r["n"]) for rel, entry in record["files"].items()
                       for r in entry.get("index", [])
                       if not r.get("v") and not is_rule_deleted(repo["id"], r["n"])]
            for rel, name in pending:
                delete_rule(repo["id"], name, rel)
                removed += 1
    return {"deleted": removed}


def save_rule_in_repo(repo_id: str, file_rel: str, source: str, rule_name: str = "", is_new: bool = False, overwrite: bool = True) -> Dict[str, Any]:
    """Create or update a YARA rule directly in the repository without going to Workbench."""
    if not (source or "").strip():
        return {"error": "Cannot save an empty rule", "status": 400}

    parsed = parse_rule_index(source)
    if not parsed:
        return {"error": "Rule source does not contain any valid YARA rule declaration", "status": 400}

    actual_rule_name = parsed[0]["name"]
    rule_name_to_save = rule_name or actual_rule_name

    from yara_service import workbench_validate
    val = workbench_validate(source)
    if not val.get("valid"):
        err_msg = "; ".join(e.get("message", "syntax error") for e in val.get("errors", []))
        return {"error": f"Rule compilation failed: {err_msg}", "status": 400, "compile_errors": val.get("errors", [])}

    repos = {r["id"]: r for r in discover_repos()}
    if not repo_id:
        repo_id = "custom"
    if repo_id not in repos:
        if repo_id == "custom":
            os.makedirs(YARA_CUSTOM_DIR, exist_ok=True)
            repos = {r["id"]: r for r in discover_repos()}
        else:
            return {"error": f"Unknown repository: {repo_id}", "status": 400}

    repo_path = repos[repo_id]["path"]

    target_rel = file_rel.strip() if file_rel else ""
    if is_new or not target_rel:
        if not target_rel:
            safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", actual_rule_name)
            target_rel = f"{safe_name}.yar"
        if not target_rel.lower().endswith(RULE_EXTS):
            target_rel += ".yar"

    abs_path = _safe_join(repo_path, target_rel)
    if not abs_path:
        return {"error": "Invalid file path (path traversal blocked)", "status": 400}

    os.makedirs(os.path.dirname(abs_path), exist_ok=True)

    if is_new:
        if os.path.exists(abs_path) and not overwrite:
            return {"error": f"File '{target_rel}' already exists in {repo_id}", "status": 409, "exists": True}
        with open(abs_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(source.strip() + "\n")
    else:
        if os.path.exists(abs_path):
            with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            heads = list(RULE_HEAD_RE.finditer(content))
            if len(heads) <= 1:
                with open(abs_path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(source.strip() + "\n")
            else:
                replaced = False
                for i, m in enumerate(heads):
                    if m.group(1) == rule_name_to_save or m.group(1) == actual_rule_name:
                        start = m.start()
                        end = heads[i + 1].start() if i + 1 < len(heads) else len(content)
                        new_content = content[:start].rstrip() + "\n\n" + source.strip() + "\n\n" + content[end:].lstrip()
                        with open(abs_path, "w", encoding="utf-8", newline="\n") as f:
                            f.write(new_content)
                        replaced = True
                        break
                if not replaced:
                    with open(abs_path, "a", encoding="utf-8", newline="\n") as f:
                        f.write("\n\n" + source.strip() + "\n")
        else:
            with open(abs_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(source.strip() + "\n")

    remove_tombstone(repo_id, actual_rule_name)
    if rule_name_to_save != actual_rule_name:
        remove_tombstone(repo_id, rule_name_to_save)

    invalidate_repo(repo_id)
    return {
        "saved": True,
        "repo": repo_id,
        "rule": actual_rule_name,
        "file": target_rel,
        "compile_status": "valid"
    }


# ---------------------------------------------------------------------------
# Corpus directories (approved roots only)
# ---------------------------------------------------------------------------
def corpus_roots() -> List[Dict[str, str]]:
    roots: List[Dict[str, str]] = []
    seen = set()

    def add(label: str, path: str):
        try:
            real = os.path.realpath(os.path.abspath(os.path.expanduser(path)))
        except Exception:
            return
        if real in seen or not os.path.isdir(real):
            return
        seen.add(real)
        roots.append({"id": f"corpus-{len(roots)}", "label": label, "path": real})

    if os.path.isdir(DEFAULT_CORPUS_DIR):
        add("Default corpus", DEFAULT_CORPUS_DIR)
    for chunk in os.environ.get("MANTIS_YARA_CORPUS_DIRS", "").split(os.pathsep):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" in chunk:
            label, path = chunk.split("=", 1)
            add(label.strip() or os.path.basename(path), path)
        else:
            add(os.path.basename(os.path.abspath(chunk)) or chunk, chunk)
    return roots


def resolve_corpus_root(corpus_id: str) -> Optional[Dict[str, str]]:
    for root in corpus_roots():
        if root["id"] == corpus_id:
            return root
    return None


def iter_corpus_files(root_path: str, max_files: int = 2000, max_depth: int = 6,
                      max_total_bytes: int = 4 * 1024 * 1024 * 1024):
    """Yield (relpath, abspath, size) safely: no escapes, no symlink leaks."""
    base = os.path.realpath(root_path)
    total = 0
    count = 0
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        try:
            depth = os.path.relpath(os.path.realpath(dirpath), base).count(os.sep)
        except ValueError:
            dirnames[:] = []
            continue
        if depth > max_depth:
            dirnames[:] = []
            continue
        # Prune symlinked / escaping directories.
        kept = []
        for d in sorted(dirnames):
            full = os.path.join(dirpath, d)
            try:
                real = os.path.realpath(full)
                if os.path.commonpath([base, real]) == base and os.path.isdir(real):
                    kept.append(d)
            except (OSError, ValueError):
                continue
        dirnames[:] = kept
        for fn in sorted(filenames):
            if count >= max_files:
                return
            full = os.path.join(dirpath, fn)
            try:
                if not os.path.isfile(full) or os.path.islink(full):
                    continue
                real = os.path.realpath(full)
                if os.path.commonpath([base, real]) != base:
                    continue
                size = os.path.getsize(real)
            except (OSError, ValueError):
                continue
            if total + size > max_total_bytes:
                return
            total += size
            count += 1
            yield os.path.relpath(real, base), real, size
