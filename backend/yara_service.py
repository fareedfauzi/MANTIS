"""YARA analyst workflows: sample scanning, match inspection, Workbench,
corpus testing. All operations are local-only: nothing is ever submitted to
external providers. Samples are treated as untrusted binary data and are
never executed. Uploads are scanned in memory and never written to disk.
"""

import hashlib
import logging
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from yara_engine import EngineCompileError, ScanTimeout, get_engine
from yara_repos import (
    YARA_CUSTOM_DIR,
    discover_repos,
    ensure_repo_artifacts,
    invalidate_repo,
    resolve_corpus_root,
    iter_corpus_files,
    _repo_label,
    _safe_join,
)

logger = logging.getLogger("mantis.yara.service")

# ---------------------------------------------------------------------------
# Resource limits (overridable via environment)
# ---------------------------------------------------------------------------
def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


MAX_UPLOAD_BYTES = _int_env("MANTIS_YARA_MAX_UPLOAD_BYTES", 64 * 1024 * 1024)
MAX_CORPUS_FILES = _int_env("MANTIS_YARA_MAX_CORPUS_FILES", 2000)
MAX_CORPUS_DEPTH = _int_env("MANTIS_YARA_MAX_CORPUS_DEPTH", 6)
MAX_CORPUS_BYTES = _int_env("MANTIS_YARA_MAX_CORPUS_BYTES", 4 * 1024 * 1024 * 1024)
ENGINE_TIMEOUT_S = _int_env("MANTIS_YARA_ENGINE_TIMEOUT", 30)
SCAN_TIMEOUT_S = _int_env("MANTIS_YARA_SCAN_TIMEOUT", 120)
MAX_CONCURRENT_SCANS = _int_env("MANTIS_YARA_MAX_CONCURRENT_SCANS", 2)
MATCH_CONTEXT_BYTES = _int_env("MANTIS_YARA_MATCH_CONTEXT", 96)
MAX_MATCH_OCCURRENCES = _int_env("MANTIS_YARA_MAX_OCCURRENCES", 10)
MAX_WORKBENCH_BYTES = _int_env("MANTIS_YARA_MAX_WORKBENCH_BYTES", 2 * 1024 * 1024)
MAX_CORPUS_FILE_BYTES = _int_env("MANTIS_YARA_MAX_CORPUS_FILE_BYTES", 256 * 1024 * 1024)
MAX_TEST_FILES = _int_env("MANTIS_YARA_MAX_TEST_FILES", 200)
MAX_TEST_BYTES = _int_env("MANTIS_YARA_MAX_TEST_BYTES", 512 * 1024 * 1024)
MAX_OFFSETS_PER_FILE = 200

_scan_semaphore = threading.Semaphore(max(1, MAX_CONCURRENT_SCANS))

SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}\.yar(a)?$")


def scan_limits() -> Dict[str, Any]:
    return {
        "max_upload_bytes": MAX_UPLOAD_BYTES,
        "max_corpus_files": MAX_CORPUS_FILES,
        "max_corpus_depth": MAX_CORPUS_DEPTH,
        "engine_timeout_s": ENGINE_TIMEOUT_S,
        "scan_timeout_s": SCAN_TIMEOUT_S,
        "max_concurrent_scans": MAX_CONCURRENT_SCANS,
    }


# ---------------------------------------------------------------------------
# Scanning (shared by Sample Scanner, Workbench tests, corpus testing)
# ---------------------------------------------------------------------------
def _resolve_repos(repo_ids: Optional[List[str]]) -> List[Dict[str, Any]]:
    repos = discover_repos()
    if repo_ids:
        wanted = {r.strip().lower() for r in repo_ids if r and str(r).strip()}
        repos = [r for r in repos if r["id"].lower() in wanted or r["label"].lower() in wanted]
    return repos


def _artifacts_for(repo_ids: Optional[List[str]]) -> List[Tuple[str, str, str, Any, int]]:
    """[(rel, repo_id, engine_name, compiled, rule_count)] for requested repos."""
    out = []
    for repo in _resolve_repos(repo_ids):
        for rel, engine, compiled, n_rules in ensure_repo_artifacts(repo["id"]):
            out.append((rel, repo["id"], engine, compiled, n_rules))
    return out


def _engine_for(name: str):
    return get_engine("yarax" if name == "yarax" else "classic")


SCAN_FANOUT_WORKERS = _int_env("MANTIS_YARA_SCAN_WORKERS", 4)


def _scan_one_bytes(args) -> Tuple[List[Dict[str, Any]], str, int]:
    rel, repo_id, engine_name, compiled, n_rules, data, timeout = args
    try:
        from yara_repos import collection_label
        eng = _engine_for(engine_name)
        out = []
        for m in eng.scan_bytes(compiled, data, timeout=timeout):
            m["repository"] = repo_id
            m["repository_label"] = _repo_label(repo_id)
            m["collection"] = collection_label(rel)
            m["rule_file"] = rel
            m["engine"] = eng.name
            out.append(m)
        return out, "", n_rules
    except ScanTimeout:
        return [], f"{repo_id}: scan timeout", 0
    except Exception as e:
        return [], f"{repo_id}: {type(e).__name__}: {e}", 0


def scan_data(data: bytes, artifacts, timeout: int = 0) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Scan bytes with prebuilt artifacts (fanned out). Returns (matches, stats)."""
    timeout = timeout or ENGINE_TIMEOUT_S
    t0 = time.monotonic()
    matches: List[Dict[str, Any]] = []
    errors: List[str] = []
    rules_scanned = 0
    if not artifacts:
        return matches, {"rules_scanned": 0, "errors": errors,
                         "scan_s": round(time.monotonic() - t0, 3)}
    workers = max(1, min(SCAN_FANOUT_WORKERS, len(artifacts)))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="mantis-yara-scan") as pool:
        futures = [pool.submit(_scan_one_bytes, (rel, repo_id, eng_name, compiled, n_rules, data, timeout))
                   for rel, repo_id, eng_name, compiled, n_rules in artifacts]
        for fut in as_completed(futures):
            try:
                found, err, n = fut.result()
            except Exception as e:  # pragma: no cover - defensive
                found, err, n = [], f"scan worker crashed: {e}", 0
            matches.extend(found)
            if err:
                errors.append(err)
            rules_scanned += n
    # Deterministic order: rule name, then offset.
    matches.sort(key=lambda m: (m.get("rule", "").lower(),
                                min([s["offset"] for s in m.get("strings", [])] or [0])))
    return matches, {"rules_scanned": rules_scanned, "errors": errors,
                     "scan_s": round(time.monotonic() - t0, 3)}


def scan_file_local(path: str, artifacts, timeout: int = 0):
    """Scan a server-local file with prebuilt 5-tuple artifacts
    (rel, repo_id, engine, compiled, rule_count) as yielded by
    `_artifacts_for`. Returns (matches, stats) like `scan_data`."""
    from yara_repos import collection_label
    timeout = timeout or ENGINE_TIMEOUT_S
    t0 = time.monotonic()
    matches: List[Dict[str, Any]] = []
    errors: List[str] = []
    rules_scanned = 0
    for rel, repo_id, engine_name, compiled, n_rules in artifacts:
        try:
            eng = _engine_for(engine_name)
            for m in eng.scan_file(compiled, path, timeout=timeout):
                m["repository"] = repo_id
                m["repository_label"] = _repo_label(repo_id)
                m["collection"] = collection_label(rel)
                m["rule_file"] = rel
                m["engine"] = eng.name
                matches.append(m)
            rules_scanned += n_rules
        except ScanTimeout:
            errors.append(f"{repo_id}: scan timeout")
        except Exception as e:
            errors.append(f"{repo_id}: {type(e).__name__}: {e}")
    matches.sort(key=lambda m: (m.get("rule", "").lower(),
                                min([s["offset"] for s in m.get("strings", [])] or [0])))
    return matches, {"rules_scanned": rules_scanned, "errors": errors,
                     "scan_s": round(time.monotonic() - t0, 3)}


def hash_sample(data: bytes, filename: str) -> Dict[str, Any]:
    return {
        "filename": filename,
        "size": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _hex_ascii(chunk: bytes) -> Tuple[str, str]:
    return (" ".join(f"{b:02X}" for b in chunk),
            "".join(chr(b) if 32 <= b < 127 else "." for b in chunk))


def match_context(data: bytes, offset: int, length: int,
                  before: Optional[int] = None, after: Optional[int] = None) -> Dict[str, Any]:
    """Hex/ASCII view of one match (+ optional context) from known bytes."""
    before = MATCH_CONTEXT_BYTES if before is None else max(0, before)
    after = MATCH_CONTEXT_BYTES if after is None else max(0, after)
    size = len(data)
    start = max(0, offset - before)
    end = min(size, offset + length + after)
    matched = data[offset:offset + length] if 0 <= offset < size else b""
    hex_s, ascii_s = _hex_ascii(matched)
    ctx_b, ctx_b_a = _hex_ascii(data[start:offset])
    ctx_a, ctx_a_a = _hex_ascii(data[offset + length:end])
    return {
        "offset": offset,
        "offset_hex": f"0x{offset:X}",
        "length": length,
        "hex": hex_s,
        "ascii": ascii_s,
        "context_before": {"offset_hex": f"0x{start:X}", "hex": ctx_b, "ascii": ctx_b_a},
        "context_after": {"offset_hex": f"0x{offset + length:X}", "hex": ctx_a, "ascii": ctx_a_a},
    }


def read_range(path: str, offset: int, length: int) -> bytes:
    """Read one byte range from disk without loading the whole file."""
    with open(path, "rb") as f:
        f.seek(max(0, offset))
        return f.read(max(0, length))


def match_context_file(path: str, size: int, offset: int, length: int) -> Dict[str, Any]:
    before, after = MATCH_CONTEXT_BYTES, MATCH_CONTEXT_BYTES
    start = max(0, offset - before)
    end = min(size, offset + length + after)
    blob = read_range(path, start, end - start)
    base = offset - start
    matched = blob[base:base + length]
    hex_s, ascii_s = _hex_ascii(matched)
    ctx_b, ctx_b_a = _hex_ascii(blob[:base])
    ctx_a, ctx_a_a = _hex_ascii(blob[base + length:])
    return {
        "offset": offset, "offset_hex": f"0x{offset:X}", "length": length,
        "hex": hex_s, "ascii": ascii_s,
        "context_before": {"offset_hex": f"0x{start:X}", "hex": ctx_b, "ascii": ctx_b_a},
        "context_after": {"offset_hex": f"0x{offset + length:X}", "hex": ctx_a, "ascii": ctx_a_a},
    }


def enrich_matches(data: Optional[bytes], matches: List[Dict[str, Any]],
                   path: str = "", size: int = 0) -> List[Dict[str, Any]]:
    """Attach inline byte views (capped occurrences per string)."""
    for m in matches:
        by_string: Dict[str, List[Dict[str, Any]]] = {}
        for s in m.get("strings", []):
            off, ln = int(s.get("offset", 0)), int(s.get("length", 0))
            try:
                if data is not None:
                    view = match_context(data, off, ln)
                else:
                    view = match_context_file(path, size, off, ln)
            except (OSError, ValueError) as e:
                view = {"offset": off, "offset_hex": f"0x{off:X}", "length": ln,
                        "error": f"unreadable: {e}"}
            view["id"] = s.get("id", "")
            by_string.setdefault(s.get("id", ""), []).append(view)
        # Cap stored occurrences per string id (counts below use everything).
        m["string_views"] = {sid: views[:MAX_MATCH_OCCURRENCES] for sid, views in by_string.items()}
        m["string_counts"] = {sid: len(views) for sid, views in by_string.items()}
    return matches


def scan_upload(data: bytes, filename: str, repo_ids: Optional[List[str]]) -> Dict[str, Any]:
    t0 = time.monotonic()
    with _scan_semaphore:
        selected = [str(r).strip() for r in (repo_ids or []) if str(r or "").strip()]
        if selected:
            known = {r["id"].lower(): r["id"] for r in discover_repos()}
            unknown = sorted(r for r in selected if r.lower() not in known)
            if unknown:
                return {"error": f"Unknown YARA repository: {unknown[0]}",
                        "status": 400}
        artifacts = _artifacts_for(repo_ids)
        if repo_ids and not artifacts:
            wanted = ", ".join(sorted({str(r).strip() for r in repo_ids if str(r or "").strip()}))
            return {"error": f"No compiled YARA rules available for selected repositories: {wanted or '?'}",
                    "status": 400}
        matches, stats = scan_data(data, artifacts)
        matches = enrich_matches(data, matches)
    repo_labels = {r["id"]: r["label"] for r in discover_repos()}
    repo_summary: Dict[str, Dict[str, Any]] = {}
    for rel, repo_id, engine_name, _compiled, n_rules in artifacts:
        row = repo_summary.setdefault(repo_id, {
            "id": repo_id,
            "label": repo_labels.get(repo_id, _repo_label(repo_id)),
            "files": 0,
            "rules_scanned": 0,
            "matches": 0,
            "engines": set(),
        })
        row["files"] += 1
        row["rules_scanned"] += int(n_rules or 0)
        if engine_name:
            row["engines"].add(engine_name)
    for m in matches:
        repo_id = m.get("repository") or ""
        if repo_id in repo_summary:
            repo_summary[repo_id]["matches"] += 1
    for err in stats["errors"]:
        repo_id = str(err).split(":", 1)[0].strip()
        row = repo_summary.setdefault(repo_id, {
            "id": repo_id,
            "label": repo_labels.get(repo_id, _repo_label(repo_id)),
            "files": 0,
            "rules_scanned": 0,
            "matches": 0,
            "engines": set(),
        })
        row.setdefault("errors", []).append(err)
    repositories = []
    for row in repo_summary.values():
        repositories.append({
            **row,
            "engines": sorted(row.get("engines") or []),
            "errors": list(row.get("errors") or []),
        })
    repositories.sort(key=lambda r: str(r.get("label") or r.get("id") or "").lower())
    return {
        **hash_sample(data, filename),
        "engine": "YARA-X+classic",
        "repositories": sorted({a[1] for a in artifacts}),
        "repository_stats": repositories,
        "rules_loaded": sum(int(a[4] or 0) for a in artifacts),
        "rules_scanned": stats["rules_scanned"],
        "matched_rules": len(matches),
        "scan_duration_s": round(time.monotonic() - t0, 3),
        "errors": stats["errors"],
        "matches": matches,
    }


# ---------------------------------------------------------------------------
# Workbench
# ---------------------------------------------------------------------------
def workbench_validate(source: str) -> Dict[str, Any]:
    """Temporary isolated compilation. Touches no repository or cache."""
    errors: List[Dict[str, Any]] = []
    engine_used = ""
    try:
        engine_used = "YARA-X"
        errors = get_engine("yarax").validate(source or "")
    except RuntimeError:
        engine_used = "classic-libyara"
        try:
            errors = get_engine("classic").validate(source or "")
        except RuntimeError as e:
            return {"valid": False, "engine": "none",
                    "errors": [{"message": str(e)}]}
    if errors and engine_used == "YARA-X":
        # Offer the classic verdict too so analysts see whether the rule is
        # salvageable by the fallback engine (informational only).
        try:
            classic_errors = get_engine("classic").validate(source or "")
            return {"valid": False, "engine": engine_used, "errors": errors,
                    "classic_errors": classic_errors,
                    "classic_valid": not classic_errors}
        except RuntimeError:
            pass
    return {"valid": not errors, "engine": engine_used, "errors": errors}


def writable_repos() -> List[Dict[str, str]]:
    """Repositories analysts may save into (never third-party bundles)."""
    out = []
    for repo in discover_repos():
        if repo["id"] in ("custom", "internal") or repo["id"].startswith("extra::"):
            out.append({"id": repo["id"], "label": _repo_label(repo["id"])})
    if not any(r["id"] == "custom" for r in out):
        out.insert(0, {"id": "custom", "label": _repo_label("custom")})
    return out


def workbench_save(repo_id: str, filename: str, source: str, overwrite: bool = False) -> Dict[str, Any]:
    allowed = {r["id"] for r in writable_repos()}
    if repo_id not in allowed:
        return {"error": f"Repository is not writable: {repo_id}", "status": 400}
    if not (source or "").strip():
        return {"error": "Cannot save an empty rule", "status": 400}
    if len((source or "").encode("utf-8", "replace")) > MAX_WORKBENCH_BYTES:
        return {"error": f"Rule source exceeds {MAX_WORKBENCH_BYTES} bytes", "status": 400}
    if not SAFE_FILENAME_RE.match(filename or ""):
        return {"error": "Invalid filename (use A-Za-z0-9_.- ending in .yar/.yara)", "status": 400}
    repos = {r["id"]: r for r in discover_repos()}
    repo = repos.get(repo_id)
    if not repo:
        return {"error": f"Unknown repository: {repo_id}", "status": 400}
    if repo_id == "custom":
        try:
            os.makedirs(YARA_CUSTOM_DIR, exist_ok=True)
        except OSError as e:
            return {"error": f"Cannot create custom repo: {e}", "status": 500}
        repo = {"id": "custom", "label": _repo_label("custom"), "path": YARA_CUSTOM_DIR}
    target = _safe_join(repo["path"], filename)
    if not target or os.path.basename(target) != filename:
        return {"error": "Path traversal blocked", "status": 400}
    if os.path.exists(target) and not overwrite:
        return {"error": f"Refusing to overwrite existing rule without explicit overwrite: {filename}",
                "status": 409, "exists": True}
    try:
        with open(target, "w", encoding="utf-8", newline="\n") as f:
            f.write(source or "")
    except OSError as e:
        return {"error": f"Write failed: {e}", "status": 500}
    # Invalidate only; the collection rebuilds lazily on next search/scan so
    # the save request never blocks on a full recompile.
    invalidate_repo(repo_id)
    return {"saved": True, "repository": repo_id, "file": filename, "overwritten": bool(overwrite),
            "rebuild": "pending"}


# ---------------------------------------------------------------------------
# Corpus testing
# ---------------------------------------------------------------------------
def _compile_workbench_source(source: str):
    """Compile Workbench source in isolation (never touches the cache)."""
    last_errors: List[Dict[str, Any]] = []
    for prefer in ("yarax", "classic"):
        try:
            eng = get_engine(prefer)
        except RuntimeError:
            continue
        try:
            return eng, eng.compile({"workbench": source or ""})
        except EngineCompileError as e:
            last_errors = e.errors
            continue
    raise EngineCompileError(last_errors or [{"message": "no YARA engine available"}])


def _file_md5_bytes(data: bytes) -> str:
    try:
        return hashlib.md5(data).hexdigest()
    except Exception:
        return ""


def _summarize_test_run(files_out, string_hits, n_files, truncated):
    """Shared stats/coverage rollup for corpus and upload test runs."""
    coverage = []
    for sid, per_file in sorted(string_hits.items()):
        n = len(per_file)
        coverage.append({
            "string": sid,
            "files_matched": n,
            "total_files": n_files,
            "coverage": round(100.0 * n / n_files, 1) if n_files else 0.0,
            "samples": [{"file": f, "offsets": sorted(o)[:MAX_MATCH_OCCURRENCES]} for f, o in
                        sorted(per_file.items())],
        })
    coverage.sort(key=lambda c: (-c["files_matched"], c["string"]))
    detected = sum(1 for f in files_out if f.get("match"))
    undetected = sum(1 for f in files_out if not f.get("match") and not f.get("error"))
    errored = sum(1 for f in files_out if f.get("error"))
    total = len(files_out)
    return {
        "files": files_out, "total_files": n_files,
        "detected": detected, "undetected": undetected, "errored": errored,
        "detection_rate": round(100.0 * detected / total, 2) if total else 0.0,
        "string_coverage": coverage, "truncated": truncated,
    }


def corpus_test(source: str, corpus_id: str, negative_id: str = "",
                max_files: int = 0, per_file_timeout: int = 0) -> Dict[str, Any]:
    t0 = time.monotonic()
    deadline = t0 + (SCAN_TIMEOUT_S or 120)
    try:
        eng, compiled = _compile_workbench_source(source)
        engine_name = eng.name
    except EngineCompileError as e:
        return {"error": "Workbench rule does not compile", "compile_errors": e.errors,
                "status": 400}
    root = resolve_corpus_root(corpus_id or "")
    if not root:
        return {"error": f"Unknown corpus: {corpus_id}", "status": 400}
    neg_root = resolve_corpus_root(negative_id) if negative_id else None
    if negative_id and not neg_root:
        return {"error": f"Unknown negative corpus: {negative_id}", "status": 400}

    def run_set(root_path: str):
        files_out = []
        string_hits: Dict[str, Dict[str, List[int]]] = {}
        n_files = 0
        truncated = False
        for rel, abs_path, size in iter_corpus_files(
                root_path, max_files=max_files or MAX_CORPUS_FILES,
                max_depth=MAX_CORPUS_DEPTH, max_total_bytes=MAX_CORPUS_BYTES):
            if time.monotonic() > deadline:
                truncated = True
                break
            n_files += 1
            if size > MAX_CORPUS_FILE_BYTES:
                files_out.append({"file": rel, "size": size, "md5": "", "match": False,
                                  "error": f"Skipped: exceeds {MAX_CORPUS_FILE_BYTES} bytes"})
                continue
            file_md5 = ""
            try:
                digest = hashlib.md5()
                with open(abs_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4 * 1024 * 1024), b""):
                        digest.update(chunk)
                file_md5 = digest.hexdigest()
            except OSError as e:
                files_out.append({"file": rel, "size": size, "md5": "",
                                  "match": False, "error": f"unreadable: {e}"[:200]})
                continue
            try:
                matches = eng.scan_file(compiled, abs_path, timeout=per_file_timeout or ENGINE_TIMEOUT_S)
                hit = bool(matches)
            except ScanTimeout:
                matches, hit = [], False
                files_out.append({"file": rel, "size": size, "md5": file_md5,
                                  "match": False, "timeout": True})
                continue
            except Exception as e:
                files_out.append({"file": rel, "size": size, "md5": file_md5,
                                  "match": False, "error": str(e)[:200]})
                continue
            for m in matches:
                for s in m.get("strings", []):
                    sid = s.get("id", "")
                    bucket = string_hits.setdefault(sid, {}).setdefault(rel, [])
                    if len(bucket) < MAX_OFFSETS_PER_FILE:
                        bucket.append(int(s.get("offset", 0)))
            files_out.append({"file": rel, "size": size, "md5": file_md5, "match": hit,
                              "rules": sorted({m.get("rule", "") for m in matches})})
        return _summarize_test_run(files_out, string_hits, n_files, truncated)

    pos = run_set(root["path"])
    out: Dict[str, Any] = {
        "engine": engine_name,
        "corpus": {"id": root["id"], "label": root["label"]},
        "positive": pos,
        "scan_duration_s": 0.0,
    }
    if neg_root:
        neg = run_set(neg_root["path"])
        fp = neg["detected"]
        neg_total = neg["total_files"]
        out["negative"] = {**neg, "false_positives": fp,
                           "false_positive_rate": round(100.0 * fp / neg_total, 2) if neg_total else 0.0}
        out["negative_corpus"] = {"id": neg_root["id"], "label": neg_root["label"]}
    out["scan_duration_s"] = round(time.monotonic() - t0, 3)
    return out


def test_upload_sources(source: str, uploads: list,
                        max_files: int = 0, per_file_timeout: int = 0) -> Dict[str, Any]:
    """Test the Workbench rule against analyst-uploaded blobs (in memory only).

    uploads: [(filename, bytes)]. Nothing is written to disk. The rule is
    compiled once, then every blob is scanned with it.
    """
    t0 = time.monotonic()
    deadline = t0 + (SCAN_TIMEOUT_S or 120)
    try:
        eng, compiled = _compile_workbench_source(source)
        engine_name = eng.name
    except EngineCompileError as e:
        return {"error": "Workbench rule does not compile", "compile_errors": e.errors,
                "status": 400}
    cap_files = max_files or MAX_TEST_FILES
    total_bytes = 0
    files_out = []
    string_hits: Dict[str, Dict[str, List[int]]] = {}
    n_files = 0
    truncated = False
    for name, data in uploads or []:
        if n_files >= cap_files:
            truncated = True
            break
        if time.monotonic() > deadline:
            truncated = True
            break
        label = str(name or "upload")
        blob = data if isinstance(data, (bytes, bytearray)) else b""
        total_bytes += len(blob)
        if total_bytes > MAX_TEST_BYTES:
            truncated = True
            break
        n_files += 1
        if len(blob) > MAX_UPLOAD_BYTES:
            files_out.append({"file": label, "size": len(blob), "md5": "",
                              "match": False,
                              "error": f"Skipped: exceeds {MAX_UPLOAD_BYTES} bytes"})
            continue
        file_md5 = _file_md5_bytes(bytes(blob))
        try:
            matches = eng.scan_bytes(compiled, bytes(blob),
                                     timeout=per_file_timeout or ENGINE_TIMEOUT_S)
            hit = bool(matches)
        except ScanTimeout:
            matches, hit = [], False
            files_out.append({"file": label, "size": len(blob), "md5": file_md5,
                              "match": False, "timeout": True})
            continue
        except Exception as e:
            files_out.append({"file": label, "size": len(blob), "md5": file_md5,
                              "match": False, "error": str(e)[:200]})
            continue
        for m in matches:
            for s in m.get("strings", []):
                sid = s.get("id", "")
                bucket = string_hits.setdefault(sid, {}).setdefault(label, [])
                if len(bucket) < MAX_OFFSETS_PER_FILE:
                    bucket.append(int(s.get("offset", 0)))
        files_out.append({"file": label, "size": len(blob), "md5": file_md5, "match": hit,
                          "rules": sorted({m.get("rule", "") for m in matches})})
    summary = _summarize_test_run(files_out, string_hits, n_files, truncated)
    summary["engine"] = engine_name
    summary["scan_duration_s"] = round(time.monotonic() - t0, 3)
    return summary


def test_path_sources(source: str, path: str,
                      max_files: int = 0, per_file_timeout: int = 0) -> Dict[str, Any]:
    """Test the Workbench rule against a server-local file or folder.

    No uploads involved: files are read straight from the given path and
    scanned in memory, never written anywhere or submitted externally.
    Runs on the same machine as the server (local-only deployment); the
    usual file caps (count/size/depth/bytes) and the shared scan deadline
    apply. Symlinks and special files are refused.
    """
    raw = (path or "").strip().strip('"').strip("'")
    if not raw:
        return {"error": "No server path provided", "status": 400}
    abs_path = os.path.abspath(os.path.expanduser(raw))
    if not os.path.exists(abs_path):
        return {"error": f"Path does not exist: {raw[:200]}", "status": 400}
    cap_files = max_files or MAX_TEST_FILES
    uploads: list = []
    total = 0
    truncated = False

    def _read_bounded(real_path: str, size: int):
        with open(real_path, "rb") as f:
            return f.read(size + 1)

    if os.path.islink(abs_path):
        return {"error": "Refusing symlinked path", "status": 400}
    if os.path.isfile(abs_path):
        try:
            size = os.path.getsize(abs_path)
        except OSError as e:
            return {"error": f"Cannot access path: {e}", "status": 400}
        if size > MAX_UPLOAD_BYTES:
            return _summarize_test_run(
                [{"file": os.path.basename(abs_path), "size": size, "md5": "",
                  "match": False,
                  "error": f"Skipped: exceeds {MAX_UPLOAD_BYTES} bytes"}],
                {}, 1, False) | {"engine": "not-run", "scan_duration_s": 0.0}
        try:
            data = _read_bounded(abs_path, size)
            if len(data) > MAX_UPLOAD_BYTES:
                raise OSError(f"exceeds {MAX_UPLOAD_BYTES} bytes")
            uploads.append((os.path.basename(abs_path), data))
        except OSError as e:
            return {"error": f"Cannot read path: {e}", "status": 400}
    elif os.path.isdir(abs_path):
        for rel, real, size in iter_corpus_files(
                abs_path, max_files=cap_files,
                max_depth=MAX_CORPUS_DEPTH, max_total_bytes=MAX_TEST_BYTES):
            if len(uploads) >= cap_files:
                truncated = True
                break
            if size > MAX_UPLOAD_BYTES:
                continue
            try:
                data = _read_bounded(real, size)
            except OSError:
                continue
            if len(data) > MAX_UPLOAD_BYTES:
                continue
            uploads.append((rel, data))
            total += len(data)
            if total > MAX_TEST_BYTES:
                truncated = True
                break
        if not uploads and not truncated:
            return {"error": "No readable files found under path", "status": 400}
    else:
        return {"error": "Path is not a regular file or folder", "status": 400}
    out = test_upload_sources(source or "", uploads, max_files=cap_files,
                              per_file_timeout=per_file_timeout)
    for f in uploads:
        del f
    del uploads
    if truncated:
        out["truncated"] = True
    out["tested_path"] = abs_path
    return out
