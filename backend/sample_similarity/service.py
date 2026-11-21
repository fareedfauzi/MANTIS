"""Sample similarity: families, ingest, profiles and comparison.

Storage model (no sample bytes are ever kept):
  families          one row per malware family / cluster
  family_samples    one row per analysed sample: hashes, summary, zlib-compressed
                    feature document, TLSH and code sketch for fast compare
  profile_items     the family profile: items (strings, imports, APIs, function
                    hashes, metadata) seen in at least two samples, with a tier
  comparisons       verdict history (hashes + result, never the file)

Adding or removing a sample rebuilds that family's profile from the stored
features, so no sample ever needs to be re-read from disk.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
import zlib
from collections import Counter, OrderedDict
from datetime import datetime, timezone
from typing import Dict, List, Optional

from deployment_config import DATA_DIR
from sample_similarity import extract, scoring, vt
from sample_similarity.scoring import FUNCTION_LIKE_KINDS

# MANTIS_SIMILARITY_DB lets tests use a scratch database; production uses DATA_DIR.
DB_PATH = os.environ.get("MANTIS_SIMILARITY_DB") or os.path.join(DATA_DIR, "sample_similarity.db")
MAX_FAMILY_NAME = 120
MAX_EVIDENCE = 8
MAX_RESULT_FAMILIES = 20

_LOCK = threading.RLock()
_JOBS: "OrderedDict[str, dict]" = OrderedDict()
_JOB_KEEP = 50

SCHEMA = """
CREATE TABLE IF NOT EXISTS families (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    profile_version INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS family_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    family_id INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
    sha256 TEXT NOT NULL,
    md5 TEXT NOT NULL DEFAULT '',
    sha1 TEXT NOT NULL DEFAULT '',
    file_name TEXT NOT NULL DEFAULT '',
    file_type TEXT NOT NULL DEFAULT '',
    file_size INTEGER NOT NULL DEFAULT 0,
    entropy REAL NOT NULL DEFAULT 0,
    packer TEXT NOT NULL DEFAULT '',
    tlsh TEXT NOT NULL DEFAULT '',
    sketch TEXT NOT NULL DEFAULT '[]',
    summary TEXT NOT NULL DEFAULT '{}',
    payload BLOB NOT NULL,
    extractor_version INTEGER NOT NULL,
    added_at TEXT NOT NULL,
    UNIQUE(family_id, sha256)
);
CREATE TABLE IF NOT EXISTS profile_items (
    family_id INTEGER NOT NULL REFERENCES families(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    item TEXT NOT NULL,
    members INTEGER NOT NULL,
    tier TEXT NOT NULL,
    PRIMARY KEY (family_id, kind, item)
);
CREATE INDEX IF NOT EXISTS idx_profile_kind_item ON profile_items(kind, item);
CREATE TABLE IF NOT EXISTS vt_snapshots (
    sha256 TEXT PRIMARY KEY,
    fetched_at TEXT NOT NULL,
    status TEXT NOT NULL,
    payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS comparisons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    file_name TEXT NOT NULL DEFAULT '',
    sha256 TEXT NOT NULL,
    file_type TEXT NOT NULL DEFAULT '',
    best_family TEXT NOT NULL DEFAULT '',
    best_label TEXT NOT NULL DEFAULT '',
    best_score REAL NOT NULL DEFAULT 0,
    result TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect(path: Optional[str] = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(path: Optional[str] = None) -> None:
    os.makedirs(os.path.dirname(path or DB_PATH), exist_ok=True)
    with _LOCK:
        conn = _connect(path)
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()


def _db() -> sqlite3.Connection:
    init_db()
    return _connect()


# --------------------------------------------------------------------------- items

def _go_items(go: dict) -> List[str]:
    """Go user function names and module dependencies, as profile items."""
    return [f"go:{n}" for n in go.get("names") or []] + list(go.get("deps") or [])


def sample_items(feats: dict) -> Dict[str, set]:
    """Turn one feature document into profile items grouped by kind."""
    code = feats.get("code") or {}
    meta = set()
    if feats.get("imphash"):
        meta.add(f"imphash:{feats['imphash']}")
    if feats.get("rich_hash"):
        meta.add(f"rich:{feats['rich_hash']}")
    if feats.get("pdb_path"):
        meta.add(f"pdb:{feats['pdb_path']}")
    for k, v in (feats.get("version_info") or {}).items():
        # CompanyName is shared by a whole vendor, so it is not family identity
        if v and k != "CompanyName":
            meta.add(f"ver:{k}={v}")
    return {
        # PyInstaller bundles: the program's own literals, not the launcher/stdlib.
        "string": set(feats.get("program_strings") or feats.get("strings") or []),
        "floss": set(feats.get("floss_strings") or []),
        "import": set(feats.get("imports") or []),
        "api": set(feats.get("api_behaviour") or []),
        "function": set(code.get("function_hashes") or []),
        "meta": meta,
        "vt": set(feats.get("vt_items") or []),
        "go": set(_go_items(feats.get("go") or {})),
        "lang": set((feats.get("lang") or {}).get("names") or []),
        "py_modules": set(feats.get("py_modules") or []),
        "py_symbols": set(feats.get("py_symbols") or []),
    }


def _rebuild_profile(conn: sqlite3.Connection, family_id: int) -> int:
    rows = conn.execute("SELECT payload FROM family_samples WHERE family_id=?", (family_id,)).fetchall()
    n = len(rows)
    counts: Dict[str, Counter] = {}
    for row in rows:
        feats = json.loads(zlib.decompress(row["payload"]))
        for kind, items in sample_items(feats).items():
            counter = counts.setdefault(kind, Counter())
            counter.update(items)
    conn.execute("DELETE FROM profile_items WHERE family_id=?", (family_id,))
    batch = []
    for kind, counter in counts.items():
        for item, members in counter.items():
            tier = scoring.tier_for(members, n)
            # Singletons in a mature family are never evidence, so they are not stored.
            if n >= 3 and members < 2:
                continue
            batch.append((family_id, kind, item, members, tier))
    conn.executemany(
        "INSERT INTO profile_items(family_id, kind, item, members, tier) VALUES (?,?,?,?,?)", batch
    )
    conn.execute(
        "UPDATE families SET profile_version = profile_version + 1, updated_at=? WHERE id=?", (_now(), family_id)
    )
    return len(batch)


# --------------------------------------------------------------------------- families

def _family_row(conn, family_id: int) -> Optional[sqlite3.Row]:
    return conn.execute("SELECT * FROM families WHERE id=?", (family_id,)).fetchone()


def _family_summary(conn, row) -> dict:
    n = conn.execute("SELECT COUNT(*) FROM family_samples WHERE family_id=?", (row["id"],)).fetchone()[0]
    items = conn.execute(
        "SELECT tier, COUNT(*) c FROM profile_items WHERE family_id=? GROUP BY tier", (row["id"],)
    ).fetchall()
    tiers = {r["tier"]: r["c"] for r in items}
    last = conn.execute(
        "SELECT MAX(added_at) FROM family_samples WHERE family_id=?", (row["id"],)
    ).fetchone()[0]
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "sample_count": n,
        "status": scoring.profile_status(n),
        "profile_version": row["profile_version"],
        "core_items": tiers.get("CORE", 0),
        "variable_items": tiers.get("VARIABLE", 0),
        "untiered_items": tiers.get("UNTIERED", 0),
        "last_added": last,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def list_families() -> dict:
    with _LOCK:
        conn = _db()
        try:
            rows = conn.execute("SELECT * FROM families ORDER BY LOWER(name)").fetchall()
            return {"families": [_family_summary(conn, r) for r in rows]}
        finally:
            conn.close()


def get_family(family_id: int) -> dict:
    with _LOCK:
        conn = _db()
        try:
            row = _family_row(conn, family_id)
            if not row:
                raise LookupError("Family not found")
            out = _family_summary(conn, row)
            samples = conn.execute(
                "SELECT id, sha256, md5, file_name, file_type, file_size, entropy, packer, tlsh, extractor_version, summary, added_at "
                "FROM family_samples WHERE family_id=? ORDER BY added_at DESC",
                (family_id,),
            ).fetchall()
            out["samples"] = [
                {**{k: s[k] for k in s.keys() if k != "summary"}, "summary": json.loads(s["summary"] or "{}")}
                for s in samples
            ]
            top = conn.execute(
                "SELECT kind, item, members, tier FROM profile_items WHERE family_id=? AND tier IN ('CORE','VARIABLE') "
                "ORDER BY members DESC, kind, item LIMIT 60",
                (family_id,),
            ).fetchall()
            out["profile"] = [
                {"kind": t["kind"], "item": t["item"], "members": t["members"], "tier": t["tier"],
                 "share": round(t["members"] / max(1, out["sample_count"]), 2)}
                for t in top
            ]
            return out
        finally:
            conn.close()


def _clean_name(name: str) -> str:
    name = " ".join((name or "").split())[:MAX_FAMILY_NAME]
    if not name:
        raise ValueError("Family name is required")
    return name


def create_family(name: str, description: str = "") -> dict:
    name = _clean_name(name)
    with _LOCK:
        conn = _db()
        try:
            if conn.execute("SELECT 1 FROM families WHERE name=?", (name,)).fetchone():
                raise ValueError("A family with this name already exists")
            now = _now()
            cur = conn.execute(
                "INSERT INTO families(name, description, created_at, updated_at) VALUES (?,?,?,?)",
                (name, (description or "").strip()[:500], now, now),
            )
            conn.commit()
            return get_family(cur.lastrowid)
        finally:
            conn.close()


def update_family(family_id: int, name: Optional[str], description: Optional[str]) -> dict:
    with _LOCK:
        conn = _db()
        try:
            row = _family_row(conn, family_id)
            if not row:
                raise LookupError("Family not found")
            new_name = _clean_name(name) if name is not None else row["name"]
            if new_name.lower() != row["name"].lower() and conn.execute(
                "SELECT 1 FROM families WHERE name=? AND id<>?", (new_name, family_id)
            ).fetchone():
                raise ValueError("A family with this name already exists")
            new_desc = (description if description is not None else row["description"]).strip()[:500]
            conn.execute("UPDATE families SET name=?, description=?, updated_at=? WHERE id=?",
                         (new_name, new_desc, _now(), family_id))
            conn.commit()
            return get_family(family_id)
        finally:
            conn.close()


def delete_family(family_id: int) -> dict:
    with _LOCK:
        conn = _db()
        try:
            row = _family_row(conn, family_id)
            if not row:
                raise LookupError("Family not found")
            conn.execute("DELETE FROM families WHERE id=?", (family_id,))
            conn.commit()
            return {"deleted": True, "name": row["name"]}
        finally:
            conn.close()


def delete_sample(family_id: int, sample_id: int) -> dict:
    with _LOCK:
        conn = _db()
        try:
            cur = conn.execute("DELETE FROM family_samples WHERE id=? AND family_id=?", (sample_id, family_id))
            if cur.rowcount == 0:
                raise LookupError("Sample not found in this family")
            _rebuild_profile(conn, family_id)
            conn.commit()
            return get_family(family_id)
        finally:
            conn.close()


# --------------------------------------------------------------------------- jobs

def _job_new(kind: str, meta: dict) -> dict:
    job = {
        "id": uuid.uuid4().hex[:12],
        "kind": kind,
        "status": "queued",
        "total": 0,
        "done": 0,
        "message": "Queued",
        "items": [],
        "result": None,
        "error": "",
        "created_at": _now(),
        **meta,
    }
    with _LOCK:
        _JOBS[job["id"]] = job
        while len(_JOBS) > _JOB_KEEP:
            _JOBS.popitem(last=False)
    return job


def get_job(job_id: str) -> dict:
    with _LOCK:
        job = _JOBS.get(job_id)
        if not job:
            raise LookupError("Job not found")
        return {k: v for k, v in job.items() if not k.startswith("_")}


def _analyse_file(path: str, name: str, use_floss: bool = True) -> dict:
    with open(path, "rb") as fh:
        data = fh.read()
    if not data:
        raise ValueError("File is empty")
    feats = extract.extract_features(data, name)
    if use_floss:
        fl = extract.floss_strings(data)
        feats["floss_strings"] = fl["strings"]
        feats["floss"] = {"status": fl["status"], "count": fl["count"], "truncated": fl.get("truncated", False)}
        feats["statuses"]["floss"] = fl["status"]
    else:
        feats["floss_strings"] = []
        feats["floss"] = {"status": "off", "count": 0}
        feats["statuses"]["floss"] = "off"
    return feats


def _attach_vt(conn, feats: dict, use_vt: bool) -> dict:
    """Look up VirusTotal by hash (cached) and attach the labels as a profile feature.

    Returns a status dict shown beside the result. Never raises: a VT problem
    must not stop the local analysis.
    """
    if not use_vt:
        return {"status": "off"}
    key = vt.resolve_key()
    if not key:
        feats["vt_items"] = []
        return {"status": "no_key"}
    with _LOCK:
        snap = vt.lookup(conn, feats["sha256"], key)
        conn.commit()
    feats["vt_items"] = vt.profile_items(snap)
    return vt.detection_summary(snap)


def _summary(feats: dict) -> dict:
    code = feats.get("code") or {}
    return {
        "sections": len(feats.get("sections") or []),
        "strings": len(feats.get("strings") or []),
        "imports": len(feats.get("imports") or []),
        "functions": code.get("function_count", 0),
        "api_behaviour": len(feats.get("api_behaviour") or []),
        "signed": bool(feats.get("signed")),
        "overlay_size": (feats.get("overlay") or {}).get("size", 0),
        "imphash": feats.get("imphash", ""),
        "statuses": feats.get("statuses") or {},
    }


def _store_sample(conn, family_id: int, feats: dict) -> str:
    """Insert one analysed sample. Returns 'added' or 'duplicate'."""
    if conn.execute("SELECT 1 FROM family_samples WHERE family_id=? AND sha256=?",
                    (family_id, feats["sha256"])).fetchone():
        return "duplicate"
    payload = zlib.compress(json.dumps(feats, separators=(",", ":")).encode(), 6)
    conn.execute(
        "INSERT INTO family_samples(family_id, sha256, md5, sha1, file_name, file_type, file_size, entropy, packer, "
        "tlsh, sketch, summary, payload, extractor_version, added_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            family_id, feats["sha256"], feats.get("md5", ""), feats.get("sha1", ""),
            feats.get("file_name", ""), feats.get("file_type", ""), int(feats.get("file_size", 0)),
            float(feats.get("entropy", 0.0)), feats.get("packer", ""), feats.get("tlsh", ""),
            json.dumps((feats.get("code") or {}).get("sketch", [])),
            json.dumps(_summary(feats)), payload, int(feats.get("extractor_version", extract.EXTRACTOR_VERSION)), _now(),
        ),
    )
    return "added"


def start_ingest(family_id: int, files: List[tuple], use_vt: bool = False) -> dict:
    """files: list of (display_name, temp_path). Temp files are deleted after analysis."""
    with _LOCK:
        conn = _db()
        try:
            if not _family_row(conn, family_id):
                raise LookupError("Family not found")
        finally:
            conn.close()
    job = _job_new("ingest", {"family_id": family_id, "total": len(files), "message": "Analysing samples"})
    threading.Thread(target=_run_ingest, args=(job["id"], files, use_vt), daemon=True).start()
    return {"job_id": job["id"]}


def _run_ingest(job_id: str, files: List[tuple], use_vt: bool = False) -> None:
    _set(job_id, status="running")
    conn = _db()
    added = 0
    try:
        for name, path in files:
            item = {"file": name, "status": "", "message": ""}
            try:
                feats = _analyse_file(path, name)
                item["vt"] = _attach_vt(conn, feats, use_vt)
                with _LOCK:
                    result = _store_sample(conn, _job_family(job_id), feats)
                    conn.commit()
                item["status"] = result
                item["message"] = (
                    f"{feats['file_type']} · {feats['file_size']:,} bytes" if result == "added" else "Already in this family"
                )
                added += result == "added"
            except Exception as exc:  # keep going through the batch
                item["status"] = "failed"
                item["message"] = str(exc)[:200]
            finally:
                _remove(path)
            _append_item(job_id, item)
        with _LOCK:
            n = _rebuild_profile(conn, _job_family(job_id))
            conn.commit()
        _set(job_id, status="done", message=f"Added {added} of {len(files)} sample(s); profile has {n} items")
    except Exception as exc:
        _set(job_id, status="failed", error=str(exc)[:300], message="Ingest failed")
    finally:
        conn.close()


# --------------------------------------------------------------------------- compare

def _job_family(job_id: str) -> int:
    with _LOCK:
        return int(_JOBS[job_id]["family_id"])


def _set(job_id: str, **kw) -> None:
    with _LOCK:
        job = _JOBS.get(job_id)
        if job is not None:
            job.update(kw)


def _append_item(job_id: str, item: dict) -> None:
    with _LOCK:
        job = _JOBS.get(job_id)
        if job is not None:
            job["items"].append(item)
            job["done"] += 1
            job["message"] = f"Processed {job['done']} of {job['total']}"


def _remove(path: str) -> None:
    """Delete an uploaded sample and its temp directory once it is no longer needed."""
    try:
        os.remove(path)
    except OSError:
        pass
    parent = os.path.dirname(path)
    if os.path.basename(parent).startswith("mantis-sim-"):
        try:
            os.rmdir(parent)  # only succeeds when empty
        except OSError:
            pass


def start_compare(name: str, path: str, use_vt: bool = False) -> dict:
    job = _job_new("compare", {"total": 1, "message": "Analysing sample"})
    threading.Thread(target=_run_compare, args=(job["id"], name, path, use_vt), daemon=True).start()
    return {"job_id": job["id"]}


def _run_compare(job_id: str, name: str, path: str, use_vt: bool = False) -> None:
    _set(job_id, status="running")
    try:
        feats = _analyse_file(path, name)
        with _LOCK:
            vt_conn = _db()
            try:
                vt_status = _attach_vt(vt_conn, feats, use_vt)
            finally:
                vt_conn.close()
        result = compare_features(feats)
        result["vt"] = vt_status
        with _LOCK:
            conn = _db()
            try:
                conn.execute(
                    "INSERT INTO comparisons(created_at, file_name, sha256, file_type, best_family, best_label, best_score, result) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (_now(), name, feats["sha256"], feats["file_type"],
                     (result.get("best") or {}).get("name", ""), (result.get("best") or {}).get("label", "NO MATCH"),
                     float((result.get("best") or {}).get("overall", 0.0)), json.dumps(result)),
                )
                conn.commit()
            finally:
                conn.close()
        _set(job_id, status="done", result=result, message="Comparison complete")
    except Exception as exc:
        _set(job_id, status="failed", error=str(exc)[:300], message="Comparison failed")
    finally:
        _remove(path)


def _evidence_items(conn) -> Dict[str, Dict[str, int]]:
    """Global document frequency of each item across families (for rarity and library detection)."""
    df: Dict[str, Dict[str, int]] = {}
    for r in conn.execute("SELECT kind, item, COUNT(DISTINCT family_id) c FROM profile_items GROUP BY kind, item"):
        df.setdefault(r["kind"], {})[r["item"]] = r["c"]
    return df


def _feature(label: str, score: float, available: bool, evidence: List[str], note: str = "") -> dict:
    return {
        "label": label,
        "score": round(float(score), 1) if available else 0.0,
        "available": bool(available),
        "evidence": evidence[:MAX_EVIDENCE],
        "note": note,
    }


def _recall(sample: set, fam: Dict[str, int], idf: Dict[str, float], n: int,
            sample_weight: Optional[float] = None) -> tuple:
    """Prevalence-weighted Dice overlap between a family's evidence and the sample.

    Two-sided on purpose. A one-sided "share of family items present" is trivially
    satisfied when the family is small and the sample is large: a 16-item family is
    contained in almost any 30,000-item sample, which is how an unrelated program
    used to score as similar. The Dice form divides by the family and the sample
    mass, so shared bulk (a bundled library, a common runtime) cannot carry a match
    on its own.

    Family items are weighted by rarity (idf) and by how many members share them.
    sample_weight is the sample's own weighted mass (computed once per kind).
    Thin families return den=0 and are reported as not analysed.
    """
    if len(fam) < scoring.MIN_EVIDENCE_ITEMS:
        return 0.0, [], 0
    weight = {x: idf.get(x, 1.0) * (m / max(1, n)) for x, m in fam.items()}
    hits = [x for x in fam if x in sample]
    den_fam = sum(weight.values())
    num = sum(weight[x] for x in hits)
    if sample_weight is None:
        sample_weight = float(len(sample))
    den = den_fam + sample_weight
    share = (200.0 * num / den) if den else 0.0
    hits.sort(key=lambda x: -weight[x])
    return share, hits, len(fam)


def _short(x: str) -> str:
    return x if len(x) <= 120 else x[:117] + "..."


def compare_features(feats: dict) -> dict:
    """Score one analysed sample against every family. Pure read, nothing is stored."""
    sample = sample_items(feats)
    sha = feats.get("sha256", "")
    with _LOCK:
        conn = _db()
        try:
            total_families = conn.execute("SELECT COUNT(*) FROM families").fetchone()[0]
            fams = conn.execute("SELECT id, name FROM families").fetchall()
            df_all = _evidence_items(conn)
            out_fams = []
            exact = []
            # Weighted mass of the sample per kind, computed once for all families.
            sample_mass: Dict[str, float] = {}
            for _kind, _items in sample.items():
                _idf = {it: scoring.idf(df_all.get(_kind, {}).get(it, 1), total_families) for it in _items}
                sample_mass[_kind] = float(sum(_idf.values()))
            for fam in fams:
                fid = fam["id"]
                n = conn.execute("SELECT COUNT(*) FROM family_samples WHERE family_id=?", (fid,)).fetchone()[0]
                if n == 0:
                    continue
                if conn.execute("SELECT 1 FROM family_samples WHERE family_id=? AND sha256=?", (fid, sha)).fetchone():
                    exact.append(fam["name"])
                ev_rows = conn.execute(
                    "SELECT kind, item, members FROM profile_items WHERE family_id=? AND tier IN ('CORE','VARIABLE','UNTIERED')",
                    (fid,),
                ).fetchall()
                ev: Dict[str, Dict[str, int]] = {}
                for r in ev_rows:
                    kind_df = df_all.get(r["kind"], {}).get(r["item"], 1)
                    # Library: present in more than half of all families (min 4 families).
                    library = (scoring.is_library_function(kind_df, total_families)
                               if r["kind"] in FUNCTION_LIKE_KINDS else scoring.is_library(kind_df, total_families))
                    if library:
                        continue
                    ev.setdefault(r["kind"], {})[r["item"]] = r["members"]
                idf = {
                    kind: {it: scoring.idf(df_all.get(kind, {}).get(it, 1), total_families) for it in items}
                    for kind, items in ev.items()
                }
                features: Dict[str, dict] = {}

                def rec(kind):
                    return _recall(sample.get(kind, set()), ev.get(kind, {}), idf.get(kind, {}), n,
                                   sample_mass.get(kind))

                # strings / imports / api / metadata / functions: rarity-weighted recall
                s_share, s_hits, s_den = rec("string")
                features["strings"] = _feature(
                    scoring.FEATURE_LABELS["strings"], s_share, bool(s_den) and bool(sample["string"]),
                    [_short(h) for h in s_hits], f"{len(s_hits)} of {s_den} family strings present")

                f_share, f_hits, f_den = rec("floss")
                features["floss"] = _feature(
                    scoring.FEATURE_LABELS["floss"], f_share, bool(f_den) and bool(sample["floss"]),
                    [_short(h) for h in f_hits], f"{len(f_hits)} of {f_den} family FLOSS strings present")

                fn_share, fn_hits, fn_den = rec("function")
                features["code_functions"] = _feature(
                    scoring.FEATURE_LABELS["code_functions"], fn_share, bool(fn_den) and bool(sample["function"]),
                    [h[:16] for h in fn_hits], f"{len(fn_hits)} of {fn_den} family functions matched exactly")

                i_share, i_hits, i_den = rec("import")
                features["imports"] = _feature(
                    scoring.FEATURE_LABELS["imports"], i_share, bool(i_den) and bool(sample["import"]),
                    i_hits, f"{len(i_hits)} of {i_den} family imports present")

                a_share, a_hits, a_den = rec("api")
                features["api_behaviour"] = _feature(
                    scoring.FEATURE_LABELS["api_behaviour"], a_share, bool(a_den) and bool(sample["api"]),
                    a_hits, f"{len(a_hits)} of {a_den} family APIs reached from code")

                m_share, m_hits, m_den = rec("meta")
                features["metadata"] = _feature(
                    scoring.FEATURE_LABELS["metadata"], m_share, bool(m_den) and bool(sample["meta"]),
                    [_short(h) for h in m_hits], f"{len(m_hits)} of {m_den} metadata items present")

                # fuzzy file / code similarity against each stored sample of the family
                samples = conn.execute(
                    "SELECT tlsh, sketch FROM family_samples WHERE family_id=?", (fid,)
                ).fetchall()
                best_dist = None
                best_sketch = 0.0
                for s in samples:
                    d = scoring.tlsh_distance(feats.get("tlsh", ""), s["tlsh"])
                    if d is not None and (best_dist is None or d < best_dist):
                        best_dist = d
                    sk = extract.sketch_similarity(feats.get("code", {}).get("sketch", []), json.loads(s["sketch"] or "[]"))
                    if sk is not None:
                        best_sketch = max(best_sketch, sk)
                has_sketch = bool(feats.get("code", {}).get("sketch")) and any(
                    json.loads(s["sketch"] or "[]") for s in samples)
                features["code_fuzzy"] = _feature(
                    scoring.FEATURE_LABELS["code_fuzzy"], best_sketch * 100.0, has_sketch,
                    [f"closest sketch similarity {best_sketch:.2f}"] if has_sketch else [],
                    "Sketch of .text shingles")
                features["tlsh"] = _feature(
                    scoring.FEATURE_LABELS["tlsh"],
                    scoring.tlsh_score(best_dist) if best_dist is not None else 0.0,
                    best_dist is not None,
                    [f"closest TLSH distance {best_dist}"] if best_dist is not None else [],
                    "Lower distance is closer")

                g_share, g_hits, g_den = rec("go")
                features["go_symbols"] = _feature(
                    scoring.FEATURE_LABELS["go_symbols"], g_share, bool(g_den) and bool(sample["go"]),
                    [_short(h) for h in g_hits], f"{len(g_hits)} of {g_den} family Go symbols/modules present")
                l_share, l_hits, l_den = rec("lang")
                features["lang_symbols"] = _feature(
                    scoring.FEATURE_LABELS["lang_symbols"], l_share, bool(l_den) and bool(sample["lang"]),
                    [_short(h) for h in l_hits], f"{len(l_hits)} of {l_den} family C++/Rust names present")

                y_share, y_hits, y_den = rec("py_symbols")
                features["py_symbols"] = _feature(
                    scoring.FEATURE_LABELS["py_symbols"], y_share, bool(y_den) and bool(sample["py_symbols"]),
                    [_short(h) for h in y_hits[:6]], f"{len(y_hits)} of {y_den} family program names present")
                m_share, m_hits, m_den = rec("py_modules")
                features["py_modules"] = _feature(
                    scoring.FEATURE_LABELS["py_modules"], m_share, bool(m_den) and bool(sample["py_modules"]),
                    [_short(h) for h in m_hits], f"{len(m_hits)} of {m_den} family bundled modules present")
                v_share, v_hits, v_den = rec("vt")
                features["vt"] = _feature(
                    scoring.FEATURE_LABELS["vt"], v_share, bool(v_den) and bool(sample.get("vt")),
                    v_hits, f"{len(v_hits)} of {v_den} family VT labels present" if v_den else "No VT data in this family")

                for key, weight in scoring.WEIGHTS.items():
                    features[key]["weight"] = weight

                overall, coverage = scoring.combine(features)
                evidence = scoring.evidence_score(features)
                status = scoring.profile_status(n)
                label = scoring.label_for(evidence, features, status, coverage)
                out_fams.append({
                    "id": fid,
                    "name": fam["name"],
                    "sample_count": n,
                    "status": status,
                    "label": label,
                    "overall": overall,
                    "evidence": evidence,
                    "coverage": coverage,
                    "features": features,
                    "caveat": scoring.young_family_caveat(status, n),
                    "exact_sha256_member": fam["name"] in exact,
                })
        finally:
            conn.close()

    out_fams.sort(key=lambda f: (-f["overall"], f["name"].lower()))
    best = out_fams[0] if out_fams and out_fams[0]["label"] not in ("NO MATCH", "INSUFFICIENT EVIDENCE") else None
    if best and best["exact_sha256_member"]:
        verdict = f"Already a member of {best['name']} (identical SHA256)"
    elif best:
        verdict = f"{best['label']} similarity to {best['name']} (evidence score {best['evidence']:.1f}, {best['coverage']*100:.0f}% of weight analysed)"
    elif any(f["label"] == "INSUFFICIENT EVIDENCE" for f in out_fams):
        verdict = "Insufficient evidence: too few features could be analysed to call a family"
    else:
        verdict = "No family match"
    sample_out = {
        "sha256": sha,
        "md5": feats.get("md5", ""),
        "sha1": feats.get("sha1", ""),
        "file_name": feats.get("file_name", ""),
        "file_type": feats.get("file_type", ""),
        "file_size": feats.get("file_size", 0),
        "entropy": feats.get("entropy", 0.0),
        "packer": feats.get("packer", ""),
        "imphash": feats.get("imphash", ""),
        "signed": bool(feats.get("signed")),
        "statuses": feats.get("statuses", {}),
        "summary": _summary(feats),
    }
    return {
        "sample": sample_out,
        "exact_sha256_families": exact,
        "verdict": verdict,
        "best": best and {k: best[k] for k in ("id", "name", "label", "overall", "evidence", "coverage")},
        "families": out_fams[:MAX_RESULT_FAMILIES],
        "weights": scoring.WEIGHTS,
        "created_at": _now(),
    }


def list_comparisons(limit: int = 50) -> dict:
    with _LOCK:
        conn = _db()
        try:
            rows = conn.execute(
                "SELECT id, created_at, file_name, sha256, file_type, best_family, best_label, best_score "
                "FROM comparisons ORDER BY id DESC LIMIT ?", (max(1, min(int(limit), 200)),)
            ).fetchall()
            return {"comparisons": [dict(r) for r in rows]}
        finally:
            conn.close()


def get_comparison(comparison_id: int) -> dict:
    with _LOCK:
        conn = _db()
        try:
            row = conn.execute("SELECT result FROM comparisons WHERE id=?", (comparison_id,)).fetchone()
            if not row:
                raise LookupError("Comparison not found")
            return json.loads(row["result"])
        finally:
            conn.close()


def dashboard() -> dict:
    with _LOCK:
        conn = _db()
        try:
            fams = conn.execute("SELECT COUNT(*) FROM families").fetchone()[0]
            samples = conn.execute("SELECT COUNT(*) FROM family_samples").fetchone()[0]
            comps = conn.execute("SELECT COUNT(*) FROM comparisons").fetchone()[0]
            size = conn.execute("SELECT COALESCE(SUM(LENGTH(payload)),0) FROM family_samples").fetchone()[0]
            recent = conn.execute(
                "SELECT id, created_at, file_name, best_label, best_score FROM comparisons ORDER BY id DESC LIMIT 5"
            ).fetchall()
            return {
                "families": fams,
                "samples": samples,
                "comparisons": comps,
                "recent_comparisons": [dict(r) for r in recent],
                "stored_bytes": size,
                "extractor_version": extract.EXTRACTOR_VERSION,
                "weights": scoring.WEIGHTS,
            }
        finally:
            conn.close()
