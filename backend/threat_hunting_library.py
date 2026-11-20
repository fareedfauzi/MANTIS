"""GitHub-backed, provenance-preserving threat hunting query library."""

import hashlib
import io
import json
import os
import re
import sqlite3
import subprocess
import threading
import time
import tomllib
import zipfile
from contextlib import closing
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote

import requests
import yaml
import startup_progress as progress

DB_PATH = os.environ.get("MANTIS_THREAT_HUNTING_DB") or os.path.join(
    os.path.dirname(__file__), "data", "threat_hunting.db")

SEEDS = (
    "a2awais/Threat-Hunting", "elastic/detection-rules",
    "cyb3rmik3/KQL-threat-hunting-queries", "HaHashem/soc-hunting-queries",
    "df00tech/mitre-attack-detections",
)
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
FENCE_RE = re.compile(r"^```\s*([\w-]*)[^\n]*\n(.*?)^```", re.M | re.S)
LANGS = {"spl":"SPL", "splunk":"SPL", "kql":"KQL", "eql":"EQL", "cql":"CQL",
         "aql":"AQL", "ppl":"PPL", "xql":"XQL", "yaral":"YARA-L", "yara-l":"YARA-L",
         "lucene":"Lucene", "sql":"SQL", "esql":"ES|QL", "es|ql":"ES|QL"}
LANGS.update({"kuery":"KQL", "logscale":"CQL", "humio":"CQL"})
EXTS = {".spl":"SPL", ".kql":"KQL", ".eql":"EQL", ".cql":"CQL", ".aql":"AQL",
        ".ppl":"PPL", ".xql":"XQL", ".yaral":"YARA-L", ".esql":"ES|QL"}
STRUCTURED = {".yaml", ".yml", ".json", ".toml"}
DOCS = {".md", ".markdown"}
IGNORED = ("license", "contributing", "changelog", "code_of_conduct", "requirements", "package")
lock = threading.Lock()
running = set()
sync_gate = threading.Lock()
_scheduler_started = False
MAX_ARCHIVE_BYTES = 250 * 1024 * 1024
MAX_ARCHIVE_FILES = 150000
MAX_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_QUERY_FILE_BYTES = 150000


def progress_key(name):
    return "hunt-" + name.lower().replace("/", "-") + "-" + hashlib.sha256(name.lower().encode()).hexdigest()[:8]


class LibraryError(Exception):
    pass


def _db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS hl_repos (
            name TEXT PRIMARY KEY, branch TEXT DEFAULT '', license TEXT DEFAULT '',
            state TEXT DEFAULT 'idle', last_sync TEXT DEFAULT '', error TEXT DEFAULT '',
            count INTEGER DEFAULT 0, enabled INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS hl_queries (
            hash TEXT PRIMARY KEY, query TEXT NOT NULL, language TEXT NOT NULL,
            platform TEXT NOT NULL, platform_basis TEXT NOT NULL, category TEXT NOT NULL,
            category_basis TEXT NOT NULL, telemetry TEXT NOT NULL, telemetry_basis TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS hl_sources (
            repo TEXT NOT NULL, path TEXT NOT NULL, ordinal INTEGER NOT NULL,
            blob_sha TEXT NOT NULL, query_hash TEXT NOT NULL, title TEXT NOT NULL,
            description TEXT NOT NULL, author TEXT NOT NULL, updated TEXT NOT NULL,
            mitre TEXT NOT NULL, url TEXT NOT NULL, tags TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(repo,path,ordinal),
            FOREIGN KEY(repo) REFERENCES hl_repos(name) ON DELETE CASCADE,
            FOREIGN KEY(query_hash) REFERENCES hl_queries(hash)
        );
        CREATE INDEX IF NOT EXISTS hl_sources_hash ON hl_sources(query_hash);
        CREATE TABLE IF NOT EXISTS hl_sync_history (
            id INTEGER PRIMARY KEY, repo TEXT NOT NULL, started TEXT NOT NULL,
            finished TEXT NOT NULL, state TEXT NOT NULL, detail TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS hl_migrations (name TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS hl_removed_repos (name TEXT PRIMARY KEY);
    """)
    columns = {r[1] for r in conn.execute("PRAGMA table_info(hl_repos)")}
    for key in ("head_sha", "etag", "last_modified"):
        if key not in columns:
            conn.execute(f"ALTER TABLE hl_repos ADD COLUMN {key} TEXT NOT NULL DEFAULT ''")
    if not any(r[1] == "tags" for r in conn.execute("PRAGMA table_info(hl_sources)")):
        conn.execute("ALTER TABLE hl_sources ADD COLUMN tags TEXT NOT NULL DEFAULT ''")
    if not conn.execute("SELECT 1 FROM hl_migrations WHERE name='spl_fence_labels' ").fetchone():
        for row in conn.execute("SELECT hash,query,platform_basis FROM hl_queries WHERE language='KQL'").fetchall():
            if _language(row["query"], "", "") == "SPL":
                if row["platform_basis"] == "inferred":
                    conn.execute("UPDATE hl_queries SET language='SPL',platform='Splunk' WHERE hash=?", (row["hash"],))
                else:
                    conn.execute("UPDATE hl_queries SET language='SPL' WHERE hash=?", (row["hash"],))
        conn.execute("INSERT OR IGNORE INTO hl_migrations(name) VALUES ('spl_fence_labels')")
    conn.executemany("""INSERT OR IGNORE INTO hl_repos(name)
        SELECT ? WHERE NOT EXISTS (SELECT 1 FROM hl_removed_repos WHERE name=?)""",
        [(r,r) for r in SEEDS])
    conn.commit()
    return conn


def repos():
    with closing(_db()) as conn:
        rows = conn.execute("SELECT * FROM hl_repos ORDER BY name").fetchall()
    return [dict(r) for r in rows]


def add_repo(value):
    value = str(value).strip().removeprefix("https://github.com/").strip("/")
    if not REPO_RE.fullmatch(value) or ".." in value:
        raise LibraryError("Enter a public GitHub repository as owner/name")
    with closing(_db()) as conn:
        conn.execute("DELETE FROM hl_removed_repos WHERE name=?", (value,))
        conn.execute("INSERT OR IGNORE INTO hl_repos(name) VALUES (?)", (value,))
        conn.commit()
    progress.register(progress_key(value), value + " hunting queries", unit="bytes")
    return value


def remove_repo(name):
    if not REPO_RE.fullmatch(name):
        raise LibraryError("Invalid repository")
    with closing(_db()) as conn:
        conn.execute("INSERT OR IGNORE INTO hl_removed_repos(name) VALUES (?)", (name,))
        conn.execute("DELETE FROM hl_repos WHERE name=?", (name,))
        conn.execute("DELETE FROM hl_queries WHERE hash NOT IN (SELECT query_hash FROM hl_sources)")
        conn.commit()
    progress.unregister(progress_key(name))


def _remote_head(name):
    """Ask Git's smart HTTP service for HEAD, without GitHub's REST API."""
    try:
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        result = subprocess.run(
            ["git", "ls-remote", "--symref", f"https://github.com/{name}.git", "HEAD"],
            capture_output=True, text=True, timeout=25, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "", ""
    if result.returncode:
        return "", ""
    branch = re.search(r"^ref:\s+refs/heads/([^\s]+)\s+HEAD$", result.stdout, re.M)
    sha = re.search(r"^([a-f0-9]{40})\s+HEAD$", result.stdout, re.M)
    return (branch.group(1) if branch else "", sha.group(1) if sha else "")


def _archive(name, branch, etag="", last_modified=""):
    """Download a public ZIP with conditional requests and a strict size limit."""
    url = f"https://github.com/{name}/archive/refs/heads/{quote(branch,safe='')}.zip"
    headers = {"User-Agent":"MANTIS-Hunting-Library"}
    if etag: headers["If-None-Match"] = etag
    if last_modified: headers["If-Modified-Since"] = last_modified
    for attempt in range(3):
        try:
            with requests.get(url,headers=headers,stream=True,timeout=(15,90)) as response:
                if response.status_code == 304:
                    return None, dict(response.headers)
                if response.status_code == 404:
                    raise LibraryError("Repository branch not found")
                if response.status_code in (429,502,503) and attempt < 2:
                    time.sleep(attempt+1)
                    continue
                if response.status_code != 200:
                    raise LibraryError(f"Repository archive returned HTTP {response.status_code}")
                length = int(response.headers.get("Content-Length") or 0)
                if length > MAX_ARCHIVE_BYTES:
                    raise LibraryError("Repository archive exceeds the 250 MB limit")
                progress.set_total(progress_key(name),length or None)
                data = io.BytesIO()
                for chunk in response.iter_content(256*1024):
                    if not chunk: continue
                    if data.tell()+len(chunk)>MAX_ARCHIVE_BYTES:
                        raise LibraryError("Repository archive exceeds the 250 MB limit")
                    data.write(chunk)
                    progress.set_bytes(progress_key(name),data.tell(),length or None)
                return data.getvalue(), dict(response.headers)
        except requests.RequestException as exc:
            if attempt==2: raise LibraryError("Repository archive could not be downloaded") from exc
            time.sleep(attempt+1)
    raise LibraryError("Repository archive could not be downloaded")


def _archive_files(payload):
    """Read candidate files directly from ZIP; never extract untrusted paths."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload))
    except (zipfile.BadZipFile, OSError) as exc:
        raise LibraryError("Invalid repository archive") from exc
    with archive:
        entries = archive.infolist()
        if len(entries)>MAX_ARCHIVE_FILES or sum(e.file_size for e in entries)>MAX_UNCOMPRESSED_BYTES:
            raise LibraryError("Repository archive exceeds safe file limits")
        files, license_text = [], ""
        for entry in entries:
            parts=entry.filename.replace("\\","/").split("/")
            if entry.is_dir() or len(parts)<2 or any(p in ("",".","..") for p in parts):
                continue
            path="/".join(parts[1:])
            if entry.file_size>MAX_QUERY_FILE_BYTES or entry.compress_size>MAX_ARCHIVE_BYTES:
                continue
            if re.fullmatch(r"(?:LICENSE|COPYING)(?:\.[A-Za-z0-9]+)?",path,re.I) and not license_text:
                license_text=archive.read(entry).decode("utf-8","replace")
            if not _candidate(path): continue
            data=archive.read(entry)
            files.append((path,hashlib.sha256(data).hexdigest(),data))
        return files, license_text


def _license(text):
    if re.search(r"Apache License\s*,?\s*Version 2\.0",text,re.I): return "Apache-2.0"
    if re.search(r"MIT License|Permission is hereby granted, free of charge",text,re.I): return "MIT"
    if re.search(r"BSD [23]-Clause",text,re.I): return "BSD"
    if re.search(r"GNU GENERAL PUBLIC LICENSE\s+Version 3",text,re.I): return "GPL-3.0"
    return "Unknown"


def _archive_updated(headers):
    value=headers.get("Last-Modified") or ""
    if not value: return ""
    try:
        return parsedate_to_datetime(value).astimezone(timezone.utc).isoformat()
    except (TypeError,ValueError,OverflowError):
        return ""


def _candidate(path):
    lower = path.lower()
    ext = os.path.splitext(lower)[1]
    name = os.path.basename(lower)
    if any(name.startswith(n) for n in IGNORED) or any(p in lower.split("/") for p in ("test", "tests", "fixtures", "vendor", "node_modules")):
        return False
    return ext in DOCS | STRUCTURED | set(EXTS)


def _language(query, hint="", path=""):
    q = query.strip()
    # Repositories sometimes label Splunk fences as KQL. Strong SPL syntax
    # takes precedence over that fence label or the surrounding file extension.
    if re.search(r"\b(?:index\s*=|sourcetype\s*=|dc\s*\(|relative_time\s*\()|\|\s*(?:stats|eval|tstats|rex|sort|convert|chart|timechart)\b", q, re.I):
        return "SPL"
    hint = hint.lower().strip().replace("_", "-")
    if hint in LANGS:
        return LANGS[hint]
    ext = os.path.splitext(path.lower())[1]
    if ext in EXTS:
        return EXTS[ext]
    if re.search(r"\b(?:DeviceProcessEvents|SecurityEvent|SigninLogs|Event\s*\|\s*where)\b|\|\s*(?:where|project|summarize|extend)\b", q, re.I): return "KQL"
    if re.search(r"^\s*(?:process|network|file|registry)\s+where\b", q, re.I): return "EQL"
    if re.search(r"\bSELECT\s+.+\s+FROM\s+.+\s+WHERE\b", q, re.I | re.S): return "AQL" if "events" in q.lower() else "SQL"
    if re.search(r"\b(?:event_simpleName|#event_simpleName)\s*=|\|\s*(?:groupBy|select)\(", q, re.I): return "CQL"
    if re.search(r"^\s*(?:filter|dataset)\s+\w+\s*(?:=|\|)", q, re.I): return "XQL"
    return ""


def _classify(query, language, path, metadata):
    # Metadata fields are preserved as verified; path/heuristics are marked inferred.
    platform = metadata.get("platform") or ""
    platform_basis = "verified" if platform else "inferred"
    if not platform:
        platform = {"SPL":"Splunk", "EQL":"Elastic", "ES|QL":"Elastic", "PPL":"OpenSearch", "AQL":"QRadar",
                    "XQL":"Cortex XDR", "YARA-L":"Google SecOps", "CQL":"CrowdStrike LogScale"}.get(language, "")
        if language == "KQL":
            platform = "Elastic Security" if "elastic" in path.lower() else "Microsoft Sentinel" if re.search(r"SecurityEvent|SigninLogs|AzureActivity",query) else "KQL (platform unspecified)"
    category = metadata.get("category") or ""
    category_basis = "verified" if category else "inferred"
    if not category:
        combined = (path + " " + metadata.get("title", "")).lower()
        category = next((label for term,label in (("credential","Credential access"),("lateral","Lateral movement"),
                    ("persistence","Persistence"),("execution","Execution"),("exfil","Exfiltration"),
                    ("malware","Malware"),("ransom","Ransomware")) if term in combined), "Unclassified")
    telemetry = metadata.get("telemetry") or ""
    telemetry_basis = "verified" if telemetry else "inferred"
    if not telemetry:
        tables = re.findall(r"\b(?:Device[A-Za-z]+Events|SecurityEvent|SigninLogs|Sysmon|ProcessRollup2)\b", query)
        telemetry = ", ".join(dict.fromkeys(tables))
    return platform, platform_basis, category, category_basis, telemetry, telemetry_basis


def _record(query, hint, path, metadata):
    if not isinstance(query, str): return None
    query = query.strip()
    if len(query) < 15 or len(query) > 100000 or "\x00" in query: return None
    language = _language(query, hint, path)
    if not language: return None
    return {"query":query, "language":language, "metadata":metadata}


def _structured_items(obj, inherited=None):
    if not isinstance(obj, (dict, list)): return
    if isinstance(obj, list):
        for item in obj: yield from _structured_items(item, inherited)
        return
    meta = dict(inherited or {})
    for key in ("title", "name", "description", "author", "platform", "category", "telemetry", "language", "type", "mitre", "tags"):
        value = obj.get(key)
        if isinstance(value, str): meta["title" if key == "name" else key] = value
        elif key in ("tags", "mitre", "author") and isinstance(value, list): meta[key] = " ".join(map(str, value))
    if meta.get("language") == "kuery": meta["language"] = "kql"
    if not meta.get("language") and meta.get("type") in ("eql", "esql", "query"):
        meta["language"] = "kql" if meta["type"] == "query" else meta["type"]
    # Rule-like record with an actual executable search expression.
    for key in ("query", "search_query", "hunting_query", "search", "query_text"):
        if isinstance(obj.get(key), str):
            yield obj[key], meta
            break
    for key, value in obj.items():
        if isinstance(value, (dict, list)):
            yield from _structured_items(value, meta)


def extract(path, content):
    """Return only clearly identified queries; never index arbitrary code fences."""
    ext = os.path.splitext(path.lower())[1]
    result = []
    if ext in EXTS:
        # Explicit query headings can divide a native file; blank lines cannot.
        blocks = re.split(r"(?m)^\s*(?://|#|--)\s*(?:Query|Hunt)\s*:\s*([^\n]+)\n", content)
        if len(blocks) == 1:
            blocks = ["", "", content]
        elif blocks[0].strip():
            initial = _record(blocks[0], "", path, {})
            if initial: result.append(initial)
        for index in range(1, len(blocks), 2):
            item = _record(blocks[index + 1], "", path, {"title":blocks[index].strip()})
            if item: result.append(item)
    elif ext in DOCS:
        for match in FENCE_RE.finditer(content):
            preceding = content[:match.start()].splitlines()[-12:]
            heading = next((line.lstrip("# ").strip() for line in reversed(preceding) if line.startswith("#")), "")
            item = _record(match.group(2), match.group(1), path, {"title": heading})
            if item: result.append(item)
    elif ext in STRUCTURED:
        try:
            data = tomllib.loads(content) if ext == ".toml" else json.loads(content) if ext == ".json" else yaml.safe_load(content)
        except (ValueError, yaml.YAMLError):
            return []
        for query, meta in _structured_items(data):
            item = _record(query, meta.get("language", ""), path, meta)
            if item: result.append(item)
    return result


def _sync(name):
    with sync_gate:
        _sync_one(name)


def _sync_one(name):
    started = datetime.now(timezone.utc).isoformat()
    key=progress_key(name)
    with closing(_db()) as conn:
        row = conn.execute("SELECT * FROM hl_repos WHERE name=?", (name,)).fetchone()
        if not row: raise LibraryError("Repository not configured")
        old=dict(row)
        conn.execute("UPDATE hl_repos SET state='running',error='' WHERE name=?", (name,))
        conn.commit()
    progress.start(key,message=f"Checking {name}")
    progress.set_unit(key,"bytes")
    try:
        branch, head=_remote_head(name)
        if head and head==old["head_sha"] and old["last_sync"]:
            stamp=datetime.now(timezone.utc).isoformat()
            with closing(_db()) as conn:
                conn.execute("UPDATE hl_repos SET state='complete',last_sync=?,error='' WHERE name=?",(stamp,name))
                conn.execute("INSERT INTO hl_sync_history(repo,started,finished,state,detail) VALUES (?,?,?,?,?)",
                             (name,started,stamp,"complete","Up to date; archive not downloaded"))
                conn.commit()
            progress.skip(key,"Up to date; archive not downloaded")
            return
        candidates=list(dict.fromkeys([b for b in (branch,old["branch"],"main","master") if b]))
        payload,headers=None,{}
        for candidate in candidates:
            try:
                payload,headers=_archive(name,candidate,
                    old["etag"] if candidate==old["branch"] else "",
                    old["last_modified"] if candidate==old["branch"] else "")
                branch=candidate
                break
            except LibraryError as exc:
                if str(exc)!="Repository branch not found": raise
        else:
            raise LibraryError("No public archive found for the repository's default branch")
        stamp=datetime.now(timezone.utc).isoformat()
        if payload is None:
            with closing(_db()) as conn:
                conn.execute("UPDATE hl_repos SET state='complete',last_sync=?,head_sha=?,error='' WHERE name=?",
                             (stamp,head or old["head_sha"],name))
                conn.execute("INSERT INTO hl_sync_history(repo,started,finished,state,detail) VALUES (?,?,?,?,?)",
                             (name,started,stamp,"complete","Archive unchanged (HTTP 304)"))
                conn.commit()
            progress.skip(key,"Archive unchanged")
            return
        files,license_text=_archive_files(payload)
        with closing(_db()) as conn:
            known={(r["path"],r["blob_sha"]) for r in conn.execute(
                "SELECT DISTINCT path,blob_sha FROM hl_sources WHERE repo=?",(name,))}
        changed=[(path,sha,data) for path,sha,data in files if (path,sha) not in known]
        progress.set_unit(key,"files")
        progress.set_total(key,len(changed) or 1)
        progress.advance(key,0,f"Indexing {len(changed)} changed files")
        parsed=[]
        for path,sha,data in changed:
            parsed.append((path,sha,extract(path,data.decode("utf-8","replace"))))
            progress.advance(key,1,f"Indexed {len(parsed)}/{len(changed)} files")
        stamp = datetime.now(timezone.utc).isoformat()
        with closing(_db()) as conn:
            conn.execute("BEGIN")
            for path,sha,items in parsed:
                conn.execute("DELETE FROM hl_sources WHERE repo=? AND path=?", (name, path))
                for ordinal, item in enumerate(items):
                    query = item["query"]
                    digest = hashlib.sha256(query.encode()).hexdigest()
                    meta = item["metadata"]
                    classification = _classify(query,item["language"],name + "/" + path,meta)
                    conn.execute("INSERT OR IGNORE INTO hl_queries VALUES (?,?,?,?,?,?,?,?,?)",
                                 (digest,query,item["language"],*classification))
                    url = f"https://github.com/{name}/blob/{head or quote(branch,safe='')}/{quote(path)}"
                    tags = " ".join(str(meta.get(k, "")) for k in ("mitre", "tags", "title", "description"))
                    mitre = list(dict.fromkeys(ATTACK_RE.findall(tags)))
                    conn.execute("INSERT INTO hl_sources(repo,path,ordinal,blob_sha,query_hash,title,description,author,updated,mitre,url,tags) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                                 (name,path,ordinal,sha,digest,
                                  meta.get("title") or os.path.splitext(os.path.basename(path))[0],
                                  meta.get("description", ""),meta.get("author", ""),
                                  _archive_updated(headers),json.dumps(mitre),url,meta.get("tags", "")))
            paths = {path for path,_,_ in files}
            for row in conn.execute("SELECT DISTINCT path FROM hl_sources WHERE repo=?", (name,)).fetchall():
                if row["path"] not in paths:
                    conn.execute("DELETE FROM hl_sources WHERE repo=? AND path=?", (name,row["path"]))
            conn.execute("DELETE FROM hl_queries WHERE hash NOT IN (SELECT query_hash FROM hl_sources)")
            count = conn.execute("SELECT count(*) FROM hl_sources WHERE repo=?", (name,)).fetchone()[0]
            license_id = _license(license_text)
            conn.execute("UPDATE hl_repos SET branch=?,head_sha=?,etag=?,last_modified=?,license=?,state='complete',last_sync=?,error='',count=? WHERE name=?",
                         (branch,head,headers.get("ETag",""),headers.get("Last-Modified",""),license_id,stamp,count,name))
            conn.execute("INSERT INTO hl_sync_history(repo,started,finished,state,detail) VALUES (?,?,?,?,?)",
                         (name,started,stamp,"complete",f"{len(changed)} files changed; {count} source queries"))
            conn.commit()
        progress.finish(key,f"{count} source queries ready")
    except Exception as exc:
        error = str(exc) if isinstance(exc, LibraryError) else "Repository synchronization failed"
        with closing(_db()) as conn:
            conn.execute("UPDATE hl_repos SET state='error',error=? WHERE name=?", (error,name))
            conn.execute("INSERT INTO hl_sync_history(repo,started,finished,state,detail) VALUES (?,?,?,?,?)",
                         (name,started,datetime.now(timezone.utc).isoformat(),"error",error))
            conn.commit()
        progress.fail(key,error)
    finally:
        with lock: running.discard(name)


def sync(name):
    if not REPO_RE.fullmatch(name): raise LibraryError("Invalid repository")
    with closing(_db()) as conn:
        if not conn.execute("SELECT 1 FROM hl_repos WHERE name=?",(name,)).fetchone():
            raise LibraryError("Repository not configured")
    with lock:
        if name in running: return {"state":"running"}
        running.add(name)
    with closing(_db()) as conn:
        conn.execute("UPDATE hl_repos SET state='running',error='' WHERE name=?", (name,))
        conn.commit()
    progress.register(progress_key(name),name+" hunting queries",unit="bytes")
    threading.Thread(target=_sync,args=(name,),daemon=True,name="hunt-library-sync").start()
    return {"state":"running"}


def sync_all():
    return {r["name"]:sync(r["name"]) for r in repos() if r["enabled"]}


def start_scheduler():
    global _scheduler_started
    if _scheduler_started: return
    _scheduler_started = True
    def loop():
        while True:
            try:
                now=time.time()
                for repo in repos():
                    try:
                        last=datetime.fromisoformat(repo["last_sync"]).timestamp() if repo["last_sync"] else 0
                    except ValueError:
                        last=0
                    if repo["enabled"] and now-last > 86400 and repo["state"] != "running":
                        sync(repo["name"])
            except Exception:
                pass
            time.sleep(3600)
    threading.Thread(target=loop,daemon=True,name="hunt-library-scheduler").start()


def search(q="", language="", platform="", category="", repo="", limit=40, offset=0):
    clauses, args = [], []
    if q:
        clauses.append("(q.query LIKE ? OR EXISTS (SELECT 1 FROM hl_sources s WHERE s.query_hash=q.hash AND (s.title LIKE ? OR s.description LIKE ? OR s.mitre LIKE ? OR s.path LIKE ? OR s.tags LIKE ? OR s.author LIKE ?)))")
        args += ["%"+q[:200]+"%"]*7
    for value,column in ((language,"q.language"),(platform,"q.platform"),(category,"q.category")):
        if value: clauses.append(column+"=?"); args.append(value)
    if repo:
        clauses.append("EXISTS (SELECT 1 FROM hl_sources sr WHERE sr.query_hash=q.hash AND sr.repo=?)")
        args.append(repo)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with closing(_db()) as conn:
        total = conn.execute("SELECT count(*) FROM hl_queries q"+where,args).fetchone()[0]
        rows = conn.execute("SELECT q.* FROM hl_queries q"+where+
                            " ORDER BY (SELECT MAX(updated) FROM hl_sources s WHERE s.query_hash=q.hash) DESC, q.hash LIMIT ? OFFSET ?",
                            args+[max(1,min(int(limit),100)),max(0,int(offset))]).fetchall()
        items=[]
        for row in rows:
            item=dict(row)
            item["sources"]=[dict(s) for s in conn.execute("SELECT repo,path,title,description,author,updated,mitre,url,tags FROM hl_sources WHERE query_hash=? ORDER BY repo,path",(row["hash"],))]
            for source in item["sources"]: source["mitre"]=json.loads(source["mitre"])
            items.append(item)
        facets={key:[r[0] for r in conn.execute(f"SELECT DISTINCT {key} FROM hl_queries WHERE {key}<>'' ORDER BY {key}")]
                for key in ("language","platform","category")}
    return {"total":total,"items":items,"facets":facets}


def history(name):
    with closing(_db()) as conn:
        rows=conn.execute("SELECT started,finished,state,detail FROM hl_sync_history WHERE repo=? ORDER BY id DESC LIMIT 20",(name,)).fetchall()
    return [dict(r) for r in rows]
