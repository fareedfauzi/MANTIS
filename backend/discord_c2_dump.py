"""Read-only Discord bot evidence collection. Tokens are never persisted."""

import json
import hashlib
import os
import re
import sqlite3
import threading
import time
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "discord_c2_dump.db")
ATTACHMENT_ROOT = Path(__file__).resolve().parent / "data" / "discord_c2_attachments"
API = "https://discord.com/api/v10"
SNOWFLAKE = re.compile(r"^[0-9]{15,22}$")
URL = re.compile(r"https?://[^\s<>\"']+", re.I)
HASH = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.I)
CHANNEL_TYPES = {0:"Text", 2:"Voice", 4:"Category", 5:"Announcement", 10:"Announcement thread",
                 11:"Public thread", 12:"Private thread", 13:"Stage", 15:"Forum", 16:"Media"}
MESSAGE_TYPES = {0, 5, 10, 11, 12}
TEXT_EXTENSIONS = {".txt", ".log", ".json", ".jsonl", ".csv", ".xml", ".yaml", ".yml",
                   ".toml", ".md", ".ini", ".cfg", ".conf", ".ps1", ".bat", ".sh", ".py", ".js"}
DOWNLOAD_HOSTS = {"cdn.discordapp.com", "media.discordapp.net"}
_job_lock = threading.Lock()
_active_jobs = {}


class DiscordError(Exception):
    pass


def _db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS discord_messages (
            id TEXT PRIMARY KEY, guild_id TEXT NOT NULL, guild_name TEXT NOT NULL,
            channel_id TEXT NOT NULL, channel_name TEXT NOT NULL,
            author_id TEXT NOT NULL, author_name TEXT NOT NULL,
            timestamp TEXT NOT NULL, content TEXT NOT NULL,
            attachments TEXT NOT NULL, embeds TEXT NOT NULL, urls TEXT NOT NULL,
            hashes TEXT NOT NULL, raw TEXT NOT NULL, collected_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_discord_messages_channel ON discord_messages(channel_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_discord_messages_guild ON discord_messages(guild_id, timestamp);
        CREATE TABLE IF NOT EXISTS discord_channels (
            id TEXT PRIMARY KEY, guild_id TEXT NOT NULL, name TEXT NOT NULL, type INTEGER NOT NULL,
            parent_id TEXT NOT NULL DEFAULT '', state TEXT NOT NULL DEFAULT 'not_started',
            cursor TEXT NOT NULL DEFAULT '', history_count INTEGER NOT NULL DEFAULT 0,
            pins_count INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS discord_names (
            guild_id TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL,
            matches TEXT NOT NULL, PRIMARY KEY(guild_id,kind,id)
        );
        CREATE TABLE IF NOT EXISTS discord_attachments (
            id TEXT PRIMARY KEY, message_id TEXT NOT NULL, guild_id TEXT NOT NULL, filename TEXT NOT NULL,
            url TEXT NOT NULL, size INTEGER NOT NULL, state TEXT NOT NULL, sha256 TEXT NOT NULL DEFAULT '',
            path TEXT NOT NULL DEFAULT '', text TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_discord_attachments_message ON discord_attachments(message_id);
        CREATE TABLE IF NOT EXISTS discord_jobs (
            id TEXT PRIMARY KEY, guild_id TEXT NOT NULL, state TEXT NOT NULL, started_at TEXT NOT NULL,
            updated_at TEXT NOT NULL, channel_ids TEXT NOT NULL, channel_done INTEGER NOT NULL DEFAULT 0,
            read_count INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT ''
        );
    """)
    columns = {r[1] for r in conn.execute("PRAGMA table_info(discord_messages)")}
    if "pinned" not in columns:
        conn.execute("ALTER TABLE discord_messages ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0")
    if "attachment_text" not in columns:
        conn.execute("ALTER TABLE discord_messages ADD COLUMN attachment_text TEXT NOT NULL DEFAULT ''")
    conn.commit()
    return conn


def _id(value, label):
    value = str(value or "").strip()
    if not SNOWFLAKE.fullmatch(value):
        raise DiscordError(f"Invalid {label}")
    return value


def _call(session, path, params=None):
    # All paths are built from fixed routes and validated snowflake IDs.
    for attempt in range(6):
        try:
            response = session.get(API + path, params=params, timeout=20)
        except requests.RequestException:
            raise DiscordError("Discord could not be reached") from None
        if response.status_code == 429 and attempt < 5:
            try:
                delay = float(response.json().get("retry_after", 1))
            except (ValueError, TypeError):
                delay = 1
            time.sleep(min(max(delay, 0.1), 30))
            continue
        if response.status_code != 200:
            reason = {401: "Invalid bot token", 403: "Bot lacks access to this resource",
                      404: "Guild or channel not found", 429: "Discord rate limit reached"}.get(
                          response.status_code, "Discord request failed")
            raise DiscordError(f"{reason} (HTTP {response.status_code})")
        try:
            return response.json()
        except ValueError:
            raise DiscordError("Discord returned invalid JSON") from None
    raise DiscordError("Discord rate limit reached")


def _session(token):
    token = str(token or "").strip()
    if not token or len(token) > 256 or any(c.isspace() for c in token):
        raise DiscordError("Enter a valid bot token")
    session = requests.Session()
    session.headers.update({"Authorization": "Bot " + token, "User-Agent": "MANTIS-DiscordC2Dump/1.0"})
    return session


def _now():
    return datetime.now(timezone.utc).isoformat()


def _archived(session, parent, route, warnings):
    threads, before = [], ""
    while True:
        params = {"limit": 100}
        if before:
            params["before"] = before
        try:
            page = _call(session, f"/channels/{parent['id']}/{route}", params)
        except DiscordError as exc:
            warnings.append({"channel": parent.get("name") or parent["id"], "scope": route, "error": str(exc)})
            break
        batch = page.get("threads") or []
        threads.extend(batch)
        if not batch or not page.get("has_more"):
            break
        last = batch[-1]
        marker = last.get("id") if "users/@me" in route else (last.get("thread_metadata") or {}).get("archive_timestamp")
        if not marker or marker == before:
            warnings.append({"channel":parent.get("name") or parent["id"], "scope":route,
                             "error":"Archived thread pagination ended without a cursor"})
            break
        before = marker
    return threads


def _name_matches(value):
    value = str(value or "")
    matches = URL.findall(value) + HASH.findall(value)
    matches += re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", value)
    return list(dict.fromkeys(matches))


def inspect(token, guild_id):
    guild_id = _id(guild_id, "guild ID")
    warnings = []
    with _session(token) as session:
        bot = _call(session, "/users/@me")
        guild = _call(session, f"/guilds/{guild_id}")
        channels = _call(session, f"/guilds/{guild_id}/channels")
        try:
            active_threads = _call(session, f"/guilds/{guild_id}/threads/active")
            channels += active_threads.get("threads", [])
        except DiscordError as exc:
            warnings.append({"scope":"active threads", "error":str(exc)})
        for parent in list(channels):
            if parent.get("type") not in (0, 5, 15, 16):
                continue
            channels += _archived(session, parent, "threads/archived/public", warnings)
            if parent.get("type") in (0, 5):
                private = _archived(session, parent, "threads/archived/private", warnings)
                channels += private
                if not private:
                    channels += _archived(session, parent, "users/@me/threads/archived/private", warnings)
        try:
            roles = _call(session, f"/guilds/{guild_id}/roles")
        except DiscordError as exc:
            roles = guild.get("roles") or []
            warnings.append({"scope":"roles", "error":str(exc)})
        try:
            emojis = _call(session, f"/guilds/{guild_id}/emojis")
        except DiscordError as exc:
            emojis = guild.get("emojis") or []
            warnings.append({"scope":"emojis", "error":str(exc)})
    inventory = {str(c["id"]):c for c in channels if c.get("id") and c.get("type") in CHANNEL_TYPES}
    items = [dict(id=c["id"], name=c.get("name") or c["id"], type=c["type"],
                  type_label=CHANNEL_TYPES[c["type"]], parent_id=c.get("parent_id") or "",
                  collectable=c["type"] in MESSAGE_TYPES) for c in inventory.values()]
    with closing(_db()) as conn:
        conn.execute("DELETE FROM discord_names WHERE guild_id=?",(guild_id,))
        for c in items:
            conn.execute("""INSERT INTO discord_channels(id,guild_id,name,type,parent_id,updated_at)
                VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,
                type=excluded.type,parent_id=excluded.parent_id,updated_at=excluded.updated_at""",
                (c["id"],guild_id,c["name"],c["type"],c["parent_id"],_now()))
        for kind, values in (("role",roles),("emoji",emojis),("channel",items)):
            for value in values:
                if not value.get("id"):
                    continue
                name = value.get("name") or ""
                conn.execute("""INSERT INTO discord_names(guild_id,kind,id,name,matches) VALUES (?,?,?,?,?)
                    ON CONFLICT(guild_id,kind,id) DO UPDATE SET name=excluded.name,matches=excluded.matches""",
                    (guild_id,kind,str(value["id"]),name,json.dumps(_name_matches(name))))
        conn.commit()
    return {"bot": {"id": bot.get("id"), "username": bot.get("username")},
            "guild": {"id": guild_id, "name": guild.get("name") or guild_id},
            "channels": items, "names": {"roles":len(roles),"emojis":len(emojis)}, "warnings":warnings}


def _normalize(message, guild, channel):
    content = message.get("content") or ""
    attachments = [{"id": a.get("id"), "filename": a.get("filename"), "size": a.get("size"),
                    "url": a.get("url"), "content_type": a.get("content_type")}
                   for a in message.get("attachments") or []]
    embeds = [{"title": e.get("title"), "description": e.get("description"), "url": e.get("url")}
              for e in message.get("embeds") or []]
    evidence = "\n".join([content] + [str(e.get("description") or "") + " " + str(e.get("url") or "") for e in embeds])
    author = message.get("author") or {}
    return (message["id"], guild["id"], guild["name"], channel["id"], channel["name"],
            author.get("id") or "", author.get("global_name") or author.get("username") or "",
            message.get("timestamp") or "", content, json.dumps(attachments), json.dumps(embeds),
            json.dumps(list(dict.fromkeys(URL.findall(evidence)))),
            json.dumps(list(dict.fromkeys(HASH.findall(evidence)))), json.dumps(message),
            datetime.now(timezone.utc).isoformat())


def _store_messages(conn, guild, channel, messages, pinned=False):
    for message in messages:
        rec = _normalize(message, guild, channel)
        conn.execute("""INSERT INTO discord_messages
            (id,guild_id,guild_name,channel_id,channel_name,author_id,author_name,timestamp,
             content,attachments,embeds,urls,hashes,raw,collected_at,pinned)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET guild_name=excluded.guild_name,
            channel_name=excluded.channel_name, content=excluded.content,
            attachments=excluded.attachments, embeds=excluded.embeds, urls=excluded.urls,
            hashes=excluded.hashes, raw=excluded.raw, collected_at=excluded.collected_at,
            pinned=MAX(discord_messages.pinned,excluded.pinned)""", (*rec, int(pinned or message.get("pinned", False))))
    conn.commit()


def _download_attachment(session, conn, guild_id, message_id, attachment, max_mb):
    aid = str(attachment.get("id") or "")
    if not SNOWFLAKE.fullmatch(aid):
        return
    existing = conn.execute("SELECT state FROM discord_attachments WHERE id=?",(aid,)).fetchone()
    if existing and existing["state"] == "downloaded":
        return
    url = attachment.get("url") or ""
    parsed = urlparse(url)
    size = int(attachment.get("size") or 0)
    max_bytes = max_mb * 1024 * 1024
    state, error, digest, path, extracted = "skipped", "", "", "", ""
    if parsed.scheme != "https" or parsed.hostname not in DOWNLOAD_HOSTS or parsed.username or parsed.password or parsed.port:
        error = "Attachment URL is not an approved Discord CDN host"
    elif size > max_bytes:
        error = f"Attachment exceeds {max_mb} MB limit"
    else:
        try:
            # Never forward the bot token to the CDN; do not follow redirects.
            with requests.get(url, stream=True, timeout=30, allow_redirects=False) as response:
                if response.status_code != 200:
                    raise DiscordError(f"CDN returned HTTP {response.status_code}")
                if int(response.headers.get("Content-Length") or 0) > max_bytes:
                    raise DiscordError("Attachment exceeds size limit")
                folder = ATTACHMENT_ROOT / guild_id / message_id
                folder.mkdir(parents=True, exist_ok=True)
                filename = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(attachment.get("filename") or "file"))[:120] or "file"
                dest = folder / (aid + "_" + filename)
                temporary = dest.with_suffix(dest.suffix + ".part")
                sha = hashlib.sha256()
                chunks, length = [], 0
                try:
                    with open(temporary, "wb") as file:
                        for chunk in response.iter_content(65536):
                            if not chunk: continue
                            length += len(chunk)
                            if length > max_bytes:
                                raise DiscordError("Attachment exceeds size limit")
                            file.write(chunk); sha.update(chunk)
                            if length <= 2 * 1024 * 1024: chunks.append(chunk)
                    os.replace(temporary, dest)
                finally:
                    if temporary.exists(): temporary.unlink()
                digest, path, state = sha.hexdigest(), str(dest), "downloaded"
                kind = (attachment.get("content_type") or "").split(";",1)[0].lower()
                if length <= 2 * 1024 * 1024 and (kind.startswith("text/") or Path(filename).suffix.lower() in TEXT_EXTENSIONS):
                    data = b"".join(chunks)
                    if b"\x00" not in data:
                        extracted = data.decode("utf-8", "replace")
        except (requests.RequestException, DiscordError, OSError, ValueError) as exc:
            state, error = "failed", str(exc)[:200]
    conn.execute("""INSERT INTO discord_attachments(id,message_id,guild_id,filename,url,size,state,sha256,path,text,error)
        VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,
        sha256=excluded.sha256,path=excluded.path,text=excluded.text,error=excluded.error""",
        (aid,message_id,guild_id,attachment.get("filename") or "",url,size,state,digest,path,extracted,error))
    if extracted:
        conn.execute("UPDATE discord_messages SET attachment_text=attachment_text || ? WHERE id=? AND attachment_text NOT LIKE ?",
                     ("\n"+extracted,message_id,"%"+extracted[:100]+"%"))
    conn.commit()


def _job_update(conn, job_id, **fields):
    if fields:
        keys = list(fields)
        conn.execute("UPDATE discord_jobs SET " + ",".join(k+"=?" for k in keys) + ",updated_at=? WHERE id=?",
                     [fields[k] for k in keys] + [_now(),job_id])
        conn.commit()


def _channel_update(conn, channel_id, **fields):
    keys = list(fields)
    conn.execute("UPDATE discord_channels SET " + ",".join(k+"=?" for k in keys) + ",updated_at=? WHERE id=?",
                 [fields[k] for k in keys] + [_now(),channel_id])
    conn.commit()


def _collect_channel(session, conn, guild, channel, job_id, download, max_mb, stop):
    cid = channel["id"]
    prior = conn.execute("SELECT cursor,state FROM discord_channels WHERE id=?",(cid,)).fetchone()
    before = prior["cursor"] if prior and prior["state"] in ("partial","interrupted","cancelled") else ""
    _channel_update(conn,cid,state="running",error="")
    read = 0
    while not stop.is_set():
        params = {"limit":100}
        if before: params["before"] = before
        page = _call(session,f"/channels/{cid}/messages",params)
        if not isinstance(page,list): raise DiscordError("Unexpected message response")
        if not page: break
        _store_messages(conn,guild,channel,page)
        for message in page:
            if download:
                for attachment in message.get("attachments") or []:
                    _download_attachment(session,conn,guild["id"],message["id"],attachment,max_mb)
        read += len(page)
        before = page[-1]["id"]
        _channel_update(conn,cid,cursor=before,history_count=(conn.execute(
            "SELECT history_count FROM discord_channels WHERE id=?",(cid,)).fetchone()[0]+len(page)))
        if job_id:
            _job_update(conn,job_id,read_count=(conn.execute(
                "SELECT read_count FROM discord_jobs WHERE id=?",(job_id,)).fetchone()[0]+len(page)))
        if len(page) < 100: break
    if stop.is_set():
        _channel_update(conn,cid,state="cancelled")
        return read, False
    pinned_count, marker = 0, ""
    while not stop.is_set():
        params = {"limit":50}
        if marker: params["before"] = marker
        pins = _call(session,f"/channels/{cid}/messages/pins",params)
        items = pins.get("items") or []
        messages = [i["message"] for i in items if isinstance(i.get("message"),dict)]
        _store_messages(conn,guild,channel,messages,pinned=True)
        if download:
            for message in messages:
                for attachment in message.get("attachments") or []:
                    _download_attachment(session,conn,guild["id"],message["id"],attachment,max_mb)
        pinned_count += len(messages)
        if not items or not pins.get("has_more"): break
        next_marker = items[-1].get("pinned_at")
        if not next_marker or next_marker == marker:
            raise DiscordError("Pins pagination ended without a cursor")
        marker = next_marker
    if stop.is_set():
        _channel_update(conn,cid,state="cancelled")
        return read, False
    _channel_update(conn,cid,state="complete",cursor="",pins_count=pinned_count)
    return read, True


def collect(token, guild_id, channel_ids=None, download=True, max_attachment_mb=25,
            job_id="", stop=None):
    info = inspect(token,guild_id)
    available = {c["id"]:c for c in info["channels"] if c["collectable"]}
    if not isinstance(channel_ids or [],list) or len(channel_ids or []) > 1000:
        raise DiscordError("Select up to 1,000 channels")
    selected = list(dict.fromkeys(_id(c,"channel ID") for c in channel_ids)) if channel_ids else list(available)
    if not selected or any(c not in available for c in selected):
        raise DiscordError("Select readable message channels from this guild")
    max_attachment_mb = max(1,min(int(max_attachment_mb),100))
    stop = stop or threading.Event()
    read, errors, done = 0, list(info["warnings"]), 0
    with _session(token) as session, closing(_db()) as conn:
        for cid in selected:
            if stop.is_set(): break
            try:
                count, finished = _collect_channel(session,conn,info["guild"],available[cid],job_id,download,max_attachment_mb,stop)
                read += count
                done += int(finished)
            except (DiscordError, requests.RequestException, OSError, ValueError) as exc:
                errors.append({"channel":available[cid]["name"],"error":str(exc)})
                _channel_update(conn,cid,state="partial",error=str(exc))
            if job_id: _job_update(conn,job_id,channel_done=done)
    return {"read":read,"channels":len(selected),"complete":done,"errors":errors,"cancelled":stop.is_set()}


def start_collection(token, guild_id, channel_ids=None, download=True, max_attachment_mb=25):
    guild_id = _id(guild_id, "guild ID")
    _session(token).close()  # Validate without retaining the token in persistent state.
    if not isinstance(channel_ids, list) or len(channel_ids) > 1000:
        raise DiscordError("Select up to 1,000 channels")
    selected = [_id(cid, "channel ID") for cid in channel_ids]
    job_id = uuid.uuid4().hex
    with closing(_db()) as conn:
        conn.execute("INSERT INTO discord_jobs(id,guild_id,state,started_at,updated_at,channel_ids) VALUES(?,?,?,?,?,?)",
                     (job_id,guild_id,"queued",_now(),_now(),json.dumps(selected)))
        conn.commit()
    stop = threading.Event()
    with _job_lock:
        _active_jobs[job_id] = stop

    def worker():
        try:
            with closing(_db()) as conn:
                _job_update(conn,job_id,state="running")
            result = collect(token,guild_id,selected,download,max_attachment_mb,job_id,stop)
            state = "cancelled" if result["cancelled"] else ("partial" if result["errors"] or result["complete"] < result["channels"] else "complete")
            with closing(_db()) as conn:
                _job_update(conn,job_id,state=state,error=json.dumps(result["errors"])[:10000])
        except Exception as exc:
            with closing(_db()) as conn:
                _job_update(conn,job_id,state="failed",error=str(exc)[:500])
        finally:
            with _job_lock:
                _active_jobs.pop(job_id,None)

    threading.Thread(target=worker,daemon=True,name="discord-collect-"+job_id[:8]).start()
    return {"id":job_id,"state":"queued"}


def job_status(job_id):
    if not re.fullmatch(r"[a-f0-9]{32}",job_id):
        raise DiscordError("Invalid job ID")
    with closing(_db()) as conn:
        row = conn.execute("SELECT * FROM discord_jobs WHERE id=?",(job_id,)).fetchone()
        if not row: raise DiscordError("Job not found")
        result = dict(row)
        ids = json.loads(result["channel_ids"])
        if ids:
            result["channels"] = [dict(r) for r in conn.execute(
                "SELECT id,name,type,state,history_count,pins_count,error FROM discord_channels WHERE id IN ("+
                ",".join("?" for _ in ids)+") ORDER BY name",ids)]
        else:
            result["channels"] = [dict(r) for r in conn.execute(
                "SELECT id,name,type,state,history_count,pins_count,error FROM discord_channels WHERE guild_id=? ORDER BY name",(result["guild_id"],))]
    with _job_lock:
        if result["state"] in ("queued","running") and job_id not in _active_jobs:
            result["state"] = "interrupted"
    result["channel_ids"] = ids
    result["error"] = json.loads(result["error"]) if result["error"].startswith("[") else result["error"]
    return result


def cancel_job(job_id):
    job_status(job_id)
    with _job_lock:
        stop = _active_jobs.get(job_id)
        if stop: stop.set()
    return job_status(job_id)


def channel_status(guild_id):
    with closing(_db()) as conn:
        return [dict(r) for r in conn.execute(
            "SELECT id,name,type,parent_id,state,history_count,pins_count,error,updated_at FROM discord_channels WHERE guild_id=? ORDER BY name",
            (_id(guild_id,"guild ID"),))]


def names(guild_id, search=""):
    with closing(_db()) as conn:
        rows = conn.execute("SELECT kind,id,name,matches FROM discord_names WHERE guild_id=? AND (name LIKE ? OR matches LIKE ?) ORDER BY kind,name LIMIT 1000",
                            (_id(guild_id,"guild ID"),"%"+search[:200]+"%","%"+search[:200]+"%")).fetchall()
    return [dict(kind=r["kind"],id=r["id"],name=r["name"],matches=json.loads(r["matches"])) for r in rows]


def attachment(attachment_id):
    with closing(_db()) as conn:
        row = conn.execute("SELECT * FROM discord_attachments WHERE id=?",(_id(attachment_id,"attachment ID"),)).fetchone()
    if not row or row["state"] != "downloaded" or not row["path"] or not Path(row["path"]).is_file():
        raise DiscordError("Attachment not available locally")
    path = Path(row["path"]).resolve()
    if not path.is_relative_to(ATTACHMENT_ROOT.resolve()):
        raise DiscordError("Invalid attachment path")
    return str(path), row["filename"]


def messages(guild_id="", channel_id="", search="", limit=100, offset=0, pinned=False):
    clauses, args = [], []
    for value, column in ((guild_id, "guild_id"), (channel_id, "channel_id")):
        if value:
            clauses.append(column + " = ?")
            args.append(_id(value, column))
    if search:
        clauses.append("(content LIKE ? OR author_name LIKE ? OR channel_name LIKE ? OR urls LIKE ? OR hashes LIKE ? OR attachment_text LIKE ?)")
        args.extend(["%" + search[:200] + "%"] * 6)
    if pinned:
        clauses.append("pinned = 1")
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with closing(_db()) as conn:
        total = conn.execute("SELECT count(*) FROM discord_messages" + where, args).fetchone()[0]
        rows = conn.execute("SELECT * FROM discord_messages" + where +
                            " ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?",
                            args + [max(1, min(int(limit), 500)), max(0, int(offset))]).fetchall()
    items = []
    ids = [r["id"] for r in rows]
    attachments = {}
    if ids:
        with closing(_db()) as conn:
            for r in conn.execute("SELECT id,message_id,state,sha256,text,error FROM discord_attachments WHERE message_id IN ("+
                                  ",".join("?" for _ in ids)+")",ids):
                attachments[r["id"]] = dict(r)
    for row in rows:
        item = dict(row)
        for key in ("attachments", "embeds", "urls", "hashes", "raw"):
            item[key] = json.loads(item[key])
        for a in item["attachments"]:
            a.update({k:v for k,v in attachments.get(str(a.get("id")),{}).items() if k not in ("id","message_id")})
        items.append(item)
    return {"total": total, "items": items}
