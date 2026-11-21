"""Credential Stealer Intelligence & Harvester module for MANTIS.

Capabilities:
- Local folder / file scanner (recursive .txt, .log, .csv, .zip/.rar/.7z) with native Windows folder picker.
- Telegram channel & external cloud link harvester (Pixeldrain, GoFile, MediaFire, Mega, direct URLs)
  with automatic password extraction from message captions and ephemeral archive cleanup.
- Weekly automated scheduler daemon (configurable day & UTC hour) + on-demand full sync.
- Plaintext password vault storage in SQLite (with SHA-256 deduplication hash, victim telemetry,
  and corporate watchlist hit detection).
- Built-in high-speed stealer & combo parsers + AI Agent Parser Studio that synthesizes and tests
  Python named-group regexes on unrecognized .txt log formats via MANTIS AI (with heuristic fallback).
"""
import asyncio
import csv
import hashlib
import io
import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger("mantis.credential_stealer")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
CS_DB_PATH = os.environ.get("MANTIS_CS_DB") or os.path.join(DATA_DIR, "credential_stealer.db")
STAGING_TEMP_DIR = os.path.join(DATA_DIR, "cs_staging_tmp")
DISK_FLOOR_BYTES = 2 * 1024 * 1024 * 1024
TG_BATCH_SIZE = 100
MAX_LINKS_PER_MESSAGE = 20

WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
COMMON_ARCHIVE_PASSWORDS = [
    "", "infected", "1234", "123456", "virus", "malware", "pass", "password", "123", "12345",
]

DEFAULT_SETTINGS = {
    "weekly_enabled": "true",
    "weekly_day": "Sunday",
    "weekly_hour_utc": "2",
    "auto_ai_parse": "true",
    "ephemeral_delete_archives": "true",
    "delete_after_parse": "false",
    "max_archive_mb": "250",
    "max_files_per_sync": "200",
    "extra_extensions": ".json,.sql,.db,.tar,.gz,.tgz",
    "last_weekly_run": "",
}

_CREDENTIALS_COLUMNS_SQL = """(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL DEFAULT '' COLLATE NOCASE,
    url TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '' COLLATE NOCASE,
    email TEXT NOT NULL DEFAULT '',
    password_plain TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL DEFAULT '',
    stealer_family TEXT NOT NULL DEFAULT 'Unknown',
    victim_ip TEXT NOT NULL DEFAULT '',
    victim_country TEXT NOT NULL DEFAULT '',
    victim_os TEXT NOT NULL DEFAULT '',
    victim_hwid TEXT NOT NULL DEFAULT '',
    source_type TEXT NOT NULL DEFAULT 'local',
    source_name TEXT NOT NULL DEFAULT '',
    file_name TEXT NOT NULL DEFAULT '',
    parser_name TEXT NOT NULL DEFAULT '',
    matched_watchlist INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    sightings INTEGER NOT NULL DEFAULT 1,
    UNIQUE(domain, username, password_hash)
)"""

_CREDENTIALS_INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS idx_cs_creds_domain ON cs_credentials(domain);
CREATE INDEX IF NOT EXISTS idx_cs_creds_email ON cs_credentials(email);
CREATE INDEX IF NOT EXISTS idx_cs_creds_user ON cs_credentials(username);
CREATE INDEX IF NOT EXISTS idx_cs_creds_family ON cs_credentials(stealer_family);
CREATE INDEX IF NOT EXISTS idx_cs_creds_watchlist ON cs_credentials(matched_watchlist);
CREATE INDEX IF NOT EXISTS idx_cs_creds_seen ON cs_credentials(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_cs_creds_source ON cs_credentials(source_name);
CREATE INDEX IF NOT EXISTS idx_cs_creds_source_type ON cs_credentials(source_type);
"""

SCHEMA_SQL = f"""
CREATE TABLE IF NOT EXISTS cs_credentials {_CREDENTIALS_COLUMNS_SQL};
{_CREDENTIALS_INDEXES_SQL}

CREATE TABLE IF NOT EXISTS cs_sources_local (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    folder_path TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL DEFAULT '',
    recursive INTEGER NOT NULL DEFAULT 1,
    auto_weekly INTEGER NOT NULL DEFAULT 1,
    delete_after_parse INTEGER NOT NULL DEFAULT 0,
    last_scanned_at TEXT DEFAULT '',
    files_scanned INTEGER NOT NULL DEFAULT 0,
    total_creds INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'ready',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cs_sources_tg (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL DEFAULT '',
    download_mode TEXT NOT NULL DEFAULT 'all',
    max_messages INTEGER NOT NULL DEFAULT 0,
    last_message_id INTEGER NOT NULL DEFAULT 0,
    last_synced_at TEXT DEFAULT '',
    total_creds INTEGER NOT NULL DEFAULT 0,
    files_downloaded INTEGER NOT NULL DEFAULT 0,
    messages_read INTEGER NOT NULL DEFAULT 0,
    messages_remaining INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'idle',
    last_error TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cs_parsers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    stealer_family TEXT NOT NULL DEFAULT 'Generic',
    mode TEXT NOT NULL DEFAULT 'block_regex',
    pattern TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    sample_text TEXT NOT NULL DEFAULT '',
    is_builtin INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    matches_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cs_unparsed_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path TEXT NOT NULL,
    file_name TEXT NOT NULL,
    source_name TEXT NOT NULL DEFAULT '',
    sample_snippet TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    suggested_parser_json TEXT DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cs_watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type TEXT NOT NULL DEFAULT 'domain',
    value TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    hits_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cs_jobs (
    id TEXT PRIMARY KEY,
    job_type TEXT NOT NULL,
    source_label TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'running',
    files_processed INTEGER NOT NULL DEFAULT 0,
    files_total INTEGER NOT NULL DEFAULT 0,
    files_downloaded INTEGER NOT NULL DEFAULT 0,
    files_skipped INTEGER NOT NULL DEFAULT 0,
    messages_remaining INTEGER NOT NULL DEFAULT 0,
    creds_found INTEGER NOT NULL DEFAULT 0,
    creds_new INTEGER NOT NULL DEFAULT 0,
    unparsed_files INTEGER NOT NULL DEFAULT 0,
    current_file TEXT NOT NULL DEFAULT '',
    log_lines TEXT NOT NULL DEFAULT '[]',
    error_msg TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    finished_at TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS cs_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

_RESERVED_LABELS = {
    "url", "host", "hostname", "username", "user", "user name", "userid", "user id",
    "login", "mail", "email", "password", "pass", "passwd", "pwd", "secret",
    "soft", "software", "browser", "application", "program", "profile", "app",
    "null", "none", "undefined", "unknown", "[not_saved]",
}


def _is_dangerous_catchall_regex(pattern: str) -> bool:
    """Detects dangerous catch-all regexes that match arbitrary non-empty lines without delimiters or key labels."""
    if not pattern:
        return True
    p = pattern.strip()
    p_no_classes = re.sub(r"\[\^?[^\]]*\]", "", p)
    p_no_names = re.sub(r"\(\?P<[a-zA-Z0-9_]+>", "", p_no_classes)
    has_newline_transition = bool(re.search(r"\\n|\n", p_no_classes))
    has_key_markers = bool(re.search(r"(?:url|host|user|login|pass|mail|email|account|web|soft|browser)\b", p_no_names, flags=re.I))
    # If the regex spans multiple lines without having any literal key markers outside character classes, it is a dangerous catch-all
    if has_newline_transition and not has_key_markers:
        return True
    return False


BUILTIN_PARSERS = [
    {
        "name": "Standard Stealer Block (RedLine / Lumma / Vidar / Stealc / MetaStealer)",
        "stealer_family": "Stealer Log",
        "mode": "block_regex",
        "pattern": (
            r"(?im)^\s*(?:url|host|hostname|origin|action_url|web|website|site|target|uri|portal|link)\s*[:=]\s*(?P<url>[^\s\r\n]+)"
            r"(?:\r?\n\s*(?:soft(?:ware)?|browser|application|program|profile)\s*[:=][^\r\n]*)?"
            r"\r?\n\s*(?:user(?:\s*name)?|userid|login|mail|email|account)\s*[:=]\s*(?P<username>[^\r\n]*)"
            r"\r?\n\s*(?:pass(?:word)?|passwd|pwd|secret)\s*[:=][ \t]*(?P<password>[^\r\n]+)"
            r"(?:\r?\n\s*(?:soft(?:ware)?|browser|application|program|profile)\s*[:=][^\r\n]*)?"
        ),
        "description": "Multi-line stealer Password.txt blocks with URL/Host, Username/Login, Password, and optional Soft/Browser line.",
        "sample_text": "URL: https://portal.example.com/login\nUsername: alice@example.com\nPassword: P@ssword123!\nApplication: Chrome",
    },
    {
        "name": "Order-Agnostic Stealer Parser",
        "stealer_family": "Stealer Log",
        "mode": "block_regex",
        "pattern": (
            r"(?im)^\s*(?:url|host|hostname|origin|web|website|site|target|portal|link)\s*[:=]\s*(?P<url>[^\s\r\n]+)"
            r"(?:\r?\n[^\r\n]{0,200}){0,4}?\r?\n\s*"
            r"(?:user(?:\s*name)?|userid|login|mail|email|account)\s*[:=]\s*(?P<username>[^\r\n]*)"
            r"(?:\r?\n[^\r\n]{0,200}){0,4}?\r?\n\s*"
            r"(?:pass(?:word)?|passwd|pwd|secret)\s*[:=][ \t]*(?P<password>[^\r\n]+)"
        ),
        "description": "Comprehensive order-agnostic stealer parser handling all header orderings, separators, and banner lines.",
        "sample_text": "URL: https://portal.example.com/login\nUsername: alice@example.com\nPassword: P@ssword123!",
    },
    {
        "name": "RedLine / Vidar / CocCoc Block (Soft First)",
        "stealer_family": "RedLine",
        "mode": "block_regex",
        "pattern": (
            r"(?im)^\s*(?:soft(?:ware)?|browser|application|program|profile)\s*[:=][^\r\n]*"
            r"\r?\n\s*(?:host|url|hostname|origin|web|website|site|target|uri|portal|link)\s*[:=]\s*(?P<url>[^\s\r\n]+)"
            r"(?:\r?\n[^\r\n]{0,160}){0,3}?\r?\n\s*"
            r"(?:login|user(?:\s*name)?|userid|mail|email|account)\s*[:=]\s*(?P<username>[^\r\n]*)"
            r"(?:\r?\n[^\r\n]{0,160}){0,3}?\r?\n\s*"
            r"(?:pass(?:word)?|passwd|pwd|secret)\s*[:=][ \t]*(?P<password>[^\r\n]+)"
        ),
        "description": "Multi-line stealer logs with Soft/Browser line first, followed by Host/URL, Login, and Password.",
        "sample_text": "Soft: Google Chrome (Default)\nHost: https://example.com\nLogin: admin\nPassword: SecretPassword123",
    },
    {
        "name": "Raccoon / Mars / Meta Stealer Block",
        "stealer_family": "Raccoon / Meta",
        "mode": "block_regex",
        "pattern": (
            r"(?im)^\s*(?:Host|URL|Web|Website|Server|Origin|Target|URI|Portal)\s*[:=]\s*(?P<url>[^\s\r\n]+)"
            r"(?:\r?\n[^\r\n]{0,160}){0,3}?\r?\n\s*"
            r"(?:Login|User(?:\s*Name)?|UserId|Account|Email)\s*[:=]\s*(?P<username>[^\r\n]*)"
            r"\r?\n\s*(?:Password|Passwd|Pass|Pwd|Secret)\s*[:=][ \t]*(?P<password>[^\r\n]+)"
        ),
        "description": "Flexible multi-line blocks where metadata lines sit between Host/URL and Login/Password.",
        "sample_text": "Host: https://vpn.acme.org\nBrowser: Chrome Default\nLogin: jdoe\nPassword: Secret99!",
    },
    {
        "name": "Standard Colon ULP (http(s)://url:user:pass)",
        "stealer_family": "ULP Combo",
        "mode": "line_regex",
        "pattern": (
            r"^(?P<url>(?:https?://)?[a-zA-Z0-9.-]+(?::\d+)?(?:/[^:\r\n]*)?):(?P<username>[^:\r\n]+):(?P<password>[^\r\n]+)$"
        ),
        "description": "Single-line URL:USER:PASS format with standard colon delimiters, supporting lines with or without http(s):// protocol prefix.",
        "sample_text": "https://sso.corp.com/auth:bob@corp.com:Winter2026!\nsite.com/login:bob@corp.com:Winter2026!",
    },
    {
        "name": "ULP Combo List (url:user:pass / pipe / tab)",
        "stealer_family": "ULP Combo",
        "mode": "line_regex",
        "pattern": (
            r"^(?P<url>(?:https?://|android://|ftp://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s:|;\t]*)?)"
            r"(?:[ \t]*[|;\t][ \t]*|:)(?P<username>[^:|;\t\r\n]{1,160})(?:[ \t]*[|;\t][ \t]*|:)(?P<password>[^\r\n]{1,256})$"
        ),
        "description": "Single-line ULP combo format separated by :, |, ;, or Tab.",
        "sample_text": "https://sso.corp.com/auth:bob@corp.com:Winter2026!",
    },
    {
        "name": "Reversed ULP Combo (user:pass:url)",
        "stealer_family": "ULP Combo",
        "mode": "line_regex",
        "pattern": (
            r"^(?P<username>(?!https?://|android://|ftp://)[^:|;\t\r\n]{1,160})"
            r"(?:[ \t]*[|;\t][ \t]*|:)(?P<password>[^:|;\t\r\n]{1,256})"
            r"(?:[ \t]*[|;\t][ \t]*|:)(?P<url>(?:https?://|android://|ftp://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s\r\n]*)?)$"
        ),
        "description": "Single-line reversed combo format (username:password:url or email|password|domain).",
        "sample_text": "bob@corp.com:Winter2026!:https://sso.corp.com/auth",
    },
    {
        "name": "Email:Password Combo",
        "stealer_family": "Email Combo",
        "mode": "line_regex",
        "pattern": (
            r"^(?P<username>[a-zA-Z0-9_.+-]+@(?P<url>[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+))"
            r"(?:[ \t]*[|;\t][ \t]*|:)(?P<password>[^\r\n]{1,256})$"
        ),
        "description": "Standard email:password or email|password combo lists (infers domain from email).",
        "sample_text": "admin@target-domain.io:SummerPass#42",
    },
    {
        "name": "Generic Account Combo (username:password)",
        "stealer_family": "Account Combo",
        "mode": "line_regex",
        "pattern": (
            r"^(?P<username>(?!(?:https?|android|ftp)://)"
            r"(?!(?i:url|host|hostname|origin|web|website|site|target|targetsite|soft|software|browser|application|program|profile|user|username|userid|login|mail|email|account|accountid|pass|password|passwd|pwd|secret|secretpass|ip|os|country|hwid|uid|build|location|geo|server|port|note|comment|date|time)[ \t]*[:|;\t])"
            r"(?:[a-zA-Z0-9_.-]+\\)?[^\s:|;\t/]{1,120})"
            r"(?:[ \t]*[|;\t][ \t]*|:(?!\s))(?P<password>[^\s:|;\t\r\n][^:|;\t\r\n]{0,255})$"
        ),
        "description": "Two-column username:password or domain\\user:password combo lists without URLs.",
        "sample_text": "CORP\\jdoe:WinterPass#2026",
    },
    {
        "name": "Key-Value Inline (url=... user=... pass=...)",
        "stealer_family": "KV Inline",
        "mode": "line_regex",
        "pattern": (
            r"(?i)(?:url|host|site|target|website|uri)\s*[:=]\s*(?P<url>\S+)[\s,|;]+"
            r"(?:user(?:\s*name)?|userid|login|email)\s*[:=]\s*(?P<username>[^\s,|;]+)[\s,|;]+"
            r"(?:pass(?:word)?|passwd|pwd|secret)\s*[:=]\s*(?P<password>\S+)"
        ),
        "description": "Single-line key-value pairs separated by spaces, commas, or pipes.",
        "sample_text": "url=https://mail.example.net | user=support | pass=Tr0ub4dor&3",
    },
]

PASSWORD_HINT_RE = re.compile(
    r"(?:pass(?:word)?|pwd|passphrase|key|code|parol|пароль)\s*[:=\-]?\s*[`\"']?([^\s\r\n<>\"'`]{2,48})",
    re.IGNORECASE,
)
URL_EXTRACT_RE = re.compile(r"https?://[^\s<>\"'\])]+", re.IGNORECASE)
NON_CRED_FILENAMES = {
    "system.txt", "userinformation.txt", "information.txt", "info.txt",
    "readme.txt", "domaindetects.txt", "installedprograms.txt",
    "processlist.txt", "processes.txt", "process.txt", "clipboard.txt",
    "screenshot.jpg", "screenshot.png", "screen.png", "screen.jpg",
    "hardware.txt", "software.txt", "softwares.txt", "installedbrowsers.txt",
    "installedsoftware.txt", "importantautofills.txt", "tokens.txt",
    "autofills.txt", "creditcards.txt", "desktop.ini", "thumbs.db",
    "brute.txt", "rdx.txt",
}
NON_CRED_DIRNAMES = {
    "autofills", "cookies", "creditcards", "filegrabber", "discord",
    "steam", "wallets", "telegram", "history", "downloads",
    "googleaccounts", "important files", "important_files",
}
PASSWORD_FILENAME_KEYWORDS = {
    "passwords.txt", "password.txt", "all passwords.txt",
    "all_passwords.txt", "allpasswords.txt", "all-passwords.txt",
    "credentials.txt", "creds.txt",
}


def _is_password_filename(filename: str) -> bool:
    """Robust matcher for stealer password files (e.g. 'All Passwords.txt', 'Passwords.txt', 'all_passwords.txt')."""
    fn = os.path.basename(filename or "").strip().lower()
    if not fn:
        return False
    if fn in PASSWORD_FILENAME_KEYWORDS:
        return True
    stem, ext = os.path.splitext(fn)
    if ext not in (".txt", ".log", ""):
        return False
    clean_stem = re.sub(r"[\s_\-]+", "", stem)
    return clean_stem in {
        "passwords", "password", "allpasswords", "allpassword", "pass", "allpass",
        "creds", "credentials", "allcreds", "allcredentials", "logins", "alllogins",
    } or clean_stem.endswith("passwords") or clean_stem.startswith("passwords")


def _is_non_cred_filename(filename: str) -> bool:
    fn = (filename or "").lower()
    if _is_password_filename(fn):
        return False
    return fn in NON_CRED_FILENAMES or fn.startswith(("cookies", "autofill", "history", "credit", "cc_", "process", "installed"))


def _is_non_cred_path(path: str) -> bool:
    norm = os.path.normpath(path).replace("\\", "/").lower()
    parts = norm.split("/")
    for part in parts[:-1]:
        if part in NON_CRED_DIRNAMES:
            return True
    return _is_non_cred_filename(parts[-1])

_scheduler_started = False
_scheduler_lock = threading.Lock()
_db_init_lock = threading.Lock()
_db_initialized = False


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect_db() -> sqlite3.Connection:
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(CS_DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=60000")
    except sqlite3.Error:
        pass
    return conn


def _migrate_and_dedup_credentials(conn: sqlite3.Connection) -> None:
    """Upgrades legacy cs_credentials schema and deduplicates existing rows by (domain, username, password_hash)."""
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='cs_credentials'"
    ).fetchone()
    ddl = (row[0] if row else "") or ""
    ddl_compact = re.sub(r"\s+", "", ddl).upper()
    if "UNIQUE(DOMAIN,USERNAME,PASSWORD_HASH)" in ddl_compact:
        return

    logger.info("Migrating cs_credentials to deduplicated UNIQUE(domain, username, password_hash) schema...")
    conn.execute("DROP TABLE IF EXISTS cs_credentials_dedup")
    conn.execute(f"CREATE TABLE cs_credentials_dedup {_CREDENTIALS_COLUMNS_SQL}")
    conn.execute(
        """
        INSERT INTO cs_credentials_dedup
        (domain, url, username, email, password_plain, password_hash, stealer_family,
         victim_ip, victim_country, victim_os, victim_hwid, source_type, source_name,
         file_name, parser_name, matched_watchlist, first_seen, last_seen, sightings)
        SELECT
            CASE
                WHEN LOWER(TRIM(domain)) LIKE 'www.%.%' THEN SUBSTR(LOWER(TRIM(domain)), 5)
                ELSE LOWER(TRIM(domain))
            END,
            RTRIM(TRIM(url), '/'),
            TRIM(CASE WHEN TRIM(username) != '' THEN username ELSE email END),
            LOWER(TRIM(email)),
            password_plain,
            password_hash,
            stealer_family,
            victim_ip,
            victim_country,
            victim_os,
            victim_hwid,
            source_type,
            source_name,
            file_name,
            parser_name,
            matched_watchlist,
            first_seen,
            last_seen,
            CASE WHEN sightings > 0 THEN sightings ELSE 1 END
        FROM cs_credentials
        WHERE 1
        ORDER BY id ASC
        ON CONFLICT(domain, username, password_hash) DO UPDATE SET
            url = CASE WHEN LENGTH(excluded.url) > LENGTH(cs_credentials_dedup.url) THEN excluded.url ELSE cs_credentials_dedup.url END,
            email = CASE WHEN cs_credentials_dedup.email = '' THEN excluded.email ELSE cs_credentials_dedup.email END,
            first_seen = CASE WHEN excluded.first_seen < cs_credentials_dedup.first_seen THEN excluded.first_seen ELSE cs_credentials_dedup.first_seen END,
            last_seen = CASE WHEN excluded.last_seen > cs_credentials_dedup.last_seen THEN excluded.last_seen ELSE cs_credentials_dedup.last_seen END,
            sightings = cs_credentials_dedup.sightings + excluded.sightings,
            matched_watchlist = MAX(cs_credentials_dedup.matched_watchlist, excluded.matched_watchlist)
        """
    )
    conn.execute("DROP TABLE cs_credentials")
    conn.execute("ALTER TABLE cs_credentials_dedup RENAME TO cs_credentials")
    conn.executescript(_CREDENTIALS_INDEXES_SQL)


def init_db() -> None:
    global _db_initialized
    with _db_init_lock:
        conn = connect_db()
        try:
            conn.executescript(SCHEMA_SQL)
            _migrate_and_dedup_credentials(conn)
            try:
                conn.execute("ALTER TABLE cs_sources_local ADD COLUMN delete_after_parse INTEGER NOT NULL DEFAULT 0")
            except sqlite3.OperationalError:
                pass
            for column in ("files_downloaded", "files_skipped", "messages_remaining"):
                try:
                    conn.execute(f"ALTER TABLE cs_jobs ADD COLUMN {column} INTEGER NOT NULL DEFAULT 0")
                except sqlite3.OperationalError:
                    pass
            for column in ("messages_read", "messages_remaining"):
                try:
                    conn.execute(f"ALTER TABLE cs_sources_tg ADD COLUMN {column} INTEGER NOT NULL DEFAULT 0")
                except sqlite3.OperationalError:
                    pass
            migration_done = conn.execute("SELECT 1 FROM cs_settings WHERE key='_tg_default_50_migrated'").fetchone()
            if not migration_done:
                migrated = conn.execute("UPDATE cs_sources_tg SET max_messages=0 WHERE max_messages=50").rowcount
                conn.execute("INSERT INTO cs_settings(key,value) VALUES('_tg_default_50_migrated','1')")
                logger.info("Migrated %d Telegram channels from the old 50-message default to unlimited", migrated)
            ts = now_iso()
            for key, val in DEFAULT_SETTINGS.items():
                conn.execute(
                    "INSERT OR IGNORE INTO cs_settings(key, value) VALUES(?, ?)",
                    (key, str(val)),
                )
            for p in BUILTIN_PARSERS:
                conn.execute(
                    """
                    INSERT INTO cs_parsers
                    (name, stealer_family, mode, pattern, description, sample_text, is_builtin, enabled, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?)
                    ON CONFLICT(name) DO UPDATE SET
                        stealer_family = excluded.stealer_family,
                        mode = excluded.mode,
                        pattern = excluded.pattern,
                        description = excluded.description,
                        sample_text = excluded.sample_text
                    WHERE is_builtin = 1
                    """,
                    (
                        p["name"], p["stealer_family"], p["mode"], p["pattern"],
                        p["description"], p["sample_text"], ts,
                    ),
                )
            # Remove dangerous catch-all / corrupted custom parsers
            conn.execute(
                """
                DELETE FROM cs_parsers 
                WHERE is_builtin = 0 
                  AND (
                    name IN (
                        'Generic Line-Sequential Credential Parser',
                        'Generic Credential / Combo Parser',
                        'apple_cdn_ipsw_url_fallback_parser',
                        'Machine_Mac_Identifier_Parser',
                        'KeyValueEmailIdentifierParser',
                        'identifier_list_parser',
                        'ASP.NET / Form Field Credential Dumper Parser',
                        'redline_encoded_traffic_parser',
                        'ASPNet_FormField_Coupon_Parser',
                        'Generic Two-Line Combo Parser',
                        'telegram_tag_watermark_stealer_block',
                        'generic_credential_note_parser',
                        'email_password_multiline_combo_parser'
                    )
                    OR pattern LIKE '%[^\r\n]%\r%\n%[^\r\n]%\r%\n%[^\r\n]%'
                  )
                """
            )
            # Purge corrupted records generated by rogue parsers (if any exist)
            has_corrupt = conn.execute("SELECT 1 FROM cs_credentials WHERE domain LIKE '%=%' LIMIT 1").fetchone()
            if has_corrupt:
                conn.execute(
                    """
                    DELETE FROM cs_credentials 
                    WHERE parser_name IN ('Generic Line-Sequential Credential Parser', 'Generic Credential / Combo Parser')
                       OR domain LIKE '%=%'
                       OR domain LIKE '%---%'
                       OR username IN ('URL', 'Username', 'Password', 'Host', 'Soft', 'Application', 'Login', 'Pass', 'Pwd')
                       OR password_plain LIKE 'Application: %'
                       OR password_plain LIKE 'Soft: %'
                    """
                )
            # Reset any orphaned scanning states from interrupted jobs
            try:
                conn.execute("UPDATE cs_sources_local SET status = 'ready' WHERE status = 'scanning'")
                conn.execute("UPDATE cs_jobs SET status = 'stopped' WHERE status = 'running'")
            except sqlite3.OperationalError:
                pass

            # Ensure FTS5 trigram virtual table and sync triggers exist
            _ensure_fts_index(conn)

            conn.commit()
            _db_initialized = True
        finally:
            conn.close()


def _ensure_fts_index(conn: sqlite3.Connection) -> None:
    """Ensure FTS5 virtual table with trigram tokenizer and sync triggers exist."""
    try:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='cs_credentials_fts'"
        ).fetchone()
        fts_created = False
        if not row:
            conn.executescript("""
                CREATE VIRTUAL TABLE IF NOT EXISTS cs_credentials_fts USING fts5(
                    domain, url, username, email, victim_ip, source_name,
                    content='cs_credentials',
                    content_rowid='id',
                    tokenize='trigram'
                );

                CREATE TRIGGER IF NOT EXISTS cs_credentials_ai AFTER INSERT ON cs_credentials BEGIN
                  INSERT INTO cs_credentials_fts(rowid, domain, url, username, email, victim_ip, source_name)
                  VALUES (new.id, new.domain, new.url, new.username, new.email, new.victim_ip, new.source_name);
                END;

                CREATE TRIGGER IF NOT EXISTS cs_credentials_ad AFTER DELETE ON cs_credentials BEGIN
                  INSERT INTO cs_credentials_fts(cs_credentials_fts, rowid, domain, url, username, email, victim_ip, source_name)
                  VALUES('delete', old.id, old.domain, old.url, old.username, old.email, old.victim_ip, old.source_name);
                END;

                CREATE TRIGGER IF NOT EXISTS cs_credentials_au AFTER UPDATE ON cs_credentials BEGIN
                  INSERT INTO cs_credentials_fts(cs_credentials_fts, rowid, domain, url, username, email, victim_ip, source_name)
                  VALUES('delete', old.id, old.domain, old.url, old.username, old.email, old.victim_ip, old.source_name);
                  INSERT INTO cs_credentials_fts(rowid, domain, url, username, email, victim_ip, source_name)
                  VALUES (new.id, new.domain, new.url, new.username, new.email, new.victim_ip, new.source_name);
                END;
            """)
            fts_created = True

        if fts_created:
            has_rows = conn.execute("SELECT 1 FROM cs_credentials LIMIT 1").fetchone()
            if has_rows:
                logger.info("[FTS5] Rebuilding cs_credentials_fts index from existing records...")
                conn.execute("INSERT INTO cs_credentials_fts(cs_credentials_fts) VALUES('rebuild')")
                logger.info("[FTS5] cs_credentials_fts index rebuilt successfully.")
    except Exception as e:
        logger.warning("[FTS5] FTS5 initialization error (will use fallback LIKE queries): %s", e)


def ensure_db() -> None:
    if not _db_initialized:
        init_db()


# ---------------------------------------------------------------------------
# Settings Helpers
# ---------------------------------------------------------------------------
def _extra_extensions(raw: Any) -> List[str]:
    parts = raw.split(",") if isinstance(raw, str) else raw
    if not isinstance(parts, (list, tuple)) or len(parts) > 20:
        raise ValueError("extra_extensions accepts at most 20 extensions")
    cleaned = []
    for part in parts:
        ext = str(part).strip().lower()
        if not ext:
            continue
        ext = "." + ext.lstrip(".")
        if len(ext) > 10 or "/" in ext or "\\" in ext or not re.fullmatch(r"\.[a-z0-9]+", ext):
            raise ValueError(f"Invalid extension: {ext[:20]}")
        if ext not in cleaned:
            cleaned.append(ext)
    return cleaned


def get_settings() -> Dict[str, Any]:
    ensure_db()
    conn = connect_db()
    try:
        raw = dict(DEFAULT_SETTINGS)
        for row in conn.execute("SELECT key, value FROM cs_settings"):
            raw[row["key"]] = row["value"]
        return {
            "weekly_enabled": str(raw.get("weekly_enabled", "true")).lower() == "true",
            "weekly_day": raw.get("weekly_day", "Sunday") if raw.get("weekly_day") in WEEKDAYS else "Sunday",
            "weekly_hour_utc": max(0, min(23, int(raw.get("weekly_hour_utc", 2) or 2))),
            "auto_ai_parse": str(raw.get("auto_ai_parse", "true")).lower() == "true",
            "ephemeral_delete_archives": str(raw.get("ephemeral_delete_archives", "true")).lower() == "true",
            "delete_after_parse": str(raw.get("delete_after_parse", "false")).lower() == "true",
            "max_archive_mb": max(10, min(2048, int(raw.get("max_archive_mb", 250) or 250))),
            "max_files_per_sync": max(10, min(5000, int(raw.get("max_files_per_sync", 200) or 200))),
            "extra_extensions": _extra_extensions(raw.get("extra_extensions", DEFAULT_SETTINGS["extra_extensions"])),
            "last_weekly_run": raw.get("last_weekly_run", ""),
        }
    finally:
        conn.close()


def save_settings(payload: Dict[str, Any]) -> Dict[str, Any]:
    ensure_db()
    current = get_settings()
    updated = {
        "weekly_enabled": "true" if payload.get("weekly_enabled", current["weekly_enabled"]) else "false",
        "weekly_day": payload.get("weekly_day", current["weekly_day"]) if payload.get("weekly_day", current["weekly_day"]) in WEEKDAYS else current["weekly_day"],
        "weekly_hour_utc": str(max(0, min(23, int(payload.get("weekly_hour_utc", current["weekly_hour_utc"]))))),
        "auto_ai_parse": "true" if payload.get("auto_ai_parse", current["auto_ai_parse"]) else "false",
        "ephemeral_delete_archives": "true" if payload.get("ephemeral_delete_archives", current["ephemeral_delete_archives"]) else "false",
        "delete_after_parse": "true" if payload.get("delete_after_parse", current.get("delete_after_parse", False)) else "false",
        "max_archive_mb": str(max(10, min(2048, int(payload.get("max_archive_mb", current["max_archive_mb"]))))),
        "max_files_per_sync": str(max(10, min(5000, int(payload.get("max_files_per_sync", current["max_files_per_sync"]))))),
        "extra_extensions": ",".join(_extra_extensions(payload.get("extra_extensions", current["extra_extensions"]))),
    }
    conn = connect_db()
    try:
        for k, v in updated.items():
            conn.execute(
                "INSERT INTO cs_settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (k, v),
            )
        conn.commit()
    finally:
        conn.close()
    return get_settings()


# ---------------------------------------------------------------------------
# Normalization & Victim Telemetry Extraction
# ---------------------------------------------------------------------------
def extract_domain(url_or_domain: str, username: str = "") -> str:
    """Fast string-splitting domain extractor optimized for multi-million-line log streams."""
    raw = (url_or_domain or "").strip()
    if raw:
        raw = re.sub(r"^(?:url|host|hostname|web|site|portal|link|origin|domain)\s*[:=]\s*", "", raw, flags=re.I).strip()
        scheme_idx = raw.find("://")
        if scheme_idx != -1:
            raw = raw[scheme_idx + 3:]
        for sep in ("/", "?", "#"):
            sep_idx = raw.find(sep)
            if sep_idx != -1:
                raw = raw[:sep_idx]
        at_idx = raw.rfind("@")
        if at_idx != -1:
            raw = raw[at_idx + 1:]
        if ":" in raw and not raw.startswith("["):
            raw = raw.split(":", 1)[0]
        cleaned = raw.strip(".").lower()
        if cleaned.startswith("www.") and "." in cleaned[4:]:
            cleaned = cleaned[4:]
        if re.search(r"[=\-*_~#]", cleaned) or not re.search(r"[a-z0-9]", cleaned):
            cleaned = ""
        if "." in cleaned:
            return cleaned[:180]
    if "@" in (username or ""):
        u = username.split("@", 1)[-1].strip().lower()
        if "." in u and not re.search(r"[=\-*_~#]", u):
            return u[:180]
    return ""


def _normalize_cred_fields(domain: str, url: str, username: str, email: str = "") -> Tuple[str, str, str, str]:
    """Normalizes credential identifiers so case, scheme/path, and www differences deduplicate consistently."""
    u_raw = (username or email or "").strip()
    u_clean = re.sub(r"^(?:user(?:\s*name)?|userid|user id|login|mail|email|account)\s*[:=]\s*", "", u_raw, flags=re.I).strip()
    if u_clean.lower() in _RESERVED_LABELS or re.match(r"^[=\-*_~#]{2,}$", u_clean):
        u_clean = ""
    user_val = u_clean[:200]
    email_val = (email or extract_email(user_val)).strip().lower()[:254]

    url_raw = (url or "").strip()
    url_clean = re.sub(r"^(?:url|host|hostname|web|website|site|target|portal|link|origin)\s*[:=]\s*", "", url_raw, flags=re.I).strip().rstrip("/")
    if url_clean.lower() in _RESERVED_LABELS or re.match(r"^[=\-*_~#]{2,}$", url_clean):
        url_clean = ""
    url_val = url_clean[:500]

    dom_raw = (domain or "").strip()
    dom_clean = re.sub(r"^(?:domain|host|url|site)\s*[:=]\s*", "", dom_raw, flags=re.I).strip()
    if dom_clean.lower() in _RESERVED_LABELS or re.match(r"^[=\-*_~#]{2,}$", dom_clean):
        dom_clean = ""

    dom_val = extract_domain(dom_clean or url_val, user_val)
    if not dom_val and dom_clean and "." in dom_clean and not re.search(r"[=\-*_~#]", dom_clean):
        dom_val = dom_clean.lower()[:180]

    if dom_val.startswith("www.") and "." in dom_val[4:]:
        dom_val = dom_val[4:]

    if not url_val and dom_val:
        url_val = dom_val[:500]

    return dom_val, url_val, user_val, email_val


def extract_email(username: str) -> str:
    u = (username or "").strip()
    if "@" in u and "." in u.split("@")[-1]:
        return u[:254].lower()
    return ""


def detect_stealer_family(filename: str = "", content: str = "", default_family: str = "Unknown") -> str:
    combined = (f"{filename}\n{content[:2500]}").lower()
    markers = [
        ("LummaC2", ["lummac2", "lumma", "lid="]),
        ("RedLine", ["redline", "build id:", "redline stealer", "redline_market_bot"]),
        ("Vidar", ["vidar", "vidar stealer"]),
        ("Stealc", ["stealc"]),
        ("Raccoon", ["raccoon", "record id:"]),
        ("MetaStealer", ["metastealer", "meta stealer", "metastealer_bot"]),
        ("RisePro", ["risepro"]),
        ("Aurora", ["aurora stealer", "aurora"]),
        ("Mystic", ["mystic stealer"]),
        ("Taurus", ["taurus"]),
        ("Formbook", ["formbook", "xloader"]),
    ]
    for fam, keys in markers:
        if any(k in combined for k in keys):
            return fam
    return default_family


def parse_victim_system_info(text: str, filename: str = "") -> Dict[str, str]:
    info = {
        "victim_ip": "",
        "victim_country": "",
        "victim_os": "",
        "victim_hwid": "",
        "stealer_family": detect_stealer_family(filename, text, ""),
    }
    if not text:
        return info
    m_ip = re.search(r"(?im)^(?:IP(?:\s*Address)?|External\s*IP)\s*[:=]\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", text)
    if m_ip:
        info["victim_ip"] = m_ip.group(1).strip()
    m_country = re.search(r"(?im)^(?:Country|Location|Geo)\s*[:=]\s*([A-Za-z]{2}(?:\s*\([^)]+\))?|[A-Za-z\s]{2,32})", text)
    if m_country:
        info["victim_country"] = m_country.group(1).strip()[:32]
    m_os = re.search(r"(?im)^(?:OS|Operating\s*System|Windows)\s*[:=]\s*([^\r\n]{2,80})", text)
    if m_os:
        info["victim_os"] = m_os.group(1).strip()[:80]
    m_hwid = re.search(r"(?im)^(?:HWID|Machine\s*ID|UID|Build\s*ID)\s*[:=]\s*([A-Za-z0-9\-_]{6,80})", text)
    if m_hwid:
        info["victim_hwid"] = m_hwid.group(1).strip()[:80]
    return info


# ---------------------------------------------------------------------------
# Parser Execution Engine
# ---------------------------------------------------------------------------
def list_parsers(conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
    ensure_db()
    own = conn is None
    if own:
        conn = connect_db()
    try:
        rows = conn.execute(
            "SELECT * FROM cs_parsers ORDER BY is_builtin DESC, id ASC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        if own:
            conn.close()


def _append_dedup_match(
    matches: List[Dict[str, Any]],
    seen: Dict[Tuple[str, str, str], int],
    url_raw: str,
    user_raw: str,
    pass_raw: str,
    stealer_family: str,
) -> None:
    """Normalizes, validates, and deduplicates parsed credentials in-batch."""
    p_raw = (pass_raw or "").strip()
    p_clean = re.sub(r"^(?:pass(?:word)?|passwd|pwd|secret)\s*[:=]\s*", "", p_raw, flags=re.I).strip()

    if not p_clean or re.match(r"^[=\-*_~#]{2,}$", p_clean):
        return
    if p_clean.lower() in _RESERVED_LABELS:
        return
    if re.match(r"^(?:username|user|url|host|soft|application|browser)\s*[:=]", p_raw, flags=re.I):
        return

    domain_val, url_val, user_val, email_val = _normalize_cred_fields("", url_raw, user_raw, "")

    if not user_val and not url_val and not domain_val:
        return

    if p_clean in {"UNKNOWN", "[NOT_SAVED]", "null", "None"} and not url_val and not domain_val:
        return

    key = (domain_val, user_val.lower(), p_clean)
    existing_idx = seen.get(key)
    if existing_idx is not None:
        if len(url_val) > len(matches[existing_idx]["url"]):
            matches[existing_idx]["url"] = url_val
        return
    seen[key] = len(matches)
    matches.append({
        "domain": domain_val,
        "url": url_val,
        "username": user_val,
        "email": email_val,
        "password_plain": p_clean,
        "stealer_family": stealer_family,
    })


def test_parser_pattern(
    sample_text: str,
    pattern: str,
    mode: str = "block_regex",
    stealer_family: str = "Custom",
    max_matches: int = 50000,
) -> Dict[str, Any]:
    if not pattern or not pattern.strip():
        raise ValueError("Regex pattern cannot be empty.")
    try:
        flags = re.MULTILINE if mode == "line_regex" else (re.MULTILINE | re.DOTALL)
        compiled = re.compile(pattern, flags)
    except re.error as exc:
        raise ValueError(f"Invalid regular expression: {exc}")

    matches: List[Dict[str, Any]] = []
    seen: Dict[Tuple[str, str, str], int] = {}

    if mode == "line_regex":
        for line in (sample_text or "").splitlines():
            line_s = line.strip()
            if not line_s:
                continue
            m = compiled.search(line_s)
            if not m:
                continue
            gd = m.groupdict()
            url_val = (gd.get("url") or gd.get("host") or gd.get("domain") or "").strip()
            user_val = (gd.get("username") or gd.get("user") or gd.get("email") or gd.get("login") or "").strip()
            pass_val = (gd.get("password") or gd.get("pass") or gd.get("pwd") or "").strip()
            if not (user_val or url_val) or not pass_val:
                continue
            _append_dedup_match(matches, seen, url_val, user_val, pass_val, stealer_family or "Custom")
            if len(matches) >= max_matches:
                break
    else:
        for m in compiled.finditer(sample_text or ""):
            gd = m.groupdict()
            url_val = (gd.get("url") or gd.get("host") or gd.get("domain") or "").strip()
            user_val = (gd.get("username") or gd.get("user") or gd.get("email") or gd.get("login") or "").strip()
            pass_val = (gd.get("password") or gd.get("pass") or gd.get("pwd") or "").strip()
            if not pass_val or (not url_val and not user_val):
                continue
            # Filter out placeholder "UNKNOWN" / "[NOT_SAVED]" lines if obviously empty
            if pass_val in {"UNKNOWN", "[NOT_SAVED]", "null", "None"} and not url_val:
                continue
            _append_dedup_match(matches, seen, url_val, user_val, pass_val, stealer_family or "Custom")
            if len(matches) >= max_matches:
                break

    return {
        "valid": True,
        "count": len(matches),
        "matches": matches,
        "named_groups": list(compiled.groupindex.keys()),
    }


_KV_URL_KEYS = {
    "url", "host", "hostname", "origin", "action_url", "web", "website",
    "site", "target", "targetsite", "target site", "uri", "portal", "link",
    "domain", "server", "application",
}
_KV_USER_KEYS = {
    "user", "username", "user name", "userid", "user id", "login", "mail",
    "email", "account", "accountid", "account id", "uname", "id",
}
_KV_PASS_KEYS = {
    "pass", "password", "passwd", "pwd", "secret", "secretpass", "secret pass",
    "pin", "code", "token",
}
_GENERIC_CRED_STEMS = {
    "", "passwords", "password", "all_passwords", "all-passwords", "combo",
    "combos", "creds", "credentials", "log", "logs", "snippet",
}


def _read_text_file(fpath: str, max_bytes: int = 25 * 1024 * 1024) -> str:
    """Reads a text log file while handling UTF-8, UTF-16 LE/BE, BOMs, and NUL bytes."""
    with open(fpath, "rb") as f:
        raw = f.read(max_bytes)
    if not raw:
        return ""
    if raw.startswith(b"\xff\xfe"):
        text = raw[2:].decode("utf-16-le", errors="ignore")
    elif raw.startswith(b"\xfe\xff"):
        text = raw[2:].decode("utf-16-be", errors="ignore")
    elif raw.startswith(b"\xef\xbb\xbf"):
        text = raw[3:].decode("utf-8", errors="ignore")
    elif raw[:256].count(b"\x00") > 10:
        text = raw.decode("utf-16-le", errors="ignore")
    else:
        text = raw.decode("utf-8", errors="ignore")
    return text.replace("\ufeff", "").replace("\x00", "")


def _is_non_cred_filename(filename: str) -> bool:
    fn = (filename or "").lower()
    return fn in NON_CRED_FILENAMES or fn.startswith(("cookies", "autofill", "history", "credit", "cc_", "process", "installed"))


def _fallback_domain_from_filename(filename: str) -> str:
    stem = os.path.splitext(os.path.basename(filename or ""))[0]
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "-", stem).strip("-._").lower()
    if cleaned in _GENERIC_CRED_STEMS:
        return ""
    return cleaned[:120]


_STEALER_URL_KEYS = {
    "url", "host", "hostname", "origin", "action_url", "action url", "web", "website",
    "site", "target", "targetsite", "target site", "uri", "portal", "link",
    "domain", "server", "http", "https", "address",
}
_STEALER_USER_KEYS = {
    "user", "username", "user name", "userid", "user id", "login", "mail",
    "email", "account", "accountid", "account id", "uname", "id", "name", "client",
}
_STEALER_PASS_KEYS = {
    "pass", "password", "passwd", "pwd", "secret", "secretpass", "secret pass",
    "pin", "code", "пароль", "passphrase",
}
_STEALER_APP_KEYS = {"soft", "software", "browser", "application", "program", "profile", "app"}
_STEALER_IGNORE_KEYS = {
    "telegram", "channel", "support", "admin", "dev", "owner", "contact", "watermark",
    "date", "time", "ip", "country", "hwid", "os", "build", "screen", "display",
    "ram", "gpu", "cpu", "location", "path", "wallet", "version",
}


def _clean_field_val(val: str) -> str:
    """Strips common leading field labels if a parser or line erroneously retained them."""
    return re.sub(
        r"^(?:url|host|hostname|web|site|user(?:\s*name)?|userid|login|mail|email|pass(?:word)?|passwd|pwd|soft|browser|application)\s*[:=]\s*",
        "",
        (val or "").strip(),
        flags=re.I,
    ).strip()


def _score_matches(matches: List[Dict[str, Any]]) -> float:
    """Computes quality score for parsed matches to reject noisy catch-all regexes."""
    if not matches:
        return 0.0
    valid_score = 0.0
    penalty = 0.0
    for m in matches:
        dom = m.get("domain", "")
        url = m.get("url", "")
        usr = m.get("username", "")
        pwd = m.get("password_plain", "")

        # Immediate disqualifiers: delimiter lines or reserved header labels as values
        if not pwd or re.match(r"^[=\-*_~#]{2,}$", pwd):
            penalty += 25.0
            continue
        if re.match(r"^[=\-*_~#]{2,}$", dom) or re.match(r"^[=\-*_~#]{2,}$", url):
            penalty += 25.0
            continue
        if usr.lower() in _RESERVED_LABELS:
            penalty += 20.0
            continue
        if re.search(r"^(?:url|host|username|password|soft|application)\s*[:=]", usr, flags=re.I):
            penalty += 20.0
            continue
        if re.search(r"^(?:url|host|username|password|soft|application)\s*[:=]", pwd, flags=re.I):
            penalty += 20.0
            continue

        item_score = 1.0
        if dom and "." in dom and not re.search(r"[=\-*_~#]", dom):
            item_score += 2.0
        if url.startswith(("http://", "https://")):
            item_score += 1.5
        if usr and "@" in usr:
            item_score += 1.5
        elif usr:
            item_score += 1.0
        if len(pwd) >= 3:
            item_score += 1.0
        valid_score += item_score

    return max(0.0, valid_score - penalty)


def _parse_order_agnostic_blocks(content: str, stealer_family: str = "Stealer Log") -> List[Dict[str, Any]]:
    """Extracts credentials from multi-line stealer blocks regardless of key ordering, watermarks, or banners."""
    matches: List[Dict[str, Any]] = []
    seen: Dict[Tuple[str, str, str], int] = {}
    cur: Dict[str, str] = {}

    def _flush() -> None:
        nonlocal cur
        p_val = _clean_field_val(cur.get("password") or "")
        url_val = _clean_field_val(cur.get("url") or "")
        u_val = _clean_field_val(cur.get("username") or "")
        cur = {}
        if not p_val or (not url_val and not u_val):
            return
        if p_val.lower() in {"unknown", "[not_saved]", "null", "none"} and not url_val:
            return
        if re.match(r"^[=\-*_~#]{2,}$", p_val) or re.match(r"^[=\-*_~#]{2,}$", url_val):
            return
        if len(matches) >= 50000:
            return
        _append_dedup_match(matches, seen, url_val, u_val, p_val, stealer_family or "Stealer Log")

    for raw_line in (content or "").splitlines():
        line = raw_line.strip()
        if not line:
            # An empty line concludes the block if we already have password and (url or user)
            if cur.get("password") and (cur.get("url") or cur.get("username")):
                _flush()
            continue

        # Common block separators: ======, ------, ******, [LOG...], [BOT...]
        if re.match(r"^(?:[=\-*_~#]{3,}|\[LOG[^\]]*\]|\[BOT[^\]]*\])$", line):
            _flush()
            continue

        m = re.match(r"^([A-Za-z\u0400-\u04FF][A-Za-z0-9 _\-]{0,28})\s*[:=]\s*(.*)$", line)
        if not m:
            continue

        key_raw = m.group(1).strip()
        val = m.group(2).strip()
        norm_key = re.sub(r"[\s_\-]+", " ", key_raw.lower())

        if norm_key in _STEALER_IGNORE_KEYS or "t.me/" in val.lower():
            continue

        if norm_key in _STEALER_URL_KEYS:
            if cur.get("url") or (cur.get("password") and cur.get("username")):
                _flush()
            cur["url"] = val
        elif norm_key in _STEALER_USER_KEYS:
            if cur.get("username") and cur.get("password"):
                _flush()
            cur["username"] = val
        elif norm_key in _STEALER_PASS_KEYS:
            if cur.get("password") and (cur.get("url") or cur.get("username")):
                _flush()
            cur["password"] = val
        elif norm_key in _STEALER_APP_KEYS:
            if cur.get("password") and (cur.get("url") or cur.get("username")):
                cur["app"] = val
                _flush()
            else:
                cur["app"] = val

    _flush()
    return matches


def _looks_like_credential_file(filename: str, content: str) -> bool:
    if _is_password_filename(filename):
        return True
    if _is_non_cred_filename(filename):
        return False
    fn = (filename or "").lower()
    if any(k in fn for k in ("password", "pass", "cred", "combo", "ulp", "login", "account")):
        return True
    sample = (content or "")[:4000]
    lines = [ln.strip() for ln in sample.splitlines() if ln.strip()]
    if len(lines) < 1:
        return False
    # Check if there are indicators of structured credential lines or key-value blocks
    sample_l = sample.lower()
    if any(tok in sample_l for tok in ("pass:", "password:", "pwd:", "login:", "username:", "http://", "https://")):
        return True
    delim_hits = sum(1 for ln in lines[:25] if ln.count(":") >= 1 or ln.count("|") >= 2 or ln.count(";") >= 2 or "\t" in ln)
    return delim_hits >= min(2, len(lines))


def parse_text_with_parsers(
    content: str,
    filename: str = "",
    victim_info: Optional[Dict[str, str]] = None,
    parsers: Optional[List[Dict[str, Any]]] = None,
    update_match_stats: bool = True,
    force_parser_name: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], str]:
    if parsers is None:
        parsers = list_parsers()
    vinfo = victim_info or {}
    inferred_family = vinfo.get("stealer_family") or detect_stealer_family(filename, content, "")

    # A parser chosen by the user runs alone; if it finds nothing we fall back to
    # automatic detection so an upload never silently returns zero credentials.
    if force_parser_name:
        spec = next((p for p in parsers if (p.get("name") or "") == force_parser_name), None)
        if spec is not None and spec.get("enabled", 1):
            forced_matches: List[Dict[str, Any]] = []
            try:
                res = test_parser_pattern(
                    content,
                    spec.get("pattern", ""),
                    spec.get("mode", "block_regex"),
                    inferred_family or spec.get("stealer_family") or "Unknown",
                )
                forced_matches = res.get("matches") or []
            except Exception:
                forced_matches = []
            if forced_matches:
                fallback_dom = _fallback_domain_from_filename(filename).lower()
                if fallback_dom:
                    for item in forced_matches:
                        if not item.get("domain"):
                            item["domain"] = fallback_dom
                        if not item.get("url"):
                            item["url"] = fallback_dom
                if update_match_stats and spec.get("id"):
                    conn = connect_db()
                    try:
                        conn.execute(
                            "UPDATE cs_parsers SET matches_count = matches_count + ? WHERE id = ?",
                            (len(forced_matches), int(spec["id"])),
                        )
                        conn.commit()
                    finally:
                        conn.close()
                return forced_matches, force_parser_name

    best_matches: List[Dict[str, Any]] = []
    best_parser_name = ""
    best_parser_id = 0
    best_score = 0.0

    # 1. Detect if the content is a multi-line stealer log (Passwords.txt, or lines starting with URL:, Host:, Username:, Password:)
    fn_lower = (filename or "").lower()
    is_pwd_fn = _is_password_filename(filename)
    sample_text = (content or "")[:25000]
    sample_lines = sample_text.splitlines()
    stealer_hits = 0
    for ln in sample_lines[:80]:
        ln_s = ln.strip().lower()
        if any(ln_s.startswith(k) for k in ("url:", "host:", "username:", "login:", "password:", "pass:", "application:", "soft:", "browser:")):
            stealer_hits += 1

    is_stealer_log = is_pwd_fn or (stealer_hits >= 2)

    # If this is a stealer log, prioritize Order-Agnostic Stealer Parser and built-in stealer blocks!
    if is_stealer_log:
        ag_matches = _parse_order_agnostic_blocks(content, inferred_family or "Stealer Log")
        ag_score = _score_matches(ag_matches)
        if ag_matches and ag_score > 0:
            best_matches = ag_matches
            best_parser_name = "Order-Agnostic Stealer Parser"
            best_parser_id = 0
            best_score = ag_score

        # Also test structured built-in stealer block regexes
        for p in parsers:
            if not p.get("enabled", 1) or not p.get("is_builtin", 0) or p.get("mode") != "block_regex":
                continue
            p_name = p.get("name", "")
            if not any(k in p_name.lower() for k in ("stealer", "redline", "raccoon", "meta", "vidar")):
                continue
            try:
                res = test_parser_pattern(
                    content,
                    p["pattern"],
                    p.get("mode", "block_regex"),
                    inferred_family or p.get("stealer_family") or "Stealer Log",
                )
                score = _score_matches(res["matches"])
                if score > best_score:
                    best_matches = res["matches"]
                    best_parser_name = p["name"]
                    best_parser_id = int(p["id"])
                    best_score = score
            except Exception:
                continue

        # If a stealer parser succeeded, return it immediately without letting loose line/combo parsers shred the blocks
        if best_matches:
            fallback_dom = _fallback_domain_from_filename(filename).lower()
            if fallback_dom:
                for item in best_matches:
                    if not item.get("domain"):
                        item["domain"] = fallback_dom
                    if not item.get("url"):
                        item["url"] = fallback_dom
            if best_parser_id and update_match_stats:
                conn = connect_db()
                try:
                    conn.execute("UPDATE cs_parsers SET matches_count = matches_count + ? WHERE id = ?", (len(best_matches), best_parser_id))
                    conn.commit()
                finally:
                    conn.close()
            return best_matches, best_parser_name

    # 2. General parsing for single-line combo dumps (URL:USER:PASS, email:pass, tab/pipe delimited)
    ordered = sorted(parsers, key=lambda p: (0 if p.get("is_builtin", 0) else 1, int(p.get("id", 0))))
    generic_names = {"Generic Account Combo (username:password)"}
    primary_parsers = [p for p in ordered if p.get("name") not in generic_names]
    fallback_parsers = [p for p in ordered if p.get("name") in generic_names]

    def _run_parser_group(group: List[Dict[str, Any]]) -> None:
        nonlocal best_matches, best_parser_name, best_parser_id, best_score
        for p in group:
            if not p.get("enabled", 1):
                continue
            pattern = p.get("pattern", "")
            if _is_dangerous_catchall_regex(pattern):
                continue
            try:
                res = test_parser_pattern(
                    content,
                    pattern,
                    p.get("mode", "block_regex"),
                    inferred_family or p.get("stealer_family") or "Unknown",
                )
                score = _score_matches(res["matches"])
                if score > best_score:
                    best_matches = res["matches"]
                    best_parser_name = p["name"]
                    best_parser_id = int(p["id"])
                    best_score = score
            except Exception:
                continue

    _run_parser_group(primary_parsers)

    if not best_matches and "\n" in content:
        ag_matches = _parse_order_agnostic_blocks(content, inferred_family or "Stealer Log")
        ag_score = _score_matches(ag_matches)
        if ag_matches and ag_score > best_score:
            best_matches = ag_matches
            best_parser_name = "Order-Agnostic Stealer Parser"
            best_parser_id = 0
            best_score = ag_score

    if not best_matches and fallback_parsers:
        _run_parser_group(fallback_parsers)

    if best_matches:
        fallback_dom = _fallback_domain_from_filename(filename).lower()
        if fallback_dom:
            for item in best_matches:
                if not item.get("domain"):
                    item["domain"] = fallback_dom
                if not item.get("url"):
                    item["url"] = fallback_dom

    if best_matches and best_parser_id and update_match_stats:
        conn = connect_db()
        try:
            conn.execute(
                "UPDATE cs_parsers SET matches_count = matches_count + ? WHERE id = ?",
                (len(best_matches), best_parser_id),
            )
            conn.commit()
        finally:
            conn.close()

    return best_matches, best_parser_name


# ---------------------------------------------------------------------------
# Watchlist Matching & Credential Upsert
# ---------------------------------------------------------------------------
def list_watchlist(conn: Optional[sqlite3.Connection] = None) -> List[Dict[str, Any]]:
    ensure_db()
    own = conn is None
    if own:
        conn = connect_db()
    try:
        rows = conn.execute("SELECT * FROM cs_watchlist ORDER BY id DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        if own:
            conn.close()


def _matches_watchlist(domain: str, url: str, username: str, email: str, rules: List[Dict[str, Any]]) -> Optional[int]:
    dl = (domain or "").lower()
    ul = (url or "").lower()
    usrl = (username or "").lower()
    eml = (email or "").lower()
    for r in rules:
        val = (r.get("value") or "").strip().lower().lstrip("@")
        ttype = r.get("target_type", "domain")
        if not val:
            continue
        if ttype == "domain":
            if dl == val or dl.endswith("." + val) or val in ul:
                return int(r["id"])
        elif ttype == "email_domain":
            if eml.endswith("@" + val) or eml.endswith("." + val) or ("@" + val) in usrl:
                return int(r["id"])
        elif ttype == "keyword":
            if val in dl or val in ul or val in usrl or val in eml:
                return int(r["id"])
    return None


_UPSERT_SQL = """
INSERT INTO cs_credentials
(domain, url, username, email, password_plain, password_hash, stealer_family,
 victim_ip, victim_country, victim_os, victim_hwid, source_type, source_name,
 file_name, parser_name, matched_watchlist, first_seen, last_seen, sightings)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
ON CONFLICT(domain, username, password_hash) DO UPDATE SET
    url = CASE WHEN LENGTH(excluded.url) > LENGTH(cs_credentials.url) THEN excluded.url ELSE cs_credentials.url END,
    email = CASE WHEN cs_credentials.email = '' THEN excluded.email ELSE cs_credentials.email END,
    password_plain = excluded.password_plain,
    last_seen = excluded.last_seen,
    sightings = cs_credentials.sightings + 1,
    matched_watchlist = MAX(cs_credentials.matched_watchlist, excluded.matched_watchlist)
"""


def _upsert_credentials_accurate(
    creds: List[Dict[str, Any]],
    source_type: str,
    source_name: str,
    file_name: str,
    parser_name: str,
    victim_info: Optional[Dict[str, str]] = None,
    *,
    conn: Optional[sqlite3.Connection] = None,
    rules: Optional[List[Dict[str, Any]]] = None,
    measure_new: bool = True,
) -> Tuple[int, int]:
    """Batched executemany upsert (25k rows/batch) with accurate new-row counting."""
    if not creds:
        return 0, 0
    ensure_db()
    vinfo = victim_info or {}
    own_conn = conn is None
    if own_conn:
        conn = connect_db()
    ts = now_iso()
    src_trim = source_name[:120]
    fn_trim = file_name[:220]
    pname_trim = parser_name[:120]
    vip = vinfo.get("victim_ip", "")
    vcountry = vinfo.get("victim_country", "")
    vos = vinfo.get("victim_os", "")
    vhwid = vinfo.get("victim_hwid", "")
    default_fam = vinfo.get("stealer_family") or "Unknown"

    rows_to_upsert: List[Tuple[Any, ...]] = []
    matched_rule_hits: Dict[int, int] = {}
    inserted_new = 0
    try:
        if rules is None:
            rules = list_watchlist(conn)
        has_rules = bool(rules)
        for item in creds:
            pass_plain = str(item.get("password_plain") or "")
            if not pass_plain:
                continue
            pass_hash = hashlib.sha256(pass_plain.encode("utf-8", "ignore")).hexdigest()
            domain, url, username, email = _normalize_cred_fields(
                str(item.get("domain") or ""),
                str(item.get("url") or ""),
                str(item.get("username") or ""),
                str(item.get("email") or ""),
            )
            fam = (item.get("stealer_family") or default_fam)[:64]

            rule_id = _matches_watchlist(domain, url, username, email, rules) if has_rules else None
            matched_flag = 1 if rule_id is not None else 0
            if rule_id is not None:
                matched_rule_hits[rule_id] = matched_rule_hits.get(rule_id, 0) + 1

            rows_to_upsert.append((
                domain, url, username, email, pass_plain, pass_hash, fam,
                vip, vcountry, vos, vhwid,
                source_type, src_trim, fn_trim, pname_trim,
                matched_flag, ts, ts,
            ))

        if not rows_to_upsert:
            return 0, 0

        # Hold the write lock from the first lookup so a concurrent scan cannot
        # claim the same new credential. Keep each lookup under 999 parameters.
        if measure_new and not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        batch_size = 300 if measure_new else 25000
        for offset in range(0, len(rows_to_upsert), batch_size):
            batch = rows_to_upsert[offset:offset + batch_size]
            if measure_new:
                placeholders = ", ".join(["(?, ?, ?)"] * len(batch))
                keys = [value for row in batch for value in (row[0], row[2], row[5])]
                inserted_new += conn.execute(
                    f"""
                    WITH incoming(domain, username, password_hash) AS (VALUES {placeholders}),
                    distinct_keys AS (
                        SELECT DISTINCT domain COLLATE NOCASE AS domain,
                               username COLLATE NOCASE AS username, password_hash
                        FROM incoming
                    )
                    SELECT COUNT(*) FROM distinct_keys AS incoming
                    WHERE NOT EXISTS (
                        SELECT 1 FROM cs_credentials AS existing
                        WHERE existing.domain = incoming.domain
                          AND existing.username = incoming.username
                          AND existing.password_hash = incoming.password_hash
                    )
                    """,
                    keys,
                ).fetchone()[0]
            conn.executemany(_UPSERT_SQL, batch)

        for rid, hits in matched_rule_hits.items():
            conn.execute("UPDATE cs_watchlist SET hits_count = hits_count + ? WHERE id = ?", (hits, rid))

        conn.commit()

    finally:
        if own_conn:
            conn.close()
    return len(rows_to_upsert), inserted_new


def add_watchlist_target(target_type: str, value: str, description: str = "") -> Dict[str, Any]:
    ensure_db()
    ttype = target_type if target_type in ("domain", "email_domain", "keyword") else "domain"
    clean_val = (value or "").strip().lower()
    if ttype in ("domain", "email_domain"):
        clean_val = clean_val.lstrip("@")
    if not clean_val:
        raise ValueError("Watchlist target value is required.")
    conn = connect_db()
    ts = now_iso()
    try:
        conn.execute(
            """
            INSERT INTO cs_watchlist(target_type, value, description, hits_count, created_at)
            VALUES(?, ?, ?, 0, ?)
            ON CONFLICT(value) DO UPDATE SET target_type=excluded.target_type, description=excluded.description
            """,
            (ttype, clean_val, description.strip()[:240], ts),
        )
        # Retroactively flag existing credentials matching this rule
        rows = conn.execute("SELECT id, domain, url, username, email FROM cs_credentials").fetchall()
        rule_obj = [{"id": 1, "target_type": ttype, "value": clean_val}]
        matched_ids = [
            (r["id"],) for r in rows
            if _matches_watchlist(r["domain"], r["url"], r["username"], r["email"], rule_obj) is not None
        ]
        if matched_ids:
            conn.executemany("UPDATE cs_credentials SET matched_watchlist = 1 WHERE id = ?", matched_ids)
        conn.execute("UPDATE cs_watchlist SET hits_count = ? WHERE value = ?", (len(matched_ids), clean_val))
        conn.commit()
        row = conn.execute("SELECT * FROM cs_watchlist WHERE value = ?", (clean_val,)).fetchone()
        return dict(row) if row else {}
    finally:
        conn.close()


def delete_watchlist_target(item_id: int) -> bool:
    ensure_db()
    conn = connect_db()
    try:
        cur = conn.execute("DELETE FROM cs_watchlist WHERE id = ?", (int(item_id),))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Jobs Tracker Helpers
# ---------------------------------------------------------------------------
def _job_create(job_type: str, source_label: str, files_total: int = 0) -> str:
    ensure_db()
    job_id = f"cs-{uuid.uuid4().hex[:10]}"
    conn = connect_db()
    try:
        conn.execute(
            """
            INSERT INTO cs_jobs(id, job_type, source_label, status, files_total, started_at, log_lines)
            VALUES(?, ?, ?, 'running', ?, ?, ?)
            """,
            (job_id, job_type, source_label[:200], int(files_total), now_iso(), json.dumps([f"[{now_iso()}] Job started: {source_label}"])),
        )
        conn.commit()
    finally:
        conn.close()
    return job_id


def _job_update(
    job_id: str,
    *,
    files_total: Optional[int] = None,
    files_processed: Optional[int] = None,
    files_downloaded: Optional[int] = None,
    files_skipped: Optional[int] = None,
    messages_remaining: Optional[int] = None,
    creds_found: Optional[int] = None,
    creds_new: Optional[int] = None,
    unparsed_files: Optional[int] = None,
    current_file: Optional[str] = None,
    log_msg: Optional[str] = None,
    status: Optional[str] = None,
    error_msg: Optional[str] = None,
) -> None:
    conn = connect_db()
    try:
        row = conn.execute("SELECT * FROM cs_jobs WHERE id = ?", (job_id,)).fetchone()
        if not row:
            return
        logs = json.loads(row["log_lines"] or "[]")
        if log_msg:
            logs.append(f"[{now_iso()}] {log_msg}")
            if len(logs) > 200:
                logs = logs[-200:]
        finished_at = now_iso() if status in ("completed", "failed", "paused") else row["finished_at"]
        conn.execute(
            """
            UPDATE cs_jobs SET
                files_total = ?,
                files_processed = ?,
                files_downloaded = ?,
                files_skipped = ?,
                messages_remaining = ?,
                creds_found = ?,
                creds_new = ?,
                unparsed_files = ?,
                current_file = ?,
                log_lines = ?,
                status = ?,
                error_msg = ?,
                finished_at = ?
            WHERE id = ?
            """,
            (
                files_total if files_total is not None else row["files_total"],
                files_processed if files_processed is not None else row["files_processed"],
                files_downloaded if files_downloaded is not None else row["files_downloaded"],
                files_skipped if files_skipped is not None else row["files_skipped"],
                messages_remaining if messages_remaining is not None else row["messages_remaining"],
                creds_found if creds_found is not None else row["creds_found"],
                creds_new if creds_new is not None else row["creds_new"],
                unparsed_files if unparsed_files is not None else row["unparsed_files"],
                current_file if current_file is not None else row["current_file"],
                json.dumps(logs),
                status if status is not None else row["status"],
                error_msg if error_msg is not None else row["error_msg"],
                finished_at,
                job_id,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def list_jobs(limit: int = 30) -> List[Dict[str, Any]]:
    ensure_db()
    conn = connect_db()
    try:
        rows = conn.execute(
            "SELECT * FROM cs_jobs ORDER BY started_at DESC LIMIT ?",
            (max(1, min(100, int(limit))),),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["log_lines"] = json.loads(d.get("log_lines") or "[]")
            except Exception:
                d["log_lines"] = []
            out.append(d)
        return out
    finally:
        conn.close()


def clear_jobs(keep_running: bool = True) -> int:
    """Clear historical ingestion and harvester job execution logs."""
    ensure_db()
    conn = connect_db()
    try:
        with conn:
            if keep_running:
                deleted = conn.execute("DELETE FROM cs_jobs WHERE status != 'running'").rowcount
            else:
                deleted = conn.execute("DELETE FROM cs_jobs").rowcount
        return deleted
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Unparsed Queue & AI Agent Parser Studio
# ---------------------------------------------------------------------------
def queue_unparsed_file(file_path: str, file_name: str, source_name: str, content: str) -> int:
    ensure_db()
    lines = (content or "").splitlines()[:35]
    snippet = "\n".join(lines)[:4000]
    if not snippet.strip():
        return 0
    conn = connect_db()
    try:
        existing = conn.execute(
            "SELECT id FROM cs_unparsed_queue WHERE file_path = ? AND status = 'pending'",
            (file_path,),
        ).fetchone()
        if existing:
            return int(existing["id"])
        cur = conn.execute(
            """
            INSERT INTO cs_unparsed_queue(file_path, file_name, source_name, sample_snippet, status, created_at)
            VALUES(?, ?, ?, ?, 'pending', ?)
            """,
            (file_path, file_name[:220], source_name[:120], snippet, now_iso()),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def list_unparsed_queue(status: str = "pending") -> List[Dict[str, Any]]:
    ensure_db()
    conn = connect_db()
    try:
        if status == "all":
            rows = conn.execute("SELECT * FROM cs_unparsed_queue ORDER BY id DESC LIMIT 100").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM cs_unparsed_queue WHERE status = ? ORDER BY id DESC LIMIT 100",
                (status,),
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _heuristic_synthesize_parser(sample_text: str, hint_family: str = "") -> Dict[str, Any]:
    """Synthesizes a Python named-group regex directly from unrecognized text structure."""
    lines = [ln.rstrip() for ln in (sample_text or "").splitlines() if ln.strip() and not ln.strip().startswith(("#", "//", "---", "==="))]
    if not lines:
        raise ValueError("Sample snippet is empty.")

    # Check 1: Delimited single lines using ->, |, ;, tab, comma, or whitespace
    for sep_name, sep_esc in [
        ("arrow", r"\s*->\s*"),
        ("pipe", r"\s*\|\s*"),
        ("semicolon", r"\s*;\s*"),
        ("tab", r"\t+"),
        ("comma", r"\s*,\s*"),
        ("colon", r":"),
    ]:
        delim_counts = [len(re.split(sep_esc, ln)) for ln in lines[:12]]
        avg_cols = sum(delim_counts) / max(1, len(delim_counts))
        if avg_cols >= 2.8:
            # Inspect sample columns to determine order of url/email/username/password
            parts = re.split(sep_esc, lines[0])
            col_types = []
            for p in parts[:4]:
                pl = p.lower()
                if "http" in pl or (re.search(r"\.[a-z]{2,}", pl) and "@" not in pl and " " not in pl):
                    col_types.append("url")
                elif "@" in pl:
                    col_types.append("email")
                else:
                    col_types.append("text")

            if len(parts) >= 3:
                g0, g1, g2 = "url", "username", "password"
                if col_types[0] == "email" and col_types[1] == "url":
                    g0, g1, g2 = "username", "url", "password"
                elif col_types[0] != "url" and col_types[1] == "url":
                    g0, g1, g2 = "username", "url", "password"
                non_sep = r"[^|;\t\r\n]+" if sep_name != "colon" else r"\S+"
                url_part = r"https?://[^\s|;\t\r\n]+|\S+" if sep_name == "colon" else non_sep
                p0 = url_part if g0 == "url" else non_sep
                p1 = url_part if g1 == "url" else non_sep
                pattern = f"^(?P<{g0}>{p0}){sep_esc}(?P<{g1}>{p1}){sep_esc}(?P<{g2}>[^\\r\\n]+)$"
                return {
                    "name": f"Auto-{sep_name.title()} Custom Parser",
                    "stealer_family": hint_family or "Custom Delimited",
                    "mode": "line_regex",
                    "pattern": pattern,
                    "explanation": f"Heuristic synthesizer detected {len(parts)}-column '{sep_name}' separated lines.",
                }

    # Check 2: Multi-line labelled key: value blocks
    url_keys = []
    user_keys = []
    pass_keys = []
    for ln in lines[:40]:
        m = re.match(r"^\s*([A-Za-z0-9 _\-]{2,24})\s*[:=]\s*(.+)$", ln)
        if not m:
            continue
        k, v = m.group(1).strip(), m.group(2).strip()
        kl = k.lower()
        vl = v.lower()
        if any(w in kl for w in ("url", "host", "site", "domain", "target", "link", "origin", "server", "web")) or "http" in vl:
            if k not in url_keys:
                url_keys.append(re.escape(k))
        elif any(w in kl for w in ("user", "login", "mail", "email", "acct", "account", "uid", "nick", "id")):
            if k not in user_keys:
                user_keys.append(re.escape(k))
        elif any(w in kl for w in ("pass", "pwd", "secret", "key", "token", "pin")):
            if k not in pass_keys:
                pass_keys.append(re.escape(k))

    if url_keys and user_keys and pass_keys:
        uk = "|".join(url_keys[:4])
        lk = "|".join(user_keys[:4])
        pk = "|".join(pass_keys[:4])
        # Determine appearance order in the first block
        first_idx = {}
        for idx, ln in enumerate(lines[:15]):
            m = re.match(r"^\s*([A-Za-z0-9 _\-]{2,24})\s*[:=]", ln)
            if m:
                esc = re.escape(m.group(1).strip())
                if esc in url_keys and "url" not in first_idx:
                    first_idx["url"] = idx
                elif esc in user_keys and "username" not in first_idx:
                    first_idx["username"] = idx
                elif esc in pass_keys and "password" not in first_idx:
                    first_idx["password"] = idx
        ordered_fields = sorted(first_idx.items(), key=lambda x: x[1])
        if len(ordered_fields) == 3:
            key_map = {"url": uk, "username": lk, "password": pk}
            parts = [f"(?:{key_map[fld]})\\s*[:=]\\s*(?P<{fld}>[^\\r\\n]+)" for fld, _ in ordered_fields]
            pattern = r"(?im)^\s*" + r"[^\r\n]*(?:\r?\n[^\r\n]*){0,2}?\r?\n\s*".join(parts)
            return {
                "name": "Auto Multi-Line Key-Value Parser",
                "stealer_family": hint_family or "Custom Stealer Log",
                "mode": "block_regex",
                "pattern": pattern,
                "explanation": "Heuristic synthesizer extracted key labels and line ordering from sample block.",
            }

    # Check 3: Bracketed or spaced tabular format (e.g. "example.com   alice   Pass123")
    if all(len(ln.split()) == 3 for ln in lines[:4]) and any("." in tok or "@" in tok for tok in lines[0].split()):
        pattern = r"^(?P<url>\S+)\s+(?P<username>\S+)\s+(?P<password>[^\r\n]+)$"
        return {
            "name": "Whitespace Separated ULP Parser",
            "stealer_family": hint_family or "Custom Combo",
            "mode": "line_regex",
            "pattern": pattern,
            "explanation": "Heuristic synthesizer detected whitespace-delimited columns.",
        }

    raise ValueError("Could not automatically infer a credential pattern from the provided snippet. Configure MANTIS AI in Settings or adjust sample lines.")


def get_mantis_ai_status() -> Dict[str, Any]:
    """Checks whether MANTIS AI has an active, configured provider."""
    try:
        import ai_service as ai_mod

        conn = ai_mod._connect()
        try:
            row_count = int(conn.execute("SELECT COUNT(*) FROM ai_settings").fetchone()[0])
        finally:
            conn.close()

        if row_count == 0:
            return {
                "available": False,
                "provider": "",
                "provider_label": "",
                "model": "",
                "reason": "No AI provider is configured in MANTIS AI Settings.",
            }

        raw = ai_mod._settings_raw()
        pub = ai_mod.get_settings(mask=True)
        provider = str(pub.get("provider") or "").strip()
        provider_label = str(pub.get("provider_label") or provider or "MANTIS AI")
        model = str(pub.get("model") or "").strip()

        if not pub.get("available") or not ai_mod._settings_available(raw):
            meta = ai_mod.AI_PROVIDER_PRESETS.get(provider, {})
            adapter = meta.get("adapter", "openai_compatible")
            if not raw.get("enabled", True) or provider.lower() in ("", "none", "disabled"):
                reason = "MANTIS AI is currently disabled in Settings."
            elif adapter == "chatgpt_account":
                reason = "Not signed in to ChatGPT Account in MANTIS AI."
            elif adapter in {"cli", "antigravity", "claude_code", "opencode", "copilot"}:
                reason = f"CLI executable not found for {provider_label} in MANTIS AI."
            elif meta.get("api_key_required", True) and not raw.get("api_key"):
                reason = f"API key is not configured for {provider_label} in MANTIS AI."
            else:
                reason = f"Incomplete AI configuration for {provider_label} in MANTIS AI."
            return {
                "available": False,
                "provider": provider,
                "provider_label": provider_label,
                "model": model,
                "reason": reason,
            }

        return {
            "available": True,
            "provider": provider,
            "provider_label": provider_label,
            "model": model,
            "reason": "",
        }
    except Exception as exc:
        return {
            "available": False,
            "provider": "",
            "provider_label": "",
            "model": "",
            "reason": f"MANTIS AI status unavailable ({exc}).",
        }


def ai_generate_parser(sample_snippet: str, hint_family: str = "") -> Dict[str, Any]:
    """Uses MANTIS AI to generate and test a named-group Python regex (requires configured MANTIS AI)."""
    ai_status = get_mantis_ai_status()
    if not ai_status.get("available"):
        raise ValueError(ai_status.get("reason") or "AI Agent Parser is disabled because no AI provider is configured in MANTIS AI.")

    snippet = (sample_snippet or "").strip()[:5000]
    if not snippet:
        raise ValueError("Sample snippet is required to generate a parser.")

    used_llm = False
    model_used = "heuristic-synthesizer"
    warning = ""
    candidate: Optional[Dict[str, Any]] = None

    try:
        import ai_service as ai_mod
        settings = ai_mod._settings_raw()
        if ai_mod._settings_available(settings):
            model_used = str(settings.get("model") or "mantis-ai")
            system_prompt = (
                "You are MANTIS AI, an expert reverse engineer and threat intelligence parser generator.\n"
                "Given a raw sample of a credential stealer log or combo list, write ONE valid Python `re` regular expression "
                "to extract every credential entry.\n"
                "CRITICAL REQUIREMENTS:\n"
                "1. Return ONLY a single valid JSON object (no markdown fences) with keys: "
                "\"name\", \"stealer_family\", \"mode\" (\"line_regex\" or \"block_regex\"), \"pattern\", \"explanation\".\n"
                "2. The `pattern` MUST contain Python named capture groups: (?P<url>...) or (?P<domain>...), (?P<username>...), and (?P<password>...).\n"
                "3. Keep regex non-greedy and safe against catastrophic backtracking.\n"
                "4. Test mentally against every block/line in the user's sample."
            )
            user_prompt = (
                f"Optional hint family: {hint_family or 'Auto-detect'}\n\n"
                f"RAW SAMPLE:\n{snippet}"
            )
            raw_out = ai_mod.AIProvider(settings).generate([
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ])
            cleaned = (raw_out or "").strip()
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)
            parsed_json = json.loads(cleaned)
            if isinstance(parsed_json, dict) and parsed_json.get("pattern"):
                mode = parsed_json.get("mode", "block_regex")
                if mode not in ("line_regex", "block_regex"):
                    mode = "block_regex"
                test_res = test_parser_pattern(
                    snippet,
                    parsed_json["pattern"],
                    mode,
                    parsed_json.get("stealer_family") or hint_family or "AI Custom",
                )
                if test_res["count"] > 0 and not _is_dangerous_catchall_regex(parsed_json["pattern"]):
                    used_llm = True
                    candidate = {
                        "name": str(parsed_json.get("name") or "AI Generated Stealer Parser")[:80],
                        "stealer_family": str(parsed_json.get("stealer_family") or hint_family or "AI Custom")[:48],
                        "mode": mode,
                        "pattern": str(parsed_json["pattern"]),
                        "explanation": str(parsed_json.get("explanation") or "Generated by MANTIS AI.")[:300],
                    }
                else:
                    warning = "AI pattern rejected (overly broad catch-all or matched 0 rows); switched to heuristic structural synthesis."
    except Exception as exc:
        warning = f"MANTIS AI unavailable or returned invalid regex ({exc}); used structural heuristic synthesizer."

    if candidate is None:
        candidate = _heuristic_synthesize_parser(snippet, hint_family=hint_family)
        model_used = "heuristic-synthesizer"

    test_out = test_parser_pattern(snippet, candidate["pattern"], candidate["mode"], candidate["stealer_family"])
    return {
        "parser": candidate,
        "test_matches": test_out["matches"][:50],
        "match_count": test_out["count"],
        "used_llm": used_llm,
        "model": model_used,
        "warning": warning,
    }


def save_parser_and_reparse(
    name: str,
    stealer_family: str,
    mode: str,
    pattern: str,
    description: str = "",
    sample_text: str = "",
    reparse_queue: bool = True,
) -> Dict[str, Any]:
    ensure_db()
    clean_name = (name or "").strip()[:100]
    if not clean_name:
        raise ValueError("Parser name is required.")
    clean_mode = mode if mode in ("line_regex", "block_regex") else "block_regex"
    # Validate regex before storing
    re.compile(pattern)
    if _is_dangerous_catchall_regex(pattern):
        raise ValueError("Pattern rejected: Overly broad catch-all regex with no specific anchors, delimiters, or key labels. Catch-all patterns corrupt multi-line stealer logs.")

    conn = connect_db()
    try:
        conn.execute(
            """
            INSERT INTO cs_parsers(name, stealer_family, mode, pattern, description, sample_text, is_builtin, enabled, created_at)
            VALUES(?, ?, ?, ?, ?, ?, 0, 1, ?)
            ON CONFLICT(name) DO UPDATE SET
                stealer_family = excluded.stealer_family,
                mode = excluded.mode,
                pattern = excluded.pattern,
                description = excluded.description,
                sample_text = excluded.sample_text,
                enabled = 1
            """,
            (
                clean_name,
                (stealer_family or "Custom")[:64],
                clean_mode,
                pattern,
                description[:300],
                sample_text[:4000],
                now_iso(),
            ),
        )
        conn.commit()
        parser_row = dict(conn.execute("SELECT * FROM cs_parsers WHERE name = ?", (clean_name,)).fetchone())
    finally:
        conn.close()

    reparse_stats = {"files_reparsed": 0, "creds_found": 0, "creds_new": 0}
    if reparse_queue:
        reparse_stats = reparse_pending_queue()

    return {"parser": parser_row, "reparse": reparse_stats}


def reparse_pending_queue() -> Dict[str, int]:
    ensure_db()
    pending = list_unparsed_queue("pending")
    parsers = list_parsers()
    files_reparsed = 0
    total_found = 0
    total_new = 0
    conn = connect_db()
    try:
        for item in pending:
            fpath = item.get("file_path") or ""
            content = ""
            if fpath and os.path.exists(fpath) and os.path.isfile(fpath):
                try:
                    content = _read_text_file(fpath, max_bytes=15 * 1024 * 1024)
                except Exception:
                    content = item.get("sample_snippet") or ""
            else:
                content = item.get("sample_snippet") or ""
            if not content.strip():
                continue

            vinfo = parse_victim_system_info(content, item.get("file_name") or "")
            creds, pname = parse_text_with_parsers(content, item.get("file_name") or "", victim_info=vinfo, parsers=parsers)
            if creds:
                src_type = "upload" if (not fpath or fpath.startswith(("upload://", "ephemeral://"))) else "local"
                found, new_c = _upsert_credentials_accurate(
                    creds,
                    src_type,
                    item.get("source_name") or "Queue Reparse",
                    item.get("file_name") or "snippet.txt",
                    pname,
                    victim_info=vinfo,
                )
                conn.execute("UPDATE cs_unparsed_queue SET status = 'parsed' WHERE id = ?", (item["id"],))
                files_reparsed += 1
                total_found += found
                total_new += new_c
        conn.commit()
    finally:
        conn.close()
    return {"files_reparsed": files_reparsed, "creds_found": total_found, "creds_new": total_new}


def delete_parser(parser_id: int) -> bool:
    ensure_db()
    conn = connect_db()
    try:
        cur = conn.execute("DELETE FROM cs_parsers WHERE id = ? AND is_builtin = 0", (int(parser_id),))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def dismiss_unparsed_item(unparsed_id: int) -> bool:
    ensure_db()
    conn = connect_db()
    try:
        cur = conn.execute("UPDATE cs_unparsed_queue SET status = 'ignored' WHERE id = ?", (int(unparsed_id),))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def dismiss_all_unparsed() -> int:
    ensure_db()
    conn = connect_db()
    try:
        with conn:
            cur = conn.execute("UPDATE cs_unparsed_queue SET status = 'ignored' WHERE status = 'pending'")
            return cur.rowcount
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Archive Extraction & File Processing Helpers
# ---------------------------------------------------------------------------
def _extract_passwords_from_text(text: str) -> List[str]:
    found = []
    for m in PASSWORD_HINT_RE.finditer(text or ""):
        cand = m.group(1).strip()
        if cand and cand not in found:
            found.append(cand)
    return found


def _extract_archive_to_dir(archive_path: str, out_dir: str, password_candidates: Optional[List[str]] = None) -> None:
    if os.path.getsize(archive_path) == 0:
        raise ValueError("The archive is empty (0 bytes).")

    pwds = []
    for p in (password_candidates or []) + COMMON_ARCHIVE_PASSWORDS:
        if p not in pwds:
            pwds.append(p)

    lower = archive_path.lower()
    if lower.endswith(".zip") and zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path, "r") as zf:
            infos = [i for i in zf.infolist() if not i.is_dir() and i.file_size <= 25 * 1024 * 1024]
            probe_info = next((i for i in infos if i.file_size > 0), None)
            has_pwd_files = any(
                _is_password_filename(i.filename)
                for i in infos
            )
            for pwd in pwds:
                try:
                    pwd_bytes = pwd.encode("utf-8") if pwd else None
                    if probe_info is not None:
                        with zf.open(probe_info, pwd=pwd_bytes) as pf:
                            pf.read(64)
                    for info in infos:
                        fn_low = info.filename.lower()
                        if not fn_low.endswith((".txt", ".log", ".csv", ".zip", ".rar", ".7z")):
                            continue
                        base_low = os.path.basename(info.filename).lower()
                        is_nested_archive = base_low.endswith((".zip", ".rar", ".7z"))
                        if not is_nested_archive and _is_non_cred_filename(base_low):
                            continue
                        if not is_nested_archive and has_pwd_files and (not _is_password_filename(base_low) and base_low not in {"system.txt", "userinformation.txt", "information.txt", "info.txt"}):
                            continue
                        safe_rel = os.path.normpath(info.filename).lstrip("\\/")
                        if ".." in safe_rel.split(os.sep):
                            continue
                        parts = [p.lower() for p in safe_rel.split(os.sep)[:-1]]
                        if any(p in NON_CRED_DIRNAMES for p in parts):
                            continue
                        target_path = os.path.join(out_dir, safe_rel)
                        os.makedirs(os.path.dirname(target_path), exist_ok=True)
                        with zf.open(info, pwd=pwd_bytes) as src, open(target_path, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                    return
                except Exception:
                    continue
        raise ValueError("The ZIP archive is damaged or requires a different password.")

    ext = Path(archive_path).suffix.lower()
    if ext not in (".rar", ".7z"):
        raise ValueError("The file is not a valid ZIP archive.")

    seven_zip = shutil.which("7z") or shutil.which("7zz")
    if not seven_zip and os.name == "nt":
        for env_var in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"):
            program_dir = os.environ.get(env_var)
            if program_dir:
                candidate = Path(program_dir) / "7-Zip" / "7z.exe"
                if candidate.is_file():
                    seven_zip = str(candidate)
                    break
    bsdtar = shutil.which("bsdtar")
    if not bsdtar and os.name == "nt":
        candidate = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "tar.exe"
        if candidate.is_file():
            bsdtar = str(candidate)

    archive = os.path.abspath(archive_path)
    commands = []
    if seven_zip:
        commands.extend([seven_zip, "x", "-y", f"-p{pwd}", "--", archive] for pwd in pwds)
    if bsdtar:
        commands.append([bsdtar, "-xf", archive])
    if not commands:
        raise ValueError(f"Install 7-Zip on the MANTIS host to unpack {ext.upper()[1:]} archives.")

    for cmd in commands:
        # Failed password attempts can leave partial files. Only keep a successful extraction.
        with tempfile.TemporaryDirectory(dir=out_dir) as attempt_dir:
            try:
                proc = subprocess.run(
                    cmd, cwd=attempt_dir, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600,
                )
            except OSError:
                continue
            except subprocess.TimeoutExpired:
                raise ValueError("Archive extraction timed out.") from None
            if proc.returncode == 0:
                for entry in Path(attempt_dir).iterdir():
                    dest = Path(out_dir) / entry.name
                    if dest.exists():
                        if dest.is_dir():
                            shutil.rmtree(dest, ignore_errors=True)
                        else:
                            try:
                                dest.unlink(missing_ok=True)
                            except Exception:
                                pass
                    try:
                        shutil.move(str(entry), str(dest))
                    except Exception:
                        pass
                return

    raise ValueError(f"Could not unpack the {ext.upper()[1:]} archive. Check its password, integrity, and whether all parts are available.")


def _handle_unparsed_file(
    stored_path: str,
    rel_name: str,
    source_type: str,
    source_name: str,
    content: str,
    victim_info: Dict[str, str],
    parsers: List[Dict[str, Any]],
    settings: Dict[str, Any],
    job_id: Optional[str] = None,
) -> Tuple[int, int, int, List[Dict[str, Any]]]:
    """Queues an unrecognized non-empty text file and optionally invokes Auto-AI Parser."""
    if not (content or "").strip() or _is_non_cred_filename(rel_name):
        return 0, 0, 0, parsers
    qid = queue_unparsed_file(stored_path, rel_name, source_name, content)
    if not qid:
        return 0, 0, 0, parsers
    if settings.get("auto_ai_parse") and get_mantis_ai_status().get("available"):
        try:
            gen = ai_generate_parser(
                "\n".join(content.splitlines()[:35]),
                hint_family=victim_info.get("stealer_family", ""),
            )
            if gen.get("match_count", 0) > 0:
                p_spec = gen["parser"]
                save_parser_and_reparse(
                    p_spec["name"], p_spec["stealer_family"], p_spec["mode"],
                    p_spec["pattern"], p_spec.get("explanation", ""), "\n".join(content.splitlines()[:25]),
                    reparse_queue=False,
                )
                parsers = list_parsers()
                creds2, pname2 = parse_text_with_parsers(content, rel_name, victim_info=victim_info, parsers=parsers)
                if creds2:
                    f2, n2 = _upsert_credentials_accurate(
                        creds2, source_type, source_name, rel_name, pname2, victim_info=victim_info
                    )
                    conn = connect_db()
                    try:
                        conn.execute("UPDATE cs_unparsed_queue SET status = 'parsed' WHERE id = ?", (qid,))
                        conn.commit()
                    finally:
                        conn.close()
                    if job_id:
                        _job_update(job_id, log_msg=f"AI Auto-Parser '{p_spec['name']}' matched {f2} credentials in {rel_name}")
                    return f2, n2, 0, parsers
        except Exception as exc:
            logger.debug("Auto-AI parse skipped for %s: %s", rel_name, exc)
    return 0, 0, 1, parsers


def _record_uploaded_source(fname: str, files_count: int, creds_found: int, unparsed_count: int) -> None:
    """Records or updates a direct browser upload inside cs_sources_local so it appears in Sources."""
    ensure_db()
    ts = now_iso()
    folder_key = f"upload://{fname}"
    label = f"Uploaded: {fname}"[:120]
    status = "unparsed" if (creds_found == 0 and unparsed_count > 0) else "ready"
    conn = connect_db()
    try:
        conn.execute(
            """
            INSERT INTO cs_sources_local
            (folder_path, label, recursive, auto_weekly, last_scanned_at, files_scanned, total_creds, status, created_at)
            VALUES (?, ?, 0, 0, ?, ?, ?, ?, ?)
            ON CONFLICT(folder_path) DO UPDATE SET
                label = excluded.label,
                last_scanned_at = excluded.last_scanned_at,
                files_scanned = cs_sources_local.files_scanned + excluded.files_scanned,
                total_creds = MAX(cs_sources_local.total_creds, excluded.total_creds),
                status = excluded.status
            """,
            (folder_key, label, ts, max(1, int(files_count)), int(creds_found), status, ts),
        )
        conn.commit()
    finally:
        conn.close()


_STREAM_THRESHOLD_BYTES = 10 * 1024 * 1024
_STREAM_CHUNK_BYTES = 16 * 1024 * 1024


def _detect_stream_encoding(head: bytes) -> Tuple[str, int]:
    """Detects text encoding and BOM byte length from the leading bytes of a file."""
    if head.startswith(b"\xff\xfe"):
        return "utf-16-le", 2
    if head.startswith(b"\xfe\xff"):
        return "utf-16-be", 2
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8", 3
    if head[:256].count(b"\x00") > 10:
        return "utf-16-le", 0
    return "utf-8", 0


def _decode_stream_bytes(raw: bytes, enc: str) -> str:
    return raw.decode(enc, errors="ignore").replace("\ufeff", "").replace("\x00", "")


def _ingest_large_text_file_stream(
    tf: str,
    *,
    source_type: str,
    source_name: str,
    rel_name: str,
    victim_info: Dict[str, str],
    parsers: List[Dict[str, Any]],
    settings: Dict[str, Any],
    job_id: Optional[str] = None,
    single_file_mode: bool = True,
    base_found: int = 0,
    base_new: int = 0,
    force_parser_name: Optional[str] = None,
) -> Tuple[int, int, int, List[Dict[str, Any]]]:
    """Streams multi-MB / multi-GB text files in 16 MB line-aligned chunks with batched SQLite upserts."""
    ensure_db()
    file_size = os.path.getsize(tf)
    if file_size <= 0:
        return 0, 0, 0, parsers

    with open(tf, "rb") as fb:
        sample_bytes = fb.read(256 * 1024)
    enc, bom_len = _detect_stream_encoding(sample_bytes)
    sample_text = _decode_stream_bytes(sample_bytes[bom_len:], enc)
    if not sample_text.strip():
        return 0, 0, 0, parsers

    vinfo = dict(victim_info or {})
    if not vinfo.get("stealer_family"):
        vinfo["stealer_family"] = detect_stealer_family(tf, sample_text, "")

    sample_creds, pname = parse_text_with_parsers(
        sample_text, rel_name, victim_info=vinfo, parsers=parsers, update_match_stats=False,
        force_parser_name=force_parser_name,
    )

    conn = connect_db()
    total_found = 0
    total_new = 0
    t_start = time.time()
    try:
        start_count = int(conn.execute("SELECT COUNT(*) FROM cs_credentials").fetchone()[0])
        if not sample_creds:
            stored_unparsed = f"upload://{rel_name}" if source_type == "upload" else tf
            f2, _, unp2, parsers = _handle_unparsed_file(
                stored_unparsed,
                rel_name,
                source_type,
                source_name,
                sample_text,
                vinfo,
                parsers,
                settings,
                job_id=job_id,
            )
            if unp2 > 0:
                return 0, 0, unp2, parsers
            sample_creds, pname = parse_text_with_parsers(
                sample_text, rel_name, victim_info=vinfo, parsers=parsers, update_match_stats=False,
                force_parser_name=force_parser_name,
            )
            if not sample_creds:
                end_count = int(conn.execute("SELECT COUNT(*) FROM cs_credentials").fetchone()[0])
                return f2, max(0, end_count - start_count), 0, parsers

        # Lock onto the winning parser specification so we run ONLY 1 regex per 16 MB chunk
        parser_spec = next((p for p in parsers if p.get("name") == pname), None)
        parser_id = int(parser_spec["id"]) if parser_spec else 0
        is_block_mode = (parser_spec is not None and parser_spec.get("mode") == "block_regex") or (
            pname == "Order-Agnostic KV Block Fallback"
        )
        default_fam = vinfo.get("stealer_family") or (parser_spec.get("stealer_family") if parser_spec else "") or "Unknown"
        fallback_dom = _fallback_domain_from_filename(rel_name)
        rules = list_watchlist(conn)
        mb_total = max(1, (file_size + (1024 * 1024) - 1) // (1024 * 1024))

        if job_id:
            _job_update(
                job_id,
                files_processed=0 if single_file_mode else None,
                files_total=mb_total if single_file_mode else None,
                current_file=f"{rel_name} (0/{mb_total} MB — 0%)",
                log_msg=f"Streaming {rel_name} ({mb_total} MB) using parser '{pname}' in 16 MB batches...",
            )

        with open(tf, "rb") as fb:
            fb.seek(bom_len)
            chunk_idx = 0
            while True:
                buf = fb.read(_STREAM_CHUNK_BYTES)
                if not buf:
                    break
                tail = fb.readline()
                if tail:
                    buf += tail
                if enc == "utf-16-le" and (len(buf) % 2 == 1 or buf.endswith(b"\n")):
                    extra = fb.read(1)
                    if extra:
                        buf += extra

                # Align multi-line stealer blocks cleanly at blank line boundary
                if is_block_mode:
                    guard = 0
                    while guard < 32:
                        extra_ln = fb.readline()
                        if not extra_ln:
                            break
                        if enc == "utf-16-le" and len(extra_ln) % 2 == 1:
                            ex = fb.read(1)
                            if ex:
                                extra_ln += ex
                        buf += extra_ln
                        guard += 1
                        if not _decode_stream_bytes(extra_ln, enc).strip():
                            break

                chunk_idx += 1
                chunk_text = _decode_stream_bytes(buf, enc)
                if not chunk_text.strip():
                    continue

                if parser_spec is not None:
                    chunk_creds = test_parser_pattern(
                        chunk_text,
                        parser_spec["pattern"],
                        parser_spec.get("mode", "block_regex"),
                        default_fam,
                        max_matches=2_000_000,
                    )["matches"]
                else:
                    chunk_creds = _parse_order_agnostic_blocks(chunk_text, default_fam)

                if chunk_creds and fallback_dom:
                    fb_dom = fallback_dom.lower()
                    for item in chunk_creds:
                        if not item.get("domain"):
                            item["domain"] = fb_dom
                        if not item.get("url"):
                            item["url"] = fb_dom

                if chunk_creds:
                    f_cnt, _ = _upsert_credentials_accurate(
                        chunk_creds,
                        source_type,
                        source_name,
                        rel_name,
                        pname,
                        victim_info=vinfo,
                        conn=conn,
                        rules=rules,
                        measure_new=False,
                    )
                    total_found += f_cnt

                bytes_done = fb.tell()
                mb_done = min(mb_total, max(1, bytes_done // (1024 * 1024)))
                pct = min(100, int((bytes_done * 100) / max(1, file_size)))
                if job_id:
                    _job_update(
                        job_id,
                        files_processed=mb_done if single_file_mode else None,
                        files_total=mb_total if single_file_mode else None,
                        current_file=f"{rel_name} ({mb_done}/{mb_total} MB — {pct}%)",
                        creds_found=base_found + total_found,
                        log_msg=f"Stream chunk #{chunk_idx}: {mb_done}/{mb_total} MB ({pct}%), {total_found:,} parsed so far" if chunk_idx % 5 == 0 or pct == 100 else None,
                    )

        end_count = int(conn.execute("SELECT COUNT(*) FROM cs_credentials").fetchone()[0])
        total_new = max(0, end_count - start_count)
        if total_found and parser_id:
            conn.execute("UPDATE cs_parsers SET matches_count = matches_count + ? WHERE id = ?", (total_found, parser_id))
            conn.commit()

        elapsed = max(0.01, time.time() - t_start)
        if job_id:
            _job_update(
                job_id,
                files_processed=mb_total if single_file_mode else None,
                files_total=mb_total if single_file_mode else None,
                creds_found=base_found + total_found,
                creds_new=base_new + total_new,
                log_msg=f"Completed streaming {rel_name} ({mb_total} MB): {total_found:,} matches ({total_new:,} new) in {elapsed:.1f}s ({mb_total / elapsed:.1f} MB/s).",
            )
    finally:
        conn.close()

    return total_found, total_new, 0, parsers


def _ingest_directory_files(
    root_dir: str,
    *,
    source_type: str,
    source_name: str,
    recursive: bool = True,
    job_id: Optional[str] = None,
    password_hints: Optional[List[str]] = None,
    is_ephemeral: bool = False,
    delete_after_parse: bool = False,
    on_progress: Optional[Callable[[str, int, int, int], None]] = None,
    force_parser_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Scans local text files and archives and parses credentials into the database."""
    parsers = list_parsers()
    settings = get_settings()
    delete_after_parse = bool(delete_after_parse or settings.get("delete_after_parse", False))
    stats = {"files": 0, "found": 0, "new": 0, "unparsed": 0, "deleted": 0, "archive_errors": []}
    text_files: List[str] = []
    archive_files: List[str] = []
    processed = 0

    def report_progress(activity: str, found: int = 0, new: int = 0, unparsed: int = 0) -> None:
        found += stats["found"]
        new += stats["new"]
        unparsed += stats["unparsed"]
        if job_id:
            _job_update(
                job_id, files_processed=processed, current_file=activity,
                creds_found=found, creds_new=new, unparsed_files=unparsed,
            )
        if on_progress:
            on_progress(activity, found, new, unparsed)

    if os.path.isfile(root_dir):
        low = root_dir.lower()
        if low.endswith((".zip", ".rar", ".7z")):
            archive_files.append(root_dir)
        elif low.endswith((".txt", ".log", ".csv")):
            text_files.append(root_dir)
    else:
        for dirpath, dirnames, filenames in os.walk(root_dir):
            # Prune non-cred directories from traversal in-place (autofills, cookies, discord, steam, etc.)
            dirnames[:] = [d for d in dirnames if d.lower() not in NON_CRED_DIRNAMES]
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                low = fn.lower()
                if is_ephemeral and os.path.islink(full):
                    continue
                if _is_non_cred_filename(low):
                    continue
                if low.endswith((".txt", ".log", ".csv")):
                    text_files.append(full)
                elif low.endswith((".zip", ".rar", ".7z")):
                    archive_files.append(full)
            if not recursive:
                break

    # Collect per-directory victim telemetry first from System.txt / UserInformation.txt across ALL text files
    dir_victim_map: Dict[str, Dict[str, str]] = {}
    for tf in text_files:
        bn = os.path.basename(tf).lower()
        if bn in ("system.txt", "userinformation.txt", "information.txt", "info.txt"):
            try:
                dir_victim_map[os.path.dirname(tf)] = parse_victim_system_info(_read_text_file(tf, max_bytes=200_000), bn)
            except Exception:
                pass

    # If the directory tree contains specific Passwords.txt / All Passwords.txt files (e.g. extracted RedLine/Meta/Vidar bots),
    # prioritize and parse ONLY those credential files, discarding extraneous non-credential text files.
    cred_named_files = [
        tf for tf in text_files
        if _is_password_filename(tf)
    ]
    if cred_named_files:
        text_files = cred_named_files

    total_items = len(text_files) + len(archive_files)
    if job_id:
        _job_update(job_id, files_total=total_items, log_msg=f"Discovered {len(text_files)} text files and {len(archive_files)} archives in {source_name}")

    streamed_single_large = False
    next_progress_at = 0.0
    for index, tf in enumerate(text_files):
        rel_name = os.path.basename(tf)
        if (job_id or on_progress) and time.monotonic() >= next_progress_at:
            report_progress(f"Parsing log {index + 1:,} of {len(text_files):,} ({rel_name})")
            next_progress_at = time.monotonic() + 1.0
        processed += 1
        stats["files"] += 1
        if _is_non_cred_filename(rel_name):
            continue
        try:
            fsize = os.path.getsize(tf)
        except Exception:
            continue
        if fsize == 0:
            continue

        parent_vinfo = dict(dir_victim_map.get(os.path.dirname(tf), {}))
        if fsize > _STREAM_THRESHOLD_BYTES:
            single_mode = (total_items == 1)
            if single_mode:
                streamed_single_large = True
            f_s, n_s, u_s, parsers = _ingest_large_text_file_stream(
                tf,
                source_type=source_type,
                source_name=source_name,
                rel_name=rel_name,
                victim_info=parent_vinfo,
                parsers=parsers,
                settings=settings,
                job_id=job_id,
                single_file_mode=single_mode,
                base_found=stats["found"],
                base_new=stats["new"],
                force_parser_name=force_parser_name,
            )
            stats["found"] += f_s
            stats["new"] += n_s
            stats["unparsed"] += u_s
            if delete_after_parse and not is_ephemeral and os.path.isfile(tf):
                try:
                    os.remove(tf)
                    stats["deleted"] += 1
                    if job_id:
                        _job_update(job_id, log_msg=f"Deleted parsed large text file: {rel_name}")
                except Exception as exc:
                    logger.warning("Could not delete %s: %s", tf, exc)
            continue

        try:
            content = _read_text_file(tf, max_bytes=_STREAM_THRESHOLD_BYTES)
        except Exception:
            continue

        if not parent_vinfo.get("stealer_family"):
            parent_vinfo["stealer_family"] = detect_stealer_family(tf, content, "")

        creds, pname = parse_text_with_parsers(content, rel_name, victim_info=parent_vinfo, parsers=parsers, force_parser_name=force_parser_name)
        if creds:
            found_c, new_c = _upsert_credentials_accurate(
                creds, source_type, source_name, rel_name, pname, victim_info=parent_vinfo
            )
            stats["found"] += found_c
            stats["new"] += new_c
            if delete_after_parse and not is_ephemeral and os.path.isfile(tf):
                try:
                    os.remove(tf)
                    stats["deleted"] += 1
                    if job_id:
                        _job_update(job_id, log_msg=f"Deleted parsed text file: {rel_name}")
                except Exception as exc:
                    logger.warning("Could not delete %s: %s", tf, exc)
        else:
            stored_path = "" if is_ephemeral else tf
            f2, n2, unp2, parsers = _handle_unparsed_file(
                stored_path or f"ephemeral://{rel_name}",
                rel_name,
                source_type,
                source_name,
                content,
                parent_vinfo,
                parsers,
                settings,
                job_id=job_id,
            )
            stats["found"] += f2
            stats["new"] += n2
            stats["unparsed"] += unp2
            if delete_after_parse and not is_ephemeral and f2 > 0 and os.path.isfile(tf):
                try:
                    os.remove(tf)
                    stats["deleted"] += 1
                    if job_id:
                        _job_update(job_id, log_msg=f"Deleted parsed text file: {rel_name}")
                except Exception as exc:
                    logger.warning("Could not delete %s: %s", tf, exc)

    # Process archives via temporary directory
    for af in archive_files:
        stats["files"] += 1
        aname = os.path.basename(af)

        def report_archive(activity: str, found: int, new: int, unparsed: int) -> None:
            report_progress(f"{aname} — {activity}", found, new, unparsed)

        report_progress(f"Extracting {aname}")
        tmp_ext = tempfile.mkdtemp(prefix="cs_archive_")
        try:
            try:
                _extract_archive_to_dir(af, tmp_ext, password_candidates=password_hints)
            except (ValueError, OSError, zipfile.BadZipFile) as exc:
                error = f"{aname}: {exc}"
                stats["archive_errors"].append(error)
                if job_id:
                    _job_update(job_id, log_msg=error)
                continue
            report_progress(f"{aname} — Finding logs")
            sub_stats = _ingest_directory_files(
                tmp_ext,
                source_type=source_type,
                source_name=f"{source_name} / {aname}",
                recursive=True,
                password_hints=password_hints,
                job_id=None,
                is_ephemeral=True,
                delete_after_parse=False,
                on_progress=report_archive if job_id or on_progress else None,
            )
            stats["files"] += sub_stats["files"]
            stats["found"] += sub_stats["found"]
            stats["new"] += sub_stats["new"]
            stats["unparsed"] += sub_stats["unparsed"]
            stats["archive_errors"].extend(sub_stats["archive_errors"])
            if delete_after_parse and not is_ephemeral and os.path.isfile(af):
                try:
                    os.remove(af)
                    stats["deleted"] += 1
                    if job_id:
                        _job_update(job_id, log_msg=f"Deleted parsed archive: {aname}")
                except Exception as exc:
                    logger.warning("Could not delete %s: %s", af, exc)
        finally:
            shutil.rmtree(tmp_ext, ignore_errors=True)
            processed += 1
            if job_id:
                _job_update(
                    job_id, files_processed=processed, creds_found=stats["found"],
                    creds_new=stats["new"], unparsed_files=stats["unparsed"],
                )

    # Prune any empty directories left after file deletion
    if delete_after_parse and not is_ephemeral and os.path.isdir(root_dir):
        for dirpath, dirnames, filenames in os.walk(root_dir, topdown=False):
            if dirpath != root_dir:
                try:
                    if not os.listdir(dirpath):
                        os.rmdir(dirpath)
                except Exception:
                    pass

    if job_id:
        del_note = f", {stats['deleted']} deleted after parse" if stats.get("deleted", 0) > 0 else ""
        _job_update(
            job_id,
            files_processed=None if streamed_single_large else total_items,
            creds_found=stats["found"],
            creds_new=stats["new"],
            unparsed_files=stats["unparsed"],
            log_msg=f"Scan finished: {stats['files']} files{del_note}, {stats['found']} parsed ({stats['new']} new).",
        )
    return stats


# ---------------------------------------------------------------------------
# Local Folder Picker & Local Ingestion API
# ---------------------------------------------------------------------------
def _run_windows_picker(dialog_setup: str, path_property: str) -> Dict[str, Any]:
    """Runs a native STA PowerShell WinForms file/folder picker dialog and returns the selected path."""
    try:
        import deployment_config
        if deployment_config.is_server_mode():
            return {
                "selected": False,
                "path": "",
                "error": "Native GUI file pickers are disabled in Server Mode. Use Web Upload or the Server Staging directory.",
            }
    except Exception:
        pass

    if os.name != "nt":
        return {"selected": False, "path": "", "error": "The picker requires a Windows desktop. Enter a path on the MANTIS host to scan it."}

    ps_script = f"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Add-Type -AssemblyName System.Windows.Forms
if (-not [System.Windows.Forms.SystemInformation]::UserInteractive) {{
    throw 'Start MANTIS in your Windows desktop session, or enter the path manually.'
}}

{dialog_setup}
$owner = New-Object System.Windows.Forms.Form
$owner.ShowInTaskbar = $false
$owner.TopMost = $true
$owner.Opacity = 0
try {{
    $owner.Show()
    $owner.Activate()
    if ($dlg.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) {{
        [Console]::Out.Write($dlg.{path_property})
    }}
}} finally {{
    $dlg.Dispose()
    $owner.Dispose()
}}
"""
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Sta", "-Command", ps_script],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return {"selected": False, "path": "", "error": "The Windows picker timed out. Open it again or enter the path manually."}
    except OSError as exc:
        return {"selected": False, "path": "", "error": f"Could not launch the Windows picker: {exc}"}

    if proc.returncode:
        detail = proc.stderr.strip().splitlines()
        message = detail[0] if detail else f"PowerShell exited with code {proc.returncode}."
        return {"selected": False, "path": "", "error": f"Could not open the Windows picker: {message}"}
    if proc.stdout and not os.path.exists(proc.stdout):
        return {"selected": False, "path": "", "error": "The selected path is no longer accessible. Select it again or enter a different path."}
    return {"selected": bool(proc.stdout), "path": proc.stdout}


def browse_local_folder() -> Dict[str, Any]:
    """Opens native Windows folder picker dialog and returns the selected path."""
    return _run_windows_picker(
        "$dlg = New-Object System.Windows.Forms.FolderBrowserDialog; "
        "$dlg.Description = 'Select a Credential Stealer logs folder'; "
        "$dlg.ShowNewFolderButton = $false",
        "SelectedPath",
    )


def browse_local_file() -> Dict[str, Any]:
    """Opens native Windows file picker dialog for single/multi-GB .txt or archive files."""
    return _run_windows_picker(
        "$dlg = New-Object System.Windows.Forms.OpenFileDialog; "
        "$dlg.Title = 'Select a Credential Stealer log or archive'; "
        "$dlg.Filter = 'Stealer & Combo Files (*.txt;*.log;*.csv;*.zip;*.rar;*.7z)|*.txt;*.log;*.csv;*.zip;*.rar;*.7z|All Files (*.*)|*.*'",
        "FileName",
    )


def list_local_sources() -> List[Dict[str, Any]]:
    ensure_db()
    conn = connect_db()
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM cs_sources_local ORDER BY id DESC").fetchall()]
    finally:
        conn.close()


def add_and_scan_local_folder(
    folder_path: str,
    label: str = "",
    recursive: bool = True,
    auto_weekly: bool = True,
    background: bool = True,
    delete_after_parse: bool = False,
    parser_name: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_db()
    clean_path = os.path.normpath((folder_path or "").strip().strip('"'))
    if not clean_path or not os.path.exists(clean_path):
        raise ValueError(f"Path does not exist: {clean_path}")

    clean_label = (label or os.path.basename(clean_path) or clean_path)[:120]
    conn = connect_db()
    ts = now_iso()
    try:
        conn.execute(
            """
            INSERT INTO cs_sources_local(folder_path, label, recursive, auto_weekly, delete_after_parse, status, created_at)
            VALUES(?, ?, ?, ?, ?, 'scanning', ?)
            ON CONFLICT(folder_path) DO UPDATE SET
                label = excluded.label,
                recursive = excluded.recursive,
                auto_weekly = excluded.auto_weekly,
                delete_after_parse = excluded.delete_after_parse,
                status = 'scanning'
            """,
            (clean_path, clean_label, 1 if recursive else 0, 1 if auto_weekly else 0, 1 if delete_after_parse else 0, ts),
        )
        conn.commit()
        src_row = dict(conn.execute("SELECT * FROM cs_sources_local WHERE folder_path = ?", (clean_path,)).fetchone())
    finally:
        conn.close()

    job_id = _job_create("local_folder", clean_label)

    def _run():
        try:
            stats = _ingest_directory_files(
                clean_path,
                source_type="local",
                source_name=clean_label,
                recursive=recursive,
                job_id=job_id,
                is_ephemeral=False,
                delete_after_parse=delete_after_parse,
                force_parser_name=parser_name,
            )
            if stats["archive_errors"] and os.path.isfile(clean_path) and stats["files"] == 1:
                raise ValueError(stats["archive_errors"][0])
            c2 = connect_db()
            try:
                c2.execute(
                    """
                    UPDATE cs_sources_local SET
                        status = 'ready',
                        last_scanned_at = ?,
                        files_scanned = ?,
                        total_creds = total_creds + ?
                    WHERE id = ?
                    """,
                    (now_iso(), stats["files"], stats["new"], src_row["id"]),
                )
                c2.commit()
            finally:
                c2.close()
            del_note = f" ({stats['deleted']} deleted after parse)" if stats.get("deleted", 0) > 0 else ""
            _job_update(
                job_id,
                status="completed",
                creds_found=stats["found"],
                creds_new=stats["new"],
                unparsed_files=stats["unparsed"],
                log_msg=f"Completed scan: {stats['files']} files{del_note}, {stats['found']} parsed ({stats['new']} new), {stats['unparsed']} unrecognized.",
            )
        except Exception as exc:
            logger.exception("Local folder scan failed")
            c2 = connect_db()
            try:
                c2.execute("UPDATE cs_sources_local SET status = 'error' WHERE id = ?", (src_row["id"],))
                c2.commit()
            finally:
                c2.close()
            _job_update(job_id, status="failed", error_msg=str(exc), log_msg=f"Scan failed: {exc}")

    if background:
        threading.Thread(target=_run, daemon=True, name=f"cs-local-{job_id}").start()
    else:
        _run()

    return {"source": src_row, "job_id": job_id}


def scan_local_source_by_id(
    source_id: int,
    background: bool = True,
    delete_after_parse: Optional[bool] = None,
    parser_name: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_db()
    conn = connect_db()
    try:
        row = conn.execute("SELECT * FROM cs_sources_local WHERE id = ?", (int(source_id),)).fetchone()
    finally:
        conn.close()
    if not row:
        raise ValueError("Local folder source not found.")
    row_dict = dict(row)
    del_opt = bool(row_dict.get("delete_after_parse", 0)) if delete_after_parse is None else bool(delete_after_parse)
    return add_and_scan_local_folder(
        row_dict["folder_path"],
        row_dict["label"],
        bool(row_dict.get("recursive", 1)),
        bool(row_dict.get("auto_weekly", 1)),
        background=background,
        delete_after_parse=del_opt,
        parser_name=parser_name,
    )


def delete_local_source(source_id: int) -> bool:
    ensure_db()
    conn = connect_db()
    try:
        cur = conn.execute("DELETE FROM cs_sources_local WHERE id = ?", (int(source_id),))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def ingest_staged_files(
    staged_files: List[Tuple[str, str]],
    source_label: str = "Browser Upload",
    parser_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Ingests files uploaded directly from the browser (already saved into a temp dir)."""
    job_id = _job_create("upload", source_label, files_total=len(staged_files))
    total_found = 0
    total_new = 0
    total_unparsed = 0
    files_processed = 0
    file_summaries: List[Dict[str, Any]] = []
    failed_archives = 0
    parsers = list_parsers()
    settings = get_settings()

    try:
        for idx, (fname, fpath) in enumerate(staged_files, 1):
            _job_update(job_id, files_processed=idx, current_file=fname)
            files_processed += 1
            low = fname.lower()
            if low.endswith((".zip", ".rar", ".7z")):
                stats = _ingest_directory_files(
                    fpath,
                    source_type="upload",
                    source_name=fname,
                    is_ephemeral=True,
                    force_parser_name=parser_name,
                )
                total_found += stats["found"]
                total_new += stats["new"]
                total_unparsed += stats["unparsed"]
                if not stats["archive_errors"] or stats["files"] > 1:
                    _record_uploaded_source(fname, stats["files"], stats["found"], stats["unparsed"])
                else:
                    failed_archives += 1
                for error in stats["archive_errors"]:
                    _job_update(job_id, log_msg=error)
                file_summaries.append({
                    "file_name": fname,
                    "creds_found": stats["found"],
                    "creds_new": stats["new"],
                    "unparsed": stats["unparsed"],
                    "archive_errors": stats["archive_errors"],
                })
            elif low.endswith((".txt", ".log", ".csv")):
                fsize = os.path.getsize(fpath) if os.path.exists(fpath) else 0
                f_c = 0
                n_c = 0
                u_c = 0
                pname = ""
                if fsize > _STREAM_THRESHOLD_BYTES:
                    f_c, n_c, u_c, parsers = _ingest_large_text_file_stream(
                        fpath,
                        source_type="upload",
                        source_name=fname,
                        rel_name=fname,
                        victim_info={},
                        parsers=parsers,
                        settings=settings,
                        job_id=job_id,
                        single_file_mode=(len(staged_files) == 1),
                        base_found=total_found,
                        base_new=total_new,
                        force_parser_name=parser_name,
                    )
                    pname = "streamed"
                else:
                    content = _read_text_file(fpath, max_bytes=_STREAM_THRESHOLD_BYTES)
                    vinfo = parse_victim_system_info(content, fname)
                    creds, pname = parse_text_with_parsers(
                        content, fname, victim_info=vinfo, parsers=parsers, force_parser_name=parser_name
                    )
                    if creds:
                        f_c, n_c = _upsert_credentials_accurate(
                            creds, "upload", fname, fname, pname, victim_info=vinfo
                        )
                    elif content.strip():
                        f_c, n_c, u_c, parsers = _handle_unparsed_file(
                            f"upload://{fname}",
                            fname,
                            "upload",
                            fname,
                            content,
                            vinfo,
                            parsers,
                            settings,
                            job_id=job_id,
                        )
                total_found += f_c
                total_new += n_c
                total_unparsed += u_c
                _record_uploaded_source(fname, 1, f_c, u_c)
                file_summaries.append({
                    "file_name": fname,
                    "creds_found": f_c,
                    "creds_new": n_c,
                    "unparsed": u_c,
                    "parser": pname if f_c else "",
                })
        all_failed = failed_archives > 0 and failed_archives == files_processed
        _job_update(
            job_id,
            status="failed" if all_failed else "completed",
            error_msg="Could not unpack any uploaded archive." if all_failed else None,
            creds_found=total_found,
            creds_new=total_new,
            unparsed_files=total_unparsed,
            log_msg=f"Upload finished: {total_found} credentials parsed ({total_new} new), {total_unparsed} queued for AI Parser.",
        )
    except Exception as exc:
        _job_update(job_id, status="failed", error_msg=str(exc))

    return {
        "job_id": job_id,
        "files_processed": files_processed,
        "creds_found": total_found,
        "creds_new": total_new,
        "unparsed_files": total_unparsed,
        "file_summaries": file_summaries,
    }


# ---------------------------------------------------------------------------
# External Cloud Link Resolver (Pixeldrain, GoFile, MediaFire, Mega, Direct)
# ---------------------------------------------------------------------------
def _download_external_link(url: str, dest_dir: str, max_bytes: int, job_id: Optional[str] = None, remaining_files: int = 10) -> List[str]:
    """Resolves Pixeldrain, GoFile, MediaFire, Mega, or direct links into downloaded local files."""
    downloaded: List[str] = []
    if remaining_files <= 0:
        return downloaded
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0"}
    extra = tuple(get_settings().get("extra_extensions", []))
    cloud_extensions = (".zip", ".rar", ".7z", ".txt", ".log", ".csv") + extra

    def _stream_to_file(dl_url: str, fallback_name: str, extra_headers: Optional[Dict[str, str]] = None) -> Optional[str]:
        if shutil.disk_usage(tempfile.gettempdir()).free < DISK_FLOOR_BYTES:
            raise RuntimeError("Free disk space is below the 2 GiB safety floor")
        h = dict(headers)
        if extra_headers:
            h.update(extra_headers)
        with requests.get(dl_url, headers=h, stream=True, timeout=60, allow_redirects=True) as resp:
            resp.raise_for_status()
            ctype = (resp.headers.get("Content-Type") or "").lower()
            if "text/html" in ctype and not fallback_name.endswith(".html"):
                return None
            cdisp = resp.headers.get("Content-Disposition") or ""
            fname = fallback_name
            m_fn = re.search(r'filename\*?=(?:UTF-8\'\')?["\']?([^"\';]+)', cdisp, re.I)
            if m_fn:
                fname = urllib.parse.unquote(m_fn.group(1)).strip()
            fname = re.sub(r'[<>:"/\\|?*]', "_", fname)[:140] or fallback_name
            out_path = os.path.join(dest_dir, fname)
            size = 0
            try:
                with open(out_path, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=65536):
                        if not chunk:
                            continue
                        size += len(chunk)
                        if size > max_bytes:
                            raise ValueError("Remote archive exceeds max_archive_mb limit")
                        if shutil.disk_usage(tempfile.gettempdir()).free < DISK_FLOOR_BYTES:
                            raise RuntimeError("Free disk space is below the 2 GiB safety floor")
                        f.write(chunk)
            except Exception:
                if os.path.exists(out_path):
                    os.remove(out_path)
                raise
            return out_path

    low = url.lower()
    try:
        # 1. Pixeldrain
        m_pd_file = re.search(r"pixeldrain\.com/u/([A-Za-z0-9]+)", url, re.I)
        if m_pd_file:
            fid = m_pd_file.group(1)
            dl_url = f"https://pixeldrain.com/api/file/{fid}?download"
            p = _stream_to_file(dl_url, f"pixeldrain_{fid}.zip")
            if p:
                downloaded.append(p)
            return downloaded

        m_pd_list = re.search(r"pixeldrain\.com/l/([A-Za-z0-9]+)", url, re.I)
        if m_pd_list:
            lid = m_pd_list.group(1)
            meta = requests.get(f"https://pixeldrain.com/api/list/{lid}", headers=headers, timeout=20).json()
            for fobj in (meta.get("files") or [])[:remaining_files]:
                fid = fobj.get("id")
                fname = fobj.get("name") or f"{fid}.zip"
                if fid and fname.lower().endswith(cloud_extensions):
                    p = _stream_to_file(f"https://pixeldrain.com/api/file/{fid}?download", fname)
                    if p:
                        downloaded.append(p)
            return downloaded

        # 2. GoFile
        m_gf = re.search(r"gofile\.io/d/([A-Za-z0-9]+)", url, re.I)
        if m_gf:
            cid = m_gf.group(1)
            acc = requests.post("https://api.gofile.io/accounts", headers=headers, timeout=20).json()
            token = ((acc.get("data") or {}).get("token")) or ""
            if token:
                info = requests.get(
                    f"https://api.gofile.io/contents/{cid}?wt=4fd6sg89d7s6",
                    headers={**headers, "Authorization": f"Bearer {token}"},
                    timeout=20,
                ).json()
                children = ((info.get("data") or {}).get("children")) or {}
                for _, child in list(children.items())[:remaining_files]:
                    link = child.get("link")
                    fname = child.get("name") or f"gofile_{cid}.zip"
                    if link and fname.lower().endswith(cloud_extensions):
                        p = _stream_to_file(link, fname, {"Cookie": f"accountToken={token}"})
                        if p:
                            downloaded.append(p)
            return downloaded

        # 3. MediaFire
        if "mediafire.com/" in low:
            html_resp = requests.get(url, headers=headers, timeout=25)
            m_dl = re.search(r'href="(https?://download\d+\.mediafire\.com/[^"]+)"', html_resp.text, re.I)
            if m_dl:
                p = _stream_to_file(m_dl.group(1), "mediafire_log.zip")
                if p:
                    downloaded.append(p)
            return downloaded

        # 4. Mega (using megadl CLI if present on host)
        if "mega.nz/" in low or "mega.co.nz/" in low:
            megadl = shutil.which("megadl")
            if megadl:
                if shutil.disk_usage(tempfile.gettempdir()).free < DISK_FLOOR_BYTES:
                    raise RuntimeError("Free disk space is below the 2 GiB safety floor")
                proc = subprocess.run([megadl, "--path", dest_dir, url], capture_output=True, timeout=120)
                if proc.returncode == 0:
                    for fn in os.listdir(dest_dir):
                        path = os.path.join(dest_dir, fn)
                        if not os.path.isfile(path):
                            continue
                        if os.path.getsize(path) > max_bytes or len(downloaded) >= remaining_files:
                            os.remove(path)
                            if job_id:
                                _job_update(job_id, log_msg=f"Skipped Mega file {fn}: exceeds max_archive_mb or file budget")
                            continue
                        downloaded.append(path)
            elif job_id:
                _job_update(job_id, log_msg=f"Mega link discovered ({url}) — install megatools (`megadl`) to auto-fetch Mega URLs.")
            return downloaded

        # 5. Direct Archive / Txt URLs
        parsed_path = urllib.parse.urlparse(url).path.lower()
        if parsed_path.endswith(cloud_extensions):
            fname = os.path.basename(parsed_path) or "direct_log.zip"
            p = _stream_to_file(url, fname)
            if p:
                downloaded.append(p)
    except Exception as exc:
        if job_id:
            _job_update(job_id, log_msg=f"Cloud link fetch skipped ({url[:70]}): {exc}")
    return downloaded


# ---------------------------------------------------------------------------
# Telegram Channel Harvester
# ---------------------------------------------------------------------------
def list_tg_sources() -> List[Dict[str, Any]]:
    ensure_db()
    conn = connect_db()
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM cs_sources_tg ORDER BY id DESC").fetchall()]
    finally:
        conn.close()


def add_tg_source(username: str, title: str = "", download_mode: str = "all", max_messages: int = 0) -> Dict[str, Any]:
    ensure_db()
    clean_user = (username or "").strip()
    clean_user = re.sub(r"^https?://t\.me/", "", clean_user, flags=re.I).strip("/").lstrip("@")
    if not clean_user:
        raise ValueError("Telegram channel username is required.")
    mode = download_mode if download_mode in ("all", "archives", "links", "txt") else "all"
    requested = int(max_messages)
    limit = 0 if requested == 0 else max(5, min(100000, requested))

    conn = connect_db()
    ts = now_iso()
    try:
        conn.execute(
            """
            INSERT INTO cs_sources_tg(username, title, download_mode, max_messages, status, created_at)
            VALUES(?, ?, ?, ?, 'idle', ?)
            ON CONFLICT(username) DO UPDATE SET
                title = COALESCE(NULLIF(excluded.title, ''), cs_sources_tg.title),
                download_mode = excluded.download_mode,
                max_messages = excluded.max_messages
            """,
            (clean_user, (title or f"@{clean_user}")[:120], mode, limit, ts),
        )
        conn.commit()
        return dict(conn.execute("SELECT * FROM cs_sources_tg WHERE username = ?", (clean_user,)).fetchone())
    finally:
        conn.close()


def delete_tg_source(channel_id: int) -> bool:
    ensure_db()
    conn = connect_db()
    try:
        cur = conn.execute("DELETE FROM cs_sources_tg WHERE id = ?", (int(channel_id),))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


async def _sync_tg_channel_coro(channel_row: Dict[str, Any], job_id: str) -> Dict[str, int]:
    from telethon import TelegramClient
    from telethon.sessions import StringSession
    import tg_mtproto

    session_str, api_id, api_hash = tg_mtproto.get_session()
    settings = get_settings()
    max_bytes = int(settings.get("max_archive_mb", 250)) * 1024 * 1024
    ephemeral = bool(settings.get("ephemeral_delete_archives", True))

    client = TelegramClient(StringSession(session_str), api_id, api_hash)
    await client.connect()
    stats = {"files": 0, "found": 0, "new": 0, "unparsed": 0, "messages": 0,
             "skipped": 0, "remaining": 0, "last_id": int(channel_row.get("last_message_id") or 0),
             "status": "ready"}
    skip_reasons = {"extension not allowed": 0, "exceeds max_archive_mb": 0,
                    "link fetch failed": 0, "disk floor": 0}
    saved_files = saved_new = 0
    stop_reason = ""
    tmp_stage = tempfile.mkdtemp(prefix=f"cs_tg_{channel_row['username']}_")
    preserve_stage = False
    chan_title = channel_row.get("title") or channel_row["username"]
    entity = None

    def persist_cursor(status="syncing", error=""):
        nonlocal saved_files, saved_new
        conn = connect_db()
        try:
            conn.execute(
                """UPDATE cs_sources_tg SET title=?, last_message_id=?, last_synced_at=?,
                   files_downloaded=files_downloaded+?, total_creds=total_creds+?,
                   messages_read=messages_read+?, messages_remaining=?, status=?, last_error=? WHERE id=?""",
                (chan_title[:120], stats["last_id"], now_iso(), stats["files"] - saved_files,
                 stats["new"] - saved_new, stats["messages"] - persist_cursor.saved_messages,
                 stats["remaining"], status, error[:400], channel_row["id"]),
            )
            conn.commit()
            saved_files, saved_new = stats["files"], stats["new"]
            persist_cursor.saved_messages = stats["messages"]
        finally:
            conn.close()
    persist_cursor.saved_messages = 0

    try:
        entity = await client.get_entity(channel_row["username"])
        chan_title = getattr(entity, "title", None) or chan_title
        mode = channel_row.get("download_mode", "all")
        message_limit = int(channel_row.get("max_messages") or 0)
        file_limit = int(settings.get("max_files_per_sync", 200))
        extra = tuple(settings.get("extra_extensions", []))
        allowed_ext = (
            (".txt", ".log", ".csv") if mode == "txt"
            else (".zip", ".rar", ".7z") if mode == "archives"
            else (".txt", ".log", ".csv", ".zip", ".rar", ".7z") + extra
        )
        _job_update(job_id, files_total=message_limit, log_msg=f"Reading @{channel_row['username']} from message {stats['last_id'] + 1} onward")

        while True:
            if shutil.disk_usage(tempfile.gettempdir()).free < DISK_FLOOR_BYTES:
                stop_reason = "Free disk space is below the 2 GiB safety floor"
                skip_reasons["disk floor"] += 1
                preserve_stage = True
                break
            if stats["files"] >= file_limit:
                stop_reason = f"Stopped after {stats['files']} files"
                break
            if message_limit and stats["messages"] >= message_limit:
                stop_reason = f"Stopped after {stats['messages']} messages"
                break
            batch_size = min(TG_BATCH_SIZE, message_limit - stats["messages"]) if message_limit else TG_BATCH_SIZE
            batch = [msg async for msg in client.iter_messages(entity, min_id=stats["last_id"],
                                                                reverse=True, limit=batch_size)]
            if not batch:
                break
            batch_cursor = stats["last_id"]
            try:
                for msg in batch:
                    if msg.id <= stats["last_id"]:
                        continue
                    # Message progress moves even for text-only or skipped attachments.
                    _job_update(job_id, files_processed=stats["messages"] + 1, current_file="")
                    text = msg.message or ""
                    pwd_hints = _extract_passwords_from_text(text)
                    if text and len(text) > 20:
                        creds_inline, pname_inline = parse_text_with_parsers(text, f"tg_msg_{msg.id}.txt")
                        if creds_inline:
                            f_i, n_i = _upsert_credentials_accurate(
                                creds_inline, "telegram", f"@{channel_row['username']}", f"msg_{msg.id}", pname_inline
                            )
                            stats["found"] += f_i
                            stats["new"] += n_i

                    msg_dir = os.path.join(tmp_stage, f"msg_{msg.id}")
                    os.makedirs(msg_dir, exist_ok=True)
                    fetched_any = False
                    partial_message = False
                    if msg.document and mode in ("all", "archives", "txt"):
                        fname = "attachment.bin"
                        for attr in getattr(msg.document, "attributes", []) or []:
                            if getattr(attr, "file_name", None):
                                fname = attr.file_name
                                break
                        fsize = getattr(msg.document, "size", 0) or 0
                        reason = ("extension not allowed" if not fname.lower().endswith(allowed_ext)
                                  else "exceeds max_archive_mb" if not 0 < fsize <= max_bytes else "")
                        if reason:
                            stats["skipped"] += 1
                            skip_reasons[reason] += 1
                            _job_update(job_id, files_skipped=stats["skipped"], log_msg=f"Skipped {fname}: {reason}")
                        elif stats["files"] >= file_limit:
                            partial_message = True
                        else:
                            if shutil.disk_usage(tempfile.gettempdir()).free < DISK_FLOOR_BYTES:
                                stop_reason = "Free disk space is below the 2 GiB safety floor"
                                skip_reasons["disk floor"] += 1
                                preserve_stage = True
                                partial_message = True
                            else:
                                dest_file = os.path.join(msg_dir, re.sub(r'[<>:"/\\|?*]', "_", fname))
                                _job_update(job_id, current_file=fname)
                                await client.download_media(msg, file=dest_file)
                                fetched_any = True
                                stats["files"] += 1
                                _job_update(job_id, files_downloaded=stats["files"], current_file="")

                    if text and mode in ("all", "links"):
                        links = [u for u in URL_EXTRACT_RE.findall(text)
                                 if any(dom in u.lower() for dom in ("pixeldrain.com", "gofile.io", "mediafire.com", "mega.nz")) or
                                 urllib.parse.urlparse(u).path.lower().endswith(allowed_ext)]
                        if len(links) > MAX_LINKS_PER_MESSAGE:
                            excess = len(links) - MAX_LINKS_PER_MESSAGE
                            stats["skipped"] += excess
                            skip_reasons["link limit"] = skip_reasons.get("link limit", 0) + excess
                            _job_update(job_id, files_skipped=stats["skipped"], log_msg=f"Message {msg.id}: skipped {excess} links beyond the {MAX_LINKS_PER_MESSAGE}-link limit")
                        for u in links[:MAX_LINKS_PER_MESSAGE]:
                            if stats["files"] >= file_limit:
                                partial_message = True
                                break
                            if shutil.disk_usage(tempfile.gettempdir()).free < DISK_FLOOR_BYTES:
                                stop_reason = "Free disk space is below the 2 GiB safety floor"
                                skip_reasons["disk floor"] += 1
                                preserve_stage = True
                                partial_message = True
                                break
                            _job_update(job_id, current_file=u[:80])
                            dl_files = _download_external_link(
                                u, msg_dir, max_bytes=max_bytes, job_id=job_id,
                                remaining_files=file_limit - stats["files"])
                            if dl_files:
                                fetched_any = True
                                stats["files"] += len(dl_files)
                                _job_update(job_id, files_downloaded=stats["files"], current_file="")
                            else:
                                stats["skipped"] += 1
                                if shutil.disk_usage(tempfile.gettempdir()).free < DISK_FLOOR_BYTES:
                                    stop_reason = "Free disk space is below the 2 GiB safety floor"
                                    skip_reasons["disk floor"] += 1
                                    preserve_stage = True
                                    partial_message = True
                                    _job_update(job_id, files_skipped=stats["skipped"], log_msg=f"Stopped downloading {u[:80]}: disk floor reached", current_file="")
                                    break
                                skip_reasons["link fetch failed"] += 1
                                _job_update(job_id, files_skipped=stats["skipped"], log_msg=f"Link fetch failed: {u[:80]}", current_file="")

                    if fetched_any:
                        s = _ingest_directory_files(
                            msg_dir, source_type="telegram", source_name=f"@{channel_row['username']}",
                            recursive=True, job_id=None, password_hints=pwd_hints, is_ephemeral=ephemeral,
                        )
                        stats["found"] += s["found"]
                        stats["new"] += s["new"]
                        stats["unparsed"] += s["unparsed"]
                    if ephemeral and not preserve_stage:
                        shutil.rmtree(msg_dir, ignore_errors=True)
                    if partial_message:
                        stop_reason = stop_reason or f"Stopped after {stats['files']} files"
                        break
                    stats["last_id"] = batch_cursor = msg.id
                    stats["messages"] += 1
                persist_cursor()
            except Exception:
                # Keep every completed message, even when a later message in this batch fails.
                stats["last_id"] = batch_cursor
                persist_cursor(status="error")
                raise
            if stop_reason or len(batch) < batch_size:
                break

        if stop_reason and entity is not None:
            try:
                count = await client.get_messages(entity, limit=0, min_id=stats["last_id"])
                stats["remaining"] = int(count.total)
            except (AttributeError, TypeError):
                stats["remaining"] = sum(1 async for _ in client.iter_messages(entity, min_id=stats["last_id"], reverse=True))
        stats["status"] = "paused" if stop_reason and stats["remaining"] else "ready"
        message = (f"{stop_reason}. {stats['remaining']} messages still queued; the next sync resumes here."
                   if stats["status"] == "paused" else "")
        persist_cursor(status=stats["status"], error=message)
        reasons = ", ".join(f"{n} {reason}" for reason, n in skip_reasons.items() if n) or "none"
        _job_update(job_id, files_processed=stats["messages"],
                    files_total=stats["messages"] if stats["status"] == "ready" else message_limit,
                    files_downloaded=stats["files"], files_skipped=stats["skipped"],
                    messages_remaining=stats["remaining"], status=stats["status"] if stats["status"] == "paused" else None,
                    error_msg=message if stats["status"] == "paused" else "",
                    log_msg=f"{message + ' ' if message else ''}Messages scanned: {stats['messages']}; files downloaded: {stats['files']}; files skipped: {stats['skipped']}. Skip reasons: {reasons}.")
        return stats
    finally:
        await client.disconnect()
        if ephemeral and not preserve_stage:
            shutil.rmtree(tmp_stage, ignore_errors=True)


def sync_tg_source_async(channel_id: int) -> Dict[str, Any]:
    ensure_db()
    conn = connect_db()
    try:
        row = conn.execute("SELECT * FROM cs_sources_tg WHERE id = ?", (int(channel_id),)).fetchone()
        if not row:
            raise ValueError("Telegram channel source not found.")
        chan = dict(row)
        conn.execute("UPDATE cs_sources_tg SET status = 'syncing' WHERE id = ?", (int(channel_id),))
        conn.commit()
    finally:
        conn.close()

    job_id = _job_create("tg_sync", f"@{chan['username']}")

    def _run():
        try:
            stats = asyncio.run(_sync_tg_channel_coro(chan, job_id))
            _job_update(
                job_id,
                status="paused" if stats["status"] == "paused" else "completed",
                files_processed=stats["messages"],
                files_downloaded=stats["files"],
                files_skipped=stats["skipped"],
                messages_remaining=stats["remaining"],
                creds_found=stats["found"],
                creds_new=stats["new"],
                unparsed_files=stats["unparsed"],
                log_msg=f"Telegram sync {'paused' if stats['status'] == 'paused' else 'finished'}: {stats['messages']} messages, {stats['files']} files, {stats['found']} creds parsed ({stats['new']} new).",
            )
        except Exception as exc:
            err_str = str(getattr(exc, "detail", exc))
            c2 = connect_db()
            try:
                c2.execute(
                    "UPDATE cs_sources_tg SET status = 'error', last_error = ? WHERE id = ?",
                    (err_str[:400], chan["id"]),
                )
                c2.commit()
            finally:
                c2.close()
            _job_update(job_id, status="failed", error_msg=err_str, log_msg=f"Telegram sync failed: {err_str}")

    threading.Thread(target=_run, daemon=True, name=f"cs-tg-{job_id}").start()
    return {"job_id": job_id, "channel": chan["username"]}


def sync_all_async(job_type: str = "weekly_auto") -> Dict[str, Any]:
    ensure_db()
    local_sources = [s for s in list_local_sources() if s.get("auto_weekly", 1) or job_type != "weekly_auto"]
    tg_sources = list_tg_sources()
    job_id = _job_create(job_type, f"Full Sync ({len(local_sources)} local, {len(tg_sources)} TG)")

    def _run():
        totals = {"files": 0, "found": 0, "new": 0, "unparsed": 0, "messages": 0, "skipped": 0, "remaining": 0}
        settings = get_settings()
        try:
            for src in local_sources:
                if not os.path.exists(src["folder_path"]):
                    continue
                _job_update(job_id, log_msg=f"Scanning local folder: {src['label']}")
                del_opt = bool(src.get("delete_after_parse", 0)) or bool(settings.get("delete_after_parse", False))
                st = _ingest_directory_files(
                    src["folder_path"],
                    source_type="local",
                    source_name=src["label"] or src["folder_path"],
                    recursive=bool(src.get("recursive", 1)),
                    job_id=job_id,
                    is_ephemeral=False,
                    delete_after_parse=del_opt,
                )
                totals["files"] += st["files"]
                totals["found"] += st["found"]
                totals["new"] += st["new"]
                totals["unparsed"] += st["unparsed"]

            for ch in tg_sources:
                _job_update(job_id, log_msg=f"Syncing Telegram channel: @{ch['username']}")
                try:
                    st = asyncio.run(_sync_tg_channel_coro(ch, job_id))
                    totals["files"] += st["files"]
                    totals["found"] += st["found"]
                    totals["new"] += st["new"]
                    totals["unparsed"] += st["unparsed"]
                    totals["messages"] += st["messages"]
                    totals["skipped"] += st["skipped"]
                    totals["remaining"] += st["remaining"]
                except Exception as ch_exc:
                    err_s = str(getattr(ch_exc, "detail", ch_exc))
                    _job_update(job_id, log_msg=f"Skipped @{ch['username']}: {err_s}")

            conn = connect_db()
            try:
                conn.execute(
                    "INSERT INTO cs_settings(key, value) VALUES('last_weekly_run', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (now_iso(),),
                )
                conn.commit()
            finally:
                conn.close()

            _job_update(
                job_id,
                status="paused" if totals["remaining"] else "completed",
                files_processed=totals["messages"] if tg_sources else totals["files"],
                files_downloaded=totals["files"],
                files_skipped=totals["skipped"],
                messages_remaining=totals["remaining"],
                creds_found=totals["found"],
                creds_new=totals["new"],
                unparsed_files=totals["unparsed"],
                log_msg=f"Full sync completed: {totals['files']} files, {totals['found']} parsed ({totals['new']} new).",
            )
        except Exception as exc:
            _job_update(job_id, status="failed", error_msg=str(exc))

    threading.Thread(target=_run, daemon=True, name=f"cs-all-{job_id}").start()
    return {"job_id": job_id, "local_count": len(local_sources), "tg_count": len(tg_sources)}


# ---------------------------------------------------------------------------
# Search, Overview & Export APIs
# ---------------------------------------------------------------------------
def get_overview() -> Dict[str, Any]:
    ensure_db()
    conn = connect_db()
    try:
        total_creds = conn.execute("SELECT COUNT(*) FROM cs_credentials").fetchone()[0]
        unique_domains = conn.execute("SELECT COUNT(DISTINCT domain) FROM cs_credentials WHERE domain != ''").fetchone()[0]
        watchlist_hits = conn.execute("SELECT COUNT(*) FROM cs_credentials WHERE matched_watchlist = 1").fetchone()[0]
        pending_unparsed = conn.execute("SELECT COUNT(*) FROM cs_unparsed_queue WHERE status = 'pending'").fetchone()[0]
        active_parsers = conn.execute("SELECT COUNT(*) FROM cs_parsers WHERE enabled = 1").fetchone()[0]

        families = [
            {"family": r[0] or "Unknown", "count": r[1]}
            for r in conn.execute(
                "SELECT stealer_family, COUNT(*) AS cnt FROM cs_credentials GROUP BY stealer_family ORDER BY cnt DESC LIMIT 12"
            ).fetchall()
        ]
        top_domains = [
            {"domain": r[0], "count": r[1]}
            for r in conn.execute(
                "SELECT domain, COUNT(*) AS cnt FROM cs_credentials WHERE domain != '' GROUP BY domain ORDER BY cnt DESC LIMIT 10"
            ).fetchall()
        ]
        return {
            "metrics": {
                "total_credentials": total_creds,
                "unique_domains": unique_domains,
                "watchlist_hits": watchlist_hits,
                "pending_unparsed": pending_unparsed,
                "active_parsers": active_parsers,
                "local_sources": len(list_local_sources()),
                "tg_sources": len(list_tg_sources()),
            },
            "families": families,
            "top_domains": top_domains,
            "settings": get_settings(),
            "ai_status": get_mantis_ai_status(),
        }
    finally:
        conn.close()


def _build_cs_fts_query(clean_q: str) -> Optional[str]:
    """Tokenize query string into safe AND-joined FTS5 trigram terms."""
    raw_tokens = clean_q.split()
    valid_terms = []
    for t in raw_tokens:
        clean = t.strip('"\' ,;:')
        if len(clean) >= 3:
            valid_terms.append('"' + clean.replace('"', '""') + '"')
    if valid_terms:
        return " AND ".join(valid_terms)
    return None


def search_credentials(
    q: str = "",
    family: str = "",
    source_type: str = "",
    watchlist_only: bool = False,
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, Any]:
    ensure_db()
    clauses = ["1=1"]
    params: List[Any] = []

    clean_q = (q or "").strip()
    use_fts = False

    if clean_q:
        fts_expr = _build_cs_fts_query(clean_q)
        if fts_expr:
            clauses.append("id IN (SELECT rowid FROM cs_credentials_fts WHERE cs_credentials_fts MATCH ?)")
            params.append(fts_expr)
            use_fts = True
        else:
            like = f"%{clean_q}%"
            clauses.append("(domain LIKE ? OR url LIKE ? OR username LIKE ? OR email LIKE ? OR victim_ip LIKE ? OR source_name LIKE ?)")
            params.extend([like, like, like, like, like, like])

    if family and family.strip() and family.strip().lower() != "all":
        clauses.append("stealer_family = ?")
        params.append(family.strip())
    if source_type and source_type.strip() and source_type.strip().lower() != "all":
        clauses.append("source_type = ?")
        params.append(source_type.strip())
    if watchlist_only:
        clauses.append("matched_watchlist = 1")

    where_sql = " AND ".join(clauses)
    lim = max(1, min(500, int(limit or 100)))
    off = max(0, int(offset or 0))

    conn = connect_db()
    try:
        try:
            total = conn.execute(f"SELECT COUNT(*) FROM cs_credentials WHERE {where_sql}", params).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM cs_credentials WHERE {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
                params + [lim, off],
            ).fetchall()
        except sqlite3.OperationalError as op_err:
            # If FTS query encountered an error, gracefully fallback to LIKE search
            if use_fts and clean_q:
                logger.warning("[FTS5] Search query failed in FTS5, falling back to LIKE: %s", op_err)
                fb_clauses = ["1=1"]
                fb_params: List[Any] = []
                like = f"%{clean_q}%"
                fb_clauses.append("(domain LIKE ? OR url LIKE ? OR username LIKE ? OR email LIKE ? OR victim_ip LIKE ? OR source_name LIKE ?)")
                fb_params.extend([like, like, like, like, like, like])
                if family and family.strip() and family.strip().lower() != "all":
                    fb_clauses.append("stealer_family = ?")
                    fb_params.append(family.strip())
                if source_type and source_type.strip() and source_type.strip().lower() != "all":
                    fb_clauses.append("source_type = ?")
                    fb_params.append(source_type.strip())
                if watchlist_only:
                    fb_clauses.append("matched_watchlist = 1")
                where_fb = " AND ".join(fb_clauses)
                total = conn.execute(f"SELECT COUNT(*) FROM cs_credentials WHERE {where_fb}", fb_params).fetchone()[0]
                rows = conn.execute(
                    f"SELECT * FROM cs_credentials WHERE {where_fb} ORDER BY id DESC LIMIT ? OFFSET ?",
                    fb_params + [lim, off],
                ).fetchall()
            else:
                raise
        return {
            "total": total,
            "limit": lim,
            "offset": off,
            "items": [dict(r) for r in rows],
        }
    finally:
        conn.close()


def delete_credential(cred_id: int) -> bool:
    ensure_db()
    conn = connect_db()
    try:
        cur = conn.execute("DELETE FROM cs_credentials WHERE id = ?", (int(cred_id),))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def delete_all_credentials() -> int:
    ensure_db()
    conn = connect_db()
    try:
        with conn:
            deleted = conn.execute("DELETE FROM cs_credentials").rowcount
            conn.execute("UPDATE cs_watchlist SET hits_count = 0 WHERE hits_count != 0")
        return deleted
    finally:
        conn.close()


def get_credential_sources_stats() -> List[Dict[str, Any]]:
    """Return aggregated stats for all distinct sources/archives in cs_credentials."""
    ensure_db()
    conn = connect_db()
    try:
        cur = conn.execute(
            "SELECT source_type, source_name, count(id) FROM cs_credentials GROUP BY source_type, source_name"
        )
        rows = cur.fetchall()
        groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for st, sn, cnt in rows:
            st = (st or "unknown").lower()
            sn_raw = sn or "Unknown"
            parts = [p.strip() for p in sn_raw.split(" / ")]
            if len(parts) > 1 and parts[0] == "files":
                group_key = f"{parts[0]} / {parts[1]}"
                display_name = parts[1]
            elif len(parts) > 1:
                group_key = parts[0]
                display_name = parts[0]
            else:
                group_key = sn_raw
                display_name = sn_raw

            key = (st, group_key)
            if key not in groups:
                group_id = hashlib.md5(f"{st}:{group_key}".encode("utf-8")).hexdigest()[:16]
                groups[key] = {
                    "id": group_id,
                    "source_type": st,
                    "group_key": group_key,
                    "display_name": display_name,
                    "count": 0,
                    "raw_sources": [],
                }
            groups[key]["count"] += cnt
            groups[key]["raw_sources"].append(sn_raw)

        result = list(groups.values())
        result.sort(key=lambda x: x["count"], reverse=True)
        return result
    finally:
        conn.close()


def delete_credentials_by_sources(
    source_keys: Optional[List[str]] = None,
    raw_sources: Optional[List[str]] = None,
    delete_all: bool = False,
) -> int:
    """Delete credentials belonging to selected sources or all."""
    ensure_db()
    if delete_all:
        return delete_all_credentials()

    if not source_keys and not raw_sources:
        return 0

    conn = connect_db()
    try:
        total_deleted = 0
        with conn:
            all_raw = set(raw_sources or [])
            if source_keys:
                for sk in source_keys:
                    sk = (sk or "").strip()
                    if not sk:
                        continue
                    cur = conn.execute(
                        "DELETE FROM cs_credentials WHERE source_name = ? OR source_name LIKE ? || ' / %'",
                        (sk, sk),
                    )
                    total_deleted += cur.rowcount

            if all_raw:
                raw_list = list(all_raw)
                batch_size = 400
                for i in range(0, len(raw_list), batch_size):
                    chunk = raw_list[i : i + batch_size]
                    placeholders = ",".join("?" for _ in chunk)
                    cur = conn.execute(
                        f"DELETE FROM cs_credentials WHERE source_name IN ({placeholders})",
                        chunk,
                    )
                    total_deleted += cur.rowcount

            # Recalculate watchlist hits
            w_rows = conn.execute("SELECT id, target_type, value FROM cs_watchlist").fetchall()
            for w_id, ttype, val in w_rows:
                if ttype == "domain":
                    cnt = conn.execute(
                        "SELECT count(id) FROM cs_credentials WHERE domain = ? OR domain LIKE ? || '.%'",
                        (val, val),
                    ).fetchone()[0]
                else:
                    cnt = conn.execute(
                        "SELECT count(id) FROM cs_credentials WHERE username = ? OR email = ?",
                        (val, val),
                    ).fetchone()[0]
                conn.execute("UPDATE cs_watchlist SET hits_count = ? WHERE id = ?", (cnt, w_id))

        return total_deleted
    finally:
        conn.close()



def export_credentials_csv(
    q: str = "",
    family: str = "",
    source_type: str = "",
    watchlist_only: bool = False,
) -> str:
    data = search_credentials(q=q, family=family, source_type=source_type, watchlist_only=watchlist_only, limit=5000, offset=0)
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "id", "domain", "url", "username", "email", "password_plain",
        "stealer_family", "victim_ip", "victim_country", "victim_os",
        "source_type", "source_name", "file_name", "parser_name", "matched_watchlist", "last_seen",
    ])
    for item in data["items"]:
        writer.writerow([
            item["id"], item["domain"], item["url"], item["username"], item["email"], item["password_plain"],
            item["stealer_family"], item["victim_ip"], item["victim_country"], item["victim_os"],
            item["source_type"], item["source_name"], item["file_name"], item["parser_name"],
            item["matched_watchlist"], item["last_seen"],
        ])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Weekly Scheduler Daemon
# ---------------------------------------------------------------------------
def _weekly_scheduler_loop() -> None:
    while True:
        try:
            time.sleep(900)  # Check every 15 minutes
            s = get_settings()
            if not s.get("weekly_enabled"):
                continue
            now = datetime.now(timezone.utc)
            day_name = WEEKDAYS[now.weekday()]
            if day_name != s.get("weekly_day"):
                continue
            if now.hour < int(s.get("weekly_hour_utc", 2)):
                continue
            last_run = s.get("last_weekly_run") or ""
            if last_run:
                try:
                    last_dt = datetime.fromisoformat(last_run.replace("Z", "+00:00"))
                    if (now - last_dt).total_seconds() < 6 * 86400:
                        continue
                except Exception:
                    pass
            logger.info("Triggering scheduled weekly Credential Stealer sync...")
            sync_all_async(job_type="weekly_auto")
        except Exception:
            logger.exception("Credential Stealer weekly scheduler tick failed")


def start_weekly_scheduler() -> None:
    global _scheduler_started
    with _scheduler_lock:
        if _scheduler_started:
            return
        init_db()
        t = threading.Thread(target=_weekly_scheduler_loop, daemon=True, name="cs-weekly-scheduler")
        t.start()
        _scheduler_started = True
