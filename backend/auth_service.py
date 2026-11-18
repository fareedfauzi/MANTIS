import os
import sys
import sqlite3
import hashlib
import hmac
import base64
import json
import time
import secrets
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import deployment_config

logger = logging.getLogger("mantis.auth")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
USERS_DB_PATH = os.path.join(DATA_DIR, "users.db")
ROOT_DIR = os.path.dirname(BASE_DIR)
ENV_PATH = os.path.join(ROOT_DIR, ".env")

# Ensure DATA_DIR exists
os.makedirs(DATA_DIR, exist_ok=True)


def _get_or_create_secret_key() -> bytes:
    """Retrieve or generate persistent 32-byte secret key."""
    key_hex = os.environ.get("MANTIS_SECRET_KEY", "").strip()
    if len(key_hex) == 64:
        try:
            return bytes.fromhex(key_hex)
        except ValueError:
            pass

    # Check .env directly
    if os.path.exists(ENV_PATH):
        try:
            with open(ENV_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("MANTIS_SECRET_KEY="):
                        val = line.split("=", 1)[1].strip().strip('"').strip("'")
                        if len(val) == 64:
                            os.environ["MANTIS_SECRET_KEY"] = val
                            return bytes.fromhex(val)
        except Exception:
            pass

    # Generate new random key and save to .env
    new_key = secrets.token_bytes(32)
    new_hex = new_key.hex()
    os.environ["MANTIS_SECRET_KEY"] = new_hex

    try:
        lines = []
        if os.path.exists(ENV_PATH):
            with open(ENV_PATH, "r", encoding="utf-8") as f:
                lines = f.readlines()
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.append(f"\n# Secret key for JWT sessions and per-user API key encryption\nMANTIS_SECRET_KEY={new_hex}\n")
        with open(ENV_PATH, "w", encoding="utf-8") as f:
            f.writelines(lines)
    except Exception as e:
        logger.warning(f"Could not persist MANTIS_SECRET_KEY to .env: {e}")

    return new_key


SECRET_KEY = _get_or_create_secret_key()


def get_db_connection() -> sqlite3.Connection:
    """Return SQLite connection with WAL mode and row factory."""
    conn = sqlite3.connect(USERS_DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_users_db() -> None:
    """Initialize users and user_api_keys tables with default admin account."""
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'analyst',
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                last_login INTEGER
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_api_keys (
                user_id TEXT NOT NULL,
                provider TEXT NOT NULL COLLATE NOCASE,
                encrypted_key TEXT NOT NULL,
                nonce TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, provider),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        conn.commit()

        # Ensure default workstation user exists for local workstation mode
        conn.execute("""
            INSERT OR IGNORE INTO users (id, username, password_hash, salt, role, is_active, created_at)
            VALUES ('workstation_user', 'local_analyst', '', '', 'admin', 1, ?)
        """, (int(time.time()),))

        # Check if default admin exists
        row = conn.execute("SELECT COUNT(*) as cnt FROM users WHERE id != 'workstation_user'").fetchone()
        if row["cnt"] == 0:
            default_user = os.environ.get("MANTIS_ADMIN_USER", "admin")
            default_pass = os.environ.get("MANTIS_ADMIN_PASSWORD", "mantis2026!")
            create_user(username=default_user, password=default_pass, role="admin")
            logger.info(f"Initialized default administrator account: '{default_user}'")


def _hash_password(password: str, salt: bytes) -> str:
    """Hash password using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120000).hex()


def create_user(username: str, password: str, role: str = "analyst") -> Dict[str, Any]:
    """Create a new user account."""
    username = username.strip().lower()
    if not username or len(username) < 3:
        raise ValueError("Username must be at least 3 characters long.")
    if not password or len(password) < 6:
        raise ValueError("Password must be at least 6 characters long.")
    if role not in ("admin", "analyst"):
        role = "analyst"

    salt = secrets.token_bytes(16)
    pw_hash = _hash_password(password, salt)
    user_id = secrets.token_hex(8)
    now = int(time.time())

    with get_db_connection() as conn:
        conn.execute(
            """INSERT INTO users (id, username, password_hash, salt, role, is_active, created_at)
               VALUES (?, ?, ?, ?, ?, 1, ?)""",
            (user_id, username, pw_hash, salt.hex(), role, now)
        )
        conn.commit()

    return {"id": user_id, "username": username, "role": role, "created_at": now}


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Verify credentials and return user dict if valid."""
    username = username.strip().lower()
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1",
            (username,)
        ).fetchone()

        if not row:
            return None

        salt = bytes.fromhex(row["salt"])
        expected_hash = row["password_hash"]
        actual_hash = _hash_password(password, salt)

        if hmac.compare_digest(expected_hash, actual_hash):
            now = int(time.time())
            conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, row["id"]))
            conn.commit()
            return {
                "id": row["id"],
                "username": row["username"],
                "role": row["role"],
                "created_at": row["created_at"],
                "last_login": now,
            }

    return None


def list_users() -> List[Dict[str, Any]]:
    """List all user accounts."""
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT id, username, role, is_active, created_at, last_login FROM users ORDER BY username ASC"
        ).fetchall()
        return [dict(r) for r in rows]


def delete_user(user_id: str) -> bool:
    """Delete a user account."""
    with get_db_connection() as conn:
        cur = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return cur.rowcount > 0


# --- Token Management ---

def create_session_token(user: Dict[str, Any], expires_in_seconds: int = 86400 * 7) -> str:
    """Generate a tamper-proof signed session token."""
    now = int(time.time())
    payload = {
        "sub": user["id"],
        "name": user["username"],
        "role": user["role"],
        "iat": now,
        "exp": now + expires_in_seconds,
    }
    payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode('ascii').rstrip('=')

    sig = hmac.new(SECRET_KEY, payload_b64.encode('ascii'), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode('ascii').rstrip('=')

    return f"{payload_b64}.{sig_b64}"


def verify_session_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify token signature and expiration, returning decoded user info."""
    if not token or "." not in token:
        return None

    try:
        payload_b64, sig_b64 = token.split(".", 1)

        # Pad base64 strings
        def pad(s: str) -> bytes:
            return base64.urlsafe_b64decode(s + "=" * ((4 - len(s) % 4) % 4))

        expected_sig = hmac.new(SECRET_KEY, payload_b64.encode('ascii'), hashlib.sha256).digest()
        actual_sig = pad(sig_b64)

        if not hmac.compare_digest(expected_sig, actual_sig):
            return None

        payload = json.loads(pad(payload_b64).decode('utf-8'))
        if payload.get("exp", 0) < int(time.time()):
            return None

        # Verify user still exists and is active
        with get_db_connection() as conn:
            row = conn.execute(
                "SELECT id, username, role, is_active FROM users WHERE id = ? AND is_active = 1",
                (payload["sub"],)
            ).fetchone()
            if not row:
                return None
            return {
                "id": row["id"],
                "username": row["username"],
                "role": row["role"],
            }
    except Exception as e:
        logger.debug(f"Token verification error: {e}")
        return None


# --- Per-User Encrypted API Key Storage ---

def _encrypt_key(raw_key: str) -> (str, str):
    """Encrypt raw API key using AES-GCM."""
    aesgcm = AESGCM(SECRET_KEY)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, raw_key.encode("utf-8"), None)
    return base64.b64encode(ciphertext).decode("ascii"), base64.b64encode(nonce).decode("ascii")


def _decrypt_key(encrypted_b64: str, nonce_b64: str) -> str:
    """Decrypt API key using AES-GCM."""
    aesgcm = AESGCM(SECRET_KEY)
    ciphertext = base64.b64decode(encrypted_b64)
    nonce = base64.b64decode(nonce_b64)
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")


def save_user_api_key(user_id: str, provider: str, raw_key: str) -> None:
    """Encrypt and store an API key for a specific user."""
    provider = provider.strip().lower()
    raw_key = raw_key.strip()
    if not raw_key:
        delete_user_api_key(user_id, provider)
        return

    enc_key, nonce = _encrypt_key(raw_key)
    now = int(time.time())

    with get_db_connection() as conn:
        conn.execute(
            """INSERT INTO user_api_keys (user_id, provider, encrypted_key, nonce, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(user_id, provider) DO UPDATE SET
                   encrypted_key = excluded.encrypted_key,
                   nonce = excluded.nonce,
                   updated_at = excluded.updated_at""",
            (user_id, provider, enc_key, nonce, now)
        )
        conn.commit()


def delete_user_api_key(user_id: str, provider: str) -> bool:
    """Remove a user's API key."""
    provider = provider.strip().lower()
    with get_db_connection() as conn:
        cur = conn.execute(
            "DELETE FROM user_api_keys WHERE user_id = ? AND provider = ?",
            (user_id, provider)
        )
        conn.commit()
        return cur.rowcount > 0


def get_user_api_key(user_id: str, provider: str) -> Optional[str]:
    """Retrieve and decrypt an API key for a specific user."""
    provider = provider.strip().lower()
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT encrypted_key, nonce FROM user_api_keys WHERE user_id = ? AND provider = ?",
            (user_id, provider)
        ).fetchone()

        if not row:
            return None

        try:
            return _decrypt_key(row["encrypted_key"], row["nonce"])
        except Exception as e:
            logger.error(f"Failed to decrypt key for {user_id}/{provider}: {e}")
            return None


def get_all_user_api_keys(user_id: str, mask: bool = True) -> Dict[str, str]:
    """Return all configured API keys for a user (masked by default)."""
    result = {}
    with get_db_connection() as conn:
        rows = conn.execute(
            "SELECT provider, encrypted_key, nonce FROM user_api_keys WHERE user_id = ?",
            (user_id,)
        ).fetchall()

        for r in rows:
            prov = r["provider"]
            if mask:
                result[prov] = "••••••••••••"
            else:
                try:
                    result[prov] = _decrypt_key(r["encrypted_key"], r["nonce"])
                except Exception:
                    result[prov] = ""
    return result


# Initialize tables on import
init_users_db()
