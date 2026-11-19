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


def _encryption_keys() -> list:
    """Key material for per-user API key encryption, in priority order.

    Session HMAC and AES-GCM used to share one key. `MANTIS_ENCRYPTION_KEY`
    (64 hex chars) separates them; the legacy derivation stays last so existing
    stored keys remain readable after the split.
    """
    keys = []
    raw = os.environ.get("MANTIS_ENCRYPTION_KEY", "").strip()
    if len(raw) == 64:
        try:
            keys.append(bytes.fromhex(raw))
        except ValueError:
            logger.warning("MANTIS_ENCRYPTION_KEY is not valid hex; ignoring it")
    if SECRET_KEY not in keys:
        keys.append(SECRET_KEY)
    return keys


def get_db_connection() -> sqlite3.Connection:
    """Return SQLite connection with WAL mode and row factory."""
    conn = sqlite3.connect(USERS_DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


MIN_ADMIN_PASSWORD_LEN = 8


def update_env_admin_password(new_password: str) -> None:
    """Persist or update MANTIS_ADMIN_PASSWORD in .env so a custom password survives restarts."""
    os.environ["MANTIS_ADMIN_PASSWORD"] = new_password
    try:
        lines = []
        found = False
        if os.path.exists(ENV_PATH):
            with open(ENV_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("MANTIS_ADMIN_PASSWORD="):
                        lines.append(f"MANTIS_ADMIN_PASSWORD={new_password}\n")
                        found = True
                    else:
                        lines.append(line)
        if not found:
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.append(f"\n# Administrator password\nMANTIS_ADMIN_PASSWORD={new_password}\n")
        with open(ENV_PATH, "w", encoding="utf-8") as f:
            f.writelines(lines)
    except Exception as e:
        logger.warning(f"Could not persist MANTIS_ADMIN_PASSWORD to .env: {e}")


def set_user_password(user_id: str, new_password: str, persist_env: bool = False) -> None:
    """Update password hash and salt for an existing user account."""
    if not new_password or len(new_password) < MIN_ADMIN_PASSWORD_LEN:
        raise ValueError(f"Password must be at least {MIN_ADMIN_PASSWORD_LEN} characters long.")
    salt = secrets.token_bytes(16)
    pw_hash = _hash_password(new_password, salt)
    with get_db_connection() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
            (pw_hash, salt.hex(), user_id),
        )
        conn.commit()
    revoke_user_sessions(user_id)
    if persist_env:
        update_env_admin_password(new_password)


def init_users_db(rotate_admin: bool = False) -> None:
    """Initialize users and user_api_keys tables.
    
    If rotate_admin is True (server startup), generates a fresh secure random
    administrator password (unless MANTIS_ADMIN_PASSWORD is set in env),
    updates the admin account in the database, and prints it clearly to stdout.
    If rotate_admin is False (module import), only ensures tables and default
    accounts exist without rotating existing passwords.
    """
    admin_id = None
    admin_username = None

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
        # Session revocation: logout kills one token; a password change kills every
        # token issued before it. Without this, a signed token stayed valid for its
        # full 7-day lifetime after logout or after the password was reset.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS revoked_sessions (
                token_sig TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_revoked_sessions_exp ON revoked_sessions(expires_at);
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS session_revocations (
                user_id TEXT PRIMARY KEY,
                revoked_before INTEGER NOT NULL
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

        # Ensure default workstation user exists for local workstation mode
        conn.execute("""
            INSERT OR IGNORE INTO users (id, username, password_hash, salt, role, is_active, created_at)
            VALUES ('workstation_user', 'local_analyst', '', '', 'admin', 1, ?)
        """, (int(time.time()),))
        conn.commit()

        # Check if an admin user already exists
        row = conn.execute(
            "SELECT id, username FROM users WHERE role = 'admin' AND id != 'workstation_user' LIMIT 1"
        ).fetchone()
        if row:
            admin_id = row["id"]
            admin_username = row["username"]

    default_user = admin_username or os.environ.get("MANTIS_ADMIN_USER", "admin").strip() or "admin"
    explicit_pw = os.environ.get("MANTIS_ADMIN_PASSWORD", "").strip()

    if explicit_pw and len(explicit_pw) < MIN_ADMIN_PASSWORD_LEN:
        raise ValueError(
            f"MANTIS_ADMIN_PASSWORD is too short. Minimum length is {MIN_ADMIN_PASSWORD_LEN} characters (got {len(explicit_pw)})."
        )

    # In workstation mode, login is not needed so skip rotating admin password & banner output
    if not deployment_config.is_server_mode():
        if not admin_id:
            create_user(username=default_user, password=explicit_pw or secrets.token_urlsafe(16), role="admin")
        return

    # If admin already exists and we are not asked to rotate on server startup, keep existing credentials
    if admin_id and not rotate_admin:
        return
    elif explicit_pw:
        # Honour MANTIS_ADMIN_PASSWORD. Previously the explicit password was validated
        # above and then discarded, so a random one silently replaced it on every start.
        admin_pass = explicit_pw
        is_random = False
    else:
        admin_pass = secrets.token_urlsafe(16)
        is_random = True

    if admin_id:
        set_user_password(admin_id, admin_pass)
    else:
        created = create_user(username=default_user, password=admin_pass, role="admin")
        admin_id = created["id"]

    border = "=" * 68
    print(f"\n{border}")
    if is_random:
        print("  MANTIS SECURITY: Administrator Password Generated for This Session")
    else:
        print("  MANTIS SECURITY: Administrator Account Initialized (from ENV)")
    print(f"{border}")
    print(f"  Username: {default_user}")
    if is_random:
        print(f"  Password: {admin_pass}")
    else:
        print("  Password: set from MANTIS_ADMIN_PASSWORD")
    print(f"  Role:     admin")
    if is_random:
        print("  Notice:   Auto-generated random session password (resets on server restart).")
        print("            To set a permanent password, change it in Settings -> Users & Team,")
        print("            or set MANTIS_ADMIN_PASSWORD in your .env / environment.")
    print(f"{border}\n", flush=True)

    logger.info("Admin user '%s' initialized (random_generated=%s)", default_user, is_random)


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


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve user record by ID."""
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT id, username, role, is_active, created_at, last_login FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        return dict(row) if row else None


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Retrieve user record by username."""
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT id, username, role, is_active, created_at, last_login FROM users WHERE username = ? COLLATE NOCASE",
            (username.strip(),),
        ).fetchone()
        return dict(row) if row else None


# --- Token Management ---

def create_session_token(user: Dict[str, Any], expires_in_seconds: int = 86400 * 7) -> str:
    """Generate a tamper-proof signed session token."""
    now = int(time.time())
    payload = {
        "sub": user["id"],
        "name": user["username"],
        "role": user["role"],
        "iat": now,
        # Unique per issuance: without it two logins in the same second produced
        # byte-identical tokens, so logging one out logged them both out.
        "jti": secrets.token_hex(8),
        "exp": now + expires_in_seconds,
    }
    payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode('ascii').rstrip('=')

    sig = hmac.new(SECRET_KEY, payload_b64.encode('ascii'), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode('ascii').rstrip('=')

    return f"{payload_b64}.{sig_b64}"


def _split_token(token: str):
    if not token or "." not in token:
        return None, None
    return token.split(".", 1)


def revoke_session(token: str) -> bool:
    """Kill a single session token (logout). Idempotent."""
    payload_b64, sig_b64 = _split_token(token)
    if not sig_b64:
        return False
    user_id, expires_at = "", int(time.time()) + 86400 * 7
    try:
        padded = payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        user_id = str(payload.get("sub", ""))
        expires_at = int(payload.get("exp", expires_at))
    except Exception:
        pass
    try:
        with get_db_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO revoked_sessions (token_sig, user_id, expires_at) VALUES (?, ?, ?)",
                (sig_b64, user_id, expires_at),
            )
            conn.execute("DELETE FROM revoked_sessions WHERE expires_at < ?", (int(time.time()),))
            conn.commit()
        return True
    except sqlite3.Error as e:
        logger.warning("Could not revoke session: %s", e)
        return False


def revoke_user_sessions(user_id: str) -> None:
    """Invalidate every token issued for a user before now (password change, role change)."""
    if not user_id:
        return
    try:
        with get_db_connection() as conn:
            conn.execute(
                "INSERT INTO session_revocations (user_id, revoked_before) VALUES (?, ?) "
                "ON CONFLICT(user_id) DO UPDATE SET revoked_before = excluded.revoked_before",
                (user_id, int(time.time())),
            )
            conn.commit()
    except sqlite3.Error as e:
        logger.warning("Could not revoke sessions for %s: %s", user_id, e)


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

        # Verify the token was not logged out and predates no password reset.
        with get_db_connection() as conn:
            try:
                if conn.execute("SELECT 1 FROM revoked_sessions WHERE token_sig = ? LIMIT 1",
                                (sig_b64,)).fetchone():
                    return None
                epoch = conn.execute("SELECT revoked_before FROM session_revocations WHERE user_id = ?",
                                     (payload["sub"],)).fetchone()
                if epoch and int(payload.get("iat", 0)) < int(epoch["revoked_before"]):
                    return None
            except sqlite3.OperationalError:
                # Older database without the revocation tables: keep working.
                pass

            # Verify user still exists and is active
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
    aesgcm = AESGCM(_encryption_keys()[0])
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, raw_key.encode("utf-8"), None)
    return base64.b64encode(ciphertext).decode("ascii"), base64.b64encode(nonce).decode("ascii")


def _decrypt_key(encrypted_b64: str, nonce_b64: str) -> str:
    """Decrypt API key using AES-GCM, trying the current key then the legacy one."""
    ciphertext = base64.b64decode(encrypted_b64)
    nonce = base64.b64decode(nonce_b64)
    last = None
    for key in _encryption_keys():
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")
        except Exception as e:  # InvalidTag: try the next candidate
            last = e
    raise last


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


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="MANTIS User & Admin Account CLI Management")
    parser.add_argument("--reset-admin", nargs="?", const="", help="Reset admin password (autogenerates if no password provided)")
    parser.add_argument("--username", default="admin", help="Admin username to reset (default: admin)")
    args = parser.parse_args()

    if args.reset_admin is not None:
        new_pw = args.reset_admin.strip()
        if not new_pw:
            new_pw = secrets.token_urlsafe(16)
        elif len(new_pw) < MIN_ADMIN_PASSWORD_LEN:
            print(f"Error: Password must be at least {MIN_ADMIN_PASSWORD_LEN} characters long.")
            sys.exit(1)

        user = get_user_by_username(args.username)
        if not user:
            print(f"Error: User '{args.username}' not found.")
            sys.exit(1)

        set_user_password(user["id"], new_pw, persist_env=True)
        print("\n" + "=" * 68)
        print("  MANTIS Administrator Password Successfully Reset")
        print("=" * 68)
        print(f"  Username: {args.username}")
        print(f"  Password: {new_pw}")
        print(f"  Persisted to: {ENV_PATH}")
        print("=" * 68 + "\n")

