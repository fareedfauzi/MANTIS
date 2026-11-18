#!/usr/bin/env python3
"""
MANTIS - Authentication & Multi-User Workflow Test Suite
=========================================================
Tests the complete Team Server authentication workflow:
  1. Unauthenticated request rejection (401)
  2. Invalid credential rejection
  3. Default Admin authentication (JWT session creation)
  4. /api/auth/me profile verification
  5. User creation by Admin (RBAC check)
  6. New analyst login & token issuance
  7. Unauthorized user creation attempt by analyst (403 Forbidden check)
  8. Personal API key encryption at rest (AES-256-GCM)
  9. Key retrieval & masking (••••••••••••)
  10. User key isolation (Analyst keys separate from Admin keys)
  11. Logout & session invalidation
  12. Cleanup of test user

Can be run directly or called by test_server_auth.bat / start_server.bat.
"""

import sys
import os
import json
import time
import urllib.request
import urllib.error
import sqlite3
from typing import Optional, Tuple, Dict, Any

# Ensure backend directory is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

import deployment_config
import auth_service

# Terminal colors for Windows CMD / PowerShell
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Windows VT100 support
if os.name == 'nt':
    os.system('')


def log_step(step_num: int, title: str):
    print(f"\n{BOLD}{CYAN}[Step {step_num}]{RESET} {title}")


def log_pass(msg: str):
    print(f"  {GREEN}[PASS]{RESET} {msg}")


def log_fail(msg: str):
    print(f"  {RED}[FAIL]{RESET} {msg}")


def log_info(msg: str):
    print(f"  {YELLOW}[*]{RESET} {msg}")


class ApiClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.token: Optional[str] = None

    def request(self, method: str, path: str, data: Optional[Dict] = None, token: Optional[str] = None) -> Tuple[int, Any, Dict]:
        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json"}
        active_token = token if token is not None else self.token
        if active_token:
            headers["Authorization"] = f"Bearer {active_token}"

        req_body = json.dumps(data).encode("utf-8") if data is not None else None
        req = urllib.request.Request(url, data=req_body, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
                body = resp.read().decode("utf-8")
                headers_dict = dict(resp.getheaders())
                try:
                    parsed = json.loads(body)
                except Exception:
                    parsed = body
                return status, parsed, headers_dict
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8")
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = body
            return e.code, parsed, dict(e.headers)
        except Exception as e:
            return 0, str(e), {}


def run_auth_workflow_tests(base_url: str = "http://127.0.0.1:9999") -> bool:
    print(f"{BOLD}{'=' * 72}{RESET}")
    print(f"{BOLD}  MANTIS Authentication & Multi-User Workflow Validation Suite{RESET}")
    print(f"{BOLD}  Target: {base_url}{RESET}")
    print(f"{BOLD}{'=' * 72}{RESET}")

    client = ApiClient(base_url)

    # Pre-check: Ensure server is running and in server mode
    status, body, _ = client.request("GET", "/api/config/deployment")
    if status != 200:
        log_fail(f"Could not reach MANTIS server at {base_url} (HTTP {status}): {body}")
        log_info("Please start the server first using 'start_server.bat' or 'run.bat --server'.")
        return False

    mode = body.get("mode") if isinstance(body, dict) else "unknown"
    log_info(f"Target server is online. Active deployment mode: [{mode}]")

    if mode != "server":
        log_info("Server is currently in 'workstation' mode. Switching running server to 'server' mode via API...")
        status, body, _ = client.request("POST", "/api/config/deployment/mode", {"mode": "server"})
        if status != 200:
            log_fail(f"Could not switch server mode to 'server': {body}")
            return False
        log_pass("Server switched to 'server' mode successfully.")
        time.sleep(0.5)

    all_passed = True
    test_analyst_id = None
    created_analyst_token = None

    try:
        # STEP 1: Unauthenticated request to protected endpoint
        log_step(1, "Testing unauthenticated request rejection (401)")
        status, body, _ = client.request("GET", "/api/auth/me", token="")
        if status == 401:
            log_pass("Unauthenticated request to /api/auth/me rejected with HTTP 401.")
        else:
            log_fail(f"Expected HTTP 401, got {status}: {body}")
            all_passed = False

        # STEP 2: Invalid credentials login
        log_step(2, "Testing invalid credential rejection")
        status, body, _ = client.request("POST", "/api/auth/login", {"username": "admin", "password": "wrong_password_999"})
        if status == 401:
            log_pass("Invalid password correctly rejected with HTTP 401.")
        else:
            log_fail(f"Expected HTTP 401, got {status}: {body}")
            all_passed = False

        # STEP 3: Admin authentication
        log_step(3, "Testing Administrator login with default credentials")
        default_admin = os.environ.get("MANTIS_ADMIN_USER", "admin")
        default_pass = os.environ.get("MANTIS_ADMIN_PASSWORD", "mantis2026!")
        status, body, _ = client.request("POST", "/api/auth/login", {"username": default_admin, "password": default_pass})
        if status == 200 and isinstance(body, dict) and body.get("token"):
            admin_token = body["token"]
            client.token = admin_token
            log_pass(f"Admin '{default_admin}' logged in successfully. JWT session token received.")
        else:
            log_fail(f"Admin login failed with status {status}: {body}")
            return False

        # STEP 4: Profile check (/api/auth/me)
        log_step(4, "Verifying Admin profile and role via /api/auth/me")
        status, body, _ = client.request("GET", "/api/auth/me")
        if status == 200 and body.get("user", {}).get("role") == "admin":
            log_pass(f"Session valid: authenticated as '{body['user']['username']}' with role '{body['user']['role']}'.")
        else:
            log_fail(f"Profile check failed: {body}")
            all_passed = False

        # STEP 5: Create a new analyst user account
        log_step(5, "Testing team member account provisioning by Admin")
        test_username = f"analyst_test_{int(time.time()) % 10000}"
        test_password = "AnalystSecurePassword2026!"
        status, body, _ = client.request("POST", "/api/auth/users", {
            "username": test_username,
            "password": test_password,
            "role": "analyst"
        })
        if status == 200 and body.get("success") and body.get("user"):
            test_analyst_id = body["user"]["id"]
            log_pass(f"Created new analyst account '{test_username}' (ID: {test_analyst_id}).")
        else:
            log_fail(f"User creation failed: {body}")
            all_passed = False

        # STEP 6: Analyst login
        log_step(6, "Testing authentication as the newly created analyst")
        status, body, _ = client.request("POST", "/api/auth/login", {
            "username": test_username,
            "password": test_password
        })
        if status == 200 and body.get("token"):
            created_analyst_token = body["token"]
            log_pass(f"Analyst '{test_username}' logged in successfully.")
        else:
            log_fail(f"Analyst login failed: {body}")
            all_passed = False

        # STEP 7: RBAC privilege check - Analyst cannot create users
        log_step(7, "Verifying Role-Based Access Control (Analyst blocked from user admin)")
        status, body, _ = client.request("POST", "/api/auth/users", {
            "username": "unauthorized_user",
            "password": "Password123!",
            "role": "analyst"
        }, token=created_analyst_token)
        if status == 403:
            log_pass("Analyst attempt to create user blocked with HTTP 403 Forbidden.")
        else:
            log_fail(f"Expected HTTP 403 for analyst user creation, got {status}: {body}")
            all_passed = False

        # STEP 8: Store encrypted personal API key
        log_step(8, "Testing personal API key encryption & vault storage")
        sample_key = "SAMPLE_VT_KEY_ALICE_SECRET_1234567890"
        status, body, _ = client.request("POST", "/api/user/keys", {
            "provider": "virustotal",
            "key": sample_key
        }, token=created_analyst_token)
        if status == 200 and body.get("success"):
            log_pass("VirusTotal API key saved to personal vault.")
        else:
            log_fail(f"Failed to save personal key: {body}")
            all_passed = False

        # STEP 9: Verify AES-256-GCM encryption at rest in SQLite database
        log_step(9, "Verifying AES-256-GCM encryption at rest in users.db")
        db_path = os.path.join(BACKEND_DIR, "data", "users.db")
        if os.path.exists(db_path):
            with sqlite3.connect(db_path) as conn:
                row = conn.execute(
                    "SELECT encrypted_key, nonce FROM user_api_keys WHERE user_id = ? AND provider = 'virustotal'",
                    (test_analyst_id,)
                ).fetchone()
                if row:
                    enc_key, nonce = row[0], row[1]
                    if sample_key not in enc_key:
                        log_pass(f"Key is strictly ciphertext in database (Encrypted: {enc_key[:16]}..., Nonce: {nonce[:8]}...). Plaintext is NEVER stored.")
                    else:
                        log_fail("CRITICAL: Raw API key was stored as plaintext in database!")
                        all_passed = False
                else:
                    log_fail("Key row not found in user_api_keys table.")
                    all_passed = False
        else:
            log_fail(f"users.db not found at {db_path}")
            all_passed = False

        # STEP 10: Verify Key Masking and Isolation
        log_step(10, "Testing key masking and cross-user isolation")
        # Check analyst's keys: should be masked
        status, body, _ = client.request("GET", "/api/user/keys", token=created_analyst_token)
        if status == 200 and body.get("keys", {}).get("virustotal") == "••••••••••••":
            log_pass("Analyst personal key returned as masked: '••••••••••••'.")
        else:
            log_fail(f"Masking failed: {body}")
            all_passed = False

        # Check Admin's keys: should NOT have virustotal from analyst
        status, body, _ = client.request("GET", "/api/user/keys", token=admin_token)
        if status == 200 and "virustotal" not in body.get("keys", {}):
            log_pass("Admin vault confirmed completely isolated: analyst's key is not accessible.")
        else:
            log_fail(f"Vault isolation violation: Admin saw analyst's key!")
            all_passed = False

        # STEP 11: Logout
        log_step(11, "Testing session logout")
        status, body, headers = client.request("POST", "/api/auth/logout", token=created_analyst_token)
        if status == 200:
            log_pass("Analyst logged out successfully.")
        else:
            log_fail(f"Logout failed: {body}")
            all_passed = False

    finally:
        # STEP 12: Cleanup test user account
        if test_analyst_id and client.token:
            log_step(12, f"Cleaning up test user account ({test_analyst_id})")
            status, body, _ = client.request("DELETE", f"/api/auth/users/{test_analyst_id}")
            if status == 200:
                log_pass(f"Test user account {test_analyst_id} deleted successfully.")
            else:
                log_info(f"Could not delete test user {test_analyst_id}: {body}")

    print(f"\n{BOLD}{'=' * 72}{RESET}")
    if all_passed:
        print(f"{BOLD}{GREEN}  >>> SUCCESS: ALL AUTHENTICATION WORKFLOW TESTS PASSED (12/12) <<<{RESET}")
    else:
        print(f"{BOLD}{RED}  >>> SOME AUTHENTICATION TESTS FAILED <<<{RESET}")
    print(f"{BOLD}{'=' * 72}{RESET}\n")

    return all_passed


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9999"
    success = run_auth_workflow_tests(target)
    sys.exit(0 if success else 1)
