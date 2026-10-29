# -*- coding: utf-8 -*-
"""Sign in with ChatGPT support for the built-in Genesect agent.

This module implements the supported local/open-source Sign in with ChatGPT
flow: loopback OAuth callback, PKCE, local token storage, refresh, model
listing, and token handoff to the Responses API client. It intentionally does
not scrape Codex, Claude, Cursor, browser, or ChatGPT app sessions.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import secrets
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode, urlparse, parse_qs
from urllib.request import Request, urlopen
from urllib.error import HTTPError


AUTH_ENDPOINT = "https://auth.openai.com/api/accounts/authorize"
TOKEN_ENDPOINT = "https://auth.openai.com/api/accounts/oauth/token"
JWKS_ENDPOINT = "https://auth.openai.com/.well-known/jwks.json"
API_RESOURCE = "https://api.openai.com/v1"
MODELS_ENDPOINT = "https://api.openai.com/v1/models"
RESPONSES_ENDPOINT = "https://api.openai.com/v1/responses"
SCOPE = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
AGENT_NAME = "Genesect"
CALLBACK_PATH = "/auth/callback"
FIRST_TIME_CLIENT_ID = "dynamic_agent_client"


class ChatGPTSignInError(RuntimeError):
    pass


def _root_dir():
    return os.path.join(os.path.expanduser("~"), ".genesect", "chatgpt")


def _credentials_path():
    return os.path.join(_root_dir(), "account.json")


def _host_path():
    return os.path.join(_root_dir(), "host.json")


def _now_ts():
    return int(time.time())


def _utc_now():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _b64url(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decode_jwt_payload(token):
    try:
        parts = str(token).split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8"))
    except Exception:
        return {}


def _validated_id_claims(token, client_id, expected_nonce=None):
    """Return (claims, signature_verified).

    PyJWT is optional because Genesect's base install intentionally stays light.
    When available, verify against OpenAI's JWKS. Otherwise perform the local
    issuer/audience/expiry/nonce checks below on the decoded payload and record
    that signature verification was not performed.
    """
    try:
        import jwt
        from jwt import PyJWKClient
        signing_key = PyJWKClient(JWKS_ENDPOINT).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience=client_id,
            issuer="https://auth.openai.com",
        )
        if expected_nonce and claims.get("nonce") and claims.get("nonce") != expected_nonce:
            raise ChatGPTSignInError("ID token nonce does not match the sign-in attempt.")
        return claims, True
    except ImportError:
        pass
    except ChatGPTSignInError:
        raise
    except Exception as exc:
        raise ChatGPTSignInError("ID token signature validation failed: %s" % exc)
    return _decode_jwt_payload(token), False


def _atomic_write_json(path, data):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as stream:
            return json.load(stream)
    except Exception:
        return {}


def get_host_id():
    data = _read_json(_host_path())
    host_id = str(data.get("ext_agent_host_id", "")).strip()
    if host_id:
        return host_id
    host_id = "urn:uuid:%s" % uuid.uuid4()
    _atomic_write_json(_host_path(), {
        "ext_agent_host_id": host_id,
        "created_at": _utc_now(),
    })
    return host_id


def credential_status():
    data = _read_json(_credentials_path())
    if not data:
        return {
            "signed_in": False,
            "path": _credentials_path(),
            "message": "Not signed in.",
        }
    expires_at = int(data.get("expires_at", 0) or 0)
    return {
        "signed_in": bool(data.get("refresh_token") or data.get("access_token")),
        "email": data.get("email", ""),
        "client_id": data.get("client_id", ""),
        "scopes": data.get("scopes", []),
        "expires_at": expires_at,
        "expired": expires_at <= _now_ts() + 60,
        "path": _credentials_path(),
    }


def sign_out():
    path = _credentials_path()
    try:
        os.remove(path)
        return True
    except FileNotFoundError:
        return True
    except Exception as exc:
        raise ChatGPTSignInError("Could not remove ChatGPT credentials: %s" % exc)


def _post_form(url, fields):
    body = urlencode(fields).encode("utf-8")
    request = Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise ChatGPTSignInError("OAuth token endpoint failed HTTP %s: %s" % (exc.code, detail))


class _CallbackHandler(BaseHTTPRequestHandler):
    server_version = "GenesectChatGPTOAuth/1.0"

    def log_message(self, _fmt, *_args):
        return

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != CALLBACK_PATH:
            self.send_response(404)
            self.end_headers()
            return
        self.server.callback_query = parse_qs(parsed.query)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(
            b"<html><body><h3>Genesect ChatGPT sign-in complete.</h3>"
            b"<p>You can return to IDA.</p></body></html>"
        )


def _wait_for_callback(server, timeout_seconds):
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        server.handle_request()
        query = getattr(server, "callback_query", None)
        if query is not None:
            return query
    raise ChatGPTSignInError("Timed out waiting for ChatGPT sign-in callback.")


def sign_in_interactive(timeout_seconds=300):
    """Run browser-based Sign in with ChatGPT and save one local account."""
    host_id = get_host_id()
    existing = _read_json(_credentials_path())
    previous_client_id = str(existing.get("client_id", "")).strip()
    client_id_for_auth = previous_client_id or FIRST_TIME_CLIENT_ID

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = _b64url(secrets.token_bytes(48))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())

    server = ThreadingHTTPServer(("127.0.0.1", 0), _CallbackHandler)
    server.timeout = 1.0
    redirect_uri = "http://127.0.0.1:%d%s" % (int(server.server_address[1]), CALLBACK_PATH)

    params = {
        "client_id": client_id_for_auth,
        "ext_agent_host_id": host_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": SCOPE,
        "resource": API_RESOURCE,
        "state": state,
        "nonce": nonce,
        "code_challenge_method": "S256",
        "code_challenge": challenge,
    }
    if client_id_for_auth == FIRST_TIME_CLIENT_ID:
        params["agent_name_hint"] = AGENT_NAME
    else:
        if existing.get("id_token"):
            params["id_token_hint"] = existing.get("id_token")
        if existing.get("email"):
            params["login_hint"] = existing.get("email")

    auth_url = AUTH_ENDPOINT + "?" + urlencode(params)
    thread = threading.Thread(target=webbrowser.open, args=(auth_url,), daemon=True)
    thread.start()

    try:
        query = _wait_for_callback(server, timeout_seconds)
    finally:
        server.server_close()

    returned_state = (query.get("state") or [""])[0]
    if returned_state != state:
        raise ChatGPTSignInError("OAuth state validation failed.")
    if query.get("error"):
        raise ChatGPTSignInError("OAuth sign-in failed: %s" % (query.get("error_description") or query.get("error")))

    code = (query.get("code") or [""])[0]
    if not code:
        raise ChatGPTSignInError("OAuth callback did not include an authorization code.")

    issued_client_id = (query.get("client_id") or [""])[0] or previous_client_id
    if not issued_client_id or issued_client_id == FIRST_TIME_CLIENT_ID:
        raise ChatGPTSignInError("OAuth callback did not include an issued client_id.")
    if previous_client_id and issued_client_id != previous_client_id:
        raise ChatGPTSignInError("OAuth callback returned a different client_id than the saved account.")

    token = _post_form(TOKEN_ENDPOINT, {
        "grant_type": "authorization_code",
        "client_id": issued_client_id,
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": redirect_uri,
        "resource": API_RESOURCE,
    })
    return _save_token_response(token, issued_client_id, host_id, nonce)


def _save_token_response(token, client_id, host_id, expected_nonce=None):
    id_claims, signature_verified = _validated_id_claims(token.get("id_token", ""), client_id, expected_nonce)
    if id_claims:
        if id_claims.get("iss") != "https://auth.openai.com":
            raise ChatGPTSignInError("ID token issuer is not OpenAI.")
        audience = id_claims.get("aud")
        if isinstance(audience, list):
            aud_ok = client_id in audience
        else:
            aud_ok = audience == client_id
        if not aud_ok:
            raise ChatGPTSignInError("ID token audience does not match the issued client_id.")
        if expected_nonce and id_claims.get("nonce") and id_claims.get("nonce") != expected_nonce:
            raise ChatGPTSignInError("ID token nonce does not match the sign-in attempt.")
        if int(id_claims.get("exp", 0) or 0) <= _now_ts():
            raise ChatGPTSignInError("ID token is expired.")

    scopes = str(token.get("scope", "")).split()
    if "chatgpt.tokens.use.direct" not in scopes:
        raise ChatGPTSignInError("ChatGPT plan usage scope was not granted.")

    saved_at = _now_ts()
    data = {
        "email": id_claims.get("email", ""),
        "issuer": id_claims.get("iss", "https://auth.openai.com"),
        "subject": id_claims.get("sub", ""),
        "client_id": client_id,
        "ext_agent_host_id": host_id,
        "id_token": token.get("id_token", ""),
        "access_token": token.get("access_token", ""),
        "refresh_token": token.get("refresh_token", ""),
        "token_type": token.get("token_type", "Bearer"),
        "expires_in": int(token.get("expires_in", 3600) or 3600),
        "expires_at": saved_at + int(token.get("expires_in", 3600) or 3600),
        "earliest_refresh_at": token.get("earliest_refresh_at", 0),
        "scopes": scopes,
        "saved_at": _utc_now(),
        "id_token_signature_verified": bool(signature_verified),
    }
    _atomic_write_json(_credentials_path(), data)
    return data


def refresh_credentials(force=False):
    data = _read_json(_credentials_path())
    if not data:
        raise ChatGPTSignInError("ChatGPT account is not signed in.")
    if not force and int(data.get("expires_at", 0) or 0) > _now_ts() + 180:
        return data
    refresh_token = data.get("refresh_token")
    client_id = data.get("client_id")
    if not refresh_token or not client_id:
        raise ChatGPTSignInError("Saved ChatGPT credentials cannot be refreshed; sign in again.")
    token = _post_form(TOKEN_ENDPOINT, {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
        "resource": API_RESOURCE,
    })
    if not token.get("id_token"):
        token["id_token"] = data.get("id_token", "")
    return _save_token_response(token, client_id, data.get("ext_agent_host_id") or get_host_id())


def get_access_token():
    data = refresh_credentials(force=False)
    token = data.get("access_token")
    if not token:
        raise ChatGPTSignInError("Saved ChatGPT account does not have an access token.")
    return token


def list_models():
    token = get_access_token()
    request = Request(MODELS_ENDPOINT, headers={"Authorization": "Bearer %s" % token})
    try:
        with urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise ChatGPTSignInError("Model list failed HTTP %s: %s" % (exc.code, detail))
    models = payload.get("models")
    if models is None:
        models = payload.get("data", [])
    values = []
    for item in models:
        slug = item.get("slug") or item.get("id")
        if not slug:
            continue
        if item.get("visibility") and item.get("visibility") != "list":
            continue
        values.append({
            "slug": slug,
            "display_name": item.get("display_name") or slug,
        })
    return values


def resolve_model(requested_model=""):
    """Return an account-accessible model, replacing stale saved slugs."""
    models = list_models()
    slugs = [str(item.get("slug") or "").strip() for item in models]
    slugs = [slug for slug in slugs if slug]
    if not slugs:
        raise ChatGPTSignInError("The signed-in ChatGPT account returned no available models.")
    requested = str(requested_model or "").strip()
    if requested and requested.lower() not in ("auto", "default") and requested in slugs:
        return requested, models
    return slugs[0], models


def _response_output_text(response):
    parts = []
    for item in (response or {}).get("output") or []:
        if not isinstance(item, dict):
            continue
        for content in item.get("content") or []:
            if not isinstance(content, dict):
                continue
            text = content.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "".join(parts)


def create_response(
    model,
    response_input,
    instructions="",
    max_output_tokens=None,
    timeout=180,
    on_chunk=None,
):
    """Create a required streaming Responses API request using account OAuth.

    The ``chatgpt.tokens.use.direct`` account grant accepts the Responses API
    in streaming mode.  Parse the SSE stream here so the standalone launcher
    and the IDA batch bridge share exactly the same transport behavior.
    """
    body = {
        "model": str(model),
        "input": response_input,
        "store": False,
        "stream": True,
    }
    if instructions:
        body["instructions"] = str(instructions)
    if max_output_tokens is not None:
        body["max_output_tokens"] = int(max_output_tokens)

    request = Request(
        RESPONSES_ENDPOINT,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": "Bearer %s" % get_access_token(),
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        },
    )
    parts = []
    completed = False
    try:
        with urlopen(request, timeout=timeout) as response:
            for raw_line in response:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if not data or data == "[DONE]":
                    continue
                try:
                    event = json.loads(data)
                except Exception:
                    continue
                event_type = str(event.get("type") or "")
                if event_type == "response.output_text.delta":
                    delta = str(event.get("delta") or "")
                    if delta:
                        parts.append(delta)
                        if on_chunk:
                            on_chunk(delta)
                elif event_type == "response.completed":
                    completed = True
                    if not parts:
                        text = _response_output_text(event.get("response") or {})
                        if text:
                            parts.append(text)
                            if on_chunk:
                                on_chunk(text)
                elif event_type in ("response.failed", "error"):
                    error = event.get("error") or (event.get("response") or {}).get("error") or {}
                    if isinstance(error, dict):
                        detail = error.get("message") or error.get("code") or json.dumps(error)
                    else:
                        detail = str(error)
                    raise ChatGPTSignInError("ChatGPT account response failed: %s" % detail)
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise ChatGPTSignInError(
            "Responses API failed HTTP %s: %s" % (exc.code, detail[:1000])
        )

    if not completed:
        raise ChatGPTSignInError("ChatGPT account response stream ended before completion.")
    return "".join(parts)
