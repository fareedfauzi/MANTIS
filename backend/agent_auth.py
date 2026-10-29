import hmac
import hashlib
import os
from dataclasses import dataclass
from typing import Dict, Set

from fastapi import Header, HTTPException


def _env(*names: str) -> str:
    for name in names:
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return ""


@dataclass
class AgentIdentity:
    name: str
    token_tag: str
    permissions: Set[str]


def _configured_token() -> str:
    return _env("MANTIS_AGENT_TOKEN", "IOCINTEL_AGENT_TOKEN")


def _configured_permissions() -> Set[str]:
    raw = _env("MANTIS_AGENT_PERMISSIONS", "IOCINTEL_AGENT_PERMISSIONS") or "read_only"
    return {p.strip() for p in raw.split(",") if p.strip()}


def configured_permissions() -> Set[str]:
    return _configured_permissions()


def _dev_no_token_allowed() -> bool:
    return (_env("MANTIS_AGENT_DEV_ALLOW_NO_TOKEN", "IOCINTEL_AGENT_DEV_ALLOW_NO_TOKEN").lower() in {"1", "true", "yes"})


def require_agent(
    authorization: str = Header(default=""),
    x_mantis_agent_token: str = Header(default=""),
) -> AgentIdentity:
    expected = _configured_token()
    supplied = (x_mantis_agent_token or "").strip()
    if not supplied and authorization.lower().startswith("bearer "):
        supplied = authorization.split(" ", 1)[1].strip()

    if not expected:
        if _dev_no_token_allowed():
            return AgentIdentity(name="hermes-dev", token_tag="dev-no-token", permissions={"read_only"})
        raise HTTPException(status_code=503, detail="MANTIS_AGENT_TOKEN is required before agent tools are enabled.")

    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing MANTIS agent token.")

    token_tag = hashlib.sha256(expected.encode("utf-8", errors="ignore")).hexdigest()[:12]
    return AgentIdentity(name="hermes", token_tag=f"sha256:{token_tag}", permissions=_configured_permissions())


def local_agent_identity(name: str = "hermes-mcp") -> AgentIdentity:
    expected = _configured_token()
    if not expected:
        if _dev_no_token_allowed():
            return AgentIdentity(name=f"{name}-dev", token_tag="dev-no-token", permissions={"read_only"})
        raise RuntimeError("MANTIS_AGENT_TOKEN is required before local MCP agent tools are enabled.")
    token_tag = hashlib.sha256(expected.encode("utf-8", errors="ignore")).hexdigest()[:12]
    return AgentIdentity(name=name, token_tag=f"sha256:{token_tag}", permissions=_configured_permissions())


def require_permission(identity: AgentIdentity, permission: str) -> None:
    if permission not in identity.permissions and "admin" not in identity.permissions:
        raise HTTPException(status_code=403, detail=f"Agent token lacks required permission: {permission}")
