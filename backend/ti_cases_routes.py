"""Authenticated API for the shared TI case manager."""
import csv
import io
import re
from typing import Any, Callable, Dict
from urllib.parse import urlsplit

import requests
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field

import auth_service
import malware_db
import ti_cases as store


class CaseIn(BaseModel):
    name: str
    description: str = ""
    status: str = "Open"
    notes: str = ""
    tags: list[str] = Field(default_factory=list)
    ttps: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class IOCIn(BaseModel):
    value: str
    type: str = "auto"
    description: str = ""
    assessment: str = "Unknown"
    confidence: str = "Low"
    first_seen: str | None = None
    last_seen: str | None = None
    tags: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class LinkIn(BaseModel):
    ioc_id: int | None = None
    value: str | None = None
    type: str = "auto"
    note: str = ""
    references: list[str] = Field(default_factory=list)


class RelationIn(BaseModel):
    related_id: int
    reason: str = ""


class MWDBConfig(BaseModel):
    url: str
    api_key: str = ""


def validate_mwdb_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        local_http = parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1", "::1")
        if (not (parsed.scheme == "https" or local_http) or not parsed.hostname or
                parsed.username or parsed.password or parsed.path not in ("", "/") or
                parsed.query or parsed.fragment or parsed.port == 0):
            raise ValueError()
    except ValueError as exc:
        raise HTTPException(400, "Use an HTTPS MWDB origin (HTTP is allowed only for localhost)") from exc
    return url.rstrip("/")


def build_router(get_user: Callable, require_admin: Callable) -> APIRouter:
    router = APIRouter(prefix="/api/ti", tags=["TI Case Manager"])

    def guard(fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except KeyError as exc:
            raise HTTPException(404, str(exc).strip("'")) from exc
        except (ValueError, OverflowError) as exc:
            raise HTTPException(400, str(exc)) from exc
        except __import__("sqlite3").IntegrityError as exc:
            raise HTTPException(409, "Another IOC already has this normalized value and type") from exc

    @router.get("/cases")
    def cases(q: str = "", status: str = "", tag: str = "", limit: int = Query(50, ge=1, le=100),
              offset: int = Query(0, ge=0), user: Dict = Depends(get_user)):
        return store.list_cases(q, status, tag, limit, offset)

    @router.post("/cases", status_code=201)
    def create_case(body: CaseIn, user: Dict = Depends(get_user)):
        return guard(store.save_case, body.model_dump(), user["username"])

    @router.get("/cases/{case_id}")
    def get_case(case_id: int, user: Dict = Depends(get_user)):
        return guard(store.case_detail, case_id)

    @router.put("/cases/{case_id}")
    def update_case(case_id: int, body: CaseIn, user: Dict = Depends(get_user)):
        return guard(store.save_case, body.model_dump(), user["username"], case_id)

    @router.delete("/cases/{case_id}")
    def delete_case(case_id: int, admin: Dict = Depends(require_admin)):
        guard(store.delete_case, case_id, admin["username"])
        return {"ok": True}

    @router.get("/iocs")
    def iocs(q: str = "", type: str = "", assessment: str = "", tag: str = "",
             limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0),
             user: Dict = Depends(get_user)):
        return store.list_iocs(q, type, assessment, tag, limit, offset)

    @router.get("/iocs/lookup")
    def lookup(value: str, type: str = "auto", user: Dict = Depends(get_user)):
        return {"match": store.lookup(value, type)}

    @router.post("/iocs", status_code=201)
    def create_ioc(body: IOCIn, user: Dict = Depends(get_user)):
        return guard(store.save_ioc, body.model_dump(), user["username"])

    @router.get("/iocs/{ioc_id}")
    def get_ioc(ioc_id: int, user: Dict = Depends(get_user)):
        return guard(store.ioc_detail, ioc_id)

    @router.put("/iocs/{ioc_id}")
    def update_ioc(ioc_id: int, body: IOCIn, user: Dict = Depends(get_user)):
        return guard(store.save_ioc, body.model_dump(), user["username"], ioc_id)

    @router.delete("/iocs/{ioc_id}")
    def delete_ioc(ioc_id: int, admin: Dict = Depends(require_admin)):
        with store.connect() as db:
            if not db.execute("SELECT 1 FROM iocs WHERE id=?", (ioc_id,)).fetchone():
                raise HTTPException(404, "IOC not found")
            db.execute("DELETE FROM iocs WHERE id=?", (ioc_id,))
        return {"ok": True}

    @router.post("/iocs/import")
    async def import_iocs(text: str = Form(""), file: UploadFile | None = File(None),
                          case_id: int | None = Form(None), user: Dict = Depends(get_user)):
        if file:
            raw = await file.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise HTTPException(413, "Import exceeds 2 MB")
            if not file.filename.lower().endswith((".txt", ".csv")):
                raise HTTPException(400, "Only TXT and CSV are supported")
            text += "\n" + raw.decode("utf-8-sig", errors="replace")
        if case_id:
            guard(store.case_detail, case_id)
        values = []
        for line in text.splitlines():
            if not line.strip():
                continue
            if "," in line:
                columns = next(csv.reader([line]))
                value = columns[0].strip()
                if value.lower() in ("ioc", "indicator", "value"):
                    continue
                values.append(value)
            else:
                values.append(line.strip())
        if len(values) > 5000:
            raise HTTPException(413, "Maximum 5000 indicators per import")
        created, rejected = [], []
        for value in values:
            try:
                ioc = store.save_ioc({"value": value}, user["username"])
                if case_id:
                    store.link_ioc(case_id, ioc["id"], user["username"])
                created.append(ioc["id"])
            except ValueError:
                rejected.append(value[:120])
        return {"imported": len(set(created)), "rejected": rejected[:100]}

    @router.post("/cases/{case_id}/iocs")
    def add_case_ioc(case_id: int, body: LinkIn, user: Dict = Depends(get_user)):
        guard(store.case_detail, case_id)
        if body.ioc_id:
            ioc = guard(store.ioc_detail, body.ioc_id)
        elif body.value:
            ioc = guard(store.save_ioc, {"value": body.value, "type": body.type,
                                         "references": body.references}, user["username"])
        else:
            raise HTTPException(400, "IOC ID or value required")
        guard(store.link_ioc, case_id, ioc["id"], user["username"], body.note)
        return store.ioc_detail(ioc["id"])

    @router.delete("/cases/{case_id}/iocs/{ioc_id}")
    def remove_case_ioc(case_id: int, ioc_id: int, user: Dict = Depends(get_user)):
        guard(store.unlink_ioc, case_id, ioc_id, user["username"])
        return {"ok": True}

    @router.post("/cases/{case_id}/relations")
    def add_relation(case_id: int, body: RelationIn, user: Dict = Depends(get_user)):
        guard(store.relation, case_id, body.related_id, body.reason, user["username"])
        return store.case_detail(case_id)

    @router.delete("/cases/{case_id}/relations/{related_id}")
    def remove_relation(case_id: int, related_id: int, user: Dict = Depends(get_user)):
        guard(store.relation, case_id, related_id, "", user["username"], True)
        return {"ok": True}

    @router.post("/cases/{case_id}/samples")
    async def upload_sample(case_id: int, file: UploadFile = File(...), user: Dict = Depends(get_user)):
        guard(store.case_detail, case_id)
        if not file.filename:
            raise HTTPException(400, "File name required")
        data = await file.read(100 * 1024 * 1024 + 1)
        if not data or len(data) > 100 * 1024 * 1024:
            raise HTTPException(413, "Sample must be between 1 byte and 100 MB")
        sample = malware_db.add_sample(file_bytes=data, filename=file.filename,
                                       uploaded_by=user["username"])
        store.link_sample(case_id, sample, user["username"])
        return store.case_detail(case_id)["samples"]

    @router.post("/cases/{case_id}/samples/{sha256}")
    def link_local_sample(case_id: int, sha256: str, user: Dict = Depends(get_user)):
        sample = malware_db.get_sample(sha256)
        if not sample:
            raise HTTPException(404, "Sample not found in Malware Repository")
        guard(store.link_sample, case_id, sample, user["username"])
        return store.case_detail(case_id)["samples"]

    @router.delete("/cases/{case_id}/samples/{source}/{sha256}")
    def remove_sample(case_id: int, source: str, sha256: str, user: Dict = Depends(get_user)):
        if source not in ("local", "mwdb"):
            raise HTTPException(400, "Invalid sample source")
        guard(store.unlink_sample, case_id, sha256, source, user["username"])
        return {"ok": True}

    @router.get("/cases/{case_id}/samples/{sha256}/download")
    def download_sample(case_id: int, sha256: str, user: Dict = Depends(get_user)):
        with store.connect() as db:
            linked = db.execute("SELECT 1 FROM case_samples WHERE case_id=? AND sha256=? AND source='local'",
                                (case_id, sha256)).fetchone()
        if not linked:
            raise HTTPException(404, "Sample is not linked to this case")
        try:
            content, filename = malware_db.build_sample_zip(sha256, password="infected")
        except FileNotFoundError as exc:
            raise HTTPException(404, str(exc)) from exc
        return Response(content=content, media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{filename}"',
                                 "X-Archive-Password": "infected"})

    def mwdb_settings(user):
        keys = auth_service.get_all_user_api_keys(user["id"], mask=False)
        url = keys.get("ti_mwdb_url", "")
        token = keys.get("ti_mwdb_key", "")
        if not url or not token:
            raise HTTPException(400, "Configure MWDB URL and API key in TI Case Manager settings")
        return validate_mwdb_url(url), token

    @router.get("/mwdb/config")
    def get_mwdb_config(user: Dict = Depends(get_user)):
        keys = auth_service.get_all_user_api_keys(user["id"], mask=False)
        return {"url": keys.get("ti_mwdb_url", ""), "configured": bool(keys.get("ti_mwdb_key"))}

    @router.put("/mwdb/config")
    def set_mwdb_config(body: MWDBConfig, user: Dict = Depends(get_user)):
        if body.url:
            validate_mwdb_url(body.url)
        auth_service.save_user_api_key(user["id"], "ti_mwdb_url", body.url.rstrip("/"))
        if body.api_key:
            auth_service.save_user_api_key(user["id"], "ti_mwdb_key", body.api_key)
        return get_mwdb_config(user)

    @router.get("/mwdb/search/{sha256}")
    def search_mwdb(sha256: str, user: Dict = Depends(get_user)):
        if not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
            raise HTTPException(400, "SHA256 required")
        url, token = mwdb_settings(user)
        try:
            response = requests.get(f"{url}/api/file/{sha256.lower()}", headers={"Authorization": f"Bearer {token}"},
                                    timeout=10, allow_redirects=False)
            if response.status_code == 404:
                raise HTTPException(404, "Sample not found in MWDB")
            if 300 <= response.status_code < 400:
                raise HTTPException(502, "MWDB redirect refused")
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("Invalid MWDB response")
            return {"sha256": sha256.lower(), "metadata": data}
        except requests.RequestException as exc:
            raise HTTPException(502, f"MWDB request failed: {type(exc).__name__}") from exc

    @router.post("/cases/{case_id}/mwdb/{sha256}")
    def attach_mwdb(case_id: int, sha256: str, user: Dict = Depends(get_user)):
        guard(store.case_detail, case_id)
        found = search_mwdb(sha256, user)
        metadata = found["metadata"]
        sample = {"sha256": sha256.lower(), "filename": metadata.get("file_name") or metadata.get("name") or sha256,
                  "md5": metadata.get("md5", ""), "sha1": metadata.get("sha1", ""),
                  "size": metadata.get("file_size") or 0,
                  "metadata": {k: metadata.get(k) for k in ("file_type", "tags", "upload_time")}}
        guard(store.link_sample, case_id, sample, user["username"], "mwdb")
        return store.case_detail(case_id)["samples"]

    @router.get("/cases/{case_id}/mwdb/{sha256}/download")
    def download_mwdb(case_id: int, sha256: str, user: Dict = Depends(get_user)):
        if not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
            raise HTTPException(400, "SHA256 required")
        with store.connect() as db:
            linked = db.execute("SELECT 1 FROM case_samples WHERE case_id=? AND sha256=? AND source='mwdb'",
                                (case_id, sha256)).fetchone()
        if not linked:
            raise HTTPException(404, "Sample is not linked to this case")
        url, token = mwdb_settings(user)
        try:
            response = requests.get(f"{url}/api/file/{sha256}/download", headers={"Authorization": f"Bearer {token}"},
                                    timeout=30, allow_redirects=False, stream=True)
            if 300 <= response.status_code < 400:
                response.close()
                raise HTTPException(502, "MWDB redirect refused")
            response.raise_for_status()
            content = response.raw.read(100 * 1024 * 1024 + 1)
            response.close()
            if len(content) > 100 * 1024 * 1024:
                raise HTTPException(413, "MWDB sample exceeds 100 MB")
            return Response(content=content, media_type="application/octet-stream",
                            headers={"Content-Disposition": f'attachment; filename="{sha256}.bin"',
                                     "X-Content-Type-Options": "nosniff"})
        except requests.RequestException as exc:
            raise HTTPException(502, f"MWDB download failed: {type(exc).__name__}") from exc

    return router
