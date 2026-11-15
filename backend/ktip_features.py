"""On-demand Kaspersky TIP features shared by IOC Search and Binary Lab."""

import io
import ipaddress
import json
import hashlib
import os
import re
import threading
import time
import uuid
import zipfile
from urllib.parse import quote

import requests


BASE = "https://tip.kaspersky.com/api"
MAX_REPORT_BYTES = 24 * 1024 * 1024
_infrastructure_cache = None
_infrastructure_cache_lock = threading.Lock()


class TipError(RuntimeError):
    def __init__(self, message: str, status: int = 502):
        super().__init__(message)
        self.status = status


def request(path, key, *, method="GET", timeout=35, params=None, body=None, payload=None, binary=False,
            client_cert=None, basic_auth=None):
    if not key.strip():
        raise TipError("Configure a Kaspersky TIP API token in Settings → API Keys.", 400)
    headers = {} if basic_auth else {"Authorization": f"Bearer {key.strip()}"}
    if body is not None:
        headers["Content-Type"] = "application/octet-stream"
    try:
        with requests.request(method, BASE + path, headers=headers, params=params, data=body,
                              json=payload, timeout=timeout, stream=True, allow_redirects=False,
                              cert=client_cert, auth=basic_auth) as response:
            if response.status_code != 200:
                status = response.status_code
                if status in {401, 402, 403, 429, 451}:
                    raise TipError(f"Kaspersky TIP denied the request (HTTP {status}). Check token access and quota.", status)
                raise TipError(f"Kaspersky TIP returned HTTP {status}.", 404 if status == 404 else 502)
            data = bytearray()
            for chunk in response.iter_content(64 * 1024):
                data.extend(chunk)
                if len(data) > MAX_REPORT_BYTES:
                    raise TipError("Kaspersky response exceeds the download size limit.")
            return bytes(data) if binary else json.loads(data)
    except requests.Timeout as exc:
        raise TipError("Kaspersky TIP did not respond in time.", 504) from exc
    except (requests.RequestException, ValueError, OSError) as exc:
        raise TipError("Could not read the Kaspersky TIP response.") from exc


def quick_lookup(kind, value, key):
    return {"zonelookup": request(f"/zonelookup/{kind}/{quote(value, safe='')}", key)}


def similar_hash(value, key):
    return request(f"/hash/{quote(value, safe='')}", key,
                   params={"sections": "SimilarFiles", "count": 25}, timeout=180)


def _infrastructure_records(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for field in ("data", "results", "items", "records", "infrastructure"):
            value = payload.get(field)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                for nested in ("items", "results", "records"):
                    if isinstance(value.get(nested), list):
                        return value[nested]
        status = payload.get("status")
        if isinstance(status, dict):
            status = status.get("code") or status.get("message")
        detail = payload.get("error") or payload.get("message") or (status if status not in ("ok", "success", 200) else None)
        if detail:
            raise TipError(f"Kaspersky campaign infrastructure is unavailable ({str(detail)[:160]}).")
    raise TipError("Kaspersky returned an unrecognized campaign infrastructure format.")


def infrastructure(ip, key):
    global _infrastructure_cache
    if not key.strip():
        raise TipError("Configure a Kaspersky TIP API token in Settings → API Keys.", 400)
    identity = hashlib.sha256(key.strip().encode()).digest()
    with _infrastructure_cache_lock:
        cache = _infrastructure_cache
    if cache and cache[0] == identity and cache[1] > time.monotonic():
        records = cache[2]
    else:
        cert = os.environ.get("MANTIS_KTIP_INFRA_CERT", "").strip()
        client_key = os.environ.get("MANTIS_KTIP_INFRA_CLIENT_KEY", "").strip()
        username = os.environ.get("MANTIS_KTIP_INFRA_USERNAME", "").strip()
        password = os.environ.get("MANTIS_KTIP_INFRA_PASSWORD", "")
        payload = request("/apt_cnc/all", key, client_cert=(cert, client_key) if cert and client_key else cert or None,
                          basic_auth=(username, password) if cert and username and password else None)
        records = _infrastructure_records(payload)
        with _infrastructure_cache_lock:
            _infrastructure_cache = (identity, time.monotonic() + 300, records)
    target = ipaddress.ip_address(ip)
    matches = []
    for row in records:
        if not isinstance(row, dict):
            continue
        try:
            if ipaddress.ip_address(row.get("ip")) != target:
                continue
        except ValueError:
            continue
        matches.append({field: row[field] for field in (
            "ip", "first_seen", "last_seen", "asn", "asn_name", "country_code", "tags", "threats", "threat", "type"
        ) if field in row})
    return {"matches": matches}


def report_search(query, key, skip=0):
    result = request("/search", key, method="POST", timeout=60, payload={
        "query": query, "sources": {"reporting": {"skip": skip, "count": 25}},
    })
    reporting = result.get("reporting") if isinstance(result, dict) else None
    if isinstance(reporting, dict):
        code = (reporting.get("status") or {}).get("code")
        if code in {401, 402, 403, 429, 451}:
            raise TipError(f"Kaspersky Reporting denied access (HTTP {code}). Check subscription access and quota.", code)
    if not isinstance(reporting, dict) or not isinstance(reporting.get("items"), list):
        raise TipError("Kaspersky report results are unavailable. Check Reporting access.")
    return reporting


def _sandbox_report(task_id, key):
    sections = ",".join(("sample-and-execution-properties", "detection-names", "suspicious-activities",
                         "process-operations", "file-operations", "registry-operations", "traffic-report",
                         "mitre-matrix", "dropped-files-list", "downloaded-files-list"))
    data = request(f"/sandbox/tasks/file/{task_id}/report/data", key, params={"section": sections}, binary=True)
    reports = {}
    budget = MAX_REPORT_BYTES
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for entry in archive.infolist():
                if entry.is_dir() or not entry.filename.lower().endswith(".json") or entry.file_size > budget:
                    continue
                with archive.open(entry) as file:
                    raw = file.read(budget + 1)
                if len(raw) > budget:
                    break
                budget -= len(raw)
                try:
                    reports[entry.filename] = json.loads(raw)
                except ValueError:
                    continue
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        raise TipError("Kaspersky returned an unreadable sandbox report archive.") from exc
    if not reports:
        raise TipError("Kaspersky returned no readable sandbox report sections.")
    return reports


def related_hashes(data):
    """Collect hashes only from the explicitly requested Similarity result."""
    found = {}

    def visit(node):
        if len(found) >= 50:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if key.lower() in {"md5", "sha1", "sha256"} and isinstance(value, str):
                    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value):
                        found[value.lower()] = None
                elif isinstance(value, (dict, list)):
                    visit(value)
        elif isinstance(node, list):
            for value in node:
                visit(value)

    visit(data)
    return list(found)[:50]


def analyze_file(path, key, technology, update, *, timeout=900):
    if technology not in {"sandbox", "similarity"}:
        raise ValueError("Unsupported Kaspersky analysis technology")
    with path.open("rb") as sample:
        created = request("/threat-analysis/tasks/upload-exec-file", key, method="POST", timeout=180,
                          params={"original_file_name": path.name, "technologies": technology}, body=sample)
    try:
        task_id = str(uuid.UUID(created["id"]))
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise TipError("Kaspersky did not return a valid analysis task ID.") from exc
    update("running", "Submitted to Kaspersky TIP", {"task_id": task_id})
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = request(f"/sandbox/tasks/file/{task_id}", key)
        state = result.get("status")
        if state in {"failed", "discarded"}:
            raise TipError(f"Kaspersky analysis ended with status {state}.")
        if state in {"completed", "completed-with-error"}:
            break
        time.sleep(10)
    else:
        raise TipError("Kaspersky analysis did not finish before the polling timeout.", 504)
    if technology == "sandbox":
        return {"task_id": task_id, "status": state, "sections": _sandbox_report(task_id, key)}
    base = f"/threat-analysis/tasks/{task_id}/reports/similarity"
    found = {"original_file": request(base + "/original-file/similar-files", key, params={"skip": 0, "count": 25})}
    if (result.get("similarity") or {}).get("unpacked_file_similarity_count"):
        found["unpacked_file"] = request(base + "/unpacked-file/similar-files", key, params={"skip": 0, "count": 25})
    return {"task_id": task_id, "status": state, **found}


def download_sample(task_id, kind, md5, key):
    task_id = str(uuid.UUID(task_id))
    if kind not in {"drop_file", "transferred_file"} or not re.fullmatch(r"[a-fA-F0-9]{32}", md5):
        raise TipError("Select a dropped or transferred sample and provide its MD5.", 400)
    data = request(f"/sandbox/tasks/{task_id}/{kind}/{md5}", key, binary=True)
    if not zipfile.is_zipfile(io.BytesIO(data)):
        raise TipError("Kaspersky did not return a sample archive.")
    return data
