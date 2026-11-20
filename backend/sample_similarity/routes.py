"""HTTP routes for sample similarity. Mounted under /api/similarity."""
from __future__ import annotations

import os
import tempfile
from typing import List, Optional

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel

from sample_similarity import service

router = APIRouter(prefix="/api/similarity")

MAX_UPLOAD_BYTES = 256 * 1024 * 1024
MAX_FILES = 50


class FamilyIn(BaseModel):
    name: str
    description: Optional[str] = ""


class FamilyPatch(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


def _call(fn, *args):
    try:
        return fn(*args)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


async def _stage(files: List[UploadFile], tmpdir: str) -> list:
    """Write uploads to temp files. Caller deletes them once analysed."""
    staged = []
    total = 0
    for idx, f in enumerate((files or [])[:MAX_FILES]):
        name = os.path.basename(f.filename or "") or f"sample-{idx + 1}.bin"
        path = os.path.join(tmpdir, f"{idx + 1:04d}.bin")
        size = 0
        with open(path, "wb") as out:
            while True:
                chunk = await f.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                total += len(chunk)
                if size > MAX_UPLOAD_BYTES or total > MAX_UPLOAD_BYTES * MAX_FILES:
                    raise HTTPException(status_code=413, detail=f"{name} exceeds the upload limit")
                out.write(chunk)
        if size == 0:
            os.remove(path)
            continue
        staged.append((name, path))
    return staged


@router.get("/dashboard")
def dashboard():
    return service.dashboard()


@router.get("/families")
def list_families():
    return service.list_families()


@router.post("/families")
def create_family(body: FamilyIn):
    return _call(service.create_family, body.name, body.description or "")


@router.get("/families/{family_id}")
def get_family(family_id: int):
    return _call(service.get_family, family_id)


@router.put("/families/{family_id}")
def update_family(family_id: int, body: FamilyPatch):
    return _call(service.update_family, family_id, body.name, body.description)


@router.delete("/families/{family_id}")
def delete_family(family_id: int):
    return _call(service.delete_family, family_id)


@router.delete("/families/{family_id}/samples/{sample_id}")
def delete_sample(family_id: int, sample_id: int):
    return _call(service.delete_sample, family_id, sample_id)


@router.post("/families/{family_id}/samples")
async def add_samples(family_id: int, files: List[UploadFile] = File(...)):
    tmpdir = tempfile.mkdtemp(prefix="mantis-sim-")
    try:
        staged = await _stage(files, tmpdir)
    except Exception:
        _rm_tree(tmpdir)
        raise
    if not staged:
        _rm_tree(tmpdir)
        raise HTTPException(status_code=400, detail="No non-empty files were uploaded")
    try:
        return _call(service.start_ingest, family_id, staged)
    except Exception:
        _rm_tree(tmpdir)
        raise


@router.post("/compare")
async def compare(file: UploadFile = File(...)):
    tmpdir = tempfile.mkdtemp(prefix="mantis-sim-")
    staged = await _stage([file], tmpdir)
    if not staged:
        _rm_tree(tmpdir)
        raise HTTPException(status_code=400, detail="The uploaded file is empty")
    name, path = staged[0]
    return service.start_compare(name, path)


@router.get("/jobs/{job_id}")
def job(job_id: str):
    return _call(service.get_job, job_id)


@router.get("/comparisons")
def comparisons(limit: int = 50):
    return service.list_comparisons(limit)


@router.get("/comparisons/{comparison_id}")
def comparison(comparison_id: int):
    return _call(service.get_comparison, comparison_id)


def _rm_tree(path: str) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)
