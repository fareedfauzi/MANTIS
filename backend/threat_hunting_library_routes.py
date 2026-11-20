from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

import threat_hunting_library as library
import native_query_converter as engine

router = APIRouter(prefix="/api/hunting-library", tags=["hunting-library"])


class RepoRequest(BaseModel):
    repo: str = Field(max_length=240)


class ConvertRequest(BaseModel):
    query: str = Field(min_length=1, max_length=100000)
    source: str
    target: str


def _call(fn, *args):
    try:
        return fn(*args)
    except library.LibraryError as exc:
        raise HTTPException(400, str(exc)) from None


@router.get("/repos")
def repos():
    return library.repos()


@router.post("/repos")
def add_repo(req: RepoRequest):
    return {"repo": _call(library.add_repo, req.repo)}


@router.delete("/repos/{owner}/{name}")
def remove_repo(owner: str, name: str):
    _call(library.remove_repo, owner + "/" + name)
    return {"removed": True}


@router.post("/repos/{owner}/{name}/sync")
def sync_repo(owner: str, name: str):
    return _call(library.sync, owner + "/" + name)


@router.post("/sync")
def sync_all():
    return _call(library.sync_all)


@router.get("/repos/{owner}/{name}/history")
def history(owner: str, name: str):
    return _call(library.history, owner + "/" + name)


@router.get("/queries")
def queries(q: str = "", language: str = "", platform: str = "", category: str = "",
            repo: str = "", limit: int = 40, offset: int = 0):
    return library.search(q, language, platform, category, repo, limit, offset)


@router.get("/platforms")
def platforms():
    return [{"id": key, "name": spec["name"], "language": spec["language"]}
            for key, spec in engine.HUNTING_PLATFORMS.items()]


@router.post("/convert")
def convert(req: ConvertRequest):
    if req.source not in engine.HUNTING_PLATFORMS or req.target not in engine.HUNTING_PLATFORMS:
        raise HTTPException(400, "Select a supported source and target platform")
    try:
        return engine.improve_query(req.query, "convert_language", req.source,
                                    target_platform=req.target)
    except Exception as exc:
        raise HTTPException(400, str(exc)[:300]) from None
