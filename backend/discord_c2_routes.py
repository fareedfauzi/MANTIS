from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

import discord_c2_dump as dump

router = APIRouter(prefix="/api/discord-c2", tags=["discord-c2"])


class InspectRequest(BaseModel):
    token: str = Field(max_length=256)
    guild_id: str = Field(max_length=22)


class CollectRequest(InspectRequest):
    channel_ids: list[str] = Field(default_factory=list, max_length=1000)
    download_attachments: bool = True
    max_attachment_mb: int = Field(default=25, ge=1, le=100)


@router.post("/inspect")
def inspect(req: InspectRequest):
    try:
        return dump.inspect(req.token, req.guild_id)
    except dump.DiscordError as exc:
        raise HTTPException(400, str(exc)) from None


@router.post("/collect")
def collect(req: CollectRequest):
    try:
        return dump.start_collection(req.token, req.guild_id, req.channel_ids,
                                     req.download_attachments, req.max_attachment_mb)
    except dump.DiscordError as exc:
        raise HTTPException(400, str(exc)) from None


@router.get("/messages")
def messages(guild_id: str = "", channel_id: str = "", search: str = "",
             limit: int = 100, offset: int = 0, pinned: bool = False):
    try:
        return dump.messages(guild_id, channel_id, search, limit, offset, pinned)
    except dump.DiscordError as exc:
        raise HTTPException(400, str(exc)) from None


@router.get("/jobs/{job_id}")
def job(job_id: str):
    try: return dump.job_status(job_id)
    except dump.DiscordError as exc: raise HTTPException(400,str(exc)) from None


@router.post("/jobs/{job_id}/cancel")
def cancel(job_id: str):
    try: return dump.cancel_job(job_id)
    except dump.DiscordError as exc: raise HTTPException(400,str(exc)) from None


@router.get("/channels")
def channels(guild_id: str):
    try: return dump.channel_status(guild_id)
    except dump.DiscordError as exc: raise HTTPException(400,str(exc)) from None


@router.get("/names")
def names(guild_id: str, search: str = ""):
    try: return dump.names(guild_id,search)
    except dump.DiscordError as exc: raise HTTPException(400,str(exc)) from None


@router.get("/attachments/{attachment_id}")
def attachment(attachment_id: str):
    try:
        path, name = dump.attachment(attachment_id)
        return FileResponse(path,filename=name,media_type="application/octet-stream")
    except dump.DiscordError as exc: raise HTTPException(404,str(exc)) from None
