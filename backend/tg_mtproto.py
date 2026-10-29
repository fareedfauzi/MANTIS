import os
import time
import json
import logging
import re
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional

logger = logging.getLogger("mantis.tg.mtproto")

router = APIRouter(prefix="/api/tg/mtproto", tags=["telegram_mtproto"])

def get_session():
    try:
        import dotenv
        dotenv.load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env"), override=False)
    except Exception:
        pass
    session_str = os.environ.get("TELEGRAM_STRING_SESSION")
    api_id = os.environ.get("TELEGRAM_API_ID")
    api_hash = os.environ.get("TELEGRAM_API_HASH")
    if not session_str or not api_id or not api_hash:
        raise HTTPException(status_code=401, detail="MTProto not configured. Please login first.")
    return session_str, int(api_id), api_hash

class GlobalSearchReq(BaseModel):
    query: str
    limit: int = 50

@router.post("/search-global")
async def search_global(req: GlobalSearchReq):
    try:
        from telethon import TelegramClient, functions, types
        from telethon.sessions import StringSession
    except ImportError:
        raise HTTPException(status_code=500, detail="telethon not installed")
        
    session_str, api_id, api_hash = get_session()
    client = TelegramClient(StringSession(session_str), api_id, api_hash)
    await client.connect()
    
    try:
        result = await client(functions.messages.SearchGlobalRequest(
            q=req.query,
            filter=types.InputMessagesFilterEmpty(),
            min_date=None,
            max_date=None,
            offset_rate=0,
            offset_peer=types.InputPeerEmpty(),
            offset_id=0,
            limit=min(req.limit, 100)
        ))
        
        messages = []
        chats_info = {chat.id: chat for chat in result.chats}
        users_info = {user.id: user for user in result.users}
        
        for msg in result.messages:
            peer_id = None
            chat_title = "Unknown"
            if getattr(msg.peer_id, 'channel_id', None):
                peer_id = msg.peer_id.channel_id
            elif getattr(msg.peer_id, 'chat_id', None):
                peer_id = msg.peer_id.chat_id
            elif getattr(msg.peer_id, 'user_id', None):
                peer_id = msg.peer_id.user_id
                
            if peer_id and peer_id in chats_info:
                chat = chats_info[peer_id]
                chat_title = getattr(chat, 'title', chat_title)
            elif peer_id and peer_id in users_info:
                user = users_info[peer_id]
                chat_title = getattr(user, 'username', getattr(user, 'first_name', chat_title))
                
            messages.append({
                "id": msg.id,
                "date": msg.date.isoformat() if msg.date else None,
                "text": msg.message or "",
                "chat_title": chat_title,
                "chat_id": peer_id
            })
            
        return {"total": len(messages), "messages": messages}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await client.disconnect()

class ProfileReq(BaseModel):
    username: str

@router.post("/profile")
async def profile_channel(req: ProfileReq):
    try:
        from telethon import TelegramClient, functions, types
        from telethon.sessions import StringSession
    except ImportError:
        raise HTTPException(status_code=500, detail="telethon not installed")
        
    session_str, api_id, api_hash = get_session()
    client = TelegramClient(StringSession(session_str), api_id, api_hash)
    await client.connect()
    
    try:
        entity = await client.get_entity(req.username)
        full = await client(functions.channels.GetFullChannelRequest(channel=entity))
        
        profile = {
            "id": entity.id,
            "title": getattr(entity, 'title', ''),
            "username": getattr(entity, 'username', ''),
            "about": getattr(full.full_chat, 'about', ''),
            "participants_count": getattr(full.full_chat, 'participants_count', 0),
        }
        return {"profile": profile}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await client.disconnect()

@router.post("/recommendations")
async def get_recommendations(req: ProfileReq):
    try:
        from telethon import TelegramClient, functions, types
        from telethon.sessions import StringSession
    except ImportError:
        raise HTTPException(status_code=500, detail="telethon not installed")
        
    session_str, api_id, api_hash = get_session()
    client = TelegramClient(StringSession(session_str), api_id, api_hash)
    await client.connect()
    
    try:
        entity = await client.get_entity(req.username)
        result = await client(functions.channels.GetChannelRecommendationsRequest(channel=entity))
        
        recommendations = []
        for chat in result.chats:
            recommendations.append({
                "id": chat.id,
                "title": getattr(chat, 'title', ''),
                "username": getattr(chat, 'username', ''),
                "participants_count": getattr(chat, 'participants_count', 0)
            })
        return {"total": len(recommendations), "recommendations": recommendations}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        await client.disconnect()

class JoinChannelReq(BaseModel):
    channel: str

@router.post("/join-channel")
async def join_channel(req: JoinChannelReq):
    try:
        from telethon import TelegramClient, functions
        from telethon.sessions import StringSession
    except ImportError:
        raise HTTPException(status_code=500, detail="telethon not installed")

    session_str, api_id, api_hash = get_session()
    client = TelegramClient(StringSession(session_str), api_id, api_hash)
    await client.connect()

    try:
        entity = await client.get_entity(req.channel)
        updates = await client(functions.channels.JoinChannelRequest(channel=entity))
        title = getattr(entity, 'title', req.channel)
        username = getattr(entity, 'username', req.channel)
        return {"ok": True, "title": title, "username": username, "id": entity.id}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to join channel: {e}")
    finally:
        await client.disconnect()

class SyncHistoryReq(BaseModel):
    channel_id: str
    channel_username: str
    limit: int = 50

@router.post("/sync-history")
async def sync_channel_history(req: SyncHistoryReq):
    try:
        from telethon import TelegramClient, functions
        from telethon.sessions import StringSession
        from tg_channel_monitor import (
            connect_db, extract_iocs_from_text, parse_credential_lines,
            get_target_assets, match_target_assets, process_and_cleanup_archive,
            TEMP_DOWNLOAD_DIR
        )
    except ImportError as e:
        raise HTTPException(status_code=500, detail=f"Dependencies missing: {e}")

    session_str, api_id, api_hash = get_session()
    client = TelegramClient(StringSession(session_str), api_id, api_hash)
    conn = None
    connected = False

    try:
        conn = connect_db()
        channel = conn.execute(
            "SELECT * FROM tg_monitored_channels WHERE id = ?", (req.channel_id,)
        ).fetchone()
        if not channel:
            raise HTTPException(status_code=404, detail="Monitored channel not found")
        channel_username = channel["username"]
        await client.connect()
        connected = True
        entity = await client.get_entity(channel_username)
        history = await client(functions.messages.GetHistoryRequest(
            peer=entity,
            offset_id=0,
            offset_date=None,
            add_offset=0,
            limit=max(1, min(req.limit, 100)),
            max_id=0,
            min_id=0,
            hash=0
        ))

        targets = get_target_assets(conn=conn)
        saved_count = 0
        new_exposures = 0

        for msg in history.messages:
            if not getattr(msg, 'message', None) and not getattr(msg, 'media', None):
                continue

            text = msg.message or ""
            date_str = msg.date.isoformat() if getattr(msg, 'date', None) else time.strftime("%Y-%m-%dT%H:%M:%S")
            iocs = extract_iocs_from_text(text)

            has_media = 1 if getattr(msg, 'media', None) else 0
            media_type = type(msg.media).__name__ if has_media else ""
            file_name = ""
            file_size = 0

            # File download and processing with STRICT INSTANT CLEANUP
            if channel["auto_download_files"] and getattr(msg, 'file', None) and msg.file.name:
                file_name = os.path.basename(str(msg.file.name)).strip()
                file_name = re.sub(r"[^A-Za-z0-9._-]", "_", file_name)[:180]
                file_size = msg.file.size or 0
                max_file_bytes = max(1, int(channel["file_max_mb"] or 50)) * 1024 * 1024
                if file_name.lower().endswith((".txt", ".zip", ".log", ".json", ".csv")) and file_size <= max_file_bytes:
                    os.makedirs(TEMP_DOWNLOAD_DIR, exist_ok=True)
                    tmp_file_path = os.path.join(TEMP_DOWNLOAD_DIR, f"tg_{msg.id}_{file_name}")
                    try:
                        await client.download_media(msg, file=tmp_file_path)
                        # Process and IMMEDIATELY delete original & temp unpacked files
                        res = process_and_cleanup_archive(tmp_file_path)
                        for exp in res.get("exposures", []):
                            matched = match_target_assets(exp["domain"], exp["username"], targets)
                            cursor = conn.execute(
                                "INSERT OR IGNORE INTO tg_stealer_exposures (message_id, channel_id, domain, url, username, password_masked, password_hash, stealer_family, matched_asset, observed_at)"
                                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                (msg.id, req.channel_id, exp["domain"], exp["url"], exp["username"], exp["password_masked"], exp["password_hash"], exp["stealer_family"], matched, date_str)
                            )
                            new_exposures += max(0, cursor.rowcount)
                        for k, v in res.get("iocs", {}).items():
                            if k in iocs:
                                iocs[k] = list(set(iocs[k] + v))[:50]
                    except Exception as err:
                        logger.error(f"Failed download/process for {file_name}: {err}")
                    finally:
                        if os.path.exists(tmp_file_path):
                            try:
                                os.unlink(tmp_file_path)
                            except Exception:
                                pass

            # Direct text credential parse
            direct_exps = parse_credential_lines(text)
            for exp in direct_exps:
                matched = match_target_assets(exp["domain"], exp["username"], targets)
                cursor = conn.execute(
                    "INSERT OR IGNORE INTO tg_stealer_exposures (message_id, channel_id, domain, url, username, password_masked, password_hash, stealer_family, matched_asset, observed_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (msg.id, req.channel_id, exp["domain"], exp["url"], exp["username"], exp["password_masked"], exp["password_hash"], exp["stealer_family"], matched, date_str)
                )
                new_exposures += max(0, cursor.rowcount)

            conn.execute(
                "INSERT INTO tg_channel_messages (channel_id, message_id, timestamp, sender, text, has_media, media_type, file_name, file_size, extracted_iocs)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(channel_id, message_id) DO UPDATE SET text=excluded.text, extracted_iocs=excluded.extracted_iocs",
                (req.channel_id, msg.id, date_str, getattr(msg, 'sender_id', ''), text, has_media, media_type, file_name, file_size, json.dumps(iocs))
            )
            saved_count += 1

        conn.execute(
            "UPDATE tg_monitored_channels SET "
            "total_messages = (SELECT COUNT(*) FROM tg_channel_messages WHERE channel_id = ?), "
            "last_message_id = COALESCE((SELECT MAX(message_id) FROM tg_channel_messages WHERE channel_id = ?), 0), "
            "telegram_id = ?, title = ?, last_fetched_at = ? WHERE id = ?",
            (req.channel_id, req.channel_id, getattr(entity, "id", None),
             getattr(entity, "title", "") or channel_username,
             time.strftime("%Y-%m-%dT%H:%M:%S"), req.channel_id),
        )
        conn.commit()

        return {"ok": True, "synced_messages": saved_count, "new_exposures": new_exposures}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Sync failed: {e}")
    finally:
        if conn is not None:
            conn.close()
        if connected:
            await client.disconnect()
