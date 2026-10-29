import os
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
try:
    from telethon import TelegramClient
    from telethon.sessions import StringSession
    from telethon.errors import SessionPasswordNeededError
    import dotenv
except ImportError:
    pass

router = APIRouter(prefix="/api/tg/auth", tags=["telegram_auth"])

_login_clients = {}

class AuthSendCodeReq(BaseModel):
    api_id: int
    api_hash: str
    phone: str

class AuthLoginReq(BaseModel):
    phone: str
    phone_code_hash: str
    code: str
    password: str = ""

@router.get("/status")
async def auth_status():
    env_file = os.path.join(os.getcwd(), ".env")
    try:
        import dotenv
        dotenv.load_dotenv(env_file)
    except Exception:
        pass
    session_str = os.environ.get("TELEGRAM_STRING_SESSION")
    if session_str:
        return {"authenticated": True}
    return {"authenticated": False}

@router.post("/send_code")
async def auth_send_code(req: AuthSendCodeReq):
    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession
    except ImportError:
        raise HTTPException(status_code=500, detail="telethon not installed")
        
    client = TelegramClient(StringSession(), req.api_id, req.api_hash)
    await client.connect()
    try:
        sent = await client.send_code_request(req.phone)
        _login_clients[req.phone] = {
            "client": client,
            "api_id": req.api_id,
            "api_hash": req.api_hash,
            "needs_2fa": False
        }
        return {"phone_code_hash": sent.phone_code_hash}
    except Exception as e:
        await client.disconnect()
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/login")
async def auth_login(req: AuthLoginReq):
    try:
        from telethon.errors import SessionPasswordNeededError
        import dotenv
    except ImportError:
        raise HTTPException(status_code=500, detail="telethon or python-dotenv not installed")

    if req.phone not in _login_clients:
        raise HTTPException(status_code=400, detail="Must call send_code first")
    client_data = _login_clients[req.phone]
    client = client_data["client"]
    api_id = client_data["api_id"]
    api_hash = client_data["api_hash"]
    try:
        if client_data["needs_2fa"]:
            if not req.password:
                raise HTTPException(status_code=401, detail="2fa_required — please enter your 2FA password")
            await client.sign_in(password=req.password)
        else:
            try:
                await client.sign_in(req.phone, code=req.code, phone_code_hash=req.phone_code_hash)
            except SessionPasswordNeededError:
                client_data["needs_2fa"] = True
                if not req.password:
                    raise HTTPException(status_code=401, detail="2fa_required — please enter your 2FA password")
                await client.sign_in(password=req.password)

        session_str = client.session.save()

        env_file = os.path.join(os.getcwd(), ".env")
        if not os.path.exists(env_file):
            with open(env_file, "w") as f:
                f.write("")

        dotenv.set_key(env_file, "TELEGRAM_API_ID", str(api_id))
        dotenv.set_key(env_file, "TELEGRAM_API_HASH", api_hash)
        dotenv.set_key(env_file, "TELEGRAM_PHONE", req.phone)
        dotenv.set_key(env_file, "TELEGRAM_STRING_SESSION", session_str)

        os.environ["TELEGRAM_STRING_SESSION"] = session_str

        await client.disconnect()
        del _login_clients[req.phone]
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as e:
        try:
            await client.disconnect()
        except Exception:
            pass
        _login_clients.pop(req.phone, None)
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/verify")
async def auth_verify():
    env_file = os.path.join(os.getcwd(), ".env")
    try:
        from telethon import TelegramClient
        from telethon.sessions import StringSession
        import dotenv
        dotenv.load_dotenv(env_file)
    except Exception:
        raise HTTPException(status_code=500, detail="telethon or python-dotenv not installed")
        
    session_str = os.environ.get("TELEGRAM_STRING_SESSION")
    api_id = os.environ.get("TELEGRAM_API_ID")
    api_hash = os.environ.get("TELEGRAM_API_HASH")
    if not session_str or not api_id or not api_hash:
        raise HTTPException(status_code=401, detail="No session found in environment")
        
    client = TelegramClient(StringSession(session_str), int(api_id), api_hash)
    await client.connect()
    try:
        if not await client.is_user_authorized():
            raise HTTPException(status_code=401, detail="Session is no longer authorized (logged out or revoked)")
        me = await client.get_me()
        return {"ok": True, "user_id": me.id, "username": me.username or "", "name": me.first_name or ""}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Verification failed: {e}")
    finally:
        await client.disconnect()

@router.post("/logout")
async def auth_logout():
    env_file = os.path.join(os.getcwd(), ".env")
    errs = []
    try:
        import dotenv
        if os.path.exists(env_file):
            dotenv.unset_key(env_file, "TELEGRAM_STRING_SESSION")
    except Exception as e:
        errs.append(f"Failed to edit .env: {e}")
        
    if "TELEGRAM_STRING_SESSION" in os.environ:
        try:
            del os.environ["TELEGRAM_STRING_SESSION"]
        except Exception as e:
            errs.append(f"Failed to remove from env: {e}")
            
    if errs:
        raise HTTPException(status_code=500, detail=" | ".join(errs))
        
    return {"ok": True}
