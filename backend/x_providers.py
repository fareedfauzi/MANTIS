"""Pluggable timeline providers for X Monitor.

Three providers return the same shape as intel_query.query_twitter_user_tweets():
    {"tweets": [canonical tweet dicts], "pagination": {...}, "diagnostics": {...}}
or {"error": "..."}. Every provider maps its raw response to the TwitterAPI.io
item shape and then runs the shared intel_query normalizer, so downstream
storage, dedupe and classification are identical for all three.

  twitterapi  - TwitterAPI.io (paid, per-user key). Delegates to intel_query.
  x_official  - Official X API v2 (bearer token). GET /2/users/by/username, /2/users/{id}/tweets.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from intel_query import (
    extract_twitter_iocs,
    normalize_twitter_tweet,
    query_twitter_user_tweets,
)

logger = logging.getLogger("mantis.x_providers")

PROVIDERS = ("twitterapi", "x_official")
DEFAULT_PROVIDER = "twitterapi"
PROVIDER_LABELS = {
    "twitterapi": "TwitterAPI.io",
    "x_official": "Official X API v2",
}

X_API_BASE = "https://api.x.com/2"
_X_TIMEOUT = (10, 30)
_X_USER_IDS: Dict[str, str] = {}
_X_USER_IDS_LOCK = threading.Lock()

_TWEET_FIELDS = "created_at,entities,public_metrics,referenced_tweets,conversation_id,in_reply_to_user_id,lang,attachments,author_id"
_MEDIA_FIELDS = "type,url,preview_image_url,width,height"
_USER_FIELDS = "name,username,profile_image_url"


def normalize_provider(value: Any) -> str:
    name = str(value or "").strip().lower() or DEFAULT_PROVIDER
    return name if name in PROVIDERS else ""


def provider_requires_key(provider: str) -> bool:
    return provider in ("twitterapi", "x_official")


def _screen_name(username: str) -> str:
    name = (username or "").strip().lstrip("@")
    return name if re.match(r"^[A-Za-z0-9_]{1,15}$", name) else ""


def _iso_from_twitter(value: str) -> str:
    try:
        return datetime.strptime(value, "%a %b %d %H:%M:%S %z %Y").astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return value or ""


def _canonical(item: Dict[str, Any]) -> Dict[str, Any]:
    """Run the shared intel_query normalizer, as query_twitter_user_tweets does."""
    tweet = normalize_twitter_tweet(item)
    if tweet.get("id"):
        tweet["iocs"] = extract_twitter_iocs(tweet)
    return tweet


def _page(tweets: List[Dict[str, Any]], provider_items: int, cursor: str = "",
          has_next: bool = False, provider: str = "") -> Dict[str, Any]:
    return {
        "source": "Twitter/X",
        "provider": provider,
        "tweets": tweets,
        "pagination": {"has_next_page": bool(has_next and cursor), "next_cursor": cursor or ""},
        "diagnostics": {
            "provider": provider,
            "provider_tweets": provider_items,
            "normalized_tweets": len(tweets),
            "cursor_present": bool(cursor),
            "has_next_page": bool(has_next and cursor),
            "response_keys": [],
        },
        "relationships": {},
    }


# ---------------------------------------------------------------- official X API v2

def _x_error(resp: requests.Response) -> str:
    code = resp.status_code
    if code == 401:
        return "X API rejected the bearer token (401). Check the Official X API key in Settings."
    if code == 403:
        return "X API denied this request (403). Your X API plan may not include user timelines."
    if code == 404:
        return "X user not found (404)."
    if code == 429:
        return "X API rate limit reached (429). Retry later."
    return f"X API returned HTTP {code}."


def _x_get(path: str, bearer: str, params: Dict[str, Any]) -> Any:
    try:
        resp = requests.get(f"{X_API_BASE}{path}", headers={"Authorization": f"Bearer {bearer}"},
                            params=params, timeout=_X_TIMEOUT)
    except requests.Timeout:
        return {"error": "X API timeout"}
    except requests.RequestException:
        return {"error": "X API request failed"}
    if resp.status_code != 200:
        return {"error": _x_error(resp)}
    try:
        return resp.json()
    except ValueError:
        return {"error": "X API returned a malformed response"}


def _x_user_id(name: str, bearer: str) -> Any:
    key = name.lower()
    with _X_USER_IDS_LOCK:
        cached = _X_USER_IDS.get(key)
    if cached:
        return cached
    data = _x_get(f"/users/by/username/{name}", bearer, {"user.fields": "name,username,profile_image_url"})
    if isinstance(data, dict) and data.get("error"):
        return data
    user = data.get("data") if isinstance(data, dict) else None
    if not isinstance(user, dict) or not user.get("id"):
        return {"error": "X user not found (404)."}
    with _X_USER_IDS_LOCK:
        _X_USER_IDS[key] = str(user["id"])
    return str(user["id"])


def _x_media(includes: Dict[str, Any], keys: List[str]) -> List[Dict[str, Any]]:
    by_key = {m.get("media_key"): m for m in includes.get("media", []) if isinstance(m, dict)}
    out = []
    for key in keys or []:
        m = by_key.get(key)
        if not m:
            continue
        out.append({"type": m.get("type") or "photo", "url": m.get("url") or m.get("preview_image_url") or "",
                    "preview_image_url": m.get("preview_image_url") or "", "width": m.get("width") or 0,
                    "height": m.get("height") or 0})
    return out


def _x_item(tweet: Dict[str, Any], name: str, author: Dict[str, Any], includes: Dict[str, Any]) -> Dict[str, Any]:
    metrics = tweet.get("public_metrics") or {}
    entities = tweet.get("entities") or {}
    refs = {r.get("type"): r.get("id") for r in tweet.get("referenced_tweets") or [] if isinstance(r, dict)}
    item: Dict[str, Any] = {
        "id": str(tweet.get("id") or ""),
        "url": f"https://x.com/{name}/status/{tweet.get('id')}",
        "text": tweet.get("text") or "",
        "createdAt": tweet.get("created_at") or "",
        "lang": tweet.get("lang") or "",
        "author": {"userName": author.get("username") or name, "name": author.get("name") or "",
                   "profilePicture": author.get("profile_image_url") or "", "id": str(author.get("id") or "")},
        "replyCount": metrics.get("reply_count", 0),
        "retweetCount": metrics.get("retweet_count", 0),
        "quoteCount": metrics.get("quote_count", 0),
        "likeCount": metrics.get("like_count", 0),
        "bookmarkCount": metrics.get("bookmark_count", 0),
        "viewCount": metrics.get("impression_count", 0),
        "conversationId": tweet.get("conversation_id") or "",
        "inReplyToUsername": "",
        "entities": {
            "urls": [{"expanded_url": u.get("expanded_url") or u.get("url") or ""} for u in entities.get("urls", []) if isinstance(u, dict)],
            "hashtags": [{"text": h.get("tag") or ""} for h in entities.get("hashtags", []) if isinstance(h, dict)],
            "user_mentions": [{"screen_name": m.get("username") or "", "name": "", "id_str": str(m.get("id") or "")}
                              for m in entities.get("mentions", []) if isinstance(m, dict)],
        },
        "extendedEntities": {"media": _x_media(includes, (tweet.get("attachments") or {}).get("media_keys") or [])},
    }
    if tweet.get("in_reply_to_user_id"):
        item["inReplyToId"] = ""
    if "retweeted" in refs:
        item["retweeted_tweet"] = {"id": str(refs["retweeted"])}
    if "quoted" in refs:
        item["quoted_tweet"] = {"id": str(refs["quoted"])}
    return item


def _x_official_page(username: str, bearer: str, cursor: str, max_results: int) -> Dict[str, Any]:
    name = _screen_name(username)
    if not name:
        return {"error": "Invalid X username (1-15 letters/numbers/underscore)"}
    if not bearer:
        return {"error": "No Official X API bearer token provided"}
    user_id = _x_user_id(name, bearer)
    if isinstance(user_id, dict):
        return user_id
    params: Dict[str, Any] = {
        "max_results": max(5, min(int(max_results or 50), 100)),
        "exclude": "replies",
        "tweet.fields": _TWEET_FIELDS,
        "expansions": "attachments.media_keys,author_id",
        "media.fields": _MEDIA_FIELDS,
        "user.fields": _USER_FIELDS,
    }
    if cursor:
        params["pagination_token"] = cursor[:500]
    data = _x_get(f"/users/{user_id}/tweets", bearer, params)
    if isinstance(data, dict) and data.get("error"):
        return data
    raw_items = [t for t in (data.get("data") or []) if isinstance(t, dict)]
    includes = data.get("includes") or {}
    users = {str(u.get("id")): u for u in includes.get("users", []) if isinstance(u, dict)}
    author = users.get(user_id) or {"username": name}
    items = [_x_item(t, name, author, includes) for t in raw_items]
    tweets = [_canonical(i) for i in items]
    tweets = [t for t in tweets if t.get("id")]
    meta = data.get("meta") or {}
    next_token = str(meta.get("next_token") or "")
    return _page(tweets, len(items), next_token, bool(next_token), provider="x_official")


# ---------------------------------------------------------------- dispatch

def fetch_timeline_page(provider: str, username: str, credential: str = "", cursor: str = "",
                        force_refresh: bool = False, max_results: int = 50) -> Dict[str, Any]:
    if provider == "twitterapi":
        data = query_twitter_user_tweets(username, credential, cursor=cursor, include_replies=False,
                                         force_refresh=force_refresh)
        if isinstance(data, dict) and "provider" not in data:
            data["provider"] = "twitterapi"
        return data
    if provider == "x_official":
        return _x_official_page(username, credential, cursor, max_results)
    return {"error": f"Unknown X collector provider: {provider}"}
