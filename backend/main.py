import json
import binary_lab as binary_lab_mod
from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
import requests
from typing import Any, Dict, List, Optional
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from misp_updater import download_misp_clusters
from yara_updater import download_yara_forge, download_elastic_yara
from rss_manager import update_feeds
import cti_collect as cti_collect_mod
import cti_catalog as cti_catalog_mod
import cti_db as cti_db_mod
import cti_query as cti_query_mod
import ai_service as ai_mod
import ai_case_service as ai_case_mod
from agent_tools.router import router as agent_tools_router
import similarity_service as similarity_mod
import tg_intel as tg_mod
import ransomware_monitor as ransomware_monitor_mod
import todays_intelligence as todays_intel_mod
import x_monitor as x_monitor_mod
import breach_watcher
import tweetfeed_service as tweetfeed_mod
import infra_hunt_service as infra_hunt_mod
import vt_hunting_service as vt_hunting_mod
from yara_repos import (
    discover_repos as yara_discover_repos,
    discover_explorer_repos as yara_discover_explorer_repos,
    ensure_all_built as yara_ensure_all_built,
    engine_status as yara_engine_status,
    search_rules as yara_search_rules,
    get_rule_source as yara_get_rule_source,
    corpus_roots as yara_corpus_roots,
)
from yara_service import (
    scan_limits as yara_scan_limits,
    scan_upload as yara_scan_upload,
    workbench_validate as yara_workbench_validate,
    workbench_save as yara_workbench_save,
    writable_repos as yara_writable_repos,
    corpus_test as yara_corpus_test,
    test_upload_sources as yara_test_upload_sources,
    test_path_sources as yara_test_path_sources,
    MAX_UPLOAD_BYTES as YARA_MAX_UPLOAD_BYTES,
    MAX_TEST_BYTES as YARA_MAX_TEST_BYTES,
    MAX_TEST_FILES as YARA_MAX_TEST_FILES,
)
from misp_galaxy import (
    MISP_GALAXY_CATEGORIES,
    GALAXY_GROUP_SCOPES,
    categories_for_scope,
    refresh_galaxy,
    search_scope,
)
import asyncio
import logging
import threading
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from pydantic import BaseModel, Field
import os
import re
import shutil
import time
import tempfile
import subprocess
from intel_query import do_domain_intel, do_ip_intel, do_hash_intel, do_keyword_intel, do_url_intel, do_infra_intel, is_ip, is_hash, is_domain, is_url, normalize_domain, normalize_ip, normalize_url, query_vt_relation, query_urlscan_downloaded_file, query_threatfox_ioc, query_otx_pulse_indicators, query_triage_overview, query_triage_summary, query_triage_static, query_triage_behavioral, get_source_metadata, query_cb_search, query_cb_ioc_search, query_cb_threats, query_cb_cves,     query_ransomlook_group_or_search, query_ransomlook_actor_or_search, query_ransomlook_posts, query_ransomlook_export, query_ha_report, query_ransomware_live_group_victims, query_ransomware_live_recent_victims, query_ransomware_live_country, query_ransomware_live_sector, query_ransomware_live_cyberattacks, query_ransomware_live_yara, query_ransomware_live_victim_detail, query_ransomware_live_iocs, query_ransomware_live_ransom_notes, query_ransomware_live_negotiations,     query_ransomware_live_stats, query_ransomware_live_sectors, query_ransomware_live_validate, query_abuseipdb_reports, query_urlscan_result, query_urlscan_hash, query_urlscan_keyword, query_urlscan_infra, query_urlscan, query_malshare_limit, query_malshare_feed, query_twitter_search, query_twitter_tweet, query_twitter_replies, query_twitter_quotes, query_twitter_thread, query_twitter_user, query_twitter_user_search, query_twitter_user_tweets, query_twitter_follower_ids, query_dnsdumpster, query_dnsdumpster_map, query_orkl, query_orkl_library_entry, query_orkl_report_sha1, query_orkl_threat_actors, query_orkl_threat_actor, query_orkl_sources, query_orkl_source, query_orkl_news, query_validin_lazy, query_validin_fingerprint, query_validin_threat, query_validin_infra
import pocindex_mod
from intel_query import (
    query_github_search, query_github_repo,
    query_github_commits, query_github_commit_detail, query_github_readme,
    query_github_issues, query_github_issue_comments, query_github_user,
    query_github_user_repos, query_github_org, query_malware_news_topic,
    query_archive_historical_urls, query_archive_timeline, query_archive_snapshot,
    query_shodan_host_history, query_shodan_search, query_shodan_domain,
    query_censys_host_timeline, query_censys_search, query_censys_aggregate,
    query_censys_certificate, query_censys_webproperty,
    query_silent_push_padns, query_silent_push_domain_search, query_silent_push_scan_data,
    query_driftnet_search, query_driftnet_user,
    query_pulsedive_indicator_properties, query_pulsedive_indicator_links,
    query_pulsedive_explore, query_pulsedive_threat, query_pulsedive_threat_links,
    query_pulsedive_feed, query_pulsedive_feed_links,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(threadName)s] %(name)s: %(message)s",
)
logger = logging.getLogger("mantis.startup")


def _mantis_env(*names: str, default: str = "") -> str:
    """Return the first set env var. MANTIS_* names take precedence; legacy
    IOCINTEL_* names are still honoured for backward compatibility."""
    for name in names:
        value = os.environ.get(name, "")
        if value is not None and str(value).strip() != "":
            return str(value)
    return default


def _timed_task(name: str, func, *args, **kwargs):
    """Run one startup task with start/finish/duration logging."""
    started = time.monotonic()
    logger.info("startup task started: %s", name)
    _startup_status[name] = {"state": "running", "started_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    try:
        result = func(*args, **kwargs)
        elapsed = time.monotonic() - started
        logger.info("startup task finished: %s in %.2fs", name, elapsed)
        _startup_status[name] = {
            "state": "done",
            "duration_s": round(elapsed, 2),
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        return result
    except Exception:
        elapsed = time.monotonic() - started
        logger.exception("startup task FAILED: %s after %.2fs", name, elapsed)
        _startup_status[name] = {
            "state": "error",
            "duration_s": round(elapsed, 2),
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        return None


_startup_status: dict = {}
_startup_executor: ThreadPoolExecutor | None = None
_similarity_progress: dict = {}
_similarity_progress_lock = threading.Lock()
_similarity_api_cache: dict = {}
_similarity_api_cache_lock = threading.Lock()
_SIMILARITY_API_CACHE_TTL = 120.0


def _similarity_cached(key: str, loader, ttl: float = _SIMILARITY_API_CACHE_TTL):
    now = time.monotonic()
    with _similarity_api_cache_lock:
        cached = _similarity_api_cache.get(key)
        if cached and now - float(cached.get("time", 0)) < ttl:
            return cached.get("data")
    data = loader()
    with _similarity_api_cache_lock:
        _similarity_api_cache[key] = {"time": time.monotonic(), "data": data}
    return data


def _similarity_clear_cache() -> None:
    with _similarity_api_cache_lock:
        _similarity_api_cache.clear()


def _similarity_progress_id(value: str) -> str:
    value = (value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,120}", value):
        return ""
    return value


def _similarity_progress_init(progress_id: str, operation: str) -> None:
    progress_id = _similarity_progress_id(progress_id)
    if not progress_id:
        return
    now = time.time()
    with _similarity_progress_lock:
        _similarity_progress[progress_id] = {
            "id": progress_id,
            "operation": operation,
            "status": "running",
            "started_at": now,
            "updated_at": now,
            "events": [],
        }


def _similarity_progress_event(progress_id: str, phase: str, message: str, status: str = "running", sample: str = "", details: dict | None = None) -> None:
    progress_id = _similarity_progress_id(progress_id)
    if not progress_id:
        return
    now = time.time()
    event = {
        "time": time.strftime("%H:%M:%S"),
        "elapsed": 0,
        "phase": str(phase or "processing")[:80],
        "message": str(message or "")[:1000],
        "status": str(status or "running")[:40],
        "sample": os.path.basename(str(sample or ""))[:260],
        "details": details or {},
    }
    with _similarity_progress_lock:
        state = _similarity_progress.setdefault(progress_id, {
            "id": progress_id,
            "operation": "similarity",
            "status": "running",
            "started_at": now,
            "updated_at": now,
            "events": [],
        })
        event["elapsed"] = round(now - float(state.get("started_at") or now), 1)
        state["updated_at"] = now
        state["status"] = "failed" if status == "failed" else state.get("status", "running")
        state["events"].append(event)
        state["events"] = state["events"][-200:]


def _similarity_progress_finish(progress_id: str, status: str, message: str = "") -> None:
    progress_id = _similarity_progress_id(progress_id)
    if not progress_id:
        return
    if message:
        _similarity_progress_event(progress_id, "complete" if status == "done" else "error", message, "done" if status == "done" else "failed")
    with _similarity_progress_lock:
        state = _similarity_progress.get(progress_id)
        if state:
            state["status"] = status
            state["updated_at"] = time.time()


def _similarity_progress_callback(progress_id: str):
    return lambda phase, message, status="running", sample="", details=None: _similarity_progress_event(progress_id, phase, message, status, sample, details)


def refresh_rss_feeds_periodically():
    try:
        interval = max(900, int(_mantis_env("MANTIS_RSS_REFRESH_SECONDS", "IOCINTEL_RSS_REFRESH_SECONDS", default="21600")))
    except ValueError:
        interval = 21600
    while True:
        try:
            _timed_task("rss-refresh", update_feeds)
        except Exception as e:
            logger.exception("RSS feed update failed: %s", e)
        time.sleep(interval)


def refresh_rep_feeds_periodically():
    """Batch 4 reputation feeds: refresh stale feeds, then hourly check.

    ET Open / Spamhaus / CINS / blocklist.de / Tor / StevenBlack refresh
    on their own intervals; refresh_due() skips fresh ones cheaply.
    """
    import feed_intel as _fi
    try:
        _timed_task("rep-feeds-refresh", _fi.refresh_due)
    except Exception as e:
        logger.exception("Reputation feed refresh failed: %s", e)
    while True:
        time.sleep(3600)
        try:
            _timed_task("rep-feeds-refresh", _fi.refresh_due)
        except Exception as e:
            logger.exception("Reputation feed refresh failed: %s", e)


def refresh_openphish_periodically():
    """OpenPhish Community feed: refresh at startup if stale, then ~12h.
    Local feed fetch only; analyst lookups never touch the network."""
    import phish_feeds as _pf
    try:
        _timed_task("openphish-refresh",
                    lambda: _pf.refresh_openphish(force=False))
    except Exception as e:
        logger.exception("OpenPhish refresh failed: %s", e)
    while True:
        time.sleep(12 * 3600)
        try:
            _timed_task("openphish-refresh",
                        lambda: _pf.refresh_openphish(force=False))
        except Exception as e:
            logger.exception("OpenPhish refresh failed: %s", e)


def refresh_cti_periodically():
    """CTI article collection loop. Registry first (idempotent), then poll
    enabled feeds on schedule. Failures never stop the loop or the app."""
    try:
        interval = max(900, int(_mantis_env("MANTIS_CTI_SYNC_INTERVAL_S",
                                            "IOCINTEL_CTI_SYNC_INTERVAL_S",
                                            default=str(3 * 3600))))
    except ValueError:
        interval = 3 * 3600
    try:
        _timed_task("cti-registry", cti_collect_mod.ensure_registry)
    except Exception as e:
        logger.exception("CTI registry build failed: %s", e)
    while True:
        try:
            _timed_task("cti-sync", cti_collect_mod.sync_feeds)
            
            try:
                import cti_db
                import tg_intel
                _timed_task("cti-prune", lambda: cti_db.prune_old_articles(90))
                _timed_task("tg-prune", lambda: tg_intel.prune_old_messages(90))
            except Exception as e:
                logger.warning("Database pruning failed: %s", e)
                
        except Exception as e:
            logger.exception("CTI article sync failed: %s", e)
        time.sleep(interval)

app = FastAPI(title="MANTIS")
import tg_mtproto
app.include_router(tg_mtproto.router)
_background_updates_started = False
_infra_monitor_stop = threading.Event()


def _infra_monitor_loop():
    try:
        interval = max(300, int(_mantis_env("MANTIS_INFRA_MONITOR_INTERVAL_S", default="900")))
    except ValueError:
        interval = 900
    while not _infra_monitor_stop.wait(interval):
        try:
            result = infra_hunt_mod.run_due_hunts()
            if result.get("due"):
                logger.info("Infrastructure monitor processed %s due hunt(s)", result["due"])
        except Exception:
            logger.exception("Infrastructure monitor cycle failed")

@app.on_event("startup")
def start_background_update_loops():
    global _background_updates_started, _startup_executor
    if _background_updates_started:
        return
    _background_updates_started = True
    t0 = time.monotonic()
    # UI-first startup: the server is already listening, but the browser (opened
    # ~2s after launch) must get the page shell, CSS/JS and first API calls in a
    # quiet process. So only fast cached jobs run now; the heavy jobs
    # (large YARA bundle download, multi-repo compile of ~16k rules, first RSS
    # crawl) start after a short delay, each still in its own thread, with YARA
    # repo prebuild opt-in because it can monopolize the process for minutes.
    try:
        heavy_delay = float(_mantis_env("MANTIS_HEAVY_STARTUP_DELAY_S",
                                        "IOCINTEL_HEAVY_STARTUP_DELAY_S", default="120"))
    except ValueError:
        heavy_delay = 120.0
    heavy_delay = max(0.0, heavy_delay)
    logger.info("MANTIS startup: UI-first mode (fast jobs now, heavy jobs in %.0fs)", heavy_delay)
    _startup_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="mantis-startup")
    _startup_executor.submit(_timed_task, "misp-clusters", download_misp_clusters)
    _startup_executor.submit(_timed_task, "pocindex-init", pocindex_mod.init_pocindex)
    for name in ("yara-forge", "yara-elastic", "yara-repos", "rss-refresh", "cti-registry", "cti-sync"):
        _startup_status[name] = {"state": "waiting", "starts_in_s": heavy_delay}
    threading.Thread(target=_delayed_heavy_startup, name="mantis-heavy-starter",
                     args=(heavy_delay,), daemon=True).start()
    if _mantis_env("MANTIS_INFRA_MONITOR_ENABLED", default="true").lower() not in {"0", "false", "no"}:
        _infra_monitor_stop.clear()
        threading.Thread(target=_infra_monitor_loop, name="mantis-infra-monitor", daemon=True).start()
    logger.info("MANTIS startup: fast tasks submitted in %.2fs (heavy tasks deferred, see per-task finish logs)", time.monotonic() - t0)


@app.on_event("shutdown")
def stop_background_update_loops():
    global _startup_executor
    _infra_monitor_stop.set()
    ex, _startup_executor = _startup_executor, None
    if ex is not None:
        ex.shutdown(wait=False, cancel_futures=True)


def _yara_startup_build():
    # Startup build is serial (one repo at a time): parallel multi-repo
    # compiles oversubscribe the CPU and starve request serving.
    # On-demand refreshes elsewhere keep full parallelism.
    return yara_ensure_all_built(max_workers=1)


def _delayed_heavy_startup(delay_s: float):
    """Sleep, then launch the heavy refresh jobs in parallel threads."""
    if delay_s > 0:
        time.sleep(delay_s)
    if _startup_executor is None:  # shutting down before the delay elapsed
        return
    logger.info("MANTIS startup: launching deferred heavy tasks in parallel threads")
    _startup_executor.submit(_timed_task, "yara-forge", download_yara_forge)
    _startup_executor.submit(_timed_task, "yara-elastic", download_elastic_yara)
    # Local YARA rule repositories are built lazily by Rule Explorer/search.
    # Prebuilding them at startup is opt-in because it can monopolize CPU for
    # minutes and make unrelated pages feel hung.
    yara_startup_build = _mantis_env("MANTIS_YARA_STARTUP_BUILD",
                                     "IOCINTEL_YARA_STARTUP_BUILD", default="0").strip().lower()
    if yara_startup_build in {"1", "true", "yes", "on"}:
        _startup_executor.submit(_timed_task, "yara-repos", _yara_startup_build)
    else:
        _startup_status["yara-repos"] = {
            "state": "skipped",
            "message": "Startup YARA prebuild disabled; Rule Explorer builds lazily when needed.",
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
    # RSS does its first refresh inside its own loop thread (also parallel),
    # then keeps refreshing on schedule — no duplicate initial refresh.
    threading.Thread(target=refresh_rss_feeds_periodically, name="mantis-rss-loop", daemon=True).start()
    # CTI articles: registry build (catalog + approved domains) then polite
    # periodic collection, all in one background thread. Collection failures
    # never affect startup or other tasks.
    threading.Thread(target=refresh_cti_periodically, name="mantis-cti-loop", daemon=True).start()
    # OpenPhish Community feed: local index refresh only (~12h).
    threading.Thread(target=refresh_openphish_periodically, name="mantis-openphish-loop", daemon=True).start()
    # Batch 4 reputation feeds: background refresh only (~hourly check).
    threading.Thread(target=refresh_rep_feeds_periodically, name="mantis-repfeeds-loop", daemon=True).start()


@app.get("/api/meta/startup-status")
def startup_status():
    """Diagnostics: per-task startup timing so slow starts are explainable."""
    return {"tasks": dict(_startup_status)}



class FeedToggleRequest(BaseModel):
    id: str
    enabled: bool

@app.get("/api/feeds/catalog")
def feeds_catalog_list():
    import feed_manager
    try:
        return {"sources": feed_manager.get_feed_list()}
    except Exception as e:
        logger.exception("Failed to get feed catalog")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/feeds/catalog/sync")
def feeds_catalog_sync():
    import feed_manager
    try:
        res = feed_manager.sync_catalog()
        if not res.get("ok"):
            raise HTTPException(status_code=500, detail=res.get("reason", "unknown error"))
        return {"sources": feed_manager.get_feed_list(), "added": res.get("added", 0)}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to sync feed catalog")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/feeds/toggle")
def feeds_catalog_toggle(req: FeedToggleRequest):
    import feed_manager
    try:
        result = feed_manager.toggle_feed(req.id, req.enabled)
        if not result.get("ok"):
            raise HTTPException(status_code=404, detail=result.get("reason", "Feed source not found"))
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to toggle feed")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/feeds/status")

def feeds_status():
    """Compact feed health for Settings (no new page)."""
    import feed_intel as _fi
    import phish_feeds as _pf
    try:
        out = _fi.feed_status()
    except Exception as e:
        out = {"sources": [], "error": str(e)[:200]}
    try:
        op = _pf.feed_status()
        out["openphish"] = {
            "count": op.get("count", 0),
            "feed_timestamp": op.get("feed_timestamp", ""),
            "stale": op.get("stale", True)}
    except Exception:
        pass
    return out

# Deployment mode note: this deployment mode stores API credentials in the
# browser (localStorage). Use only on trusted/local deployments.
# CORS is configurable via environment variables; a wildcard default is only
# used when explicitly enabled for local development.
def _cors_origins() -> list:
    if _mantis_env("MANTIS_ALLOW_ALL_CORS", "IOCINTEL_ALLOW_ALL_CORS").strip().lower() in {"1", "true", "yes"}:
        return ["*"]
    raw = _mantis_env("MANTIS_ALLOWED_ORIGINS", "IOCINTEL_ALLOWED_ORIGINS").strip()
    if raw:
        return [o.strip() for o in raw.split(",") if o.strip()]
    return [
        "http://localhost",
        "http://127.0.0.1",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:9999",
        "http://127.0.0.1:9999",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=[
        "Content-Disposition",
        "X-VT-Failed-Samples", "X-VT-Succeeded-Count",
    ],
)
app.include_router(agent_tools_router)

# Basic input validation for lazy detail endpoints: accept legitimate
# provider IDs while rejecting empty strings, newlines and URL fragments.
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,128}$")
_HEX_ID_RE = re.compile(r"^[A-Fa-f0-9]{1,64}$")
_RWLIVE_VICTIM_ID_RE = re.compile(r"^[A-Za-z0-9+/_=-]{1,256}$")
_RWLIVE_IOC_TYPE_RE = re.compile(r"^(|md5|sha1|sha256|hash|ip|domain|url|email|btc)$")
_TWEET_ID_RE = re.compile(r"^[0-9]{1,20}$")
_X_HANDLE_RE = re.compile(r"^[A-Za-z0-9_]{1,15}$")

def _require_id(value: str, label: str, pattern=None) -> str:
    v = (value or "").strip()
    if not v or "\n" in v or "\r" in v:
        raise HTTPException(status_code=400, detail=f"Invalid {label}.")
    if pattern is not None and not pattern.match(v):
        raise HTTPException(status_code=400, detail=f"Invalid {label}.")
    return v


def _intel_or_500(label: str, fn, *args, **kwargs):
    """Run an intel fan-out; upstream crashes become a generic 500.

    Tracebacks are logged server-side only — never returned to clients."""
    try:
        return fn(*args, **kwargs)
    except HTTPException:
        raise
    except Exception as e:
        import requests
        if isinstance(e, requests.exceptions.HTTPError) and e.response is not None and e.response.status_code == 429:
            logger.warning("%s rate limited (429)", label)
            raise HTTPException(status_code=429, detail=f"{label} rate limit exceeded.")
        logger.exception("%s intel query failed", label)
        raise HTTPException(status_code=500, detail="Internal Server Error")

class IntelRequest(BaseModel):
    indicator: str
    vt_key: str = ""
    abusech_key: str = ""
    otx_key: str = ""
    triage_key: str = ""
    tip_key: str = ""
    rwlive_key: str = ""
    cb_key: str = ""
    ransomlook_key: str = ""
    threatbook_key: str = ""
    silentpush_key: str = ""
    driftnet_key: str = ""
    urlscan_key: str = ""
    ha_key: str = ""
    malshare_key: str = ""
    shodan_key: str = ""
    censys_key: str = ""
    etugen_key: str = ""
    zoomeye_key: str = ""
    pulsedive_key: str = ""
    fofa_key: str = ""
    validin_key: str = ""
    netlas_key: str = ""
    twitter_key: str = ""
    github_key: str = ""
    dnsdumpster_key: str = ""
    mnemonic_key: str = ""
    greynoise_key: str = ""
    leakix_key: str = ""
    phishstats_key: str = ""
    misp_url: str = ""
    misp_key: str = ""
    misp_verify_ssl: bool = True

    abuseipdb_key: str = ""
    sources: list = Field(default_factory=list)  # empty = all sources
    github_repos: list = Field(default_factory=list)


class VTSampleDownloadRequest(BaseModel):
    file_hash: str
    vt_key: str = ""


class VTSampleZipRequest(BaseModel):
    hashes: List[str]
    vt_key: str = ""
    password: str = "infected"


class AiChatRequest(BaseModel):
    messages: list = Field(default_factory=list)
    page_context: dict = Field(default_factory=dict)
    operation: str = "chat"


class AiToolRequest(BaseModel):
    tool: str
    arguments: dict = Field(default_factory=dict)
    reason: str = ""
    page: str = ""


class AiAgentStartRequest(BaseModel):
    page_context: dict = Field(default_factory=dict)
    goal: str = ""
    limits: dict = Field(default_factory=dict)


class AiAgentNextRequest(BaseModel):
    agent_run_id: str
    latest_context: dict = Field(default_factory=dict)
    last_status: str = ""
    last_error: str = ""


class AiAgentStopRequest(BaseModel):
    agent_run_id: str
    reason: str = "Analyst requested stop."


class AiCaseSyncRequest(BaseModel):
    case_id: str = ""
    page_context: dict = Field(default_factory=dict)
    note: str = ""
    selected_sources: list = Field(default_factory=list)


class AiCaseStepRequest(BaseModel):
    case_id: str = ""
    page_context: dict = Field(default_factory=dict)
    selected_sources: list = Field(default_factory=list)


class AiCaseRunNextRequest(BaseModel):
    case_id: str = ""
    page_context: dict = Field(default_factory=dict)
    selected_sources: list = Field(default_factory=list)
    keys: dict = Field(default_factory=dict)
    github_repos: list = Field(default_factory=list)
    max_sources: int = 1


class AiCaseAutoRunRequest(BaseModel):
    case_id: str = ""
    page_context: dict = Field(default_factory=dict)
    selected_sources: list = Field(default_factory=list)
    keys: dict = Field(default_factory=dict)
    github_repos: list = Field(default_factory=list)
    max_steps: int = 3


class AiCorrelationRequest(BaseModel):
    correlation_id: str = ""
    entities: list = Field(default_factory=list)


class AiCorrelationMarkRequest(BaseModel):
    correlation_id: str
    evidence_id: str
    mark: str = ""
    note: str = ""


class AiAttributionRequest(BaseModel):
    attribution_id: str = ""
    activity: dict = Field(default_factory=dict)
    candidate_names: list = Field(default_factory=list)
    candidates: list = Field(default_factory=list)
    limit: int = 10


class AiYaraRequest(BaseModel):
    source: str = ""
    validation: dict = Field(default_factory=dict)
    test_result: dict = Field(default_factory=dict)
    max_iterations: int = 5


class TodaysIntelRequest(BaseModel):
    rwlive_key: str = ""
    abusech_key: str = ""
    urlscan_key: str = ""
    github_key: str = ""
    vt_key: str = ""
    greynoise_key: str = ""
    shodan_key: str = ""
    censys_key: str = ""
    otx_key: str = ""
    limit: int = 12
    range: str = "today"
    source_type: str = ""
    severity: str = ""
    group: str = ""
    country: str = ""
    region: str = ""
    sector: str = ""
    snapshot: dict = Field(default_factory=dict)


class XMonitorRequest(BaseModel):
    id: str = ""
    username: str = ""
    display_name: str = ""
    notes: str = ""
    tags: list | str = Field(default_factory=list)
    enabled: bool = True
    interval_minutes: int = 60
    delete_posts: bool = False
    twitter_key: str = ""
    q: str = ""
    account: str = ""
    category: str = "all"
    entity: str = ""
    range: str = "7d"
    start_date: str = ""
    end_date: str = ""
    sort: str = "newest"
    page: int = 1
    page_size: int = 36
    max_accounts: int = 12
    accounts_per_batch: int = 0
    mode: str = "monitor"


class TweetFeedRequest(BaseModel):
    value: str = ""
    range: str = "today"
    ioc_type: str = ""
    tag: str = ""
    user: str = ""
    limit: int = 50


@app.get("/api/ai/settings")
def ai_settings_get():
    return ai_mod.get_settings(mask=True)


@app.post("/api/ai/settings")
def ai_settings_save(req: dict):
    try:
        return ai_mod.save_settings(req or {})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("MANTIS AI settings save failed")
        raise HTTPException(status_code=500, detail="MANTIS AI settings save failed. Check backend logs for diagnostics.")


@app.post("/api/ai/test")
def ai_test_connection(req: Optional[dict] = None):
    try:
        return ai_mod.test_connection(req or None)
    except ai_mod.AIUnavailable as e:
        raise HTTPException(status_code=400, detail=str(e))
    except TimeoutError as e:
        raise HTTPException(status_code=504, detail=str(e))
    except ai_mod.AIProviderError as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/api/todays-intelligence")
def todays_intelligence(req: TodaysIntelRequest):
    try:
        return todays_intel_mod.build_dashboard(
            rwlive_key=(req.rwlive_key or "").strip(),
            limit=max(5, min(int(req.limit or 12), 40)),
            filters={
                "range": req.range,
                "source_type": req.source_type,
                "severity": req.severity,
                "group": req.group,
                "country": req.country,
                "region": req.region,
                "sector": req.sector,
            },
            keys={
                "abusech_key": (req.abusech_key or "").strip(),
                "urlscan_key": (req.urlscan_key or "").strip(),
                "github_key": (req.github_key or "").strip(),
                "vt_key": (req.vt_key or "").strip(),
                "greynoise_key": (req.greynoise_key or "").strip(),
                "shodan_key": (req.shodan_key or "").strip(),
                "censys_key": (req.censys_key or "").strip(),
                "otx_key": (req.otx_key or "").strip(),
            },
        )
    except Exception as e:
        logger.exception("Today's Intelligence failed")
        raise HTTPException(status_code=500, detail=f"Today's Intelligence failed: {e}")


@app.post("/api/todays-intelligence/ai-brief")
def todays_intelligence_ai_brief(req: TodaysIntelRequest):
    try:
        snapshot = req.snapshot or todays_intel_mod.build_dashboard(
            rwlive_key=(req.rwlive_key or "").strip(),
            limit=max(5, min(int(req.limit or 12), 40)),
            filters={
                "range": req.range,
                "source_type": req.source_type,
                "severity": req.severity,
                "group": req.group,
                "country": req.country,
                "region": req.region,
                "sector": req.sector,
            },
            keys={
                "abusech_key": (req.abusech_key or "").strip(),
                "urlscan_key": (req.urlscan_key or "").strip(),
                "github_key": (req.github_key or "").strip(),
                "vt_key": (req.vt_key or "").strip(),
                "greynoise_key": (req.greynoise_key or "").strip(),
                "shodan_key": (req.shodan_key or "").strip(),
                "censys_key": (req.censys_key or "").strip(),
                "otx_key": (req.otx_key or "").strip(),
            },
        )
        return todays_intel_mod.ai_brief(snapshot)
    except ai_mod.AIUnavailable as e:
        raise HTTPException(status_code=400, detail=str(e))
    except TimeoutError as e:
        raise HTTPException(status_code=504, detail=str(e))
    except ai_mod.AIProviderError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except Exception:
        logger.exception("Today's Intelligence AI brief failed")
        raise HTTPException(status_code=500, detail="Today's Intelligence AI brief failed. Check backend logs for diagnostics.")


@app.post("/api/todays-intelligence/ai-report")
def todays_intelligence_ai_report(req: TodaysIntelRequest):
    try:
        snapshot = req.snapshot or todays_intel_mod.build_dashboard(
            rwlive_key=(req.rwlive_key or "").strip(),
            limit=max(5, min(int(req.limit or 12), 40)),
            filters={
                "range": req.range,
                "source_type": req.source_type,
                "severity": req.severity,
                "group": req.group,
                "country": req.country,
                "region": req.region,
                "sector": req.sector,
            },
            keys={
                "abusech_key": (req.abusech_key or "").strip(),
                "urlscan_key": (req.urlscan_key or "").strip(),
                "github_key": (req.github_key or "").strip(),
                "vt_key": (req.vt_key or "").strip(),
                "greynoise_key": (req.greynoise_key or "").strip(),
                "shodan_key": (req.shodan_key or "").strip(),
                "censys_key": (req.censys_key or "").strip(),
                "otx_key": (req.otx_key or "").strip(),
            },
        )
        return todays_intel_mod.ai_report(snapshot)
    except ai_mod.AIUnavailable as e:
        raise HTTPException(status_code=400, detail=str(e))
    except TimeoutError as e:
        raise HTTPException(status_code=504, detail=str(e))
    except ai_mod.AIProviderError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except Exception:
        logger.exception("Today's Intelligence AI report failed")
        raise HTTPException(status_code=500, detail="Today's Intelligence AI report failed. Check backend logs for diagnostics.")


@app.post("/api/tweetfeed/ioc")
def tweetfeed_ioc(req: TweetFeedRequest):
    try:
        return tweetfeed_mod.ioc_lookup(req.value)
    except Exception as e:
        logger.exception("TweetFeed IOC lookup failed")
        raise HTTPException(status_code=500, detail=f"TweetFeed IOC lookup failed: {e}")


@app.post("/api/tweetfeed/feed")
def tweetfeed_feed(req: TweetFeedRequest):
    try:
        return tweetfeed_mod.feed(
            range_mode=req.range,
            ioc_type=req.ioc_type,
            tag=req.tag,
            user=req.user,
            limit=max(1, min(int(req.limit or 50), 500)),
        )
    except Exception as e:
        logger.exception("TweetFeed feed failed")
        raise HTTPException(status_code=500, detail=f"TweetFeed feed failed: {e}")


@app.get("/api/tweetfeed/status")
def tweetfeed_status():
    return tweetfeed_mod.status()


@app.get("/api/tweetfeed/counts")
def tweetfeed_counts():
    return tweetfeed_mod.counts()


@app.get("/api/tweetfeed/trends")
def tweetfeed_trends():
    return tweetfeed_mod.trends()


@app.get("/api/tweetfeed/contributors")
def tweetfeed_contributors(range: str = "today", limit: int = 8):
    return tweetfeed_mod.contributors(range_mode=range, limit=max(1, min(int(limit or 8), 50)))


@app.get("/api/tweetfeed/campaigns")
def tweetfeed_campaigns(limit: int = 12):
    return tweetfeed_mod.campaigns(limit=max(1, min(int(limit or 12), 100)))


def _x_monitor_payload(req: XMonitorRequest) -> dict:
    return {
        "q": req.q,
        "account": req.account,
        "category": req.category,
        "entity": req.entity,
        "range": req.range,
        "start_date": req.start_date,
        "end_date": req.end_date,
        "sort": req.sort,
        "page": req.page,
        "page_size": req.page_size,
    }


@app.post("/api/x-monitor/dashboard")
def x_monitor_dashboard(req: XMonitorRequest):
    try:
        return x_monitor_mod.dashboard(_x_monitor_payload(req))
    except Exception as e:
        logger.exception("X Monitor dashboard failed")
        raise HTTPException(status_code=500, detail=f"X Monitor failed: {e}")


@app.get("/api/x-monitor/accounts")
def x_monitor_accounts():
    try:
        return x_monitor_mod.list_accounts()
    except Exception as e:
        logger.exception("X Monitor accounts failed")
        raise HTTPException(status_code=500, detail=f"X Monitor accounts failed: {e}")


@app.post("/api/x-monitor/accounts")
def x_monitor_add_account(req: XMonitorRequest):
    try:
        return {"account": x_monitor_mod.add_account(req.dict())}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("X Monitor add account failed")
        raise HTTPException(status_code=500, detail="X Monitor add account failed.")


@app.post("/api/x-monitor/accounts/update")
def x_monitor_update_account(req: XMonitorRequest):
    account_id = (req.id or "").strip()
    if not account_id:
        raise HTTPException(status_code=400, detail="Account id is required.")
    try:
        return {"account": x_monitor_mod.update_account(account_id, req.dict())}
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("X Monitor update account failed")
        raise HTTPException(status_code=500, detail="X Monitor update account failed.")


@app.post("/api/x-monitor/accounts/delete")
def x_monitor_delete_account(req: XMonitorRequest):
    account_id = (req.id or "").strip()
    if not account_id:
        raise HTTPException(status_code=400, detail="Account id is required.")
    try:
        return x_monitor_mod.delete_account(account_id, bool(req.delete_posts))
    except Exception:
        logger.exception("X Monitor delete account failed")
        raise HTTPException(status_code=500, detail="X Monitor delete account failed.")


@app.post("/api/x-monitor/refresh")
def x_monitor_refresh(req: XMonitorRequest):
    try:
        return x_monitor_mod.collect({
            "twitter_key": (req.twitter_key or "").strip(),
            "account_id": (req.id or "").strip(),
            "max_accounts": req.max_accounts,
            "accounts_per_batch": req.accounts_per_batch,
            "mode": req.mode,
            "range": req.range,
            "start_date": req.start_date,
            "end_date": req.end_date,
        })
    except Exception as e:
        logger.exception("X Monitor refresh failed")
        raise HTTPException(status_code=500, detail=f"X Monitor refresh failed: {e}")


SAMPLE_HASH_RE = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
SAMPLE_BATCH_LIMIT = 50
SAMPLE_TOTAL_BYTES_LIMIT = 1024 * 1024 * 1024


def _require_sample_hash(file_hash: str) -> str:
    file_hash = (file_hash or "").strip()
    if not SAMPLE_HASH_RE.fullmatch(file_hash):
        raise HTTPException(status_code=400, detail="Invalid sample hash format.")
    return file_hash.lower()


def _require_vt_download_key(vt_key: str) -> str:
    api_key = (vt_key or "").strip() or os.environ.get("VT_API_KEY", "")
    if not api_key:
        raise HTTPException(status_code=401, detail="VirusTotal API key is required to download samples.")
    return api_key


def _open_vt_sample(file_hash: str, api_key: str):
    vt_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/download"
    try:
        resp = requests.get(vt_url, headers={"x-apikey": api_key}, stream=True, timeout=(10, 120))
    except requests.exceptions.Timeout:
        raise HTTPException(status_code=504, detail="VirusTotal sample download timed out.")
    except requests.exceptions.RequestException:
        logger.exception("VT sample download request failed")
        raise HTTPException(status_code=502, detail="VirusTotal sample download request failed.")

    if resp.status_code == 200:
        return resp

    resp.close()
    if resp.status_code == 401:
        raise HTTPException(status_code=401, detail="VirusTotal rejected the API key.")
    if resp.status_code == 403:
        raise HTTPException(
            status_code=403,
            detail="VirusTotal sample download requires a VT Premium / Intelligence API key with download privileges."
        )
    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail=f"Sample {file_hash} was not found on VirusTotal.")
    if resp.status_code == 429:
        raise HTTPException(status_code=429, detail="VirusTotal sample download rate limit exceeded.")
    raise HTTPException(status_code=502, detail=f"VirusTotal download failed (HTTP {resp.status_code}).")


def _vt_sample_stream(file_hash: str, vt_key: str):
    file_hash = _require_sample_hash(file_hash)
    api_key = _require_vt_download_key(vt_key)
    resp = _open_vt_sample(file_hash, api_key)

    def iterfile():
        try:
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    yield chunk
        finally:
            resp.close()

    response_headers = {
        "Content-Disposition": f'attachment; filename="{file_hash}.bin"',
        "X-Content-Type-Options": "nosniff",
    }
    content_length = resp.headers.get("Content-Length", "")
    if content_length and not resp.headers.get("Content-Encoding"):
        response_headers["Content-Length"] = content_length
    return StreamingResponse(iterfile(), media_type="application/octet-stream", headers=response_headers)


@app.post("/api/vt/download")
def download_vt_sample_post(req: VTSampleDownloadRequest):
    return _vt_sample_stream(req.file_hash, req.vt_key)


def _encrypted_sample_zip(raw_hashes: List[str], password: str, open_sample,
                          provider_slug: str, failed_header_name: str, success_header_name: str):
    try:
        import pyzipper
    except ImportError:
        raise HTTPException(status_code=500, detail="Encrypted ZIP support is unavailable. Install the pyzipper dependency.")

    if password != "infected":
        raise HTTPException(status_code=400, detail='The sample archive password must be "infected".')

    hashes = []
    seen = set()
    for value in raw_hashes or []:
        file_hash = _require_sample_hash(value)
        if file_hash not in seen:
            hashes.append(file_hash)
            seen.add(file_hash)
    if not hashes:
        raise HTTPException(status_code=400, detail="At least one valid sample hash is required.")
    if len(hashes) > SAMPLE_BATCH_LIMIT:
        raise HTTPException(status_code=400, detail=f"A maximum of {SAMPLE_BATCH_LIMIT} samples can be downloaded per batch.")

    temp_dir = tempfile.mkdtemp(prefix=f"mantis-{provider_slug}-samples-")
    zip_path = os.path.join(temp_dir, f"{provider_slug}_samples.zip")
    failed = []
    succeeded = 0
    total_bytes = 0

    try:
        with pyzipper.AESZipFile(
            zip_path,
            "w",
            compression=pyzipper.ZIP_DEFLATED,
            encryption=pyzipper.WZ_AES,
        ) as archive:
            archive.setpassword(b"infected")
            archive.setencryption(pyzipper.WZ_AES, nbits=256)
            for file_hash in hashes:
                sample_path = os.path.join(temp_dir, f"{file_hash}.bin")
                try:
                    resp = open_sample(file_hash)
                except HTTPException as exc:
                    if exc.status_code in (401, 403, 429):
                        raise
                    failed.append((file_hash, exc.status_code))
                    continue

                sample_bytes = 0
                try:
                    try:
                        declared_size = int(resp.headers.get("Content-Length", "0") or 0)
                    except ValueError:
                        declared_size = 0
                    if declared_size and total_bytes + declared_size > SAMPLE_TOTAL_BYTES_LIMIT:
                        raise HTTPException(status_code=413, detail="The sample batch exceeds the 1 GiB safety limit.")
                    with open(sample_path, "wb") as sample_file:
                        for chunk in resp.iter_content(chunk_size=1024 * 1024):
                            if not chunk:
                                continue
                            sample_bytes += len(chunk)
                            if total_bytes + sample_bytes > SAMPLE_TOTAL_BYTES_LIMIT:
                                raise HTTPException(status_code=413, detail="The sample batch exceeds the 1 GiB safety limit.")
                            sample_file.write(chunk)
                    archive.write(sample_path, arcname=f"{file_hash}.bin")
                    total_bytes += sample_bytes
                    succeeded += 1
                except requests.exceptions.RequestException:
                    logger.exception("Sample stream interrupted for %s", file_hash)
                    failed.append((file_hash, 502))
                finally:
                    resp.close()
                    if os.path.exists(sample_path):
                        os.remove(sample_path)

        if not succeeded:
            raise HTTPException(
                status_code=404,
                detail={"message": "No requested samples were available for download.", "failed": failed},
            )

        def iterzip():
            try:
                with open(zip_path, "rb") as archive_file:
                    while True:
                        chunk = archive_file.read(1024 * 1024)
                        if not chunk:
                            break
                        yield chunk
            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)

        failed_header_value = ";".join(f"{file_hash}:{status}" for file_hash, status in failed)
        filename = time.strftime(f"{provider_slug}_samples_%Y%m%d_%H%M%S.zip")
        return StreamingResponse(
            iterzip(),
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                failed_header_name: failed_header_value,
                success_header_name: str(succeeded),
                "X-Content-Type-Options": "nosniff",
            },
        )
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


@app.post("/api/vt/download/zip")
def download_vt_samples_zip(req: VTSampleZipRequest):
    api_key = _require_vt_download_key(req.vt_key)
    return _encrypted_sample_zip(
        req.hashes,
        req.password,
        lambda file_hash: _open_vt_sample(file_hash, api_key),
        "vt",
        "X-VT-Failed-Samples",
        "X-VT-Succeeded-Count",
    )


@app.post("/api/ai/chat")
def ai_chat(req: AiChatRequest):
    try:
        return ai_mod.chat(req.dict())
    except ai_mod.AIUnavailable as e:
        raise HTTPException(status_code=400, detail=str(e))
    except TimeoutError as e:
        raise HTTPException(status_code=504, detail=str(e))
    except ai_mod.AIProviderError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except Exception as e:
        logger.exception("MANTIS AI chat failed")
        raise HTTPException(status_code=500, detail="MANTIS AI chat failed. Check backend logs for diagnostics.")


@app.post("/api/ai/tool/execute")
def ai_tool_execute(req: AiToolRequest):
    try:
        return ai_mod.execute_tool(req.dict())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("MANTIS AI tool execution failed")
        raise HTTPException(status_code=500, detail="MANTIS AI tool execution failed. Check backend logs for diagnostics.")


@app.get("/api/ai/audit")
def ai_audit(limit: int = 100):
    return ai_mod.audit_recent(limit=limit)


@app.get("/api/ai/case/sources")
def ai_case_sources():
    return ai_case_mod.source_inventory()


@app.get("/api/ai/case/list")
def ai_case_list(limit: int = 30):
    try:
        return ai_case_mod.list_cases(limit=limit)
    except Exception:
        logger.exception("MANTIS AI case list failed")
        raise HTTPException(status_code=500, detail="MANTIS AI case list failed. Check backend logs for diagnostics.")


@app.get("/api/ai/case/{case_id}")
def ai_case_get(case_id: str):
    try:
        return ai_case_mod.get_case(case_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception:
        logger.exception("MANTIS AI case get failed")
        raise HTTPException(status_code=500, detail="MANTIS AI case get failed. Check backend logs for diagnostics.")


@app.post("/api/ai/case/sync")
def ai_case_sync(req: AiCaseSyncRequest):
    try:
        return ai_case_mod.sync_case_from_context(req.page_context or {}, note=req.note or "Manual case sync.")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("MANTIS AI case sync failed")
        raise HTTPException(status_code=500, detail="MANTIS AI case sync failed. Check backend logs for diagnostics.")


@app.post("/api/ai/case/step")
def ai_case_step(req: AiCaseStepRequest):
    try:
        return ai_case_mod.case_step(req.dict())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("MANTIS AI case step failed")
        raise HTTPException(status_code=500, detail="MANTIS AI case step failed. Check backend logs for diagnostics.")


@app.post("/api/ai/case/run-next")
def ai_case_run_next(req: AiCaseRunNextRequest):
    try:
        return ai_case_mod.run_case_next_source(req.dict())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("MANTIS AI case source execution failed")
        raise HTTPException(status_code=500, detail="MANTIS AI case source execution failed. Check backend logs for diagnostics.")


@app.post("/api/ai/case/run-auto")
def ai_case_run_auto(req: AiCaseAutoRunRequest):
    try:
        return ai_case_mod.run_case_auto(req.dict())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception:
        logger.exception("MANTIS AI case auto-run failed")
        raise HTTPException(status_code=500, detail="MANTIS AI case auto-run failed. Check backend logs for diagnostics.")


@app.get("/api/ai/case/{case_id}/related")
def ai_case_related(case_id: str, limit: int = 10):
    try:
        return ai_case_mod.related_cases(case_id, limit=limit)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception:
        logger.exception("MANTIS AI related case lookup failed")
        raise HTTPException(status_code=500, detail="MANTIS AI related case lookup failed. Check backend logs for diagnostics.")


@app.get("/api/ai/case/{case_id}/report")
def ai_case_report(case_id: str):
    try:
        return ai_case_mod.draft_case_report(case_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception:
        logger.exception("MANTIS AI case report failed")
        raise HTTPException(status_code=500, detail="MANTIS AI case report failed. Check backend logs for diagnostics.")


@app.post("/api/ai/agent/start")
def ai_agent_start(req: AiAgentStartRequest):
    try:
        return ai_mod.start_agent(req.dict())
    except ai_mod.AIUnavailable as e:
        raise HTTPException(status_code=400, detail=str(e))
    except TimeoutError as e:
        raise HTTPException(status_code=504, detail=str(e))
    except ai_mod.AIProviderError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("MANTIS AI agent start failed")
        raise HTTPException(status_code=500, detail="MANTIS AI agent start failed. Check backend logs for diagnostics.")


@app.post("/api/ai/agent/next")
def ai_agent_next(req: AiAgentNextRequest):
    try:
        return ai_mod.agent_next(req.dict())
    except TimeoutError as e:
        raise HTTPException(status_code=504, detail=str(e))
    except ai_mod.AIProviderError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("MANTIS AI agent step failed")
        raise HTTPException(status_code=500, detail="MANTIS AI agent step failed. Check backend logs for diagnostics.")


@app.post("/api/ai/agent/stop")
def ai_agent_stop(req: AiAgentStopRequest):
    try:
        return ai_mod.stop_agent(req.agent_run_id, req.reason)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("MANTIS AI agent stop failed")
        raise HTTPException(status_code=500, detail="MANTIS AI agent stop failed. Check backend logs for diagnostics.")


@app.get("/api/ai/agent/{agent_run_id}")
def ai_agent_status(agent_run_id: str):
    run = ai_mod.AGENT_RUNS.get(agent_run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Unknown agent run.")
    return ai_mod._public_agent_state(run)


@app.post("/api/ai/correlation/compare")
def ai_correlation_compare(req: AiCorrelationRequest):
    try:
        return ai_mod.compare_correlation(req.dict())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("MANTIS AI correlation compare failed")
        raise HTTPException(status_code=500, detail="MANTIS AI correlation compare failed. Check backend logs for diagnostics.")


@app.post("/api/ai/correlation/mark")
def ai_correlation_mark(req: AiCorrelationMarkRequest):
    try:
        return ai_mod.mark_correlation_evidence(req.dict())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("MANTIS AI correlation mark failed")
        raise HTTPException(status_code=500, detail="MANTIS AI correlation mark failed. Check backend logs for diagnostics.")


@app.post("/api/ai/attribution/assess")
def ai_attribution_assess(req: AiAttributionRequest):
    try:
        return ai_mod.assess_attribution(req.dict())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("MANTIS AI attribution assessment failed")
        raise HTTPException(status_code=500, detail="MANTIS AI attribution assessment failed. Check backend logs for diagnostics.")


@app.post("/api/ai/yara/explain")
def ai_yara_explain(req: AiYaraRequest):
    try:
        return ai_mod.yara_explain(req.dict())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("MANTIS AI YARA explain failed")
        raise HTTPException(status_code=500, detail="MANTIS AI YARA explain failed. Check backend logs for diagnostics.")


@app.post("/api/ai/yara/analyze-error")
def ai_yara_analyze_error(req: AiYaraRequest):
    try:
        return ai_mod.yara_analyze_error(req.dict())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("MANTIS AI YARA error analysis failed")
        raise HTTPException(status_code=500, detail="MANTIS AI YARA error analysis failed. Check backend logs for diagnostics.")


@app.post("/api/ai/yara/suggest-fix")
def ai_yara_suggest_fix(req: AiYaraRequest):
    try:
        return ai_mod.yara_suggest_fix(req.dict())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("MANTIS AI YARA suggest fix failed")
        raise HTTPException(status_code=500, detail="MANTIS AI YARA suggest fix failed. Check backend logs for diagnostics.")


@app.post("/api/ai/yara/auto-fix")
def ai_yara_auto_fix(req: AiYaraRequest):
    try:
        return ai_mod.yara_auto_fix(req.dict())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("MANTIS AI YARA auto-fix failed")
        raise HTTPException(status_code=500, detail="MANTIS AI YARA auto-fix failed. Check backend logs for diagnostics.")


@app.post("/api/ai/yara/analyze-test")
def ai_yara_analyze_test(req: AiYaraRequest):
    try:
        return ai_mod.yara_analyze_test(req.dict())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("MANTIS AI YARA test analysis failed")
        raise HTTPException(status_code=500, detail="MANTIS AI YARA test analysis failed. Check backend logs for diagnostics.")

@app.post("/api/query/domain")
def query_domain(req: IntelRequest):
    domain = normalize_domain(req.indicator)
    if not is_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format.")
    return _intel_or_500("domain", do_domain_intel, domain, req.vt_key, req.abusech_key, req.otx_key, tip_key=req.tip_key, cb_key=req.cb_key, rwlive_key=req.rwlive_key, triage_key=req.triage_key, ha_key=req.ha_key, silentpush_key=req.silentpush_key, driftnet_key=req.driftnet_key, urlscan_key=req.urlscan_key, shodan_key=req.shodan_key, censys_key=req.censys_key, etugen_key=req.etugen_key, pulsedive_key=req.pulsedive_key, fofa_key=req.fofa_key, validin_key=req.validin_key, netlas_key=req.netlas_key, zoomeye_key=req.zoomeye_key, twitter_key=req.twitter_key, github_key=req.github_key, dnsdumpster_key=req.dnsdumpster_key, leakix_key=req.leakix_key, phishstats_key=req.phishstats_key, misp_url=req.misp_url, misp_key=req.misp_key, misp_verify_ssl=req.misp_verify_ssl, sources=req.sources)

@app.post("/api/query/ip")
def query_ip(req: IntelRequest):
    ip = normalize_ip(req.indicator)
    if not is_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format. Must be IPv4 or IPv6.")
    return _intel_or_500("ip", do_ip_intel, ip, req.vt_key, req.abusech_key, req.otx_key, tip_key=req.tip_key, cb_key=req.cb_key, threatbook_key=req.threatbook_key, triage_key=req.triage_key, ha_key=req.ha_key, silentpush_key=req.silentpush_key, driftnet_key=req.driftnet_key, urlscan_key=req.urlscan_key, shodan_key=req.shodan_key, censys_key=req.censys_key, etugen_key=req.etugen_key, pulsedive_key=req.pulsedive_key, fofa_key=req.fofa_key, validin_key=req.validin_key, netlas_key=req.netlas_key, zoomeye_key=req.zoomeye_key, twitter_key=req.twitter_key, github_key=req.github_key, abuseipdb_key=req.abuseipdb_key, greynoise_key=req.greynoise_key, leakix_key=req.leakix_key, phishstats_key=req.phishstats_key, misp_url=req.misp_url, misp_key=req.misp_key, misp_verify_ssl=req.misp_verify_ssl, sources=req.sources)

@app.post("/api/query/url")
def query_url(req: IntelRequest):
    url = normalize_url(req.indicator)
    if not is_url(url):
        raise HTTPException(status_code=400, detail="Invalid URL format. Include http:// or https:// and preserve the full URL.")
    return _intel_or_500("url", do_url_intel, url, req.vt_key, req.abusech_key, req.otx_key, tip_key=req.tip_key, cb_key=req.cb_key, triage_key=req.triage_key, ha_key=req.ha_key, silentpush_key=req.silentpush_key, urlscan_key=req.urlscan_key, pulsedive_key=req.pulsedive_key, twitter_key=req.twitter_key, github_key=req.github_key, phishstats_key=req.phishstats_key, misp_url=req.misp_url, misp_key=req.misp_key, misp_verify_ssl=req.misp_verify_ssl, sources=req.sources)

@app.post("/api/query/infra")
def query_infra(req: IntelRequest):
    indicator = req.indicator.strip()
    if not indicator:
        raise HTTPException(status_code=400, detail="Infra search query cannot be empty.")
    return _intel_or_500("infra", do_infra_intel, indicator, silentpush_key=req.silentpush_key, driftnet_key=req.driftnet_key, shodan_key=req.shodan_key, censys_key=req.censys_key, etugen_key=req.etugen_key, pulsedive_key=req.pulsedive_key, fofa_key=req.fofa_key, validin_key=req.validin_key, ha_key=req.ha_key, abuseipdb_key=req.abuseipdb_key, urlscan_key=req.urlscan_key, dnsdumpster_key=req.dnsdumpster_key, greynoise_key=req.greynoise_key, netlas_key=req.netlas_key, vt_key=req.vt_key, sources=req.sources)


class InfraHuntRequest(IntelRequest):
    name: str = ""
    description: str = ""
    enabled: bool = True
    interval_minutes: int = 1440
    providers: list = Field(default_factory=list)
    source_ids: list = Field(default_factory=list)
    max_signals: int = 3


class InfraHuntMutationRequest(BaseModel):
    name: str = ""
    seed: str = ""
    description: str = ""
    enabled: bool = True
    interval_minutes: int = 1440
    providers: list = Field(default_factory=list)
    source_ids: list = Field(default_factory=list)


class InfraSignatureRequest(BaseModel):
    slug: str = ""
    name: str = ""
    family: str = ""
    description: str = ""
    signals: dict = Field(default_factory=dict)
    minimum_matches: int = 2
    false_positive_notes: str = ""
    enabled: bool = True


def _infra_hunt_keys(req: IntelRequest) -> dict:
    return {
        "silentpush_key": req.silentpush_key,
        "driftnet_key": req.driftnet_key,
        "urlscan_key": req.urlscan_key,
        "ha_key": req.ha_key,
        "shodan_key": req.shodan_key,
        "censys_key": req.censys_key,
        "etugen_key": req.etugen_key,
        "zoomeye_key": req.zoomeye_key,
        "pulsedive_key": req.pulsedive_key,
        "fofa_key": req.fofa_key,
        "validin_key": req.validin_key,
        "netlas_key": req.netlas_key,
        "abuseipdb_key": req.abuseipdb_key,
        "dnsdumpster_key": req.dnsdumpster_key,
        "greynoise_key": req.greynoise_key,
        "vt_key": req.vt_key,
    }


@app.post("/api/infra-hunts/run")
def infra_hunt_run(req: InfraHuntRequest):
    try:
        res = infra_hunt_mod.run_hunt(
            req.indicator,
            keys=_infra_hunt_keys(req),
            providers=req.providers,
            source_ids=req.source_ids or req.sources,
            max_signals=req.max_signals,
        )
        try:
            import c2_hunting_catalog
            res["c2_matches"] = c2_hunting_catalog.match_seed_c2(res.get("features", {}))
        except Exception:
            res["c2_matches"] = []
        return res
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Infrastructure hunt failed")
        raise HTTPException(status_code=500, detail=f"Infrastructure hunt failed: {str(exc)[:240]}")


@app.post("/api/infra-hunts/preview")
def infra_hunt_preview(req: InfraHuntRequest):
    try:
        res = infra_hunt_mod.preview_hunt(
            req.indicator,
            keys=_infra_hunt_keys(req),
            providers=req.providers,
            source_ids=req.source_ids or req.sources,
            max_signals=req.max_signals,
        )
        try:
            import c2_hunting_catalog
            res["c2_matches"] = c2_hunting_catalog.match_seed_c2(res.get("features", {}))
        except Exception:
            res["c2_matches"] = []
        return res
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Infrastructure hunt preview failed")
        raise HTTPException(status_code=500, detail=f"Infrastructure hunt preview failed: {str(exc)[:240]}")


@app.get("/api/infra-hunts/playbooks")
def infra_hunt_playbooks(q: str = "", engine: str = "", family: str = "", category: str = "", limit: int = 150, offset: int = 0):
    try:
        import c2_hunting_catalog
        return c2_hunting_catalog.query_playbooks(q=q, engine=engine, family=family, category=category, limit=limit, offset=offset)
    except Exception as exc:
        logger.exception("Failed to query C2 playbooks")
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/infra-hunts/etugen-templates")
def infra_hunt_etugen_templates():
    try:
        import os, json
        rules_path = os.path.join(os.path.dirname(__file__), "data", "c2_hunting_rules", "etugen_rules.json")
        rules = []
        if os.path.isfile(rules_path):
            with open(rules_path, "r", encoding="utf-8") as f:
                rules = json.load(f)
        example_searches = [r for r in rules if not r.get("etugen_label")]
        labels = [r for r in rules if r.get("etugen_label")]
        return {
            "total": len(rules),
            "example_searches": example_searches,
            "labels": labels,
            "raw_labels": [r.get("etugen_label") for r in labels if r.get("etugen_label")]
        }
    except Exception as exc:
        logger.exception("Failed to load Etugen templates")
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/infra-hunts/providers")
def infra_hunt_providers():
    return infra_hunt_mod.provider_readiness(server_only=True)


@app.get("/api/infra-hunts")
def infra_hunts_list():
    return {"hunts": infra_hunt_mod.list_hunts()}


@app.get("/api/infra-hunts/signatures")
def infra_hunt_signatures():
    return {"signatures": infra_hunt_mod.list_signature_packs()}


@app.post("/api/infra-hunts/signatures")
def infra_hunt_signature_create(req: InfraSignatureRequest):
    try:
        return {"signature": infra_hunt_mod.save_signature_pack(req.dict())}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.put("/api/infra-hunts/signatures/{pack_id}")
def infra_hunt_signature_update(pack_id: int, req: InfraSignatureRequest):
    try:
        return {"signature": infra_hunt_mod.save_signature_pack(req.dict(), pack_id=pack_id)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.delete("/api/infra-hunts/signatures/{pack_id}")
def infra_hunt_signature_delete(pack_id: int):
    return infra_hunt_mod.delete_signature_pack(pack_id)


@app.post("/api/infra-hunts")
def infra_hunt_create(req: InfraHuntMutationRequest):
    try:
        return {"hunt": infra_hunt_mod.save_hunt(req.dict())}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/infra-hunts/{hunt_id}")
def infra_hunt_get(hunt_id: int):
    hunt = infra_hunt_mod.get_hunt(hunt_id)
    if not hunt:
        raise HTTPException(status_code=404, detail="Infrastructure hunt not found")
    return {"hunt": hunt}


@app.put("/api/infra-hunts/{hunt_id}")
def infra_hunt_update(hunt_id: int, req: InfraHuntMutationRequest):
    try:
        hunt = infra_hunt_mod.save_hunt(req.dict(), hunt_id=hunt_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"hunt": hunt}


@app.delete("/api/infra-hunts/{hunt_id}")
def infra_hunt_delete(hunt_id: int):
    return infra_hunt_mod.delete_hunt(hunt_id)


@app.post("/api/infra-hunts/{hunt_id}/run")
def infra_saved_hunt_run(hunt_id: int, req: InfraHuntRequest):
    hunt = infra_hunt_mod.get_hunt(hunt_id)
    if not hunt:
        raise HTTPException(status_code=404, detail="Infrastructure hunt not found")
    try:
        return infra_hunt_mod.run_hunt(
            hunt["seed"],
            keys=_infra_hunt_keys(req),
            providers=hunt["providers"] or req.providers,
            source_ids=hunt["source_ids"] or req.source_ids or req.sources,
            hunt_id=hunt_id,
            max_signals=req.max_signals,
        )
    except Exception as exc:
        logger.exception("Saved infrastructure hunt failed")
        raise HTTPException(status_code=500, detail=f"Infrastructure hunt failed: {str(exc)[:240]}")


@app.get("/api/infra-hunts/runs/{run_id}")
def infra_hunt_run_get(run_id: int):
    run = infra_hunt_mod.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Infrastructure hunt run not found")
    return {"run": run}


@app.post("/api/infra-hunts/run-due")
def infra_hunts_run_due(req: InfraHuntRequest):
    return infra_hunt_mod.run_due_hunts(keys=_infra_hunt_keys(req))

@app.post("/api/query/hash")
def query_hash(req: IntelRequest):
    file_hash = req.indicator.strip()
    if not is_hash(file_hash):
        raise HTTPException(status_code=400, detail="Invalid hash format. Must be MD5, SHA-1, SHA-256, SHA-512, or SHA3-384 hex.")
    return _intel_or_500("hash", do_hash_intel, file_hash, req.vt_key, req.abusech_key, req.otx_key, triage_key=req.triage_key, tip_key=req.tip_key, cb_key=req.cb_key, ha_key=req.ha_key, malshare_key=req.malshare_key, silentpush_key=req.silentpush_key, driftnet_key=req.driftnet_key, pulsedive_key=req.pulsedive_key, fofa_key=req.fofa_key, validin_key=req.validin_key, urlscan_key=req.urlscan_key, twitter_key=req.twitter_key, github_key=req.github_key, misp_url=req.misp_url, misp_key=req.misp_key, misp_verify_ssl=req.misp_verify_ssl, sources=req.sources, github_repos=req.github_repos)





class VTRelationRequest(BaseModel):
    indicator: str
    type: str
    relation: str
    vt_key: str = ""

class ThreatFoxDetailRequest(BaseModel):
    ioc_id: str
    abusech_key: str = ""

class AbuseIPDBReportsRequest(BaseModel):
    ip: str = ""
    abuseipdb_key: str = ""
    max_age: int = 90
    page: int = 1
    per_page: int = 25

class MalShareLimitRequest(BaseModel):
    malshare_key: str = ""

class MalShareFeedRequest(BaseModel):
    feed: str = "list"
    malshare_key: str = ""

class DNSDumpsterMoreRequest(BaseModel):
    domain: str = ""
    dnsdumpster_key: str = ""
    page: int = 2

class DNSDumpsterMapRequest(BaseModel):
    domain: str = ""
    dnsdumpster_key: str = ""

class OrklIdRequest(BaseModel):
    id: str = ""
    limit: int = 20
    offset: int = 0

class OrklSearchRequest(BaseModel):
    query: str = ""
    limit: int = 20
    offset: int = 0

@app.post("/api/vt-relation")
def vt_relation(req: VTRelationRequest):
    indicator = (req.indicator or "").strip()
    rel_type = (req.type or "").strip()
    relation = (req.relation or "").strip()
    if not indicator or not rel_type or not relation:
        raise HTTPException(status_code=400, detail="Missing indicator, type, or relation")
    for field in (indicator, rel_type, relation):
        if "\n" in field or "\r" in field:
            raise HTTPException(status_code=400, detail="Invalid vt-relation field.")
    res = query_vt_relation(indicator, rel_type, relation, req.vt_key)
    return res


# ============================================================================
# VIRUSTOTAL LIVEHUNT & RETROHUNT MONITORING
# ============================================================================

class VTLivehuntRulesetCreate(BaseModel):
    name: str = ""
    rules: str = ""
    enabled: bool = True
    notification_emails: list = []
    vt_key: str = ""

class VTLivehuntRulesetUpdate(BaseModel):
    name: Optional[str] = None
    rules: Optional[str] = None
    enabled: Optional[bool] = None
    notification_emails: Optional[list] = None
    vt_key: str = ""

class VTRetrohuntJobCreate(BaseModel):
    rules: str = ""
    corpus: str = "main"
    notification_emails: list = []
    vt_key: str = ""

class VTBatchDeleteRequest(BaseModel):
    ids: list = []
    vt_key: str = ""

@app.get("/api/vt/hunting/status")
def vt_hunting_status(vt_key: str = "", x_vt_key: Optional[str] = Header(None)):
    key = x_vt_key or vt_key
    return vt_hunting_mod.get_hunting_status(key)

@app.get("/api/vt/hunting/rulesets")
def vt_hunting_rulesets_list(limit: int = 40, cursor: Optional[str] = None, filter: Optional[str] = None, vt_key: str = "", x_vt_key: Optional[str] = Header(None)):
    key = x_vt_key or vt_key
    return vt_hunting_mod.list_rulesets(key, limit=limit, cursor=cursor, filter_str=filter)

@app.post("/api/vt/hunting/rulesets")
def vt_hunting_ruleset_create(req: VTLivehuntRulesetCreate, x_vt_key: Optional[str] = Header(None)):
    key = x_vt_key or req.vt_key
    return vt_hunting_mod.create_ruleset(key, req.name, req.rules, enabled=req.enabled, notification_emails=req.notification_emails)

@app.get("/api/vt/hunting/rulesets/{ruleset_id}")
def vt_hunting_ruleset_get(ruleset_id: str, vt_key: str = "", x_vt_key: Optional[str] = Header(None)):
    key = x_vt_key or vt_key
    return vt_hunting_mod.get_ruleset(key, ruleset_id)

@app.patch("/api/vt/hunting/rulesets/{ruleset_id}")
def vt_hunting_ruleset_update(ruleset_id: str, req: VTLivehuntRulesetUpdate, x_vt_key: Optional[str] = Header(None)):
    key = x_vt_key or req.vt_key
    return vt_hunting_mod.update_ruleset(key, ruleset_id, name=req.name, rules=req.rules, enabled=req.enabled, notification_emails=req.notification_emails)

@app.delete("/api/vt/hunting/rulesets/{ruleset_id}")
def vt_hunting_ruleset_delete(ruleset_id: str, vt_key: str = "", x_vt_key: Optional[str] = Header(None)):
    key = x_vt_key or vt_key
    return vt_hunting_mod.delete_ruleset(key, ruleset_id)

@app.get("/api/vt/hunting/notifications")
def vt_hunting_notifications_list(limit: int = 40, cursor: Optional[str] = None, filter: Optional[str] = None, vt_key: str = "", x_vt_key: Optional[str] = Header(None)):
    key = x_vt_key or vt_key
    return vt_hunting_mod.list_notifications(key, limit=limit, cursor=cursor, filter_str=filter)

@app.delete("/api/vt/hunting/notifications/{notification_id}")
def vt_hunting_notification_delete(notification_id: str, vt_key: str = "", x_vt_key: Optional[str] = Header(None)):
    key = x_vt_key or vt_key
    return vt_hunting_mod.delete_notification(key, notification_id)

@app.post("/api/vt/hunting/notifications/delete-batch")
def vt_hunting_notifications_delete_batch(req: VTBatchDeleteRequest, x_vt_key: Optional[str] = Header(None)):
    key = x_vt_key or req.vt_key
    return vt_hunting_mod.delete_notifications_batch(key, req.ids)

@app.get("/api/vt/hunting/notifications/{notification_id}/files")
def vt_hunting_notification_files(notification_id: str, vt_key: str = "", x_vt_key: Optional[str] = Header(None)):
    key = x_vt_key or vt_key
    return vt_hunting_mod.get_notification_files(key, notification_id)

@app.get("/api/vt/retrohunt/jobs")
def vt_retrohunt_jobs_list(limit: int = 20, vt_key: str = "", x_vt_key: Optional[str] = Header(None)):
    key = x_vt_key or vt_key
    return vt_hunting_mod.list_retrohunt_jobs(key, limit=limit)

@app.post("/api/vt/retrohunt/jobs")
def vt_retrohunt_job_create(req: VTRetrohuntJobCreate, x_vt_key: Optional[str] = Header(None)):
    key = x_vt_key or req.vt_key
    return vt_hunting_mod.create_retrohunt_job(key, req.rules, corpus=req.corpus, notification_emails=req.notification_emails)

@app.get("/api/vt/retrohunt/jobs/{job_id}")
def vt_retrohunt_job_get(job_id: str, vt_key: str = "", x_vt_key: Optional[str] = Header(None)):
    key = x_vt_key or vt_key
    return vt_hunting_mod.get_retrohunt_job(key, job_id)

@app.post("/api/vt/retrohunt/jobs/{job_id}/abort")
def vt_retrohunt_job_abort(job_id: str, vt_key: str = "", x_vt_key: Optional[str] = Header(None)):
    key = x_vt_key or vt_key
    return vt_hunting_mod.abort_retrohunt_job(key, job_id)

@app.delete("/api/vt/retrohunt/jobs/{job_id}")
def vt_retrohunt_job_delete(job_id: str, vt_key: str = "", x_vt_key: Optional[str] = Header(None)):
    key = x_vt_key or vt_key
    return vt_hunting_mod.delete_retrohunt_job(key, job_id)

@app.get("/api/vt/retrohunt/jobs/{job_id}/matches")
def vt_retrohunt_job_matches(job_id: str, limit: int = 40, cursor: Optional[str] = None, vt_key: str = "", x_vt_key: Optional[str] = Header(None)):
    key = x_vt_key or vt_key
    return vt_hunting_mod.get_retrohunt_matches(key, job_id, limit=limit, cursor=cursor)

@app.post("/api/threatfox-ioc-detail")
def threatfox_ioc_detail(req: ThreatFoxDetailRequest):
    ioc_id = _require_id(req.ioc_id, "ThreatFox IOC ID", _SAFE_ID_RE)
    return query_threatfox_ioc(ioc_id, req.abusech_key)

@app.post("/api/abuseipdb-reports")
def abuseipdb_reports(req: AbuseIPDBReportsRequest):
    # Lazy report history with documented pagination. Read-only; the backend
    # helper only allowlists passive AbuseIPDB endpoints.
    ip = (req.ip or "").strip()
    if not ip or "\n" in ip or "\r" in ip or len(ip) > 64 or not re.match(r"^[A-Za-z0-9.:]+$", ip):
        raise HTTPException(status_code=400, detail="Invalid AbuseIPDB IP.")
    return query_abuseipdb_reports(ip, req.abuseipdb_key, max_age=req.max_age, page=req.page, per_page=req.per_page)

@app.post("/api/malshare-limit")
def malshare_limit(req: MalShareLimitRequest):
    # Quota awareness only; never cached, never logged.
    return query_malshare_limit(req.malshare_key)

@app.post("/api/malshare-feed")
def malshare_feed(req: MalShareFeedRequest):
    # Backend-ready recent-24h feed (list/sources/filenames). Manual use only,
    # never called during normal lookups.
    feed = (req.feed or "").strip().lower()
    if feed not in {"list", "sources", "filenames"}:
        raise HTTPException(status_code=400, detail="Invalid MalShare feed (list/sources/filenames).")
    return query_malshare_feed(feed, req.malshare_key)

@app.post("/api/dnsdumpster-more")
def dnsdumpster_more(req: DNSDumpsterMoreRequest):
    # Lazy Plus pagination (?page=N). Read-only; never fetched by default.
    raw_domain = (req.domain or "").strip()
    if not raw_domain or "\n" in raw_domain or "\r" in raw_domain or len(raw_domain) > 253:
        raise HTTPException(status_code=400, detail="Invalid DNSDumpster domain.")
    domain = normalize_domain(raw_domain)
    if not is_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid DNSDumpster domain.")
    try:
        page = max(2, int(req.page or 2))
    except (TypeError, ValueError):
        page = 2
    return query_dnsdumpster(domain, req.dnsdumpster_key, page=page)

@app.post("/api/dnsdumpster-map")
def dnsdumpster_map(req: DNSDumpsterMapRequest):
    # Lazy Plus domain map (?map=1, base64). Never fetched by default.
    raw_domain = (req.domain or "").strip()
    if not raw_domain or "\n" in raw_domain or "\r" in raw_domain or len(raw_domain) > 253:
        raise HTTPException(status_code=400, detail="Invalid DNSDumpster domain.")
    domain = normalize_domain(raw_domain)
    if not is_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid DNSDumpster domain.")
    return query_dnsdumpster_map(domain, req.dnsdumpster_key)

class ValidinLazyRequest(BaseModel):
    kind: str = ""
    indicator: str = ""
    value: str = ""
    query_type: str = ""
    limit: int = 1000
    validin_key: str = ""

class ValidinFingerprintRequest(BaseModel):
    kind: str = "fingerprint"
    value: str = ""
    validin_key: str = ""
    limit: int = 100

class ValidinThreatRequest(BaseModel):
    kind: str = ""
    value: str = ""
    validin_key: str = ""

_VALIDIN_LAZY_KINDS = {"dns-history", "dns-extra", "subdomains", "certificates",
                       "pivots", "crawl-history", "osint-history", "ptr",
                       "registration-history", "advanced"}
_VALIDIN_FP_KINDS = {"fingerprint", "cert_hash", "jarm", "header_hash"}
_VALIDIN_THREAT_KINDS = {"names", "group", "indicators"}
_VALIDIN_INFRA_QUERY = re.compile(r"^(validin_)?(ip|domain|cidr|wildcard|fingerprint|cert_hash|jarm|header_hash)$")

@app.post("/api/validin-lazy")
def validin_lazy(req: ValidinLazyRequest):
    # Passive history-heavy retrieval only. Kind allowlist mirrors the
    # backend; Enterprise-only kinds fail closed with a plan message.
    kind = (req.kind or "").strip().lower()
    if kind not in _VALIDIN_LAZY_KINDS:
        raise HTTPException(status_code=400, detail=f"Unknown Validin lookup kind: {req.kind}")
    indicator = (req.indicator or "").strip()
    if not indicator or "\n" in indicator or "\r" in indicator or len(indicator) > 500:
        raise HTTPException(status_code=400, detail="Invalid Validin lookup value.")
    try:
        limit = max(1, min(int(req.limit or 1000), 20000))
    except (TypeError, ValueError):
        limit = 1000
    return query_validin_lazy(kind, indicator, req.validin_key,
                              value=(req.value or "").strip()[:500],
                              limit=limit, query_type=(req.query_type or "").strip()[:64])

@app.post("/api/validin-fingerprint")
def validin_fingerprint(req: ValidinFingerprintRequest):
    # Infrastructure fingerprint pivots only (cert/JARM/header hashes).
    # Never reachable from malware Hash Lookup; Infra Search only.
    kind = (req.kind or "fingerprint").strip().lower()
    if kind not in _VALIDIN_FP_KINDS:
        raise HTTPException(status_code=400, detail=f"Unknown Validin fingerprint kind: {req.kind}")
    value = (req.value or "").strip()
    if not value or "\n" in value or "\r" in value or len(value) > 256:
        raise HTTPException(status_code=400, detail="Invalid Validin fingerprint value.")
    try:
        limit = max(1, min(int(req.limit or 100), 1000))
    except (TypeError, ValueError):
        limit = 100
    out = query_validin_fingerprint(value, kind, req.validin_key, limit=limit)
    if out.get("error") and "Unknown Validin fingerprint kind" in out["error"]:
        raise HTTPException(status_code=400, detail=out["error"])
    return out

@app.post("/api/validin-threat")
def validin_threat(req: ValidinThreatRequest):
    # Verified /api/threat/* paths only (names, group summary, indicators).
    kind = (req.kind or "").strip().lower()
    if kind not in _VALIDIN_THREAT_KINDS:
        raise HTTPException(status_code=400, detail=f"Unknown Validin threat lookup: {req.kind}")
    value = (req.value or "").strip()
    if len(value) > 128 or "\n" in value or "\r" in value:
        raise HTTPException(status_code=400, detail="Invalid Validin threat key.")
    return query_validin_threat(kind, value, req.validin_key)

@app.post("/api/validin-infra")
def validin_infra(req: ValidinLazyRequest):
    # Typed Infra Search dispatcher (explicit types only, no generic proxy).
    qtype = (req.query_type or req.kind or "").strip().lower()
    if not _VALIDIN_INFRA_QUERY.match(qtype or ""):
        raise HTTPException(status_code=400, detail=f"Unknown Validin Infra Search type: {req.query_type or req.kind}")
    value = (req.indicator or req.value or "").strip()
    if not value or "\n" in value or "\r" in value or len(value) > 500:
        raise HTTPException(status_code=400, detail="Invalid Validin Infra Search value.")
    if qtype in ("cidr", "validin_cidr"):
        try:
            net = ipaddress.ip_network(value, strict=False)
            if "/" not in value or not 8 <= net.prefixlen <= 128:
                raise ValueError("bad prefix")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid CIDR for Validin Infra Search (e.g. 192.0.2.0/24).")
    return query_validin_infra(value, qtype, req.validin_key)

class ShodanLazyRequest(BaseModel):
    kind: str = ""
    ip: str = ""
    query: str = ""
    query_type: str = "shodan_query"
    page: int = 2
    shodan_key: str = ""

@app.post("/api/shodan-lazy")
def shodan_lazy(req: ShodanLazyRequest):
    # Passive Shodan only. No scan/rescan, alert, monitor or notifier paths are
    # exposed here; helpers use a fixed read-only allowlist.
    kind = (req.kind or "").strip().lower()
    if kind == "history":
        ip = normalize_ip(req.ip)
        if not is_ip(ip):
            raise HTTPException(status_code=400, detail="Invalid Shodan IP.")
        return query_shodan_host_history(ip, req.shodan_key)
    if kind == "search-page":
        query = (req.query or "").strip()
        if not query or "\n" in query or "\r" in query or len(query) > 500:
            raise HTTPException(status_code=400, detail="Invalid Shodan query.")
        try:
            page = max(2, min(int(req.page or 2), 100))
        except (TypeError, ValueError):
            page = 2
        return query_shodan_search(query, req.shodan_key, page=page, query_type=req.query_type or "shodan_query")
    if kind in {"domain", "domain-dns"}:
        domain = normalize_domain(req.query or req.ip)
        if not is_domain(domain):
            raise HTTPException(status_code=400, detail="Invalid Shodan domain.")
        return query_shodan_domain(domain, req.shodan_key)
    raise HTTPException(status_code=400, detail=f"Unknown Shodan lookup kind: {req.kind}")

class CensysLazyRequest(BaseModel):
    kind: str = ""
    ip: str = ""
    query: str = ""
    query_type: str = "censys_query"
    page_token: str = ""
    field: str = "ports"
    asset_id: str = ""
    fingerprint: str = ""
    days: int = 31
    censys_key: str = ""

@app.post("/api/censys-lazy")
def censys_lazy(req: CensysLazyRequest):
    # Passive Censys Platform only. POST search/aggregate are read-only; Live
    # Rescan, collections, tags, accounts and other write paths are not exposed.
    kind = (req.kind or "").strip().lower()
    if kind == "history":
        ip = normalize_ip(req.ip)
        if not is_ip(ip):
            raise HTTPException(status_code=400, detail="Invalid Censys IP.")
        return query_censys_host_timeline(ip, req.censys_key, days=req.days)
    if kind == "search-page":
        query = (req.query or "").strip()
        token = (req.page_token or "").strip()
        if not query or "\n" in query or "\r" in query or len(query) > 800 or len(token) > 500:
            raise HTTPException(status_code=400, detail="Invalid Censys query.")
        return query_censys_search(query, req.censys_key, query_type=req.query_type or "censys_query", page_token=token)
    if kind == "aggregate":
        query = (req.query or "").strip()
        if not query or "\n" in query or "\r" in query or len(query) > 800:
            raise HTTPException(status_code=400, detail="Invalid Censys aggregate query.")
        return query_censys_aggregate(query, req.field or "ports", req.censys_key, query_type=req.query_type or "censys_query")
    if kind == "certificate":
        return query_censys_certificate(req.fingerprint or req.asset_id or req.query, req.censys_key)
    if kind == "web-property":
        asset = (req.asset_id or req.query or "").strip()
        if not asset or "\n" in asset or "\r" in asset or len(asset) > 300:
            raise HTTPException(status_code=400, detail="Invalid Censys web property.")
        return query_censys_webproperty(asset, req.censys_key)
    raise HTTPException(status_code=400, detail=f"Unknown Censys lookup kind: {req.kind}")

class SilentPushLazyRequest(BaseModel):
    kind: str = ""
    indicator: str = ""
    query: str = ""
    query_type: str = ""
    record: str = "ANY"
    direction: str = ""
    limit: int = 100
    silentpush_key: str = ""

@app.post("/api/silentpush-lazy")
def silentpush_lazy(req: SilentPushLazyRequest):
    # Passive Silent Push retrieval only. This route is intentionally narrow:
    # no Live Scan, screenshot-on-demand, feed edits, tags, monitors or generic
    # API proxy behavior is exposed.
    kind = (req.kind or "").strip().lower()
    value = (req.indicator or req.query or "").strip()
    if not value or "\n" in value or "\r" in value or len(value) > 1000:
        raise HTTPException(status_code=400, detail="Invalid Silent Push lookup value.")
    try:
        limit = max(1, min(int(req.limit or 100), 1000))
    except (TypeError, ValueError):
        limit = 100
    if kind in {"padns", "padns-forward", "padns-reverse"}:
        direction = (req.direction or ("reverse" if kind == "padns-reverse" else "forward")).strip().lower()
        record = (req.record or "ANY").strip().upper()
        return query_silent_push_padns(value, req.silentpush_key, direction=direction, record=record, limit=limit)
    if kind == "domain-search":
        return query_silent_push_domain_search(value, req.silentpush_key, limit=min(limit, 250))
    if kind in {"scan-data", "spql"}:
        query_type = (req.query_type or ("spql" if kind == "spql" else "auto")).strip().lower()
        return query_silent_push_scan_data(value, req.silentpush_key, limit=min(limit, 250), query_type=query_type)
    raise HTTPException(status_code=400, detail=f"Unknown Silent Push lookup kind: {req.kind}")

class DriftnetLazyRequest(BaseModel):
    kind: str = ""
    dataset: str = "protocols"
    indicator: str = ""
    query: str = ""
    query_type: str = "auto"
    page: int = 0
    most_recent: bool = True
    summarize: str = ""
    from_date: str = ""
    to_date: str = ""
    filter: str = ""
    driftnet_key: str = ""

_DRIFTNET_LAZY_DATASETS = {
    "protocols", "protocol_body", "body", "ports", "ipports", "domains", "domain_scans",
    "fdns", "mx", "txt", "rdns", "domain_whois", "domain_reverse", "ip_whois",
    "ip_pocs", "ip_pwhois", "bgp", "rwhois", "routes", "ip_rdns", "ip_reverse",
    "ct", "favicons", "ja4", "ja4t", "jarm",
}
_DRIFTNET_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

@app.post("/api/driftnet-lazy")
def driftnet_lazy(req: DriftnetLazyRequest):
    # Passive Driftnet retrieval only. This route accepts dataset names and
    # search expressions, never provider paths, and the backend client enforces
    # an additional passive endpoint allowlist.
    kind = (req.kind or "dataset").strip().lower()
    if any(marker in kind for marker in ("prioritize", "scan-on-demand", "live-scan", "submit", "monitor")):
        raise HTTPException(status_code=400, detail="Driftnet active collection endpoints are not available.")
    if kind == "quota":
        return query_driftnet_user(req.driftnet_key)
    dataset = (req.dataset or "protocols").strip().lower()
    if dataset not in _DRIFTNET_LAZY_DATASETS:
        raise HTTPException(status_code=400, detail="Invalid Driftnet dataset.")
    value = (req.indicator or req.query or "").strip()
    if not value or "\n" in value or "\r" in value or len(value) > 1000:
        raise HTTPException(status_code=400, detail="Invalid Driftnet lookup value.")
    for text in (value, req.query_type or "", req.summarize or "", req.filter or ""):
        if any(marker in text.lower() for marker in ("prioritize", "scan-on-demand", "live-scan", "/submit", "/monitor")):
            raise HTTPException(status_code=400, detail="Driftnet active collection terms are not available.")
    if req.from_date and not _DRIFTNET_DATE_RE.match(req.from_date):
        raise HTTPException(status_code=400, detail="Invalid Driftnet from date.")
    if req.to_date and not _DRIFTNET_DATE_RE.match(req.to_date):
        raise HTTPException(status_code=400, detail="Invalid Driftnet to date.")
    try:
        page = max(0, min(int(req.page or 0), 99))
    except (TypeError, ValueError):
        page = 0
    if kind in {"dataset", "page", "search", "body-search"}:
        if kind == "body-search":
            dataset = "body"
        return query_driftnet_search(
            value,
            req.driftnet_key,
            dataset=dataset,
            query_type=req.query_type or "auto",
            page=page,
            most_recent=bool(req.most_recent),
            summarize=(req.summarize or "").strip(),
            from_date=(req.from_date or "").strip(),
            to_date=(req.to_date or "").strip(),
            filter_value=(req.filter or "").strip(),
        )
    raise HTTPException(status_code=400, detail=f"Unknown Driftnet lookup kind: {req.kind}")

@app.post("/api/orkl/report")
def orkl_report(req: OrklIdRequest):
    report_id = _require_id(req.id, "ORKL report ID", _SAFE_ID_RE)
    return query_orkl_library_entry(report_id)

@app.post("/api/orkl/search")
def orkl_search(req: OrklSearchRequest):
    query = (req.query or "").strip()
    if not query or "\n" in query or "\r" in query or len(query) > 500:
        raise HTTPException(status_code=400, detail="Invalid ORKL search query.")
    return query_orkl(query, limit=max(1, min(req.limit, 50)), offset=max(0, req.offset))

@app.post("/api/orkl/report-sha1")
def orkl_report_sha1(req: OrklIdRequest):
    sha1 = _require_id(req.id, "ORKL report SHA-1", re.compile(r"^[A-Fa-f0-9]{40}$"))
    return query_orkl_report_sha1(sha1)

@app.post("/api/orkl/actor")
def orkl_actor(req: OrklIdRequest):
    actor_id = _require_id(req.id, "ORKL threat actor ID", _SAFE_ID_RE)
    return query_orkl_threat_actor(actor_id)

@app.get("/api/orkl/actors")
def orkl_actors(limit: int = 50, offset: int = 0):
    return query_orkl_threat_actors(limit=max(1, min(limit, 100)), offset=max(0, offset))

@app.post("/api/orkl/source")
def orkl_source(req: OrklIdRequest):
    source_id = _require_id(req.id, "ORKL source ID", _SAFE_ID_RE)
    return query_orkl_source(source_id)

@app.get("/api/orkl/sources")
def orkl_sources(limit: int = 50, offset: int = 0):
    return query_orkl_sources(limit=max(1, min(limit, 100)), offset=max(0, offset))

@app.get("/api/orkl/news")
def orkl_news(limit: int = 20, offset: int = 0):
    return query_orkl_news(limit=max(1, min(limit, 100)), offset=max(0, offset))

class URLScanDownloadedFileRequest(BaseModel):
    sha256: str
    urlscan_key: str = ""

class OSVQueryRequest(BaseModel):
    package_name: str = ""
    ecosystem: str = ""
    version: str = ""
    commit: str = ""
    purl: str = ""

class OtxPulseIndicatorsRequest(BaseModel):
    pulse_id: str = ""
    otx_key: str = ""
    limit: int = 100

class TriageReportRequest(BaseModel):
    sample_id: str = ""
    task_id: str = ""
    report: str = "overview"
    triage_key: str = ""

class TriageDownloadRequest(BaseModel):
    sample_id: str = ""
    task_id: str = ""
    kind: str = "sample"
    triage_key: str = ""

@app.post("/api/otx-pulse-indicators")
def otx_pulse_indicators(req: OtxPulseIndicatorsRequest):
    pid = _require_id(req.pulse_id, "Pulse ID", _HEX_ID_RE)
    return query_otx_pulse_indicators(pid, req.otx_key, req.limit)

# Official Triage download endpoints (verified against tria.ge API docs):
#   sample -> GET /samples/{sampleID}/sample
#   pcap   -> GET /samples/{sampleID}/{taskID}/dump.pcap
#   pcapng -> GET /samples/{sampleID}/{taskID}/dump.pcapng
TRIAGE_DOWNLOADS = {
    "sample": {"path": lambda sid, tid: f"/samples/{sid}/sample", "media": "application/octet-stream", "ext": "bin", "needs_task": False},
    "pcap": {"path": lambda sid, tid: f"/samples/{sid}/{tid}/dump.pcap", "media": "application/octet-stream", "ext": "pcap", "needs_task": True},
    "pcapng": {"path": lambda sid, tid: f"/samples/{sid}/{tid}/dump.pcapng", "media": "application/octet-stream", "ext": "pcapng", "needs_task": True},
}

@app.post("/api/triage-report")
def triage_report(req: TriageReportRequest):
    sid = _require_id(req.sample_id, "Triage sample ID", _SAFE_ID_RE)
    kind = (req.report or "overview").strip().lower()
    if kind == "overview":
        return query_triage_overview(sid, req.triage_key)
    if kind == "summary":
        return query_triage_summary(sid, req.triage_key)
    if kind == "static":
        return query_triage_static(sid, req.triage_key)
    if kind in {"behavioral", "dynamic", "triage"}:
        tid = _require_id(req.task_id, "Triage task ID", _SAFE_ID_RE)
        return query_triage_behavioral(sid, tid, req.triage_key)
    raise HTTPException(status_code=400, detail=f"Unknown Triage report type: {req.report}")

@app.post("/api/triage-download")
def triage_download(req: TriageDownloadRequest):
    import requests as _rq
    sid = _require_id(req.sample_id, "Triage sample ID", _SAFE_ID_RE)
    if not req.triage_key:
        raise HTTPException(status_code=400, detail="Missing Triage API key")
    kind = (req.kind or "sample").strip().lower()
    spec = TRIAGE_DOWNLOADS.get(kind)
    if spec is None:
        raise HTTPException(status_code=400, detail=f"Unknown Triage download kind: {req.kind}")
    tid = ""
    if spec["needs_task"]:
        tid = _require_id(req.task_id, "Triage task ID", _SAFE_ID_RE)
    headers = {"Authorization": f"Bearer {req.triage_key}"}
    # IDs are validated above; never follow arbitrary user-controlled URLs.
    url = f"https://api.tria.ge/v0{spec['path'](sid, tid)}"
    filename = f"triage_{sid}_{tid + '_' if tid else ''}{kind}.{spec['ext']}"
    media = spec["media"]
    # Stream with a byte cap: samples/pcaps can be huge and must never be
    # fully buffered in worker RAM.
    cap = YARA_MAX_TEST_BYTES
    try:
        resp = _rq.get(url, headers=headers, timeout=60, stream=True)
        if resp.status_code != 200:
            resp.close()
            raise HTTPException(status_code=resp.status_code, detail=f"Triage download failed: HTTP {resp.status_code}")
        try:
            known = int(resp.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            known = 0
        if known > cap:
            resp.close()
            raise HTTPException(status_code=413, detail=f"Triage download exceeds {cap} bytes")
        from fastapi.responses import StreamingResponse

        def _chunks():
            total = 0
            try:
                for chunk in resp.iter_content(1024 * 256):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > cap:
                        break  # truncate; known-size case was rejected above
                    yield chunk
            finally:
                resp.close()

        return StreamingResponse(_chunks(), media_type=media,
                                 headers={"Content-Disposition": f'attachment; filename="{filename}"'})
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Triage download failed: {e}")

class CbMoreRequest(BaseModel):
    kind: str = "search"
    query: str = ""
    cb_key: str = ""
    limit: int = 20
    offset: int = 0

@app.post("/api/cb-more")
def cb_more(req: CbMoreRequest):
    query = (req.query or "").strip()
    if not query or "\n" in query or "\r" in query:
        raise HTTPException(status_code=400, detail="Invalid CyberBriefing query.")
    if len(query) > 500:
        raise HTTPException(status_code=400, detail="Invalid CyberBriefing query.")
    kind = (req.kind or "search").strip().lower()
    try:
        limit = max(1, min(int(req.limit or 20), 100))
    except (TypeError, ValueError):
        limit = 20
    try:
        offset = max(0, int(req.offset or 0))
    except (TypeError, ValueError):
        offset = 0
    if kind == "search":
        return query_cb_search(query, req.cb_key, limit=limit, offset=offset)
    if kind == "iocs":
        return query_cb_ioc_search(query, req.cb_key, limit=limit, offset=offset)
    if kind == "threats":
        return query_cb_threats(query, req.cb_key, limit=limit, offset=offset)
    if kind == "cves":
        return query_cb_cves(query, req.cb_key, limit=limit, offset=offset)
    raise HTTPException(status_code=400, detail=f"Unknown CyberBriefing listing kind: {req.kind}")

class HaReportRequest(BaseModel):
    report_id: str = ""
    ha_key: str = ""

class TwitterLazyRequest(BaseModel):
    kind: str = ""
    value: str = ""
    twitter_key: str = ""
    cursor: str = ""
    query_kind: str = "Latest"
    query_type: str = "all"

_GITHUB_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_GITHUB_LOGIN_RE = re.compile(r"^[A-Za-z0-9-]{1,39}$")
_GITHUB_SHA_RE = re.compile(r"^[A-Fa-f0-9]{7,40}$")

class GitHubLazyRequest(BaseModel):
    kind: str = ""
    query: str = ""
    query_type: str = "keyword"
    repo: str = ""
    username: str = ""
    org: str = ""
    sha: str = ""
    path: str = ""
    author: str = ""
    committer: str = ""
    since: str = ""
    until: str = ""
    state: str = "all"
    issue_number: int = 0
    page: int = 1
    per_page: int = 10
    github_key: str = ""

def _require_github_repo(value: str) -> str:
    repo = (value or "").strip()
    if not _GITHUB_REPO_RE.match(repo):
        raise HTTPException(status_code=400, detail="Invalid GitHub repository. Expected owner/repo.")
    return repo

def _require_github_login(value: str, label: str) -> str:
    login = (value or "").strip().lstrip("@")
    if not _GITHUB_LOGIN_RE.match(login):
        raise HTTPException(status_code=400, detail=f"Invalid GitHub {label}.")
    return login

def _github_page(value: int) -> int:
    try:
        return max(1, min(int(value or 1), 100))
    except (TypeError, ValueError):
        return 1

def _github_per_page(value: int, default: int = 10) -> int:
    try:
        return max(1, min(int(value or default), 50))
    except (TypeError, ValueError):
        return default

@app.post("/api/github-lazy")
def github_lazy(req: GitHubLazyRequest):
    # Passive GitHub CTI only. This is an allowlisted dispatcher to local
    # GET-only helpers, not a generic GitHub API proxy.
    kind = (req.kind or "").strip().lower()
    if kind == "search":
        query = (req.query or "").strip()
        if not query or "\n" in query or "\r" in query or len(query) > 500:
            raise HTTPException(status_code=400, detail="Invalid GitHub search query.")
        return query_github_search(query, req.query_type or "keyword", req.github_key,
                                   per_page=_github_per_page(req.per_page),
                                   page=_github_page(req.page))
    if kind == "repo-search":
        query = (req.query or "").strip()
        if not query or "\n" in query or "\r" in query or len(query) > 500:
            raise HTTPException(status_code=400, detail="Invalid GitHub repository search query.")
        return query_github_search(query, "repository", req.github_key,
                                   per_page=_github_per_page(req.per_page),
                                   page=_github_page(req.page))
    if kind == "repo":
        return query_github_repo(_require_github_repo(req.repo), req.github_key)
    if kind == "commits":
        repo = _require_github_repo(req.repo)
        path = (req.path or "").strip()
        if path and ("\n" in path or "\r" in path or len(path) > 500):
            raise HTTPException(status_code=400, detail="Invalid GitHub path filter.")
        return query_github_commits(repo, req.github_key, path=path, author=req.author,
                                    since=req.since, until=req.until, page=_github_page(req.page))
    if kind == "commit":
        repo = _require_github_repo(req.repo)
        sha = (req.sha or "").strip()
        if not _GITHUB_SHA_RE.match(sha):
            raise HTTPException(status_code=400, detail="Invalid GitHub commit SHA.")
        return query_github_commit_detail(repo, sha, req.github_key)
    if kind == "readme":
        return query_github_readme(_require_github_repo(req.repo), req.github_key)
    if kind == "issues":
        repo = _require_github_repo(req.repo)
        state = (req.state or "all").strip().lower()
        if state not in {"open", "closed", "all"}:
            state = "all"
        return query_github_issues(repo, req.github_key, state=state, page=_github_page(req.page))
    if kind == "issue-comments":
        repo = _require_github_repo(req.repo)
        if req.issue_number <= 0:
            raise HTTPException(status_code=400, detail="Invalid GitHub issue number.")
        return query_github_issue_comments(repo, req.issue_number, req.github_key)
    if kind == "user":
        return query_github_user(_require_github_login(req.username or req.query, "username"), req.github_key)
    if kind == "user-repos":
        return query_github_user_repos(_require_github_login(req.username or req.query, "username"),
                                       req.github_key, page=_github_page(req.page))
    if kind == "org":
        return query_github_org(_require_github_login(req.org or req.query, "organization"), req.github_key)
    raise HTTPException(status_code=400, detail=f"Unknown GitHub lookup kind: {req.kind}")

@app.post("/api/twitter-lazy")
def twitter_lazy(req: TwitterLazyRequest):
    # Read-only lazy retrieval. The backend helper only allowlists passive
    # TwitterAPI.io endpoints; write/account actions are unreachable.
    kind = (req.kind or "").strip().lower()
    value = (req.value or "").strip()
    cursor = (req.cursor or "").strip()
    if len(cursor) > 500:
        raise HTTPException(status_code=400, detail="Invalid Twitter cursor.")
    if kind in {"tweet", "replies", "quotes", "thread"}:
        if not _TWEET_ID_RE.match(value or ""):
            raise HTTPException(status_code=400, detail="Invalid tweet ID.")
        if kind == "tweet":
            return query_twitter_tweet(value, req.twitter_key)
        if kind == "replies":
            return query_twitter_replies(value, req.twitter_key, cursor=cursor)
        if kind == "quotes":
            return query_twitter_quotes(value, req.twitter_key, cursor=cursor)
        return query_twitter_thread(value, req.twitter_key, cursor=cursor)
    if kind in {"user", "user_tweets", "follower_ids"}:
        if not _X_HANDLE_RE.match(value or ""):
            raise HTTPException(status_code=400, detail="Invalid X username.")
        if kind == "user":
            return query_twitter_user(value, req.twitter_key)
        if kind == "user_tweets":
            return query_twitter_user_tweets(value, req.twitter_key, cursor=cursor)
        return query_twitter_follower_ids(value, req.twitter_key, cursor=cursor)
    if kind == "user_search":
        if not value or len(value) > 64:
            raise HTTPException(status_code=400, detail="Invalid X username.")
        return query_twitter_user_search(value, req.twitter_key, cursor=cursor)
    if kind == "search_more":
        if not value or len(value) > 500:
            raise HTTPException(status_code=400, detail="Invalid Twitter search.")
        query_kind = (req.query_kind or "Latest").strip()
        if query_kind not in {"Latest", "Top"}:
            query_kind = "Latest"
        query_type = (req.query_type or "all").strip().lower() or "all"
        if query_type not in {"all", "tag", "malware_family", "threat_actor", "cve"}:
            query_type = "all"
        return query_twitter_search(value, req.twitter_key, query_type=query_type,
                                    query_kind=query_kind, cursor=cursor)
    raise HTTPException(status_code=400, detail=f"Unknown Twitter lookup kind: {req.kind}")

class MalwareNewsTopicRequest(BaseModel):
    topic_id: int = 0
    slug: str = ""

@app.post("/api/malware-news-topic")
def malware_news_topic(req: MalwareNewsTopicRequest):
    # Lazy topic enrichment (existing content only). Read-only Discourse GET.
    if not isinstance(req.topic_id, int) or req.topic_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid Malware.News topic ID.")
    slug = (req.slug or "").strip()
    if len(slug) > 200:
        raise HTTPException(status_code=400, detail="Invalid Malware.News topic slug.")
    return query_malware_news_topic(req.topic_id, slug)

@app.post("/api/ha-report")
def ha_report(req: HaReportRequest):
    # Lazy retrieval of ONE existing report. Read-only; the backend helper
    # only allowlists passive report endpoints (no submit/scan/rescan).
    report_id = (req.report_id or "").strip()
    if not report_id or "\n" in report_id or "\r" in report_id or "/" in report_id or len(report_id) > 128:
        raise HTTPException(status_code=400, detail="Invalid Hybrid Analysis report ID.")
    return query_ha_report(report_id, req.ha_key)

class RansomLookGroupRequest(BaseModel):
    group: str = ""

class RansomLookActorRequest(BaseModel):
    actor: str = ""

class RansomLookPostsRequest(BaseModel):
    days: int = 7

class RansomLookExportRequest(BaseModel):
    db: int = 0
    ransomlook_key: str = ""

class RansomwareLiveRequest(BaseModel):
    query: str = ""
    group: str = ""
    victim_id: str = ""
    note_name: str = ""
    chat_id: str = ""
    ioc_type: str = ""
    country: str = ""
    sector: str = ""
    year: str = ""
    month: str = ""
    date: str = ""
    rwlive_key: str = ""
    limit: int = 50
    offset: int = 0

class RansomwareMonitorRequest(BaseModel):
    id: str = ""
    watch_type: str = ""
    value: str = ""
    label: str = ""
    enabled: bool = True
    rwlive_key: str = ""
    q: str = ""
    group: str = ""
    region: str = ""
    country: str = ""
    sector: str = ""
    source: str = ""
    status: str = ""
    type: str = ""
    ioc_type: str = ""
    ticker: str = ""
    cik: str = ""
    year: str = ""
    month: str = ""
    item105: bool | None = None
    item801: bool | None = None
    date_range: str = ""
    sort: str = ""
    days: int = 30
    page: int = 1
    page_size: int = 50
    limit: int = 100

def _monitor_payload(req: RansomwareMonitorRequest) -> dict:
    return {
        "rwlive_key": req.rwlive_key,
        "q": req.q,
        "group": req.group,
        "region": req.region,
        "country": req.country,
        "sector": req.sector,
        "source": req.source,
        "status": req.status,
        "type": req.type,
        "ioc_type": req.ioc_type,
        "ticker": req.ticker,
        "cik": req.cik,
        "year": req.year,
        "month": req.month,
        "item105": req.item105,
        "item801": req.item801,
        "date_range": req.date_range,
        "sort": req.sort,
        "days": req.days,
        "page": req.page,
        "page_size": req.page_size,
        "limit": req.limit,
    }

@app.post("/api/ransomlook-group")
def ransomlook_group(req: RansomLookGroupRequest):
    group = (req.group or "").strip()
    if not group or "\n" in group or "\r" in group or len(group) > 200:
        raise HTTPException(status_code=400, detail="Invalid RansomLook group.")
    return query_ransomlook_group_or_search(group)

@app.post("/api/ransomlook-actor")
def ransomlook_actor(req: RansomLookActorRequest):
    actor = (req.actor or "").strip()
    if not actor or "\n" in actor or "\r" in actor or len(actor) > 200:
        raise HTTPException(status_code=400, detail="Invalid RansomLook actor.")
    return query_ransomlook_actor_or_search(actor)

@app.post("/api/ransomlook-posts")
def ransomlook_posts(req: RansomLookPostsRequest):
    try:
        days = max(1, min(int(req.days or 7), 90))
    except (TypeError, ValueError):
        days = 7
    return query_ransomlook_posts(days)

@app.post("/api/ransomlook-export")
def ransomlook_export(req: RansomLookExportRequest):
    # Manual dataset refresh only — never called during normal IOC lookups.
    return query_ransomlook_export(req.db, req.ransomlook_key)

@app.post("/api/ransomware-monitor/overview")
def ransomware_monitor_overview(req: RansomwareMonitorRequest):
    return ransomware_monitor_mod.overview(req.days, req.rwlive_key)

@app.post("/api/ransomware-monitor/victims")
def ransomware_monitor_victims(req: RansomwareMonitorRequest):
    return ransomware_monitor_mod.victims_page(_monitor_payload(req))

@app.post("/api/ransomware-monitor/groups")
def ransomware_monitor_groups(req: RansomwareMonitorRequest):
    return ransomware_monitor_mod.groups_page(_monitor_payload(req))

@app.post("/api/ransomware-monitor/group-profile")
def ransomware_monitor_group_profile(req: RansomwareMonitorRequest):
    group = (req.group or req.q or "").strip()
    if not group or "\n" in group or "\r" in group or len(group) > 200:
        raise HTTPException(status_code=400, detail="Invalid ransomware group.")
    return ransomware_monitor_mod.group_profile(group, req.rwlive_key, req.days or 365)

@app.post("/api/ransomware-monitor/trends")
def ransomware_monitor_trends(req: RansomwareMonitorRequest):
    return ransomware_monitor_mod.trends(req.days, req.rwlive_key)

@app.post("/api/ransomware-monitor/regions")
def ransomware_monitor_regions(req: RansomwareMonitorRequest):
    return ransomware_monitor_mod.regions_page(_monitor_payload(req))

@app.post("/api/ransomware-monitor/infrastructure")
def ransomware_monitor_infrastructure(req: RansomwareMonitorRequest):
    return ransomware_monitor_mod.infrastructure_page(_monitor_payload(req))

@app.post("/api/ransomware-monitor/ransom-notes")
def ransomware_monitor_ransom_notes(req: RansomwareMonitorRequest):
    return ransomware_monitor_mod.ransom_notes_page(_monitor_payload(req))

@app.post("/api/ransomware-monitor/negotiations")
def ransomware_monitor_negotiations(req: RansomwareMonitorRequest):
    return ransomware_monitor_mod.negotiations_page(_monitor_payload(req))

@app.post("/api/ransomware-monitor/actors")
def ransomware_monitor_actors(req: RansomwareMonitorRequest):
    return ransomware_monitor_mod.actors_page(_monitor_payload(req))

@app.post("/api/ransomware-monitor/crypto")
def ransomware_monitor_crypto(req: RansomwareMonitorRequest):
    return ransomware_monitor_mod.crypto_page(_monitor_payload(req))

@app.post("/api/ransomware-monitor/ttps-vulnerabilities")
def ransomware_monitor_ttps_vulnerabilities(req: RansomwareMonitorRequest):
    return ransomware_monitor_mod.ttps_vulnerabilities_page(_monitor_payload(req))

@app.post("/api/ransomware-monitor/press-8k")
def ransomware_monitor_press_8k(req: RansomwareMonitorRequest):
    return ransomware_monitor_mod.press_8k_page(_monitor_payload(req))

@app.post("/api/ransomware-monitor/detection-iocs")
def ransomware_monitor_detection_iocs(req: RansomwareMonitorRequest):
    return ransomware_monitor_mod.detection_iocs_page(_monitor_payload(req))

@app.post("/api/ransomware-monitor/csirt-stats")
def ransomware_monitor_csirt_stats(req: RansomwareMonitorRequest):
    return ransomware_monitor_mod.csirt_stats_page(_monitor_payload(req))

@app.post("/api/ransomware-monitor/watchlist")
def ransomware_monitor_watchlist(req: RansomwareMonitorRequest):
    return ransomware_monitor_mod.watchlist_page(_monitor_payload(req))

@app.post("/api/ransomware-monitor/watchlist/add")
def ransomware_monitor_watchlist_add(req: RansomwareMonitorRequest):
    try:
        return {"entry": ransomware_monitor_mod.watchlist_add(req.watch_type or req.type, req.value, req.label, req.enabled)}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/ransomware-monitor/watchlist/delete")
def ransomware_monitor_watchlist_delete(req: RansomwareMonitorRequest):
    return ransomware_monitor_mod.watchlist_delete(req.id)

@app.post("/api/rwlive/group-victims")
def rwlive_group_victims(req: RansomwareLiveRequest):
    group = (req.group or req.query or "").strip()
    if not group or "\n" in group or "\r" in group or len(group) > 200:
        raise HTTPException(status_code=400, detail="Invalid ransomware.live group.")
    if req.year and not re.match(r"^\d{4}$", str(req.year).strip()):
        raise HTTPException(status_code=400, detail="Invalid ransomware.live year filter.")
    if req.month and not re.match(r"^(0?[1-9]|1[0-2])$", str(req.month).strip()):
        raise HTTPException(status_code=400, detail="Invalid ransomware.live month filter.")
    if req.date and not re.match(r"^\d{4}-\d{2}-\d{2}$", str(req.date).strip()):
        raise HTTPException(status_code=400, detail="Invalid ransomware.live date filter.")
    return query_ransomware_live_group_victims(group, req.rwlive_key, limit=req.limit, offset=req.offset, year=req.year, month=req.month, date=req.date)

@app.post("/api/rwlive/recent-victims")
def rwlive_recent_victims(req: RansomwareLiveRequest):
    return query_ransomware_live_recent_victims(req.rwlive_key, limit=req.limit, offset=req.offset)

@app.post("/api/rwlive/country-victims")
def rwlive_country_victims(req: RansomwareLiveRequest):
    country = (req.country or req.query or "").strip().upper()
    if not re.match(r"^[A-Z]{2}$", country):
        raise HTTPException(status_code=400, detail="ransomware.live country lookup requires an ISO-2 country code.")
    if req.year and not re.match(r"^\d{4}$", str(req.year).strip()):
        raise HTTPException(status_code=400, detail="Invalid ransomware.live year filter.")
    if req.month and not re.match(r"^(0?[1-9]|1[0-2])$", str(req.month).strip()):
        raise HTTPException(status_code=400, detail="Invalid ransomware.live month filter.")
    if req.date and not re.match(r"^\d{4}-\d{2}-\d{2}$", str(req.date).strip()):
        raise HTTPException(status_code=400, detail="Invalid ransomware.live date filter.")
    return query_ransomware_live_country(country, req.rwlive_key, limit=req.limit, offset=req.offset, year=req.year, month=req.month, date=req.date)

@app.post("/api/rwlive/sector-victims")
def rwlive_sector_victims(req: RansomwareLiveRequest):
    sector = (req.sector or req.query or "").strip()
    if not sector or "\n" in sector or "\r" in sector or len(sector) > 200:
        raise HTTPException(status_code=400, detail="Invalid ransomware.live sector.")
    if req.year and not re.match(r"^\d{4}$", str(req.year).strip()):
        raise HTTPException(status_code=400, detail="Invalid ransomware.live year filter.")
    if req.month and not re.match(r"^(0?[1-9]|1[0-2])$", str(req.month).strip()):
        raise HTTPException(status_code=400, detail="Invalid ransomware.live month filter.")
    if req.date and not re.match(r"^\d{4}-\d{2}-\d{2}$", str(req.date).strip()):
        raise HTTPException(status_code=400, detail="Invalid ransomware.live date filter.")
    return query_ransomware_live_sector(sector, req.rwlive_key, country_code=req.country, limit=req.limit, offset=req.offset, year=req.year, month=req.month, date=req.date)

@app.post("/api/rwlive/cyberattacks")
def rwlive_cyberattacks(req: RansomwareLiveRequest):
    country = (req.country or "").strip().upper()
    if country and not re.match(r"^[A-Z]{2}$", country):
        raise HTTPException(status_code=400, detail="ransomware.live country filter requires an ISO-2 country code.")
    if req.year and not re.match(r"^\d{4}$", str(req.year).strip()):
        raise HTTPException(status_code=400, detail="Invalid ransomware.live year filter.")
    if req.month and not re.match(r"^(0?[1-9]|1[0-2])$", str(req.month).strip()):
        raise HTTPException(status_code=400, detail="Invalid ransomware.live month filter.")
    return query_ransomware_live_cyberattacks(req.rwlive_key, recent=not bool(req.year or req.month), limit=req.limit, offset=req.offset, country=country, year=req.year, month=req.month)

@app.post("/api/rwlive/yara")
def rwlive_yara(req: RansomwareLiveRequest):
    group = (req.group or req.query or "").strip()
    if not group or "\n" in group or "\r" in group or len(group) > 200:
        raise HTTPException(status_code=400, detail="Invalid ransomware.live group.")
    return query_ransomware_live_yara(group, req.rwlive_key)

@app.post("/api/rwlive/victim-detail")
def rwlive_victim_detail(req: RansomwareLiveRequest):
    victim_id = _require_id(req.victim_id or req.query, "ransomware.live victim ID", _RWLIVE_VICTIM_ID_RE)
    return query_ransomware_live_victim_detail(victim_id, req.rwlive_key)

@app.post("/api/rwlive/iocs")
def rwlive_iocs(req: RansomwareLiveRequest):
    group = (req.group or req.query or "").strip()
    if group and ("\n" in group or "\r" in group or len(group) > 200):
        raise HTTPException(status_code=400, detail="Invalid ransomware.live group.")
    ioc_type = (req.ioc_type or "").strip().lower()
    if not _RWLIVE_IOC_TYPE_RE.match(ioc_type):
        raise HTTPException(status_code=400, detail="Invalid ransomware.live IOC type.")
    return query_ransomware_live_iocs(group, req.rwlive_key, ioc_type=ioc_type, limit=req.limit, offset=req.offset)

@app.post("/api/rwlive/ransom-notes")
def rwlive_ransom_notes(req: RansomwareLiveRequest):
    group = (req.group or req.query or "").strip()
    if not group or "\n" in group or "\r" in group or len(group) > 200:
        raise HTTPException(status_code=400, detail="Invalid ransomware.live group.")
    note_name = (req.note_name or "").strip()
    if note_name and not _SAFE_ID_RE.match(note_name):
        raise HTTPException(status_code=400, detail="Invalid ransomware.live ransom note identifier.")
    return query_ransomware_live_ransom_notes(group, req.rwlive_key, note_name=note_name, limit=req.limit, offset=req.offset)

@app.post("/api/rwlive/negotiations")
def rwlive_negotiations(req: RansomwareLiveRequest):
    group = (req.group or req.query or "").strip()
    if group and ("\n" in group or "\r" in group or len(group) > 200):
        raise HTTPException(status_code=400, detail="Invalid ransomware.live group.")
    chat_id = (req.chat_id or "").strip()
    if chat_id and not _SAFE_ID_RE.match(chat_id):
        raise HTTPException(status_code=400, detail="Invalid ransomware.live negotiation identifier.")
    return query_ransomware_live_negotiations(group, req.rwlive_key, chat_id=chat_id, limit=req.limit, offset=req.offset)

@app.post("/api/rwlive/stats")
def rwlive_stats(req: RansomwareLiveRequest):
    return query_ransomware_live_stats(req.rwlive_key)

@app.post("/api/rwlive/sectors")
def rwlive_sectors(req: RansomwareLiveRequest):
    return query_ransomware_live_sectors(req.rwlive_key)

@app.post("/api/rwlive/validate")
def rwlive_validate(req: RansomwareLiveRequest):
    return query_ransomware_live_validate(req.rwlive_key)

@app.post("/api/urlscan-downloaded-file")
def urlscan_downloaded_file(req: URLScanDownloadedFileRequest):
    file_hash = req.sha256.strip().lower()
    if not is_hash(file_hash) or len(file_hash) != 64:
        raise HTTPException(status_code=400, detail="URLScan downloaded-file pivot requires a SHA-256 hash.")
    return query_urlscan_downloaded_file(file_hash, req.urlscan_key)

class URLScanResultRequest(BaseModel):
    uuid: str = ""
    urlscan_key: str = ""

class URLScanMoreRequest(BaseModel):
    kind: str = ""
    value: str = ""
    urlscan_key: str = ""
    size: int = 25

@app.post("/api/urlscan-result")
def urlscan_result(req: URLScanResultRequest):
    # Lazy retrieval of ONE existing scan. Read-only; never submits/rescans.
    uuid = (req.uuid or "").strip().lower()
    if not re.match(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", uuid):
        raise HTTPException(status_code=400, detail="Invalid URLScan result UUID.")
    return query_urlscan_result(uuid, req.urlscan_key)

@app.post("/api/urlscan-more")
def urlscan_more(req: URLScanMoreRequest):
    # Pagination for historical searches: larger size window, same passive query.
    kind = (req.kind or "").strip().lower()
    value = (req.value or "").strip()
    if not value or "\n" in value or "\r" in value or len(value) > 2000:
        raise HTTPException(status_code=400, detail="Invalid URLScan search value.")
    try:
        size = max(1, min(int(req.size or 25), 100))
    except (TypeError, ValueError):
        size = 25
    if kind in {"domain", "ip", "url"}:
        return query_urlscan(value, kind, req.urlscan_key, size=size)
    if kind == "hash":
        return query_urlscan_hash(value, req.urlscan_key, size=size)
    if kind == "keyword":
        return query_urlscan_keyword(value, req.urlscan_key, size=size)
    if kind == "infra":
        return query_urlscan_infra(value, req.urlscan_key, size=size)
    raise HTTPException(status_code=400, detail=f"Unknown URLScan search kind: {req.kind}")

class ArchiveLazyRequest(BaseModel):
    kind: str = ""
    indicator: str = ""
    query_type: str = ""
    timestamp: str = ""
    original_url: str = ""
    limit: int = 50
    resume_key: str = ""
    from_ts: str = ""
    to_ts: str = ""
    status: str = ""
    mime: str = ""
    path: str = ""
    extension: str = ""

def _archive_lookup_type(value: str) -> str:
    kind = (value or "").strip().lower()
    if kind not in {"domain", "url"}:
        raise HTTPException(status_code=400, detail="Invalid Internet Archive query type.")
    return kind

def _archive_indicator(value: str, query_type: str) -> str:
    raw = (value or "").strip()
    if not raw or "\n" in raw or "\r" in raw or len(raw) > 2000:
        raise HTTPException(status_code=400, detail="Invalid Internet Archive indicator.")
    if query_type == "url":
        normalized = normalize_url(raw)
        if not normalized:
            raise HTTPException(status_code=400, detail="Invalid Internet Archive URL.")
        return normalized
    normalized = normalize_domain(raw)
    if not is_domain(normalized):
        raise HTTPException(status_code=400, detail="Invalid Internet Archive domain.")
    return normalized

@app.post("/api/archive-lazy")
def archive_lazy(req: ArchiveLazyRequest):
    # Passive Wayback intelligence only. This is not a generic Internet Archive
    # proxy and has no Save Page Now, upload, metadata, task, review or delete path.
    kind = (req.kind or "").strip().lower()
    if kind in {"historical-urls", "timeline"}:
        query_type = _archive_lookup_type(req.query_type)
        indicator = _archive_indicator(req.indicator, query_type)
        limit = max(1, min(int(req.limit or 50), 200))
        if kind == "historical-urls":
            return query_archive_historical_urls(
                indicator, query_type=query_type, limit=limit,
                resume_key=req.resume_key, from_ts=req.from_ts, to_ts=req.to_ts,
                status=req.status, mime=req.mime, path=req.path, extension=req.extension,
            )
        return query_archive_timeline(
            indicator, query_type=query_type, limit=limit,
            from_ts=req.from_ts, to_ts=req.to_ts, resume_key=req.resume_key,
        )
    if kind == "snapshot":
        timestamp = (req.timestamp or "").strip()
        if not re.match(r"^\d{14}$", timestamp):
            raise HTTPException(status_code=400, detail="Invalid Internet Archive snapshot timestamp.")
        original = normalize_url(req.original_url)
        if not original:
            raise HTTPException(status_code=400, detail="Invalid Internet Archive snapshot URL.")
        return query_archive_snapshot(timestamp, original)
    raise HTTPException(status_code=400, detail=f"Unknown Internet Archive lookup kind: {req.kind}")

class PulsediveLazyRequest(BaseModel):
    kind: str = ""
    indicator: str = ""
    iid: str = ""
    tid: str = ""
    fid: str = ""
    feed: str = ""
    organization: str = ""
    query: str = ""
    query_type: str = "auto"
    mode: str = "indicators"
    page: int = 0
    limit: int = 50
    historical: bool = False
    pulsedive_key: str = ""

def _pulsedive_clean_text(value: str, label: str, max_len: int = 500, required: bool = True) -> str:
    text = (value or "").strip()
    if required and not text:
        raise HTTPException(status_code=400, detail=f"Invalid Pulsedive {label}.")
    if "\n" in text or "\r" in text or len(text) > max_len:
        raise HTTPException(status_code=400, detail=f"Invalid Pulsedive {label}.")
    lowered = text.lower()
    if any(marker in lowered for marker in ("analyze", "probe=", "submit=", "qid=", "queue")):
        raise HTTPException(status_code=400, detail="Pulsedive active/submission workflows are blocked.")
    return text

@app.post("/api/pulsedive-lazy")
def pulsedive_lazy(req: PulsediveLazyRequest):
    # Passive Pulsedive intelligence only. This is not a generic Pulsedive
    # proxy: analyze.php, probe, submit, queue and QID workflows are unreachable.
    kind = (req.kind or "").strip().lower()
    if kind in {"indicator-properties", "properties"}:
        iid = _require_id(req.iid, "Pulsedive indicator ID", _SAFE_ID_RE)
        return query_pulsedive_indicator_properties(iid, req.pulsedive_key, historical=False)
    if kind in {"indicator-history", "history", "historical-properties"}:
        iid = _require_id(req.iid, "Pulsedive indicator ID", _SAFE_ID_RE)
        return query_pulsedive_indicator_properties(iid, req.pulsedive_key, historical=True)
    if kind in {"indicator-links", "links", "relationships"}:
        iid = _require_id(req.iid, "Pulsedive indicator ID", _SAFE_ID_RE)
        indicator = _pulsedive_clean_text(req.indicator, "indicator", required=False)
        return query_pulsedive_indicator_links(iid, req.pulsedive_key, indicator=indicator)
    if kind == "explore":
        query = _pulsedive_clean_text(req.query or req.indicator, "Explore query", max_len=1000)
        mode = (req.mode or "indicators").strip().lower()
        if mode not in {"indicators", "threats"}:
            raise HTTPException(status_code=400, detail="Invalid Pulsedive Explore mode.")
        try:
            limit = max(1, min(int(req.limit or 50), 250))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid Pulsedive result limit.")
        return query_pulsedive_explore(query, req.pulsedive_key, query_type=req.query_type or "auto", mode=mode, limit=limit)
    if kind == "threat":
        threat = _pulsedive_clean_text(req.query or req.indicator, "threat")
        return query_pulsedive_threat(threat, req.pulsedive_key)
    if kind in {"threat-links", "threat-indicators"}:
        tid = _require_id(req.tid, "Pulsedive threat ID", _SAFE_ID_RE)
        try:
            page = max(0, min(int(req.page or 0), 10))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid Pulsedive page.")
        return query_pulsedive_threat_links(tid, req.pulsedive_key, page=page, summary=False)
    if kind == "feed":
        fid = _require_id(req.fid, "Pulsedive feed ID", _SAFE_ID_RE) if (req.fid or "").strip() else ""
        feed = _pulsedive_clean_text(req.feed, "feed name", required=False)
        org = _pulsedive_clean_text(req.organization, "organization", required=False)
        if not fid and not (feed and org):
            raise HTTPException(status_code=400, detail="Pulsedive feed lookup requires fid or feed plus organization.")
        return query_pulsedive_feed(fid=fid, feed=feed, organization=org, api_key=req.pulsedive_key)
    if kind in {"feed-links", "feed-indicators"}:
        fid = _require_id(req.fid, "Pulsedive feed ID", _SAFE_ID_RE)
        try:
            page = max(0, min(int(req.page or 0), 10))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="Invalid Pulsedive page.")
        return query_pulsedive_feed_links(fid, req.pulsedive_key, page=page, summary=False)
    raise HTTPException(status_code=400, detail=f"Unknown Pulsedive lookup kind: {req.kind}")

class KeywordRequest(BaseModel):
    keyword: str
    query_type: str
    abusech_key: str = ""
    otx_key: str = ""
    triage_key: str = ""
    tip_key: str = ""
    malshare_key: str = ""
    rwlive_key: str = ""
    cb_key: str = ""
    ransomlook_key: str = ""
    ha_key: str = ""
    urlscan_key: str = ""
    silentpush_key: str = ""
    driftnet_key: str = ""
    shodan_key: str = ""
    censys_key: str = ""
    etugen_key: str = ""
    pulsedive_key: str = ""
    fofa_key: str = ""
    validin_key: str = ""
    twitter_key: str = ""
    github_key: str = ""
    dnsdumpster_key: str = ""
    sources: list = Field(default_factory=list)
    github_repos: list = Field(default_factory=list)

@app.post("/api/query/keyword")
def query_keyword(req: KeywordRequest):
    kw = req.keyword.strip()
    if not kw:
        raise HTTPException(status_code=400, detail="Keyword cannot be empty.")
    allowed_query_types = {
        "all", "tag", "signature", "malware_family", "yara", "clamav", "imphash", "tlsh",
        "telfhash", "gimphash", "icon_dhash", "file_type",
        "cert_subject", "cert_issuer", "cert_serial",
        "otx_pulse", "sigma", "campaign", "tool", "certificate",
        "domain", "ip", "url", "hash", "repository", "github_user", "github_org",
        "triage_family", "triage_tag", "triage_c2", "triage_botnet",
        "triage_wallet", "triage_domain", "triage_ip", "triage_url",
        "triage_hash",
        "threat_actor", "cve",
        "ransomware_group", "ransomware_victim", "ransomware_country", "ransomware_sector",
        "filename", "malshare_search",
    }
    query_type = (req.query_type or "all").strip() or "all"
    if query_type not in allowed_query_types:
        raise HTTPException(status_code=400, detail=f"Invalid keyword query type: {query_type}")
    return do_keyword_intel(kw, query_type, req.abusech_key, req.otx_key, req.triage_key, tip_key=req.tip_key, malshare_key=req.malshare_key, rwlive_key=req.rwlive_key, cb_key=req.cb_key, ha_key=req.ha_key, urlscan_key=req.urlscan_key, silentpush_key=req.silentpush_key, driftnet_key=req.driftnet_key, shodan_key=req.shodan_key, censys_key=req.censys_key, etugen_key=req.etugen_key, pulsedive_key=req.pulsedive_key, fofa_key=req.fofa_key, validin_key=req.validin_key, twitter_key=req.twitter_key, github_key=req.github_key, dnsdumpster_key=req.dnsdumpster_key, sources=req.sources, github_repos=req.github_repos)

import requests




class GalaxyRefreshRequest(BaseModel):
    category: str = ""


@app.get("/api/misp-galaxy/categories")
def misp_galaxy_categories():
    """Allowed search categories/scopes for the Galaxy browser UI."""
    return {
        "categories": {
            key: {"label": spec["label"], "short": spec["short"],
                  "group": spec["group"], "entity": spec["entity"],
                  "file": spec["file"]}
            for key, spec in MISP_GALAXY_CATEGORIES.items()
        },
        "scopes": dict(GALAXY_GROUP_SCOPES),
    }


@app.get("/api/misp-galaxy/search")
def misp_galaxy_search(category: str = "all", q: str = "", limit: int = 100, offset: int = 0):
    """Reusable Galaxy search. ``category`` must be a known category key or a
    virtual All-scope (all / all-threat-actors / all-malware-tools); anything
    else is rejected so callers can never reach arbitrary files or paths."""
    scope = (category or "all").strip().lower()
    if categories_for_scope(scope) is None:
        raise HTTPException(status_code=400, detail=f"Unknown galaxy category: {category}")
    try:
        limit = max(1, min(int(limit or 100), 500))
    except (TypeError, ValueError):
        limit = 100
    try:
        offset = max(0, int(offset or 0))
    except (TypeError, ValueError):
        offset = 0
    return search_scope(scope, q or "", limit=limit, offset=offset)


@app.post("/api/misp-galaxy/refresh")
def misp_galaxy_refresh(req: GalaxyRefreshRequest):
    category = (req.category or "").strip().lower()
    if category not in MISP_GALAXY_CATEGORIES:
        raise HTTPException(status_code=400, detail=f"Unknown galaxy category: {req.category}")
    ok = refresh_galaxy(category)
    if not ok:
        raise HTTPException(status_code=502, detail=f"Galaxy refresh failed for: {req.category}")
    return {"category": category, "refreshed": True}


# ---------------------------------------------------------------------------
# YARA section (local-only engine: Rule Explorer / Sample Scanner / Workbench)
# ---------------------------------------------------------------------------
class YaraValidateRequest(BaseModel):
    source: str = ""


class YaraSaveRequest(BaseModel):
    repo: str = ""
    filename: str = ""
    source: str = ""
    overwrite: bool = False


class YaraCorpusRequest(BaseModel):
    source: str = ""
    corpus_id: str = ""
    negative_id: str = ""
    max_files: int = 0
    per_file_timeout: int = 0


class YaraTestPathRequest(BaseModel):
    source: str = ""
    path: str = ""
    max_files: int = 0
    per_file_timeout: int = 0


@app.get("/api/yara/status")
def yara_status(scope: str = ""):
    explorer_only = (scope or "").strip().lower() == "explorer"
    return {**yara_engine_status(explorer_only=explorer_only), "limits": yara_scan_limits()}


@app.get("/api/yara/repos")
def yara_repos(scope: str = ""):
    repos = yara_discover_explorer_repos() if (scope or "").strip().lower() == "explorer" else yara_discover_repos()
    return {"repos": [{"id": r["id"], "label": r["label"]}
                      for r in repos]}


@app.get("/api/yara/rules/search")
def yara_rules_search(q: str = "", repo: str = "", repos: str = "", limit: int = 100,
                      offset: int = 0, status: str = "all", regex: bool = False):
    try:
        limit = max(1, min(int(limit or 100), 500))
    except (TypeError, ValueError):
        limit = 100
    try:
        offset = max(0, int(offset or 0))
    except (TypeError, ValueError):
        offset = 0
    return yara_search_rules(q or "", repo_id=(repo or "").strip(),
                             repos=[r.strip() for r in (repos or "").split(",") if r.strip()] or None,
                             limit=limit, offset=offset, status=status,
                             use_regex=bool(regex))


@app.get("/api/yara/rule")
def yara_rule(repo: str = "", name: str = "", namespace: str = ""):
    repo = (repo or "").strip()
    name = (name or "").strip()
    if not repo or not name:
        raise HTTPException(status_code=400, detail="repo and name are required")
    out = yara_get_rule_source(repo, name, (namespace or "").strip())
    if "error" in out:
        raise HTTPException(status_code=404, detail=out["error"])
    return out


@app.post("/api/yara/scan")
async def yara_scan(file: UploadFile = File(...), repos: str = Form("")):
    # Local-only: the upload is scanned in memory and never written to disk.
    data = bytearray()
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        data += chunk
        if len(data) > YARA_MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413,
                                detail=f"Sample exceeds {YARA_MAX_UPLOAD_BYTES} bytes")
    if not data:
        raise HTTPException(status_code=400, detail="Cannot scan an empty file")
    repo_ids = [r.strip() for r in (repos or "").split(",") if r.strip()]
    if not repo_ids:
        raise HTTPException(status_code=400, detail="At least one repository must be selected")
    try:
        # CPU-bound scan (incl. semaphore wait) must not run on the event loop.
        out = await asyncio.to_thread(yara_scan_upload, bytes(data),
                                      file.filename or "upload", repo_ids)
    finally:
        del data
    if "error" in out:
        raise HTTPException(status_code=out.pop("status", 400), detail=out["error"])
    return out


@app.post("/api/yara/validate")
def yara_validate(req: YaraValidateRequest):
    # Temporary isolated compilation; never touches repositories or cache.
    return yara_workbench_validate(req.source or "")


@app.get("/api/yara/workbench/repos")
def yara_workbench_repos():
    return {"repos": yara_writable_repos()}


@app.post("/api/yara/workbench/save")
def yara_workbench_save_route(req: YaraSaveRequest):
    out = yara_workbench_save((req.repo or "").strip(), (req.filename or "").strip(),
                              req.source or "", bool(req.overwrite))
    if "error" in out:
        raise HTTPException(status_code=out.pop("status", 400), detail=out["error"])
    return out


@app.get("/api/yara/corpus/dirs")
def yara_corpus_dirs():
    # Only directory ids/labels are exposed, never absolute paths.
    return {"dirs": [{"id": d["id"], "label": d["label"]} for d in yara_corpus_roots()]}


@app.post("/api/yara/corpus/test")
def yara_corpus_test_route(req: YaraCorpusRequest):
    try:
        max_files = max(0, int(req.max_files or 0))
    except (TypeError, ValueError):
        max_files = 0
    try:
        per_file_timeout = max(0, int(req.per_file_timeout or 0))
    except (TypeError, ValueError):
        per_file_timeout = 0
    out = yara_corpus_test(req.source or "", (req.corpus_id or "").strip(),
                           (req.negative_id or "").strip(),
                           max_files=max_files, per_file_timeout=per_file_timeout)
    if "error" in out:
        raise HTTPException(status_code=out.pop("status", 400), detail=out["error"])
    return out


@app.post("/api/yara/workbench/test-path")
def yara_workbench_test_path(req: YaraTestPathRequest):
    # Test the Workbench rule against a server-local file or folder.
    # Plain JSON (no multipart): files are read straight from the given path
    # and scanned in memory, never written anywhere or submitted externally.
    try:
        max_files = max(0, int(req.max_files or 0))
    except (TypeError, ValueError):
        max_files = 0
    try:
        per_file_timeout = max(0, int(req.per_file_timeout or 0))
    except (TypeError, ValueError):
        per_file_timeout = 0
    out = yara_test_path_sources(req.source or "", (req.path or "").strip(),
                                 max_files=max_files, per_file_timeout=per_file_timeout)
    if "error" in out:
        raise HTTPException(status_code=out.pop("status", 400), detail=out["error"])
    return out


@app.get("/api/yara/browse-path")
def yara_browse_path(path: str = ""):
    # Read-only server filesystem browser for picking test targets.
    # Returns names only (never file contents); local-only deployment.
    import string as _string
    raw = (path or "").strip().strip('"').strip("'")
    if not raw:
        if os.name == "nt":
            drives = [f"{d}:\\" for d in _string.ascii_uppercase
                      if os.path.exists(f"{d}:\\")]
            return {"path": "", "parent": None,
                    "entries": [{"name": d, "path": d, "is_dir": True} for d in drives],
                    "truncated": False}
        raw = "/"
    abs_path = os.path.abspath(os.path.expanduser(raw))
    if not os.path.exists(abs_path):
        raise HTTPException(status_code=400, detail="Path does not exist")
    if os.path.isfile(abs_path) and not os.path.islink(abs_path):
        return {"path": abs_path, "parent": os.path.dirname(abs_path) or None,
                "entries": [], "is_file": True, "truncated": False}
    if not os.path.isdir(abs_path):
        raise HTTPException(status_code=400, detail="Path is not a folder")
    try:
        names = sorted(os.listdir(abs_path))
    except OSError as e:
        raise HTTPException(status_code=400, detail=f"Cannot list folder: {e}")
    entries = []
    truncated = False
    for name in names:
        full = os.path.join(abs_path, name)
        try:
            is_dir = os.path.isdir(full) and not os.path.islink(full)
            is_file = os.path.isfile(full) and not os.path.islink(full)
        except OSError:
            continue
        if not is_dir and not is_file:
            continue
        entries.append({"name": name, "path": full, "is_dir": is_dir})
        if len(entries) >= 500:
            truncated = True
            break
    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    parent = os.path.dirname(abs_path.rstrip("\\/")) or None
    if parent == abs_path:
        parent = None
    return {"path": abs_path, "parent": parent, "entries": entries,
            "truncated": truncated}


@app.post("/api/yara/workbench/test-upload")
async def yara_workbench_test_upload(source: str = Form(""), files: List[UploadFile] = File(default=[])):
    # Test the Workbench rule against analyst-uploaded samples. Everything
    # stays in memory; nothing is written to disk or submitted anywhere.
    uploads = []
    total = 0
    for f in files or []:
        data = bytearray()
        while True:
            chunk = await f.read(1024 * 1024)
            if not chunk:
                break
            data += chunk
            if len(data) > YARA_MAX_UPLOAD_BYTES:
                raise HTTPException(status_code=413,
                                    detail=f"Sample {(f.filename or 'upload')} exceeds {YARA_MAX_UPLOAD_BYTES} bytes")
        total += len(data)
        if total > YARA_MAX_TEST_BYTES:
            raise HTTPException(status_code=413,
                                detail=f"Upload batch exceeds {YARA_MAX_TEST_BYTES} bytes")
        uploads.append(((f.filename or "upload"), bytes(data)))
        del data
        if len(uploads) >= YARA_MAX_TEST_FILES:
            break
    if not uploads:
        raise HTTPException(status_code=400, detail="No sample files provided")
    try:
        # CPU-bound scan must not run on the event loop.
        out = await asyncio.to_thread(yara_test_upload_sources, source or "", uploads)
    finally:
        del uploads
    if "error" in out:
        raise HTTPException(status_code=out.pop("status", 400), detail=out["error"])
    return out

@app.get("/api/meta/sources")
def get_meta_sources():
    return get_source_metadata()

@app.get("/api/meta/tags")
def get_meta_tags(abusech_key: str = ""):
    try:
        headers = {"Content-Type": "application/json"}
        if (abusech_key or "").strip():
            headers["Auth-Key"] = abusech_key.strip()
        resp = requests.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "tag_list"}, headers=headers, timeout=10)
        data = resp.json()
        tags = data.get("data", []) if isinstance(data, dict) else []
        return [t for t in tags if isinstance(t, str)][:500] if isinstance(tags, list) else []
    except Exception:
        return []

@app.get("/api/meta/malware")
def get_meta_malware(abusech_key: str = ""):
    try:
        headers = {"Content-Type": "application/json"}
        if (abusech_key or "").strip():
            headers["Auth-Key"] = abusech_key.strip()
        resp = requests.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "malware_list"}, headers=headers, timeout=10)
        data = resp.json()
        return data.get("data", {}) if isinstance(data, dict) else {}
    except Exception:
        return {}

from intel_query import query_tip_actors, query_tip_actor_profile, query_tip_actor_samples

@app.get("/api/ktip/actors")
def get_ktip_actors(tip_key: str = Header(..., alias="x-tip-key")):
    return _ktip_or_raise(query_tip_actors(tip_key))

@app.get("/api/ktip/actors/{actor_id}")
def get_ktip_actor_profile(actor_id: str, tip_key: str = Header(..., alias="x-tip-key")):
    actor_id = _require_id(actor_id, "Kaspersky actor ID", _SAFE_ID_RE)
    return _ktip_or_raise(query_tip_actor_profile(actor_id, tip_key))

@app.get("/api/ktip/actors/{actor_id}/samples")
def get_ktip_actor_samples(actor_id: str, tip_key: str = Header(..., alias="x-tip-key")):
    actor_id = _require_id(actor_id, "Kaspersky actor ID", _SAFE_ID_RE)
    return _ktip_or_raise(query_tip_actor_samples(actor_id, tip_key))


def _ktip_or_raise(res):
    """Map Kaspersky TIP backend errors to HTTP statuses: missing key is a
    client error (400, like the other key checks), upstream failures are 500."""
    if "error" not in res:
        return res
    if res["error"] == "No API Key provided":
        raise HTTPException(status_code=400, detail="Missing Kaspersky TIP API key")
    raise HTTPException(status_code=500, detail=res["error"])

# ---------------------------------------------------------------------------
# CTI Articles (local collection: recent feed, details, sources, sync)
# ---------------------------------------------------------------------------
def _cti_call_or_rebuild(label: str, fn):
    try:
        return fn()
    except Exception as e:
        if not cti_db_mod.is_corruption_error(e):
            raise HTTPException(status_code=500, detail=f"{label} failed: {e}")
        logger.warning("%s hit a malformed CTI database; rebuilding local cache", label)
        try:
            cti_db_mod.rebuild_database(reason=str(e))
            try:
                cti_collect_mod.ensure_registry()
            except Exception as registry_error:
                logger.warning("CTI registry rebuild after cache repair failed: %s", registry_error)
            return fn()
        except Exception as retry_error:
            raise HTTPException(
                status_code=500,
                detail=f"{label} failed after CTI cache rebuild: {retry_error}",
            )


@app.get("/api/cti/articles")
def cti_articles(source: str = "", hours: int = 0, limit: int = 50,
                 offset: int = 0, category: str = ""):
    try:
        limit = max(1, min(int(limit or 50), 200))
    except (TypeError, ValueError):
        limit = 50
    try:
        offset = max(0, int(offset or 0))
    except (TypeError, ValueError):
        offset = 0
    try:
        hours = max(0, int(hours or 0))
    except (TypeError, ValueError):
        hours = 0
    return _cti_call_or_rebuild(
        "CTI feed",
        lambda: cti_query_mod.recent(source_id=(source or "").strip(),
                                     hours=hours, limit=limit, offset=offset,
                                     category=(category or "").strip()),
    )


@app.get("/api/cti/search")
def cti_articles_search(q: str = "", limit: int = 50, category: str = ""):
    try:
        limit = max(1, min(int(limit or 50), 200))
    except (TypeError, ValueError):
        limit = 50
    return _cti_call_or_rebuild(
        "CTI search",
        lambda: cti_query_mod.query_cti_articles((q or "").strip(), limit=limit,
                                                 category=(category or "").strip()),
    )


@app.get("/api/cti/article/{article_id}")
def cti_article(article_id: int):
    try:
        aid = int(article_id)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid article id")
    out = _cti_call_or_rebuild("CTI article", lambda: cti_query_mod.details(aid))
    if "error" in out:
        raise HTTPException(status_code=404, detail=out["error"])
    return out


@app.post("/api/cti/article/{article_id}/ai-summary")
def cti_article_ai_summary(article_id: int):
    try:
        return ai_mod.summarize_cti_article(int(article_id))
    except (TypeError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e) or "Invalid article id")
    except ai_mod.AIUnavailable as e:
        raise HTTPException(status_code=400, detail=str(e))
    except TimeoutError as e:
        raise HTTPException(status_code=504, detail=str(e))
    except ai_mod.AIProviderError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except Exception:
        logger.exception("CTI article AI summary failed")
        raise HTTPException(status_code=500, detail="CTI article AI summary failed. Check backend logs for diagnostics.")


@app.get("/api/cti/sources")
def cti_sources():
    def _load_sources():
        out = cti_query_mod.sources_status()
        conn = cti_db_mod.connect()
        try:
            out["articles_total"] = conn.execute(
                "SELECT COUNT(*) FROM articles").fetchone()[0]
        finally:
            conn.close()
        return out

    return _cti_call_or_rebuild("CTI sources", _load_sources)


class CtiSourceToggleRequest(BaseModel):
    enabled: bool = True


class CtiSourceAddRequest(BaseModel):
    name: str = ""
    category: str = ""
    feed_url: str = ""


class CtiSourceFeedRequest(BaseModel):
    feed_url: str = ""


class CtiCategoryAddRequest(BaseModel):
    name: str = ""


class CtiCategoryRenameRequest(BaseModel):
    old_name: str = ""
    new_name: str = ""


class CtiCategoryDeleteRequest(BaseModel):
    name: str = ""


class CtiSourceEditRequest(BaseModel):
    name: str = None
    category: str = None
    feed_url: str = None


@app.get("/api/cti/categories")
def cti_categories_list():
    try:
        cats = cti_db_mod.get_categories()
        return {"categories": cats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch categories: {e}")


@app.post("/api/cti/categories")
def cti_category_add(req: CtiCategoryAddRequest):
    name = (req.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Category name is required")
    cti_db_mod.add_category(name)
    return {"name": name, "created": True}


@app.post("/api/cti/categories/rename")
def cti_category_rename(req: CtiCategoryRenameRequest):
    old_name = (req.old_name or "").strip()
    new_name = (req.new_name or "").strip()
    if not old_name or not new_name:
        raise HTTPException(status_code=400, detail="old_name and new_name are required")
    updated = cti_db_mod.rename_category(old_name, new_name)
    return {"old_name": old_name, "new_name": new_name, "updated_sources": updated}


@app.post("/api/cti/categories/delete")
def cti_category_delete_post(req: CtiCategoryDeleteRequest):
    cat = (req.name or "").strip()
    if not cat:
        raise HTTPException(status_code=400, detail="Category name is required")
    updated = cti_db_mod.delete_category(cat)
    return {"name": cat, "deleted": True, "updated_sources": updated}


@app.delete("/api/cti/categories/{category_name:path}")
def cti_category_delete(category_name: str):
    cat = (category_name or "").strip()
    if not cat:
        raise HTTPException(status_code=400, detail="Category name is required")
    updated = cti_db_mod.delete_category(cat)
    return {"name": cat, "deleted": True, "updated_sources": updated}


@app.post("/api/cti/sources")
def cti_source_add(req: CtiSourceAddRequest):
    """Manually add a feed URL (operator-pinned, discovery="manual")."""
    url = cti_db_mod._validate_feed_url(req.feed_url)
    if not url:
        raise HTTPException(status_code=400,
                            detail="A valid http(s) feed URL is required")
    host = cti_catalog_mod.feed_host(url) or url
    name = (req.name or "").strip()[:200] or host
    cat = (req.category or "").strip()
    sid = cti_db_mod.source_id_for(url, host)
    conn = cti_db_mod.connect()
    try:
        exists = conn.execute("SELECT id FROM sources WHERE id = ?",
                              (sid,)).fetchone()
    finally:
        conn.close()
    cti_db_mod.upsert_source({"feed_url": url, "title": name, "feed_type": "",
                              "category": cat, "description": "", "domain": host,
                              "discovery": "manual"}, keep_name=bool(exists))
    return {"id": sid, "created": not bool(exists)}


@app.delete("/api/cti/sources/{source_id}")
def cti_source_delete(source_id: str):
    sid = (source_id or "").strip()
    if not sid:
        raise HTTPException(status_code=400, detail="source id is required")
    if not cti_db_mod.delete_source(sid):
        raise HTTPException(status_code=404, detail="Source not found")
    return {"id": sid, "deleted": True}


@app.post("/api/cti/sources/{source_id}/edit")
def cti_source_edit(source_id: str, req: CtiSourceEditRequest):
    sid = (source_id or "").strip()
    if not sid:
        raise HTTPException(status_code=400, detail="source id is required")
    if not cti_db_mod.edit_source_details(sid, name=req.name, category=req.category, feed_url=req.feed_url):
        raise HTTPException(status_code=404, detail="Source not found or invalid data")
    return {"id": sid, "updated": True}


@app.post("/api/cti/sources/{source_id}/feed")
def cti_source_set_feed(source_id: str, req: CtiSourceFeedRequest):
    """Replace a source's feed URL in place (articles stay linked)."""
    sid = (source_id or "").strip()
    if not sid:
        raise HTTPException(status_code=400, detail="source id is required")
    if not cti_db_mod._validate_feed_url(req.feed_url):
        raise HTTPException(status_code=400,
                            detail="A valid http(s) feed URL is required")
    if not cti_db_mod.set_source_feed(sid, req.feed_url):
        raise HTTPException(status_code=404, detail="Unknown CTI source")
    return {"id": sid, "feed_url": req.feed_url.strip()}


@app.post("/api/cti/sources/{source_id}/toggle")
def cti_source_toggle(source_id: str, req: CtiSourceToggleRequest):
    sid = (source_id or "").strip()
    if not sid:
        raise HTTPException(status_code=400, detail="source id is required")
    if not cti_db_mod.set_source_enabled(sid, bool(req.enabled)):
        raise HTTPException(status_code=404, detail="Unknown CTI source")
    return {"id": sid, "enabled": bool(req.enabled)}


_cti_sync_running = False


@app.post("/api/cti/sync")
def cti_sync_now():
    """Trigger an article sync in the background (registry first). Local DB
    only; never submits anything anywhere."""
    # global _cti_sync_running
    if _cti_sync_running:
        return {"started": False, "reason": "sync already running"}

    def _run():
        global _cti_sync_running
        _cti_sync_running = True
        try:
            cti_collect_mod.ensure_registry()
            cti_collect_mod.sync_feeds()
        except Exception as e:
            logger.warning("manual CTI sync failed: %s", e)
        finally:
            _cti_sync_running = False

    threading.Thread(target=_run, name="mantis-cti-manual", daemon=True).start()
    return {"started": True}


# ---------------------------------------------------------------------------
# Telegram Intelligence (passive discovery + explicit active investigation)
# ---------------------------------------------------------------------------
class TgInvestigationRequest(BaseModel):
    name: str = ""


class TgBotAddRequest(BaseModel):
    token: str = ""
    chat_id: str = ""
    dest_chat_id: str = ""
    mode: str = "full"
    transport: str = "native"


class TgValidateRequest(BaseModel):
    token: str = ""


class TgDiscoverRequest(BaseModel):
    abusech_key: str = ""
    urlscan_key: str = ""


class TgToInvestigationRequest(BaseModel):
    investigation_id: str = ""


class TgAuthCodeRequest(BaseModel):
    api_id: int
    api_hash: str = ""
    phone: str = ""


class TgAuthLoginRequest(BaseModel):
    attempt_id: str = ""
    code: str = ""
    password: str = ""


@app.get("/api/tg/auth/status")
def tg_auth_status():
    return tg_mod.auth_status()


@app.post("/api/tg/auth/send_code")
def tg_auth_send_code(req: TgAuthCodeRequest):
    out = tg_mod.auth_send_code(req.api_id, req.api_hash, req.phone)
    if out.get("error"):
        raise HTTPException(status_code=400, detail=out["error"])
    return out


@app.post("/api/tg/auth/login")
def tg_auth_login(req: TgAuthLoginRequest):
    out = tg_mod.auth_login(req.attempt_id, req.code, req.password)
    if out.get("error"):
        raise HTTPException(status_code=400, detail=out["error"])
    return out


@app.get("/api/tg/auth/verify")
def tg_auth_verify():
    out = tg_mod.auth_verify()
    if out.get("error"):
        raise HTTPException(status_code=400, detail=out["error"])
    return out


@app.post("/api/tg/auth/logout")
def tg_auth_logout():
    return tg_mod.auth_logout()


@app.post("/api/tg/info")
def tg_bot_info(req: TgValidateRequest):
    out = tg_mod.bot_info(req.token)
    if not out.get("ok"):
        raise HTTPException(status_code=400, detail=out.get("error", "Unable to fetch bot information"))
    return out


@app.get("/api/tg/bots")
def tg_bot_list():
    return tg_mod.list_bots()


@app.post("/api/tg/bots")
def tg_bot_add(req: TgBotAddRequest):
    # Passive registration: shape-checked only, Telegram is NOT contacted.
    out = tg_mod.add_bot(req.token or "",
                         (req.chat_id or "").strip(),
                         (req.dest_chat_id or "").strip(),
                         req.mode or "full",
                         req.transport or "native")
    if "error" in out:
        raise HTTPException(status_code=400, detail=out["error"])
    return out


@app.get("/api/tg/bots/{bot_id}")
def tg_bot_get(bot_id: str):
    out = tg_mod.bot_messages_summary((bot_id or "").strip())
    if "error" in out:
        raise HTTPException(status_code=404, detail=out["error"])
    return out


@app.post("/api/tg/bots/{bot_id}/validate")
def tg_bot_validate(bot_id: str, req: TgValidateRequest):
    # ACTIVE (explicit getMe): validates a pasted token without storing it,
    # or the registered bot's stored credential when no token is supplied.
    bot_id = (bot_id or "").strip()
    token = (req.token or "").strip()
    stored = False
    if not token:
        token = tg_mod._job_token(bot_id)
        stored = True
        if not token:
            raise HTTPException(status_code=404, detail="Bot not found")
    out = tg_mod.bot_validate(token)
    if stored:
        conn = tg_mod.connect()
        try:
            if out.get("ok"):
                conn.execute("UPDATE tg_bots SET token_state = 'validated', bot_id = ?,"
                             " username = ?, display_name = ? WHERE id = ?",
                             (out.get("bot_id", ""), out.get("username", ""),
                              out.get("display_name", ""), bot_id))
            else:
                conn.execute("UPDATE tg_bots SET token_state = 'invalid', last_error = ?"
                             " WHERE id = ?", (out.get("error", "")[:300], bot_id))
            conn.commit()
        finally:
            conn.close()
    if not out.get("ok"):
        raise HTTPException(status_code=400, detail=out.get("error", "validation failed"))
    out["stored"] = stored
    return out


@app.post("/api/tg/bots/{bot_id}/diagnose")
def tg_bot_diagnose(bot_id: str):
    # ACTIVE read-only diagnostics (getMe/getWebhookInfo). No state changes.
    token = tg_mod._job_token((bot_id or "").strip())
    if not token:
        raise HTTPException(status_code=404, detail="Bot not found")
    return tg_mod.bot_diagnostics(token)


@app.post("/api/tg/bots/{bot_id}/start")
def tg_bot_start(bot_id: str):
    # ACTIVE (explicit): begin Full/Live collection for one bot.
    out = tg_mod.start_bot((bot_id or "").strip())
    if "error" in out:
        raise HTTPException(status_code=400, detail=out["error"])
    return out


@app.post("/api/tg/bots/{bot_id}/stop")
def tg_bot_stop(bot_id: str):
    return tg_mod.stop_bot((bot_id or "").strip(), paused=False)


@app.post("/api/tg/bots/{bot_id}/pause")
def tg_bot_pause(bot_id: str):
    return tg_mod.stop_bot((bot_id or "").strip(), paused=True)


@app.delete("/api/tg/bots/{bot_id}")
def tg_bot_delete(bot_id: str):
    return tg_mod.delete_bot((bot_id or "").strip())


@app.get("/api/tg/messages")
def tg_messages(bot_id: str = "", text: str = "", msg_type: str = "",
                date_from: str = "", date_to: str = "",
                limit: int = 200, offset: int = 0):
    try:
        limit = max(1, min(int(limit or 200), 500))
    except (TypeError, ValueError):
        limit = 200
    try:
        offset = max(0, int(offset or 0))
    except (TypeError, ValueError):
        offset = 0
    return tg_mod.query_messages((bot_id or "").strip(), (text or "").strip(),
                                 (msg_type or "").strip(),
                                 (date_from or "").strip(),
                                 (date_to or "").strip(),
                                 limit=limit, offset=offset)


@app.post("/api/tg/discover")
def tg_discover(req: TgDiscoverRequest):
    # PASSIVE: existing MANTIS provider clients + local CTI only.
    out = {"threatfox": {}, "urlscan": {}, "malwarebazaar": {},
           "cti_articles": {}, "stored": {}}
    out["threatfox"] = tg_mod.discover_threatfox(req.abusech_key or "")
    out["urlscan"] = tg_mod.discover_urlscan(req.urlscan_key or "")
    out["malwarebazaar"] = tg_mod.discover_malwarebazaar(req.abusech_key or "")
    out["cti_articles"] = tg_mod.discover_cti_articles()
    arts = []
    for key in ("threatfox", "urlscan", "malwarebazaar"):
        arts.extend((out[key] or {}).get("artifacts", []))
    try:
        out["stored"] = tg_mod.store_artifacts(arts)
    except Exception as e:
        out["stored"] = {"error": str(e)[:200]}
    try:
        out["grouped"] = tg_mod.group_discovery(arts)
    except Exception:
        out["grouped"] = {"groups": [], "total": 0, "hosts": 0, "sources": []}
    return out


class TgSearchRequest(BaseModel):
    source: str = ""
    query: str = ""
    size: int = 50
    abusech_key: str = ""
    urlscan_key: str = ""


@app.post("/api/tg/discover/search")
def tg_discover_search(req: TgSearchRequest):
    # PASSIVE per-source search (existing MANTIS clients). Results are
    # normalized AND stored locally like the full discovery run.
    source = (req.source or "").strip().lower()
    query = (req.query or "").strip()
    try:
        size = max(1, min(int(req.size or 50), 100))
    except (TypeError, ValueError):
        size = 50
    if source == "threatfox":
        out = tg_mod.discover_threatfox(req.abusech_key or "",
                                        query or "api.telegram.org", size)
    elif source == "urlscan":
        out = tg_mod.discover_urlscan_query(req.urlscan_key or "",
                                            query or "api.telegram.org", size)
    else:
        raise HTTPException(status_code=400,
                            detail="source must be threatfox or urlscan")
    if "error" in out and not out.get("artifacts"):
        raise HTTPException(status_code=400, detail=out["error"])
    try:
        out["stored"] = tg_mod.store_artifacts(out.get("artifacts", []))
    except Exception as e:
        out["stored"] = {"error": str(e)[:200]}
    try:
        out["grouped"] = tg_mod.group_discovery(out.get("artifacts", []))
    except Exception:
        out["grouped"] = {"groups": [], "total": 0, "hosts": 0, "sources": []}
    return out


@app.get("/api/tg/artifacts")
def tg_artifacts(kind: str = "", source: str = "", limit: int = 100,
                 offset: int = 0):
    try:
        limit = max(1, min(int(limit or 100), 500))
    except (TypeError, ValueError):
        limit = 100
    try:
        offset = max(0, int(offset or 0))
    except (TypeError, ValueError):
        offset = 0
    return tg_mod.list_artifacts((kind or "").strip(), (source or "").strip(),
                                 limit=limit, offset=offset)


@app.post("/api/tg/artifacts/{artifact_id}/validate")
def tg_artifact_validate(artifact_id: int):
    # ACTIVE, manual analyst action only.
    try:
        aid = int(artifact_id)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid artifact id")
    out = tg_mod.validate_artifact(aid)
    if "error" in out:
        raise HTTPException(status_code=400, detail=out["error"])
    return out


class TgDirectValidateRequest(BaseModel):
    value: str = ""


@app.post("/api/tg/artifacts/validate-direct")
def tg_artifact_validate_direct(req: TgDirectValidateRequest):
    # ACTIVE, manual analyst action: validate a pasted value without storing.
    out = tg_mod.bot_validate((req.value or "").strip())
    if not out.get("ok"):
        raise HTTPException(status_code=400, detail=out.get("error", "validation failed"))
    return out


class TgSeedArtifactRequest(BaseModel):
    investigation_id: str = ""
    artifact: dict = {}


@app.get("/api/tg/stream")
def tg_stream(abusech_key: str = "", urlscan_key: str = "", limit: int = 30):
    try:
        limit = max(1, min(int(limit or 30), 100))
    except (TypeError, ValueError):
        limit = 30
    return tg_mod.aggregate_stream(abusech_key or "", urlscan_key or "",
                                   limit=limit)


# ---------------------------------------------------------------------------
# Telegram Channel Monitoring & Threat Intelligence API
# ---------------------------------------------------------------------------
import tg_channel_monitor

class TgAddChannelReq(BaseModel):
    username: str
    category: str = "threat_actor_public"
    auto_download: bool = True

class TgAddTargetReq(BaseModel):
    value: str
    target_type: str = "domain"
    description: str = ""

@app.get("/api/tg/monitor/channels")
def tg_monitor_channels_list():
    return tg_channel_monitor.list_monitored_channels()

@app.post("/api/tg/monitor/channels")
def tg_monitor_channel_add(req: TgAddChannelReq):
    out = tg_channel_monitor.add_monitored_channel(req.username, req.category, req.auto_download)
    if "error" in out:
        raise HTTPException(status_code=400, detail=out["error"])
    return out

@app.delete("/api/tg/monitor/channels/{channel_id}")
def tg_monitor_channel_delete(channel_id: str):
    out = tg_channel_monitor.delete_monitored_channel(channel_id)
    if "error" in out:
        raise HTTPException(status_code=404, detail=out["error"])
    return out

@app.get("/api/tg/monitor/live-feed")
def tg_monitor_live_feed(page: int = 1, page_size: int = 20, limit: Optional[int] = None, category: str = ""):
    return tg_channel_monitor.get_live_messages(page=page, page_size=page_size, limit=limit, category=category)

@app.get("/api/tg/monitor/exposures")
def tg_monitor_exposures(domain: str = "", limit: int = 100, offset: int = 0):
    return tg_channel_monitor.get_stealer_exposures(domain=domain, limit=limit, offset=offset)

@app.get("/api/tg/monitor/targets")
def tg_monitor_targets_list():
    return tg_channel_monitor.list_target_assets()

@app.post("/api/tg/monitor/targets")
def tg_monitor_target_add(req: TgAddTargetReq):
    out = tg_channel_monitor.add_target_asset(req.value, req.target_type, req.description)
    if "error" in out:
        raise HTTPException(status_code=400, detail=out["error"])
    return out

@app.delete("/api/tg/monitor/targets/{target_id}")
def tg_monitor_target_delete(target_id: int):
    out = tg_channel_monitor.delete_target_asset(target_id)
    if "error" in out:
        raise HTTPException(status_code=404, detail=out["error"])
    return out

@app.get("/api/tg/monitor/stats")
def tg_monitor_stats():
    return tg_channel_monitor.get_monitor_stats()


# ---------------------------------------------------------------------------
# Breach Watcher Engine
# ---------------------------------------------------------------------------
class LeakLookupReq(BaseModel):
    query: str
    query_type: str = "domain"
    key: Optional[str] = ""

@app.get("/api/breach-watcher/feed")
def breach_watcher_feed(page: int = 1, page_size: int = 20, query: str = "", source: str = "", refresh: bool = False):
    return breach_watcher.get_breach_feed(page=page, page_size=page_size, query=query, source_filter=source, refresh=refresh)

@app.get("/api/breach-watcher/hibp/breaches")
def breach_watcher_hibp_breaches(search: str = "", refresh: bool = False):
    return breach_watcher.get_hibp_breaches(search=search, force_refresh=refresh)

@app.get("/api/breach-watcher/hibp/latest")
def breach_watcher_hibp_latest(refresh: bool = False):
    return breach_watcher.get_hibp_latest(force_refresh=refresh)

@app.get("/api/breach-watcher/hibp/dataclasses")
def breach_watcher_hibp_dataclasses():
    return breach_watcher.get_hibp_dataclasses()

@app.get("/api/breach-watcher/hibp/breach/{name}")
def breach_watcher_hibp_breach_name(name: str):
    return breach_watcher.get_hibp_breach_by_name(name)

@app.post("/api/breach-watcher/leak-lookup/search")
def breach_watcher_leak_lookup(req: LeakLookupReq):
    return breach_watcher.search_leak_lookup(query=req.query, query_type=req.query_type, key=req.key)

@app.get("/api/breach-watcher/stats")
def breach_watcher_stats(refresh: bool = False):
    return breach_watcher.get_breach_stats(refresh=refresh)



# ---------------------------------------------------------------------------
# Similarity Engine (Phase 1: local static metadata/fingerprints only)
# ---------------------------------------------------------------------------
SIMILARITY_MAX_UPLOAD_BYTES = 256 * 1024 * 1024
SIMILARITY_MAX_FILES = 50


async def _similarity_stage_uploads(files: List[UploadFile], tmpdir: str) -> list:
    staged = []
    total = 0
    for idx, f in enumerate(files or []):
        if idx >= SIMILARITY_MAX_FILES:
            break
        filename = os.path.basename(f.filename or f"sample-{idx + 1}.bin")
        if not filename:
            filename = f"sample-{idx + 1}.bin"
        path = os.path.join(tmpdir, f"{idx + 1:04d}-{filename}")
        size = 0
        with open(path, "wb") as out:
            while True:
                chunk = await f.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                total += len(chunk)
                if size > SIMILARITY_MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail=f"Sample {filename} exceeds {SIMILARITY_MAX_UPLOAD_BYTES} bytes")
                if total > SIMILARITY_MAX_UPLOAD_BYTES * SIMILARITY_MAX_FILES:
                    raise HTTPException(status_code=413, detail="Similarity upload batch is too large")
                out.write(chunk)
        if size <= 0:
            try:
                os.remove(path)
            except OSError:
                pass
            continue
        staged.append((filename, path))
    return staged


@app.get("/api/similarity/dashboard")
def similarity_dashboard():
    try:
        return _similarity_cached("dashboard", similarity_mod.dashboard)
    except Exception as e:
        logger.exception("Similarity dashboard failed")
        raise HTTPException(status_code=500, detail=f"Similarity dashboard failed: {e}")


@app.get("/api/similarity/ida/status")
def similarity_ida_status():
    try:
        return _similarity_cached("ida-status", similarity_mod.ida_status)
    except Exception as e:
        logger.exception("Similarity IDA status failed")
        raise HTTPException(status_code=500, detail=f"Similarity IDA status failed: {e}")


@app.get("/api/similarity/hexrays/status")
def similarity_hexrays_status():
    try:
        return _similarity_cached("hexrays-status", similarity_mod.hexrays_status)
    except Exception as e:
        logger.exception("Similarity Hex-Rays status failed")
        raise HTTPException(status_code=500, detail=f"Similarity Hex-Rays status failed: {e}")


@app.get("/api/similarity/entities")
def similarity_entities():
    try:
        return _similarity_cached("entities", similarity_mod.list_entities)
    except Exception as e:
        logger.exception("Similarity entity list failed")
        raise HTTPException(status_code=500, detail=f"Similarity entity list failed: {e}")


@app.get("/api/similarity/entities/{entity_id}")
def similarity_entity(entity_id: int):
    try:
        out = similarity_mod.get_entity(int(entity_id))
    except Exception as e:
        logger.exception("Similarity entity read failed")
        raise HTTPException(status_code=500, detail=f"Similarity entity read failed: {e}")
    if not out:
        raise HTTPException(status_code=404, detail="Similarity entity not found")
    return out


@app.put("/api/similarity/entities/{entity_id}")
def similarity_update_entity(entity_id: int, req: dict):
    try:
        out = similarity_mod.update_entity(
            int(entity_id),
            str((req or {}).get("name") or ""),
            str((req or {}).get("entity_type") or (req or {}).get("type") or "malware"),
            str((req or {}).get("description") or ""),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("Similarity entity update failed")
        raise HTTPException(status_code=500, detail=f"Similarity entity update failed: {e}")
    if not out:
        raise HTTPException(status_code=404, detail="Similarity entity not found")
    _similarity_clear_cache()
    return out


@app.get("/api/similarity/entities/{entity_id}/code")
def similarity_entity_code(entity_id: int):
    try:
        out = similarity_mod.get_entity_code(int(entity_id))
    except Exception as e:
        logger.exception("Similarity entity code read failed")
        raise HTTPException(status_code=500, detail=f"Similarity entity code read failed: {e}")
    if not out:
        raise HTTPException(status_code=404, detail="Similarity entity not found")
    return out


@app.get("/api/similarity/entities/{entity_id}/functions")
def similarity_entity_functions(entity_id: int, limit: int = 200):
    try:
        out = similarity_mod.get_entity_functions(int(entity_id), limit)
    except Exception as e:
        logger.exception("Similarity entity functions read failed")
        raise HTTPException(status_code=500, detail=f"Similarity entity functions read failed: {e}")
    if not out:
        raise HTTPException(status_code=404, detail="Similarity entity not found")
    return out


@app.get("/api/similarity/entities/{entity_id}/blocks")
def similarity_entity_blocks(entity_id: int):
    try:
        out = similarity_mod.get_entity_code(int(entity_id))
    except Exception as e:
        logger.exception("Similarity entity blocks read failed")
        raise HTTPException(status_code=500, detail=f"Similarity entity blocks read failed: {e}")
    if not out:
        raise HTTPException(status_code=404, detail="Similarity entity not found")
    return {"entity": out["entity"], "blocks": out.get("blocks", [])}


@app.get("/api/similarity/entities/{entity_id}/api-patterns")
def similarity_entity_api_patterns(entity_id: int):
    try:
        out = similarity_mod.get_entity_code(int(entity_id))
    except Exception as e:
        logger.exception("Similarity entity API pattern read failed")
        raise HTTPException(status_code=500, detail=f"Similarity entity API pattern read failed: {e}")
    if not out:
        raise HTTPException(status_code=404, detail="Similarity entity not found")
    return {"entity": out["entity"], "api_patterns": out.get("api_patterns", [])}


@app.post("/api/similarity/entities/{entity_id}/code/rebuild")
def similarity_entity_code_rebuild(entity_id: int):
    try:
        out = similarity_mod.rebuild_entity_code(int(entity_id))
    except Exception as e:
        logger.exception("Similarity entity code rebuild failed")
        raise HTTPException(status_code=500, detail=f"Similarity entity code rebuild failed: {e}")
    if not out:
        raise HTTPException(status_code=404, detail="Similarity entity not found")
    return out


@app.delete("/api/similarity/entities/{entity_id}")
def similarity_delete_entity(entity_id: int):
    try:
        ok = similarity_mod.delete_entity(int(entity_id))
    except Exception as e:
        logger.exception("Similarity entity delete failed")
        raise HTTPException(status_code=500, detail=f"Similarity entity delete failed: {e}")
    if not ok:
        raise HTTPException(status_code=404, detail="Similarity entity not found")
    _similarity_clear_cache()
    return {"deleted": True}


@app.post("/api/similarity/entities/{entity_id}/samples")
async def similarity_add_entity_samples(
    entity_id: int,
    progress_id: str = Form(""),
    files: List[UploadFile] = File(default=[]),
):
    if not files:
        raise HTTPException(status_code=400, detail="At least one sample file is required")
    progress_id = _similarity_progress_id(progress_id)
    _similarity_progress_init(progress_id, "add_entity_samples")
    _similarity_progress_event(progress_id, "upload", f"Received {len(files)} uploaded sample(s).", "running")
    with tempfile.TemporaryDirectory(prefix="mantis-similarity-", ignore_cleanup_errors=True) as tmpdir:
        staged = await _similarity_stage_uploads(files, tmpdir)
        if not staged:
            _similarity_progress_finish(progress_id, "failed", "No non-empty sample files provided.")
            raise HTTPException(status_code=400, detail="No non-empty sample files provided")
        _similarity_progress_event(progress_id, "upload", f"Staged {len(staged)} sample(s) for local processing.", "done")
        try:
            out = await asyncio.to_thread(similarity_mod.add_entity_samples, int(entity_id), staged, _similarity_progress_callback(progress_id))
            if not out:
                _similarity_progress_finish(progress_id, "failed", "Similarity entity not found.")
                raise HTTPException(status_code=404, detail="Similarity entity not found")
            _similarity_progress_finish(progress_id, "done", "Similarity entity sample import complete.")
            _similarity_clear_cache()
            return out
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("Similarity entity sample import failed")
            _similarity_progress_finish(progress_id, "failed", f"Similarity entity sample import failed: {e}")
            raise HTTPException(status_code=500, detail=f"Similarity entity sample import failed: {e}")


@app.get("/api/similarity/progress/{progress_id}")
def similarity_progress(progress_id: str):
    progress_id = _similarity_progress_id(progress_id)
    if not progress_id:
        raise HTTPException(status_code=400, detail="Invalid progress id")
    with _similarity_progress_lock:
        state = dict(_similarity_progress.get(progress_id) or {})
        if state.get("events"):
            state["events"] = list(state["events"])
    if not state:
        return {"id": progress_id, "status": "unknown", "events": []}
    state["elapsed"] = round(time.time() - float(state.get("started_at") or time.time()), 1)
    return state


@app.post("/api/similarity/entities")
async def similarity_create_entity(
    name: str = Form(...),
    entity_type: str = Form("malware"),
    description: str = Form(""),
    progress_id: str = Form(""),
    files: List[UploadFile] = File(default=[]),
):
    if not files:
        raise HTTPException(status_code=400, detail="At least one sample file is required")
    progress_id = _similarity_progress_id(progress_id)
    _similarity_progress_init(progress_id, "create_entity")
    _similarity_progress_event(progress_id, "upload", f"Received {len(files)} uploaded sample(s).", "running")
    with tempfile.TemporaryDirectory(prefix="mantis-similarity-", ignore_cleanup_errors=True) as tmpdir:
        staged = await _similarity_stage_uploads(files, tmpdir)
        if not staged:
            _similarity_progress_finish(progress_id, "failed", "No non-empty sample files provided.")
            raise HTTPException(status_code=400, detail="No non-empty sample files provided")
        _similarity_progress_event(progress_id, "upload", f"Staged {len(staged)} sample(s) for local processing.", "done")
        try:
            out = await asyncio.to_thread(similarity_mod.create_entity, name, entity_type, description, staged, _similarity_progress_callback(progress_id))
            _similarity_progress_finish(progress_id, "done", "Similarity entity processing complete.")
            _similarity_clear_cache()
            return out
        except ValueError as e:
            _similarity_progress_finish(progress_id, "failed", str(e))
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.exception("Similarity entity creation failed")
            _similarity_progress_finish(progress_id, "failed", f"Similarity entity creation failed: {e}")
            raise HTTPException(status_code=500, detail=f"Similarity entity creation failed: {e}")


@app.post("/api/similarity/compare")
async def similarity_compare(progress_id: str = Form(""), files: List[UploadFile] = File(default=[])):
    if not files:
        raise HTTPException(status_code=400, detail="A sample file is required")
    progress_id = _similarity_progress_id(progress_id)
    _similarity_progress_init(progress_id, "compare_sample")
    _similarity_progress_event(progress_id, "upload", "Received sample for comparison.", "running")
    with tempfile.TemporaryDirectory(prefix="mantis-similarity-", ignore_cleanup_errors=True) as tmpdir:
        staged = await _similarity_stage_uploads(files[:1], tmpdir)
        if not staged:
            _similarity_progress_finish(progress_id, "failed", "No non-empty sample file provided.")
            raise HTTPException(status_code=400, detail="No non-empty sample file provided")
        filename, path = staged[0]
        _similarity_progress_event(progress_id, "upload", f"Staged {filename} for local processing.", "done", filename)
        try:
            out = await asyncio.to_thread(similarity_mod.compare_sample, path, filename, _similarity_progress_callback(progress_id))
            _similarity_progress_finish(progress_id, "done", "Similarity comparison complete.")
            _similarity_clear_cache()
            return out
        except Exception as e:
            logger.exception("Similarity comparison failed")
            _similarity_progress_finish(progress_id, "failed", f"Similarity comparison failed: {e}")
            raise HTTPException(status_code=500, detail=f"Similarity comparison failed: {e}")


@app.get("/api/similarity/comparisons/{comparison_id}")
def similarity_comparison(comparison_id: int):
    try:
        out = similarity_mod.get_comparison(int(comparison_id))
    except Exception as e:
        logger.exception("Similarity comparison read failed")
        raise HTTPException(status_code=500, detail=f"Similarity comparison read failed: {e}")
    if not out:
        raise HTTPException(status_code=404, detail="Similarity comparison not found")
    return out


@app.get("/api/similarity/settings")
def similarity_settings_get():
    return _similarity_cached("settings", similarity_mod.get_settings)


@app.post("/api/similarity/settings")
def similarity_settings_save(req: dict):
    try:
        out = similarity_mod.save_settings(req or {})
        _similarity_clear_cache()
        return out
    except Exception as e:
        logger.exception("Similarity settings save failed")
        raise HTTPException(status_code=400, detail=f"Similarity settings save failed: {e}")


@app.get("/api/similarity/select-ida")
def similarity_select_ida(initial: str = ""):
    ida_names = {"ida.exe", "ida64.exe", "idat.exe", "idat64.exe", "idal.exe", "idal64.exe"}
    if os.name != "nt":
        raise HTTPException(status_code=501, detail="Native file selection is only available on Windows.")
    start = (initial or "").strip().strip('"').strip("'")
    if start and os.path.isfile(start):
        start = os.path.dirname(start)
    if start and not os.path.isdir(start):
        start = ""
    script = r"""
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = 'Select IDA executable'
$dialog.Filter = 'IDA executables (ida*.exe;idat*.exe;idal*.exe)|ida*.exe;idat*.exe;idal*.exe|Executable files (*.exe)|*.exe|All files (*.*)|*.*'
$dialog.CheckFileExists = $true
$dialog.Multiselect = $false
if ($env:MANTIS_INITIAL_DIR -and (Test-Path -LiteralPath $env:MANTIS_INITIAL_DIR)) {
    $dialog.InitialDirectory = $env:MANTIS_INITIAL_DIR
}
$result = $dialog.ShowDialog()
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    [Console]::Out.Write($dialog.FileName)
}
"""
    env = dict(os.environ)
    env["MANTIS_INITIAL_DIR"] = start
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {"cancelled": True, "path": "", "reason": "Selection timed out."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Native file picker failed: {e}")
    if proc.returncode != 0:
        detail = ((proc.stderr or "") + " " + (proc.stdout or "")).strip()
        raise HTTPException(status_code=500, detail=f"Native file picker failed: {detail[:300]}")
    selected = (proc.stdout or "").strip().strip('"')
    if not selected:
        return {"cancelled": True, "path": ""}
    abs_path = os.path.abspath(os.path.expanduser(selected))
    if not os.path.isfile(abs_path) or os.path.basename(abs_path).lower() not in ida_names:
        raise HTTPException(status_code=400, detail="Selected file is not a supported IDA executable.")
    return {"cancelled": False, "path": abs_path}


@app.get("/api/similarity/browse-path")
def similarity_browse_path(path: str = ""):
    import string as _string
    raw = (path or "").strip().strip('"').strip("'")
    if not raw:
        if os.name == "nt":
            drives = [f"{d}:\\" for d in _string.ascii_uppercase if os.path.exists(f"{d}:\\")]
            return {"path": "", "parent": None,
                    "entries": [{"name": d, "path": d, "is_dir": True, "selectable": False} for d in drives],
                    "truncated": False}
        raw = "/"
    abs_path = os.path.abspath(os.path.expanduser(raw))
    ida_names = {"ida.exe", "ida64.exe", "idat.exe", "idat64.exe", "idal.exe", "idal64.exe"}
    if os.path.isfile(abs_path) and not os.path.islink(abs_path):
        return {"path": abs_path, "parent": os.path.dirname(abs_path) or None, "is_file": True,
                "entries": [{"name": os.path.basename(abs_path), "path": abs_path,
                             "is_dir": False, "selectable": os.path.basename(abs_path).lower() in ida_names}],
                "truncated": False}
    if not os.path.isdir(abs_path):
        raise HTTPException(status_code=400, detail="Path does not exist")
    try:
        names = sorted(os.listdir(abs_path))
    except OSError as e:
        raise HTTPException(status_code=400, detail=f"Cannot list folder: {e}")
    entries = []
    truncated = False
    for name in names:
        full = os.path.join(abs_path, name)
        try:
            is_dir = os.path.isdir(full) and not os.path.islink(full)
            is_file = os.path.isfile(full) and not os.path.islink(full)
        except OSError:
            continue
        selectable = is_file and name.lower() in ida_names
        if not is_dir and not selectable:
            continue
        entries.append({"name": name, "path": full, "is_dir": is_dir, "selectable": selectable})
        if len(entries) >= 500:
            truncated = True
            break
    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    parent = os.path.dirname(abs_path.rstrip("\\/")) or None
    if parent == abs_path:
        parent = None
    return {"path": abs_path, "parent": parent, "entries": entries, "truncated": truncated}


# Mount frontend if exists
frontend_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
if not os.path.exists(frontend_path):
    os.makedirs(frontend_path)


def _asset_version() -> int:
    """Cache-buster for app.js/styles.css: max mtime of the frontend files.

    Served as ?v= so browsers always refetch JS/CSS after an update instead
    of running stale cached code (stale JS caused real UI bugs before).
    """
    try:
        return int(max(os.path.getmtime(os.path.join(frontend_path, f))
                       for f in ("app.js", "styles.css", "index.html", "similarity.js")))
    except OSError:
        return 0


@app.get("/", include_in_schema=False)
def _index():
    from fastapi.responses import HTMLResponse
    try:
        with open(os.path.join(frontend_path, "index.html"), "r", encoding="utf-8") as f:
            html = f.read()
    except OSError:
        return HTMLResponse("<h1>MANTIS frontend not found</h1>", status_code=500)

    v = _asset_version()
    html = html.replace('href="styles.css"', f'href="styles.css?v={v}"')
    html = html.replace('src="app.js"', f'src="app.js?v={v}"')
    html = html.replace('src="similarity.js"', f'src="similarity.js?v={v}"')
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})

@app.get("/api/poc/stats")
def api_poc_stats():
    return pocindex_mod.get_stats()

@app.get("/api/poc/sync-status")
def api_poc_sync_status():
    """Return the current background sync state so the UI can show progress."""
    return pocindex_mod.get_sync_status()

@app.get("/api/poc/trending")
def api_poc_trending(limit: int = 20):
    return pocindex_mod.get_trending(limit=limit)

@app.get("/api/poc/search")
def api_poc_search(q: str = "", kev: bool = False, has_poc: bool = False, severity: str = "", source: str = "", limit: int = 50, page: int = 1, sort: str = "NEWEST"):
    offset = max(0, (page - 1) * limit)
    return pocindex_mod.search_poc(
        query=q,
        severity_filter=[s.strip().upper() for s in severity.split(",")] if severity else None,
        source_filter=[s.strip().upper() for s in source.split(",")] if source else None,
        kev_only=kev,
        has_poc_only=has_poc,
        limit=limit,
        offset=offset,
        sort_by=sort
    )

@app.get("/api/osv/vuln/{vuln_id}")
def api_osv_vuln(vuln_id: str):
    return pocindex_mod.query_osv_vulnerability(vuln_id)

@app.get("/api/osv/ecosystems")
def api_osv_ecosystems():
    return pocindex_mod.get_osv_ecosystems()

@app.get("/api/osv/malicious-stats")
def api_osv_malicious_stats():
    return pocindex_mod.get_osv_malicious_stats()

@app.get("/api/osv/recent")
def api_osv_recent(ecosystem: str = "", malicious: bool = False, limit: int = 50, offset: int = 0,
                   include_details: bool = False, q: str = ""):
    return pocindex_mod.query_osv_recent(
        ecosystem=ecosystem,
        malicious=malicious,
        limit=limit,
        offset=offset,
        include_details=include_details,
        q=q,
    )

@app.post("/api/osv/query")
def api_osv_query(req: OSVQueryRequest):
    return pocindex_mod.query_osv_package(
        package_name=req.package_name,
        ecosystem=req.ecosystem,
        version=req.version,
        commit=req.commit,
        purl=req.purl,
    )


@app.post("/api/ai/case/{case_id}/assess")
def ai_case_assess_post(case_id: str):
    try:
        return ai_case_mod.generate_case_assessment_db(case_id)
    except Exception as e:
        logger.exception("MANTIS AI case assess failed")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/ai/case/{case_id}/export")
def ai_case_export(case_id: str):
    from fastapi.responses import PlainTextResponse
    try:
        data = ai_case_mod.export_case_markdown(case_id)
        return PlainTextResponse(data["markdown"], headers={"Content-Disposition": f"attachment; filename=\"{data['filename']}\""})
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception("MANTIS AI case export failed")
        raise HTTPException(status_code=500, detail="MANTIS AI case export failed.")

@app.get("/api/ai/case/{case_id}/export-json")
def ai_case_export_json(case_id: str):
    from fastapi.responses import JSONResponse
    try:
        case = ai_case_mod.get_case(case_id)
        return JSONResponse(
            content=case, 
            headers={"Content-Disposition": f"attachment; filename=\"mantis_case_{case_id}.json\""}
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception("MANTIS AI case JSON export failed")
        raise HTTPException(status_code=500, detail="MANTIS AI case JSON export failed.")

class AiCaseAeadRequest(BaseModel):
    case_id: str = ""
    indicator: str = ""
    indicator_type: str = "auto"
    page_context: dict = Field(default_factory=dict)
    selected_sources: list = Field(default_factory=list)
    keys: dict = Field(default_factory=dict)
    github_repos: list = Field(default_factory=list)
    max_enrich_steps: int = 2


@app.post("/api/ai/case/aead-run")
def ai_case_aead_run(req: AiCaseAeadRequest):
    try:
        return ai_case_mod.run_case_aead(req.dict())
    except Exception as e:
        logger.exception("MANTIS AI AEAD run failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/ai/case/{case_id}/report-html")
def ai_case_report_html(case_id: str):
    from fastapi.responses import HTMLResponse
    try:
        data = ai_case_mod.generate_case_html_report(case_id)
        return HTMLResponse(data["html"])
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception("MANTIS AI case HTML report generation failed")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/ai/reports")
def ai_reports_list():
    try:
        return {"reports": ai_case_mod.list_saved_reports()}
    except Exception as e:
        logger.exception("Listing AI reports failed")
        raise HTTPException(status_code=500, detail="Failed to list AI reports.")


@app.get("/api/ai/reports/{filename}")
def ai_report_get_file(filename: str):
    from fastapi.responses import HTMLResponse
    reports_dir = os.path.join(ai_case_mod.DATA_DIR, "reports")
    safe_name = os.path.basename(filename)
    fpath = os.path.join(reports_dir, safe_name)
    if not os.path.exists(fpath):
        # Fallback: check if we can regenerate from case_id
        if safe_name.startswith("mantis_report_") and safe_name.endswith(".html"):
            case_id = safe_name.replace("mantis_report_", "").replace(".html", "")
            try:
                data = ai_case_mod.generate_case_html_report(case_id)
                return HTMLResponse(data["html"])
            except Exception:
                pass
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        with open(fpath, "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    except Exception as e:
        logger.exception("Serving AI report failed")
        raise HTTPException(status_code=500, detail="Failed to read AI report.")


@app.delete("/api/ai/reports/{filename}")
def ai_report_delete_file(filename: str):
    reports_dir = os.path.join(ai_case_mod.DATA_DIR, "reports")
    safe_name = os.path.basename(filename)
    fpath = os.path.join(reports_dir, safe_name)
    if not os.path.exists(fpath):
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        os.remove(fpath)
        return {"deleted": True, "filename": safe_name}
    except Exception as e:
        logger.exception("Deleting AI report failed")
        raise HTTPException(status_code=500, detail="Failed to delete AI report.")




@app.get("/api/binary-lab/select-ghidra")
def binary_lab_select_ghidra(initial: str = "", mode: str = "folder"):
    if os.name != "nt":
        raise HTTPException(status_code=501, detail="Native selection is only available on Windows.")
    start = (initial or "").strip().strip('"').strip("'")
    if start and os.path.isfile(start):
        start = os.path.dirname(start)
    if start and not os.path.isdir(start):
        start = ""
    if mode == "file":
        script = r"""
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = 'Select Ghidra analyzeHeadless executable or ghidraRun'
$dialog.Filter = 'Ghidra files (analyzeHeadless*.bat;ghidraRun*.bat)|analyzeHeadless*.bat;ghidraRun*.bat|Batch files (*.bat;*.cmd)|*.bat;*.cmd|All files (*.*)|*.*'
$dialog.CheckFileExists = $true
$dialog.Multiselect = $false
if ($env:MANTIS_INITIAL_DIR -and (Test-Path -LiteralPath $env:MANTIS_INITIAL_DIR)) {
    $dialog.InitialDirectory = $env:MANTIS_INITIAL_DIR
}
$result = $dialog.ShowDialog()
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    [Console]::Out.Write($dialog.FileName)
}
"""
    else:
        script = r"""
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.Description = 'Select Ghidra root installation folder (e.g. ghidra_11.2_PUBLIC)'
$dialog.ShowNewFolderButton = $false
if ($env:MANTIS_INITIAL_DIR -and (Test-Path -LiteralPath $env:MANTIS_INITIAL_DIR)) {
    $dialog.SelectedPath = $env:MANTIS_INITIAL_DIR
}
$result = $dialog.ShowDialog()
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    [Console]::Out.Write($dialog.SelectedPath)
}
"""
    env = dict(os.environ)
    env["MANTIS_INITIAL_DIR"] = start
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {"cancelled": True, "path": "", "reason": "Selection timed out."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Native file picker failed: {e}")
    if proc.returncode != 0:
        detail = ((proc.stderr or "") + " " + (proc.stdout or "")).strip()
        raise HTTPException(status_code=500, detail=f"Native file picker failed: {detail[:300]}")
    selected = (proc.stdout or "").strip().strip('"')
    if not selected:
        return {"cancelled": True, "path": ""}
    abs_path = os.path.abspath(os.path.expanduser(selected))
    return {"cancelled": False, "path": abs_path}


@app.get("/api/binary-lab/select-ida")
def binary_lab_select_ida(initial: str = ""):
    if os.name != "nt":
        raise HTTPException(status_code=501, detail="Native file selection is only available on Windows.")
    start = (initial or "").strip().strip('"').strip("'")
    if start and os.path.isfile(start):
        start = os.path.dirname(start)
    if start and not os.path.isdir(start):
        start = ""
    script = r"""
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = 'Select IDA Pro executable (idat64.exe or ida64.exe)'
$dialog.Filter = 'IDA executables (idat64*.exe;ida64*.exe;ida*.exe)|idat64*.exe;ida64*.exe;ida*.exe;idat*.exe|Executable files (*.exe)|*.exe|All files (*.*)|*.*'
$dialog.CheckFileExists = $true
$dialog.Multiselect = $false
if ($env:MANTIS_INITIAL_DIR -and (Test-Path -LiteralPath $env:MANTIS_INITIAL_DIR)) {
    $dialog.InitialDirectory = $env:MANTIS_INITIAL_DIR
}
$result = $dialog.ShowDialog()
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    [Console]::Out.Write($dialog.FileName)
}
"""
    env = dict(os.environ)
    env["MANTIS_INITIAL_DIR"] = start
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {"cancelled": True, "path": "", "reason": "Selection timed out."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Native file picker failed: {e}")
    if proc.returncode != 0:
        detail = ((proc.stderr or "") + " " + (proc.stdout or "")).strip()
        raise HTTPException(status_code=500, detail=f"Native file picker failed: {detail[:300]}")
    selected = (proc.stdout or "").strip().strip('"')
    if not selected:
        return {"cancelled": True, "path": ""}
    abs_path = os.path.abspath(os.path.expanduser(selected))
    return {"cancelled": False, "path": abs_path}


@app.get("/api/binary-lab/select-goresym")
def binary_lab_select_goresym(initial: str = ""):
    if os.name != "nt":
        raise HTTPException(status_code=501, detail="Native file selection is only available on Windows.")
    start = (initial or "").strip().strip('"').strip("'")
    if start and os.path.isfile(start):
        start = os.path.dirname(start)
    if start and not os.path.isdir(start):
        start = ""
    script = r"""
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = 'Select GoReSym executable (GoReSym.exe)'
$dialog.Filter = 'GoReSym executable (GoReSym*.exe;goresym*.exe)|GoReSym*.exe;goresym*.exe|Executable files (*.exe)|*.exe|All files (*.*)|*.*'
$dialog.CheckFileExists = $true
$dialog.Multiselect = $false
if ($env:MANTIS_INITIAL_DIR -and (Test-Path -LiteralPath $env:MANTIS_INITIAL_DIR)) {
    $dialog.InitialDirectory = $env:MANTIS_INITIAL_DIR
}
$result = $dialog.ShowDialog()
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    [Console]::Out.Write($dialog.FileName)
}
"""
    env = dict(os.environ)
    env["MANTIS_INITIAL_DIR"] = start
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {"cancelled": True, "path": "", "reason": "Selection timed out."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Native file picker failed: {e}")
    if proc.returncode != 0:
        detail = ((proc.stderr or "") + " " + (proc.stdout or "")).strip()
        raise HTTPException(status_code=500, detail=f"Native file picker failed: {detail[:300]}")
    selected = (proc.stdout or "").strip().strip('"')
    if not selected:
        return {"cancelled": True, "path": ""}
    abs_path = os.path.abspath(os.path.expanduser(selected))
    return {"cancelled": False, "path": abs_path}


@app.get("/api/binary-lab/select-ilspycmd")
def binary_lab_select_ilspycmd(initial: str = ""):
    if os.name != "nt":
        raise HTTPException(status_code=501, detail="Native file selection is only available on Windows.")
    start = (initial or "").strip().strip('"').strip("'")
    if start and os.path.isfile(start):
        start = os.path.dirname(start)
    if start and not os.path.isdir(start):
        start = ""
    script = r"""
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = 'Select ILSpyCmd binary (ilspycmd.exe or ilspycmd.dll)'
$dialog.Filter = 'ILSpyCmd binary (ilspycmd*.exe;ilspycmd*.dll)|ilspycmd*.exe;ilspycmd*.dll|Executable files (*.exe)|*.exe|All files (*.*)|*.*'
$dialog.CheckFileExists = $true
$dialog.Multiselect = $false
if ($env:MANTIS_INITIAL_DIR -and (Test-Path -LiteralPath $env:MANTIS_INITIAL_DIR)) {
    $dialog.InitialDirectory = $env:MANTIS_INITIAL_DIR
}
$result = $dialog.ShowDialog()
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    [Console]::Out.Write($dialog.FileName)
}
"""
    env = dict(os.environ)
    env["MANTIS_INITIAL_DIR"] = start
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {"cancelled": True, "path": "", "reason": "Selection timed out."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Native file picker failed: {e}")
    if proc.returncode != 0:
        detail = ((proc.stderr or "") + " " + (proc.stdout or "")).strip()
        raise HTTPException(status_code=500, detail=f"Native file picker failed: {detail[:300]}")
    selected = (proc.stdout or "").strip().strip('"')
    if not selected:
        return {"cancelled": True, "path": ""}
    abs_path = os.path.abspath(os.path.expanduser(selected))
    return {"cancelled": False, "path": abs_path}



@app.get("/api/binary-lab/select-folder")
def binary_lab_select_folder(initial: str = ""):
    if os.name != "nt":
        raise HTTPException(status_code=501, detail="Native folder selection is only available on Windows.")
    start = (initial or "").strip().strip('"').strip("'")
    if start and not os.path.isdir(start):
        start = ""
    script = r"""
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.Description = 'Select directory of binary samples for Binary Lab'
$dialog.ShowNewFolderButton = $false
if ($env:MANTIS_INITIAL_DIR -and (Test-Path -LiteralPath $env:MANTIS_INITIAL_DIR)) {
    $dialog.SelectedPath = $env:MANTIS_INITIAL_DIR
}
$result = $dialog.ShowDialog()
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    [Console]::Out.Write($dialog.SelectedPath)
}
"""
    env = dict(os.environ)
    env["MANTIS_INITIAL_DIR"] = start
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {"cancelled": True, "path": "", "reason": "Selection timed out."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Native folder picker failed: {e}")
    if proc.returncode != 0:
        detail = ((proc.stderr or "") + " " + (proc.stdout or "")).strip()
        raise HTTPException(status_code=500, detail=f"Native folder picker failed: {detail[:300]}")
    selected = (proc.stdout or "").strip().strip('"')
    if not selected:
        return {"cancelled": True, "path": ""}
    abs_path = os.path.abspath(os.path.expanduser(selected))
    return {"cancelled": False, "path": abs_path}


@app.get("/api/binary-lab/status")
def binary_lab_status():
    return binary_lab_mod.engine_status()


@app.get("/api/binary-lab/settings")
def binary_lab_settings():
    return binary_lab_mod.get_settings(mask=True)


@app.post("/api/binary-lab/settings")
def binary_lab_settings_save(req: dict):
    try:
        return binary_lab_mod.save_settings(req or {})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/binary-lab/test-provider")
def binary_lab_test_provider(req: dict = None):
    try:
        return binary_lab_mod.test_provider_connection(req or {})
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/binary-lab/jobs")
def binary_lab_jobs(limit: int = 50):
    return binary_lab_mod.list_jobs(limit=limit)


@app.get("/api/binary-lab/jobs/{job_id}")
def binary_lab_job(job_id: str):
    try:
        return binary_lab_mod.get_job(job_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/api/binary-lab/jobs/{job_id}/catalogs")
def binary_lab_job_catalogs(job_id: str, sample_index: int = 0):
    try:
        return binary_lab_mod.get_job_catalogs(job_id, sample_index=sample_index)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/api/binary-lab/jobs/{job_id}/ida-log")
def binary_lab_job_ida_log(job_id: str, sample_index: int = 0):
    try:
        return binary_lab_mod.get_job_ida_log(job_id, sample_index=sample_index)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/api/binary-lab/jobs/path")
def binary_lab_start_path(payload: dict):
    path = str(payload.get("path") or "").strip()
    if not path:
        raise HTTPException(status_code=400, detail="Missing path")
    try:
        return binary_lab_mod.create_job_from_path(path, payload.get("settings") or {})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/binary-lab/jobs/upload")
def binary_lab_start_upload(files: List[UploadFile] = File(...), config: str = Form(None)):
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")
    try:
        overrides = json.loads(config or "{}")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid config JSON: {exc}")
    try:
        return binary_lab_mod.create_job_from_uploads(files, overrides)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/binary-lab/jobs/{job_id}/cancel")
def binary_lab_cancel_job(job_id: str):
    if not binary_lab_mod.cancel_job(job_id):
        raise HTTPException(status_code=404, detail="Job not running or already stopped.")
    return {"cancelled": True}


@app.post("/api/binary-lab/jobs/{job_id}/resume")
def binary_lab_resume_job(job_id: str):
    try:
        return binary_lab_mod.resume_job(job_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.delete("/api/binary-lab/jobs/{job_id}")
def binary_lab_delete_job(job_id: str):
    try:
        binary_lab_mod.delete_job(job_id)
        return {"deleted": True}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/api/binary-lab/jobs/{job_id}/artifacts")
def binary_lab_job_artifacts(job_id: str):
    try:
        return binary_lab_mod.list_artifacts(job_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/api/binary-lab/jobs/{job_id}/artifacts/{artifact_path:path}")
def binary_lab_job_artifact(job_id: str, artifact_path: str, download: bool = False):
    try:
        abs_path = binary_lab_mod.artifact_path(job_id, artifact_path)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    from fastapi.responses import FileResponse

    suffix = abs_path.suffix.lower()
    media_type = None
    if suffix in (".html", ".htm"):
        media_type = "text/html; charset=utf-8"
    elif suffix == ".pdf":
        media_type = "application/pdf"
    elif suffix in (".md", ".txt", ".json", ".log"):
        media_type = "text/plain; charset=utf-8"

    headers = {"X-Content-Type-Options": "nosniff"}
    if suffix in (".html", ".htm"):
        headers["Content-Security-Policy"] = (
            "sandbox; default-src 'none'; style-src 'unsafe-inline'; "
            "img-src data:; font-src data:"
        )

    if download:
        return FileResponse(str(abs_path), filename=abs_path.name, media_type=media_type,
                            content_disposition_type="attachment", headers=headers)
    return FileResponse(str(abs_path), media_type=media_type, content_disposition_type="inline", headers=headers)


@app.get("/api/binary-lab/jobs/{job_id}/download")
def binary_lab_download_job(job_id: str):
    from fastapi.responses import Response
    try:
        archive = binary_lab_mod.zip_output(job_id)
        return Response(
            content=archive,
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{job_id}.zip"'},
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/api/binary-lab/jobs/{job_id}/case")
def binary_lab_create_case(job_id: str, payload: dict = None):
    try:
        sample_idx = int((payload or {}).get("sample_index", 0))
        return binary_lab_mod.create_case_from_job(job_id, sample_index=sample_idx)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# Mount frontend static files as fallback route (must remain at the end of the file)
app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")

