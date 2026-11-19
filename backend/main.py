import os
import sys

# Ensure both repo root and backend directory are on sys.path
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_BACKEND_DIR)
for _p in (_REPO_ROOT, _BACKEND_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import json
import binary_lab as binary_lab_mod
from fastapi import Cookie, Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import StreamingResponse
import requests
import http_defaults

# Every outbound provider call gets a socket timeout unless the caller sets one.
http_defaults.install()
from typing import Any, Dict, List, Optional, Tuple
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from misp_updater import download_misp_clusters
import yara_updater
from yara_updater import (
    download_yara_forge,
    download_elastic_yara,
    download_yaraify,
    download_malpedia_yara,
)
import startup_progress
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
import intel_reports as intel_reports_mod
import ransom_notes_db as ransom_notes_db_mod
import todays_intelligence as todays_intel_mod
import x_monitor as x_monitor_mod
import breach_watcher
import credential_stealer as cred_stealer_mod
import tweetfeed_service as tweetfeed_mod
import infra_hunt_service as infra_hunt_mod
import infra_pivoting_service as infra_pivoting_mod
import vt_hunting_service as vt_hunting_mod
import deployment_config
import auth_service
import login_throttle
import malware_db as mwdb_mod
from yara_repos import (
    discover_repos as yara_discover_repos,
    discover_explorer_repos as yara_discover_explorer_repos,
    ensure_all_built as yara_ensure_all_built,
    engine_status as yara_engine_status,
    search_rules as yara_search_rules,
    get_rule_source as yara_get_rule_source,
    save_rule_in_repo as yara_save_rule_in_repo,
    delete_rule as yara_delete_rule,
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
import sigma_repos
import sigma_engine
import sigma_converter
import sigma_updater
import data_updater
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
from uuid import UUID
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

# Paths that must answer without a session even in server mode: the sign-in
# surface itself, the deployment banner the login page reads, the startup
# progress the loader polls, and the SSO sign-in flow (itself an auth path).
_SERVER_MODE_PUBLIC_PATHS = {
    "/api/config/deployment",
    "/api/meta/startup-progress",
    "/api/meta/startup-status",
}
_SERVER_MODE_PUBLIC_PREFIXES = ("/api/auth/", "/api/ai/sso/")


def _enforce_server_mode_auth(request: Request) -> None:
    """Require a session for every API call when running as a team server.

    `get_current_user` already returns 401 in server mode, but it was only wired
    into a handful of routes, so the rest of the API (including destructive
    endpoints and the AI/provider settings) answered anonymously. Applied
    app-wide it covers every current and future route. Workstation mode is
    untouched: `get_current_user` still resolves the local analyst.
    """
    if not deployment_config.is_server_mode():
        return None
    path = request.url.path
    if not path.startswith("/api/"):
        return None  # static shell, health, docs
    if path in _SERVER_MODE_PUBLIC_PATHS:
        return None
    if any(path.startswith(p) for p in _SERVER_MODE_PUBLIC_PREFIXES):
        return None
    # Pass the header/cookie explicitly: calling the dependency directly would
    # leave its FastAPI markers (Header(None), Cookie(None)) as the arguments.
    get_current_user(request, request.headers.get("authorization"),
                     request.cookies.get("mantis_session"))  # raises 401 without a session
    return None


app = FastAPI(title="MANTIS", dependencies=[Depends(_enforce_server_mode_auth)])
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

def _sigma_sync_then_warm_index() -> None:
    """Sync Sigma repositories, then build the YAML index off the request path.

    Indexing ~9.5k rule files takes ~30s; doing it inside the first GET made
    /api/sigma/repos, /api/sigma/stats and /api/sigma/rules look like they had
    hung, and the UI retried, stacking the work.
    """
    try:
        sigma_updater.download_all_repositories(force=False)
    except Exception as e:
        logger.warning("Sigma repository sync failed: %s", e)
    try:
        rules = sigma_repos.index_rules()
        logger.info("Sigma rule index warmed: %d rules", len(rules or []))
    except Exception as e:
        logger.warning("Sigma rule index warm-up failed: %s", e)


@app.on_event("startup")
def start_background_update_loops():
    global _background_updates_started, _startup_executor
    if _background_updates_started:
        return
    _background_updates_started = True
    t0 = time.monotonic()
    try:
        auth_service.init_users_db(rotate_admin=True)
    except Exception as e:
        logger.exception("Failed to initialize user authentication database on startup: %s", e)
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
    _register_startup_progress(heavy_delay)
    _startup_executor.submit(_timed_task, "misp-clusters", download_misp_clusters)
    _startup_executor.submit(_timed_task, "pocindex-init", pocindex_mod.init_pocindex)
    for name in ("yara-forge", "yara-elastic", "yaraify", "malpedia-yara", "yara-repos", "rss-refresh", "cti-registry", "cti-sync"):
        _startup_status[name] = {"state": "waiting", "starts_in_s": heavy_delay}
    threading.Thread(target=_delayed_heavy_startup, name="mantis-heavy-starter",
                     args=(heavy_delay,), daemon=True).start()
    if _mantis_env("MANTIS_INFRA_MONITOR_ENABLED", default="true").lower() not in {"0", "false", "no"}:
        _infra_monitor_stop.clear()
        threading.Thread(target=_infra_monitor_loop, name="mantis-infra-monitor", daemon=True).start()
    try:
        cred_stealer_mod.start_weekly_scheduler()
    except Exception:
        logger.exception("Credential Stealer scheduler init failed")
    logger.info("MANTIS startup: fast tasks submitted in %.2fs (heavy tasks deferred, see per-task finish logs)", time.monotonic() - t0)


@app.on_event("shutdown")
def stop_background_update_loops():
    global _startup_executor
    _infra_monitor_stop.set()
    ex, _startup_executor = _startup_executor, None
    if ex is not None:
        ex.shutdown(wait=False, cancel_futures=True)


_STARTUP_PROGRESS_TASKS = (
    ("misp-clusters", "MISP galaxies (threat actors, malware, tools)", None, "files"),
    ("pocindex", "PoC index (CVE exploits, KEV, CVSS)", None, "files"),
    ("cveproject", "CVEProject baseline", None, "bytes"),
    ("yara-forge", "YARA Forge rules", None, "bytes"),
    ("yara-elastic", "Elastic YARA rules", None, "files"),
    ("yaraify", "YARAify rules", None, "bytes"),
    ("malpedia-yara", "Malpedia YARA rules", None, "bytes"),
    ("sigma-hq", "SigmaHQ Detection Rules (Official)", None, "bytes"),
    ("sigma-hayabusa", "Hayabusa Event Log Rules (Yamato Security)", None, "bytes"),
    ("sigma-mdecrevoisier", "mdecrevoisier Cloud & AD Rules", None, "bytes"),
    ("sigma-joe-security", "Joe Security Cloud Sigma Rules", None, "bytes"),
    ("sigma-mbabinski", "mbabinski Red Team & Threat Rules", None, "bytes"),
    ("sigma-tsale", "tsale Adversary Tradecraft Rules", None, "bytes"),
)


def _register_startup_progress(heavy_delay: float) -> None:
    """Declare every first-run download up front so the UI lists them immediately."""
    for key, label, total, unit in _STARTUP_PROGRESS_TASKS:
        startup_progress.register(key, label, total=total, unit=unit)
    startup_progress.register("yara-repos", "Local YARA repositories", unit="files")
    startup_progress.skip("yara-repos", "Built on demand (Rule Explorer)")

    # Pre-check local caches immediately so returning users aren't left in 'Waiting' state
    try:
        if yara_updater._is_fresh(yara_updater.YARA_FORGE_EXTRACT):
            startup_progress.skip("yara-forge", "Already up to date (cached)")
        if yara_updater._is_fresh(yara_updater.ELASTIC_YARA_EXTRACT):
            startup_progress.skip("yara-elastic", "Already up to date (cached)")
        if yara_updater._is_fresh(yara_updater.YARAIFY_EXTRACT):
            startup_progress.skip("yaraify", "Already up to date (cached)")
        if yara_updater._is_fresh(yara_updater.MALPEDIA_YARA_EXTRACT):
            startup_progress.skip("malpedia-yara", "Already up to date (cached)")
    except Exception as e:
        logger.debug("YARA cache check error: %s", e)

    try:
        if os.path.exists(pocindex_mod.CVEPROJECT_LIST):
            startup_progress.skip("cveproject", "Already up to date (cached)")
    except Exception as e:
        logger.debug("CVEProject cache check error: %s", e)

    try:
        if sigma_updater.is_repo_downloaded("sigma-hq"):
            startup_progress.skip("sigma-hq", "Already up to date (cached)")
        if sigma_updater.is_repo_downloaded("hayabusa"):
            startup_progress.skip("sigma-hayabusa", "Already up to date (cached)")
        if sigma_updater.is_repo_downloaded("mdecrevoisier"):
            startup_progress.skip("sigma-mdecrevoisier", "Already up to date (cached)")
        if sigma_updater.is_repo_downloaded("joe-security"):
            startup_progress.skip("sigma-joe-security", "Already up to date (cached)")
        if sigma_updater.is_repo_downloaded("mbabinski"):
            startup_progress.skip("sigma-mbabinski", "Already up to date (cached)")
        if sigma_updater.is_repo_downloaded("tsale"):
            startup_progress.skip("sigma-tsale", "Already up to date (cached)")
    except Exception as e:
        logger.debug("Sigma cache check error: %s", e)


def _yara_startup_build():
    # Startup build is serial (one repo at a time): parallel multi-repo
    # compiles oversubscribe the CPU and starve request serving.
    # On-demand refreshes elsewhere keep full parallelism.
    return yara_ensure_all_built(max_workers=1)


def _delayed_heavy_startup(delay_s: float):
    """Sleep, then launch the heavy refresh jobs in parallel threads."""
    needs_download = False
    try:
        if not yara_updater._is_fresh(yara_updater.YARA_FORGE_EXTRACT) or \
           not yara_updater._is_fresh(yara_updater.ELASTIC_YARA_EXTRACT) or \
           not yara_updater._is_fresh(yara_updater.YARAIFY_EXTRACT) or \
           not yara_updater._is_fresh(yara_updater.MALPEDIA_YARA_EXTRACT):
            needs_download = True
    except Exception:
        needs_download = True

    if needs_download and delay_s > 0:
        time.sleep(delay_s)
    elif delay_s > 0:
        time.sleep(min(3.0, delay_s))

    if _startup_executor is None:  # shutting down before the delay elapsed
        return
    logger.info("MANTIS startup: launching deferred heavy tasks in parallel threads")
    _startup_executor.submit(_timed_task, "yara-forge", download_yara_forge)
    _startup_executor.submit(_timed_task, "yara-elastic", download_elastic_yara)
    _startup_executor.submit(_timed_task, "yaraify", download_yaraify)
    _startup_executor.submit(_timed_task, "malpedia-yara", download_malpedia_yara)
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
    # Sigma detection rules: download & sync all 6 upstream repositories, then
    # warm the YAML index. Building it inside a request cost ~30s per cold call
    # (three routes use it), which read as a hang.
    threading.Thread(target=_sigma_sync_then_warm_index, name="mantis-sigma-sync", daemon=True).start()
    # Weekly & startup auto-updater: checks every startup and runs recurring 7-day refresh for all data/
    threading.Thread(target=data_updater.start_weekly_updater_loop, name="mantis-weekly-data-updater", daemon=True).start()


@app.get("/api/meta/startup-progress")
def startup_progress_status():
    """Per-dataset download progress for the first-run loading screen."""
    return startup_progress.snapshot()


@app.get("/api/meta/auto-update-status")
def get_auto_update_status_endpoint():
    """Returns persistent state of the automatic startup and weekly data updates."""
    return data_updater.get_auto_update_status()


@app.post("/api/meta/auto-update-now")
def trigger_auto_update_now_endpoint():
    """Triggers an immediate background synchronization across all data/ resources."""
    threading.Thread(target=data_updater.run_full_data_update, kwargs={"force": True, "caller": "user_api"}, daemon=True).start()
    return {"success": True, "message": "Full background update initiated for all datasets in data/."}


@app.get("/api/meta/startup-status")
def startup_status():
    """Diagnostics: per-task startup timing so slow starts are explainable."""
    return {"tasks": dict(_startup_status)}


class DeploymentModeRequest(BaseModel):
    mode: str


@app.get("/api/config/deployment")
def get_deployment_config():
    """Returns deployment mode (workstation vs server), tool auto-detection, and staging paths."""
    return deployment_config.get_deployment_summary()


@app.post("/api/config/deployment/mode")
def set_deployment_mode_endpoint(req: DeploymentModeRequest):
    """Updates deployment mode (workstation vs server) and persists to .env."""
    if deployment_config.is_server_mode() and req.mode.lower() == "workstation":
        raise HTTPException(
            status_code=400,
            detail="Switching to Workstation mode from the web interface is disabled while running in Team Server mode. Configure MANTIS_MODE at startup via run.bat or .env."
        )
    mode = deployment_config.set_deployment_mode(req.mode)
    return deployment_config.get_deployment_summary()


@app.get("/api/staging/list")
def list_staging_files_endpoint(category: str = "all"):
    """Lists files/directories available in server staging (samples, stealer_logs)."""
    return deployment_config.list_staging_items(category)


# ===========================================================================
# MULTI-USER AUTHENTICATION & PERSONAL ENCRYPTED API KEY VAULT
# ===========================================================================

class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "analyst"


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class ResetUserPasswordRequest(BaseModel):
    new_password: str


class UserKeySaveRequest(BaseModel):
    provider: str
    key: str


def get_current_user(
    request: Request,
    authorization: Optional[str] = Header(None),
    mantis_session: Optional[str] = Cookie(None),
) -> Dict[str, Any]:
    """Resolve active user. Checks session token; in workstation mode defaults to local analyst."""
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    elif mantis_session:
        token = mantis_session.strip()

    if token:
        user = auth_service.verify_session_token(token)
        if user:
            user["mode"] = "server" if deployment_config.is_server_mode() else "workstation"
            return user

    if not deployment_config.is_server_mode():
        return {
            "id": "workstation_user",
            "username": "local_analyst",
            "role": "admin",
            "mode": "workstation",
        }

    raise HTTPException(status_code=401, detail="Authentication required in Team Server mode.")


def require_admin_user(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required.")
    return current_user


@app.post("/api/staging/upload")
async def staging_upload_endpoint(
    category: str = Form("samples"),
    files: List[UploadFile] = File(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Upload malware samples or stealer logs directly into server drop zones via Web UI."""
    if category not in ("samples", "stealer_logs"):
        raise HTTPException(status_code=400, detail=f"Invalid staging category: {category}")
    if not files:
        raise HTTPException(status_code=400, detail="No files provided for upload.")

    saved_items = []
    for f in files:
        if not f.filename:
            continue
        try:
            saved = deployment_config.save_staging_file(category, f.filename, f.file)
            saved_items.append(saved)
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to save file {f.filename}: {e}")

    return {
        "success": True,
        "category": category,
        "count": len(saved_items),
        "items": saved_items,
        "staging": deployment_config.list_staging_items(category),
    }


@app.delete("/api/staging/item")
def staging_delete_item_endpoint(
    category: str = Query(...),
    filename: str = Query(...),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Delete a file or folder from server drop zones via Web UI."""
    if category not in ("samples", "stealer_logs"):
        raise HTTPException(status_code=400, detail=f"Invalid staging category: {category}")
    try:
        deleted = deployment_config.delete_staging_file(category, filename)
        if not deleted:
            raise HTTPException(status_code=404, detail=f"Item '{filename}' not found in {category}.")
        return {
            "success": True,
            "category": category,
            "filename": filename,
            "staging": deployment_config.list_staging_items(category),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error deleting file: {e}")



def _request_is_https(request: Request) -> bool:
    proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
    if proto:
        return proto == "https"
    try:
        return request.url.scheme == "https"
    except Exception:
        return False


def _cookie_secure(request: Request) -> bool:
    """Whether the session cookie is marked Secure.

    `MANTIS_COOKIE_SECURE` forces the value (1/0); otherwise it mirrors the
    scheme of the request, so HTTPS deployments get a Secure cookie while
    plain-HTTP installs keep working.
    """
    raw = (os.environ.get("MANTIS_COOKIE_SECURE") or "auto").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return _request_is_https(request)


@app.post("/api/auth/login")
def auth_login(req: LoginRequest, response: Response, request: Request):
    client_addr = request.client.host if request.client else ""
    wait = login_throttle.get_throttle().retry_after(req.username, client_addr)
    if wait:
        # Same generic wording as a bad password: the throttle must not reveal
        # whether the account exists.
        response.headers["Retry-After"] = str(wait)
        raise HTTPException(status_code=429,
                            detail=f"Too many failed sign-in attempts. Try again in {wait} seconds.",
                            headers={"Retry-After": str(wait)})
    user = auth_service.authenticate_user(req.username, req.password)
    if not user:
        remaining_wait = login_throttle.get_throttle().register_failure(req.username, client_addr)
        if remaining_wait:
            logger.warning("Login throttled for %s from %s (%ss)",
                           req.username[:64], client_addr or "unknown", remaining_wait)
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    login_throttle.get_throttle().reset(req.username, client_addr)
    token = auth_service.create_session_token(user)
    response.set_cookie(
        key="mantis_session",
        value=token,
        httponly=True,
        samesite="lax",
        secure=_cookie_secure(request),
        max_age=86400 * 7,
        path="/",
    )
    return {"success": True, "token": token, "user": user}


@app.post("/api/auth/logout")
def auth_logout(request: Request, response: Response):
    # Delete the cookie and also kill the token server-side: clearing the cookie
    # alone left a copied token valid for its full 7-day lifetime.
    token = request.cookies.get("mantis_session", "")
    if not token:
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()
    if token:
        try:
            auth_service.revoke_session(token)
        except Exception as e:
            logger.warning("Session revocation failed: %s", e)
    response.delete_cookie(key="mantis_session", path="/")
    return {"success": True}


@app.get("/api/auth/me")
def auth_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    return {
        "authenticated": True,
        "user": current_user,
        "mode": current_user.get("mode", "workstation"),
    }


@app.get("/api/auth/users")
def auth_list_users(admin: Dict[str, Any] = Depends(require_admin_user)):
    return {"users": auth_service.list_users()}


@app.post("/api/auth/users")
def auth_create_user(req: CreateUserRequest, admin: Dict[str, Any] = Depends(require_admin_user)):
    try:
        new_u = auth_service.create_user(req.username, req.password, req.role)
        return {"success": True, "user": new_u}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/api/auth/users/{user_id}")
def auth_delete_user(user_id: str, admin: Dict[str, Any] = Depends(require_admin_user)):
    if user_id == admin.get("id"):
        raise HTTPException(status_code=400, detail="Cannot delete your own admin account.")
    deleted = auth_service.delete_user(user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="User not found.")
    return {"success": True, "deleted": user_id}


@app.post("/api/auth/password")
def auth_change_password(
    req: ChangePasswordRequest,
    response: Response,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Allows any logged in user (or admin) to change their own password."""
    if current_user.get("id") == "workstation_user":
        raise HTTPException(status_code=400, detail="Cannot change password for local workstation guest.")

    # Authenticate current password
    user = auth_service.authenticate_user(current_user["username"], req.current_password)
    if not user:
        raise HTTPException(status_code=400, detail="Current password is incorrect.")

    if len(req.new_password) < auth_service.MIN_ADMIN_PASSWORD_LEN:
        raise HTTPException(
            status_code=400,
            detail=f"New password must be at least {auth_service.MIN_ADMIN_PASSWORD_LEN} characters long."
        )

    persist_env = (current_user.get("role") == "admin")
    auth_service.set_user_password(current_user["id"], req.new_password, persist_env=persist_env)

    # Issue refreshed session token
    refreshed_user = auth_service.get_user_by_id(current_user["id"]) or user
    new_token = auth_service.create_session_token(refreshed_user)
    response.set_cookie(
        key="mantis_session",
        value=new_token,
        httponly=True,
        samesite="lax",
        secure=_cookie_secure(request),
        max_age=86400 * 7,
        path="/",
    )

    return {
        "success": True,
        "token": new_token,
        "message": "Password updated successfully." + (" (Saved to .env)" if persist_env else "")
    }


@app.post("/api/auth/users/{user_id}/password")
def auth_reset_user_password(
    user_id: str,
    req: ResetUserPasswordRequest,
    admin: Dict[str, Any] = Depends(require_admin_user),
):
    """Allows an administrator to reset another analyst's password."""
    user = auth_service.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if len(req.new_password) < auth_service.MIN_ADMIN_PASSWORD_LEN:
        raise HTTPException(
            status_code=400,
            detail=f"New password must be at least {auth_service.MIN_ADMIN_PASSWORD_LEN} characters long."
        )

    persist_env = (user.get("role") == "admin")
    auth_service.set_user_password(user_id, req.new_password, persist_env=persist_env)
    return {
        "success": True,
        "message": f"Password for '{user['username']}' updated successfully." + (" (Saved to .env)" if persist_env else "")
    }


@app.get("/api/user/keys")
def get_user_keys_endpoint(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Return all configured API keys for the current logged-in analyst (masked)."""
    keys = auth_service.get_all_user_api_keys(current_user["id"], mask=True)
    return {"user_id": current_user["id"], "username": current_user["username"], "keys": keys}


@app.post("/api/user/keys")
def save_user_key_endpoint(req: UserKeySaveRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Encrypt and save a personal API key for the current logged-in analyst."""
    auth_service.save_user_api_key(current_user["id"], req.provider, req.key)
    return {
        "success": True,
        "provider": req.provider,
        "keys": auth_service.get_all_user_api_keys(current_user["id"], mask=True),
    }


class ThreatClusterStatusRequest(BaseModel):
    api_key: str = ""


@app.post("/api/threatcluster/status")
def threatcluster_status(req: ThreatClusterStatusRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Plan, scopes and daily credits for a ThreatCluster key. Uses the body key when given
    (to test before saving), otherwise the analyst's stored key. /me costs no credits."""
    from threatcluster_client import key_status
    api_key = (req.api_key or "").strip()
    if not api_key:
        stored = auth_service.get_all_user_api_keys(current_user["id"], mask=False)
        api_key = (stored.get("threatcluster") or "").strip()
    if not api_key:
        raise HTTPException(status_code=400, detail="No ThreatCluster API key saved for this account.")
    result = key_status(api_key)
    if "error" in result:
        raise HTTPException(status_code=502, detail=result["error"])
    return result


@app.delete("/api/user/keys/{provider}")
def delete_user_key_endpoint(provider: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Remove a personal API key for the current logged-in analyst."""
    auth_service.delete_user_api_key(current_user["id"], provider)
    return {"success": True, "deleted": provider}





class FeedToggleRequest(BaseModel):
    id: str
    enabled: bool


class FeedExportRequest(BaseModel):
    feed_ids: list[str]

@app.get("/api/feeds/catalog")
def feeds_catalog_list(tip_key: str = Header("", alias="x-tip-key")):
    import feed_manager
    try:
        return {"sources": feed_manager.get_feed_list(tip_key)}
    except Exception as e:
        logger.exception("Failed to get feed catalog")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/feeds/catalog/sync")
def feeds_catalog_sync(tip_key: str = Header("", alias="x-tip-key")):
    import feed_manager
    try:
        res = feed_manager.sync_catalog()
        if not res.get("ok"):
            raise HTTPException(status_code=500, detail=res.get("reason", "unknown error"))
        return {"sources": feed_manager.get_feed_list(tip_key), "added": res.get("added", 0)}
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to sync feed catalog")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/feeds/toggle")
def feeds_catalog_toggle(req: FeedToggleRequest, tip_key: str = Header("", alias="x-tip-key")):
    import feed_manager
    try:
        result = feed_manager.toggle_feed(req.id, req.enabled, tip_key)
        if not result.get("ok"):
            raise HTTPException(status_code=result.get("status", 404), detail=result.get("reason", "Feed source not found"))
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to toggle feed")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/feeds/kaspersky/refresh")
def feeds_kaspersky_refresh(force: bool = False, tip_key: str = Header("", alias="x-tip-key")):
    from feed_intel import refresh_kaspersky_feeds
    from feed_manager import get_feed_list

    refresh_kaspersky_feeds(tip_key, force=force)
    return {"sources": get_feed_list(tip_key)}


@app.post("/api/feeds/export")
def feeds_export(req: FeedExportRequest, tip_key: str = Header("", alias="x-tip-key")):
    from feed_manager import export_feed_csv, get_feed_list

    feed_ids = list(dict.fromkeys(req.feed_ids))
    if not feed_ids or len(feed_ids) > 500:
        raise HTTPException(status_code=400, detail="Select between 1 and 500 feeds.")
    sources = {source["id"]: source for source in get_feed_list(tip_key)}
    for feed_id in feed_ids:
        source = sources.get(feed_id)
        if source is None:
            raise HTTPException(status_code=404, detail="A selected feed no longer exists.")
        if source["status"] == "not-configured":
            raise HTTPException(status_code=403, detail="Configure a Kaspersky TIP token to download this feed.")
        if not source["record_count"]:
            raise HTTPException(status_code=409, detail=f"{source['name']} has no cached indicators yet.")

    return StreamingResponse(
        export_feed_csv(feed_ids), media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="mantis-data-feeds.csv"', "Cache-Control": "no-store"},
    )

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
    allow_all = _mantis_env("MANTIS_ALLOW_ALL_CORS", "IOCINTEL_ALLOW_ALL_CORS", default="false")
    if allow_all.lower() in {"1", "true", "yes"}:
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

@app.middleware("http")
async def no_cache_static_middleware(request, call_next):
    response = await call_next(request)
    path = request.url.path.lower()
    if path.endswith((".js", ".css", ".html")) or path == "/":
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

app.include_router(agent_tools_router)

from opendir_routes import router as opendir_router  # noqa: E402
app.include_router(opendir_router)
if os.environ.get("MANTIS_OPENDIR_WATCH", "1") != "0":
    import opendir_hunt as _opendir_hunt  # noqa: E402
    _opendir_hunt.start_watch_scheduler()

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
    threatcluster_key: str = ""
    sources: list = Field(default_factory=list)  # empty = all sources
    github_repos: list = Field(default_factory=list)


# The Settings UI saves a key under the id of its input element, which is the
# short name for some providers ("vt-key" -> "vt"), while the query layer asks
# for the long one ("virustotal"). Without these aliases a key typed into
# Settings was stored but never used.
USER_KEY_ALIASES = {
    "virustotal": ("vt",),
    "hybrid_analysis": ("ha",),
    "cybercure": ("cb",),
    "ransomware_live": ("rwlive",),
    "twitter": ("x_official",),
    "misp": ("misp_key",),
}


def _stored_key(user_keys: Dict[str, str], provider: str) -> str:
    """Look a provider key up under its canonical id, then its UI aliases."""
    for name in (provider,) + USER_KEY_ALIASES.get(provider, ()):
        value = (user_keys.get(name) or "").strip()
        if value:
            return value
    return ""


INTEL_KEY_FIELDS = {
    # Field on IntelRequest -> provider id used by the key vault.
    "vt_key": "virustotal",
    "shodan_key": "shodan",
    "censys_key": "censys",
    "otx_key": "otx",
    "urlscan_key": "urlscan",
    "abuseipdb_key": "abuseipdb",
    "threatcluster_key": "threatcluster",
    "greynoise_key": "greynoise",
    "fofa_key": "fofa",
    "zoomeye_key": "zoomeye",
    "validin_key": "validin",
    "netlas_key": "netlas",
    "etugen_key": "etugen",
    "pulsedive_key": "pulsedive",
    "silentpush_key": "silentpush",
    "driftnet_key": "driftnet",
    "leakix_key": "leakix",
    "phishstats_key": "phishstats",
    "github_key": "github",
    "twitter_key": "twitter",
    "triage_key": "triage",
    "ha_key": "hybrid_analysis",
    "malshare_key": "malshare",
    "cb_key": "cybercure",
    "rwlive_key": "ransomware_live",
    "threatbook_key": "threatbook",
    "misp_key": "misp",
    "dnsdumpster_key": "dnsdumpster",
    "tip_key": "tip",
    "abusech_key": "abusech",
    "ransomlook_key": "ransomlook",
    "mnemonic_key": "mnemonic",
}


def _populate_user_keys(req: IntelRequest, user_id: str) -> IntelRequest:
    """Inject current user's encrypted personal API keys if not supplied in request."""
    try:
        user_keys = auth_service.get_all_user_api_keys(user_id, mask=False)
        for field, prov in INTEL_KEY_FIELDS.items():
            if getattr(req, field, None):
                continue  # an explicit request value always wins
            value = _stored_key(user_keys, prov)
            if value:
                setattr(req, field, value)
    except Exception as e:
        logger.warning(f"Error populating user keys: {e}")
    return req


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
    x_official_key: str = ""
    provider: str = ""
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
    except Exception as e:
        logger.exception("AI test connection failed")
        raise HTTPException(status_code=500, detail=f"AI connection test failed: {str(e)}")


@app.get("/api/ai/detect-exe")
def ai_detect_exe(provider: str = "antigravity"):
    path = ai_mod.detect_cli_executable(provider)
    if path:
        return {"found": True, "path": path, "provider": provider}
    return {"found": False, "path": "", "provider": provider}


@app.get("/api/ai/sso/status")
def ai_sso_status(provider: str = "chatgpt_desktop"):
    return ai_mod.get_sso_status(provider)


@app.post("/api/ai/sso/signin")
async def ai_sso_signin(req: Optional[dict] = None):
    req = req or {}
    provider = req.get("provider", "chatgpt_desktop")
    if provider == "chatgpt_desktop":
        # Refuse immediately on a host with no desktop session instead of
        # holding the request open for the full sign-in timeout.
        unsupported = ai_mod.sso_signin_unsupported_reason()
        if unsupported:
            raise HTTPException(status_code=400, detail=unsupported)
        try:
            res = await asyncio.to_thread(ai_mod.sign_in_chatgpt, 180)
            return {"ok": True, "data": res}
        except Exception as e:
            logger.exception("ChatGPT SSO sign-in failed")
            raise HTTPException(status_code=400, detail=str(e))
    raise HTTPException(status_code=400, detail=f"SSO signin not supported for provider '{provider}'")


@app.post("/api/ai/sso/signout")
def ai_sso_signout(req: Optional[dict] = None):
    req = req or {}
    provider = req.get("provider", "chatgpt_desktop")
    if provider == "chatgpt_desktop":
        return ai_mod.sign_out_chatgpt()
    return {"ok": True, "signed_in": False}


_DASH_BUILD_LOCK = threading.Semaphore(1)
_DASH_CACHE: dict = {}
_DASH_CACHE_TTL_S = 120
_DASH_CACHE_MAX = 8


def _dash_cache_key(req: "TodaysIntelRequest") -> str:
    """Identify a dashboard request. Provider keys are hashed, never stored raw."""
    import hashlib as _hashlib
    key_material = json.dumps({
        "limit": req.limit, "range": req.range, "source_type": req.source_type,
        "severity": req.severity, "group": req.group, "country": req.country,
        "region": req.region, "sector": req.sector,
    }, sort_keys=True)
    providers = "|".join(sorted(
        f"{name}={getattr(req, name, '') or ''}" for name in (
            "rwlive_key", "abusech_key", "urlscan_key", "github_key", "vt_key",
            "greynoise_key", "shodan_key", "censys_key", "otx_key")))
    return key_material + "#" + _hashlib.sha256(providers.encode()).hexdigest()[:16]


def _dash_cache_get(key: str):
    entry = _DASH_CACHE.get(key)
    if not entry:
        return None
    expires_at, payload = entry
    if expires_at < time.time():
        _DASH_CACHE.pop(key, None)
        return None
    return payload


def _dash_cache_put(key: str, payload) -> None:
    if len(_DASH_CACHE) >= _DASH_CACHE_MAX:
        oldest = min(_DASH_CACHE.items(), key=lambda kv: kv[1][0])[0]
        _DASH_CACHE.pop(oldest, None)
    _DASH_CACHE[key] = (time.time() + _DASH_CACHE_TTL_S, payload)


@app.post("/api/todays-intelligence")
def todays_intelligence(req: TodaysIntelRequest):
    cache_key = _dash_cache_key(req)
    cached = _dash_cache_get(cache_key)
    if cached is not None:
        return cached
    # One dashboard build allocates hundreds of MB (20 fan-out lanes + 500 article
    # summaries). Without a guard, a handful of parallel clicks on a 3 GB host
    # pushed the process into the OOM killer. Serialise builds, cache the result.
    if not _DASH_BUILD_LOCK.acquire(timeout=25):
        raise HTTPException(status_code=503,
                            detail="Today's Intelligence is already building. Try again in a moment.",
                            headers={"Retry-After": "10"})
    try:
        cached = _dash_cache_get(cache_key)
        if cached is not None:
            return cached
        result = _build_todays_intelligence(req)
        _dash_cache_put(cache_key, result)
        return result
    finally:
        _DASH_BUILD_LOCK.release()


def _dashboard_build_guarded(fn):
    """Run one dashboard build under the single-flight gate (no caching).

    The AI endpoints rebuild the snapshot unless the caller sends one, and each
    build allocates several hundred MB, so they share the same gate.
    """
    if not _DASH_BUILD_LOCK.acquire(timeout=25):
        raise HTTPException(status_code=503,
                            detail="Today's Intelligence is already building. Try again in a moment.",
                            headers={"Retry-After": "10"})
    try:
        return fn()
    finally:
        _DASH_BUILD_LOCK.release()


def _build_todays_intelligence(req: "TodaysIntelRequest"):
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
        snapshot = req.snapshot or _dashboard_build_guarded(
            lambda: todays_intel_mod.build_dashboard(
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
        ))
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
        snapshot = req.snapshot or _dashboard_build_guarded(
            lambda: todays_intel_mod.build_dashboard(
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
        ))
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
            "x_official_key": (req.x_official_key or "").strip(),
            "provider": (req.provider or "").strip(),
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
def ai_chat(req: AiChatRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    user_ai_key = ""
    user_id = current_user.get("id") if isinstance(current_user, dict) else ""
    if user_id:
        try:
            user_keys = auth_service.get_all_user_api_keys(user_id, mask=False)
            user_ai_key = user_keys.get("ai") or user_keys.get("deepseek") or user_keys.get("openai") or user_keys.get("gemini") or ""
        except Exception:
            pass
    try:
        return ai_mod.chat(req.dict(), user_api_key=user_ai_key)
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
def query_domain(req: IntelRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    req = _populate_user_keys(req, current_user["id"])
    import threat_assessment
    domain = normalize_domain(threat_assessment.refang_ioc(req.indicator))
    if not is_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format.")
    return _intel_or_500("domain", do_domain_intel, domain, req.vt_key, req.abusech_key, req.otx_key, tip_key=req.tip_key, cb_key=req.cb_key, rwlive_key=req.rwlive_key, triage_key=req.triage_key, ha_key=req.ha_key, silentpush_key=req.silentpush_key, driftnet_key=req.driftnet_key, urlscan_key=req.urlscan_key, shodan_key=req.shodan_key, censys_key=req.censys_key, etugen_key=req.etugen_key, pulsedive_key=req.pulsedive_key, fofa_key=req.fofa_key, validin_key=req.validin_key, netlas_key=req.netlas_key, zoomeye_key=req.zoomeye_key, twitter_key=req.twitter_key, github_key=req.github_key, dnsdumpster_key=req.dnsdumpster_key, leakix_key=req.leakix_key, phishstats_key=req.phishstats_key, misp_url=req.misp_url, misp_key=req.misp_key, misp_verify_ssl=req.misp_verify_ssl, sources=req.sources, threatcluster_key=req.threatcluster_key)

@app.post("/api/query/ip")
def query_ip(req: IntelRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    req = _populate_user_keys(req, current_user["id"])
    import threat_assessment
    ip = normalize_ip(threat_assessment.refang_ioc(req.indicator))
    if not is_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format. Must be IPv4 or IPv6.")
    return _intel_or_500("ip", do_ip_intel, ip, req.vt_key, req.abusech_key, req.otx_key, tip_key=req.tip_key, cb_key=req.cb_key, threatbook_key=req.threatbook_key, triage_key=req.triage_key, ha_key=req.ha_key, silentpush_key=req.silentpush_key, driftnet_key=req.driftnet_key, urlscan_key=req.urlscan_key, shodan_key=req.shodan_key, censys_key=req.censys_key, etugen_key=req.etugen_key, pulsedive_key=req.pulsedive_key, fofa_key=req.fofa_key, validin_key=req.validin_key, netlas_key=req.netlas_key, zoomeye_key=req.zoomeye_key, twitter_key=req.twitter_key, github_key=req.github_key, abuseipdb_key=req.abuseipdb_key, greynoise_key=req.greynoise_key, leakix_key=req.leakix_key, phishstats_key=req.phishstats_key, misp_url=req.misp_url, misp_key=req.misp_key, misp_verify_ssl=req.misp_verify_ssl, sources=req.sources, threatcluster_key=req.threatcluster_key)

@app.post("/api/query/url")
def query_url(req: IntelRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    req = _populate_user_keys(req, current_user["id"])
    import threat_assessment
    url = normalize_url(threat_assessment.refang_ioc(req.indicator))
    if not is_url(url):
        raise HTTPException(status_code=400, detail="Invalid URL format. Include http:// or https:// and preserve the full URL.")
    return _intel_or_500("url", do_url_intel, url, req.vt_key, req.abusech_key, req.otx_key, tip_key=req.tip_key, cb_key=req.cb_key, triage_key=req.triage_key, ha_key=req.ha_key, silentpush_key=req.silentpush_key, urlscan_key=req.urlscan_key, pulsedive_key=req.pulsedive_key, twitter_key=req.twitter_key, github_key=req.github_key, phishstats_key=req.phishstats_key, misp_url=req.misp_url, misp_key=req.misp_key, misp_verify_ssl=req.misp_verify_ssl, sources=req.sources)

@app.post("/api/query/infra")
def query_infra(req: IntelRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    req = _populate_user_keys(req, current_user["id"])
    import threat_assessment
    indicator = threat_assessment.refang_ioc(req.indicator).strip()
    if not indicator:
        raise HTTPException(status_code=400, detail="Infra search query cannot be empty.")
    return _intel_or_500("infra", do_infra_intel, indicator, silentpush_key=req.silentpush_key, driftnet_key=req.driftnet_key, shodan_key=req.shodan_key, censys_key=req.censys_key, etugen_key=req.etugen_key, pulsedive_key=req.pulsedive_key, fofa_key=req.fofa_key, validin_key=req.validin_key, ha_key=req.ha_key, abuseipdb_key=req.abuseipdb_key, urlscan_key=req.urlscan_key, dnsdumpster_key=req.dnsdumpster_key, greynoise_key=req.greynoise_key, netlas_key=req.netlas_key, vt_key=req.vt_key, sources=req.sources)


class ThreatAssessmentRequest(BaseModel):
    indicator: str
    type: str = "auto"
    results: Dict[str, Any] = Field(default_factory=dict)
    pivot_keys: Dict[str, str] = Field(default_factory=dict)
    pivot_id: str = ""
    auto_pivot: bool = True


_ASSESSMENT_PIVOTS: Dict[tuple, tuple] = {}
_ASSESSMENT_PIVOTS_LOCK = threading.Lock()


def _assessment_pivot_keys(user_id: str, supplied: Dict[str, str]) -> Dict[str, str]:
    saved = auth_service.get_all_user_api_keys(user_id, mask=False)
    aliases = {"virustotal": "vt_key", "otx": "otx_key", "urlscan": "urlscan_key",
               "abusech": "abusech_key"}
    allowed = {spec.get("key_field") for spec in infra_pivoting_mod.PROVIDER_CAPABILITY_REGISTRY.values()}
    keys = {}
    for provider, spec in infra_pivoting_mod.PROVIDER_CAPABILITY_REGISTRY.items():
        field = spec.get("key_field")
        if field and saved.get(provider):
            keys[field] = saved[provider]
    for provider, field in aliases.items():
        if saved.get(provider):
            keys[field] = saved[provider]
    keys.update({k: str(v).strip() for k, v in supplied.items() if k in allowed and isinstance(v, str) and v.strip()})
    return keys


@app.post("/api/query/threat-assessment")
def query_threat_assessment(req: ThreatAssessmentRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Assess evidence collected by IOC Search.
    Evaluates node role hypotheses, rarity-weighted APT attribution,
    executive 3-question triage, and context-aware defensive playbook.
    """
    import threat_assessment
    try:
        assessment = threat_assessment.enrich_ioc_query(req.indicator, req.type, req.results)
        seed = assessment["indicator"]
        seed_type = assessment["ioc_type"]
        cache_key = (current_user["id"], seed_type, seed.lower())
        inv_id = ""
        with _ASSESSMENT_PIVOTS_LOCK:
            previous = _ASSESSMENT_PIVOTS.get(cache_key)
            if previous and time.time() - previous[1] < 900:
                inv_id = previous[0]
            elif req.pivot_id and previous and previous[0] == req.pivot_id:
                inv_id = req.pivot_id
            if not inv_id and req.auto_pivot and any(s["status"] in {"contributed", "unassessed"} for s in assessment["source_evidence"]):
                keys = _assessment_pivot_keys(current_user["id"], req.pivot_keys)
                capabilities = infra_pivoting_mod.get_provider_capabilities_status(keys)
                selected = [p["id"] for p in capabilities["providers"]
                            if p.get("ready") and p.get("is_passive")
                            and seed_type in p.get("supported_seed_types", ())]
                if selected:
                    pivot = infra_pivoting_mod.start_investigation(
                        seed, mode="quick", keys=keys, async_execution=True,
                        custom_config={"seed_type": seed_type, "name": f"IOC Search assessment: {seed}",
                                       "providers": selected, "max_depth": 1, "max_assets": 100,
                                       "provider_asset_limit": 18, "per_pivot_limit": 15,
                                       "timeout_seconds": 90, "api_budget": 24,
                                       "passive_only": True},
                    )
                    inv_id = pivot["id"]
                    _ASSESSMENT_PIVOTS[cache_key] = (inv_id, time.time())
        if inv_id:
            pivot = infra_pivoting_mod.get_investigation(inv_id)
            if pivot and pivot.get("canonical_seed", "").lower() == seed.lower():
                assessment = threat_assessment.enrich_ioc_query(seed, seed_type, req.results, pivot)
        assessment["pivot"]["id"] = inv_id
        return assessment
    except Exception as exc:
        logger.exception("IOC Search threat assessment failed")
        raise HTTPException(status_code=500, detail=f"Threat assessment error: {str(exc)}")


class ThreatAssessmentSummaryRequest(BaseModel):
    indicator: str
    type: str = "auto"
    assessment: Optional[Dict[str, Any]] = None
    results: Dict[str, Any] = Field(default_factory=dict)
    pivot_id: str = ""


_ASSESSMENT_SUMMARY_JOBS: Dict[str, Dict[str, Any]] = {}
_ASSESSMENT_SUMMARY_JOBS_LOCK = threading.Lock()


@app.post("/api/query/threat-assessment/summary/jobs")
def start_threat_assessment_summary(req: ThreatAssessmentSummaryRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """Run long source-by-source synthesis outside the request; allow UI navigation."""
    import secrets
    job_id = secrets.token_urlsafe(24)
    owner = current_user["id"]
    with _ASSESSMENT_SUMMARY_JOBS_LOCK:
        for key, item in list(_ASSESSMENT_SUMMARY_JOBS.items()):
            if time.time() - item["created"] > 3600:
                del _ASSESSMENT_SUMMARY_JOBS[key]
        _ASSESSMENT_SUMMARY_JOBS[job_id] = {"owner": owner, "created": time.time(),
                                             "status": "running", "done": 0, "total": 1,
                                             "stage": "Preparing source evidence"}

    def update(done, total, stage):
        with _ASSESSMENT_SUMMARY_JOBS_LOCK:
            _ASSESSMENT_SUMMARY_JOBS[job_id].update(done=done, total=total, stage=stage)

    def worker():
        try:
            import threat_assessment
            pivot = infra_pivoting_mod.get_investigation(req.pivot_id) if req.pivot_id else None
            assessment = req.assessment
            if not assessment or not assessment.get("three_questions"):
                assessment = threat_assessment.enrich_ioc_query(req.indicator, req.type, req.results, pivot)
            user_keys = auth_service.get_all_user_api_keys(owner, mask=False)
            ai_key = user_keys.get("ai") or user_keys.get("deepseek") or user_keys.get("openai") or user_keys.get("gemini") or ""
            result = ai_mod.generate_threat_assessment_summary(
                req.indicator, req.type, assessment, req.results, pivot, ai_key, progress_callback=update)
            with _ASSESSMENT_SUMMARY_JOBS_LOCK:
                _ASSESSMENT_SUMMARY_JOBS[job_id].update(status=result.get("status", "error"), result=result)
        except Exception as exc:
            logger.exception("Threat assessment synthesis job failed")
            with _ASSESSMENT_SUMMARY_JOBS_LOCK:
                _ASSESSMENT_SUMMARY_JOBS[job_id].update(status="error", result={"error": str(exc)})

    threading.Thread(target=worker, name="assessment-summary", daemon=True).start()
    return {"job_id": job_id, "status": "running"}


@app.get("/api/query/threat-assessment/summary/jobs/{job_id}")
def get_threat_assessment_summary_job(job_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    with _ASSESSMENT_SUMMARY_JOBS_LOCK:
        job = _ASSESSMENT_SUMMARY_JOBS.get(job_id)
        if not job or job["owner"] != current_user["id"]:
            raise HTTPException(status_code=404, detail="Summary job not found")
        return {key: value for key, value in job.items() if key not in {"owner", "created"}}


@app.post("/api/query/threat-assessment/summary")
def query_threat_assessment_summary(req: ThreatAssessmentSummaryRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Synthesize an executive summary of findings across all intelligence sources and infrastructure pivots
    using MANTIS AI. Only executes when AI is configured, returning a safe status otherwise.
    """
    import threat_assessment
    try:
        pivot = None
        if req.pivot_id:
            pivot = infra_pivoting_mod.get_investigation(req.pivot_id)
        assessment = req.assessment
        if not assessment or not assessment.get("three_questions"):
            assessment = threat_assessment.enrich_ioc_query(req.indicator, req.type, req.results, pivot)
        user_ai_key = ""
        user_id = current_user.get("id") if isinstance(current_user, dict) else ""
        if user_id:
            try:
                user_keys = auth_service.get_all_user_api_keys(user_id, mask=False)
                user_ai_key = user_keys.get("ai") or user_keys.get("deepseek") or user_keys.get("openai") or user_keys.get("gemini") or ""
            except Exception:
                pass
        return ai_mod.generate_threat_assessment_summary(
            indicator=req.indicator,
            ioc_type=req.type,
            assessment=assessment,
            results=req.results,
            pivot=pivot,
            user_api_key=user_ai_key,
        )
    except Exception as exc:
        logger.exception("Threat assessment AI summarization endpoint error")
        return {
            "available": False,
            "status": "error",
            "summary": None,
            "error": str(exc),
        }


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


class ExposureRefreshRequest(BaseModel):
    tool_id: str
    shodan_pages: int = Field(default=100, ge=1, le=100)
    shodan_key: str = ""
    fofa_key: str = ""
    censys_key: str = ""
    zoomeye_key: str = ""
    validin_key: str = ""


class ExposureQueryRequest(BaseModel):
    provider: str
    query: str


class CatalogQueryRequest(BaseModel):
    family: str
    engine: str
    query: str
    category: str = ""
    technique: str = ""
    notes: str = ""


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


@app.post("/api/infra-hunts/playbooks")
def create_hunting_query(req: CatalogQueryRequest):
    import c2_hunting_catalog
    try:
        return c2_hunting_catalog.save_query(req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.put("/api/infra-hunts/playbooks/{query_id}")
def update_hunting_query(query_id: str, req: CatalogQueryRequest):
    import c2_hunting_catalog
    try:
        return c2_hunting_catalog.save_query(req.model_dump(), query_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.delete("/api/infra-hunts/playbooks/{query_id}")
def delete_hunting_query(query_id: str):
    import c2_hunting_catalog
    try:
        return c2_hunting_catalog.delete_query(query_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.get("/api/exposure-monitor")
def exposure_monitor_catalog():
    import exposure_monitor
    return exposure_monitor.catalog()


@app.post("/api/exposure-monitor/{tool_id}/queries")
def create_exposure_query(tool_id: str, req: ExposureQueryRequest):
    import exposure_monitor
    try:
        return exposure_monitor.save_query(tool_id, req.provider, req.query)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.put("/api/exposure-monitor/{tool_id}/queries/{query_id}")
def update_exposure_query(tool_id: str, query_id: str, req: ExposureQueryRequest):
    import exposure_monitor
    try:
        return exposure_monitor.save_query(tool_id, req.provider, req.query, query_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.delete("/api/exposure-monitor/{tool_id}/queries/{query_id}")
def delete_exposure_query(tool_id: str, query_id: str):
    import exposure_monitor
    try:
        return exposure_monitor.delete_query(tool_id, query_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/api/exposure-monitor/refresh")
def exposure_monitor_refresh(req: ExposureRefreshRequest):
    import exposure_monitor
    try:
        return exposure_monitor.refresh(req.tool_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/exposure-monitor/{tool_id}")
def exposure_monitor_detail(tool_id: str):
    import exposure_monitor
    try:
        return exposure_monitor.detail(tool_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


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


# =====================================================================
# AUTOMATED INFRASTRUCTURE PIVOTING ENDPOINTS
# =====================================================================

class InfraPivotingKeysPayload(BaseModel):
    vt_key: str = ""
    shodan_key: str = ""
    censys_key: str = ""
    fofa_key: str = ""
    urlscan_key: str = ""
    silentpush_key: str = ""
    validin_key: str = ""
    netlas_key: str = ""
    greynoise_key: str = ""
    abusech_key: str = ""
    otx_key: str = ""


class InfraPivotingRunRequest(InfraPivotingKeysPayload):
    seed: str
    seed_type: str = ""
    name: str = ""
    mode: str = "quick"
    max_depth: Optional[int] = None
    max_assets: Optional[int] = None
    per_pivot_limit: Optional[int] = None
    timeout_seconds: Optional[int] = None
    api_budget: Optional[int] = None
    min_confidence_to_expand: Optional[int] = None
    passive_only: bool = True
    enabled_methods: List[str] = Field(default_factory=list)
    providers: List[str] = Field(default_factory=list)
    async_execution: bool = True


class InfraPivotingNormalizeRequest(BaseModel):
    seed: str
    seed_type: str = ""


class InfraPivotingExtractTextRequest(BaseModel):
    text: str


class InfraPivotingAttributeRequest(BaseModel):
    items: List[Dict[str, Any]] = Field(default_factory=list)
    top_n: int = 5


def _extract_pivoting_keys(req: InfraPivotingKeysPayload) -> dict:
    return {
        "vt_key": (req.vt_key or "").strip(),
        "shodan_key": (req.shodan_key or "").strip(),
        "censys_key": (req.censys_key or "").strip(),
        "fofa_key": (req.fofa_key or "").strip(),
        "urlscan_key": (req.urlscan_key or "").strip(),
        "silentpush_key": (req.silentpush_key or "").strip(),
        "validin_key": (req.validin_key or "").strip(),
        "netlas_key": (req.netlas_key or "").strip(),
        "greynoise_key": (req.greynoise_key or "").strip(),
        "abusech_key": (req.abusech_key or "").strip(),
        "otx_key": (req.otx_key or "").strip(),
    }


@app.get("/api/infra-pivoting/capabilities")
def infra_pivoting_capabilities_get():
    return infra_pivoting_mod.get_provider_capabilities_status()


@app.post("/api/infra-pivoting/capabilities")
def infra_pivoting_capabilities_post(req: InfraPivotingKeysPayload):
    return infra_pivoting_mod.get_provider_capabilities_status(_extract_pivoting_keys(req))


@app.post("/api/infra-pivoting/normalize")
def infra_pivoting_normalize(req: InfraPivotingNormalizeRequest):
    try:
        return {"normalized": infra_pivoting_mod.normalize_seed_indicator(req.seed, req.seed_type)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/infra-pivoting/extract-text")
def infra_pivoting_extract_text(req: InfraPivotingExtractTextRequest):
    import threat_assessment
    return threat_assessment.extract_iocs_from_text(req.text)


@app.post("/api/infra-pivoting/attribute")
def infra_pivoting_attribute(req: InfraPivotingAttributeRequest):
    import threat_assessment
    return threat_assessment.get_attributor().evaluate(req.items, top_n=req.top_n)


@app.post("/api/infra-pivoting/run")
def infra_pivoting_run(req: InfraPivotingRunRequest):
    try:
        custom_cfg = {
            "seed_type": req.seed_type,
            "name": req.name,
            "max_depth": req.max_depth,
            "max_assets": req.max_assets,
            "per_pivot_limit": req.per_pivot_limit,
            "timeout_seconds": req.timeout_seconds,
            "api_budget": req.api_budget,
            "min_confidence_to_expand": req.min_confidence_to_expand,
            "passive_only": req.passive_only,
            "enabled_methods": req.enabled_methods,
            "providers": req.providers,
        }
        return infra_pivoting_mod.start_investigation(
            seed=req.seed,
            mode=req.mode,
            custom_config=custom_cfg,
            keys=_extract_pivoting_keys(req),
            async_execution=req.async_execution,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to start infrastructure pivoting investigation")
        raise HTTPException(status_code=500, detail=f"Failed to start investigation: {str(exc)[:240]}")


@app.get("/api/infra-pivoting/investigations")
def infra_pivoting_list(limit: int = 50):
    return {"investigations": infra_pivoting_mod.list_investigations(limit=limit)}


@app.get("/api/infra-pivoting/investigations/{inv_id}")
def infra_pivoting_get(inv_id: str):
    inv = infra_pivoting_mod.get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


@app.post("/api/infra-pivoting/investigations/{inv_id}/cancel")
def infra_pivoting_cancel(inv_id: str):
    try:
        return infra_pivoting_mod.cancel_investigation(inv_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/api/infra-pivoting/investigations/{inv_id}/resume")
def infra_pivoting_resume(inv_id: str, req: Optional[InfraPivotingKeysPayload] = None, async_execution: bool = True):
    try:
        keys = _extract_pivoting_keys(req) if req else {}
        return infra_pivoting_mod.resume_investigation(inv_id, keys=keys, async_execution=async_execution)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.exception("Failed to resume infrastructure pivoting investigation")
        raise HTTPException(status_code=500, detail=f"Failed to resume investigation: {str(exc)[:240]}")


@app.delete("/api/infra-pivoting/investigations/{inv_id}")
def infra_pivoting_delete(inv_id: str):
    return infra_pivoting_mod.delete_investigation(inv_id)


@app.get("/api/infra-pivoting/raw/{raw_ref_id}")
def infra_pivoting_raw_get(raw_ref_id: str):
    raw = infra_pivoting_mod.get_raw_response(raw_ref_id)
    if not raw:
        raise HTTPException(status_code=404, detail="Raw response reference not found")
    return raw


@app.get("/api/infra-pivoting/investigations/{inv_id}/export")
def infra_pivoting_export(inv_id: str, format: str = "json"):
    try:
        content, media_type, filename = infra_pivoting_mod.export_investigation(inv_id, fmt=format)
        return Response(
            content=content,
            media_type=media_type,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/api/query/hash")
def query_hash(req: IntelRequest, current_user: Dict[str, Any] = Depends(get_current_user)):
    req = _populate_user_keys(req, current_user["id"])
    import threat_assessment
    file_hash = threat_assessment.refang_ioc(req.indicator).strip()
    if not is_hash(file_hash):
        raise HTTPException(status_code=400, detail="Invalid hash format. Must be MD5, SHA-1, SHA-256, SHA-512, or SHA3-384 hex.")
    return _intel_or_500("hash", do_hash_intel, file_hash, req.vt_key, req.abusech_key, req.otx_key, triage_key=req.triage_key, tip_key=req.tip_key, cb_key=req.cb_key, ha_key=req.ha_key, malshare_key=req.malshare_key, silentpush_key=req.silentpush_key, driftnet_key=req.driftnet_key, pulsedive_key=req.pulsedive_key, fofa_key=req.fofa_key, validin_key=req.validin_key, urlscan_key=req.urlscan_key, twitter_key=req.twitter_key, github_key=req.github_key, misp_url=req.misp_url, misp_key=req.misp_key, misp_verify_ssl=req.misp_verify_ssl, sources=req.sources, github_repos=req.github_repos, threatcluster_key=req.threatcluster_key)





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

class MalShareDownloadRequest(BaseModel):
    file_hash: str = ""
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

@app.post("/api/malshare/download")
def malshare_download(req: MalShareDownloadRequest):
    file_hash = _require_sample_hash(req.file_hash.strip())
    api_key = req.malshare_key.strip()
    if not api_key:
        raise HTTPException(status_code=400, detail="Configure a MalShare API key in Settings → API Keys.")
    try:
        response = requests.get("https://malshare.com/api.php", params={
            "api_key": api_key, "action": "getfile", "hash": file_hash,
        }, stream=True, timeout=(10, 120))
    except requests.Timeout as exc:
        raise HTTPException(status_code=504, detail="MalShare sample download timed out.") from exc
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail="MalShare sample download failed.") from exc
    if response.status_code != 200:
        status = response.status_code
        response.close()
        raise HTTPException(status_code=status if status in {401, 403, 404, 429} else 502,
                            detail=f"MalShare sample download returned HTTP {status}.")
    content_type = response.headers.get("Content-Type", "").lower()
    if "text/" in content_type or "application/json" in content_type:
        detail = response.raw.read(512).decode("utf-8", errors="replace").strip()
        response.close()
        raise HTTPException(status_code=502, detail=f"MalShare did not return a sample: {detail[:200]}")

    def chunks():
        try:
            yield from (chunk for chunk in response.iter_content(1024 * 1024) if chunk)
        finally:
            response.close()

    return StreamingResponse(chunks(), media_type="application/octet-stream", headers={
        "Content-Disposition": f'attachment; filename="{file_hash}.bin"',
        "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
    })

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

class IntelReportRequest(BaseModel):
    days: int = 30

def _report_days(days: int) -> int:
    return max(1, min(int(days or 30), 366))

@app.get("/api/intel-reports/status")
def intel_reports_status(recheck: bool = False):
    if recheck:
        intel_reports_mod.clear_error()
    return {**intel_reports_mod.ai_status(), "untagged": intel_reports_mod.untagged_count(30)}

@app.post("/api/intel-reports/tag")
def intel_reports_tag(req: IntelReportRequest):
    return intel_reports_mod.tag_pending(_report_days(req.days), limit=24)

@app.post("/api/intel-reports/countries")
def intel_reports_countries(req: IntelReportRequest):
    return intel_reports_mod.list_countries(_report_days(req.days))

@app.post("/api/intel-reports/industries")
def intel_reports_industries(req: IntelReportRequest):
    return intel_reports_mod.list_industries(_report_days(req.days))

@app.post("/api/intel-reports/country/{code}")
def intel_reports_country(code: str, req: IntelReportRequest):
    code = (code or "").strip()
    if not re.match(r"^[A-Za-z]{2}$", code):
        raise HTTPException(status_code=400, detail="Country report requires an ISO-2 country code.")
    try:
        return intel_reports_mod.country_detail(code, _report_days(req.days))
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/intel-reports/industry")
def intel_reports_industry(req: IntelReportRequest, name: str = ""):
    name = (name or "").strip()
    if not name or len(name) > 200 or "\n" in name or "\r" in name:
        raise HTTPException(status_code=400, detail="Invalid industry name.")
    try:
        return intel_reports_mod.industry_detail(name, _report_days(req.days))
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/api/intel-reports/brief")
def intel_reports_brief(req: IntelReportRequest, kind: str = "", value: str = ""):
    if kind not in ("country", "industry") or not value or len(value) > 200:
        raise HTTPException(status_code=400, detail="Invalid brief request.")
    try:
        return intel_reports_mod.ai_brief(kind, value, _report_days(req.days))
    except ai_mod.AIUnavailable as e:
        raise HTTPException(status_code=400, detail=str(e))
    except TimeoutError as e:
        raise HTTPException(status_code=504, detail=str(e))
    except ai_mod.AIProviderError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

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

class CustomRansomNotePayload(BaseModel):
    id: str = ""
    group_name: str = ""
    group: str = ""
    family: str = ""
    filename: str = ""
    extension: str = ".txt"
    note_content: str = ""
    note: str = ""
    snippet: str = ""
    contact_email: str = ""
    contact_onion: str = ""
    contact_matrix: str = ""
    ransom_amount: str = ""
    crypto_wallet: str = ""
    analyst_notes: str = ""
    tags: Any = []
    discovered_at: str = ""

@app.get("/api/ransomware-monitor/custom-notes")
def get_custom_ransom_notes(
    q: str = Query("", description="Search query"),
    group: str = Query("", description="Group filter"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100)
):
    if not ransom_notes_db_mod:
        raise HTTPException(status_code=503, detail="Custom notes DB module not available")
    return ransom_notes_db_mod.list_custom_notes(q=q, group=group, page=page, page_size=page_size)

@app.post("/api/ransomware-monitor/custom-notes")
def create_custom_ransom_note(req: CustomRansomNotePayload):
    if not ransom_notes_db_mod:
        raise HTTPException(status_code=503, detail="Custom notes DB module not available")
    try:
        data = req.dict() if hasattr(req, "dict") else dict(req)
        note = ransom_notes_db_mod.create_custom_note(data, author="local_analyst")
        return {"status": "success", "note": note}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create note: {e}")

@app.get("/api/ransomware-monitor/custom-notes/{note_id}")
def get_custom_ransom_note(note_id: str):
    if not ransom_notes_db_mod:
        raise HTTPException(status_code=503, detail="Custom notes DB module not available")
    note = ransom_notes_db_mod.get_custom_note(note_id)
    if not note:
        raise HTTPException(status_code=404, detail="Custom ransom note not found")
    return note

@app.put("/api/ransomware-monitor/custom-notes/{note_id}")
def update_custom_ransom_note(note_id: str, req: CustomRansomNotePayload):
    if not ransom_notes_db_mod:
        raise HTTPException(status_code=503, detail="Custom notes DB module not available")
    try:
        data = req.dict() if hasattr(req, "dict") else dict(req)
        updated = ransom_notes_db_mod.update_custom_note(note_id, data)
        if not updated:
            raise HTTPException(status_code=404, detail="Custom ransom note not found")
        return {"status": "success", "note": updated}
    except HTTPException:
        raise  # 404 "not found" was being rewritten into a 500
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update note: {e}")

@app.delete("/api/ransomware-monitor/custom-notes/{note_id}")
def delete_custom_ransom_note(note_id: str):
    if not ransom_notes_db_mod:
        raise HTTPException(status_code=503, detail="Custom notes DB module not available")
    success = ransom_notes_db_mod.delete_custom_note(note_id)
    if not success:
        raise HTTPException(status_code=404, detail="Custom ransom note not found")
    return {"status": "success", "deleted_id": note_id}

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

    selected_sources: Optional[List[str]] = None

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
    return do_keyword_intel(kw, query_type, req.abusech_key, req.otx_key, req.triage_key, tip_key=req.tip_key, malshare_key=req.malshare_key, rwlive_key=req.rwlive_key, cb_key=req.cb_key, ha_key=req.ha_key, urlscan_key=req.urlscan_key, silentpush_key=req.silentpush_key, driftnet_key=req.driftnet_key, shodan_key=req.shodan_key, censys_key=req.censys_key, etugen_key=req.etugen_key, pulsedive_key=req.pulsedive_key, fofa_key=req.fofa_key, validin_key=req.validin_key, twitter_key=req.twitter_key, github_key=req.github_key, dnsdumpster_key=req.dnsdumpster_key, sources=req.sources, github_repos=req.github_repos, selected_sources=req.selected_sources)

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
    result = search_scope(scope, q or "", limit=limit, offset=offset)
    if result.get("status") == 502:
        raise HTTPException(status_code=502, detail=result["error"])
    return result


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


class YaraRuleSaveRequest(BaseModel):
    repo: str = ""
    rule: str = ""
    file: str = ""
    source: str = ""
    is_new: bool = False
    overwrite: bool = True


class YaraRuleDeleteRequest(BaseModel):
    repo: str = ""
    rule: str = ""
    file: str = ""


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


@app.post("/api/yara/rule/save")
def yara_rule_save_route(req: YaraRuleSaveRequest):
    out = yara_save_rule_in_repo(
        repo_id=(req.repo or "").strip(),
        file_rel=(req.file or "").strip(),
        source=req.source or "",
        rule_name=(req.rule or "").strip(),
        is_new=bool(req.is_new),
        overwrite=bool(req.overwrite),
    )
    if "error" in out:
        raise HTTPException(status_code=out.pop("status", 400), detail=out["error"])
    return out


@app.delete("/api/yara/rule")
@app.post("/api/yara/rule/delete")
def yara_rule_delete_route(req: YaraRuleDeleteRequest):
    repo = (req.repo or "").strip()
    rule = (req.rule or "").strip()
    if not repo or not rule:
        raise HTTPException(status_code=400, detail="repo and rule name are required for deletion")
    out = yara_delete_rule(repo_id=repo, rule_name=rule, file_rel=(req.file or "").strip())
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


# -------------------------------------------------------------
# SIGMA RULES SUITE API ENDPOINTS
# -------------------------------------------------------------
class SigmaRuleSaveRequest(BaseModel):
    repo: str
    filename: str
    content: str

class SigmaRuleCreateRequest(BaseModel):
    content: str
    repo: str = "custom"
    filename: Optional[str] = None

class SigmaRuleDeleteRequest(BaseModel):
    repo: str
    filename: str

class SigmaValidateRequest(BaseModel):
    content: str

class SigmaConvertRequest(BaseModel):
    content: str
    target: str = "all"
    pipeline: Optional[str] = None
    mode: str = "standard"  # standard, ai, ai_repair
    provider: Optional[str] = None
    model: Optional[str] = None

class SigmaSyncRepoRequest(BaseModel):
    repo: str

@app.get("/api/sigma/repos")
def get_sigma_repos():
    return sigma_repos.get_repositories()

@app.get("/api/sigma/stats")
def get_sigma_stats():
    return sigma_repos.get_stats()

@app.get("/api/sigma/rules")
def search_sigma_rules(
    q: str = "",
    repos: str = "",
    level: str = "",
    status: str = "",
    product: str = "",
    category: str = "",
    author: str = "",
    mitre: str = "",
    tag: str = "",
    cve: str = "",
    page: int = 1,
    page_size: int = 24
):
    repo_list = [r.strip() for r in repos.split(",") if r.strip()] if repos else None
    return sigma_repos.search_rules(
        query=q,
        repos=repo_list,
        level=level or None,
        status=status or None,
        logsource_product=product or None,
        logsource_category=category or None,
        author=author or None,
        mitre_id=mitre or None,
        tag=tag or None,
        cve=cve or None,
        page=page,
        page_size=page_size
    )

@app.get("/api/sigma/rule")
def get_sigma_rule(repo: str, path: str):
    rule_data = sigma_repos.get_rule(repo_id=repo, filename_or_id=path)
    if not rule_data:
        raise HTTPException(status_code=404, detail=f"Rule '{path}' not found in repository '{repo}'")
    return rule_data

@app.post("/api/sigma/rule/save")
def save_sigma_rule(req: SigmaRuleSaveRequest):
    res = sigma_repos.save_rule(repo_id=req.repo, filename=req.filename, yaml_content=req.content)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("message", "Validation/save failed"))
    return res

@app.post("/api/sigma/rule/create")
def create_sigma_rule(req: SigmaRuleCreateRequest):
    res = sigma_repos.create_rule(yaml_content=req.content, repo_id=req.repo or "custom", filename=req.filename)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("message", "Creation failed"))
    return res

@app.delete("/api/sigma/rule")
def delete_sigma_rule_delete(repo: str, filename: str):
    return sigma_repos.delete_rule(repo_id=repo, filename=filename)

@app.post("/api/sigma/rule/delete")
def delete_sigma_rule_post(req: SigmaRuleDeleteRequest):
    return sigma_repos.delete_rule(repo_id=req.repo, filename=req.filename)

@app.get("/api/sigma/emerging")
def get_sigma_emerging(category: str = "all", q: str = ""):
    return sigma_repos.get_emerging_threats(category=category, search=q)

@app.get("/api/sigma/mitre")
def get_sigma_mitre():
    return sigma_repos.get_mitre_matrix()

@app.post("/api/sigma/validate")
def validate_sigma_content(req: SigmaValidateRequest):
    return sigma_engine.validate_sigma_rule(req.content)

@app.post("/api/sigma/convert")
def convert_sigma_query(req: SigmaConvertRequest):
    if req.target == "all" and req.mode == "standard":
        return sigma_converter.convert_all_targets(req.content, pipeline=req.pipeline)
    else:
        return sigma_converter.convert_sigma_rule(
            req.content,
            target=req.target if req.target != "all" else "splunk",
            pipeline=req.pipeline,
            mode=req.mode,
            provider=req.provider,
            model=req.model
        )

@app.post("/api/sigma/repos/sync")
def sync_sigma_repository(req: SigmaSyncRepoRequest):
    res = sigma_updater.sync_repository(req.repo)
    sigma_repos.index_rules(force=True)
    return res

@app.post("/api/sigma/repos/sync-all")
def sync_all_sigma_repositories():
    res = sigma_updater.download_all_repositories(force=True)
    sigma_repos.index_rules(force=True)
    return {"success": True, "results": res}


class SigmaCloneRequest(BaseModel):
    repo: str
    filename: str
    new_title: Optional[str] = None


@app.get("/api/sigma/custom/rules")
def get_custom_sigma_rules():
    """Return all user-authored custom Sigma rules."""
    return sigma_repos.get_custom_rules()


@app.get("/api/sigma/templates")
def get_sigma_templates():
    """Return all curated starter templates for Sigma rules."""
    return sigma_repos.get_rule_templates()


@app.get("/api/sigma/rule/uuid")
def get_sigma_new_uuid():
    """Generate a standard lowercase UUIDv4 for new Sigma rule authoring."""
    return {"uuid": sigma_repos.generate_uuid()}


@app.post("/api/sigma/rule/clone")
def clone_sigma_rule(req: SigmaCloneRequest):
    """Clone an existing Sigma rule into a user-customizable custom rule."""
    return sigma_repos.clone_rule(repo_id=req.repo, filename_or_id=req.filename, new_title=req.new_title)


@app.get("/api/sigma/custom/export")
def export_custom_sigma_rules():
    """Export all user-authored custom rules as a combined YAML package."""
    custom_rules = sigma_repos.get_custom_rules()
    parts = []
    for r in custom_rules:
        detail = sigma_repos.get_rule("custom", r["filename"])
        if detail and detail.get("raw_yaml"):
            parts.append(detail["raw_yaml"].strip())

    combined = "\n---\n".join(parts) if parts else "# No custom Sigma rules authored yet.\n"
    from fastapi.responses import Response
    return Response(
        content=combined,
        media_type="text/yaml",
        headers={"Content-Disposition": "attachment; filename=mantis_custom_sigma_rules.yml"}
    )


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


class ScanMalwareArchiveRequest(BaseModel):
    kind: str
    value: str = Field(max_length=4096)


def _require_scanmalware_key(key: str | None) -> str:
    configured = (key or "").strip()
    if not configured:
        raise HTTPException(status_code=400, detail="Add a ScanMalware API key in Settings → API Keys.")
    return configured


@app.post("/api/scanmalware/archive/search")
def search_scanmalware_archive(req: ScanMalwareArchiveRequest, x_scanmalware_key: str | None = Header(default=None)):
    from scanmalware_archive import ArchiveError, search_archive

    try:
        return search_archive(req.kind, req.value, _require_scanmalware_key(x_scanmalware_key))
    except ArchiveError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc


@app.get("/api/scanmalware/archive/scans/{scan_id}")
def get_scanmalware_archive_scan(scan_id: UUID, x_scanmalware_key: str | None = Header(default=None)):
    from scanmalware_archive import ArchiveError, scan_summary

    try:
        return scan_summary(scan_id, _require_scanmalware_key(x_scanmalware_key))
    except ArchiveError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc


def _tip_feature_call(fn, *args):
    from ktip_features import TipError
    try:
        return fn(*args)
    except TipError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc


class TipLookupRequest(BaseModel):
    kind: str
    value: str
    action: str = "quick"


@app.post("/api/ktip/lookup")
def ktip_lookup(req: TipLookupRequest, tip_key: str = Header("", alias="x-tip-key")):
    import ktip_features as tip
    from intel_query import query_tip
    value = req.value.strip()
    if req.kind not in {"hash", "ip", "domain", "url"} or not value or len(value) > 4096:
        raise HTTPException(status_code=400, detail="Enter a hash, IP, domain, or URL.")
    if req.kind == "hash" and not re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", value):
        raise HTTPException(status_code=400, detail="Enter an MD5, SHA-1, or SHA-256 hash.")
    if req.kind == "ip":
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Enter a valid IP address.") from exc
    if req.kind == "domain" and not re.fullmatch(r"[\w.-]+", value):
        raise HTTPException(status_code=400, detail="Enter a valid domain.")
    if req.kind == "url" and not value.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Enter an HTTP or HTTPS URL.")
    if req.action == "quick":
        return _tip_feature_call(tip.quick_lookup, req.kind, value, tip_key)
    if req.action == "detail":
        return _ktip_or_raise(query_tip(req.kind, value, tip_key.strip()))
    if req.action == "similar" and req.kind == "hash":
        return _tip_feature_call(tip.similar_hash, value, tip_key)
    if req.action == "infrastructure" and req.kind == "ip":
        return _tip_feature_call(tip.infrastructure, value, tip_key)
    raise HTTPException(status_code=400, detail="Unsupported Kaspersky lookup action.")


@app.get("/api/ktip/reports/search")
def ktip_reports_search(q: str, skip: int = 0, tip_key: str = Header("", alias="x-tip-key")):
    from ktip_features import report_search
    if not q.strip() or len(q) > 500 or not 0 <= skip <= 10000:
        raise HTTPException(status_code=400, detail="Enter a report search term.")
    return _tip_feature_call(report_search, q.strip(), tip_key, skip)


@app.get("/api/ktip/sandbox/{task_id}/{kind}/{md5}")
def ktip_sample_archive(task_id: UUID, kind: str, md5: str, tip_key: str = Header("", alias="x-tip-key")):
    from ktip_features import download_sample
    data = _tip_feature_call(download_sample, str(task_id), kind, md5, tip_key)
    return StreamingResponse(iter([data]), media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="{md5}.zip"', "Cache-Control": "no-store",
    })


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


@app.post("/api/cti/article/{article_id}/ai-iocs")
def cti_article_ai_iocs(article_id: int):
    try:
        return ai_mod.extract_cti_article_iocs(int(article_id))
    except (TypeError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e) or "Invalid article id")
    except ai_mod.AIUnavailable as e:
        raise HTTPException(status_code=400, detail=str(e))
    except TimeoutError as e:
        raise HTTPException(status_code=504, detail=str(e))
    except ai_mod.AIProviderError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except Exception:
        logger.exception("CTI article AI IOC extraction failed")
        raise HTTPException(status_code=500, detail="CTI AI IOC extraction failed. Check backend logs for diagnostics.")


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
    if not tg_mod._get_bot((bot_id or "").strip()):
        raise HTTPException(status_code=404, detail="Bot not found")
    return tg_mod.stop_bot((bot_id or "").strip(), paused=False)


@app.post("/api/tg/bots/{bot_id}/pause")
def tg_bot_pause(bot_id: str):
    bot = tg_mod._get_bot((bot_id or "").strip())
    if not bot:
        # Used to answer 200 {"stopped": true, "bot": null} for an unknown id.
        raise HTTPException(status_code=404, detail="Bot not found")
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
    if deployment_config.is_server_mode():
        return {"cancelled": True, "path": "", "reason": "Native file picker is disabled in Server Mode. Use server staging or web upload."}
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
@app.get("/index.html", include_in_schema=False)
def _index():
    from fastapi.responses import HTMLResponse
    try:
        with open(os.path.join(frontend_path, "index.html"), "r", encoding="utf-8") as f:
            html = f.read()
    except OSError:
        return HTMLResponse("<h1>MANTIS frontend not found</h1>", status_code=500)

    v = _asset_version() or int(time.time())
    mode = "server" if deployment_config.is_server_mode() else "workstation"
    html = re.sub(r'<body([^>]*)>', f'<body\\1 data-mode="{mode}" class="mantis-{mode}-mode">', html)
    html = re.sub(r'src="app\.js(\?v=[^"]*)?"', f'src="app.js?v={v}"', html)
    html = re.sub(r'src="auth\.js(\?v=[^"]*)?"', f'src="auth.js?v={v}"', html)
    html = re.sub(r'src="top-nav\.js(\?v=[^"]*)?"', f'src="top-nav.js?v={v}"', html)
    html = re.sub(r'src="similarity\.js(\?v=[^"]*)?"', f'src="similarity.js?v={v}"', html)
    html = re.sub(r'href="styles\.css(\?v=[^"]*)?"', f'href="styles.css?v={v}"', html)
    html = re.sub(r'href="auth\.css(\?v=[^"]*)?"', f'href="auth.css?v={v}"', html)
    return HTMLResponse(html, headers={
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    })

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
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.exception("MANTIS AI case assess failed")
        raise HTTPException(status_code=500, detail="MANTIS AI case assess failed. Check backend logs for diagnostics.")

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
    if deployment_config.is_server_mode():
        return {"cancelled": True, "path": "", "reason": "Native file picker is disabled in Server Mode."}
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
    if deployment_config.is_server_mode():
        return {"cancelled": True, "path": "", "reason": "Native file picker is disabled in Server Mode."}
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
    if deployment_config.is_server_mode():
        return {"cancelled": True, "path": "", "reason": "Native file picker is disabled in Server Mode."}
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
    if deployment_config.is_server_mode():
        return {"cancelled": True, "path": "", "reason": "Native file picker is disabled in Server Mode."}
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
    if deployment_config.is_server_mode():
        return {"cancelled": True, "path": "", "reason": "Native folder picker is disabled in Server Mode. Use server staging or web upload."}
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


@app.get("/api/binary-lab/select-executable")
def binary_lab_select_executable(initial: str = ""):
    if deployment_config.is_server_mode():
        return {"cancelled": True, "path": "", "reason": "Native file picker is disabled in Server Mode."}
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
$dialog.Title = 'Select CLI or Application Executable (.exe, .cmd, .bat)'
$dialog.Filter = 'Executable files (*.exe;*.cmd;*.bat)|*.exe;*.cmd;*.bat|All files (*.*)|*.*'
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
    try:
        cancelled = binary_lab_mod.cancel_job(job_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    if not cancelled:
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


# ---------------------------------------------------------------------------
# Malware Repository & Threat DB (MWDB Lite) Endpoints
# ---------------------------------------------------------------------------

class UpdateSampleRequest(BaseModel):
    threat_actor: Optional[str] = None
    malware_family: Optional[str] = None
    description: Optional[str] = None
    tlp: Optional[str] = None
    tags: Optional[List[str]] = None


@app.get("/api/malware-db/samples")
def mwdb_list_samples(
    q: Optional[str] = None,
    tag: Optional[str] = None,
    actor: Optional[str] = None,
    family: Optional[str] = None,
    tlp: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
):
    """Search and paginate samples with FTS5 and filtering."""
    return mwdb_mod.list_samples(
        query=q,
        tag=tag,
        actor=actor,
        family=family,
        tlp=tlp,
        limit=limit,
        offset=offset,
    )


@app.post("/api/malware-db/upload")
async def mwdb_upload_samples(
    files: List[UploadFile] = File(...),
    threat_actor: Optional[str] = Form(None),
    malware_family: Optional[str] = Form(None),
    tags: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    tlp: str = Form("amber"),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Upload one or more malware binaries into the Malware DB repository."""
    if not files:
        raise HTTPException(status_code=400, detail="No files provided for upload.")

    tag_list = []
    if tags:
        tag_list = [t.strip() for t in re.split(r"[,;\s]+", tags) if t.strip()]

    username = current_user.get("username", "local_analyst") if current_user else "local_analyst"
    results = []

    for f in files:
        if not f.filename:
            continue
        try:
            content = await f.read()
            if not content:
                continue
            saved = mwdb_mod.add_sample(
                file_bytes=content,
                filename=f.filename,
                threat_actor=threat_actor,
                malware_family=malware_family,
                tags=tag_list,
                description=description,
                tlp=tlp,
                uploaded_by=username,
            )
            results.append(saved)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error saving {f.filename}: {e}")

    return {
        "success": True,
        "count": len(results),
        "samples": results,
    }


@app.get("/api/malware-db/sample/{sha256}")
def mwdb_get_sample(sha256: str):
    """Fetch complete metadata, tags, and metrics for a sample."""
    sample = mwdb_mod.get_sample(sha256)
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found.")
    return sample


@app.patch("/api/malware-db/sample/{sha256}")
def mwdb_update_sample(
    sha256: str,
    req: UpdateSampleRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Update sample metadata, threat actor, family, and tags."""
    updated = mwdb_mod.update_sample_metadata(
        sha256=sha256,
        threat_actor=req.threat_actor,
        malware_family=req.malware_family,
        description=req.description,
        tlp=req.tlp,
        tags=req.tags,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Sample not found.")
    return updated


@app.delete("/api/malware-db/sample/{sha256}")
def mwdb_delete_sample(
    sha256: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Delete a sample from the repository."""
    if not mwdb_mod.delete_sample(sha256):
        raise HTTPException(status_code=404, detail="Sample not found.")
    return {"success": True, "deleted": sha256}


@app.get("/api/malware-db/sample/{sha256}/download")
def mwdb_download_sample(sha256: str):
    """Download sample binary packed inside a password-protected ZIP (password: infected)."""
    try:
        zip_bytes, zip_filename = mwdb_mod.build_sample_zip(sha256, password="infected")
        return Response(
            content=zip_bytes,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{zip_filename}"',
                "X-Archive-Password": "infected",
            },
        )
    except FileNotFoundError as fnf:
        raise HTTPException(status_code=404, detail=str(fnf))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate ZIP archive: {e}")


@app.post("/api/malware-db/sample/{sha256}/stage")
def mwdb_stage_sample_to_dropzone(
    sha256: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Copy or stage a sample into staging/samples so Binary Lab can access it."""
    sample = mwdb_mod.get_sample(sha256)
    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found.")
    src = sample.get("file_path")
    if not src or not os.path.exists(src):
        raise HTTPException(status_code=404, detail="Sample file missing from disk.")

    target_name = sample.get("original_filename") or f"{sha256[:16]}.bin"
    staging_target = os.path.join(deployment_config.STAGING_SAMPLES_DIR, target_name)
    shutil.copy2(src, staging_target)
    return {
        "success": True,
        "staged_path": staging_target,
        "filename": target_name,
    }


# ---------------------------------------------------------------------------
# Credential Stealer Intelligence & Harvester Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/credential-stealer/overview")
def cs_overview():
    return cred_stealer_mod.get_overview()


@app.get("/api/credential-stealer/credentials")
def cs_credentials(
    q: str = "",
    family: str = "",
    source_type: str = "",
    watchlist_only: bool = False,
    limit: int = 100,
    offset: int = 0,
):
    return cred_stealer_mod.search_credentials(
        q=q, family=family, source_type=source_type,
        watchlist_only=watchlist_only, limit=limit, offset=offset,
    )


class CSBatchDeleteRequest(BaseModel):
    sources: List[str] = []
    raw_sources: List[str] = []
    delete_all: bool = False


@app.get("/api/credential-stealer/credentials/sources")
def cs_get_credentials_sources():
    return {"sources": cred_stealer_mod.get_credential_sources_stats()}


@app.post("/api/credential-stealer/credentials/delete-batch")
def cs_delete_credentials_batch(req: CSBatchDeleteRequest):
    deleted = cred_stealer_mod.delete_credentials_by_sources(
        source_keys=req.sources,
        raw_sources=req.raw_sources,
        delete_all=req.delete_all,
    )
    return {"deleted_count": deleted}


@app.delete("/api/credential-stealer/credentials")
def cs_delete_all_credentials():
    return {"deleted_count": cred_stealer_mod.delete_all_credentials()}


@app.delete("/api/credential-stealer/credentials/{cred_id}")
def cs_delete_credential(cred_id: int):
    if not cred_stealer_mod.delete_credential(cred_id):
        raise HTTPException(status_code=404, detail="Credential record not found")
    return {"deleted": True}


@app.post("/api/credential-stealer/credentials/export")
def cs_export_credentials(payload: Optional[dict] = None):
    from fastapi.responses import Response
    body = payload or {}
    csv_text = cred_stealer_mod.export_credentials_csv(
        q=str(body.get("q") or ""),
        family=str(body.get("family") or ""),
        source_type=str(body.get("source_type") or ""),
        watchlist_only=bool(body.get("watchlist_only", False)),
    )
    return Response(
        content=csv_text,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="mantis_stealer_credentials.csv"'},
    )


@app.post("/api/credential-stealer/browse-folder")
def cs_browse_folder():
    return cred_stealer_mod.browse_local_folder()


@app.post("/api/credential-stealer/browse-file")
def cs_browse_file():
    return cred_stealer_mod.browse_local_file()


@app.get("/api/credential-stealer/sources")
def cs_list_sources():
    return {
        "local": cred_stealer_mod.list_local_sources(),
        "telegram": cred_stealer_mod.list_tg_sources(),
        "settings": cred_stealer_mod.get_settings(),
        "ai_status": cred_stealer_mod.get_mantis_ai_status(),
    }


@app.post("/api/credential-stealer/sources/local")
def cs_add_local_source(payload: dict):
    try:
        return cred_stealer_mod.add_and_scan_local_folder(
            folder_path=str((payload or {}).get("folder_path") or ""),
            label=str((payload or {}).get("label") or ""),
            recursive=bool((payload or {}).get("recursive", True)),
            auto_weekly=bool((payload or {}).get("auto_weekly", True)),
            background=bool((payload or {}).get("background", True)),
            delete_after_parse=bool((payload or {}).get("delete_after_parse", False)),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/credential-stealer/sources/local/{source_id}/scan")
def cs_scan_local_source(source_id: int, payload: Optional[dict] = None):
    try:
        del_opt = None if not payload or "delete_after_parse" not in payload else bool(payload["delete_after_parse"])
        return cred_stealer_mod.scan_local_source_by_id(source_id, background=True, delete_after_parse=del_opt)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.delete("/api/credential-stealer/sources/local/{source_id}")
def cs_delete_local_source(source_id: int):
    if not cred_stealer_mod.delete_local_source(source_id):
        raise HTTPException(status_code=404, detail="Local source not found")
    return {"deleted": True}


@app.post("/api/credential-stealer/sources/upload")
async def cs_upload_logs(files: List[UploadFile] = File(...)):
    if not files:
        raise HTTPException(status_code=400, detail="No files provided")
    with tempfile.TemporaryDirectory(prefix="mantis-cs-up-") as tmpdir:
        staged = []
        for uf in files:
            safe_name = re.sub(r'[<>:"/\\|?*]', "_", os.path.basename(uf.filename or "log.txt"))
            dst = os.path.join(tmpdir, safe_name)
            with open(dst, "wb") as out:
                while True:
                    chunk = await uf.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
            staged.append((safe_name, dst))
        return cred_stealer_mod.ingest_staged_files(staged, source_label="Browser Upload")


@app.post("/api/credential-stealer/sources/telegram")
def cs_add_telegram_source(payload: dict):
    try:
        return cred_stealer_mod.add_tg_source(
            username=str((payload or {}).get("username") or ""),
            title=str((payload or {}).get("title") or ""),
            download_mode=str((payload or {}).get("download_mode") or "all"),
            max_messages=int((payload or {}).get("max_messages") or 50),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/credential-stealer/sources/telegram/{channel_id}/sync")
def cs_sync_telegram_source(channel_id: int):
    try:
        return cred_stealer_mod.sync_tg_source_async(channel_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.delete("/api/credential-stealer/sources/telegram/{channel_id}")
def cs_delete_telegram_source(channel_id: int):
    if not cred_stealer_mod.delete_tg_source(channel_id):
        raise HTTPException(status_code=404, detail="Telegram channel source not found")
    return {"deleted": True}


@app.post("/api/credential-stealer/settings")
def cs_update_settings(payload: dict):
    return cred_stealer_mod.save_settings(payload or {})


@app.post("/api/credential-stealer/sync-all")
def cs_sync_all():
    return cred_stealer_mod.sync_all_async(job_type="manual_all")


@app.get("/api/credential-stealer/parsers")
def cs_list_parsers():
    return {
        "parsers": cred_stealer_mod.list_parsers(),
        "unparsed_queue": cred_stealer_mod.list_unparsed_queue("pending"),
        "ai_status": cred_stealer_mod.get_mantis_ai_status(),
    }


@app.post("/api/credential-stealer/parsers/ai-generate")
def cs_ai_generate_parser(payload: dict):
    try:
        return cred_stealer_mod.ai_generate_parser(
            sample_snippet=str((payload or {}).get("sample_snippet") or ""),
            hint_family=str((payload or {}).get("hint_family") or ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"AI parser generation failed: {exc}")


@app.post("/api/credential-stealer/parsers/test")
def cs_test_parser(payload: dict):
    try:
        return cred_stealer_mod.test_parser_pattern(
            sample_text=str((payload or {}).get("sample_text") or ""),
            pattern=str((payload or {}).get("pattern") or ""),
            mode=str((payload or {}).get("mode") or "block_regex"),
            stealer_family=str((payload or {}).get("stealer_family") or "Custom"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/credential-stealer/parsers")
def cs_save_parser(payload: dict):
    try:
        return cred_stealer_mod.save_parser_and_reparse(
            name=str((payload or {}).get("name") or ""),
            stealer_family=str((payload or {}).get("stealer_family") or "Custom"),
            mode=str((payload or {}).get("mode") or "block_regex"),
            pattern=str((payload or {}).get("pattern") or ""),
            description=str((payload or {}).get("description") or ""),
            sample_text=str((payload or {}).get("sample_text") or ""),
            reparse_queue=bool((payload or {}).get("reparse_queue", True)),
        )
    except (ValueError, re.error) as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.delete("/api/credential-stealer/parsers/{parser_id}")
def cs_delete_parser(parser_id: int):
    if not cred_stealer_mod.delete_parser(parser_id):
        raise HTTPException(status_code=404, detail="Custom parser not found or built-in parsers cannot be deleted")
    return {"deleted": True}


@app.delete("/api/credential-stealer/unparsed/{unparsed_id}")
def cs_dismiss_unparsed(unparsed_id: int):
    if not cred_stealer_mod.dismiss_unparsed_item(unparsed_id):
        raise HTTPException(status_code=404, detail="Unparsed queue item not found")
    return {"dismissed": True}


@app.delete("/api/credential-stealer/unparsed")
def cs_dismiss_all_unparsed():
    return {"dismissed_count": cred_stealer_mod.dismiss_all_unparsed()}


@app.get("/api/credential-stealer/watchlist")
def cs_list_watchlist():
    return {"items": cred_stealer_mod.list_watchlist()}


@app.post("/api/credential-stealer/watchlist")
def cs_add_watchlist(payload: dict):
    try:
        return cred_stealer_mod.add_watchlist_target(
            target_type=str((payload or {}).get("target_type") or "domain"),
            value=str((payload or {}).get("value") or ""),
            description=str((payload or {}).get("description") or ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.delete("/api/credential-stealer/watchlist/{item_id}")
def cs_delete_watchlist(item_id: int):
    if not cred_stealer_mod.delete_watchlist_target(item_id):
        raise HTTPException(status_code=404, detail="Watchlist item not found")
    return {"deleted": True}


@app.get("/api/credential-stealer/jobs")
def cs_list_jobs(limit: int = 30):
    return {"jobs": cred_stealer_mod.list_jobs(limit=limit)}


@app.delete("/api/credential-stealer/jobs")
def cs_clear_jobs():
    return {"deleted_count": cred_stealer_mod.clear_jobs()}


# ===========================================================================
# AI THREAT HUNTING QUERY GENERATOR API ENDPOINTS
# ===========================================================================

import threat_hunting_db as th_db
import threat_hunting_ingest as th_ingest
import threat_hunting_engine as th_engine
import threat_hunting_validator as th_validator
import threat_hunting_export as th_export
from fastapi import Response


class ThreatHuntURLRequest(BaseModel):
    url: str


class ThreatHuntCreateInvestigationRequest(BaseModel):
    title: str
    source_type: str = "text"
    raw_content: str
    description: Optional[str] = ""
    source_metadata: Optional[Dict[str, Any]] = None
    ai_provider: Optional[str] = None
    ai_model: Optional[str] = None


class ThreatHuntAIKeys(BaseModel):
    """The workbench UI sends ai_provider/ai_model; the API accepted provider/model.

    Both spellings are honoured so either client works.
    """

    provider: Optional[str] = None
    model: Optional[str] = None
    ai_provider: Optional[str] = None
    ai_model: Optional[str] = None

    def resolved(self) -> Tuple[Optional[str], Optional[str]]:
        return (self.provider or self.ai_provider, self.model or self.ai_model)


class ThreatHuntTextRequest(BaseModel):
    content: str
    source_name: str = "Manual Notes"


class ThreatHuntAnalyzeRequest(ThreatHuntAIKeys):
    pass


class ThreatHuntHypothesesRequest(ThreatHuntAIKeys):
    findings: Optional[List[Dict[str, Any]]] = None


class ThreatHuntGenerateQueryRequest(ThreatHuntAIKeys):
    hypothesis: Optional[Dict[str, Any]] = None
    hypothesis_id: Optional[str] = None
    platform: str
    mode: str = "hunting"
    custom_schema: Optional[Dict[str, Any]] = None
    schema_target: Optional[str] = None


class ThreatHuntImproveQueryRequest(ThreatHuntAIKeys):
    action: str
    target_platform: Optional[str] = None
    notes: Optional[str] = ""
    custom_schema: Optional[Dict[str, Any]] = None


class ThreatHuntValidateQueryRequest(BaseModel):
    query_text: str
    platform: str
    hypothesis: Optional[Dict[str, Any]] = None
    mode: str = "hunting"


@app.get("/api/threat-hunting/platforms")
def th_get_platforms():
    return {"platforms": list(th_engine.HUNTING_PLATFORMS.values())}


@app.post("/api/threat-hunting/ingest/file")
async def th_ingest_file(file: UploadFile = File(...)):
    try:
        content_bytes = await file.read()
        extracted = th_ingest.extract_text_from_file(file.filename or "upload.txt", content_bytes)
        return {"success": True, **extracted}
    except Exception as e:
        logger.error(f"Error ingesting file {file.filename}: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/threat-hunting/ingest/url")
def th_ingest_url(req: ThreatHuntURLRequest):
    try:
        res = th_ingest.fetch_threat_report_url(req.url)
        return {"success": True, **res}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"SSRF / URL Validation Error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error fetching URL: {str(e)}")


def _th_investigation_or_404(inv_id: str) -> Dict[str, Any]:
    inv = th_db.get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


def _th_ingest_result(inv_id: str, text: str, source_type: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    """Append extracted evidence to the investigation and report what landed."""
    if not (text or "").strip():
        raise HTTPException(status_code=400, detail="No extractable text in this source")
    updated = th_db.append_investigation_content(inv_id, text, source_type, meta)
    if not updated:
        raise HTTPException(status_code=404, detail="Investigation not found")
    chunks = th_ingest.chunk_document(updated.get("normalized_content") or updated.get("raw_content") or "")
    return {
        "success": True,
        "chars": len(text),
        "chunks_count": len(chunks) or 1,
        "total_chars": len(updated.get("raw_content") or ""),
        "sources": (updated.get("source_metadata") or {}).get("sources", []),
    }


@app.post("/api/threat-hunting/investigations/{inv_id}/ingest/file")
async def th_ingest_file_into_investigation(inv_id: str, file: UploadFile = File(...)):
    _th_investigation_or_404(inv_id)
    try:
        content_bytes = await file.read()
        extracted = th_ingest.extract_text_from_file(file.filename or "upload.txt", content_bytes)
    except Exception as e:
        logger.error(f"Error ingesting file {file.filename} into {inv_id}: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    meta = dict(extracted.get("metadata") or {})
    meta["filename"] = file.filename or meta.get("filename", "")
    return _th_ingest_result(inv_id, extracted.get("text", ""), "file", meta)


@app.post("/api/threat-hunting/investigations/{inv_id}/ingest/url")
def th_ingest_url_into_investigation(inv_id: str, req: ThreatHuntURLRequest):
    _th_investigation_or_404(inv_id)
    try:
        res = th_ingest.fetch_threat_report_url(req.url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"SSRF / URL Validation Error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error fetching URL: {str(e)}")
    meta = dict(res.get("metadata") or {})
    meta["url"] = req.url
    return _th_ingest_result(inv_id, res.get("text", ""), "url", meta)


@app.post("/api/threat-hunting/investigations/{inv_id}/ingest/text")
def th_ingest_text_into_investigation(inv_id: str, req: ThreatHuntTextRequest):
    _th_investigation_or_404(inv_id)
    return _th_ingest_result(inv_id, th_ingest.normalize_text(req.content), "text",
                             {"source_name": req.source_name})


@app.post("/api/threat-hunting/investigations")
def th_create_investigation(req: ThreatHuntCreateInvestigationRequest):
    try:
        inv = th_db.create_investigation(
            title=req.title,
            source_type=req.source_type,
            raw_content=req.raw_content,
            description=req.description or "",
            source_metadata=req.source_metadata,
            ai_provider=req.ai_provider or "",
            ai_model=req.ai_model or ""
        )
        return {"success": True, "id": inv["id"], "investigation": inv}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/threat-hunting/investigations")
def th_list_investigations(limit: int = 50, offset: int = 0):
    return {"investigations": th_db.list_investigations(limit=limit, offset=offset)}


@app.get("/api/threat-hunting/investigations/{inv_id}")
def th_get_investigation(inv_id: str):
    inv = th_db.get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return {"investigation": inv}


@app.delete("/api/threat-hunting/investigations/{inv_id}")
def th_delete_investigation(inv_id: str):
    success = th_db.delete_investigation(inv_id)
    if not success:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return {"deleted": True}


@app.post("/api/threat-hunting/investigations/{inv_id}/analyze")
def th_analyze_investigation(inv_id: str, req: ThreatHuntAnalyzeRequest):
    inv = th_db.get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    try:
        raw_text = inv.get("raw_content", "")
        provider, model = req.resolved()
        analysis = th_engine.analyze_report_content(
            content=raw_text,
            title=inv.get("title", ""),
            provider=provider,
            model=model
        )
        saved_findings = th_db.save_findings(inv_id, analysis.get("findings", []))
        th_db.update_investigation_summary(inv_id, analysis.get("summary", ""))

        # Evaluate attribution using extracted report evidence.
        import threat_assessment
        extracted = threat_assessment.extract_iocs_from_text(raw_text)
        techniques = list(extracted.get("techniques") or [])
        artifacts = []
        for f_item in saved_findings:
            if f_item.get("attack_id"):
                techniques.append(str(f_item["attack_id"]).upper())
            for art in (f_item.get("artifacts") or []):
                artifacts.append(str(art))
        assessment_attr = threat_assessment.get_attributor().evaluate([
            {
                "ioc": inv.get("title", "report"),
                "is_seed": True,
                "scale": 1.0,
                "actors": [],
                "tags": [raw_text[:8000]] + artifacts,
                "malware": artifacts,
                "techniques": sorted(set(techniques)),
            }
        ], top_n=5)

        return {
            "success": True,
            "summary": analysis.get("summary", ""),
            "findings": saved_findings,
            "threat_assessment_attribution": assessment_attr,
            "extracted_iocs": extracted.get("indicators", [])[:30],
        }
    except Exception as e:
        logger.error(f"Analysis error for {inv_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/threat-hunting/investigations/{inv_id}/hypotheses")
def th_create_hypotheses(inv_id: str, req: ThreatHuntHypothesesRequest):
    inv = th_db.get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    try:
        findings = req.findings or inv.get("findings") or []
        if not findings:
            raise HTTPException(status_code=400,
                                detail="Analyze the report first: no findings to build hypotheses from")
        provider, model = req.resolved()
        hypotheses = th_engine.generate_hunting_hypotheses(
            findings=findings,
            report_title=inv.get("title", ""),
            provider=provider,
            model=model
        )
        saved_hypo = th_db.save_hypotheses(inv_id, hypotheses)
        return {"success": True, "hypotheses": saved_hypo}
    except Exception as e:
        logger.error(f"Hypothesis formulation error for {inv_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/threat-hunting/investigations/{inv_id}/generate-query")
def th_generate_query(inv_id: str, req: ThreatHuntGenerateQueryRequest):
    inv = th_db.get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    try:
        hypothesis: Dict[str, Any] = dict(req.hypothesis or {})
        if not hypothesis and req.hypothesis_id:
            for h in inv.get("hypotheses") or []:
                if str(h.get("id")) == str(req.hypothesis_id):
                    hypothesis = dict(h)
                    break
        if not hypothesis:
            raise HTTPException(status_code=400, detail="Select a hypothesis to generate a query from")
        custom_schema = req.custom_schema
        if custom_schema is None and (req.schema_target or "").strip():
            try:
                custom_schema = json.loads(req.schema_target)
            except ValueError:
                custom_schema = None
        provider, model = req.resolved()
        gen_res = th_engine.generate_platform_query(
            hypothesis=hypothesis,
            platform=req.platform,
            mode=req.mode,
            custom_schema=custom_schema,
            provider=provider,
            model=model
        )

        query_text = gen_res.get("query", "").strip()

        # Run deterministic validation
        val_res = th_validator.validate_hunting_query(
            query_text=query_text,
            platform=req.platform,
            hypothesis=hypothesis,
            mode=req.mode
        )

        saved_query = th_db.save_query(
            investigation_id=inv_id,
            platform=gen_res.get("platform", req.platform),
            query_language=gen_res.get("query_language", ""),
            mode=req.mode,
            title=gen_res.get("title", f"Hunting Query - {req.platform}"),
            query_text=query_text,
            hypothesis_id=hypothesis.get("id", ""),
            telemetry_schema=custom_schema or {},
            validation_status=val_res.get("status", "Not Verified"),
            validation_details=val_res,
            explanation=gen_res.get("explanation", ""),
            tuning_guidance=gen_res.get("tuning_guidance", "")
        )

        return {
            "success": True,
            "query": saved_query,
            "validation": val_res
        }
    except Exception as e:
        logger.error(f"Query generation error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/threat-hunting/queries/{query_id}/improve")
def th_improve_query(query_id: str, req: ThreatHuntImproveQueryRequest):
    q = th_db.get_query(query_id)
    if not q:
        raise HTTPException(status_code=404, detail="Query not found")
    try:
        provider, model = req.resolved()
        improved = th_engine.improve_query(
            query_text=q.get("query_text", ""),
            action=req.action,
            platform=q.get("platform", ""),
            target_platform=req.target_platform,
            notes=req.notes or "",
            custom_schema=req.custom_schema,
            provider=provider,
            model=model
        )

        dest_plat = improved.get("platform", q.get("platform"))
        revised_q = improved.get("revised_query", "")

        val_res = th_validator.validate_hunting_query(
            query_text=revised_q,
            platform=dest_plat,
            mode=q.get("mode", "hunting")
        )

        updated_query = th_db.record_query_version(
            query_id=query_id,
            query_text=revised_q,
            action=req.action,
            diff=improved.get("diff", ""),
            notes=req.notes or f"Improved via {req.action}",
            validation_status=val_res.get("status"),
            validation_details=val_res,
            explanation=improved.get("explanation")
        )

        return {
            "success": True,
            "query": updated_query,
            "diff": improved.get("diff", ""),
            "explanation": improved.get("explanation", ""),
            "changes_summary": improved.get("changes_summary", []),
            "validation": val_res
        }
    except Exception as e:
        logger.error(f"Query improvement error for {query_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/threat-hunting/validate-query")
def th_validate_query(req: ThreatHuntValidateQueryRequest):
    val_res = th_validator.validate_hunting_query(
        query_text=req.query_text,
        platform=req.platform,
        hypothesis=req.hypothesis,
        mode=req.mode
    )
    return {"validation": val_res}


@app.get("/api/threat-hunting/investigations/{inv_id}/export/{fmt}")
def th_export_investigation(inv_id: str, fmt: str):
    inv = th_db.get_investigation(inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    fmt = fmt.lower().strip()
    safe_title = re.sub(r"[^\w\-_\.]", "_", inv.get("title", "investigation"))[:50]

    if fmt == "zip":
        zip_bytes = th_export.export_hunting_package_zip(inv)
        return Response(
            content=zip_bytes,
            media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename=ThreatHunting_{safe_title}.zip"}
        )
    elif fmt in ("md", "markdown"):
        md_text = th_export.export_playbook_markdown(inv)
        return Response(
            content=md_text,
            media_type="text/markdown",
            headers={"Content-Disposition": f"attachment; filename=Playbook_{safe_title}.md"}
        )
    elif fmt == "csv":
        csv_text = th_export.export_inventory_csv(inv.get("queries", []))
        return Response(
            content=csv_text,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=Query_Inventory_{safe_title}.csv"}
        )
    elif fmt == "json":
        return Response(
            content=json.dumps(inv, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=Investigation_{safe_title}.json"}
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported export format '{fmt}'")


@app.get("/api/threat-hunting/queries/{query_id}/export/{fmt}")
def th_export_query(query_id: str, fmt: str):
    q = th_db.get_query(query_id)
    if not q:
        raise HTTPException(status_code=404, detail="Query not found")

    content, media_type, filename = th_export.export_single_query(q, fmt)
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# Mount frontend static files as fallback route (must remain at the end of the file)
app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")


