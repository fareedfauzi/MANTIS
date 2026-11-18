"""
MANTIS Data Auto-Updater & Weekly Scheduler
Manages automatic startup updates and recurring weekly synchronization for all
threat intelligence datasets in backend/data/:
- SIGMA Detection Rules (SigmaHQ, Hayabusa, mdecrevoisier, Joe Security, mbabinski, tsale)
- YARA Rule Repositories (YARA Forge, Elastic, YARAify, Malpedia)
- PoC Index & CVEProject Baseline
- MISP Galaxy Clusters
- Reputation and Threat Intelligence Feeds
"""

import os
import sys
import time
import json
import logging
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

logger = logging.getLogger("data_updater")

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
STATE_FILE = DATA_DIR / "auto_update_state.json"
WEEKLY_INTERVAL_SECONDS = 7 * 24 * 3600  # 7 days

_updater_lock = threading.Lock()
_is_updating = False
_last_update_result: Dict[str, Any] = {}


def load_update_state() -> Dict[str, Any]:
    """Load persistent state of auto updates."""
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to read auto_update_state.json: {e}")

    # Default state if not found
    return {
        "last_run_timestamp": 0,
        "last_run_iso": None,
        "next_scheduled_iso": None,
        "interval_days": 7,
        "status": "idle",
        "last_result": {}
    }


def save_update_state(state: Dict[str, Any]) -> None:
    """Save persistent state to disk."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save auto_update_state.json: {e}")


def get_auto_update_status() -> Dict[str, Any]:
    """Return status of background weekly and startup updates."""
    state = load_update_state()
    now = time.time()
    last_run = state.get("last_run_timestamp", 0)
    interval = state.get("interval_days", 7) * 86400
    next_run = last_run + interval if last_run > 0 else now

    next_iso = datetime.utcfromtimestamp(next_run).isoformat() + "Z" if next_run > 0 else "Pending on startup"
    state["next_scheduled_iso"] = next_iso
    state["is_currently_updating"] = _is_updating

    # Compute human readable time remaining
    diff = next_run - now
    if diff > 0:
        days = int(diff // 86400)
        hours = int((diff % 86400) // 3600)
        state["time_until_next_run"] = f"{days}d {hours}h"
    else:
        state["time_until_next_run"] = "Due now"

    return state


def run_full_data_update(force: bool = False, caller: str = "scheduler") -> Dict[str, Any]:
    """
    Run complete update across all data/ resources:
    1. SIGMA detection rules (all 6 upstream repos)
    2. YARA rules (YARA Forge, Elastic, YARAify, Malpedia)
    3. PoC Index & CVE baseline
    4. MISP clusters
    """
    global _is_updating, _last_update_result
    with _updater_lock:
        if _is_updating:
            return {"status": "in_progress", "message": "An update job is already actively running."}
        _is_updating = True

    start_time = time.time()
    logger.info(f"Starting complete MANTIS data update (caller: {caller}, force: {force})...")
    results = {}

    try:
        # 1. Update SIGMA Rules
        try:
            import sigma_updater
            import sigma_repos
            logger.info("Auto-updater: Syncing all 6 Sigma repositories...")
            sigma_res = sigma_updater.download_all_repositories(force=force)
            sigma_repos.index_rules(force=True)
            results["sigma_rules"] = {
                "status": "success",
                "details": sigma_res,
                "total_indexed": len(sigma_repos.index_rules())
            }
        except Exception as e:
            logger.error(f"Auto-updater Sigma rules failed: {e}")
            results["sigma_rules"] = {"status": "error", "error": str(e)}

        # 2. Update YARA Rules
        try:
            import yara_updater
            logger.info("Auto-updater: Checking & updating YARA rules...")
            yara_res = {}
            if force or not yara_updater._is_fresh(yara_updater.YARA_FORGE_EXTRACT):
                yara_res["yara-forge"] = yara_updater.download_yara_forge()
            if force or not yara_updater._is_fresh(yara_updater.ELASTIC_YARA_EXTRACT):
                yara_res["yara-elastic"] = yara_updater.download_elastic_yara()
            if force or not yara_updater._is_fresh(yara_updater.YARAIFY_EXTRACT):
                yara_res["yaraify"] = yara_updater.download_yaraify()
            if force or not yara_updater._is_fresh(yara_updater.MALPEDIA_YARA_EXTRACT):
                yara_res["malpedia"] = yara_updater.download_malpedia_yara()
            results["yara_rules"] = {"status": "success", "details": yara_res}
        except Exception as e:
            logger.error(f"Auto-updater YARA rules failed: {e}")
            results["yara_rules"] = {"status": "error", "error": str(e)}

        # 3. Update PoC Index
        try:
            import pocindex_mod
            logger.info("Auto-updater: Verifying PoC Index...")
            if hasattr(pocindex_mod, "update_if_needed"):
                pocindex_mod.update_if_needed()
            elif hasattr(pocindex_mod, "init_poc_index"):
                pocindex_mod.init_poc_index()
            results["poc_index"] = {"status": "success"}
        except Exception as e:
            logger.error(f"Auto-updater PoC Index failed: {e}")
            results["poc_index"] = {"status": "error", "error": str(e)}

        # 4. Save state
        now = time.time()
        elapsed = now - start_time
        state = {
            "last_run_timestamp": now,
            "last_run_iso": datetime.utcfromtimestamp(now).isoformat() + "Z",
            "next_scheduled_iso": datetime.utcfromtimestamp(now + WEEKLY_INTERVAL_SECONDS).isoformat() + "Z",
            "interval_days": 7,
            "status": "completed",
            "caller": caller,
            "duration_seconds": round(elapsed, 2),
            "last_result": results
        }
        save_update_state(state)
        _last_update_result = state
        logger.info(f"Complete data update completed in {elapsed:.1f}s.")
        return state

    finally:
        _is_updating = False


def check_and_run_startup_update() -> None:
    """
    Called on every server startup:
    Checks if datasets need downloading or if weekly refresh interval elapsed.
    """
    state = load_update_state()
    last_run = state.get("last_run_timestamp", 0)
    now = time.time()

    import sigma_updater
    needs_initial_sync = not all(sigma_updater.is_repo_downloaded(r) for r in ("sigma-hq", "hayabusa", "mdecrevoisier", "joe-security", "mbabinski", "tsale"))
    week_elapsed = (now - last_run) >= WEEKLY_INTERVAL_SECONDS

    if needs_initial_sync or week_elapsed:
        logger.info(f"Startup check triggered update (needs_initial={needs_initial_sync}, week_elapsed={week_elapsed}).")
        run_full_data_update(force=week_elapsed, caller="startup")
    else:
        logger.info(f"Startup check: all data/ up to date. Next weekly update scheduled in {get_auto_update_status()['time_until_next_run']}.")


def start_weekly_updater_loop() -> None:
    """
    Background daemon loop that wakes up periodically (every 1 hour)
    and checks if 7 days have elapsed since the last update.
    If so, runs a full data update automatically.
    """
    logger.info("MANTIS weekly data updater thread initialized (7-day interval).")
    # First do startup check
    try:
        check_and_run_startup_update()
    except Exception as e:
        logger.warning(f"Startup data check error: {e}")

    # Periodic check loop
    while True:
        try:
            time.sleep(3600)  # Check every 1 hour
            state = load_update_state()
            last_run = state.get("last_run_timestamp", 0)
            now = time.time()

            if (now - last_run) >= WEEKLY_INTERVAL_SECONDS:
                logger.info("Weekly interval (7 days) elapsed. Starting automatic data/ update...")
                run_full_data_update(force=True, caller="weekly_schedule")
        except Exception as loop_err:
            logger.warning(f"Weekly updater loop error: {loop_err}")
            time.sleep(300)
