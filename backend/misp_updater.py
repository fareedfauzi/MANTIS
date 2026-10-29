import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

logger = logging.getLogger("mantis.startup.misp")


def _misp_cluster_files():
    """Galaxy files to cache: central map + legacy extras.

    NOTE: "malware.json" was dropped - it does not exist in the official
    MISP Galaxy repository (HTTP 404) and could never download.
    """
    try:
        from misp_galaxy import MISP_GALAXY_CATEGORIES, MISP_GALAXY_EXTRA_FILES
        return sorted(
            {spec["file"] for spec in MISP_GALAXY_CATEGORIES.values()}
            | set(MISP_GALAXY_EXTRA_FILES)
        )
    except Exception:
        return [
            "threat-actor.json",
            "ransomware.json",
            "botnet.json",
            "tool.json",
            "mitre-attack-pattern.json",
            "stealer.json",
            "rat.json",
            "backdoor.json",
            "exploit-kit.json",
            "banker.json",
            "wiper.json",
            "cryptominers.json",
        ]

MISP_CLUSTERS = _misp_cluster_files()

BASE_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/"
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "misp")

# Re-download cached galaxies older than this (galaxies update upstream).
# Override with MANTIS_MISP_MAX_AGE_SECONDS (default 7 days); 0 = always refresh.
MISP_MAX_AGE_SECONDS = 7 * 24 * 3600


def _max_age_seconds() -> int:
    for name in ("MANTIS_MISP_MAX_AGE_SECONDS", "IOCINTEL_MISP_MAX_AGE_SECONDS"):
        raw = os.environ.get(name, "").strip()
        if raw:
            try:
                return max(0, int(raw))
            except ValueError:
                continue
    return MISP_MAX_AGE_SECONDS


def _is_fresh(filepath: str) -> bool:
    try:
        if not os.path.isfile(filepath) or os.path.getsize(filepath) == 0:
            return False
        return (time.time() - os.path.getmtime(filepath)) < _max_age_seconds()
    except OSError:
        return False


def _download_one(cluster: str) -> str:
    """Download a single cluster file. Returns 'downloaded', 'cached' or 'failed'."""
    filepath = os.path.join(DATA_DIR, cluster)
    if _is_fresh(filepath):
        return "cached"
    url = f"{BASE_URL}{cluster}"
    started = time.monotonic()
    logger.info("downloading %s ...", cluster)
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            # Atomic write: readers never see half-written JSON.
            tmp_path = filepath + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(resp.text)
            os.replace(tmp_path, filepath)
            logger.info("downloaded %s in %.2fs", cluster, time.monotonic() - started)
            return "downloaded"
        logger.warning("download %s failed: HTTP %s (%.2fs)", cluster, resp.status_code, time.monotonic() - started)
        return "failed"
    except Exception as e:
        logger.warning("download %s failed after %.2fs: %s", cluster, time.monotonic() - started, e)
        return "failed"


def download_misp_clusters(max_workers: int = 5):
    t0 = time.monotonic()
    os.makedirs(DATA_DIR, exist_ok=True)
    logger.info("MISP Galaxy refresh started (%d clusters, %d threads)", len(MISP_CLUSTERS), max_workers)
    # Parallel downloads: each cluster is an independent small HTTP GET, so
    # threads give a big speedup versus the old sequential loop.
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="mantis-misp") as pool:
        futures = {pool.submit(_download_one, cluster): cluster for cluster in MISP_CLUSTERS}
        counts = {"downloaded": 0, "cached": 0, "failed": 0}
        for future in as_completed(futures):
            try:
                counts[future.result()] += 1
            except Exception as e:
                counts["failed"] += 1
                logger.warning("download %s raised: %s", futures[future], e)
    logger.info(
        "MISP Galaxy refresh finished in %.2fs (downloaded=%d cached=%d failed=%d)",
        time.monotonic() - t0, counts["downloaded"], counts["cached"], counts["failed"],
    )

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(threadName)s] %(name)s: %(message)s")
    download_misp_clusters()
