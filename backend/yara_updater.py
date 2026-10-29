import logging
import os
import json
import shutil
import time
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger("mantis.startup.yara")

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
YARA_RULES_DIR = os.path.join(DATA_DIR, "yara-rules")

YARA_FORGE_URL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip"
YARA_FORGE_ZIP = os.path.join(DATA_DIR, "yara-forge-rules-full.zip")
YARA_FORGE_EXTRACT = os.path.join(YARA_RULES_DIR, "yara-forge")

YARAIFY_URL = "https://yaraify.abuse.ch/yarahub/yaraify-rules.zip"
YARAIFY_ZIP = os.path.join(DATA_DIR, "yaraify-rules.zip")
YARAIFY_EXTRACT = os.path.join(YARA_RULES_DIR, "yaraify")

MALPEDIA_YARA_URL = "https://malpedia.caad.fkie.fraunhofer.de/api/get/yara/auto/zip"
MALPEDIA_YARA_ZIP = os.path.join(DATA_DIR, "malpedia-yara.zip")
MALPEDIA_YARA_EXTRACT = os.path.join(YARA_RULES_DIR, "malpedia")

ELASTIC_YARA_TREE_API = "https://api.github.com/repos/elastic/protections-artifacts/git/trees/main?recursive=1"
ELASTIC_YARA_RAW_BASE = "https://raw.githubusercontent.com/elastic/protections-artifacts/main/"
ELASTIC_YARA_EXTRACT = os.path.join(YARA_RULES_DIR, "elastic")

# Skip re-downloading the (large) bundles when a fresh copy already exists.
# Override with MANTIS_YARA_MAX_AGE_SECONDS (default 24h); 0 forces refresh.
YARA_MAX_AGE_SECONDS = 24 * 3600


def _max_age_seconds() -> int:
    for name in ("MANTIS_YARA_MAX_AGE_SECONDS", "IOCINTEL_YARA_MAX_AGE_SECONDS"):
        raw = os.environ.get(name, "").strip()
        if raw:
            try:
                return max(0, int(raw))
            except ValueError:
                continue
    return YARA_MAX_AGE_SECONDS


def _is_fresh(extract_dir: str) -> bool:
    try:
        if not os.path.isdir(extract_dir):
            return False
        entries = os.listdir(extract_dir)
        if not entries:
            return False
        age = time.time() - os.path.getmtime(extract_dir)
        return age < _max_age_seconds()
    except OSError:
        return False


def _safe_extract(zip_path: str, extract_dir: str) -> None:
    """Extract a rule bundle without ZipSlip: every member must resolve
    inside extract_dir (no absolute paths, no `..` escapes)."""
    base = os.path.realpath(extract_dir)
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for info in zip_ref.infolist():
            name = (info.filename or "").replace("\\", "/").strip()
            if not name or os.path.isabs(name) or name.startswith("/"):
                raise ValueError(f"refusing unsafe zip member: {info.filename!r}")
            target = os.path.realpath(os.path.join(base, name))
            if os.path.commonpath([base, target]) != base:
                raise ValueError(f"refusing escaping zip member: {info.filename!r}")
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target) or base, exist_ok=True)
                with zip_ref.open(info, 'r') as src, open(target, 'wb') as dst:
                    while True:
                        chunk = src.read(1024 * 256)
                        if not chunk:
                            break
                        dst.write(chunk)


def _replace_dir(staging_dir: str, extract_dir: str) -> None:
    """Promote a fully prepared staging directory on Windows-safe paths."""
    backup_dir = extract_dir + ".old"
    if os.path.isdir(backup_dir):
        shutil.rmtree(backup_dir, ignore_errors=True)
    elif os.path.exists(backup_dir):
        os.remove(backup_dir)
    if os.path.exists(extract_dir):
        os.replace(extract_dir, backup_dir)
    
    # Retry loop for Windows WinError 5 Access is denied
    for i in range(5):
        try:
            os.replace(staging_dir, extract_dir)
            break
        except Exception:
            if i == 4:
                if not os.path.exists(extract_dir) and os.path.isdir(backup_dir):
                    os.replace(backup_dir, extract_dir)
                raise
            time.sleep(1)

    if os.path.isdir(backup_dir):
        shutil.rmtree(backup_dir, ignore_errors=True)


def _download_and_extract(name: str, url: str, zip_path: str, extract_dir: str) -> str:
    t0 = time.monotonic()
    if _is_fresh(extract_dir):
        logger.info("%s rules are fresh, skipping download (dir=%s)", name, extract_dir)
        return "skipped-fresh"
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR, exist_ok=True)
    # Extract to a temp dir and rename atomically: a failed/interrupted run
    # must never leave a partial dir that looks "fresh" on the next start.
    staging_dir = extract_dir + ".staging"
    try:
        logger.info("downloading %s rules from %s ...", name, url)
        urllib.request.urlretrieve(url, zip_path)

        logger.info("extracting %s rules ...", name)
        if os.path.isdir(staging_dir):
            shutil.rmtree(staging_dir, ignore_errors=True)
        os.makedirs(staging_dir, exist_ok=True)
        _safe_extract(zip_path, staging_dir)
        _replace_dir(staging_dir, extract_dir)

        if os.path.exists(zip_path):
            os.remove(zip_path)
        logger.info("%s rules ready in %.2fs", name, time.monotonic() - t0)
        return "downloaded"
    except Exception as e:
        logger.warning("%s rules update failed after %.2fs: %s", name, time.monotonic() - t0, e)
        if os.path.isdir(staging_dir):
            shutil.rmtree(staging_dir, ignore_errors=True)
        return "failed"


def download_yara_forge():
    return _download_and_extract("Yara-Forge", YARA_FORGE_URL, YARA_FORGE_ZIP, YARA_FORGE_EXTRACT)


def download_yaraify():
    return _download_and_extract("Yaraify", YARAIFY_URL, YARAIFY_ZIP, YARAIFY_EXTRACT)


def download_malpedia_yara():
    return _download_and_extract("Malpedia", MALPEDIA_YARA_URL, MALPEDIA_YARA_ZIP, MALPEDIA_YARA_EXTRACT)


def download_elastic_yara():
    """Download Elastic protections YARA rules from the official GitHub repo."""
    t0 = time.monotonic()
    if _is_fresh(ELASTIC_YARA_EXTRACT):
        logger.info("Elastic YARA rules are fresh, skipping download (dir=%s)", ELASTIC_YARA_EXTRACT)
        return "skipped-fresh"
    os.makedirs(YARA_RULES_DIR, exist_ok=True)
    staging_dir = ELASTIC_YARA_EXTRACT + ".staging"
    try:
        if os.path.isdir(staging_dir):
            shutil.rmtree(staging_dir, ignore_errors=True)
        os.makedirs(staging_dir, exist_ok=True)
        req = urllib.request.Request(
            ELASTIC_YARA_TREE_API,
            headers={"User-Agent": "MANTIS-YARA-Elastic-Updater",
                     "Accept": "application/vnd.github+json"},
        )
        logger.info("downloading Elastic YARA tree from %s ...", ELASTIC_YARA_TREE_API)
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
        count = 0
        prefix = "yara/rules/"
        for item in payload.get("tree", []) if isinstance(payload, dict) else []:
            if item.get("type") != "blob":
                continue
            path = str(item.get("path") or "")
            if not path.startswith(prefix) or not path.lower().endswith((".yar", ".yara")):
                continue
            rel = path[len(prefix):].replace("\\", "/").strip("/")
            if not rel or rel.startswith("../") or "/../" in rel or os.path.isabs(rel):
                continue
            out = os.path.join(staging_dir, *rel.split("/"))
            os.makedirs(os.path.dirname(out) or staging_dir, exist_ok=True)
            url = ELASTIC_YARA_RAW_BASE + urllib.parse.quote(path, safe="/")
            urllib.request.urlretrieve(url, out)
            count += 1
        if count == 0:
            raise RuntimeError("Elastic YARA manifest contained no rule files")
        _replace_dir(staging_dir, ELASTIC_YARA_EXTRACT)
        logger.info("Elastic YARA rules ready in %.2fs (%d files)", time.monotonic() - t0, count)
        return "downloaded"
    except Exception as e:
        logger.warning("Elastic YARA update failed after %.2fs: %s", time.monotonic() - t0, e)
        if os.path.isdir(staging_dir):
            shutil.rmtree(staging_dir, ignore_errors=True)
        return "failed"


def download_all_yara(max_workers: int = 2):
    """Download managed rule sources in parallel threads (used at startup)."""
    t0 = time.monotonic()
    logger.info("YARA rules refresh started (4 sources, %d threads)", max_workers)
    jobs = [
        ("Yara-Forge", YARA_FORGE_URL, YARA_FORGE_ZIP, YARA_FORGE_EXTRACT),
        ("Yaraify", YARAIFY_URL, YARAIFY_ZIP, YARAIFY_EXTRACT),
        ("Malpedia", MALPEDIA_YARA_URL, MALPEDIA_YARA_ZIP, MALPEDIA_YARA_EXTRACT),
    ]
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="mantis-yara") as pool:
        futures = {pool.submit(_download_and_extract, *job): job[0] for job in jobs}
        futures[pool.submit(download_elastic_yara)] = "Elastic"
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
            except Exception as e:
                results[name] = "failed"
                logger.warning("%s rules raised: %s", name, e)
    logger.info("YARA rules refresh finished in %.2fs: %s", time.monotonic() - t0, results)
    return results

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(threadName)s] %(name)s: %(message)s")
    download_all_yara()
