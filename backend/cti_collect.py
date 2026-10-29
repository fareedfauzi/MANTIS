"""CTI Articles: RSS/Atom collector + article fetch/extract/normalize.

Polling is polite by default (few workers, timeouts, byte caps, per-feed
limits). One broken feed or article never stops the others: every unit of
work is exception-isolated.
"""
import calendar
import logging
import os
import re
import time
import urllib.parse
import urllib.request
import urllib.error
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser

import feedparser

import cti_config as cfg
import cti_db as db
import cti_extract as cx

logger = logging.getLogger("mantis.cti.collect")

SKIP_TAGS = {"script", "style", "nav", "footer", "header", "aside",
             "noscript", "iframe", "form", "button", "select"}
CONTENT_TAGS = {"article", "main"}


class _TextExtractor(HTMLParser):
    """Strip scripts/styles/chrome; prefer <article>/<main> when present."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth = 0
        self.skip_depth = None
        self.in_content = False
        self.content_depth = None
        self.chunks = []
        self.content_chunks = []
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        self.depth += 1
        if tag == "title":
            self._in_title = True
        if tag in SKIP_TAGS and self.skip_depth is None:
            self.skip_depth = self.depth
        if tag in CONTENT_TAGS and not self.in_content:
            self.in_content = True
            self.content_depth = self.depth

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self._in_title = False
        if self.skip_depth is not None and self.depth <= self.skip_depth:
            if self.depth == self.skip_depth:
                self.skip_depth = None
        if self.in_content and self.depth <= (self.content_depth or 0):
            self.in_content = False
            self.content_depth = None
        self.depth = max(0, self.depth - 1)

    def handle_data(self, data):
        if self.skip_depth is not None:
            return
        text = (data or "").strip()
        if not text:
            return
        if self._in_title and not self.title:
            self.title = text[:300]
        self.chunks.append(text)
        if self.in_content:
            self.content_chunks.append(text)


def extract_article_content(html: str, url: str = "") -> dict:
    """HTML -> {title, text, html, excerpt}. No assets kept, no JS run."""
    parser = _TextExtractor()
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:
        pass
    body = parser.content_chunks or parser.chunks
    text = re.sub(r"[ \t]+", " ", "\n".join(body))
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    # Sanitized excerpt HTML: paragraphs only, everything else escaped away.
    safe_html = safe_paragraphs_html(text)
    words = text.split()
    excerpt = " ".join(words[:60])
    return {"title": parser.title, "text": text[:200000],
            "html": safe_html[:20000], "excerpt": excerpt[:600]}


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def html_to_text(html: str) -> str:
    """Visible text of an HTML fragment (scripts/chrome stripped)."""
    parser = _TextExtractor()
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:
        pass
    body = parser.content_chunks or parser.chunks
    text = re.sub(r"[ \t]+", " ", "\n".join(body))
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def safe_paragraphs_html(text: str, max_paras: int = 6) -> str:
    paras = [p.strip() for p in (text or "").split("\n\n") if p.strip()][:max_paras]
    return "".join(f"<p>{_esc(p)}</p>" for p in paras)


def entry_embedded_text(entry) -> tuple:
    """Full article text already inside the feed entry, if substantial.

    Many publishers render pages client-side, so fetching the article URL
    yields only boilerplate. content:encoded (or a long summary) avoids the
    HTTP fetch entirely. Returns (text, via) with via in
    feed-content/feed-summary/"".
    """
    try:
        blocks = entry.get("content") or []
    except Exception:
        blocks = []
    for block in blocks:
        val = block.get("value") if isinstance(block, dict) else ""
        if val:
            text = html_to_text(val)
            if len(text) >= 500:
                return text, "feed-content"
    try:
        summary = entry.get("summary") or ""
    except Exception:
        summary = ""
    if summary:
        text = html_to_text(summary)
        if len(text) >= 500:
            return text, "feed-summary"
    return "", ""


def entry_published_iso(entry) -> str:
    for key in ("published_parsed", "updated_parsed"):
        try:
            ts = getattr(entry, key, None) or entry.get(key)
            if ts:
                return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(calendar.timegm(ts)))
        except Exception:
            continue
    return ""


def entry_url(entry) -> str:
    for key in ("link", "id"):
        try:
            url = (getattr(entry, key, None) or entry.get(key) or "").strip()
        except Exception:
            url = ""
        if url and url.lower().startswith(("http://", "https://")):
            return url
    return ""


def fetch_article(url: str):
    """GET article HTML (bounded). Returns (html, final_url) or (None, url)."""
    req = urllib.request.Request(url, headers={"User-Agent": cfg.CTI_USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=cfg.ARTICLE_TIMEOUT_SECONDS) as resp:
            ctype = (resp.headers.get("Content-Type") or "").lower()
            if "html" not in ctype and "xml" not in ctype and "text" not in ctype:
                return None, url
            body = resp.read(cfg.ARTICLE_MAX_BYTES + 1)
            final = resp.geturl() or url
        try:
            return body.decode("utf-8", errors="replace"), final
        except Exception:
            return None, url
    except Exception as e:
        logger.info("CTI article fetch failed %s: %s", url[:120], e)
        return None, url


class FeedLinkDiscoverer(HTMLParser):
    def __init__(self):
        super().__init__()
        self.feeds = []

    def handle_starttag(self, tag, attrs):
        if tag == "link":
            attr_dict = dict(attrs)
            if attr_dict.get("rel") == "alternate":
                ctype = attr_dict.get("type", "").lower()
                if "application/rss+xml" in ctype or "application/atom+xml" in ctype or "text/xml" in ctype:
                    href = attr_dict.get("href")
                    if href:
                        self.feeds.append(href)

def _do_fetch_feed_with_discovery(url: str, timeout: int, max_discoveries: int) -> tuple[bytes, str]:
    req = urllib.request.Request(url, headers={"User-Agent": cfg.CTI_USER_AGENT})
    logger.info("[CTI] Fetching: %s", url)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        final_url = resp.geturl()
        if final_url != url:
            logger.info("[CTI] HTTP 301/302 -> %s", final_url)
        body = resp.read(cfg.ARTICLE_MAX_BYTES * 3)
        ctype = (resp.headers.get("Content-Type") or "").lower()
        
    logger.info("[CTI] Content-Type: %s", ctype)
    body_start = body[:2000].lower()
    
    if b"<?xml" in body_start or b"<rss" in body_start or b"<feed" in body_start:
        return body, final_url
        
    if b"<html" in body_start or b"<!doctype html" in body_start:
        logger.info("[CTI] HTML response detected")
        if max_discoveries > 0:
            parser = FeedLinkDiscoverer()
            try:
                parser.feed(body.decode("utf-8", errors="ignore"))
                parser.close()
            except Exception:
                pass
            if parser.feeds:
                discovered_url = urllib.parse.urljoin(final_url, parser.feeds[0])
                logger.info("[CTI] RSS autodiscovery found: %s", discovered_url)
                logger.info("[CTI] Fetching discovered feed")
                return _do_fetch_feed_with_discovery(discovered_url, timeout, max_discoveries - 1)
        raise RuntimeError("HTML_NO_FEED: HTML returned and RSS/Atom autodiscovery found nothing")
        
    return body, final_url

def fetch_feed_with_discovery(url: str, timeout: int = 15, max_discoveries: int = 1) -> tuple[bytes, str]:
    attempt = 0
    max_attempts = 3
    delay = 2.0
    while attempt < max_attempts:
        attempt += 1
        try:
            return _do_fetch_feed_with_discovery(url, timeout, max_discoveries)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise RuntimeError(f"BLOCKED: HTTP {e.code}")
            if e.code == 429:
                raise RuntimeError("RATE_LIMITED: HTTP 429")
            if 500 <= e.code < 600:
                if attempt < max_attempts:
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise RuntimeError(f"TEMPORARY_ERROR: HTTP {e.code}")
            raise RuntimeError(f"HTTP_ERROR: {e.code} {e.reason}")
        except (urllib.error.URLError, socket.timeout, ConnectionError) as e:
            if attempt < max_attempts:
                time.sleep(delay)
                delay *= 2
                continue
            raise RuntimeError(f"TEMPORARY_ERROR: {e}")

def poll_feed(source: dict, conn=None) -> dict:
    """Sync one feed: discover entries, fetch/store new articles. Isolated."""
    if db.is_media_feed(source):
        return {"feed": source.get("feed_url", ""), "new": 0, "updated": 0,
                "seen": 0, "skipped": 0,
                "error": "Skipped: non-article feed (podcast/video)"}
    stats = {"feed": source.get("feed_url", ""), "new": 0, "updated": 0,
             "seen": 0, "skipped_known": 0, "skipped_short": 0,
             "fetch_failed": 0, "duplicates": 0, "error": ""}
    own = conn is None
    if own:
        conn = db.connect()
    try:
        # Phase 1 (reads + quick writes only): parse the feed and decide
        # what needs fetching. No network inside a transaction.
        try:
            feed_bytes, final_url = fetch_feed_with_discovery(source["feed_url"])
            parsed = feedparser.parse(feed_bytes)
        except Exception as e:
            raise RuntimeError(str(e))
        entries = list(getattr(parsed, "entries", []) or [])
        if getattr(parsed, "bozo", 0) and not entries:
            exc_str = str(getattr(parsed, "bozo_exception", "parse failed"))
            raise RuntimeError(f"INVALID_FEED: {exc_str}")
        try:
            feed_title = ((parsed.feed or {}).get("title") or "").strip()
        except Exception:
            feed_title = ""
        if feed_title and feed_title != (source.get("name") or ""):
            db.update_source_name(source["id"], feed_title, conn=conn)
        db.touch_source(source["id"], True, conn=conn)  # attempt marker
        todos = []
        for entry in entries[:cfg.MAX_NEW_PER_FEED * 2]:
            url = entry_url(entry)
            if not url:
                continue
            norm = db.normalize_url(url)
            if not norm:
                continue
            stats["seen"] += 1
            try:
                title = (getattr(entry, "title", None) or entry.get("title") or "").strip()
            except Exception:
                title = ""
            if "[virtual event]" in title.lower() or "[virtual event]" in str(entry.get("summary") or "").lower():
                stats["skipped_short"] += 1
                continue
            try:
                author = (getattr(entry, "author", None) or entry.get("author") or "").strip()
            except Exception:
                author = ""
            existing = db.find_article_by_url_norm(norm, conn=conn)
            todos.append((entry, url, norm, title, author, existing))
        if own:
            conn.commit()  # release the lock before any network I/O
        added_new = False
        fetched = []
        # Phase 2 (network, no open transaction): fetch + extract.
        for entry, url, norm, title, author, existing in todos:
            text, via, final_url, page_title, html_frag = "", "", url, "", ""
            embedded, via = entry_embedded_text(entry)
            if embedded:
                text, final_url = embedded, url
            else:
                html, final_url = fetch_article(url)
                if not html:
                    stats["fetch_failed"] += 1
                    continue
                content = extract_article_content(html, final_url)
                text, page_title, html_frag = content["text"], content["title"], content["html"]
            if not text or len(text) < 200:
                stats["skipped_short"] += 1
                continue  # boilerplate/empty page, not an article
            if via:
                html_frag = safe_paragraphs_html(text)
            words = text.split()
            fetched.append({
                "source_id": source["id"],
                "title": title or page_title or final_url,
                "url": url,
                "canonical_url": db.normalize_url(final_url) or norm,
                "url_norm": norm,
                "author": author[:200],
                "published_at": entry_published_iso(entry),
                "modified_at": "",
                "fetched_at": db.now_iso(),
                "content_text": text[:200000],
                "content_html": html_frag[:20000],
                "excerpt": " ".join(words[:60])[:600],
                "content_hash": db.content_hash(text),
                "existing": existing,
            })
        # Phase 3 (quick writes, one short transaction): store everything.
        for article in fetched:
            existing = article.pop("existing")
            if existing:
                if existing.get("content_hash") != article["content_hash"]:
                    db.update_article_content(existing["id"], article, conn=conn)
                    db.replace_indicators(existing["id"],
                                          cx.extract_indicators(article["content_text"]),
                                          conn=conn)
                    stats["updated"] += 1
            else:
                if stats["new"] >= cfg.MAX_NEW_PER_FEED:
                    continue
                # Same story under another URL (feed alias / cross-post)?
                if db.find_articles_by_hash(article["content_hash"], conn=conn):
                    stats["duplicates"] += 1
                    continue
                aid = db.insert_article(article, conn=conn)
                db.replace_indicators(aid, cx.extract_indicators(article["content_text"]),
                                      conn=conn)
                stats["new"] += 1
                added_new = True
        db.touch_source(source["id"], True, new_article=added_new, conn=conn)
        if own:
            conn.commit()
        return stats
    except Exception as e:
        if own:
            try:
                conn.rollback()
            except Exception:
                pass
        stats["error"] = str(e)[:300]
        try:
            db.touch_source(source["id"], False, error=stats["error"])
        except Exception:
            pass
        logger.warning("CTI feed failed %s: %s", source.get("feed_url", "")[:120], stats["error"])
        return stats
    finally:
        if own:
            conn.close()


def refresh_all_indicators(batch: int = 100) -> dict:
    """Re-run current extraction rules over every stored article.

    Only articles whose canonical indicator set changed are rewritten.
    Runs at most once per CTI_EXTRACT_VERSION (marker file).
    """
    db.init_db()
    try:
        dedup = db.dedupe_articles()
    except Exception as e:
        logger.warning("CTI article dedup failed: %s", e)
        dedup = {"groups": 0, "deleted": 0}
    marker = os.path.join(cfg.DATA_DIR, f".cti_extract_v{cx.CTI_EXTRACT_VERSION}")
    if os.path.exists(marker):
        return {"checked": 0, "refreshed": 0, "skipped": "current",
                "dupe_groups": dedup["groups"], "dupes_deleted": dedup["deleted"]}
    conn = db.connect()
    stats = {"checked": 0, "refreshed": 0}
    try:
        ids = [r[0] for r in conn.execute("SELECT id FROM articles").fetchall()]
        for aid in ids:
            row = conn.execute("SELECT content_text FROM articles WHERE id = ?",
                               (aid,)).fetchone()
            if not row:
                continue
            stats["checked"] += 1
            fresh = cx.extract_indicators(row[0] or "")
            current = {(i["type"], i["value"])
                       for i in db.article_indicators(aid, conn=conn)}
            if {(t, v) for t, v, _o in fresh} != current:
                db.replace_indicators(aid, fresh, conn=conn)
                stats["refreshed"] += 1
            if stats["checked"] % max(1, batch) == 0:
                conn.commit()
        conn.commit()
    finally:
        conn.close()
    try:
        with open(marker, "w", encoding="utf-8") as f:
            f.write(db.now_iso())
    except OSError:
        pass
    logger.info("CTI indicator refresh v%d: %d checked, %d rewritten, %d dupes removed",
                cx.CTI_EXTRACT_VERSION, stats["checked"], stats["refreshed"],
                dedup["deleted"])
    stats.update({"dupe_groups": dedup["groups"], "dupes_deleted": dedup["deleted"]})
    return stats


def sync_feeds(sources=None, workers: int = 0) -> dict:
    """Poll enabled feeds concurrently (bounded). Returns aggregate stats."""
    db.init_db()
    sources = [s for s in (sources if sources is not None else db.get_sources())
               if s.get("enabled") and s.get("feed_url")]
    agg = {"feeds": len(sources), "new": 0, "updated": 0, "seen": 0,
           "failed": 0, "skipped_media": 0}
    if not sources:
        return agg
    workers = max(1, min(workers or cfg.SYNC_WORKERS, len(sources)))
    with ThreadPoolExecutor(max_workers=workers,
                            thread_name_prefix="mantis-cti") as pool:
        futures = {pool.submit(poll_feed, s): s for s in sources}
        for fut in as_completed(futures):
            try:
                st = fut.result()
            except Exception as e:  # pragma: no cover - defensive
                st = {"error": str(e)[:200], "new": 0, "updated": 0, "seen": 0}
            agg["new"] += st.get("new", 0)
            agg["updated"] += st.get("updated", 0)
            agg["seen"] += st.get("seen", 0)
            if st.get("error"):
                if st["error"].startswith("Skipped:"):
                    agg["skipped_media"] += 1
                else:
                    agg["failed"] += 1
    logger.info("CTI sync finished: %d feeds, %d new, %d updated, %d failed, %d media-skipped",
                agg["feeds"], agg["new"], agg["updated"], agg["failed"],
                agg["skipped_media"])
    try:
        agg["re_extract"] = refresh_all_indicators()
    except Exception as e:
        logger.warning("CTI indicator refresh failed: %s", e)
    return agg


def ensure_registry(catalog_entries=None) -> dict:
    """Build/refresh the local feed registry from catalog + approved domains.

    Safe to run when the catalog is unreachable: existing feeds are kept,
    only metadata is refreshed and newly resolved feeds are added.
    """
    import cti_catalog as catalog_mod
    import cti_feeds as feeds_mod
    db.init_db()
    if catalog_entries is None:
        catalog_entries, _meta = catalog_mod.fetch_awesome_catalog()
    stats = {"resolved": 0, "not_found": 0, "shared": 0, "curated": 0}
    seen_urls = set()
    covered_hosts = set()

    def _host_key(host: str) -> str:
        host = (host or "").lower()
        return host[4:] if host.startswith("www.") else host

    # Curated feeds first: exact URLs, no allowlist check, no discovery noise.
    for item in cfg.curated_feeds():
        url = item["url"].strip()
        norm_url = url.lower().rstrip("/")
        if norm_url in seen_urls:
            stats["shared"] += 1
            continue
        seen_urls.add(norm_url)
        host = catalog_mod.feed_host(url) or url
        covered_hosts.add(_host_key(host))
        db.upsert_source({"feed_url": url, "title": item["name"],
                          "feed_type": "", "category": item.get("category", ""),
                          "description": "", "domain": host,
                          "discovery": "curated"}, keep_name=True)
        stats["curated"] += 1
        stats["resolved"] += 1
    for domain in cfg.approved_domains():
        if _host_key(domain) in covered_hosts:
            continue  # exact feeds already registered from the curated list
        rows = feeds_mod.resolve_domain_feeds(domain, catalog_entries)
        for row in rows:
            norm_url = (row.get("feed_url") or "").strip().lower().rstrip("/")
            if norm_url:
                if norm_url in seen_urls:
                    # Same feed reachable under two approved domains: keep the
                    # first registration so labels don't flip-flop between runs.
                    stats["shared"] += 1
                    continue
                seen_urls.add(norm_url)
            db.upsert_source(row)
            stats["resolved"] += 1
            if not row.get("feed_url"):
                stats["not_found"] += 1
    for manual in cfg.extra_feeds():
        host = catalog_mod.feed_host(manual["url"]) or manual["url"]
        norm_url = manual["url"].strip().lower().rstrip("/")
        if norm_url in seen_urls:
            stats["shared"] += 1
            continue
        seen_urls.add(norm_url)
        db.upsert_source({"feed_url": manual["url"], "title": manual["name"],
                          "feed_type": "", "category": "", "description": "",
                          "domain": host, "discovery": "manual"}, keep_name=True)
        stats["resolved"] += 1
    try:
        stats["deduped"] = db.dedupe_empty_sources()
    except Exception as e:
        logger.warning("CTI registry dedup failed: %s", e)
        stats["deduped"] = 0
    return stats
