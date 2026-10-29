import feedparser
import logging
import sqlite3
import re
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


logger = logging.getLogger("mantis.startup.rss")

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DATA_DIR, "rss_intel.db")

FEEDS = {
    "Malware.news - Latest": "https://malware.news/latest.rss",
    "Malware News": "https://malware.news/c/news.rss",
    "Malware Analysis": "https://malware.news/c/malwareanalysis.rss",
    "Forensics": "https://malware.news/c/forensics.rss"
}

# Regex patterns for IOC extraction
# Match Hashes
MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_RE = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
# Match IPv4
IP_RE = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
# Match basic domains (rudimentary, avoiding common FP domains)
# Excludes obvious ones but will catch generic ones
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
EXCLUDED_DOMAINS = {
    # Tech / Cloud / Generic Platform Infrastructure
    'github.com', 'github.io', 'githubusercontent.com', 'google.com', 'www.google.com',
    'youtube.com', 'youtu.be', 'twitter.com', 'x.com', 'facebook.com', 'instagram.com',
    'linkedin.com', 'reddit.com', 'telegram.org', 't.me', 'discord.gg', 'discord.com',
    'microsoft.com', 'azure.com', 'amazonaws.com', 'apple.com', 'cloudflare.com',
    'fastly.net', 'akamai.com', 'cloudfront.net', 'schema.org', 'w3.org', 'ietf.org',
    'wikipedia.org', 'wikimedia.org', 'creativecommons.org', 'malware.news',

    # Media / Image / Email / Form / Analytics Hosting
    'shutterstock.com', 'unsplash.com', 'imgur.com', 'giphy.com', 'cloudinary.com',
    'brevo.com', 'sibforms.com', 'sendinblue.com', 'mailchimp.com', 'feedburner.com',
    'wordpress.com', 'wordpress.org', 'wp.com', 'gravatar.com', 'disqus.com',
    'medium.com', 'substack.com',

    # Security Media & Vendor Domains
    'thehackernews.com', 'infosecurity-magazine.com', 'securityweek.com',
    'bleepingcomputer.com', 'recordedfuture.com', 'darkreading.com', 'cyberscoop.com',
    'krebssecurity.com', 'threatpost.com', 'mandiant.com', 'crowdstrike.com',
    'paloaltonetworks.com', 'sentinelone.com', 'kaspersky.com', 'sophos.com',
    'trendmicro.com', 'cisecurity.org', 'cisa.gov', 'nist.gov', 'nvd.nist.gov',
    'mitre.org', 'virustotal.com', 'alienvault.com', 'shodan.io', 'censys.io',
    'urlscan.io', 'abuse.ch', 'incident.io', 'bonfy.ai', 'exploit.in'
}

# Code package prefixes & pseudo-TLDs to filter out
CODE_PACKAGE_PREFIXES = (
    'androidx.', 'android.', 'com.google.', 'com.android.', 'org.apache.',
    'org.springframework.', 'java.', 'javax.', 'kotlin.', 'io.netty.', 'com.microsoft.'
)
INVALID_DOMAIN_EXTENSIONS = (
    '.exe', '.dll', '.sys', '.so', '.py', '.sh', '.js', '.css', '.html', '.json',
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.zip', '.rar', '.pdf', '.txt', '.xml',
    '.state', '.provider', '.internal', '.local', '.test', '.example', '.invalid', '.localhost'
)

def is_valid_ioc_domain(dom: str) -> bool:
    dom_lower = (dom or "").strip().lower()
    if not dom_lower or dom_lower in EXCLUDED_DOMAINS:
        return False
    if any(dom_lower.startswith(prefix) for prefix in CODE_PACKAGE_PREFIXES):
        return False
    if any(dom_lower.endswith(ext) for ext in INVALID_DOMAIN_EXTENSIONS):
        return False
    # Must have at least one dot and a valid 2+ char ASCII TLD
    parts = dom_lower.split('.')
    if len(parts) < 2 or len(parts[-1]) < 2 or not parts[-1].isalpha():
        return False
    # Avoid IP addresses formatted as domain strings
    if all(p.isdigit() for p in parts):
        return False
    return True

def init_db():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR, exist_ok=True)
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Table for articles
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS articles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        link TEXT UNIQUE,
        published_date TEXT,
        source_feed TEXT
    )
    ''')
    
    # Table for extracted IOCs
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        article_id INTEGER,
        ioc_value TEXT,
        ioc_type TEXT,
        FOREIGN KEY(article_id) REFERENCES articles(id),
        UNIQUE(article_id, ioc_value)
    )
    ''')
    
    # Create indexes for fast lookup
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(ioc_value)')
    
    conn.commit()
    return conn

def extract_iocs(text: str):
    if not text: return []
    iocs = []
    
    # MD5
    for m in MD5_RE.findall(text): iocs.append((m.lower(), 'md5'))
    # SHA1
    for m in SHA1_RE.findall(text): iocs.append((m.lower(), 'sha1'))
    # SHA256
    for m in SHA256_RE.findall(text): iocs.append((m.lower(), 'sha256'))
    # IPs (validated octets: 999.999.999.999 is not an address)
    for ip in IP_RE.findall(text):
        if ip == "0.0.0.0" or ip == "127.0.0.1":
            continue
        try:
            if all(0 <= int(part) <= 255 for part in ip.split(".")):
                iocs.append((ip, 'ip'))
        except ValueError:
            continue
    # Domains (Filtered with Noise Exclusion allowlist and code package heuristics)
    for dom in DOMAIN_RE.findall(text):
        if is_valid_ioc_domain(dom):
            iocs.append((dom.lower(), 'domain'))
            
    # Remove duplicates
    return list(set(iocs))

def _fetch_feed(feed_name: str, url: str):
    """Fetch one feed (network-bound). Runs in a worker thread with timing logs."""
    t0 = time.monotonic()
    logger.info("fetching feed: %s", feed_name)
    try:
        feed = feedparser.parse(url)
        entries = list(getattr(feed, "entries", []) or [])
        if not entries:
            # feedparser rarely raises: network/parse failures surface via
            # bozo / HTTP status. A dead feed must not log as success.
            status = getattr(feed, "status", None)
            bozo_exc = getattr(feed, "bozo_exception", None)
            if getattr(feed, "bozo", 0) or (status and status != 200):
                raise RuntimeError(f"feed error (status={status}, bozo={bozo_exc})")
        logger.info("fetched feed %s: %d entries in %.2fs", feed_name, len(entries), time.monotonic() - t0)
        return feed_name, entries, None
    except Exception as e:
        logger.warning("error fetching %s after %.2fs: %s", feed_name, time.monotonic() - t0, e)
        return feed_name, [], e


def update_feeds(max_workers: int = 4):
    t0 = time.monotonic()
    logger.info("RSS refresh started (%d feeds, %d threads)", len(FEEDS), max_workers)
    conn = init_db()
    cursor = conn.cursor()

    new_articles = 0
    new_iocs = 0

    # Fetch all feeds in parallel threads (network-bound), then insert
    # serially in this thread (sqlite connections are not thread-safe).
    with ThreadPoolExecutor(max_workers=min(max_workers, len(FEEDS)), thread_name_prefix="mantis-rss") as pool:
        futures = [pool.submit(_fetch_feed, name, url) for name, url in FEEDS.items()]
        fetched = [f.result() for f in as_completed(futures)]

    for feed_name, entries, error in fetched:
        if error is not None and not entries:
            continue
        try:
            for entry in entries:
                title = entry.get('title', '')
                link = (entry.get('link', '') or '').strip()
                pub_date = entry.get('published', '')
                # Dedup key: link-less articles would all collide on '' and be
                # silently dropped after the first, so fall back to a synthetic
                # feed|title|date key (stored in the link column; such entries
                # had no URL to display anyway).
                dedup_key = link or f"{feed_name}|{title.strip()}|{(pub_date or '').strip()}"[:500]

                # Check if article already exists
                cursor.execute('SELECT id FROM articles WHERE link = ?', (dedup_key,))
                if cursor.fetchone():
                    continue # Skip existing

                # Insert article
                cursor.execute(
                    'INSERT INTO articles (title, link, published_date, source_feed) VALUES (?, ?, ?, ?)',
                    (title, dedup_key, pub_date, feed_name)
                )
                article_id = cursor.lastrowid
                new_articles += 1
                
                # Extract text context
                # Combine title, summary, and content if available
                content_text = title + " " + entry.get('summary', '')
                if 'content' in entry:
                    for c in entry.content:
                        content_text += " " + c.value
                        
                # Extract and insert IOCs
                iocs = extract_iocs(content_text)
                for ioc_val, ioc_type in iocs:
                    try:
                        cursor.execute(
                            'INSERT INTO iocs (article_id, ioc_value, ioc_type) VALUES (?, ?, ?)',
                            (article_id, ioc_val, ioc_type)
                        )
                        new_iocs += 1
                    except sqlite3.IntegrityError:
                        pass # Duplicate IOC in same article
            
            conn.commit()
        except Exception as e:
            logger.warning("error storing %s: %s", feed_name, e)

    purge_fp_iocs(conn)
    logger.info("RSS refresh finished in %.2fs: %d new articles, %d new IOC mappings.",
                time.monotonic() - t0, new_articles, new_iocs)
    conn.close()

def purge_fp_iocs(conn):
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, ioc_value FROM iocs WHERE ioc_type = 'domain'")
        rows = cur.fetchall()
        to_delete = [row[0] for row in rows if not is_valid_ioc_domain(row[1])]
        if to_delete:
            cur.executemany("DELETE FROM iocs WHERE id = ?", [(idx,) for idx in to_delete])
            conn.commit()
            logger.info("Purged %d false-positive domain IOC records.", len(to_delete))
    except Exception as e:
        logger.warning("Failed to purge FP IOCs: %s", e)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(threadName)s] %(name)s: %(message)s")
    update_feeds()
