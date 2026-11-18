"""
MANTIS AI Threat Hunting Ingestion Engine
Handles:
1. File Upload: PDF, DOCX, TXT, Markdown, HTML, JSON, CSV
2. URL Ingestion with strict SSRF protection, safe redirects, and article extraction
3. Manual Text Input & Normalization
4. Document Chunking for long report multi-stage analysis
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import logging
import re
import socket
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET
import zipfile

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger("mantis.threat_hunting.ingest")

MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024  # 25MB
MAX_URL_CONTENT_BYTES = 5 * 1024 * 1024  # 5MB
URL_REQUEST_TIMEOUT = 15  # seconds
MAX_REDIRECTS = 3

DEFAULT_CHUNK_SIZE = 7500  # characters
DEFAULT_CHUNK_OVERLAP = 800  # characters


# ---------------------------------------------------------------------------
# SSRF Protection
# ---------------------------------------------------------------------------

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::ffff:0:0/96"),
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("100::/64"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]

BLOCKED_DOMAINS = {
    "localhost", "broadcasthost", "local", "internal", "lan", "home.arpa",
    "metadata.google.internal", "169.254.169.254"
}


def is_ssrf_safe_url(url: str) -> Tuple[bool, str]:
    """
    Validates a URL against SSRF vulnerabilities:
    - Enforces http / https scheme.
    - Resolves host to IP and checks against all private, loopback, link-local, and cloud metadata ranges.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return False, f"Unsupported scheme '{parsed.scheme}'. Only http and https are allowed."

        hostname = (parsed.hostname or "").strip().lower()
        if not hostname:
            return False, "Invalid URL: missing hostname."

        if hostname in BLOCKED_DOMAINS or hostname.endswith((".local", ".internal", ".lan")):
            return False, f"Access to private/internal domain '{hostname}' is blocked."

        # Resolve IP addresses
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        for item in addr_info:
            ip_str = item[4][0]
            ip_obj = ipaddress.ip_address(ip_str)

            # Check if private, loopback, link-local, reserved
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
                return False, f"Access to private/local IP address '{ip_str}' is blocked."

            for net in BLOCKED_IP_NETWORKS:
                if ip_obj in net:
                    return False, f"Access to IP address in blocked subnet '{net}' is denied."

        return True, "URL is verified safe."
    except Exception as e:
        return False, f"URL resolution error: {str(e)}"


# ---------------------------------------------------------------------------
# File Extraction
# ---------------------------------------------------------------------------

def extract_text_from_file(filename: str, content_bytes: bytes) -> Dict[str, Any]:
    """
    Extracts text and technical metadata from uploaded report files.
    Supports: PDF, DOCX, TXT, MD, HTML, JSON, CSV.
    """
    if len(content_bytes) > MAX_FILE_SIZE_BYTES:
        raise ValueError(f"File size exceeds maximum limit of {MAX_FILE_SIZE_BYTES // (1024 * 1024)}MB.")

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    text = ""
    metadata: Dict[str, Any] = {
        "filename": filename,
        "extension": ext,
        "size_bytes": len(content_bytes)
    }

    if ext == "pdf":
        text, pdf_meta = _extract_pdf(content_bytes)
        metadata.update(pdf_meta)
    elif ext in ("docx", "doc"):
        text = _extract_docx(content_bytes)
    elif ext in ("html", "htm"):
        text = _extract_html(content_bytes.decode("utf-8", errors="replace"))
    elif ext == "json":
        text = _extract_json(content_bytes.decode("utf-8", errors="replace"))
    elif ext == "csv":
        text = _extract_csv(content_bytes.decode("utf-8", errors="replace"))
    else:
        # Default txt / markdown / generic text
        text = content_bytes.decode("utf-8", errors="replace")

    # Clean and normalize
    cleaned_text = normalize_text(text)
    metadata["char_count"] = len(cleaned_text)
    metadata["word_count"] = len(cleaned_text.split())

    return {
        "text": cleaned_text,
        "metadata": metadata
    }


def _extract_pdf(content_bytes: bytes) -> Tuple[str, Dict[str, Any]]:
    pages_text: List[str] = []
    meta: Dict[str, Any] = {}
    try:
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(content_bytes))
        meta["num_pages"] = len(reader.pages)
        for i, page in enumerate(reader.pages):
            p_text = page.extract_text() or ""
            if p_text.strip():
                pages_text.append(f"--- Page {i + 1} ---\n" + p_text)
    except Exception as e:
        logger.warning(f"pypdf extraction error: {e}. Falling back to raw text scan.")
        # Fallback raw string scan
        decoded = content_bytes.decode("latin-1", errors="replace")
        matches = re.findall(r"\(([\w\s\-\.\:\\\/]+)\)\s*Tj", decoded)
        pages_text.append(" ".join(matches))

    return "\n\n".join(pages_text), meta


def _extract_docx(content_bytes: bytes) -> str:
    paragraphs: List[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(content_bytes)) as z:
            xml_content = z.read("word/document.xml")
            tree = ET.fromstring(xml_content)
            # Find all text elements
            for p in tree.iter():
                if p.tag.endswith("p"):
                    p_text = "".join(t.text for t in p.iter() if t.tag.endswith("t") and t.text)
                    if p_text.strip():
                        paragraphs.append(p_text.strip())
    except Exception as e:
        logger.error(f"Error parsing DOCX xml: {e}")
        # Raw fallback
        decoded = content_bytes.decode("utf-8", errors="replace")
        paragraphs.append(re.sub(r"[^\x20-\x7E\n]", " ", decoded))

    return "\n\n".join(paragraphs)


def _extract_html(html_str: str) -> str:
    soup = BeautifulSoup(html_str, "html.parser")
    # Remove script, style, navigation, footer, and ads
    for tag in soup(["script", "style", "noscript", "nav", "footer", "header", "aside"]):
        tag.decompose()

    # Extract preserving headings and code blocks
    lines: List[str] = []
    for elem in soup.find_all(["h1", "h2", "h3", "h4", "p", "pre", "code", "li"]):
        txt = elem.get_text().strip()
        if not txt:
            continue
        if elem.name in ("h1", "h2", "h3", "h4"):
            lines.append(f"\n### {txt}\n")
        elif elem.name in ("pre", "code"):
            lines.append(f"```\n{txt}\n```")
        elif elem.name == "li":
            lines.append(f"- {txt}")
        else:
            lines.append(txt)

    if not lines:
        return soup.get_text(separator="\n", strip=True)

    return "\n\n".join(lines)


def _extract_json(json_str: str) -> str:
    try:
        data = json.loads(json_str)
        return json.dumps(data, indent=2)
    except Exception:
        return json_str


def _extract_csv(csv_str: str) -> str:
    reader = csv.reader(io.StringIO(csv_str))
    lines: List[str] = []
    for row in reader:
        if any(cell.strip() for cell in row):
            lines.append(" | ".join(row))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# URL Ingestion
# ---------------------------------------------------------------------------

def fetch_threat_report_url(url: str) -> Dict[str, Any]:
    """
    Safely retrieves a threat intel report webpage with SSRF protection,
    redirect validation, and HTML technical content extraction.
    """
    safe, reason = is_ssrf_safe_url(url)
    if not safe:
        raise ValueError(f"SSRF Security Violation: {reason}")

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36 MANTIS-Threat-Hunter/2.0"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    current_url = url
    session = requests.Session()
    session.max_redirects = MAX_REDIRECTS

    try:
        # Check head/streaming to enforce max size
        with session.get(
            current_url,
            headers=headers,
            timeout=URL_REQUEST_TIMEOUT,
            stream=True,
            allow_redirects=True
        ) as resp:
            # Check response status
            resp.raise_for_status()

            # Verify final redirected URL is also SSRF-safe
            safe_final, final_reason = is_ssrf_safe_url(resp.url)
            if not safe_final:
                raise ValueError(f"SSRF Violation on Redirect to '{resp.url}': {final_reason}")

            # Read content up to max size
            chunks = []
            total_size = 0
            for chunk in resp.iter_content(chunk_size=64 * 1024):
                total_size += len(chunk)
                if total_size > MAX_URL_CONTENT_BYTES:
                    break
                chunks.append(chunk)

            raw_bytes = b"".join(chunks)

            # Detect encoding
            encoding = resp.encoding or "utf-8"
            html_text = raw_bytes.decode(encoding, errors="replace")

    except requests.exceptions.Timeout:
        raise TimeoutError(f"Request to {url} timed out after {URL_REQUEST_TIMEOUT}s.")
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Failed to fetch threat intel URL: {str(e)}")

    # Extract article title and clean body
    soup = BeautifulSoup(html_text, "html.parser")
    title = (soup.title.string if soup.title else "") or url

    # Try standard article containers first
    article = soup.find("article") or soup.find("main") or soup.find(class_=re.compile(r"post|article|content|entry", re.I))
    body_html = str(article) if article else html_text
    extracted_text = _extract_html(body_html)

    cleaned_text = normalize_text(extracted_text)

    return {
        "title": title.strip(),
        "url": resp.url,
        "text": cleaned_text,
        "metadata": {
            "source_url": url,
            "final_url": resp.url,
            "status_code": resp.status_code,
            "char_count": len(cleaned_text),
            "word_count": len(cleaned_text.split()),
        }
    }


# ---------------------------------------------------------------------------
# Normalization & Chunking
# ---------------------------------------------------------------------------

def normalize_text(text: str) -> str:
    """Normalizes whitespace while preserving code blocks, commands, and formatting."""
    if not text:
        return ""
    # Normalize Windows CRLF to LF
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    # Replace excessive blank lines (more than 2) with 2
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()


def chunk_document(
    text: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    chunk_overlap: int = DEFAULT_CHUNK_OVERLAP
) -> List[Dict[str, Any]]:
    """
    Splits long threat intel reports into overlapping chunks for multi-stage LLM analysis.
    Preserves paragraph and sentence boundaries wherever possible.
    """
    if not text or len(text) <= chunk_size:
        return [{"chunk_index": 0, "text": text, "start_char": 0, "end_char": len(text)}]

    chunks: List[Dict[str, Any]] = []
    start = 0
    total_len = len(text)
    idx = 0

    while start < total_len:
        end = min(start + chunk_size, total_len)

        # If not at the end of the text, look for a good break point
        if end < total_len:
            # Try to break at a double newline (paragraph boundary)
            para_break = text.rfind("\n\n", start + chunk_size // 2, end)
            if para_break != -1:
                end = para_break
            else:
                # Try single newline
                line_break = text.rfind("\n", start + chunk_size // 2, end)
                if line_break != -1:
                    end = line_break
                else:
                    # Try period followed by space
                    sentence_break = text.rfind(". ", start + chunk_size // 2, end)
                    if sentence_break != -1:
                        end = sentence_break + 1

        chunk_text = text[start:end].strip()
        if chunk_text:
            chunks.append({
                "chunk_index": idx,
                "text": chunk_text,
                "start_char": start,
                "end_char": end,
                "char_length": len(chunk_text)
            })
            idx += 1

        if end >= total_len:
            break

        # Move start with overlap
        start = max(start + 1, end - chunk_overlap)

    return chunks
