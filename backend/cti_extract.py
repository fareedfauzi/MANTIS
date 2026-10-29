"""CTI Articles: IOC extraction from normalized article text.

Reuses MANTIS validators (is_ip/is_domain/is_url/get_hash_type,
refang_value/classify_canonical_ioc) — no duplicate implementations.
Every indicator keeps observed_value (as printed) + value (canonical).
Mention semantics: presence is context, never a malicious verdict.
"""
import ipaddress
import logging
import re

from intel_query import (
    classify_canonical_ioc,
    get_hash_type,
    is_domain,
    is_ip,
    is_url,
    normalize_domain,
    normalize_ip,
    normalize_url,
    refang_value,
)

logger = logging.getLogger("mantis.cti.extract")

# Bump when extraction rules change: the sync job re-extracts all stored
# articles once per version so rule improvements apply retroactively.
CTI_EXTRACT_VERSION = 3

HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b"
                      r"|\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{96}\b|\b[a-fA-F0-9]{128}\b")
HASH_TYPES_ALL = ("md5", "sha1", "sha256", "sha3_384", "sha512")
# UUIDs/GUIDs contain 32-hex runs that are not file hashes.
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
IPV4_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
IPV4_PORT_RE = re.compile(r"\b((?:[0-9]{1,3}\.){3}[0-9]{1,3}):(\d{1,5})\b")
IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]{1,60}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)
ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
ASN_RE = re.compile(r"\bAS(\d{1,10})\b")
# Any token containing a defang marker (dot variants or mangled schemes).
DEFANG_RE = re.compile(
    r"[A-Za-z0-9_\-\[\]\(\)\{\}\.]*?"
    r"(?:\[\.\] |\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}|hxxps?://|hxxps?\[:?\]//)"
    r"[A-Za-z0-9_\-\[\]\(\)\{\}\.:/\?#@&=;\+%~]*".replace(" ", ""),
    re.IGNORECASE)

FILE_EXT_SKIP = {".exe", ".dll", ".sys", ".png", ".jpg", ".jpeg", ".gif",
                 ".css", ".js", ".pdf", ".zip"}
# TLDs that are really filename fragments or device names: overwhelmingly
# "report.pdf" / "Fal.Con" style FPs, vanishingly rare as real TLDs in intel.
TLD_SKIP = {
    "exe", "dll", "sys", "so", "dylib", "msi", "bat", "cmd", "ps1", "vbs",
    "lnk", "jar", "war", "apk", "deb", "rpm", "png", "jpg", "jpeg", "gif",
    "bmp", "ico", "svg", "mp3", "mp4", "avi", "mov", "wav", "zip", "tar",
    "gz", "bz2", "xz", "7z", "rar", "cab", "iso", "img", "doc", "docx",
    "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "md", "rst", "adoc", "log",
    "tmp", "bak", "dat", "db", "sqlite", "csv", "tsv", "json", "xml",
    "yaml", "yml", "toml", "ini", "cfg", "conf", "html", "htm", "css",
    "scss", "less", "js", "ts", "tsx", "jsx", "py", "pyc", "c", "h",
    "cpp", "hpp", "cs", "go", "rs", "rb", "php", "pl", "sh", "java",
    "sln", "pcap", "pcapng", "evtx", "ovf", "ova", "woff", "woff2",
    "ttf", "otf", "con", "prn", "aux", "nul",
    "append", "charcode", "charset", "close", "createobject", "decode",
    "encode", "fromcharcode", "join", "load", "open", "read", "readtext",
    "replace", "run", "savetofile", "shell", "sleep", "split", "stream",
    "type", "write", "writetext",
}
CODE_MEMBER_ROOTS = {
    "adodb", "assembly", "base64", "binaryformatter", "console", "crypto",
    "debug", "document", "environment", "file", "filesystemobject", "http",
    "json", "math", "msxml2", "object", "process", "regexp", "request",
    "response", "script", "shell", "string", "system", "text", "window",
    "xmlhttp", "wscript",
}
CODE_CONTEXT_RE = re.compile(
    r"(?:function|class|const|let|var|new|return|if|else|while|for|foreach|"
    r"try|catch|import|from|using|Set|CreateObject|Sub|End Sub|Dim)\s*$",
    re.IGNORECASE,
)


def _looks_like_code_member(token: str, text: str = "", start: int = -1) -> bool:
    """Reject bare object.method/API fragments that pass domain validation."""
    raw = token or ""
    lowered = raw.lower().strip(".")
    labels = lowered.split(".")
    if len(labels) != 2:
        return False
    left, right = labels
    if left in CODE_MEMBER_ROOTS or right in TLD_SKIP:
        return True
    if len(left) == 1 and right.isalpha():
        return True
    if raw != lowered and right not in {"com", "org", "net", "edu", "gov", "mil", "int"}:
        return True
    if text and start >= 0:
        before = text[max(0, start - 24):start]
        if CODE_CONTEXT_RE.search(before):
            return True
    return False


def _domain_ok(token: str, text: str = "", start: int = -1) -> str:
    """Canonical domain or empty string after false-positive filtering."""
    lowered = (token or "").lower().strip(".")
    if "." not in lowered:
        return ""
    if _looks_like_code_member(token, text=text, start=start):
        return ""
    if lowered.rsplit(".", 1)[-1] in TLD_SKIP:
        return ""
    if not is_domain(token):
        return ""
    return normalize_domain(token) or lowered


MAX_INDICATORS = 2000


def _ipv4_context_ok(text: str, start: int, end: int) -> bool:
    before_char = text[start - 1] if start > 0 else ""
    after_char = text[end] if end < len(text) else ""
    if before_char in ".-" or after_char in ".-":
        return False
    if before_char.isalpha() or after_char.isalpha():
        return False
    before = text[max(0, start - 28):start].lower()
    if re.search(r"\b(?:version|ver|v|release|build|rev|revision)\s*$", before):
        return False
    return True


def _valid_ipv4(token: str, text: str = "", start: int = -1, end: int = -1) -> str:
    try:
        parts = token.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            if text and start >= 0 and end >= 0 and not _ipv4_context_ok(text, start, end):
                return ""
            return token
    except (ValueError, AttributeError):
        pass
    return ""


def _valid_ipv6(token: str) -> str:
    token = token.strip("[]().,;:\"'").rstrip(".")
    try:
        addr = ipaddress.ip_address(token)
        return str(addr) if addr.version == 6 else ""
    except ValueError:
        return ""


def _clean_url(token: str) -> str:
    return token.rstrip(").,;:!\"'").rstrip(".")


def extract_indicators(text: str):
    """Return [(type, value, observed)] with canonical values deduped."""
    text = text or ""
    found: dict = {}

    def add(itype: str, value: str, observed: str):
        if not itype or not value or len(found) >= MAX_INDICATORS:
            return
        key = (itype, value)
        if key not in found:
            found[key] = (itype, value, (observed or value)[:500])

    uuid_spans = [(m.start(), m.end()) for m in UUID_RE.finditer(text)]

    def in_uuid(start: int, end: int) -> bool:
        return any(s <= start and end <= e for s, e in uuid_spans)

    for m in HASH_RE.finditer(text):
        token = m.group(0)
        if in_uuid(m.start(), m.end()):
            continue  # part of a UUID/GUID, not a file hash
        if len(set(token.lower())) == 1:
            continue  # placeholder run like 000...0
        kind = get_hash_type(token)
        if kind in HASH_TYPES_ALL:
            add(kind, token.lower(), token)
    port_spans = []
    for m in IPV4_PORT_RE.finditer(text):
        ip, port = m.group(1), m.group(2)
        if _valid_ipv4(ip, text, m.start(1), m.end(1)) and port.isdigit() and 1 <= int(port) <= 65535:
            port_spans.append((m.start(), m.end()))
            add("ipv4", ip, m.group(0))  # observed keeps the port
    for m in IPV4_RE.finditer(text):
        if any(s <= m.start() and m.end() <= e for s, e in port_spans):
            continue  # already captured with its port
        token = m.group(0)
        if _valid_ipv4(token, text, m.start(), m.end()):
            add("ipv4", token, token)
    for m in IPV6_RE.finditer(text):
        norm = _valid_ipv6(m.group(0))
        if norm:
            add("ipv6", norm, m.group(0).strip())
    for m in DOMAIN_RE.finditer(text):
        token = m.group(0)
        lowered = token.lower()
        if any(lowered.endswith(ext) for ext in FILE_EXT_SKIP):
            continue
        norm = _domain_ok(token, text=text, start=m.start())
        if norm:
            add("domain", norm, token)
    for m in URL_RE.finditer(text):
        token = _clean_url(m.group(0))
        if is_url(token):
            norm = normalize_url(token) or token
            add("url", norm, m.group(0).strip()[:500])
    import datetime
    current_year = datetime.datetime.now().year
    for m in CVE_RE.finditer(text):
        year = int(m.group(1))
        if 1999 <= year <= current_year + 1:
            add("cve", m.group(0).upper(), m.group(0))
    for m in ASN_RE.finditer(text):
        try:
            asn = int(m.group(1))
        except ValueError:
            continue
        if 1 <= asn <= 4294967295:
            add("asn", f"AS{asn}", m.group(0))
    for m in ATTACK_RE.finditer(text):
        add("attack", m.group(0).upper(), m.group(0))
    # Defanged pass: original text untouched; matches refanged+validated.
    # A defanged URL also yields its host indicator (ip/domain) in addition.
    for m in DEFANG_RE.finditer(text):
        observed = m.group(0).strip().strip(".,;:\"'()")
        if len(observed) < 4 or len(observed) > 500:
            continue
        canonical = refang_value(observed)
        if "://" in canonical and is_url(canonical):
            add("url", normalize_url(canonical) or canonical, observed)
        kind = classify_canonical_ioc(canonical)
        if kind == "domain":
            norm = _domain_ok(canonical)
            if norm:
                add("domain", norm, observed)
        elif kind == "ip" and is_ip(canonical):
            norm = normalize_ip(canonical)
            if norm:
                try:
                    v = "ipv6" if ipaddress.ip_address(norm).version == 6 else "ipv4"
                except ValueError:
                    continue
                add(v, norm, observed)
        elif kind == "url" and is_url(canonical):
            add("url", normalize_url(canonical) or canonical, observed)
        elif kind == "hash":
            add(get_hash_type(canonical), canonical.lower(), observed)
    return list(found.values())
