"""Shared dependency-free state and safety helpers for utility tools."""

import json
import os
import subprocess
import sys
import webbrowser
import base64
import urllib.parse
import unicodedata


MAX_EXPORT_BYTES = 64 * 1024 * 1024
EXTERNAL_TEXT_LIMITS = {
    "vt": 512,
    "google": 1000,
    "github": 1000,
    "msdn": 1000,
    "cyberchef": 32 * 1024,
}


def normalize_external_text(value):
    """Make selected UI text stable and safe for an external URL query."""
    cleaned = "".join(
        " " if unicodedata.category(char).startswith("C") else char
        for char in str(value or "")
    )
    text = " ".join(cleaned.split()).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ('"', "'", "`"):
        text = text[1:-1].strip()
    return text


def external_text_limit(mode):
    if mode not in EXTERNAL_TEXT_LIMITS:
        raise ValueError(f"Unsupported external search mode: {mode}")
    return EXTERNAL_TEXT_LIMITS[mode]


def build_external_text_url(mode, text):
    text = normalize_external_text(text)
    if not text:
        raise ValueError("Search text is empty.")
    if len(text) > external_text_limit(mode):
        raise ValueError("Search text exceeds the service safety limit.")
    if mode == "vt":
        query = urllib.parse.urlencode({"query": f'content: "{text}"', "type": "files"})
        return "https://www.virustotal.com/gui/search?" + query
    if mode == "google":
        return "https://www.google.com/search?" + urllib.parse.urlencode({"q": f'"{text}"'})
    if mode == "github":
        return "https://github.com/search?" + urllib.parse.urlencode({"q": text, "type": "code"})
    if mode == "msdn":
        return "https://learn.microsoft.com/en-us/search/?" + urllib.parse.urlencode({"terms": text, "category": "Documentation"})
    if mode == "cyberchef":
        encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
        return "https://gchq.github.io/CyberChef/#input=" + urllib.parse.quote(encoded, safe="")
    raise ValueError(f"Unsupported external search mode: {mode}")


def validate_byte_range(start, end, segments, max_bytes=MAX_EXPORT_BYTES):
    try:
        start, end = int(start), int(end)
    except (TypeError, ValueError):
        return False, "Start and end must be valid addresses.", 0
    if start < 0 or end < start:
        return False, "End address must not be before start address.", 0
    size = end - start + 1
    if size > max_bytes:
        return False, f"Range is too large ({size:,} bytes; limit {max_bytes:,}).", size
    cursor = start
    for seg_start, seg_end in sorted(segments):
        if seg_end <= cursor:
            continue
        if seg_start > cursor:
            return False, f"Range crosses an unmapped gap at 0x{cursor:X}.", size
        cursor = min(end + 1, seg_end)
        if cursor > end:
            return True, "", size
    return False, f"Range includes unmapped bytes at 0x{cursor:X}.", size


class SearchHistory:
    def __init__(self, limit=20, values=None):
        self.limit = max(1, int(limit))
        self.values = []
        for value in reversed(values or []):
            self.add(value)

    def add(self, value):
        value = str(value or "").strip()
        if not value:
            return
        self.values = [item for item in self.values if item != value]
        self.values.insert(0, value)
        del self.values[self.limit:]

    def to_json(self):
        return json.dumps(self.values, ensure_ascii=False)

    @classmethod
    def from_json(cls, value, limit=20):
        try:
            values = json.loads(value or "[]")
        except Exception:
            values = []
        return cls(limit, values if isinstance(values, list) else [])


def open_external(path_or_url):
    target = str(path_or_url)
    if target.startswith(("http://", "https://")):
        return bool(webbrowser.open(target))
    absolute = os.path.abspath(target)
    if sys.platform.startswith("win"):
        os.startfile(absolute)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", absolute])
    else:
        subprocess.Popen(["xdg-open", absolute])
    return True
