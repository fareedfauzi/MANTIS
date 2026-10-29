#!/usr/bin/env python3
"""Standalone Workspace OSINT & CTI Internet Lookup Tool.

Enables autonomous AI agents and analysts to query live, public threat intelligence
and internet OSINT sources directly from the workspace terminal without requiring
API keys.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) MANTIS-Agent/1.0"


def _fetch_json(url: str, timeout: int = 8) -> Optional[Any]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        return None


def lookup_hash_circl(hash_val: str) -> Dict[str, Any]:
    """Query CIRCL Hashlookup (open, free, NSRL/known database)."""
    h = hash_val.lower().strip()
    algo = "md5" if len(h) == 32 else ("sha1" if len(h) == 40 else "sha256")
    url = f"https://hashlookup.circl.lu/lookup/{algo}/{h}"
    res = _fetch_json(url)
    if not res:
        return {"status": "not_found", "source": "CIRCL Hashlookup"}
    return {
        "status": "found",
        "source": "CIRCL Hashlookup",
        "filename": res.get("FileName"),
        "mimetype": res.get("mimetype"),
        "filesize": res.get("FileSize"),
        "db": res.get("db"),
        "trust": res.get("hashlookup:trust"),
    }


def lookup_otx(indicator_type: str, value: str) -> Dict[str, Any]:
    """Query AlienVault OTX public API."""
    ind_type = "IPv4" if indicator_type == "ip" else ("domain" if indicator_type == "domain" else "file")
    url = f"https://otx.alienvault.com/api/v1/indicators/{ind_type}/{urllib.parse.quote(value)}/general"
    res = _fetch_json(url)
    if not res:
        return {"status": "error_or_none", "pulses": []}
    pulse_info = res.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []
    summary = []
    for p in pulses[:5]:
        summary.append({
            "name": p.get("name"),
            "author": p.get("author_name"),
            "tags": p.get("tags")[:5] if p.get("tags") else [],
            "created": p.get("created"),
            "references": p.get("references")[:3] if p.get("references") else [],
        })
    return {
        "status": "found" if pulses else "no_pulses",
        "pulse_count": pulse_info.get("count", 0),
        "pulses": summary,
    }


def lookup_rdap(indicator_type: str, value: str) -> Dict[str, Any]:
    """Query open standard RDAP for domain or IP registration/ASN."""
    endpoint = "ip" if indicator_type == "ip" else "domain"
    url = f"https://rdap.org/{endpoint}/{urllib.parse.quote(value)}"
    res = _fetch_json(url)
    if not res:
        return {"status": "not_found"}
    if indicator_type == "ip":
        return {
            "status": "found",
            "handle": res.get("handle"),
            "name": res.get("name"),
            "country": res.get("country"),
            "type": res.get("type"),
            "startAddress": res.get("startAddress"),
            "endAddress": res.get("endAddress"),
        }
    entities = res.get("entities") or []
    registrars = []
    for ent in entities:
        if "registrar" in (ent.get("roles") or []):
            vcards = ent.get("vcardArray") or []
            if len(vcards) > 1:
                for entry in vcards[1]:
                    if entry and entry[0] == "fn":
                        registrars.append(entry[3])
    return {
        "status": "found",
        "domain": res.get("ldhName"),
        "handle": res.get("handle"),
        "registrar": ", ".join(registrars) or "Unknown",
        "status_flags": res.get("status") or [],
    }


def lookup_github(query: str) -> Dict[str, Any]:
    """Search public GitHub issues and discussions for unique mutexes, strings, or CVEs."""
    url = f"https://api.github.com/search/issues?q={urllib.parse.quote(query)}+in:title,body&per_page=5"
    res = _fetch_json(url)
    if not res:
        return {"status": "error_or_none", "items": []}
    items = []
    for item in res.get("items", [])[:5]:
        items.append({
            "title": item.get("title"),
            "url": item.get("html_url"),
            "repository": item.get("repository_url", "").split("/")[-1],
            "created_at": item.get("created_at"),
            "body_snippet": (item.get("body") or "")[:200].replace("\r", " ").replace("\n", " "),
        })
    return {
        "status": "found" if items else "no_results",
        "total_count": res.get("total_count", 0),
        "items": items,
    }


def main():
    parser = argparse.ArgumentParser(description="MANTIS OSINT & Internet Threat Intelligence Lookup Tool")
    parser.add_argument("--hash", help="Query a file hash (SHA256, MD5) on open databases")
    parser.add_argument("--domain", help="Query domain RDAP, registration, and OTX")
    parser.add_argument("--ip", help="Query IP RDAP, ASN, and OTX")
    parser.add_argument("--query", "-q", help="Search public CTI and GitHub for unique strings, mutexes, PDBs, or actor names")
    parser.add_argument("--json", action="store_true", help="Output pure JSON")

    args = parser.parse_args()

    results: Dict[str, Any] = {}

    if args.hash:
        h = args.hash.strip()
        results["hash"] = h
        results["circl"] = lookup_hash_circl(h)
        results["otx"] = lookup_otx("file", h)

    if args.domain:
        d = args.domain.strip()
        results["domain"] = d
        results["rdap"] = lookup_rdap("domain", d)
        results["otx"] = lookup_otx("domain", d)

    if args.ip:
        ip = args.ip.strip()
        results["ip"] = ip
        results["rdap"] = lookup_rdap("ip", ip)
        results["otx"] = lookup_otx("ip", ip)

    if args.query:
        q = args.query.strip()
        results["query"] = q
        results["github"] = lookup_github(q)

    if not results:
        parser.print_help()
        sys.exit(1)

    if args.json:
        print(json.dumps(results, indent=2))
        return

    # Print clean Markdown summary
    print(f"## OSINT Lookup Results")
    for k, v in results.items():
        if isinstance(v, dict):
            print(f"\n### {k.upper()}")
            for sub_k, sub_v in v.items():
                if isinstance(sub_v, list):
                    print(f"- **{sub_k}** ({len(sub_v)} entries):")
                    for item in sub_v[:3]:
                        print(f"  * {item}")
                else:
                    print(f"- **{sub_k}**: {sub_v}")
        else:
            print(f"- **{k}**: {v}")


if __name__ == "__main__":
    main()
