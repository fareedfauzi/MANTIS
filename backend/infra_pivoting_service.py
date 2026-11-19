"""
MANTIS Automated Infrastructure Pivoting Engine.

An evidence-driven, passive infrastructure investigation and graph traversal engine
that discovers, normalizes, correlates, and scores related IPs, domains, URLs,
certificates, web properties, and infrastructure fingerprints across existing
MANTIS threat intelligence providers.
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import logging
import math
import os
import re
import sqlite3
import threading
import time
import urllib.parse
import uuid
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

import intel_query
import threat_assessment
from ai_pivot_policy import (
    CA_AND_CERT_DOMAINS,
    CERT_SUPPORT_HOST_TERMS,
    CERT_SUPPORT_PATH_RE,
    PUBLIC_RESOLVERS,
    REPORTING_AND_SANDBOX_DOMAINS,
    SHARED_PLATFORM_DOMAINS,
)
from infra_hunt_service import SHARED_INFRA_MARKERS, environment_keys

logger = logging.getLogger("mantis.infra_pivoting")

DATA_DIR = Path(__file__).resolve().parent / "data"
DB_PATH = DATA_DIR / "infra_pivoting.db"
_DB_LOCK = threading.RLock()

# Active running job control flags: investigation_id -> threading.Event (set = cancel requested)
_ACTIVE_JOBS: Dict[str, threading.Event] = {}
_JOBS_LOCK = threading.RLock()


# =============================================================================
# 1. CONSTANTS, FINGERPRINT PATTERNS & FALSE-POSITIVE FILTERS
# =============================================================================

PIVOT_METHODS: Dict[str, Dict[str, Any]] = {
    "passive_dns": {
        "id": "passive_dns",
        "label": "Passive DNS",
        "category": "dns",
        "description": "Historical DNS timelines and passive A/AAAA resolution history.",
        "default_enabled": True,
    },
    "whois_registration": {
        "id": "whois_registration",
        "label": "WHOIS Records",
        "category": "registration",
        "description": "Registrar, registrant email/organization, netblocks, and registration history.",
        "default_enabled": True,
    },
    "asn_hosting": {
        "id": "asn_hosting",
        "label": "BGP Peers & ASN",
        "category": "network",
        "description": "Autonomous System (ASN), BGP routing prefixes, peers, and hosting context.",
        "default_enabled": True,
    },
    "http_body_headers": {
        "id": "http_body_headers",
        "label": "HTTP Titles, Headers & ETags",
        "category": "web",
        "description": "HTTP response headers, header hashes, ETag headers, Server banners, and HTML titles.",
        "default_enabled": True,
    },
    "jarm_ja4": {
        "id": "jarm_ja4",
        "label": "JARM",
        "category": "tls_fingerprint",
        "description": "TLS active/passive server configuration JARM fingerprints (62-char hex).",
        "default_enabled": True,
    },
    "tls_cert": {
        "id": "tls_cert",
        "label": "X509 Certs, Subjects & JA4X",
        "category": "certificate",
        "description": "X509 certificate SHA-256/SHA-1, serial numbers, Issuers, Subjects, SANs, and JA4X.",
        "default_enabled": True,
    },
    "ssh_host_key": {
        "id": "ssh_host_key",
        "label": "SSH Host Keys & HASSH",
        "category": "service_fingerprint",
        "description": "SSH server host key fingerprints and HASSH key-exchange algorithm fingerprints.",
        "default_enabled": True,
    },
    "favicon_hash": {
        "id": "favicon_hash",
        "label": "Favicon Hashes",
        "category": "web",
        "description": "Favicon MurmurHash3, MD5, and SHA-256 fingerprint correlation across web properties.",
        "default_enabled": True,
    },
    "open_dirs": {
        "id": "open_dirs",
        "label": "OpenDirs",
        "category": "web",
        "description": "Exposed open directory listings ('Index of /') and Etugen Trashpile host files.",
        "default_enabled": True,
    },
    "reverse_ip": {
        "id": "reverse_ip",
        "label": "DNS Records & Reverse IP",
        "category": "dns",
        "description": "DNS record types (A, AAAA, CNAME, MX, NS, TXT, PTR) and co-hosted Reverse IP domains.",
        "default_enabled": True,
    },
    "open_ports": {
        "id": "open_ports",
        "label": "Open Ports",
        "category": "network",
        "description": "Exposed listening ports and non-standard C2 port combinations.",
        "default_enabled": True,
    },
    "ja3_ja4": {
        "id": "ja3_ja4",
        "label": "JA3 / JA4 TLS Fingerprints",
        "category": "tls_fingerprint",
        "description": "JA3, JA3S, JA4, JA4S, and JA4T client/server TLS handshake fingerprints.",
        "default_enabled": True,
    },
    "rdp_cert": {
        "id": "rdp_cert",
        "label": "RDP Certificate Fingerprints",
        "category": "certificate",
        "description": "Port 3389 RDP TLS certificate fingerprints and self-signed machine Common Names.",
        "default_enabled": True,
    },
    "url_resource_pattern": {
        "id": "url_resource_pattern",
        "label": "URL Patterns",
        "category": "web",
        "description": "Endpoint URL path structures, C2 URI patterns, and HTTP redirect chains.",
        "default_enabled": True,
    },
    "html_js_similarity": {
        "id": "html_js_similarity",
        "label": "HTML / JavaScript Similarity",
        "category": "web",
        "description": "HTML DOM body hashes and shared JavaScript/static resource SHA-256 hashes.",
        "default_enabled": True,
    },
    "service_banners": {
        "id": "service_banners",
        "label": "Service Banners",
        "category": "service_fingerprint",
        "description": "Raw TCP/UDP protocol banners, daemon versions, and C2 framework service markers.",
        "default_enabled": True,
    },
}

# Backward-compatible aliases mapped to canonical 16 method IDs
METHOD_ALIASES: Dict[str, str] = {
    "redirect_chain": "url_resource_pattern",
    "whois_records": "whois_registration",
    "bgp_peers": "asn_hosting",
    "x509_ja4x": "tls_cert",
    "ssh_hassh": "ssh_host_key",
    "dns_records": "reverse_ip",
    "url_patterns": "url_resource_pattern",
}

PIVOT_PRESETS: Dict[str, Dict[str, Any]] = {
    "quick": {
        "mode": "quick",
        "label": "Quick Pivot",
        "description": "Fast 1-hop high-confidence discovery with conservative API budget.",
        "max_depth": 1,
        "max_assets": 40,
        "per_pivot_limit": 15,
        "timeout_seconds": 45,
        "api_budget": 16,
        "min_confidence_to_expand": 45,
        "passive_only": True,
        "enabled_methods": list(PIVOT_METHODS.keys()),
    },
    "deep": {
        "mode": "deep",
        "label": "Deep Pivot",
        "description": "Multi-hop (up to 3 hops) graph traversal discovering extended infrastructure clusters.",
        "max_depth": 3,
        "max_assets": 150,
        "per_pivot_limit": 35,
        "timeout_seconds": 180,
        "api_budget": 60,
        "min_confidence_to_expand": 35,
        "passive_only": True,
        "enabled_methods": list(PIVOT_METHODS.keys()),
    },
    "custom": {
        "mode": "custom",
        "label": "Custom Pivot",
        "description": "Analyst-configured depth, asset limits, API budgets, and selective pivot methods.",
        "max_depth": 2,
        "max_assets": 80,
        "per_pivot_limit": 25,
        "timeout_seconds": 90,
        "api_budget": 30,
        "min_confidence_to_expand": 40,
        "passive_only": True,
        "enabled_methods": list(PIVOT_METHODS.keys()),
    },
}

# Known ubiquitous/default fingerprints that cause false positives when used alone
COMMON_JARM_FINGERPRINTS = {
    "00000000000000000000000000000000000000000000000000000000000000",  # No TLS / blocked
    "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d",  # Common Cloudflare/CDN
    "27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c",  # Common default Nginx
    "29d29d15d29d29d00029d29d29d29d58523989151335839938263390810630",  # Standard Apache
    "1dd40d40d00040d1dc1dd40d40d40d542d39a3b8886882962152627b6164e1",  # Default Windows IIS
}

COMMON_HTTP_TITLES = {
    "", "index of /", "404 not found", "403 forbidden", "301 moved permanently",
    "302 found", "welcome to nginx!", "apache2 ubuntu default page: it works",
    "iis windows server", "test page for the HTTP server", "just a moment...",
    "attention required! | cloudflare", "access denied", "bad request", "error",
    "default web site page", "coming soon", "home", "login",
}

COMMON_CERT_ISSUERS = {
    "let's encrypt", "r3", "e1", "r10", "r11", "e5", "e6", "digicert",
    "cloudflare", "sectigo", "zero ssl", "zerossl", "google trust services",
    "amazon", "cpanel", "plesk", "godaddy", "globalsign",
}

CDN_AND_SHARED_KEYWORDS = set(SHARED_INFRA_MARKERS) | {
    "cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "imperva",
    "sucuri", "ddos-guard", "ovh", "hetzner", "digitalocean", "linode",
    "vultr", "amazonaws", "googleusercontent", "azure", "parkingcrew",
    "sedoparking", "bodis", "namecheap", "godaddy", "wix", "squarespace",
    "shopify", "wordpress.com", "blogspot", "github", "vercel", "netlify",
}


# =============================================================================
# 2. PROVIDER CAPABILITY REGISTRY
# =============================================================================

PROVIDER_CAPABILITY_REGISTRY: Dict[str, Dict[str, Any]] = {
    "virustotal": {
        "id": "virustotal",
        "label": "VirusTotal",
        "key_field": "vt_key",
        "env_vars": ["VT_API_KEY", "VIRUSTOTAL_API_KEY", "MANTIS_VT_KEY", "IOCINTEL_VT_KEY"],
        "requires_api_key": True,
        "is_passive": True,
        "supported_seed_types": ["ip", "domain", "url", "hash"],
        "supported_pivot_methods": [
            "passive_dns", "reverse_ip", "tls_cert", "whois_registration",
            "url_resource_pattern", "html_js_similarity", "asn_hosting",
        ],
        "supports_hash_to_infra": True,
        "supported_search_fields": [
            "resolutions", "historical_ssl_certificates", "communicating_files",
            "downloaded_files", "contacted_ips", "contacted_domains", "contacted_urls",
            "subdomains", "urls", "last_https_certificate", "whois",
        ],
        "rate_limit": {"requests_per_minute": 4, "min_interval_seconds": 1.0},
        "pagination": {"supported": True, "style": "cursor_or_limit", "max_page_size": 40},
        "entitlement_notes": "Standard v3 endpoints work with free/community API key (4 req/min); higher quotas & enterprise hunting require VT Premium.",
    },
    "shodan": {
        "id": "shodan",
        "label": "Shodan",
        "key_field": "shodan_key",
        "env_vars": ["SHODAN_API_KEY", "MANTIS_SHODAN_API_KEY"],
        "requires_api_key": True,
        "is_passive": True,
        "supported_seed_types": ["ip", "domain", "certificate", "fingerprint"],
        "supported_pivot_methods": [
            "passive_dns", "reverse_ip", "tls_cert", "http_body_headers",
            "favicon_hash", "jarm_ja4", "ja3_ja4", "ssh_host_key", "rdp_cert",
            "open_dirs", "open_ports", "html_js_similarity", "service_banners", "asn_hosting",
        ],
        "supports_hash_to_infra": False,
        "supported_search_fields": [
            "ssl.cert.fingerprint", "ssl.cert.serial", "ssl.cert.subject.cn",
            "ssl.jarm", "http.favicon.hash", "http.html_hash", "http.headers_hash",
            "http.title", "ssh.fingerprint", "ssh.hassh", "port", "asn", "net", "hostname",
        ],
        "rate_limit": {"requests_per_minute": 30, "min_interval_seconds": 1.1},
        "pagination": {"supported": True, "style": "page", "max_page_size": 100},
        "entitlement_notes": "Host IP & DNS lookups work on basic API keys; search filter queries (ssl.jarm, http.favicon.hash, etc.) require Shodan Membership/Paid query credits.",
    },
    "censys": {
        "id": "censys",
        "label": "Censys",
        "key_field": "censys_key",
        "env_vars": ["CENSYS_PAT", "CENSYS_API_KEY", "MANTIS_CENSYS_PAT"],
        "requires_api_key": True,
        "is_passive": True,
        "supported_seed_types": ["ip", "domain", "certificate", "fingerprint"],
        "supported_pivot_methods": [
            "reverse_ip", "tls_cert", "http_body_headers", "jarm_ja4", "ja3_ja4",
            "ssh_host_key", "rdp_cert", "open_ports", "html_js_similarity",
            "service_banners", "asn_hosting",
        ],
        "supports_hash_to_infra": False,
        "supported_search_fields": [
            "cert.fingerprint_sha256", "cert.parsed.subject_dn",
            "host.services.jarm.fingerprint", "host.services.http.response.html_title",
            "host.services.ssh.server_host_key.fingerprint_sha256",
            "host.autonomous_system.asn", "host.dns.names", "host.services.port",
        ],
        "rate_limit": {"requests_per_minute": 25, "min_interval_seconds": 1.0},
        "pagination": {"supported": True, "style": "cursor", "max_page_size": 100},
        "entitlement_notes": "Requires Censys Personal Access Token (PAT) or API ID:Secret.",
    },
    "fofa": {
        "id": "fofa",
        "label": "FOFA",
        "key_field": "fofa_key",
        "env_vars": ["FOFA_API_KEY", "MANTIS_FOFA_API_KEY"],
        "requires_api_key": True,
        "is_passive": True,
        "supported_seed_types": ["ip", "domain", "certificate", "fingerprint"],
        "supported_pivot_methods": [
            "reverse_ip", "tls_cert", "http_body_headers", "favicon_hash",
            "jarm_ja4", "ja3_ja4", "rdp_cert", "open_dirs", "open_ports",
            "html_js_similarity", "service_banners", "asn_hosting",
        ],
        "supports_hash_to_infra": False,
        "supported_search_fields": [
            "ip", "domain", "host", "cert", "cert.subject", "cert.issuer",
            "jarm", "tls.ja3s", "body_hash", "header_hash", "icon_hash",
            "title", "server", "port", "banner", "asn",
        ],
        "rate_limit": {"requests_per_minute": 30, "min_interval_seconds": 1.0},
        "pagination": {"supported": True, "style": "page", "max_page_size": 100},
        "entitlement_notes": "Requires FOFA API key (email:key or token). Special fields like jarm/icon_hash may require FOFA membership tier.",
    },
    "crtsh": {
        "id": "crtsh",
        "label": "crt.sh (Certificate Transparency)",
        "key_field": "",
        "env_vars": [],
        "requires_api_key": False,
        "is_passive": True,
        "supported_seed_types": ["domain"],
        "supported_pivot_methods": ["tls_cert", "passive_dns", "reverse_ip"],
        "supports_hash_to_infra": False,
        "supported_search_fields": ["common_name", "name_value", "serial_number", "issuer_name"],
        "rate_limit": {"requests_per_minute": 15, "min_interval_seconds": 1.5},
        "pagination": {"supported": False, "style": "none", "max_page_size": 200},
        "entitlement_notes": "Free public Certificate Transparency JSON API. No API key required.",
    },
    "urlscan": {
        "id": "urlscan",
        "label": "urlscan.io",
        "key_field": "urlscan_key",
        "env_vars": ["URLSCAN_API_KEY", "MANTIS_URLSCAN_API_KEY"],
        "requires_api_key": False,
        "is_passive": True,
        "supported_seed_types": ["ip", "domain", "url", "hash", "fingerprint"],
        "supported_pivot_methods": [
            "passive_dns", "reverse_ip", "tls_cert", "http_body_headers",
            "url_resource_pattern", "html_js_similarity", "open_dirs", "asn_hosting",
        ],
        "supports_hash_to_infra": True,
        "supported_search_fields": [
            "page.domain", "page.ip", "page.asn", "files.sha256", "hash",
            "page.title", "page.server",
        ],
        "rate_limit": {"requests_per_minute": 30, "min_interval_seconds": 1.0},
        "pagination": {"supported": True, "style": "size", "max_page_size": 50},
        "entitlement_notes": "Public search works without an API key (rate-limited); API key enables higher quotas and private scan visibility.",
    },
    "silentpush": {
        "id": "silentpush",
        "label": "Silent Push",
        "key_field": "silentpush_key",
        "env_vars": ["SILENT_PUSH_API_KEY", "SILENTPUSH_API_KEY", "MANTIS_SILENTPUSH_API_KEY"],
        "requires_api_key": True,
        "is_passive": True,
        "supported_seed_types": ["ip", "domain", "certificate", "fingerprint"],
        "supported_pivot_methods": [
            "passive_dns", "reverse_ip", "tls_cert", "http_body_headers",
            "favicon_hash", "jarm_ja4", "ja3_ja4", "whois_registration",
            "url_resource_pattern", "html_js_similarity", "open_dirs", "asn_hosting",
        ],
        "supports_hash_to_infra": False,
        "supported_search_fields": [
            "ssl_sha256", "ssl_subject", "jarm", "body_sha256", "header_sha256",
            "favicon_murmur3", "favicon_md5", "htmltitle", "asn", "ip", "domain",
        ],
        "rate_limit": {"requests_per_minute": 30, "min_interval_seconds": 1.0},
        "pagination": {"supported": True, "style": "limit", "max_page_size": 100},
        "entitlement_notes": "Requires Silent Push API key for PADNS, domain enrichment, and SPQL webscan queries.",
    },
    "validin": {
        "id": "validin",
        "label": "Validin",
        "key_field": "validin_key",
        "env_vars": ["VALIDIN_API_KEY", "MANTIS_VALIDIN_API_KEY"],
        "requires_api_key": True,
        "is_passive": True,
        "supported_seed_types": ["ip", "domain", "certificate", "fingerprint"],
        "supported_pivot_methods": [
            "passive_dns", "reverse_ip", "tls_cert", "http_body_headers",
            "favicon_hash", "jarm_ja4", "whois_registration", "html_js_similarity",
        ],
        "supports_hash_to_infra": False,
        "supported_search_fields": [
            "dns_history", "certificates", "pivots", "jarm", "cert_hash",
            "header_hash", "fingerprint", "registration_history",
        ],
        "rate_limit": {"requests_per_minute": 30, "min_interval_seconds": 1.0},
        "pagination": {"supported": True, "style": "limit", "max_page_size": 100},
        "entitlement_notes": "Requires Validin API token for Axon passive DNS and host response fingerprint pivots.",
    },
    "netlas": {
        "id": "netlas",
        "label": "Netlas",
        "key_field": "netlas_key",
        "env_vars": ["NETLAS_API_KEY", "MANTIS_NETLAS_API_KEY"],
        "requires_api_key": True,
        "is_passive": True,
        "supported_seed_types": ["ip", "domain", "certificate", "fingerprint"],
        "supported_pivot_methods": [
            "passive_dns", "reverse_ip", "tls_cert", "http_body_headers",
            "favicon_hash", "jarm_ja4", "ja3_ja4", "ssh_host_key", "rdp_cert",
            "whois_registration", "open_ports", "html_js_similarity",
            "service_banners", "asn_hosting",
        ],
        "supports_hash_to_infra": False,
        "supported_search_fields": [
            "certificate.fingerprint_sha256", "certificate.subject_dn", "jarm",
            "ja3s", "http.favicon.hash_sha256", "http.body_sha256", "http.title",
            "ssh.fingerprint_sha256", "whois.asn.number", "ip", "host", "port",
        ],
        "rate_limit": {"requests_per_minute": 20, "min_interval_seconds": 1.2},
        "pagination": {"supported": True, "style": "offset", "max_page_size": 20},
        "entitlement_notes": "Requires Netlas API key.",
    },
    "etugen": {
        "id": "etugen",
        "label": "Etugen (OpenDirs)",
        "key_field": "etugen_key",
        "env_vars": ["ETUGEN_API_KEY", "MANTIS_ETUGEN_API_KEY"],
        "requires_api_key": True,
        "is_passive": True,
        "supported_seed_types": ["ip", "domain"],
        "supported_pivot_methods": ["open_dirs", "url_resource_pattern"],
        "supports_hash_to_infra": False,
        "supported_search_fields": ["trashpile", "title", "port", "files"],
        "rate_limit": {"requests_per_minute": 25, "min_interval_seconds": 1.0},
        "pagination": {"supported": False, "style": "none", "max_page_size": 50},
        "entitlement_notes": "Requires Etugen API key for exposed OpenDir (Trashpile) host file discovery.",
    },
    "ripe": {
        "id": "ripe",
        "label": "RIPEstat",
        "key_field": "",
        "env_vars": [],
        "requires_api_key": False,
        "is_passive": True,
        "supported_seed_types": ["ip", "asn"],
        "supported_pivot_methods": ["asn_hosting", "whois_registration"],
        "supports_hash_to_infra": False,
        "supported_search_fields": ["network-info", "as-overview", "announced-prefixes", "whois"],
        "rate_limit": {"requests_per_minute": 30, "min_interval_seconds": 0.5},
        "pagination": {"supported": False, "style": "none", "max_page_size": 50},
        "entitlement_notes": "Free public RIPEstat API for BGP prefix, ASN, and routing context.",
    },
    "greynoise": {
        "id": "greynoise",
        "label": "GreyNoise",
        "key_field": "greynoise_key",
        "env_vars": ["GREYNOISE_API_KEY", "MANTIS_GREYNOISE_API_KEY"],
        "requires_api_key": False,
        "is_passive": True,
        "supported_seed_types": ["ip"],
        "supported_pivot_methods": ["asn_hosting"],
        "supports_hash_to_infra": False,
        "supported_search_fields": ["ip", "noise", "riot", "classification"],
        "rate_limit": {"requests_per_minute": 30, "min_interval_seconds": 0.5},
        "pagination": {"supported": False, "style": "none", "max_page_size": 1},
        "entitlement_notes": "Community API works without a key for IP noise & RIOT benign service verification.",
    },
    "threatminer": {
        "id": "threatminer",
        "label": "ThreatMiner",
        "key_field": "",
        "env_vars": [],
        "requires_api_key": False,
        "is_passive": True,
        "supported_seed_types": ["ip", "domain", "hash"],
        "supported_pivot_methods": ["passive_dns", "reverse_ip", "tls_cert", "whois_registration", "url_resource_pattern"],
        "supports_hash_to_infra": True,
        "supported_search_fields": ["domain_pdns", "host_pdns", "host_certs", "sample_hosts"],
        "rate_limit": {"requests_per_minute": 10, "min_interval_seconds": 2.0},
        "pagination": {"supported": False, "style": "none", "max_page_size": 100},
        "entitlement_notes": "Free public ThreatMiner passive DNS, SSL, and sample-to-host correlation API.",
    },
    "urlhaus": {
        "id": "urlhaus",
        "label": "abuse.ch URLhaus",
        "key_field": "abusech_key",
        "env_vars": ["ABUSECH_API_KEY", "MANTIS_ABUSECH_KEY"],
        "requires_api_key": True,
        "is_passive": True,
        "supported_seed_types": ["url", "hash"],
        "supported_pivot_methods": ["url_resource_pattern"],
        "supports_hash_to_infra": True,
        "supported_search_fields": ["url", "sha256_hash", "md5_hash", "host"],
        "rate_limit": {"requests_per_minute": 30, "min_interval_seconds": 0.5},
        "pagination": {"supported": False, "style": "none", "max_page_size": 50},
        "entitlement_notes": "Requires abuse.ch Auth-Key for payload-to-URL and URL-to-payload correlation.",
    },
    "threatfox": {
        "id": "threatfox",
        "label": "abuse.ch ThreatFox",
        "key_field": "abusech_key",
        "env_vars": ["ABUSECH_API_KEY", "MANTIS_ABUSECH_KEY"],
        "requires_api_key": True,
        "is_passive": True,
        "supported_seed_types": ["ip", "domain", "url", "hash"],
        "supported_pivot_methods": ["url_resource_pattern"],
        "supports_hash_to_infra": True,
        "supported_search_fields": ["search_ioc", "search_hash"],
        "rate_limit": {"requests_per_minute": 30, "min_interval_seconds": 0.5},
        "pagination": {"supported": False, "style": "none", "max_page_size": 50},
        "entitlement_notes": "Requires abuse.ch Auth-Key for malware hash-to-C2 infrastructure correlation.",
    },
    "otx": {
        "id": "otx",
        "label": "AlienVault OTX",
        "key_field": "otx_key",
        "env_vars": ["OTX_API_KEY", "ALIENVAULT_API_KEY", "MANTIS_OTX_KEY"],
        "requires_api_key": False,
        "is_passive": True,
        "supported_seed_types": ["ip", "domain", "url", "hash"],
        "supported_pivot_methods": ["passive_dns", "reverse_ip", "url_resource_pattern"],
        "supports_hash_to_infra": True,
        "supported_search_fields": ["passive_dns", "url_list", "general"],
        "rate_limit": {"requests_per_minute": 30, "min_interval_seconds": 0.8},
        "pagination": {"supported": False, "style": "none", "max_page_size": 50},
        "entitlement_notes": "Public OTX endpoints work with optional OTX API key for higher limits.",
    },
}


# =============================================================================
# 3. DATABASE SCHEMA & CONNECTION MANAGEMENT
# =============================================================================

def _utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _loads(value: Any, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


@contextmanager
def _connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with _DB_LOCK, _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS pivot_investigations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                seed_value TEXT NOT NULL,
                seed_type TEXT NOT NULL,
                canonical_seed TEXT NOT NULL,
                mode TEXT NOT NULL DEFAULT 'quick',
                status TEXT NOT NULL DEFAULT 'queued',
                config_json TEXT NOT NULL DEFAULT '{}',
                progress_json TEXT NOT NULL DEFAULT '{}',
                frontier_json TEXT NOT NULL DEFAULT '[]',
                visited_json TEXT NOT NULL DEFAULT '[]',
                stats_json TEXT NOT NULL DEFAULT '{}',
                error TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                started_at TEXT NOT NULL DEFAULT '',
                finished_at TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS pivot_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                asset_type TEXT NOT NULL,
                value TEXT NOT NULL,
                canonical_value TEXT NOT NULL,
                depth INTEGER NOT NULL DEFAULT 0,
                relationship_confidence INTEGER NOT NULL DEFAULT 0,
                confidence_tier TEXT NOT NULL DEFAULT 'low',
                score_breakdown_json TEXT NOT NULL DEFAULT '{}',
                penalties_json TEXT NOT NULL DEFAULT '[]',
                shared_infra_flags_json TEXT NOT NULL DEFAULT '[]',
                maliciousness_context_json TEXT NOT NULL DEFAULT '{}',
                providers_json TEXT NOT NULL DEFAULT '[]',
                pivot_methods_json TEXT NOT NULL DEFAULT '[]',
                first_seen TEXT NOT NULL DEFAULT '',
                last_seen TEXT NOT NULL DEFAULT '',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                UNIQUE(investigation_id, asset_id),
                FOREIGN KEY(investigation_id) REFERENCES pivot_investigations(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS pivot_relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id TEXT NOT NULL,
                edge_id TEXT NOT NULL,
                source_asset_id TEXT NOT NULL,
                target_asset_id TEXT NOT NULL,
                relationship_type TEXT NOT NULL,
                pivot_method TEXT NOT NULL,
                confidence_score INTEGER NOT NULL DEFAULT 0,
                base_weight INTEGER NOT NULL DEFAULT 0,
                penalties_json TEXT NOT NULL DEFAULT '[]',
                providers_json TEXT NOT NULL DEFAULT '[]',
                explanation TEXT NOT NULL DEFAULT '',
                first_seen TEXT NOT NULL DEFAULT '',
                last_seen TEXT NOT NULL DEFAULT '',
                evidence_ids_json TEXT NOT NULL DEFAULT '[]',
                UNIQUE(investigation_id, edge_id),
                FOREIGN KEY(investigation_id) REFERENCES pivot_investigations(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS pivot_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id TEXT NOT NULL,
                observation_id TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                related_asset_id TEXT NOT NULL DEFAULT '',
                provider TEXT NOT NULL,
                pivot_method TEXT NOT NULL,
                observation_type TEXT NOT NULL,
                field_name TEXT NOT NULL DEFAULT '',
                field_value TEXT NOT NULL DEFAULT '',
                observed_at TEXT NOT NULL DEFAULT '',
                first_seen TEXT NOT NULL DEFAULT '',
                last_seen TEXT NOT NULL DEFAULT '',
                raw_ref_id TEXT NOT NULL DEFAULT '',
                summary TEXT NOT NULL DEFAULT '',
                UNIQUE(investigation_id, observation_id),
                FOREIGN KEY(investigation_id) REFERENCES pivot_investigations(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS pivot_raw_responses (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                pivot_method TEXT NOT NULL,
                query TEXT NOT NULL,
                status TEXT NOT NULL,
                fetched_at TEXT NOT NULL,
                response_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY(investigation_id) REFERENCES pivot_investigations(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS pivot_api_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                pivot_method TEXT NOT NULL,
                query TEXT NOT NULL,
                status TEXT NOT NULL,
                latency_ms INTEGER NOT NULL DEFAULT 0,
                result_count INTEGER NOT NULL DEFAULT 0,
                error_message TEXT NOT NULL DEFAULT '',
                raw_ref_id TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                FOREIGN KEY(investigation_id) REFERENCES pivot_investigations(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_pivot_assets_inv ON pivot_assets(investigation_id, relationship_confidence DESC);
            CREATE INDEX IF NOT EXISTS idx_pivot_rels_inv ON pivot_relationships(investigation_id, confidence_score DESC);
            CREATE INDEX IF NOT EXISTS idx_pivot_obs_inv ON pivot_observations(investigation_id, asset_id);
            CREATE INDEX IF NOT EXISTS idx_pivot_audit_inv ON pivot_api_audit(investigation_id, id ASC);
            """
        )


# =============================================================================
# 4. IOC & ASSET NORMALIZATION AND VALIDATION
# =============================================================================

_HEX32_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_HEX40_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_HEX62_RE = re.compile(r"^[a-fA-F0-9]{62}$")
_HEX64_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_JA4X_RE = re.compile(r"^[a-zA-Z0-9]{12}_[a-zA-Z0-9]{12}_[a-zA-Z0-9]{12}$")
_ASN_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.I)


def refang_text(raw: str) -> str:
    text = str(raw or "").strip()
    text = re.sub(r"\[\.\]|\(\.\)|\{\.\}", ".", text)
    text = re.sub(r"(?i)^hxxps://", "https://", text)
    text = re.sub(r"(?i)^hxxp://", "http://", text)
    text = re.sub(r"\[:\]", ":", text)
    return text.strip()


def normalize_seed_indicator(raw_input: str, explicit_type: str = "") -> Dict[str, Any]:
    """
    Normalizes and classifies an input indicator into:
    ip, domain, url, hash, certificate, jarm, ja4x, favicon, ssh_key, or asn.
    Also checks safety/pivot policy constraints.
    """
    cleaned = refang_text(raw_input)
    if not cleaned:
        raise ValueError("Indicator value cannot be empty.")

    hint = (explicit_type or "").strip().lower()

    # Check explicit prefix e.g. cert:..., jarm:..., favicon:..., ssh:..., asn:...
    if ":" in cleaned and not cleaned.lower().startswith(("http://", "https://")) and "::" not in cleaned:
        prefix, rest = cleaned.split(":", 1)
        p_low = prefix.strip().lower()
        r_clean = rest.strip()
        if p_low in {"cert", "certificate", "cert_sha256"} and _HEX64_RE.fullmatch(r_clean.replace(":", "")):
            val = r_clean.replace(":", "").lower()
            return {"type": "certificate", "value": val, "canonical": val, "asset_id": f"certificate:{val}"}
        if p_low == "jarm" and _HEX62_RE.fullmatch(r_clean):
            val = r_clean.lower()
            return {"type": "fingerprint", "subtype": "jarm", "value": val, "canonical": val, "asset_id": f"fingerprint:jarm:{val}"}
        if p_low == "ja4x" and _JA4X_RE.fullmatch(r_clean):
            val = r_clean.lower()
            return {"type": "fingerprint", "subtype": "ja4x", "value": val, "canonical": val, "asset_id": f"fingerprint:ja4x:{val}"}
        if p_low in {"favicon", "favicon_hash", "icon_hash"} and r_clean:
            return {"type": "fingerprint", "subtype": "favicon_hash", "value": r_clean, "canonical": r_clean, "asset_id": f"fingerprint:favicon_hash:{r_clean}"}
        if p_low in {"ssh", "ssh_key", "ssh_host_key"} and r_clean:
            return {"type": "fingerprint", "subtype": "ssh_host_key", "value": r_clean, "canonical": r_clean, "asset_id": f"fingerprint:ssh_host_key:{r_clean}"}
        if p_low in {"body_hash", "http_body_hash"} and r_clean:
            return {"type": "fingerprint", "subtype": "http_body_hash", "value": r_clean.lower(), "canonical": r_clean.lower(), "asset_id": f"fingerprint:http_body_hash:{r_clean.lower()}"}

    # Check URL first if scheme or slash path is present
    if hint == "url" or cleaned.lower().startswith(("http://", "https://")) or ("/" in cleaned and not _ASN_RE.fullmatch(cleaned)):
        norm_url = intel_query.normalize_url(cleaned)
        if intel_query.is_url(norm_url):
            parsed = urllib.parse.urlparse(norm_url)
            host = (parsed.hostname or "").lower().rstrip(".")
            return {
                "type": "url",
                "value": norm_url,
                "canonical": norm_url,
                "asset_id": f"url:{norm_url}",
                "extracted_host": host,
            }

    # Check IP (IPv4 / IPv6)
    norm_ip = intel_query.normalize_ip(cleaned)
    if hint == "ip" or intel_query.is_ip(norm_ip):
        try:
            ip_obj = ipaddress.ip_address(norm_ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
                raise ValueError(f"Non-routable or reserved IP address ({norm_ip}) cannot be pivoted across external threat intelligence.")
            canonical_ip = str(ip_obj)
            return {
                "type": "ip",
                "value": canonical_ip,
                "canonical": canonical_ip,
                "asset_id": f"ip:{canonical_ip}",
                "is_public_resolver": canonical_ip in PUBLIC_RESOLVERS,
            }
        except ValueError as e:
            if "Non-routable" in str(e):
                raise
            if hint == "ip":
                raise ValueError(f"Invalid IP address: {cleaned}")

    # Check JARM (62 hex chars)
    if (hint in {"jarm", "fingerprint"} or not hint) and _HEX62_RE.fullmatch(cleaned):
        val = cleaned.lower()
        return {"type": "fingerprint", "subtype": "jarm", "value": val, "canonical": val, "asset_id": f"fingerprint:jarm:{val}"}

    # Check JA4X
    if (hint in {"ja4x", "fingerprint"} or not hint) and _JA4X_RE.fullmatch(cleaned):
        val = cleaned.lower()
        return {"type": "fingerprint", "subtype": "ja4x", "value": val, "canonical": val, "asset_id": f"fingerprint:ja4x:{val}"}

    # Check File Hash (MD5=32, SHA1=40, SHA256=64) or Certificate SHA256 if hint=='certificate'
    if hint == "certificate" and _HEX64_RE.fullmatch(cleaned.replace(":", "")):
        val = cleaned.replace(":", "").lower()
        return {"type": "certificate", "value": val, "canonical": val, "asset_id": f"certificate:{val}"}

    if hint == "hash" or intel_query.is_hash(cleaned):
        val = cleaned.lower()
        if not (_HEX32_RE.fullmatch(val) or _HEX40_RE.fullmatch(val) or _HEX64_RE.fullmatch(val)):
            raise ValueError(f"Invalid file hash length or format: {cleaned}")
        hash_algo = "md5" if len(val) == 32 else ("sha1" if len(val) == 40 else "sha256")
        return {
            "type": "hash",
            "subtype": hash_algo,
            "value": val,
            "canonical": val,
            "asset_id": f"hash:{val}",
        }

    # Check Domain
    norm_dom = intel_query.normalize_domain(cleaned)
    if hint == "domain" or intel_query.is_domain(norm_dom):
        if not intel_query.is_domain(norm_dom):
            raise ValueError(f"Invalid domain format: {cleaned}")
        return {
            "type": "domain",
            "value": norm_dom,
            "canonical": norm_dom,
            "asset_id": f"domain:{norm_dom}",
        }

    # Check ASN
    m_asn = _ASN_RE.fullmatch(cleaned)
    if m_asn:
        asn_val = f"AS{m_asn.group(1)}"
        return {"type": "asn", "value": asn_val, "canonical": asn_val, "asset_id": f"asn:{asn_val}"}

    # Fallback: Free-text IOC extraction (e.g. pasted threat report sentence, log line, or email snippet)
    if not hint:
        extracted = threat_assessment.extract_iocs_from_text(raw_input)
        for cand in extracted.get("indicators", []):
            try:
                norm_res = normalize_seed_indicator(cand["value"], cand["type"])
                norm_res["extracted_from_text"] = True
                norm_res["all_extracted_iocs"] = extracted.get("indicators", [])
                return norm_res
            except ValueError:
                continue

    raise ValueError(f"Unable to classify indicator '{cleaned}' as a valid IP, domain, URL, file hash, certificate, or fingerprint.")


def is_filtered_benign_domain(domain: str) -> Tuple[bool, str]:
    """Checks if a domain is a CA/OCSP support host or a threat-intel sandbox/reporting domain."""
    dom = str(domain or "").strip().lower().rstrip(".")
    if not dom:
        return True, "Empty domain"
    for ca in CA_AND_CERT_DOMAINS:
        if dom == ca or dom.endswith(f".{ca}"):
            return True, f"Certificate Authority / OCSP infrastructure ({ca})"
    labels = dom.split(".")
    if labels and labels[0] in CERT_SUPPORT_HOST_TERMS:
        return True, f"Certificate revocation/validation endpoint ({dom})"
    for rep in REPORTING_AND_SANDBOX_DOMAINS:
        if dom == rep or dom.endswith(f".{rep}"):
            return True, f"Security sandbox / threat intel provider domain ({rep})"
    return False, ""


def detect_shared_infrastructure(value: str, metadata_text: str = "") -> List[str]:
    """Detects CDN, shared cloud hosting, domain parking, or public DNS resolver markers."""
    flags: List[str] = []
    val_low = str(value or "").strip().lower()
    blob_low = f"{val_low} {str(metadata_text or '').lower()}"

    if val_low in PUBLIC_RESOLVERS:
        flags.append("public_dns_resolver")

    for dom in SHARED_PLATFORM_DOMAINS:
        if val_low == dom or val_low.endswith(f".{dom}"):
            flags.append(f"shared_platform:{dom}")

    for marker in CDN_AND_SHARED_KEYWORDS:
        if marker in blob_low:
            tag = f"cdn_or_shared:{marker}"
            if tag not in flags:
                flags.append(tag)
            if len(flags) >= 5:
                break
    return flags


# =============================================================================
# 5. DETERMINISTIC RELATIONSHIP CONFIDENCE SCORING ENGINE
# =============================================================================

BASE_METHOD_WEIGHTS: Dict[str, int] = {
    "tls_cert_sha256": 44,
    "rdp_cert": 44,
    "ssh_host_key": 44,
    "ssh_hassh": 30,
    "malware_c2_contact": 42,
    "ja4x": 34,
    "ja3_ja4": 26,
    "http_body_hash": 32,
    "html_js_similarity": 32,
    "http_etag": 30,
    "open_dirs": 30,
    "passive_dns_a": 32,
    "redirect_chain": 32,
    "favicon_hash": 28,
    "whois_registrant": 28,
    "tls_cert_san": 28,
    "url_resource_pattern": 25,
    "service_banners": 24,
    "http_headers_hash": 22,
    "reverse_ip": 20,
    "tls_cert_subject": 18,
    "jarm": 16,
    "open_ports": 14,
    "http_title": 14,
    "whois_nameserver": 12,
    "whois_registrar": 6,
    "asn_hosting": 12,
}


def compute_relationship_confidence(
    depth: int,
    signals: List[Dict[str, Any]],
    providers: List[str],
    pivot_methods: List[str],
    shared_infra_flags: List[str],
    cohosted_domain_count: int = 0,
    last_seen_iso: str = "",
    greynoise_riot: bool = False,
) -> Dict[str, Any]:
    """
    Deterministically computes relationship confidence (0-100) separate from maliciousness.
    Penalizes common fingerprints, shared hosting, CDNs, high-density reverse IPs,
    GreyNoise RIOT public services, and stale observations.
    """
    if depth == 0:
        return {
            "score": 100,
            "tier": "seed",
            "base_score": 100,
            "corroboration_bonus": 0,
            "convergence_bonus": 0,
            "depth_multiplier": 1.0,
            "penalties": [],
            "total_penalty": 0,
            "explanation": "Investigation root seed indicator.",
        }

    # 1. Base score from distinct signal kinds (taking max weight per kind, diminishing returns on secondary kinds)
    by_kind: Dict[str, int] = {}
    penalties: List[Dict[str, Any]] = []

    for sig in signals:
        kind = str(sig.get("kind") or sig.get("pivot_method") or "passive_dns_a")
        val = str(sig.get("value") or "").strip().lower()
        weight = int(sig.get("weight") or BASE_METHOD_WEIGHTS.get(kind, 16))

        # Check common fingerprint penalties
        if kind in {"jarm", "jarm_ja4"} and val in COMMON_JARM_FINGERPRINTS:
            penalties.append({
                "type": "common_fingerprint",
                "reason": f"Ubiquitous/default JARM fingerprint ({val[:16]}...)",
                "deduction": 22,
            })
        elif kind == "http_title" and val in COMMON_HTTP_TITLES:
            penalties.append({
                "type": "common_fingerprint",
                "reason": f"Generic default HTTP title ('{val[:30]}')",
                "deduction": 20,
            })
        elif kind in {"tls_cert_issuer", "certificate_issuer"} and any(c in val for c in COMMON_CERT_ISSUERS):
            penalties.append({
                "type": "common_fingerprint",
                "reason": f"Commodity CA issuer ('{val[:30]}') is not exclusive",
                "deduction": 18,
            })

        by_kind[kind] = max(by_kind.get(kind, 0), weight)

    sorted_weights = sorted(by_kind.values(), reverse=True)
    if not sorted_weights:
        base_score = 15
    else:
        # Primary signal gives full weight, secondary signals give 65% of their weight
        base_score = sorted_weights[0] + int(sum(w * 0.65 for w in sorted_weights[1:]))

    # 2. Multi-provider corroboration bonus (+8 per extra provider, max +20)
    unique_providers = sorted(set(p for p in providers if p))
    corroboration_bonus = min(20, max(0, len(unique_providers) - 1) * 8)

    # 3. Multi-method convergence bonus (+12 if 2+ distinct pivot method categories match)
    unique_methods = sorted(set(m for m in pivot_methods if m))
    convergence_bonus = min(24, max(0, len(unique_methods) - 1) * 12)

    raw_positive = base_score + corroboration_bonus + convergence_bonus

    # 4. Hop depth decay (Depth 1 = 1.0, Depth 2 = 0.86, Depth 3 = 0.74, Depth 4+ = 0.64)
    depth_multiplier = 1.0 if depth <= 1 else (0.86 if depth == 2 else (0.74 if depth == 3 else 0.64))
    decayed_score = int(round(raw_positive * depth_multiplier))

    # 5. False-Positive Penalties
    if shared_infra_flags:
        is_only_weak_link = not any(k in by_kind for k in ("tls_cert_sha256", "ssh_host_key", "http_body_hash", "favicon_hash", "malware_c2_contact"))
        deduction = 35 if is_only_weak_link else 18
        penalties.append({
            "type": "shared_hosting_or_cdn",
            "reason": f"Shared infrastructure/CDN detected ({', '.join(shared_infra_flags[:3])})",
            "deduction": deduction,
        })

    if cohosted_domain_count > 35 and "reverse_ip" in unique_methods and len(unique_methods) == 1:
        penalties.append({
            "type": "high_density_shared_ip",
            "reason": f"IP co-hosts {cohosted_domain_count} domains without secondary fingerprint match",
            "deduction": 25,
        })

    if greynoise_riot:
        penalties.append({
            "type": "benign_public_service",
            "reason": "GreyNoise RIOT identifies IP as known benign public infrastructure",
            "deduction": 38,
        })

    # Stale observation check
    if last_seen_iso:
        try:
            dt_str = str(last_seen_iso).replace("Z", "+00:00")
            if "T" not in dt_str and len(dt_str) >= 10:
                dt_str = dt_str[:10] + "T00:00:00+00:00"
            obs_dt = datetime.fromisoformat(dt_str)
            if obs_dt.tzinfo is None:
                obs_dt = obs_dt.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - obs_dt).days
            if age_days > 365:
                penalties.append({
                    "type": "stale_observation",
                    "reason": f"Historical observation is {age_days} days old (>1 year)",
                    "deduction": 22,
                })
            elif age_days > 180:
                penalties.append({
                    "type": "stale_observation",
                    "reason": f"Historical observation is {age_days} days old (>6 months)",
                    "deduction": 12,
                })
        except Exception:
            pass

    # Deduplicate penalties by type
    deduped_penalties: List[Dict[str, Any]] = []
    seen_pen_types: Set[str] = set()
    for p in penalties:
        pt = p["type"]
        if pt not in seen_pen_types:
            seen_pen_types.add(pt)
            deduped_penalties.append(p)

    total_penalty = sum(int(p["deduction"]) for p in deduped_penalties)
    final_score = max(5, min(99, decayed_score - total_penalty))

    if final_score >= 70:
        tier = "high"
    elif final_score >= 45:
        tier = "medium"
    elif final_score >= 22:
        tier = "low"
    else:
        tier = "noise"

    explanation_parts = [
        f"Base={base_score} ({', '.join(by_kind.keys())})",
    ]
    if corroboration_bonus:
        explanation_parts.append(f"+{corroboration_bonus} multi-provider ({len(unique_providers)})")
    if convergence_bonus:
        explanation_parts.append(f"+{convergence_bonus} method convergence ({len(unique_methods)})")
    if depth > 1:
        explanation_parts.append(f"x{depth_multiplier} depth-{depth} decay")
    if total_penalty:
        explanation_parts.append(f"-{total_penalty} penalties ({', '.join(p['type'] for p in deduped_penalties)})")

    return {
        "score": final_score,
        "tier": tier,
        "base_score": base_score,
        "corroboration_bonus": corroboration_bonus,
        "convergence_bonus": convergence_bonus,
        "depth_multiplier": depth_multiplier,
        "penalties": deduped_penalties,
        "total_penalty": total_penalty,
        "explanation": " | ".join(explanation_parts),
    }


# =============================================================================
# 6. PROVIDER EXECUTION ADAPTERS, RATE LIMITER & ENTITLEMENT VERIFIER
# =============================================================================

class ProviderRateLimiter:
    """Thread-safe per-provider rate limiter and retry/backoff controller."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last_call: Dict[str, float] = {}

    def wait_for_slot(self, provider: str, cancel_event: Optional[threading.Event] = None) -> None:
        spec = PROVIDER_CAPABILITY_REGISTRY.get(provider, {})
        min_interval = float((spec.get("rate_limit") or {}).get("min_interval_seconds", 0.5))
        with self._lock:
            now = time.monotonic()
            last = self._last_call.get(provider, 0.0)
            wait_sec = max(0.0, (last + min_interval) - now)
            self._last_call[provider] = now + wait_sec
        if wait_sec > 0:
            if cancel_event and cancel_event.wait(timeout=wait_sec):
                raise InterruptedError("Investigation cancelled during rate-limit wait.")
            elif not cancel_event:
                time.sleep(wait_sec)


_RATE_LIMITER = ProviderRateLimiter()


def classify_provider_error(raw_response: Any) -> Tuple[str, str]:
    """
    Inspects a provider adapter dictionary for error/entitlement/rate-limit signals.
    Returns (status_code_label, human_error_message).
    """
    if not isinstance(raw_response, dict):
        return "ok", ""
    err = str(raw_response.get("error") or raw_response.get("note") or "").strip()
    if not err:
        return "ok", ""
    low = err.lower()
    if "not found" in low or "404" in low or "no record" in low:
        return "empty", ""
    if "429" in low or "quota" in low or "rate limit" in low or "too many requests" in low:
        return "rate_limited", err
    if "401" in low or "403" in low or "membership" in low or "access denied" in low or "forbidden" in low or "unauthorized" in low or "paid" in low or "invalid api key" in low or "permission" in low:
        return "insufficient_entitlement", err
    if "no api key" in low or "api key provided" in low:
        return "missing_key", err
    return "error", err


def get_provider_capabilities_status(user_keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Returns full provider capability registry enriched with active key readiness."""
    merged_keys = {**environment_keys(), **(user_keys or {})}
    # Also check additional env vars for VT, abuse.ch, OTX
    for prov_id, spec in PROVIDER_CAPABILITY_REGISTRY.items():
        kf = spec.get("key_field")
        if kf and not merged_keys.get(kf):
            for env_name in spec.get("env_vars", []):
                val = os.getenv(env_name, "").strip()
                if val:
                    merged_keys[kf] = val
                    break

    providers_list = []
    for prov_id, spec in PROVIDER_CAPABILITY_REGISTRY.items():
        kf = spec.get("key_field")
        has_key = bool(merged_keys.get(kf)) if kf else True
        ready = has_key or not spec.get("requires_api_key", False)
        providers_list.append({
            **spec,
            "has_key": has_key,
            "ready": ready,
            "status_label": "Ready" if has_key else ("Public / Key Optional" if not spec["requires_api_key"] else "API Key Required"),
        })

    return {
        "providers": providers_list,
        "pivot_methods": list(PIVOT_METHODS.values()),
        "presets": PIVOT_PRESETS,
    }


# =============================================================================
# 7. PIVOT EXTRACTION & EXECUTION ENGINE
# =============================================================================

class PivotExecutionContext:
    """Holds in-memory and DB-synchronized state for an active or resumed investigation."""

    def __init__(
        self,
        investigation_id: str,
        seed_info: Dict[str, Any],
        config: Dict[str, Any],
        keys: Dict[str, str],
        cancel_event: threading.Event,
    ) -> None:
        self.investigation_id = investigation_id
        self.seed_info = seed_info
        self.config = config
        self.keys = {**environment_keys(), **(keys or {})}
        for spec in PROVIDER_CAPABILITY_REGISTRY.values():
            kf = spec.get("key_field")
            if kf and not self.keys.get(kf):
                for env_name in spec.get("env_vars", []):
                    val = os.getenv(env_name, "").strip()
                    if val:
                        self.keys[kf] = val
                        break
        self.cancel_event = cancel_event

        self.max_depth = int(config.get("max_depth", 1))
        self.max_assets = int(config.get("max_assets", 50))
        self.per_pivot_limit = int(config.get("per_pivot_limit", 20))
        self.timeout_seconds = int(config.get("timeout_seconds", 60))
        self.api_budget = int(config.get("api_budget", 25))
        self.min_confidence_to_expand = int(config.get("min_confidence_to_expand", 40))
        self.passive_only = bool(config.get("passive_only", True))
        raw_methods = config.get("enabled_methods") or list(PIVOT_METHODS.keys())
        norm_methods: Set[str] = set()
        for m in raw_methods:
            norm_methods.add(m)
            if m in METHOD_ALIASES:
                norm_methods.add(METHOD_ALIASES[m])
        if "url_resource_pattern" in norm_methods:
            norm_methods.add("redirect_chain")
        self.enabled_methods: Set[str] = norm_methods
        self.selected_providers: Set[str] = set(config.get("providers") or PROVIDER_CAPABILITY_REGISTRY.keys())

        self.start_monotonic = time.monotonic()
        self.elapsed_prior = float(config.get("_elapsed_prior", 0.0))
        self.api_calls_made = 0
        self.provider_stats: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"calls": 0, "success": 0, "empty": 0, "rate_limited": 0, "entitlement_errors": 0, "errors": 0, "last_error": ""}
        )

        # Graph state
        self.assets: Dict[str, Dict[str, Any]] = {}
        self.relationships: Dict[str, Dict[str, Any]] = {}
        self.observations: Dict[str, Dict[str, Any]] = {}
        self.visited_assets: Set[str] = set()
        self.executed_queries: Set[str] = set()
        # Frontier items: list of dicts {"asset_id": str, "depth": int, "priority": int}
        self.frontier: List[Dict[str, Any]] = []

    def check_limits(self) -> Optional[str]:
        if self.cancel_event.is_set():
            return "cancelled"
        elapsed = self.elapsed_prior + (time.monotonic() - self.start_monotonic)
        if elapsed >= self.timeout_seconds:
            return "timeout_reached"
        if self.api_calls_made >= self.api_budget:
            return "api_budget_reached"
        if len(self.assets) >= self.max_assets:
            return "max_assets_reached"
        return None

    def can_use_provider(self, provider: str, method: str) -> bool:
        if provider not in self.selected_providers:
            return False
        spec = PROVIDER_CAPABILITY_REGISTRY.get(provider)
        if not spec:
            return False
        if self.passive_only and not spec.get("is_passive", True):
            return False
        if method != "malware_to_infra" and method not in spec.get("supported_pivot_methods", []):
            return False
        if method == "malware_to_infra" and not spec.get("supports_hash_to_infra", False):
            return False
        kf = spec.get("key_field")
        if spec.get("requires_api_key") and kf and not self.keys.get(kf):
            return False
        # Skip provider if it already hit an entitlement error or repeated rate limits
        pstat = self.provider_stats[provider]
        if pstat["entitlement_errors"] > 0 or pstat["rate_limited"] >= 2:
            return False
        return True

    def execute_provider_call(
        self,
        provider: str,
        pivot_method: str,
        query_desc: str,
        fn: Callable[[], Any],
        max_retries: int = 2,
    ) -> Tuple[str, Any, str]:
        """
        Executes a real provider call with deduplication, budget checking,
        rate limiting, retry/backoff on transient 429/network error, raw response
        persistence, and API audit logging.
        """
        q_key = f"{provider}::{pivot_method}::{query_desc}"
        if q_key in self.executed_queries:
            return "skipped_duplicate", {}, ""

        limit_reason = self.check_limits()
        if limit_reason:
            return limit_reason, {}, ""

        self.executed_queries.add(q_key)
        attempt = 0
        last_status = "error"
        last_err = ""
        raw_res: Any = {}
        t0 = time.monotonic()

        while attempt <= max_retries:
            if self.cancel_event.is_set():
                return "cancelled", {}, ""
            try:
                _RATE_LIMITER.wait_for_slot(provider, self.cancel_event)
            except InterruptedError:
                return "cancelled", {}, ""

            t0 = time.monotonic()
            try:
                self.api_calls_made += 1
                self.provider_stats[provider]["calls"] += 1
                raw_res = fn()
                last_status, last_err = classify_provider_error(raw_res)
            except Exception as exc:
                raw_res = {"error": str(exc)}
                last_status = "error"
                last_err = str(exc)[:300]

            if last_status == "rate_limited" and attempt < max_retries:
                attempt += 1
                backoff = min(4.0, 0.8 * (2 ** attempt))
                if self.cancel_event.wait(timeout=backoff):
                    return "cancelled", {}, ""
                continue
            break

        latency_ms = int((time.monotonic() - t0) * 1000)
        pstat = self.provider_stats[provider]
        if last_status == "ok":
            pstat["success"] += 1
        elif last_status == "empty":
            pstat["empty"] += 1
        elif last_status == "rate_limited":
            pstat["rate_limited"] += 1
            pstat["last_error"] = last_err
        elif last_status == "insufficient_entitlement":
            pstat["entitlement_errors"] += 1
            pstat["last_error"] = last_err
        else:
            pstat["errors"] += 1
            pstat["last_error"] = last_err

        raw_ref_id = f"raw_{uuid.uuid4().hex[:12]}"
        now = _utcnow()
        # Truncate huge raw JSON slightly for storage safety while preserving full structure
        raw_str = _json(raw_res)
        if len(raw_str) > 150000:
            raw_str = _json({"_truncated": True, "preview": raw_str[:140000]})

        with _DB_LOCK, _connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO pivot_raw_responses
                   (id, investigation_id, provider, pivot_method, query, status, fetched_at, response_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (raw_ref_id, self.investigation_id, provider, pivot_method, query_desc[:500], last_status, now, raw_str),
            )
            conn.execute(
                """INSERT INTO pivot_api_audit
                   (investigation_id, provider, pivot_method, query, status, latency_ms, result_count, error_message, raw_ref_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (self.investigation_id, provider, pivot_method, query_desc[:500], last_status, latency_ms, 1 if last_status == "ok" else 0, last_err[:500], raw_ref_id, now),
            )

        return last_status, raw_res, raw_ref_id

    def upsert_asset(
        self,
        asset_type: str,
        value: str,
        depth: int,
        provider: str,
        pivot_method: str,
        signal: Optional[Dict[str, Any]] = None,
        first_seen: str = "",
        last_seen: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        maliciousness_info: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Normalizes, deduplicates, and adds/merges an asset into the evidence graph.
        Returns canonical asset_id or None if rejected by policy or max_assets limit.
        """
        raw_val = str(value or "").strip()
        if not raw_val:
            return None

        # Normalize asset identity
        canonical = raw_val
        subtype = ""
        if asset_type == "ip":
            norm_ip = intel_query.normalize_ip(raw_val)
            if not intel_query.is_ip(norm_ip):
                return None
            try:
                ip_obj = ipaddress.ip_address(norm_ip)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
                    return None
                canonical = str(ip_obj)
            except ValueError:
                return None
            asset_id = f"ip:{canonical}"
        elif asset_type == "domain":
            norm_dom = intel_query.normalize_domain(raw_val.lstrip("*."))
            if not intel_query.is_domain(norm_dom):
                return None
            filtered, _ = is_filtered_benign_domain(norm_dom)
            if filtered and depth > 0:
                return None
            canonical = norm_dom
            asset_id = f"domain:{canonical}"
        elif asset_type == "url":
            norm_url = intel_query.normalize_url(raw_val)
            if not intel_query.is_url(norm_url):
                return None
            parsed = urllib.parse.urlparse(norm_url)
            host = (parsed.hostname or "").lower().rstrip(".")
            if host:
                filtered, _ = is_filtered_benign_domain(host)
                if filtered and depth > 0:
                    return None
            if CERT_SUPPORT_PATH_RE.search(parsed.path or "") and depth > 0:
                return None
            canonical = norm_url
            asset_id = f"url:{canonical}"
        elif asset_type == "certificate":
            clean_fp = raw_val.replace(":", "").strip().lower()
            if not (_HEX64_RE.fullmatch(clean_fp) or _HEX40_RE.fullmatch(clean_fp) or len(clean_fp) >= 16):
                return None
            canonical = clean_fp
            asset_id = f"certificate:{canonical}"
        elif asset_type == "hash":
            clean_h = raw_val.strip().lower()
            if not (_HEX32_RE.fullmatch(clean_h) or _HEX40_RE.fullmatch(clean_h) or _HEX64_RE.fullmatch(clean_h)):
                return None
            canonical = clean_h
            asset_id = f"hash:{canonical}"
        elif asset_type == "fingerprint":
            subtype = str((metadata or {}).get("subtype") or (signal or {}).get("kind") or "fingerprint").lower()
            canonical = raw_val.strip()
            if subtype in {"jarm", "ja4x", "http_body_hash", "http_headers_hash", "ssh_host_key"}:
                canonical = canonical.lower()
            asset_id = f"fingerprint:{subtype}:{canonical}"
        elif asset_type == "asn":
            m_asn = _ASN_RE.fullmatch(raw_val)
            canonical = f"AS{m_asn.group(1)}" if m_asn else raw_val.upper()
            asset_id = f"asn:{canonical}"
        elif asset_type == "whois":
            subtype = str((metadata or {}).get("subtype") or "registrant").lower()
            canonical = raw_val.strip().lower()
            if len(canonical) < 3 or "redacted" in canonical or "privacy" in canonical or "data protected" in canonical or "whoisguard" in canonical or "domains by proxy" in canonical or "contact privacy" in canonical:
                return None
            asset_id = f"whois:{subtype}:{canonical}"
        else:
            canonical = raw_val.strip()
            asset_id = f"{asset_type}:{canonical}"

        # Enforce global max_assets limit for new assets
        if asset_id not in self.assets and len(self.assets) >= self.max_assets:
            return None

        existing = self.assets.get(asset_id)
        meta_blob = _json(metadata or {})
        shared_flags = detect_shared_infrastructure(canonical, meta_blob)

        if not existing:
            existing = {
                "asset_id": asset_id,
                "asset_type": asset_type,
                "value": canonical,
                "canonical_value": canonical,
                "depth": depth,
                "signals": [],
                "providers": [],
                "pivot_methods": [],
                "shared_infra_flags": shared_flags,
                "maliciousness_context": maliciousness_info or {},
                "first_seen": first_seen or "",
                "last_seen": last_seen or "",
                "metadata": metadata or {},
                "relationship_confidence": 100 if depth == 0 else 0,
                "confidence_tier": "seed" if depth == 0 else "low",
                "score_breakdown": {},
                "penalties": [],
            }
            self.assets[asset_id] = existing
        else:
            existing["depth"] = min(existing["depth"], depth)
            for fl in shared_flags:
                if fl not in existing["shared_infra_flags"]:
                    existing["shared_infra_flags"].append(fl)
            if first_seen and (not existing["first_seen"] or first_seen < existing["first_seen"]):
                existing["first_seen"] = first_seen
            if last_seen and (not existing["last_seen"] or last_seen > existing["last_seen"]):
                existing["last_seen"] = last_seen
            if metadata:
                existing["metadata"].update({k: v for k, v in metadata.items() if v not in (None, "", [])})
            if maliciousness_info:
                existing["maliciousness_context"].update(maliciousness_info)

        if provider and provider not in existing["providers"]:
            existing["providers"].append(provider)
        if pivot_method and pivot_method not in existing["pivot_methods"]:
            existing["pivot_methods"].append(pivot_method)
        if signal:
            sig_entry = {
                "kind": signal.get("kind", pivot_method),
                "value": str(signal.get("value", canonical)),
                "weight": int(signal.get("weight") or BASE_METHOD_WEIGHTS.get(signal.get("kind", pivot_method), 18)),
                "provider": provider,
            }
            if not any(s["kind"] == sig_entry["kind"] and s["value"] == sig_entry["value"] and s["provider"] == provider for s in existing["signals"]):
                existing["signals"].append(sig_entry)

        # Recompute deterministic relationship confidence
        gn_riot = bool(existing["metadata"].get("greynoise_riot", False))
        cohosted_count = int(existing["metadata"].get("cohosted_domain_count", 0))
        scoring = compute_relationship_confidence(
            depth=existing["depth"],
            signals=existing["signals"],
            providers=existing["providers"],
            pivot_methods=existing["pivot_methods"],
            shared_infra_flags=existing["shared_infra_flags"],
            cohosted_domain_count=cohosted_count,
            last_seen_iso=existing["last_seen"],
            greynoise_riot=gn_riot,
        )
        existing["relationship_confidence"] = scoring["score"]
        existing["confidence_tier"] = scoring["tier"]
        existing["score_breakdown"] = scoring
        existing["penalties"] = scoring["penalties"]

        # Queue into frontier if eligible for next hop expansion
        if (
            existing["depth"] < self.max_depth
            and asset_id not in self.visited_assets
            and existing["relationship_confidence"] >= self.min_confidence_to_expand
            and asset_type in {"ip", "domain", "url", "certificate", "fingerprint", "hash"}
        ):
            if not any(f["asset_id"] == asset_id for f in self.frontier):
                self.frontier.append({
                    "asset_id": asset_id,
                    "depth": existing["depth"],
                    "priority": existing["relationship_confidence"],
                })

        return asset_id

    def add_relationship_and_observation(
        self,
        source_asset_id: str,
        target_asset_id: str,
        relationship_type: str,
        pivot_method: str,
        provider: str,
        signal_kind: str,
        signal_value: str,
        explanation: str,
        raw_ref_id: str = "",
        first_seen: str = "",
        last_seen: str = "",
    ) -> None:
        if not source_asset_id or not target_asset_id or source_asset_id == target_asset_id:
            return
        if source_asset_id not in self.assets or target_asset_id not in self.assets:
            return

        # Prevent trivial reverse duplicate edges on symmetric relationships
        edge_key = f"{source_asset_id}--{relationship_type}-->{target_asset_id}"
        edge_id = "edge_" + hashlib.sha1(edge_key.encode("utf-8")).hexdigest()[:16]

        obs_key = f"{provider}:{pivot_method}:{source_asset_id}:{target_asset_id}:{signal_kind}:{signal_value}"
        obs_id = "obs_" + hashlib.sha1(obs_key.encode("utf-8")).hexdigest()[:16]
        now = _utcnow()

        if obs_id not in self.observations:
            self.observations[obs_id] = {
                "observation_id": obs_id,
                "asset_id": target_asset_id,
                "related_asset_id": source_asset_id,
                "provider": provider,
                "pivot_method": pivot_method,
                "observation_type": relationship_type,
                "field_name": signal_kind,
                "field_value": str(signal_value)[:500],
                "observed_at": now,
                "first_seen": first_seen or "",
                "last_seen": last_seen or "",
                "raw_ref_id": raw_ref_id,
                "summary": explanation,
            }

        target_asset = self.assets[target_asset_id]
        base_weight = BASE_METHOD_WEIGHTS.get(signal_kind, 18)

        if edge_id not in self.relationships:
            self.relationships[edge_id] = {
                "edge_id": edge_id,
                "source_asset_id": source_asset_id,
                "target_asset_id": target_asset_id,
                "relationship_type": relationship_type,
                "pivot_method": pivot_method,
                "confidence_score": target_asset["relationship_confidence"],
                "base_weight": base_weight,
                "penalties": target_asset["penalties"],
                "providers": [provider] if provider else [],
                "explanation": explanation,
                "first_seen": first_seen or "",
                "last_seen": last_seen or "",
                "evidence_ids": [obs_id],
            }
        else:
            rel = self.relationships[edge_id]
            if provider and provider not in rel["providers"]:
                rel["providers"].append(provider)
            if obs_id not in rel["evidence_ids"]:
                rel["evidence_ids"].append(obs_id)
            rel["confidence_score"] = max(rel["confidence_score"], target_asset["relationship_confidence"])
            rel["penalties"] = target_asset["penalties"]
            if first_seen and (not rel["first_seen"] or first_seen < rel["first_seen"]):
                rel["first_seen"] = first_seen
            if last_seen and (not rel["last_seen"] or last_seen > rel["last_seen"]):
                rel["last_seen"] = last_seen


# =============================================================================
# 8. PIVOT HANDLERS BY ASSET TYPE AND METHOD
# =============================================================================

def _pivot_from_hash(ctx: PivotExecutionContext, asset: Dict[str, Any]) -> None:
    """
    Hash-based pivots: Queries malware-to-infrastructure relationships
    (VirusTotal, ThreatFox, URLhaus, AlienVault OTX, ThreatMiner, urlscan.io)
    to discover C2 IPs, domains, and payload URLs.
    """
    file_hash = asset["canonical_value"]
    src_id = asset["asset_id"]
    next_depth = asset["depth"] + 1
    limit = ctx.per_pivot_limit

    # 1. VirusTotal file metadata & network relationships
    if ctx.can_use_provider("virustotal", "malware_to_infra"):
        status, vt_data, raw_ref = ctx.execute_provider_call(
            "virustotal", "malware_to_infra", f"vt:file:{file_hash}",
            lambda: intel_query.query_vt(file_hash, "hash", ctx.keys.get("vt_key", "")),
        )
        if status == "ok" and isinstance(vt_data, dict):
            attrs = ((vt_data.get("data") or {}).get("attributes") or {}) if isinstance(vt_data.get("data"), dict) else {}
            stats = attrs.get("last_analysis_stats") or {}
            if stats:
                mal = int(stats.get("malicious") or 0) + int(stats.get("suspicious") or 0)
                tot = sum(int(v or 0) for v in stats.values())
                asset["maliciousness_context"]["vt_detections"] = f"{mal}/{tot}"
            threat_cls = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
            if threat_cls:
                asset["maliciousness_context"]["threat_label"] = threat_cls

        for rel_name, target_type, rel_label in (
            ("contacted_ips", "ip", "contacted_c2_ip"),
            ("contacted_domains", "domain", "contacted_c2_domain"),
            ("contacted_urls", "url", "contacted_c2_url"),
            ("itw_urls", "url", "downloaded_from_url"),
        ):
            if ctx.check_limits():
                break
            st_rel, rel_res, ref_rel = ctx.execute_provider_call(
                "virustotal", "malware_to_infra", f"vt:file:{file_hash}:{rel_name}",
                lambda rn=rel_name: intel_query.query_vt_relation(file_hash, "hash", rn, ctx.keys.get("vt_key", ""), limit=min(limit, 30)),
            )
            if st_rel == "ok" and isinstance(rel_res, dict):
                items = rel_res.get("data") if isinstance(rel_res.get("data"), list) else []
                for item in items[:limit]:
                    if not isinstance(item, dict):
                        continue
                    val = str(item.get("id") or (item.get("attributes") or {}).get("url") or "").strip()
                    if not val:
                        continue
                    tid = ctx.upsert_asset(
                        target_type, val, next_depth, "virustotal", "url_resource_pattern",
                        signal={"kind": "malware_c2_contact", "value": file_hash, "weight": 42},
                    )
                    if tid:
                        ctx.add_relationship_and_observation(
                            src_id, tid, rel_label, "url_resource_pattern", "virustotal",
                            "malware_c2_contact", val,
                            f"VirusTotal reports sample {file_hash[:12]}... {rel_name.replace('_', ' ')} {val}",
                            raw_ref_id=ref_rel,
                        )

    # 2. ThreatFox hash lookup
    if ctx.can_use_provider("threatfox", "malware_to_infra") and not ctx.check_limits():
        st, tf_data, raw_ref = ctx.execute_provider_call(
            "threatfox", "malware_to_infra", f"threatfox:hash:{file_hash}",
            lambda: intel_query.query_threatfox(file_hash, ctx.keys.get("abusech_key", "")),
        )
        if st == "ok" and isinstance(tf_data, dict):
            rows = tf_data.get("data") if isinstance(tf_data.get("data"), list) else []
            for row in rows[:limit]:
                if not isinstance(row, dict):
                    continue
                ioc_val = str(row.get("ioc") or row.get("ioc_value") or "").strip()
                ioc_type_raw = str(row.get("ioc_type") or "").lower()
                malware_fam = str(row.get("malware_printable") or row.get("malware") or "")
                if malware_fam:
                    asset["maliciousness_context"]["threatfox_family"] = malware_fam
                if not ioc_val:
                    continue
                if "ip" in ioc_type_raw:
                    ioc_val = ioc_val.split(":")[0]
                    t_type = "ip"
                elif "domain" in ioc_type_raw:
                    t_type = "domain"
                elif "url" in ioc_type_raw:
                    t_type = "url"
                else:
                    continue
                tid = ctx.upsert_asset(
                    t_type, ioc_val, next_depth, "threatfox", "url_resource_pattern",
                    signal={"kind": "malware_c2_contact", "value": file_hash, "weight": 42},
                    first_seen=str(row.get("first_seen") or ""),
                    last_seen=str(row.get("last_seen") or ""),
                    maliciousness_info={"malware_family": malware_fam} if malware_fam else None,
                )
                if tid:
                    ctx.add_relationship_and_observation(
                        src_id, tid, "associated_c2_ioc", "url_resource_pattern", "threatfox",
                        "malware_c2_contact", ioc_val,
                        f"ThreatFox links sample {file_hash[:12]}... to {t_type.upper()} {ioc_val} ({malware_fam or 'C2'})",
                        raw_ref_id=raw_ref,
                        first_seen=str(row.get("first_seen") or ""),
                        last_seen=str(row.get("last_seen") or ""),
                    )

    # 3. URLhaus payload lookup
    if ctx.can_use_provider("urlhaus", "malware_to_infra") and not ctx.check_limits():
        st, uh_data, raw_ref = ctx.execute_provider_call(
            "urlhaus", "malware_to_infra", f"urlhaus:payload:{file_hash}",
            lambda: intel_query.query_urlhaus_payload(file_hash, ctx.keys.get("abusech_key", "")),
        )
        if st == "ok" and isinstance(uh_data, dict):
            urls = uh_data.get("urls") if isinstance(uh_data.get("urls"), list) else []
            for u_item in urls[:limit]:
                if not isinstance(u_item, dict):
                    continue
                u_val = str(u_item.get("url") or "").strip()
                if not u_val:
                    continue
                tid = ctx.upsert_asset(
                    "url", u_val, next_depth, "urlhaus", "url_resource_pattern",
                    signal={"kind": "malware_c2_contact", "value": file_hash, "weight": 42},
                    first_seen=str(u_item.get("dateadded") or ""),
                )
                if tid:
                    ctx.add_relationship_and_observation(
                        src_id, tid, "payload_hosted_at", "url_resource_pattern", "urlhaus",
                        "malware_c2_contact", u_val,
                        f"URLhaus observed payload {file_hash[:12]}... distributed from {u_val}",
                        raw_ref_id=raw_ref,
                        first_seen=str(u_item.get("dateadded") or ""),
                    )

    # 4. ThreatMiner sample lookup (free public API)
    if ctx.can_use_provider("threatminer", "malware_to_infra") and not ctx.check_limits():
        st, tm_data, raw_ref = ctx.execute_provider_call(
            "threatminer", "malware_to_infra", f"threatminer:sample:{file_hash}",
            lambda: intel_query.query_threatminer_sample(file_hash),
        )
        if st == "ok" and isinstance(tm_data, dict):
            for dom in (tm_data.get("domains") or [])[:limit]:
                d_val = str(dom.get("domain") if isinstance(dom, dict) else dom).strip()
                if d_val:
                    tid = ctx.upsert_asset(
                        "domain", d_val, next_depth, "threatminer", "passive_dns",
                        signal={"kind": "malware_c2_contact", "value": file_hash, "weight": 38},
                    )
                    if tid:
                        ctx.add_relationship_and_observation(
                            src_id, tid, "contacted_c2_domain", "passive_dns", "threatminer",
                            "malware_c2_contact", d_val,
                            f"ThreatMiner associates sample {file_hash[:12]}... with domain {d_val}",
                            raw_ref_id=raw_ref,
                        )
            for host_ip in (tm_data.get("hosts") or tm_data.get("ips") or [])[:limit]:
                ip_val = str(host_ip.get("ip") if isinstance(host_ip, dict) else host_ip).strip()
                if ip_val:
                    tid = ctx.upsert_asset(
                        "ip", ip_val, next_depth, "threatminer", "reverse_ip",
                        signal={"kind": "malware_c2_contact", "value": file_hash, "weight": 38},
                    )
                    if tid:
                        ctx.add_relationship_and_observation(
                            src_id, tid, "contacted_c2_ip", "reverse_ip", "threatminer",
                            "malware_c2_contact", ip_val,
                            f"ThreatMiner associates sample {file_hash[:12]}... with IP {ip_val}",
                            raw_ref_id=raw_ref,
                        )

    # 5. urlscan.io file hash search (finds web pages serving this file SHA256)
    if len(file_hash) == 64 and ctx.can_use_provider("urlscan", "malware_to_infra") and not ctx.check_limits():
        st, us_data, raw_ref = ctx.execute_provider_call(
            "urlscan", "malware_to_infra", f"urlscan:hash:{file_hash}",
            lambda: intel_query.query_urlscan_hash(file_hash, ctx.keys.get("urlscan_key", ""), size=min(limit, 20)),
        )
        if st == "ok" and isinstance(us_data, dict):
            results = ((us_data.get("normalized") or {}).get("results") or us_data.get("results") or [])
            for item in results[:limit]:
                if not isinstance(item, dict):
                    continue
                page = item.get("page") if isinstance(item.get("page"), dict) else item
                p_url = str(page.get("url") or "").strip()
                p_dom = str(page.get("domain") or "").strip()
                p_ip = str(page.get("ip") or "").strip()
                seen_dt = str(item.get("indexed_at") or (item.get("task") or {}).get("time") or "")
                if p_url:
                    tid = ctx.upsert_asset(
                        "url", p_url, next_depth, "urlscan", "url_resource_pattern",
                        signal={"kind": "http_body_hash", "value": file_hash, "weight": 36},
                        last_seen=seen_dt,
                    )
                    if tid:
                        ctx.add_relationship_and_observation(
                            src_id, tid, "serves_file_hash", "url_resource_pattern", "urlscan",
                            "http_body_hash", file_hash,
                            f"urlscan.io recorded URL {p_url} serving resource SHA-256 {file_hash[:12]}...",
                            raw_ref_id=raw_ref, last_seen=seen_dt,
                        )
                if p_dom:
                    tid_d = ctx.upsert_asset(
                        "domain", p_dom, next_depth, "urlscan", "url_resource_pattern",
                        signal={"kind": "http_body_hash", "value": file_hash, "weight": 34},
                        last_seen=seen_dt,
                    )
                    if tid_d:
                        ctx.add_relationship_and_observation(
                            src_id, tid_d, "hosts_file_hash", "url_resource_pattern", "urlscan",
                            "http_body_hash", file_hash,
                            f"urlscan.io recorded domain {p_dom} serving resource SHA-256 {file_hash[:12]}...",
                            raw_ref_id=raw_ref, last_seen=seen_dt,
                        )
                if p_ip:
                    tid_ip = ctx.upsert_asset(
                        "ip", p_ip, next_depth, "urlscan", "url_resource_pattern",
                        signal={"kind": "http_body_hash", "value": file_hash, "weight": 32},
                        last_seen=seen_dt,
                    )
                    if tid_ip:
                        ctx.add_relationship_and_observation(
                            src_id, tid_ip, "hosts_file_hash", "url_resource_pattern", "urlscan",
                            "http_body_hash", file_hash,
                            f"urlscan.io recorded IP {p_ip} serving resource SHA-256 {file_hash[:12]}...",
                            raw_ref_id=raw_ref, last_seen=seen_dt,
                        )


def _pivot_from_url(ctx: PivotExecutionContext, asset: Dict[str, Any]) -> None:
    """
    URL pivots: Extracts host domain/IP, traces redirect chains, HTTP body/resource hashes,
    and associated payloads via urlscan.io, VirusTotal, and URLhaus.
    """
    url_val = asset["canonical_value"]
    src_id = asset["asset_id"]
    next_depth = asset["depth"] + 1
    limit = ctx.per_pivot_limit

    parsed = urllib.parse.urlparse(url_val)
    host = (parsed.hostname or "").lower().rstrip(".")
    if host:
        if intel_query.is_ip(host):
            tid = ctx.upsert_asset(
                "ip", host, next_depth, "url_parser", "passive_dns",
                signal={"kind": "passive_dns_a", "value": url_val, "weight": 36},
            )
            if tid:
                ctx.add_relationship_and_observation(
                    src_id, tid, "hosted_on_ip", "passive_dns", "url_parser",
                    "passive_dns_a", host, f"URL {url_val} directly targets IP {host}",
                )
        elif intel_query.is_domain(host):
            tid = ctx.upsert_asset(
                "domain", host, next_depth, "url_parser", "passive_dns",
                signal={"kind": "passive_dns_a", "value": url_val, "weight": 36},
            )
            if tid:
                ctx.add_relationship_and_observation(
                    src_id, tid, "hosted_on_domain", "passive_dns", "url_parser",
                    "passive_dns_a", host, f"URL {url_val} belongs to domain {host}",
                )

    # 1. urlscan.io URL lookup (redirect chains, body sha256, page IP, ASN, cert)
    if ctx.can_use_provider("urlscan", "redirect_chain") or ctx.can_use_provider("urlscan", "url_resource_pattern"):
        st, us_data, raw_ref = ctx.execute_provider_call(
            "urlscan", "redirect_chain", f"urlscan:url:{url_val}",
            lambda: intel_query.query_urlscan(url_val, "url", ctx.keys.get("urlscan_key", ""), size=min(limit, 15)),
        )
        if st == "ok" and isinstance(us_data, dict):
            results = ((us_data.get("normalized") or {}).get("results") or us_data.get("results") or [])
            for item in results[:limit]:
                if not isinstance(item, dict):
                    continue
                page = item.get("page") if isinstance(item.get("page"), dict) else item
                task = item.get("task") if isinstance(item.get("task"), dict) else {}
                final_url = str(page.get("url") or "").strip()
                task_url = str(task.get("url") or "").strip()
                p_ip = str(page.get("ip") or "").strip()
                p_dom = str(page.get("domain") or "").strip()
                p_asn = str(page.get("asn") or "").strip()
                seen_dt = str(item.get("indexed_at") or task.get("time") or "")

                if "redirect_chain" in ctx.enabled_methods and final_url and final_url != url_val:
                    tid_u = ctx.upsert_asset(
                        "url", final_url, next_depth, "urlscan", "redirect_chain",
                        signal={"kind": "redirect_chain", "value": url_val, "weight": 34},
                        last_seen=seen_dt,
                    )
                    if tid_u:
                        ctx.add_relationship_and_observation(
                            src_id, tid_u, "redirects_to", "redirect_chain", "urlscan",
                            "redirect_chain", final_url,
                            f"urlscan.io observed URL redirecting to {final_url}",
                            raw_ref_id=raw_ref, last_seen=seen_dt,
                        )
                if p_ip and "passive_dns" in ctx.enabled_methods:
                    tid_ip = ctx.upsert_asset(
                        "ip", p_ip, next_depth, "urlscan", "passive_dns",
                        signal={"kind": "passive_dns_a", "value": url_val, "weight": 32},
                        last_seen=seen_dt,
                        metadata={"asn": p_asn} if p_asn else None,
                    )
                    if tid_ip:
                        ctx.add_relationship_and_observation(
                            src_id, tid_ip, "resolves_to", "passive_dns", "urlscan",
                            "passive_dns_a", p_ip,
                            f"urlscan.io resolved URL page to IP {p_ip}",
                            raw_ref_id=raw_ref, last_seen=seen_dt,
                        )
                if p_dom and p_dom != host and "redirect_chain" in ctx.enabled_methods:
                    tid_d = ctx.upsert_asset(
                        "domain", p_dom, next_depth, "urlscan", "redirect_chain",
                        signal={"kind": "redirect_chain", "value": url_val, "weight": 30},
                        last_seen=seen_dt,
                    )
                    if tid_d:
                        ctx.add_relationship_and_observation(
                            src_id, tid_d, "redirects_to_domain", "redirect_chain", "urlscan",
                            "redirect_chain", p_dom,
                            f"urlscan.io landing page domain is {p_dom}",
                            raw_ref_id=raw_ref, last_seen=seen_dt,
                        )

    # 2. VirusTotal URL lookup (last_final_url, redirection_chain, last_http_response_content_sha256)
    if (ctx.can_use_provider("virustotal", "redirect_chain") or ctx.can_use_provider("virustotal", "http_body_headers")) and not ctx.check_limits():
        st, vt_data, raw_ref = ctx.execute_provider_call(
            "virustotal", "redirect_chain", f"vt:url:{url_val}",
            lambda: intel_query.query_vt(url_val, "url", ctx.keys.get("vt_key", "")),
        )
        if st == "ok" and isinstance(vt_data, dict):
            attrs = ((vt_data.get("data") or {}).get("attributes") or {}) if isinstance(vt_data.get("data"), dict) else {}
            stats = attrs.get("last_analysis_stats") or {}
            if stats:
                mal = int(stats.get("malicious") or 0) + int(stats.get("suspicious") or 0)
                tot = sum(int(v or 0) for v in stats.values())
                asset["maliciousness_context"]["vt_detections"] = f"{mal}/{tot}"

            if "redirect_chain" in ctx.enabled_methods:
                chain = attrs.get("redirection_chain") if isinstance(attrs.get("redirection_chain"), list) else []
                final_u = str(attrs.get("last_final_url") or "").strip()
                if final_u and final_u not in chain:
                    chain.append(final_u)
                for hop_url in chain[:limit]:
                    hop_url = str(hop_url or "").strip()
                    if hop_url and hop_url != url_val:
                        tid_hop = ctx.upsert_asset(
                            "url", hop_url, next_depth, "virustotal", "redirect_chain",
                            signal={"kind": "redirect_chain", "value": url_val, "weight": 34},
                        )
                        if tid_hop:
                            ctx.add_relationship_and_observation(
                                src_id, tid_hop, "redirects_to", "redirect_chain", "virustotal",
                                "redirect_chain", hop_url,
                                f"VirusTotal redirection chain includes {hop_url}",
                                raw_ref_id=raw_ref,
                            )

            if "http_body_headers" in ctx.enabled_methods:
                body_sha256 = str(attrs.get("last_http_response_content_sha256") or "").strip().lower()
                if _HEX64_RE.fullmatch(body_sha256):
                    tid_bh = ctx.upsert_asset(
                        "fingerprint", body_sha256, next_depth, "virustotal", "http_body_headers",
                        signal={"kind": "http_body_hash", "value": body_sha256, "weight": 32},
                        metadata={"subtype": "http_body_hash"},
                    )
                    if tid_bh:
                        ctx.add_relationship_and_observation(
                            src_id, tid_bh, "has_http_body_sha256", "http_body_headers", "virustotal",
                            "http_body_hash", body_sha256,
                            f"VirusTotal recorded HTTP response body SHA-256 {body_sha256[:16]}...",
                            raw_ref_id=raw_ref,
                        )


def _pivot_from_domain(ctx: PivotExecutionContext, asset: Dict[str, Any]) -> None:
    """
    Domain pivots:
    - Passive & Historical DNS (VirusTotal, Silent Push PADNS, Validin DNS, Shodan DNS, ThreatMiner, OTX)
    - TLS Certificates & SANs (crt.sh, VirusTotal, Validin, Silent Push)
    - WHOIS relationships (VirusTotal, Silent Push, Validin)
    - HTTP Body / Headers / Favicon / Redirects / URL patterns (urlscan.io, Silent Push)
    """
    domain = asset["canonical_value"]
    src_id = asset["asset_id"]
    next_depth = asset["depth"] + 1
    limit = ctx.per_pivot_limit

    # 1. crt.sh Certificate Transparency (TLS Certs & SANs)
    if "tls_cert" in ctx.enabled_methods and ctx.can_use_provider("crtsh", "tls_cert") and not ctx.check_limits():
        st, crt_data, raw_ref = ctx.execute_provider_call(
            "crtsh", "tls_cert", f"crtsh:domain:{domain}",
            lambda: intel_query.query_crtsh(domain),
        )
        if st == "ok" and isinstance(crt_data, dict):
            certs = crt_data.get("certificates") if isinstance(crt_data.get("certificates"), list) else []
            san_counts: Dict[str, Dict[str, Any]] = {}
            for cert in certs[:60]:
                if not isinstance(cert, dict):
                    continue
                issuer = str(cert.get("issuer") or "")
                not_before = str(cert.get("not_before") or "")
                serial = str(cert.get("serial_number") or "").strip()
                sans = cert.get("san") if isinstance(cert.get("san"), list) else []
                # Skip wildcard bloat certs covering >35 unrelated domains (e.g. Cloudflare multi-tenant SANs)
                if len(sans) > 35:
                    continue
                for san in sans:
                    clean_san = str(san or "").strip().lower().lstrip("*.")
                    if not clean_san or clean_san == domain or not intel_query.is_domain(clean_san):
                        continue
                    entry = san_counts.setdefault(clean_san, {"not_before": not_before, "issuer": issuer, "serial": serial})
                    if not_before > entry["not_before"]:
                        entry["not_before"] = not_before

            for san_dom, s_meta in list(san_counts.items())[:limit]:
                tid = ctx.upsert_asset(
                    "domain", san_dom, next_depth, "crtsh", "tls_cert",
                    signal={"kind": "tls_cert_san", "value": s_meta["serial"] or domain, "weight": 28},
                    first_seen=s_meta["not_before"],
                    last_seen=s_meta["not_before"],
                    metadata={"cert_issuer": s_meta["issuer"], "cert_serial": s_meta["serial"]},
                )
                if tid:
                    ctx.add_relationship_and_observation(
                        src_id, tid, "co_listed_in_cert_san", "tls_cert", "crtsh",
                        "tls_cert_san", san_dom,
                        f"crt.sh certificate (serial {s_meta['serial'][:12] or 'CT'}) lists both {domain} and {san_dom} in SANs",
                        raw_ref_id=raw_ref,
                        first_seen=s_meta["not_before"],
                        last_seen=s_meta["not_before"],
                    )

    # 2. VirusTotal Domain (Passive DNS, Historical SSL Certs, WHOIS, Communicating Files)
    if any(m in ctx.enabled_methods for m in ("passive_dns", "tls_cert", "whois_registration", "url_resource_pattern")) and ctx.can_use_provider("virustotal", "passive_dns") and not ctx.check_limits():
        st, vt_data, raw_ref = ctx.execute_provider_call(
            "virustotal", "passive_dns", f"vt:domain:{domain}",
            lambda: intel_query.query_vt(domain, "domain", ctx.keys.get("vt_key", "")),
        )
        if st == "ok" and isinstance(vt_data, dict):
            data_obj = vt_data.get("data") if isinstance(vt_data.get("data"), dict) else {}
            attrs = data_obj.get("attributes") if isinstance(data_obj.get("attributes"), dict) else {}
            stats = attrs.get("last_analysis_stats") or {}
            if stats:
                mal = int(stats.get("malicious") or 0) + int(stats.get("suspicious") or 0)
                tot = sum(int(v or 0) for v in stats.values())
                asset["maliciousness_context"]["vt_detections"] = f"{mal}/{tot}"

            # TLS certificate from VT
            if "tls_cert" in ctx.enabled_methods:
                last_cert = attrs.get("last_https_certificate") if isinstance(attrs.get("last_https_certificate"), dict) else {}
                hist_certs = data_obj.get("historical_ssl_certificates") if isinstance(data_obj.get("historical_ssl_certificates"), list) else []
                all_certs = ([last_cert] if last_cert else []) + hist_certs
                for c_obj in all_certs[:10]:
                    if not isinstance(c_obj, dict):
                        continue
                    c_attrs = c_obj.get("attributes") if isinstance(c_obj.get("attributes"), dict) else c_obj
                    thumb = str(c_attrs.get("thumbprint_sha256") or c_attrs.get("thumbprint") or "").strip().lower()
                    if _HEX64_RE.fullmatch(thumb):
                        subj = (c_attrs.get("subject") or {}).get("CN") or ""
                        issuer = (c_attrs.get("issuer") or {}).get("O") or (c_attrs.get("issuer") or {}).get("CN") or ""
                        tid_c = ctx.upsert_asset(
                            "certificate", thumb, next_depth, "virustotal", "tls_cert",
                            signal={"kind": "tls_cert_sha256", "value": thumb, "weight": 44},
                            metadata={"subject_cn": subj, "issuer": issuer},
                        )
                        if tid_c:
                            ctx.add_relationship_and_observation(
                                src_id, tid_c, "presents_certificate", "tls_cert", "virustotal",
                                "tls_cert_sha256", thumb,
                                f"VirusTotal observed TLS certificate SHA-256 {thumb[:16]}... on {domain}",
                                raw_ref_id=raw_ref,
                            )

            # WHOIS from VT
            if "whois_registration" in ctx.enabled_methods:
                registrar = str(attrs.get("registrar") or "").strip()
                if registrar:
                    asset["metadata"]["registrar"] = registrar
                whois_text = str(attrs.get("whois") or "")
                for line in whois_text.splitlines():
                    if ":" not in line:
                        continue
                    k_w, v_w = [x.strip() for x in line.split(":", 1)]
                    kl = k_w.lower()
                    if kl in {"registrant email", "admin email", "tech email"} and "@" in v_w:
                        tid_w = ctx.upsert_asset(
                            "whois", v_w, next_depth, "virustotal", "whois_registration",
                            signal={"kind": "whois_registrant", "value": v_w, "weight": 28},
                            metadata={"subtype": "email"},
                        )
                        if tid_w:
                            ctx.add_relationship_and_observation(
                                src_id, tid_w, "registered_by_email", "whois_registration", "virustotal",
                                "whois_registrant", v_w,
                                f"WHOIS registrant email for {domain} is {v_w}",
                                raw_ref_id=raw_ref,
                            )

        # VT Passive DNS resolutions
        if "passive_dns" in ctx.enabled_methods and not ctx.check_limits():
            st_r, res_data, ref_r = ctx.execute_provider_call(
                "virustotal", "passive_dns", f"vt:domain:{domain}:resolutions",
                lambda: intel_query.query_vt_relation(domain, "domain", "resolutions", ctx.keys.get("vt_key", ""), limit=min(limit, 35)),
            )
            if st_r == "ok" and isinstance(res_data, dict):
                items = res_data.get("data") if isinstance(res_data.get("data"), list) else []
                for item in items[:limit]:
                    if not isinstance(item, dict):
                        continue
                    r_attrs = item.get("attributes") if isinstance(item.get("attributes"), dict) else {}
                    ip_val = str(r_attrs.get("ip_address") or "").strip()
                    ts = r_attrs.get("date")
                    dt_iso = datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat() if isinstance(ts, (int, float)) and ts > 0 else ""
                    if ip_val:
                        tid_ip = ctx.upsert_asset(
                            "ip", ip_val, next_depth, "virustotal", "passive_dns",
                            signal={"kind": "passive_dns_a", "value": domain, "weight": 32},
                            last_seen=dt_iso,
                        )
                        if tid_ip:
                            ctx.add_relationship_and_observation(
                                src_id, tid_ip, "resolves_to", "passive_dns", "virustotal",
                                "passive_dns_a", ip_val,
                                f"VirusTotal passive DNS resolved {domain} -> {ip_val}",
                                raw_ref_id=ref_r, last_seen=dt_iso,
                            )

    # 3. Validin Domain (Passive DNS history, Certificates, Registration, Fingerprints)
    if ctx.can_use_provider("validin", "passive_dns") and not ctx.check_limits():
        st, val_data, raw_ref = ctx.execute_provider_call(
            "validin", "passive_dns", f"validin:domain:{domain}",
            lambda: intel_query.query_validin_domain(domain, ctx.keys.get("validin_key", "")),
        )
        if st == "ok" and isinstance(val_data, dict):
            norm = val_data.get("normalized") if isinstance(val_data.get("normalized"), dict) else {}
            if "passive_dns" in ctx.enabled_methods:
                for dns_rec in (norm.get("dns") or [])[:limit]:
                    if not isinstance(dns_rec, dict):
                        continue
                    r_val = str(dns_rec.get("value") or "").strip()
                    r_type = str(dns_rec.get("record_type") or "A").upper()
                    f_seen = str(dns_rec.get("first_seen_iso") or dns_rec.get("first_seen") or "")
                    l_seen = str(dns_rec.get("last_seen_iso") or dns_rec.get("last_seen") or "")
                    if intel_query.is_ip(r_val):
                        tid_ip = ctx.upsert_asset(
                            "ip", r_val, next_depth, "validin", "passive_dns",
                            signal={"kind": "passive_dns_a", "value": domain, "weight": 32},
                            first_seen=f_seen, last_seen=l_seen,
                        )
                        if tid_ip:
                            ctx.add_relationship_and_observation(
                                src_id, tid_ip, "resolves_to", "passive_dns", "validin",
                                f"dns_{r_type}", r_val,
                                f"Validin passive DNS ({r_type}) resolved {domain} -> {r_val}",
                                raw_ref_id=raw_ref, first_seen=f_seen, last_seen=l_seen,
                            )
                    elif intel_query.is_domain(r_val) and r_val != domain:
                        tid_d = ctx.upsert_asset(
                            "domain", r_val, next_depth, "validin", "passive_dns",
                            signal={"kind": "passive_dns_a", "value": domain, "weight": 26},
                            first_seen=f_seen, last_seen=l_seen,
                        )
                        if tid_d:
                            ctx.add_relationship_and_observation(
                                src_id, tid_d, f"dns_{r_type.lower()}_target", "passive_dns", "validin",
                                f"dns_{r_type}", r_val,
                                f"Validin DNS ({r_type}) links {domain} -> {r_val}",
                                raw_ref_id=raw_ref, first_seen=f_seen, last_seen=l_seen,
                            )

            if "tls_cert" in ctx.enabled_methods:
                for c_rec in (norm.get("certificates") or [])[:limit]:
                    if not isinstance(c_rec, dict):
                        continue
                    c_val = str(c_rec.get("value") or c_rec.get("sha256") or "").strip().lower()
                    if _HEX64_RE.fullmatch(c_val) or _HEX40_RE.fullmatch(c_val):
                        tid_c = ctx.upsert_asset(
                            "certificate", c_val, next_depth, "validin", "tls_cert",
                            signal={"kind": "tls_cert_sha256", "value": c_val, "weight": 42},
                            first_seen=str(c_rec.get("first_seen_iso") or ""),
                            last_seen=str(c_rec.get("last_seen_iso") or ""),
                        )
                        if tid_c:
                            ctx.add_relationship_and_observation(
                                src_id, tid_c, "presents_certificate", "tls_cert", "validin",
                                "tls_cert_sha256", c_val,
                                f"Validin observed TLS certificate {c_val[:16]}... for {domain}",
                                raw_ref_id=raw_ref,
                            )

            for p_rec in (norm.get("relationships") or norm.get("http_observations") or [])[:limit]:
                if not isinstance(p_rec, dict):
                    continue
                k_type = str(p_rec.get("record_type") or p_rec.get("type") or "").lower()
                p_val = str(p_rec.get("value") or "").strip()
                if not p_val:
                    continue
                if "jarm" in k_type and "jarm_ja4" in ctx.enabled_methods and _HEX62_RE.fullmatch(p_val):
                    tid_f = ctx.upsert_asset(
                        "fingerprint", p_val.lower(), next_depth, "validin", "jarm_ja4",
                        signal={"kind": "jarm", "value": p_val.lower(), "weight": 16},
                        metadata={"subtype": "jarm"},
                    )
                    if tid_f:
                        ctx.add_relationship_and_observation(
                            src_id, tid_f, "has_jarm_fingerprint", "jarm_ja4", "validin",
                            "jarm", p_val.lower(), f"Validin observed JARM {p_val[:16]}... on {domain}",
                            raw_ref_id=raw_ref,
                        )
                elif ("favicon" in k_type or "icon" in k_type) and "favicon_hash" in ctx.enabled_methods:
                    tid_f = ctx.upsert_asset(
                        "fingerprint", p_val, next_depth, "validin", "favicon_hash",
                        signal={"kind": "favicon_hash", "value": p_val, "weight": 28},
                        metadata={"subtype": "favicon_hash"},
                    )
                    if tid_f:
                        ctx.add_relationship_and_observation(
                            src_id, tid_f, "has_favicon_hash", "favicon_hash", "validin",
                            "favicon_hash", p_val, f"Validin observed favicon hash {p_val} on {domain}",
                            raw_ref_id=raw_ref,
                        )

    # 4. Silent Push Domain (PADNS forward, scan_data fingerprints, WHOIS)
    if ctx.can_use_provider("silentpush", "passive_dns") and not ctx.check_limits():
        st, sp_data, raw_ref = ctx.execute_provider_call(
            "silentpush", "passive_dns", f"silentpush:domain:{domain}",
            lambda: intel_query.query_silent_push(domain, "domain", ctx.keys.get("silentpush_key", "")),
        )
        if st == "ok" and isinstance(sp_data, dict):
            norm = sp_data.get("normalized") if isinstance(sp_data.get("normalized"), dict) else {}
            if "passive_dns" in ctx.enabled_methods:
                for rec in (norm.get("padns_forward") or [])[:limit]:
                    if not isinstance(rec, dict):
                        continue
                    ans = str(rec.get("answer") or "").strip()
                    rtype = str(rec.get("type") or "A").upper()
                    f_seen = str(rec.get("first_seen") or "")
                    l_seen = str(rec.get("last_seen") or "")
                    if intel_query.is_ip(ans):
                        tid_ip = ctx.upsert_asset(
                            "ip", ans, next_depth, "silentpush", "passive_dns",
                            signal={"kind": "passive_dns_a", "value": domain, "weight": 32},
                            first_seen=f_seen, last_seen=l_seen,
                        )
                        if tid_ip:
                            ctx.add_relationship_and_observation(
                                src_id, tid_ip, "resolves_to", "passive_dns", "silentpush",
                                f"padns_{rtype}", ans,
                                f"Silent Push PADNS ({rtype}) resolved {domain} -> {ans}",
                                raw_ref_id=raw_ref, first_seen=f_seen, last_seen=l_seen,
                            )
            for s_rec in (norm.get("scan_data") or [])[:limit]:
                if not isinstance(s_rec, dict):
                    continue
                if "favicon_hash" in ctx.enabled_methods and s_rec.get("favicon_murmur3"):
                    fav = str(s_rec["favicon_murmur3"]).strip()
                    tid_fav = ctx.upsert_asset(
                        "fingerprint", fav, next_depth, "silentpush", "favicon_hash",
                        signal={"kind": "favicon_hash", "value": fav, "weight": 28},
                        metadata={"subtype": "favicon_hash"},
                    )
                    if tid_fav:
                        ctx.add_relationship_and_observation(
                            src_id, tid_fav, "has_favicon_hash", "favicon_hash", "silentpush",
                            "favicon_hash", fav, f"Silent Push scan observed favicon murmur3 {fav}",
                            raw_ref_id=raw_ref,
                        )
                if "jarm_ja4" in ctx.enabled_methods and s_rec.get("jarm"):
                    j_val = str(s_rec["jarm"]).strip().lower()
                    if _HEX62_RE.fullmatch(j_val):
                        tid_j = ctx.upsert_asset(
                            "fingerprint", j_val, next_depth, "silentpush", "jarm_ja4",
                            signal={"kind": "jarm", "value": j_val, "weight": 16},
                            metadata={"subtype": "jarm"},
                        )
                        if tid_j:
                            ctx.add_relationship_and_observation(
                                src_id, tid_j, "has_jarm_fingerprint", "jarm_ja4", "silentpush",
                                "jarm", j_val, f"Silent Push scan observed JARM {j_val[:16]}...",
                                raw_ref_id=raw_ref,
                            )
                if "tls_cert" in ctx.enabled_methods and s_rec.get("ssl_sha256"):
                    c_sha = str(s_rec["ssl_sha256"]).strip().lower()
                    if _HEX64_RE.fullmatch(c_sha):
                        tid_c = ctx.upsert_asset(
                            "certificate", c_sha, next_depth, "silentpush", "tls_cert",
                            signal={"kind": "tls_cert_sha256", "value": c_sha, "weight": 44},
                        )
                        if tid_c:
                            ctx.add_relationship_and_observation(
                                src_id, tid_c, "presents_certificate", "tls_cert", "silentpush",
                                "tls_cert_sha256", c_sha, f"Silent Push observed SSL SHA-256 {c_sha[:16]}...",
                                raw_ref_id=raw_ref,
                            )
                if "http_body_headers" in ctx.enabled_methods and s_rec.get("body_sha256"):
                    b_sha = str(s_rec["body_sha256"]).strip().lower()
                    if _HEX64_RE.fullmatch(b_sha):
                        tid_b = ctx.upsert_asset(
                            "fingerprint", b_sha, next_depth, "silentpush", "http_body_headers",
                            signal={"kind": "http_body_hash", "value": b_sha, "weight": 32},
                            metadata={"subtype": "http_body_hash"},
                        )
                        if tid_b:
                            ctx.add_relationship_and_observation(
                                src_id, tid_b, "has_http_body_sha256", "http_body_headers", "silentpush",
                                "http_body_hash", b_sha, f"Silent Push observed HTTP body SHA-256 {b_sha[:16]}...",
                                raw_ref_id=raw_ref,
                            )

    # 5. Shodan Domain DNS lookup
    if "passive_dns" in ctx.enabled_methods and ctx.can_use_provider("shodan", "passive_dns") and not ctx.check_limits():
        st, sh_data, raw_ref = ctx.execute_provider_call(
            "shodan", "passive_dns", f"shodan:domain:{domain}",
            lambda: intel_query.query_shodan_domain(domain, ctx.keys.get("shodan_key", "")),
        )
        if st == "ok" and isinstance(sh_data, dict):
            norm = sh_data.get("normalized") if isinstance(sh_data.get("normalized"), dict) else {}
            for rec in (norm.get("records") or [])[:limit]:
                if not isinstance(rec, dict):
                    continue
                r_type = str(rec.get("type") or "").upper()
                r_val = str(rec.get("value") or "").strip()
                if r_type in {"A", "AAAA"} and intel_query.is_ip(r_val):
                    tid_ip = ctx.upsert_asset(
                        "ip", r_val, next_depth, "shodan", "passive_dns",
                        signal={"kind": "passive_dns_a", "value": domain, "weight": 32},
                    )
                    if tid_ip:
                        ctx.add_relationship_and_observation(
                            src_id, tid_ip, "resolves_to", "passive_dns", "shodan",
                            f"dns_{r_type}", r_val,
                            f"Shodan DNS ({r_type}) resolved {domain} -> {r_val}",
                            raw_ref_id=raw_ref,
                        )

    # 6. urlscan.io Domain Search (Passive DNS, Redirects, Resource hashes, Certs)
    if any(m in ctx.enabled_methods for m in ("passive_dns", "redirect_chain", "url_resource_pattern")) and ctx.can_use_provider("urlscan", "passive_dns") and not ctx.check_limits():
        st, us_data, raw_ref = ctx.execute_provider_call(
            "urlscan", "passive_dns", f"urlscan:domain:{domain}",
            lambda: intel_query.query_urlscan(domain, "domain", ctx.keys.get("urlscan_key", ""), size=min(limit, 20)),
        )
        if st == "ok" and isinstance(us_data, dict):
            results = ((us_data.get("normalized") or {}).get("results") or us_data.get("results") or [])
            for item in results[:limit]:
                if not isinstance(item, dict):
                    continue
                page = item.get("page") if isinstance(item.get("page"), dict) else item
                p_ip = str(page.get("ip") or "").strip()
                p_url = str(page.get("url") or "").strip()
                p_asn = str(page.get("asn") or "").strip()
                seen_dt = str(item.get("indexed_at") or (item.get("task") or {}).get("time") or "")
                if p_ip and "passive_dns" in ctx.enabled_methods:
                    tid_ip = ctx.upsert_asset(
                        "ip", p_ip, next_depth, "urlscan", "passive_dns",
                        signal={"kind": "passive_dns_a", "value": domain, "weight": 32},
                        last_seen=seen_dt,
                        metadata={"asn": p_asn} if p_asn else None,
                    )
                    if tid_ip:
                        ctx.add_relationship_and_observation(
                            src_id, tid_ip, "resolves_to", "passive_dns", "urlscan",
                            "passive_dns_a", p_ip,
                            f"urlscan.io observed {domain} resolving to {p_ip}",
                            raw_ref_id=raw_ref, last_seen=seen_dt,
                        )
                if p_url and "url_resource_pattern" in ctx.enabled_methods:
                    tid_u = ctx.upsert_asset(
                        "url", p_url, next_depth, "urlscan", "url_resource_pattern",
                        signal={"kind": "url_resource_pattern", "value": domain, "weight": 25},
                        last_seen=seen_dt,
                    )
                    if tid_u:
                        ctx.add_relationship_and_observation(
                            src_id, tid_u, "serves_url", "url_resource_pattern", "urlscan",
                            "url_resource_pattern", p_url,
                            f"urlscan.io captured URL {p_url} under {domain}",
                            raw_ref_id=raw_ref, last_seen=seen_dt,
                        )
                for f_obj in (item.get("files") or [])[:5]:
                    if not isinstance(f_obj, dict):
                        continue
                    f_sha = str(f_obj.get("sha256") or "").strip().lower()
                    if _HEX64_RE.fullmatch(f_sha) and "http_body_headers" in ctx.enabled_methods:
                        tid_fh = ctx.upsert_asset(
                            "fingerprint", f_sha, next_depth, "urlscan", "http_body_headers",
                            signal={"kind": "http_body_hash", "value": f_sha, "weight": 32},
                            metadata={"subtype": "http_body_hash", "filename": f_obj.get("filename", "")},
                        )
                        if tid_fh:
                            ctx.add_relationship_and_observation(
                                src_id, tid_fh, "delivers_resource_sha256", "http_body_headers", "urlscan",
                                "http_body_hash", f_sha,
                                f"urlscan.io observed HTTP resource SHA-256 {f_sha[:16]}... on {domain}",
                                raw_ref_id=raw_ref,
                            )

    # 7. ThreatMiner Domain Passive DNS, Subdomains & URIs
    if "passive_dns" in ctx.enabled_methods and ctx.can_use_provider("threatminer", "passive_dns") and not ctx.check_limits():
        st, tm_data, raw_ref = ctx.execute_provider_call(
            "threatminer", "passive_dns", f"threatminer:domain:{domain}",
            lambda: intel_query.query_threatminer_domain(domain),
        )
        if st == "ok" and isinstance(tm_data, dict):
            for rec in (tm_data.get("pdns") or tm_data.get("passive_dns") or [])[:limit]:
                if not isinstance(rec, dict):
                    continue
                ip_val = str(rec.get("ip") or "").strip()
                f_seen = str(rec.get("first_seen") or "")
                l_seen = str(rec.get("last_seen") or "")
                if ip_val:
                    tid_ip = ctx.upsert_asset(
                        "ip", ip_val, next_depth, "threatminer", "passive_dns",
                        signal={"kind": "passive_dns_a", "value": domain, "weight": 30},
                        first_seen=f_seen, last_seen=l_seen,
                    )
                    if tid_ip:
                        ctx.add_relationship_and_observation(
                            src_id, tid_ip, "resolves_to", "passive_dns", "threatminer",
                            "passive_dns_a", ip_val,
                            f"ThreatMiner passive DNS resolved {domain} -> {ip_val}",
                            raw_ref_id=raw_ref, first_seen=f_seen, last_seen=l_seen,
                        )
            if "reverse_ip" in ctx.enabled_methods:
                for sub_d in (tm_data.get("subdomains") or [])[:limit]:
                    s_clean = str(sub_d or "").strip().lower()
                    if s_clean and s_clean != domain and intel_query.is_domain(s_clean):
                        tid_sub = ctx.upsert_asset(
                            "domain", s_clean, next_depth, "threatminer", "reverse_ip",
                            signal={"kind": "passive_dns_a", "value": domain, "weight": 26},
                        )
                        if tid_sub:
                            ctx.add_relationship_and_observation(
                                src_id, tid_sub, "subdomain_of", "reverse_ip", "threatminer",
                                "subdomain", s_clean,
                                f"ThreatMiner DNS enumerated subdomain {s_clean}",
                                raw_ref_id=raw_ref,
                            )


def _pivot_from_ip(ctx: PivotExecutionContext, asset: Dict[str, Any]) -> None:
    """
    IP pivots across all 16 pivot methods:
    - Passive DNS & Reverse IP / DNS Records
    - WHOIS Records & BGP Peers / ASN
    - X509 Certs & JA4X, RDP Certificates (Port 3389)
    - JARM, JA3/JA4 TLS Fingerprints, SSH Host Keys & HASSH
    - HTTP Titles, Headers & ETags, Favicon Hashes, HTML / JS Similarity
    - OpenDirs, Open Ports, Service Banners, URL Patterns
    """
    ip_val = asset["canonical_value"]
    src_id = asset["asset_id"]
    next_depth = asset["depth"] + 1
    limit = ctx.per_pivot_limit

    # 1. GreyNoise noise & RIOT benign verification
    if "asn_hosting" in ctx.enabled_methods and ctx.can_use_provider("greynoise", "asn_hosting") and not ctx.check_limits():
        st, gn_data, raw_ref = ctx.execute_provider_call(
            "greynoise", "asn_hosting", f"greynoise:ip:{ip_val}",
            lambda: intel_query.query_greynoise(ip_val, ctx.keys.get("greynoise_key", "")),
        )
        if st == "ok" and isinstance(gn_data, dict):
            riot = bool(gn_data.get("riot", False))
            noise = bool(gn_data.get("noise", False))
            cls_label = str(gn_data.get("classification") or "")
            asset["metadata"]["greynoise_riot"] = riot
            asset["metadata"]["greynoise_noise"] = noise
            if cls_label:
                asset["maliciousness_context"]["greynoise_classification"] = cls_label
            if riot:
                ctx.upsert_asset("ip", ip_val, asset["depth"], "greynoise", "asn_hosting", metadata={"greynoise_riot": True})

    # 2. RIPEstat BGP Peers, ASN, Prefix & WHOIS Netblock context
    if ("asn_hosting" in ctx.enabled_methods or "whois_registration" in ctx.enabled_methods) and ctx.can_use_provider("ripe", "asn_hosting") and not ctx.check_limits():
        st, ripe_data, raw_ref = ctx.execute_provider_call(
            "ripe", "asn_hosting", f"ripe:ip:{ip_val}",
            lambda: intel_query.query_ripe_network(ip_val),
        )
        if st == "ok" and isinstance(ripe_data, dict):
            prefix = str(ripe_data.get("prefix") or "").strip()
            holder = str((ripe_data.get("asn_overview") or {}).get("holder") or "").strip()
            if prefix:
                asset["metadata"]["bgp_prefix"] = prefix
            if holder:
                asset["metadata"]["asn_holder"] = holder
                for fl in detect_shared_infrastructure(ip_val, holder):
                    if fl not in asset["shared_infra_flags"]:
                        asset["shared_infra_flags"].append(fl)
            for asn_num in (ripe_data.get("asns") or [])[:3]:
                asn_str = f"AS{str(asn_num).upper().lstrip('AS')}"
                tid_asn = ctx.upsert_asset(
                    "asn", asn_str, next_depth, "ripe", "asn_hosting",
                    signal={"kind": "asn_hosting", "value": asn_str, "weight": 14},
                    metadata={"holder": holder, "prefix": prefix},
                )
                if tid_asn:
                    ctx.add_relationship_and_observation(
                        src_id, tid_asn, "announced_by_asn", "asn_hosting", "ripe",
                        "asn_hosting", asn_str,
                        f"RIPEstat BGP routing: IP {ip_val} ({prefix}) announced by {asn_str} ({holder})",
                        raw_ref_id=raw_ref,
                    )
            if "whois_registration" in ctx.enabled_methods:
                for w_rec in (ripe_data.get("whois") or [])[:2]:
                    if not isinstance(w_rec, dict):
                        continue
                    netname = str(w_rec.get("netname") or w_rec.get("org-name") or w_rec.get("mnt-by") or "").strip()
                    inetnum = str(w_rec.get("inetnum") or prefix or "").strip()
                    if netname:
                        asset["metadata"]["whois_netname"] = netname
                        if inetnum and not asset["metadata"].get("bgp_prefix"):
                            asset["metadata"]["bgp_prefix"] = inetnum
                        tid_w = ctx.upsert_asset(
                            "whois", netname, next_depth, "ripe", "whois_registration",
                            signal={"kind": "whois_registrant", "value": netname, "weight": 24},
                            metadata={"subtype": "netblock", "inetnum": inetnum, "country": w_rec.get("country", "")},
                        )
                        if tid_w:
                            ctx.add_relationship_and_observation(
                                src_id, tid_w, "registered_netblock", "whois_registration", "ripe",
                                "whois_registrant", f"{netname} ({inetnum})",
                                f"RIPEstat WHOIS allocates {ip_val} ({inetnum}) to netblock {netname}",
                                raw_ref_id=raw_ref,
                            )

    # 3. Shodan Host Lookup (Certs, RDP Certs, JARM, JA3/JA4, Favicon, HTTP Titles/Headers/ETags, HTML/JS, SSH & HASSH, OpenDirs, Open Ports, Service Banners)
    if ctx.can_use_provider("shodan", "tls_cert") and not ctx.check_limits():
        st, sh_data, raw_ref = ctx.execute_provider_call(
            "shodan", "tls_cert", f"shodan:ip:{ip_val}",
            lambda: intel_query.query_shodan_ip(ip_val, ctx.keys.get("shodan_key", "")),
        )
        if st == "ok" and isinstance(sh_data, dict):
            norm = sh_data.get("normalized") if isinstance(sh_data.get("normalized"), dict) else sh_data
            hostnames = norm.get("hostnames") if isinstance(norm.get("hostnames"), list) else []
            if "reverse_ip" in ctx.enabled_methods:
                for hn in hostnames[:limit]:
                    hn_clean = str(hn or "").strip().lower()
                    if intel_query.is_domain(hn_clean):
                        tid_d = ctx.upsert_asset(
                            "domain", hn_clean, next_depth, "shodan", "reverse_ip",
                            signal={"kind": "reverse_ip", "value": ip_val, "weight": 20},
                        )
                        if tid_d:
                            ctx.add_relationship_and_observation(
                                src_id, tid_d, "ptr_or_hostname", "reverse_ip", "shodan",
                                "reverse_ip", hn_clean,
                                f"Shodan host record lists hostname {hn_clean} for {ip_val}",
                                raw_ref_id=raw_ref,
                            )

            services = norm.get("services") if isinstance(norm.get("services"), list) else []
            open_port_list: List[int] = []
            for svc in services[:30]:
                if not isinstance(svc, dict):
                    continue
                port = svc.get("port")
                if isinstance(port, int):
                    open_port_list.append(port)

                # TLS Cert, RDP Cert (port 3389) & JARM
                ssl_info = svc.get("ssl") if isinstance(svc.get("ssl"), dict) else {}
                fp = str(ssl_info.get("fingerprint_sha256") or ssl_info.get("fingerprint") or "").replace(":", "").strip().lower()
                is_rdp = (port == 3389) or ("rdp" in str(svc.get("module") or svc.get("product") or "").lower())
                if is_rdp and "rdp_cert" in ctx.enabled_methods and (_HEX64_RE.fullmatch(fp) or _HEX40_RE.fullmatch(fp)):
                    tid_rc = ctx.upsert_asset(
                        "certificate", fp, next_depth, "shodan", "rdp_cert",
                        signal={"kind": "rdp_cert", "value": fp, "weight": 44},
                        metadata={"subject": ssl_info.get("subject"), "issuer": ssl_info.get("issuer"), "port": 3389, "protocol": "RDP"},
                    )
                    if tid_rc:
                        ctx.add_relationship_and_observation(
                            src_id, tid_rc, "presents_rdp_certificate", "rdp_cert", "shodan",
                            "rdp_cert", fp,
                            f"Shodan observed RDP TLS certificate {fp[:16]}... on {ip_val}:3389",
                            raw_ref_id=raw_ref,
                        )
                elif "tls_cert" in ctx.enabled_methods and (_HEX64_RE.fullmatch(fp) or _HEX40_RE.fullmatch(fp)):
                    tid_c = ctx.upsert_asset(
                        "certificate", fp, next_depth, "shodan", "tls_cert",
                        signal={"kind": "tls_cert_sha256", "value": fp, "weight": 44},
                        metadata={"subject": ssl_info.get("subject"), "issuer": ssl_info.get("issuer"), "port": port},
                    )
                    if tid_c:
                        ctx.add_relationship_and_observation(
                            src_id, tid_c, "presents_certificate", "tls_cert", "shodan",
                            "tls_cert_sha256", fp,
                            f"Shodan observed X509 certificate {fp[:16]}... on {ip_val}:{port}",
                            raw_ref_id=raw_ref,
                        )

                if "jarm_ja4" in ctx.enabled_methods:
                    jarm_val = str(ssl_info.get("jarm") or svc.get("jarm") or "").strip().lower()
                    if _HEX62_RE.fullmatch(jarm_val):
                        tid_j = ctx.upsert_asset(
                            "fingerprint", jarm_val, next_depth, "shodan", "jarm_ja4",
                            signal={"kind": "jarm", "value": jarm_val, "weight": 16},
                            metadata={"subtype": "jarm", "port": port},
                        )
                        if tid_j:
                            ctx.add_relationship_and_observation(
                                src_id, tid_j, "has_jarm_fingerprint", "jarm_ja4", "shodan",
                                "jarm", jarm_val,
                                f"Shodan observed JARM {jarm_val[:16]}... on {ip_val}:{port}",
                                raw_ref_id=raw_ref,
                            )

                if "ja3_ja4" in ctx.enabled_methods:
                    for ja_key in ("ja3s", "ja4", "ja4s", "ja4x"):
                        ja_val = str(ssl_info.get(ja_key) or svc.get(ja_key) or "").strip().lower()
                        if ja_val:
                            tid_ja = ctx.upsert_asset(
                                "fingerprint", ja_val, next_depth, "shodan", "ja3_ja4",
                                signal={"kind": "ja3_ja4", "value": ja_val, "weight": 26},
                                metadata={"subtype": ja_key, "port": port},
                            )
                            if tid_ja:
                                ctx.add_relationship_and_observation(
                                    src_id, tid_ja, f"has_{ja_key}_fingerprint", "ja3_ja4", "shodan",
                                    ja_key, ja_val,
                                    f"Shodan observed {ja_key.upper()} {ja_val[:16]}... on {ip_val}:{port}",
                                    raw_ref_id=raw_ref,
                                )

                # HTTP Titles, Headers, ETags, OpenDirs, HTML/JS Similarity, Favicon
                http_info = svc.get("http") if isinstance(svc.get("http"), dict) else {}
                if http_info:
                    title_str = str(http_info.get("title") or "").strip()
                    if "open_dirs" in ctx.enabled_methods and "index of /" in title_str.lower():
                        tid_od = ctx.upsert_asset(
                            "fingerprint", f"opendir:{ip_val}:{port}", next_depth, "shodan", "open_dirs",
                            signal={"kind": "open_dirs", "value": title_str, "weight": 30},
                            metadata={"subtype": "open_dir", "port": port, "title": title_str},
                        )
                        if tid_od:
                            ctx.add_relationship_and_observation(
                                src_id, tid_od, "exposes_open_directory", "open_dirs", "shodan",
                                "open_dirs", title_str,
                                f"Shodan detected exposed OpenDir ('{title_str}') on {ip_val}:{port}",
                                raw_ref_id=raw_ref,
                            )
                    if "favicon_hash" in ctx.enabled_methods and http_info.get("favicon_hash") is not None:
                        fav_h = str(http_info["favicon_hash"]).strip()
                        if fav_h:
                            tid_f = ctx.upsert_asset(
                                "fingerprint", fav_h, next_depth, "shodan", "favicon_hash",
                                signal={"kind": "favicon_hash", "value": fav_h, "weight": 28},
                                metadata={"subtype": "favicon_hash", "port": port},
                            )
                            if tid_f:
                                ctx.add_relationship_and_observation(
                                    src_id, tid_f, "has_favicon_hash", "favicon_hash", "shodan",
                                    "favicon_hash", fav_h,
                                    f"Shodan observed HTTP favicon MurmurHash {fav_h} on {ip_val}:{port}",
                                    raw_ref_id=raw_ref,
                                )
                    if "html_js_similarity" in ctx.enabled_methods or "http_body_headers" in ctx.enabled_methods:
                        html_h = str(http_info.get("html_hash") or "").strip()
                        if html_h:
                            tid_bh = ctx.upsert_asset(
                                "fingerprint", html_h, next_depth, "shodan", "html_js_similarity",
                                signal={"kind": "http_body_hash", "value": html_h, "weight": 32},
                                metadata={"subtype": "http_body_hash", "port": port, "title": title_str},
                            )
                            if tid_bh:
                                ctx.add_relationship_and_observation(
                                    src_id, tid_bh, "has_http_body_hash", "html_js_similarity", "shodan",
                                    "http_body_hash", html_h,
                                    f"Shodan observed HTML body hash {html_h} on {ip_val}:{port}",
                                    raw_ref_id=raw_ref,
                                )
                    if "http_body_headers" in ctx.enabled_methods:
                        hdr_h = str(http_info.get("headers_hash") or "").strip()
                        if hdr_h:
                            tid_hh = ctx.upsert_asset(
                                "fingerprint", hdr_h, next_depth, "shodan", "http_body_headers",
                                signal={"kind": "http_headers_hash", "value": hdr_h, "weight": 22},
                                metadata={"subtype": "http_headers_hash", "port": port},
                            )
                            if tid_hh:
                                ctx.add_relationship_and_observation(
                                    src_id, tid_hh, "has_http_headers_hash", "http_body_headers", "shodan",
                                    "http_headers_hash", hdr_h,
                                    f"Shodan observed HTTP headers hash {hdr_h} on {ip_val}:{port}",
                                    raw_ref_id=raw_ref,
                                )
                        etag_val = str(http_info.get("etag") or "").strip().strip('"')
                        if etag_val:
                            tid_et = ctx.upsert_asset(
                                "fingerprint", etag_val, next_depth, "shodan", "http_body_headers",
                                signal={"kind": "http_etag", "value": etag_val, "weight": 30},
                                metadata={"subtype": "http_etag", "port": port},
                            )
                            if tid_et:
                                ctx.add_relationship_and_observation(
                                    src_id, tid_et, "has_http_etag", "http_body_headers", "shodan",
                                    "http_etag", etag_val,
                                    f"Shodan observed HTTP ETag '{etag_val}' on {ip_val}:{port}",
                                    raw_ref_id=raw_ref,
                                )

                # SSH Host Key & HASSH
                if "ssh_host_key" in ctx.enabled_methods:
                    ssh_obj = svc.get("ssh") if isinstance(svc.get("ssh"), dict) else {}
                    ssh_fp = str(ssh_obj.get("fingerprint") or svc.get("ssh_fingerprint") or "").strip()
                    if ssh_fp:
                        tid_ssh = ctx.upsert_asset(
                            "fingerprint", ssh_fp, next_depth, "shodan", "ssh_host_key",
                            signal={"kind": "ssh_host_key", "value": ssh_fp, "weight": 44},
                            metadata={"subtype": "ssh_host_key", "port": port},
                        )
                        if tid_ssh:
                            ctx.add_relationship_and_observation(
                                src_id, tid_ssh, "presents_ssh_host_key", "ssh_host_key", "shodan",
                                "ssh_host_key", ssh_fp,
                                f"Shodan observed SSH host key fingerprint {ssh_fp} on {ip_val}:{port}",
                                raw_ref_id=raw_ref,
                            )
                    hassh_val = str(ssh_obj.get("hassh") or svc.get("hassh") or "").strip().lower()
                    if hassh_val:
                        tid_hs = ctx.upsert_asset(
                            "fingerprint", hassh_val, next_depth, "shodan", "ssh_host_key",
                            signal={"kind": "ssh_hassh", "value": hassh_val, "weight": 30},
                            metadata={"subtype": "ssh_hassh", "port": port},
                        )
                        if tid_hs:
                            ctx.add_relationship_and_observation(
                                src_id, tid_hs, "has_ssh_hassh", "ssh_host_key", "shodan",
                                "ssh_hassh", hassh_val,
                                f"Shodan observed SSH HASSH {hassh_val} on {ip_val}:{port}",
                                raw_ref_id=raw_ref,
                            )

                # Service Banners
                if "service_banners" in ctx.enabled_methods:
                    banner_txt = str(svc.get("banner") or svc.get("data") or "").strip()
                    if banner_txt and len(banner_txt) <= 120 and not banner_txt.startswith(("HTTP/", "<", "{")):
                        tid_bn = ctx.upsert_asset(
                            "fingerprint", banner_txt[:80], next_depth, "shodan", "service_banners",
                            signal={"kind": "service_banners", "value": banner_txt[:80], "weight": 24},
                            metadata={"subtype": "service_banner", "port": port},
                        )
                        if tid_bn:
                            ctx.add_relationship_and_observation(
                                src_id, tid_bn, "presents_service_banner", "service_banners", "shodan",
                                "service_banners", banner_txt[:80],
                                f"Shodan observed service banner on {ip_val}:{port}",
                                raw_ref_id=raw_ref,
                            )

            if open_port_list and "open_ports" in ctx.enabled_methods:
                sorted_ports = sorted(set(open_port_list))
                asset["metadata"]["open_ports"] = sorted_ports
                non_std = [p for p in sorted_ports if p not in {80, 443, 22, 53, 25, 110, 143, 993, 995}]
                if non_std:
                    port_profile = ",".join(str(p) for p in non_std[:8])
                    tid_pp = ctx.upsert_asset(
                        "fingerprint", f"ports:{port_profile}", next_depth, "shodan", "open_ports",
                        signal={"kind": "open_ports", "value": port_profile, "weight": 14},
                        metadata={"subtype": "open_ports", "ports": sorted_ports},
                    )
                    if tid_pp:
                        ctx.add_relationship_and_observation(
                            src_id, tid_pp, "exposes_port_profile", "open_ports", "shodan",
                            "open_ports", port_profile,
                            f"Shodan observed non-standard open port profile [{port_profile}] on {ip_val}",
                            raw_ref_id=raw_ref,
                        )

    # 4. Censys Host Lookup (Certs, JARM, SSH Host Keys, Reverse DNS names)
    if ctx.can_use_provider("censys", "tls_cert") and not ctx.check_limits():
        st, cen_data, raw_ref = ctx.execute_provider_call(
            "censys", "tls_cert", f"censys:ip:{ip_val}",
            lambda: intel_query.query_censys_host_lookup(ip_val, ctx.keys.get("censys_key", "")),
        )
        if st == "ok" and isinstance(cen_data, dict):
            norm = cen_data.get("normalized") if isinstance(cen_data.get("normalized"), dict) else cen_data
            if "reverse_ip" in ctx.enabled_methods:
                for dns_name in (norm.get("dns_names") or norm.get("names") or [])[:limit]:
                    d_clean = str(dns_name or "").strip().lower()
                    if intel_query.is_domain(d_clean):
                        tid_d = ctx.upsert_asset(
                            "domain", d_clean, next_depth, "censys", "reverse_ip",
                            signal={"kind": "reverse_ip", "value": ip_val, "weight": 20},
                        )
                        if tid_d:
                            ctx.add_relationship_and_observation(
                                src_id, tid_d, "reverse_dns_name", "reverse_ip", "censys",
                                "reverse_ip", d_clean,
                                f"Censys host record associates {d_clean} with {ip_val}",
                                raw_ref_id=raw_ref,
                            )

            for svc in (norm.get("services") or [])[:30]:
                if not isinstance(svc, dict):
                    continue
                port = svc.get("port")
                c_fp = str(svc.get("certificate_sha256") or (svc.get("tls") or {}).get("certificate_sha256") or "").strip().lower()
                if "tls_cert" in ctx.enabled_methods and _HEX64_RE.fullmatch(c_fp):
                    tid_c = ctx.upsert_asset(
                        "certificate", c_fp, next_depth, "censys", "tls_cert",
                        signal={"kind": "tls_cert_sha256", "value": c_fp, "weight": 44},
                        metadata={"port": port},
                    )
                    if tid_c:
                        ctx.add_relationship_and_observation(
                            src_id, tid_c, "presents_certificate", "tls_cert", "censys",
                            "tls_cert_sha256", c_fp,
                            f"Censys observed TLS certificate SHA-256 {c_fp[:16]}... on {ip_val}:{port}",
                            raw_ref_id=raw_ref,
                        )
                jarm_v = str(svc.get("jarm") or "").strip().lower()
                if "jarm_ja4" in ctx.enabled_methods and _HEX62_RE.fullmatch(jarm_v):
                    tid_j = ctx.upsert_asset(
                        "fingerprint", jarm_v, next_depth, "censys", "jarm_ja4",
                        signal={"kind": "jarm", "value": jarm_v, "weight": 16},
                        metadata={"subtype": "jarm", "port": port},
                    )
                    if tid_j:
                        ctx.add_relationship_and_observation(
                            src_id, tid_j, "has_jarm_fingerprint", "jarm_ja4", "censys",
                            "jarm", jarm_v,
                            f"Censys observed JARM {jarm_v[:16]}... on {ip_val}:{port}",
                            raw_ref_id=raw_ref,
                        )
                ssh_k = str(svc.get("ssh_host_key_sha256") or (svc.get("ssh") or {}).get("fingerprint_sha256") or "").strip().lower()
                if "ssh_host_key" in ctx.enabled_methods and ssh_k:
                    tid_s = ctx.upsert_asset(
                        "fingerprint", ssh_k, next_depth, "censys", "ssh_host_key",
                        signal={"kind": "ssh_host_key", "value": ssh_k, "weight": 44},
                        metadata={"subtype": "ssh_host_key", "port": port},
                    )
                    if tid_s:
                        ctx.add_relationship_and_observation(
                            src_id, tid_s, "presents_ssh_host_key", "ssh_host_key", "censys",
                            "ssh_host_key", ssh_k,
                            f"Censys observed SSH server host key {ssh_k[:16]}... on {ip_val}:{port}",
                            raw_ref_id=raw_ref,
                        )

    # 5. VirusTotal IP (Reverse IP resolutions, historical SSL certificates, communicating files)
    if any(m in ctx.enabled_methods for m in ("reverse_ip", "tls_cert")) and ctx.can_use_provider("virustotal", "reverse_ip") and not ctx.check_limits():
        st, vt_data, raw_ref = ctx.execute_provider_call(
            "virustotal", "reverse_ip", f"vt:ip:{ip_val}",
            lambda: intel_query.query_vt(ip_val, "ip", ctx.keys.get("vt_key", "")),
        )
        if st == "ok" and isinstance(vt_data, dict):
            data_obj = vt_data.get("data") if isinstance(vt_data.get("data"), dict) else {}
            attrs = data_obj.get("attributes") if isinstance(data_obj.get("attributes"), dict) else {}
            stats = attrs.get("last_analysis_stats") or {}
            if stats:
                mal = int(stats.get("malicious") or 0) + int(stats.get("suspicious") or 0)
                tot = sum(int(v or 0) for v in stats.values())
                asset["maliciousness_context"]["vt_detections"] = f"{mal}/{tot}"

            if "tls_cert" in ctx.enabled_methods:
                last_cert = attrs.get("last_https_certificate") if isinstance(attrs.get("last_https_certificate"), dict) else {}
                hist_certs = data_obj.get("historical_ssl_certificates") if isinstance(data_obj.get("historical_ssl_certificates"), list) else []
                for c_obj in ([last_cert] if last_cert else []) + hist_certs[:10]:
                    if not isinstance(c_obj, dict):
                        continue
                    c_attrs = c_obj.get("attributes") if isinstance(c_obj.get("attributes"), dict) else c_obj
                    thumb = str(c_attrs.get("thumbprint_sha256") or c_attrs.get("thumbprint") or "").strip().lower()
                    if _HEX64_RE.fullmatch(thumb):
                        tid_c = ctx.upsert_asset(
                            "certificate", thumb, next_depth, "virustotal", "tls_cert",
                            signal={"kind": "tls_cert_sha256", "value": thumb, "weight": 44},
                        )
                        if tid_c:
                            ctx.add_relationship_and_observation(
                                src_id, tid_c, "presents_certificate", "tls_cert", "virustotal",
                                "tls_cert_sha256", thumb,
                                f"VirusTotal observed TLS certificate {thumb[:16]}... on {ip_val}",
                                raw_ref_id=raw_ref,
                            )

        if "reverse_ip" in ctx.enabled_methods and not ctx.check_limits():
            st_r, res_data, ref_r = ctx.execute_provider_call(
                "virustotal", "reverse_ip", f"vt:ip:{ip_val}:resolutions",
                lambda: intel_query.query_vt_relation(ip_val, "ip", "resolutions", ctx.keys.get("vt_key", ""), limit=min(limit, 40)),
            )
            if st_r == "ok" and isinstance(res_data, dict):
                items = res_data.get("data") if isinstance(res_data.get("data"), list) else []
                asset["metadata"]["cohosted_domain_count"] = max(int(asset["metadata"].get("cohosted_domain_count", 0)), len(items))
                for item in items[:limit]:
                    if not isinstance(item, dict):
                        continue
                    r_attrs = item.get("attributes") if isinstance(item.get("attributes"), dict) else {}
                    host_name = str(r_attrs.get("host_name") or "").strip().lower()
                    ts = r_attrs.get("date")
                    dt_iso = datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat() if isinstance(ts, (int, float)) and ts > 0 else ""
                    if host_name and intel_query.is_domain(host_name):
                        tid_d = ctx.upsert_asset(
                            "domain", host_name, next_depth, "virustotal", "reverse_ip",
                            signal={"kind": "reverse_ip", "value": ip_val, "weight": 20},
                            last_seen=dt_iso,
                            metadata={"cohosted_domain_count": len(items)},
                        )
                        if tid_d:
                            ctx.add_relationship_and_observation(
                                src_id, tid_d, "co_hosted_domain", "reverse_ip", "virustotal",
                                "reverse_ip", host_name,
                                f"VirusTotal reverse IP resolution shows {host_name} resolved to {ip_val}",
                                raw_ref_id=ref_r, last_seen=dt_iso,
                            )

    # 6. Validin IP (Reverse IP DNS history, Certs, JARM, Favicons)
    if ctx.can_use_provider("validin", "reverse_ip") and not ctx.check_limits():
        st, val_data, raw_ref = ctx.execute_provider_call(
            "validin", "reverse_ip", f"validin:ip:{ip_val}",
            lambda: intel_query.query_validin_ip(ip_val, ctx.keys.get("validin_key", "")),
        )
        if st == "ok" and isinstance(val_data, dict):
            norm = val_data.get("normalized") if isinstance(val_data.get("normalized"), dict) else {}
            dns_list = norm.get("dns") or []
            asset["metadata"]["cohosted_domain_count"] = max(int(asset["metadata"].get("cohosted_domain_count", 0)), len(dns_list))
            if "reverse_ip" in ctx.enabled_methods:
                for dns_rec in dns_list[:limit]:
                    if not isinstance(dns_rec, dict):
                        continue
                    d_val = str(dns_rec.get("value") or "").strip().lower()
                    f_seen = str(dns_rec.get("first_seen_iso") or dns_rec.get("first_seen") or "")
                    l_seen = str(dns_rec.get("last_seen_iso") or dns_rec.get("last_seen") or "")
                    if intel_query.is_domain(d_val):
                        tid_d = ctx.upsert_asset(
                            "domain", d_val, next_depth, "validin", "reverse_ip",
                            signal={"kind": "reverse_ip", "value": ip_val, "weight": 20},
                            first_seen=f_seen, last_seen=l_seen,
                            metadata={"cohosted_domain_count": len(dns_list)},
                        )
                        if tid_d:
                            ctx.add_relationship_and_observation(
                                src_id, tid_d, "co_hosted_domain", "reverse_ip", "validin",
                                "reverse_ip", d_val,
                                f"Validin reverse DNS history shows {d_val} hosted on {ip_val}",
                                raw_ref_id=raw_ref, first_seen=f_seen, last_seen=l_seen,
                            )

    # 7. Silent Push IP (Reverse PADNS & Webscan fingerprints)
    if ctx.can_use_provider("silentpush", "reverse_ip") and not ctx.check_limits():
        st, sp_data, raw_ref = ctx.execute_provider_call(
            "silentpush", "reverse_ip", f"silentpush:ip:{ip_val}",
            lambda: intel_query.query_silent_push(ip_val, "ip", ctx.keys.get("silentpush_key", "")),
        )
        if st == "ok" and isinstance(sp_data, dict):
            norm = sp_data.get("normalized") if isinstance(sp_data.get("normalized"), dict) else {}
            padns_rev = norm.get("padns_reverse") or []
            asset["metadata"]["cohosted_domain_count"] = max(int(asset["metadata"].get("cohosted_domain_count", 0)), len(padns_rev))
            if "reverse_ip" in ctx.enabled_methods:
                for rec in padns_rev[:limit]:
                    if not isinstance(rec, dict):
                        continue
                    q_dom = str(rec.get("query") or "").strip().lower()
                    f_seen = str(rec.get("first_seen") or "")
                    l_seen = str(rec.get("last_seen") or "")
                    if intel_query.is_domain(q_dom):
                        tid_d = ctx.upsert_asset(
                            "domain", q_dom, next_depth, "silentpush", "reverse_ip",
                            signal={"kind": "reverse_ip", "value": ip_val, "weight": 20},
                            first_seen=f_seen, last_seen=l_seen,
                            metadata={"cohosted_domain_count": len(padns_rev)},
                        )
                        if tid_d:
                            ctx.add_relationship_and_observation(
                                src_id, tid_d, "co_hosted_domain", "reverse_ip", "silentpush",
                                "reverse_ip", q_dom,
                                f"Silent Push reverse PADNS shows {q_dom} resolving to {ip_val}",
                                raw_ref_id=raw_ref, first_seen=f_seen, last_seen=l_seen,
                            )

    # 8. ThreatMiner Host Lookup
    if "reverse_ip" in ctx.enabled_methods and ctx.can_use_provider("threatminer", "reverse_ip") and not ctx.check_limits():
        st, tm_data, raw_ref = ctx.execute_provider_call(
            "threatminer", "reverse_ip", f"threatminer:ip:{ip_val}",
            lambda: intel_query.query_threatminer_host(ip_val),
        )
        if st == "ok" and isinstance(tm_data, dict):
            pdns = tm_data.get("pdns") or tm_data.get("passive_dns") or []
            for rec in pdns[:limit]:
                if not isinstance(rec, dict):
                    continue
                d_val = str(rec.get("domain") or "").strip().lower()
                f_seen = str(rec.get("first_seen") or "")
                l_seen = str(rec.get("last_seen") or "")
                if d_val and intel_query.is_domain(d_val):
                    tid_d = ctx.upsert_asset(
                        "domain", d_val, next_depth, "threatminer", "reverse_ip",
                        signal={"kind": "reverse_ip", "value": ip_val, "weight": 20},
                        first_seen=f_seen, last_seen=l_seen,
                    )
                    if tid_d:
                        ctx.add_relationship_and_observation(
                            src_id, tid_d, "co_hosted_domain", "reverse_ip", "threatminer",
                            "reverse_ip", d_val,
                            f"ThreatMiner reverse DNS shows {d_val} hosted on {ip_val}",
                            raw_ref_id=raw_ref, first_seen=f_seen, last_seen=l_seen,
                        )
            if "tls_cert" in ctx.enabled_methods:
                for cert_obj in (tm_data.get("certificates") or tm_data.get("ssl_certs") or [])[:limit]:
                    c_clean = str(cert_obj.get("fingerprint") if isinstance(cert_obj, dict) else cert_obj).strip().lower()
                    if _HEX40_RE.fullmatch(c_clean) or _HEX64_RE.fullmatch(c_clean):
                        tid_c = ctx.upsert_asset(
                            "certificate", c_clean, next_depth, "threatminer", "tls_cert",
                            signal={"kind": "tls_cert_sha256", "value": c_clean, "weight": 40},
                        )
                        if tid_c:
                            ctx.add_relationship_and_observation(
                                src_id, tid_c, "presents_certificate", "tls_cert", "threatminer",
                                "tls_cert_sha256", c_clean,
                                f"ThreatMiner SSL history links certificate {c_clean[:16]}... to {ip_val}",
                                raw_ref_id=raw_ref,
                            )

    # 9. urlscan.io IP Search (Reverse IP domains, URLs, HTML/JS Similarity hashes, OpenDirs)
    if any(m in ctx.enabled_methods for m in ("reverse_ip", "url_resource_pattern", "html_js_similarity", "http_body_headers")) and ctx.can_use_provider("urlscan", "reverse_ip") and not ctx.check_limits():
        st, us_data, raw_ref = ctx.execute_provider_call(
            "urlscan", "reverse_ip", f"urlscan:ip:{ip_val}",
            lambda: intel_query.query_urlscan(ip_val, "ip", ctx.keys.get("urlscan_key", ""), size=min(limit, 20)),
        )
        if st == "ok" and isinstance(us_data, dict):
            results = ((us_data.get("normalized") or {}).get("results") or us_data.get("results") or [])
            for item in results[:limit]:
                if not isinstance(item, dict):
                    continue
                page = item.get("page") if isinstance(item.get("page"), dict) else item
                p_dom = str(page.get("domain") or "").strip().lower()
                p_url = str(page.get("url") or "").strip()
                p_title = str(page.get("title") or "").strip()
                seen_dt = str(item.get("indexed_at") or (item.get("task") or {}).get("time") or "")
                if p_dom and intel_query.is_domain(p_dom) and "reverse_ip" in ctx.enabled_methods:
                    tid_d = ctx.upsert_asset(
                        "domain", p_dom, next_depth, "urlscan", "reverse_ip",
                        signal={"kind": "reverse_ip", "value": ip_val, "weight": 22},
                        last_seen=seen_dt,
                    )
                    if tid_d:
                        ctx.add_relationship_and_observation(
                            src_id, tid_d, "co_hosted_domain", "reverse_ip", "urlscan",
                            "reverse_ip", p_dom,
                            f"urlscan.io observed domain {p_dom} hosted on {ip_val}",
                            raw_ref_id=raw_ref, last_seen=seen_dt,
                        )
                if p_url and "url_resource_pattern" in ctx.enabled_methods:
                    tid_u = ctx.upsert_asset(
                        "url", p_url, next_depth, "urlscan", "url_resource_pattern",
                        signal={"kind": "url_resource_pattern", "value": ip_val, "weight": 25},
                        last_seen=seen_dt,
                    )
                    if tid_u:
                        ctx.add_relationship_and_observation(
                            src_id, tid_u, "serves_url", "url_resource_pattern", "urlscan",
                            "url_resource_pattern", p_url,
                            f"urlscan.io observed URL {p_url} served from {ip_val}",
                            raw_ref_id=raw_ref, last_seen=seen_dt,
                        )
                if "open_dirs" in ctx.enabled_methods and "index of /" in p_title.lower():
                    tid_od = ctx.upsert_asset(
                        "fingerprint", f"opendir:{ip_val}", next_depth, "urlscan", "open_dirs",
                        signal={"kind": "open_dirs", "value": p_title, "weight": 30},
                        metadata={"subtype": "open_dir", "title": p_title},
                    )
                    if tid_od:
                        ctx.add_relationship_and_observation(
                            src_id, tid_od, "exposes_open_directory", "open_dirs", "urlscan",
                            "open_dirs", p_title,
                            f"urlscan.io detected exposed OpenDir ('{p_title}') on {ip_val}",
                            raw_ref_id=raw_ref, last_seen=seen_dt,
                        )
                for f_obj in (item.get("files") or [])[:5]:
                    if not isinstance(f_obj, dict):
                        continue
                    f_sha = str(f_obj.get("sha256") or "").strip().lower()
                    if _HEX64_RE.fullmatch(f_sha) and ("html_js_similarity" in ctx.enabled_methods or "http_body_headers" in ctx.enabled_methods):
                        tid_fh = ctx.upsert_asset(
                            "fingerprint", f_sha, next_depth, "urlscan", "html_js_similarity",
                            signal={"kind": "html_js_similarity", "value": f_sha, "weight": 32},
                            metadata={"subtype": "http_body_hash", "filename": f_obj.get("filename", "")},
                        )
                        if tid_fh:
                            ctx.add_relationship_and_observation(
                                src_id, tid_fh, "delivers_resource_sha256", "html_js_similarity", "urlscan",
                                "html_js_similarity", f_sha,
                                f"urlscan.io observed HTML/JS resource SHA-256 {f_sha[:16]}... on {ip_val}",
                                raw_ref_id=raw_ref,
                            )

    # 10. Etugen OpenDirs (Trashpile exposed files & directories)
    if "open_dirs" in ctx.enabled_methods and ctx.can_use_provider("etugen", "open_dirs") and not ctx.check_limits():
        st, et_data, raw_ref = ctx.execute_provider_call(
            "etugen", "open_dirs", f"etugen:opendir:{ip_val}",
            lambda: intel_query.query_etugen_open_dir(ip_val, ctx.keys.get("etugen_key", "")),
        )
        if st == "ok" and isinstance(et_data, dict):
            files = (et_data.get("normalized") or {}).get("files") or et_data.get("files") or []
            if files:
                tid_od = ctx.upsert_asset(
                    "fingerprint", f"opendir:{ip_val}", next_depth, "etugen", "open_dirs",
                    signal={"kind": "open_dirs", "value": f"{len(files)} exposed files", "weight": 34},
                    metadata={"subtype": "open_dir", "file_count": len(files)},
                )
                if tid_od:
                    ctx.add_relationship_and_observation(
                        src_id, tid_od, "exposes_open_directory", "open_dirs", "etugen",
                        "open_dirs", f"{len(files)} files",
                        f"Etugen Trashpile indexed {len(files)} exposed OpenDir files on {ip_val}",
                        raw_ref_id=raw_ref,
                    )


def _pivot_from_certificate_or_fingerprint(ctx: PivotExecutionContext, asset: Dict[str, Any]) -> None:
    """
    Pivots from a TLS Certificate SHA-256/SHA-1 or an infrastructure fingerprint
    (JARM, JA4X, Favicon Hash, HTTP Body Hash, HTTP Headers Hash, SSH Host Key)
    across Shodan, Censys, FOFA, Validin, Silent Push, Netlas, and urlscan.io
    to discover all IPs and domains sharing that exact artifact.
    """
    val = asset["canonical_value"]
    a_type = asset["asset_type"]
    subtype = str(asset["metadata"].get("subtype") or ("cert_sha256" if a_type == "certificate" else "fingerprint")).lower()
    src_id = asset["asset_id"]
    next_depth = asset["depth"] + 1
    limit = ctx.per_pivot_limit

    # Map fingerprint subtype to pivot_method & signal_kind
    if a_type == "certificate" or subtype in {"cert_sha256", "tls_cert_sha256", "certificate_sha256"}:
        method = "tls_cert"
        sig_kind = "tls_cert_sha256"
        rel_name = "presents_certificate"
    elif subtype == "rdp_cert":
        method = "rdp_cert"
        sig_kind = "rdp_cert"
        rel_name = "presents_rdp_certificate"
    elif subtype == "jarm":
        method = "jarm_ja4"
        sig_kind = "jarm"
        rel_name = "shares_jarm"
    elif subtype in {"ja3", "ja3s", "ja4", "ja4s", "ja4t", "ja4x"}:
        method = "ja3_ja4" if subtype != "ja4x" else "tls_cert"
        sig_kind = "ja4x" if subtype == "ja4x" else "ja3_ja4"
        rel_name = f"shares_{subtype}"
    elif subtype in {"favicon_hash", "icon_hash", "favicon"}:
        method = "favicon_hash"
        sig_kind = "favicon_hash"
        rel_name = "shares_favicon_hash"
    elif subtype in {"http_body_hash", "body_hash", "html_js_similarity"}:
        method = "html_js_similarity" if "html_js_similarity" in ctx.enabled_methods else "http_body_headers"
        sig_kind = "http_body_hash"
        rel_name = "shares_http_body_hash"
    elif subtype in {"http_headers_hash", "header_hash", "http_etag"}:
        method = "http_body_headers"
        sig_kind = "http_etag" if subtype == "http_etag" else "http_headers_hash"
        rel_name = "shares_http_etag" if subtype == "http_etag" else "shares_http_headers_hash"
    elif subtype in {"ssh_host_key", "ssh", "ssh_hassh"}:
        method = "ssh_host_key"
        sig_kind = "ssh_hassh" if subtype == "ssh_hassh" else "ssh_host_key"
        rel_name = "shares_ssh_hassh" if subtype == "ssh_hassh" else "shares_ssh_host_key"
    else:
        return

    if method not in ctx.enabled_methods:
        return

    sig_weight = BASE_METHOD_WEIGHTS.get(sig_kind, 24)

    def _ingest_discovered_hosts(provider_name: str, hosts: List[Tuple[str, str]], raw_ref: str) -> None:
        for h_val, h_type in hosts[:limit]:
            tid = ctx.upsert_asset(
                h_type, h_val, next_depth, provider_name, method,
                signal={"kind": sig_kind, "value": val, "weight": sig_weight},
            )
            if tid:
                ctx.add_relationship_and_observation(
                    src_id, tid, rel_name, method, provider_name,
                    sig_kind, val,
                    f"{provider_name} search found {h_type.upper()} {h_val} matching {sig_kind}={val[:20]}",
                    raw_ref_id=raw_ref,
                )

    # 1. Validin fingerprint pivot
    validin_kind_map = {
        "tls_cert_sha256": "cert_hash",
        "jarm": "jarm",
        "http_headers_hash": "header_hash",
        "favicon_hash": "fingerprint",
    }
    v_kind = validin_kind_map.get(sig_kind)
    if v_kind and ctx.can_use_provider("validin", method) and not ctx.check_limits():
        st, v_data, raw_ref = ctx.execute_provider_call(
            "validin", method, f"validin:{v_kind}:{val}",
            lambda: intel_query.query_validin_fingerprint(val, v_kind, ctx.keys.get("validin_key", ""), limit=min(limit, 50)),
        )
        if st == "ok" and isinstance(v_data, dict):
            norm = v_data.get("normalized") if isinstance(v_data.get("normalized"), dict) else {}
            summary = norm.get("summary") if isinstance(norm.get("summary"), dict) else {}
            found: List[Tuple[str, str]] = []
            for ip_item in (summary.get("ips") or [])[:limit]:
                found.append((str(ip_item), "ip"))
            for dom_item in (summary.get("domains") or [])[:limit]:
                found.append((str(dom_item), "domain"))
            _ingest_discovered_hosts("validin", found, raw_ref)

    # 2. Shodan search (with multi-page pagination support)
    shodan_field_map = {
        "tls_cert_sha256": f"ssl.cert.fingerprint:{val}",
        "jarm": f"ssl.jarm:{val}",
        "favicon_hash": f"http.favicon.hash:{val}",
        "http_body_hash": f"http.html_hash:{val}",
        "http_headers_hash": f"http.headers_hash:{val}",
        "ssh_host_key": f'ssh.fingerprint:"{val}"',
    }
    sh_q = shodan_field_map.get(sig_kind)
    if sh_q and ctx.can_use_provider("shodan", method) and not ctx.check_limits():
        sh_found: List[Tuple[str, str]] = []
        page_num = 1
        last_ref = ""
        while len(sh_found) < limit and page_num <= 3 and not ctx.check_limits():
            st, sh_data, raw_ref = ctx.execute_provider_call(
                "shodan", method, f"shodan:search:{sh_q}:p{page_num}",
                lambda p=page_num: intel_query.query_shodan_search(sh_q, ctx.keys.get("shodan_key", ""), page=p),
            )
            if st != "ok" or not isinstance(sh_data, dict):
                break
            last_ref = raw_ref
            norm = sh_data.get("normalized") if isinstance(sh_data.get("normalized"), dict) else sh_data
            matches = norm.get("matches") or []
            if not matches:
                break
            for m in matches:
                if isinstance(m, dict):
                    ip_m = str(m.get("ip_str") or m.get("ip") or "").strip()
                    if ip_m:
                        sh_found.append((ip_m, "ip"))
                    for hn in (m.get("hostnames") or [])[:3]:
                        if hn:
                            sh_found.append((str(hn), "domain"))
            total_avail = int(norm.get("total") or len(matches))
            if len(sh_found) >= total_avail or len(matches) < 10:
                break
            page_num += 1
        if sh_found:
            _ingest_discovered_hosts("shodan", sh_found, last_ref)

    # 3. Censys search (with cursor pagination support)
    censys_field_map = {
        "tls_cert_sha256": f'cert.fingerprint_sha256: "{val}"',
        "jarm": f'host.services.jarm.fingerprint: "{val}"',
        "ssh_host_key": f'host.services.ssh.server_host_key.fingerprint_sha256: "{val}"',
    }
    cen_q = censys_field_map.get(sig_kind)
    if cen_q and ctx.can_use_provider("censys", method) and not ctx.check_limits():
        cen_found: List[Tuple[str, str]] = []
        cursor_token = ""
        page_idx = 1
        last_ref = ""
        page_sz = min(limit, 50)
        while len(cen_found) < limit and page_idx <= 3 and not ctx.check_limits():
            st, cen_data, raw_ref = ctx.execute_provider_call(
                "censys", method, f"censys:search:{cen_q}:p{page_idx}:{cursor_token}",
                lambda tok=cursor_token: intel_query.query_censys_search(cen_q, ctx.keys.get("censys_key", ""), page_size=page_sz, page_token=tok),
            )
            if st != "ok" or not isinstance(cen_data, dict):
                break
            last_ref = raw_ref
            norm = cen_data.get("normalized") if isinstance(cen_data.get("normalized"), dict) else cen_data
            hits = norm.get("hits") or []
            if not hits:
                break
            for hit in hits:
                if isinstance(hit, dict):
                    host_obj = hit.get("host") if isinstance(hit.get("host"), dict) else hit
                    ip_c = str(host_obj.get("ip") or "").strip()
                    if ip_c:
                        cen_found.append((ip_c, "ip"))
            cursor_token = str(norm.get("next_page_token") or (norm.get("links") or {}).get("next") or "").strip()
            if not cursor_token:
                break
            page_idx += 1
        if cen_found:
            _ingest_discovered_hosts("censys", cen_found, last_ref)

    # 4. FOFA search (with page pagination support)
    fofa_field_map = {
        "tls_cert_sha256": f'cert="{val}"',
        "jarm": f'jarm="{val}"',
        "favicon_hash": f'icon_hash="{val}"',
        "http_body_hash": f'body_hash="{val}"',
        "http_headers_hash": f'header_hash="{val}"',
    }
    fofa_q = fofa_field_map.get(sig_kind)
    if fofa_q and ctx.can_use_provider("fofa", method) and not ctx.check_limits():
        fofa_found: List[Tuple[str, str]] = []
        f_page = 1
        last_ref = ""
        f_size = min(limit, 50)
        while len(fofa_found) < limit and f_page <= 3 and not ctx.check_limits():
            st, fofa_data, raw_ref = ctx.execute_provider_call(
                "fofa", method, f"fofa:search:{fofa_q}:p{f_page}",
                lambda p=f_page: intel_query.query_fofa(fofa_q, ctx.keys.get("fofa_key", ""), size=f_size, page=p, query_type="fofa_query"),
            )
            if st != "ok" or not isinstance(fofa_data, dict):
                break
            last_ref = raw_ref
            norm = fofa_data.get("normalized") if isinstance(fofa_data.get("normalized"), dict) else fofa_data
            records = norm.get("records") or []
            if not records:
                break
            for rec in records:
                if isinstance(rec, dict):
                    if rec.get("ip"):
                        fofa_found.append((str(rec["ip"]), "ip"))
                    if rec.get("domain"):
                        fofa_found.append((str(rec["domain"]), "domain"))
            if len(records) < f_size:
                break
            f_page += 1
        if fofa_found:
            _ingest_discovered_hosts("fofa", fofa_found, last_ref)

    # 5. Silent Push SPQL Scan Data search
    sp_field_map = {
        "tls_cert_sha256": f'ssl_sha256 = "{val}" AND datasource = "webscan"',
        "jarm": f'jarm = "{val}" AND datasource = "webscan"',
        "favicon_hash": f'favicon_murmur3 = "{val}" AND datasource = "webscan"',
        "http_body_hash": f'body_sha256 = "{val}" AND datasource = "webscan"',
    }
    sp_q = sp_field_map.get(sig_kind)
    if sp_q and ctx.can_use_provider("silentpush", method) and not ctx.check_limits():
        st, sp_data, raw_ref = ctx.execute_provider_call(
            "silentpush", method, f"silentpush:spql:{sp_q}",
            lambda: intel_query.query_silent_push_scan_data(sp_q, ctx.keys.get("silentpush_key", ""), limit=min(limit, 50), query_type="spql"),
        )
        if st == "ok" and isinstance(sp_data, dict):
            norm = sp_data.get("normalized") if isinstance(sp_data.get("normalized"), dict) else {}
            found = []
            for rec in (norm.get("scan_data") or [])[:limit]:
                if isinstance(rec, dict):
                    if rec.get("ip"):
                        found.append((str(rec["ip"]), "ip"))
                    if rec.get("domain") or rec.get("hostname"):
                        found.append((str(rec.get("domain") or rec.get("hostname")), "domain"))
            _ingest_discovered_hosts("silentpush", found, raw_ref)

    # 6. Netlas search (with offset pagination support)
    netlas_field_map = {
        "tls_cert_sha256": f'certificate.fingerprint_sha256:"{val}"',
        "jarm": f'jarm:"{val}"',
        "favicon_hash": f'http.favicon.hash_sha256:"{val}"',
        "http_body_hash": f'http.body_sha256:"{val}"',
    }
    nl_q = netlas_field_map.get(sig_kind)
    if nl_q and ctx.can_use_provider("netlas", method) and not ctx.check_limits():
        nl_found: List[Tuple[str, str]] = []
        nl_offset = 0
        nl_size = min(limit, 20)
        last_ref = ""
        while len(nl_found) < limit and nl_offset < 60 and not ctx.check_limits():
            st, nl_data, raw_ref = ctx.execute_provider_call(
                "netlas", method, f"netlas:search:{nl_q}:start{nl_offset}",
                lambda off=nl_offset: intel_query.query_netlas_search(nl_q, ctx.keys.get("netlas_key", ""), size=nl_size, start=off),
            )
            if st != "ok" or not isinstance(nl_data, dict):
                break
            last_ref = raw_ref
            norm = nl_data.get("normalized") if isinstance(nl_data.get("normalized"), dict) else nl_data
            records = norm.get("records") or []
            if not records:
                break
            for rec in records:
                if isinstance(rec, dict):
                    if rec.get("ip"):
                        nl_found.append((str(rec["ip"]), "ip"))
                    if rec.get("host") or rec.get("domain"):
                        nl_found.append((str(rec.get("host") or rec.get("domain")), "domain"))
            if len(records) < nl_size:
                break
            nl_offset += nl_size
        if nl_found:
            _ingest_discovered_hosts("netlas", nl_found, last_ref)


# =============================================================================
# 9. PERSISTENCE, GRAPH SERIALIZATION & ORCHESTRATION LOOP
# =============================================================================

def _persist_checkpoint(ctx: PivotExecutionContext, status: str, error: str = "") -> None:
    """Persists full graph state, frontier, visited set, and progress to SQLite."""
    now = _utcnow()
    elapsed = round(ctx.elapsed_prior + (time.monotonic() - ctx.start_monotonic), 2)
    progress = {
        "status": status,
        "assets_discovered": len(ctx.assets),
        "relationships_mapped": len(ctx.relationships),
        "observations_recorded": len(ctx.observations),
        "api_calls_made": ctx.api_calls_made,
        "api_budget": ctx.api_budget,
        "frontier_remaining": len(ctx.frontier),
        "visited_count": len(ctx.visited_assets),
        "elapsed_seconds": elapsed,
        "max_depth": ctx.max_depth,
        "max_assets": ctx.max_assets,
        "provider_stats": dict(ctx.provider_stats),
    }

    with _DB_LOCK, _connect() as conn:
        finished_at = now if status in {"completed", "cancelled", "failed"} else ""
        conn.execute(
            """UPDATE pivot_investigations
               SET status=?, progress_json=?, frontier_json=?, visited_json=?, stats_json=?,
                   error=?, updated_at=?, finished_at=CASE WHEN ?<>'' THEN ? ELSE finished_at END
               WHERE id=?""",
            (
                status,
                _json(progress),
                _json(ctx.frontier),
                _json(sorted(ctx.visited_assets)),
                _json({"executed_queries": sorted(ctx.executed_queries), "elapsed": elapsed}),
                error[:1000],
                now,
                finished_at,
                finished_at,
                ctx.investigation_id,
            ),
        )

        for a in ctx.assets.values():
            conn.execute(
                """INSERT OR REPLACE INTO pivot_assets
                   (investigation_id, asset_id, asset_type, value, canonical_value, depth,
                    relationship_confidence, confidence_tier, score_breakdown_json, penalties_json,
                    shared_infra_flags_json, maliciousness_context_json, providers_json,
                    pivot_methods_json, first_seen, last_seen, metadata_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ctx.investigation_id,
                    a["asset_id"],
                    a["asset_type"],
                    a["value"],
                    a["canonical_value"],
                    a["depth"],
                    a["relationship_confidence"],
                    a["confidence_tier"],
                    _json({**a.get("score_breakdown", {}), "signals": a.get("signals", [])}),
                    _json(a.get("penalties", [])),
                    _json(a.get("shared_infra_flags", [])),
                    _json(a.get("maliciousness_context", {})),
                    _json(a.get("providers", [])),
                    _json(a.get("pivot_methods", [])),
                    a.get("first_seen", ""),
                    a.get("last_seen", ""),
                    _json(a.get("metadata", {})),
                ),
            )

        for r in ctx.relationships.values():
            conn.execute(
                """INSERT OR REPLACE INTO pivot_relationships
                   (investigation_id, edge_id, source_asset_id, target_asset_id, relationship_type,
                    pivot_method, confidence_score, base_weight, penalties_json, providers_json,
                    explanation, first_seen, last_seen, evidence_ids_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ctx.investigation_id,
                    r["edge_id"],
                    r["source_asset_id"],
                    r["target_asset_id"],
                    r["relationship_type"],
                    r["pivot_method"],
                    r["confidence_score"],
                    r["base_weight"],
                    _json(r.get("penalties", [])),
                    _json(r.get("providers", [])),
                    r.get("explanation", ""),
                    r.get("first_seen", ""),
                    r.get("last_seen", ""),
                    _json(r.get("evidence_ids", [])),
                ),
            )

        for o in ctx.observations.values():
            conn.execute(
                """INSERT OR REPLACE INTO pivot_observations
                   (investigation_id, observation_id, asset_id, related_asset_id, provider,
                    pivot_method, observation_type, field_name, field_value, observed_at,
                    first_seen, last_seen, raw_ref_id, summary)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ctx.investigation_id,
                    o["observation_id"],
                    o["asset_id"],
                    o.get("related_asset_id", ""),
                    o["provider"],
                    o["pivot_method"],
                    o["observation_type"],
                    o.get("field_name", ""),
                    o.get("field_value", ""),
                    o.get("observed_at", ""),
                    o.get("first_seen", ""),
                    o.get("last_seen", ""),
                    o.get("raw_ref_id", ""),
                    o.get("summary", ""),
                ),
            )


def _execute_traversal_loop(ctx: PivotExecutionContext) -> None:
    """Runs the bounded breadth-first priority traversal loop."""
    try:
        _persist_checkpoint(ctx, "running")
        while ctx.frontier:
            stop_reason = ctx.check_limits()
            if stop_reason == "cancelled":
                _persist_checkpoint(ctx, "cancelled", "Cancelled by user.")
                return
            if stop_reason:
                _persist_checkpoint(ctx, "completed", f"Stopped cleanly: {stop_reason}")
                return

            # Sort frontier: shallowest depth first, then highest relationship confidence
            ctx.frontier.sort(key=lambda item: (item["depth"], -item["priority"]))
            next_item = ctx.frontier.pop(0)
            aid = next_item["asset_id"]

            if aid in ctx.visited_assets:
                continue
            asset = ctx.assets.get(aid)
            if not asset or asset["depth"] >= ctx.max_depth:
                continue

            ctx.visited_assets.add(aid)
            a_type = asset["asset_type"]

            if a_type == "hash":
                _pivot_from_hash(ctx, asset)
            elif a_type == "url":
                _pivot_from_url(ctx, asset)
            elif a_type == "domain":
                _pivot_from_domain(ctx, asset)
            elif a_type == "ip":
                _pivot_from_ip(ctx, asset)
            elif a_type in {"certificate", "fingerprint"}:
                _pivot_from_certificate_or_fingerprint(ctx, asset)

            _persist_checkpoint(ctx, "running")

        final_status = "cancelled" if ctx.cancel_event.is_set() else "completed"
        _persist_checkpoint(ctx, final_status)
    except Exception as exc:
        logger.exception("Pivot traversal failed for %s", ctx.investigation_id)
        _persist_checkpoint(ctx, "failed", str(exc))
    finally:
        with _JOBS_LOCK:
            _ACTIVE_JOBS.pop(ctx.investigation_id, None)


# =============================================================================
# 10. PUBLIC SERVICE API (CREATE, RUN, CANCEL, RESUME, GET, LIST, EXPORT)
# =============================================================================

def start_investigation(
    seed: str,
    mode: str = "quick",
    custom_config: Optional[Dict[str, Any]] = None,
    keys: Optional[Dict[str, str]] = None,
    async_execution: bool = True,
) -> Dict[str, Any]:
    """
    Creates and starts an Automated Infrastructure Pivoting investigation.
    If async_execution=True, runs in a background daemon thread and returns immediately.
    """
    init_db()
    seed_info = normalize_seed_indicator(seed, (custom_config or {}).get("seed_type", ""))
    mode_clean = str(mode or "quick").strip().lower()
    if mode_clean not in PIVOT_PRESETS:
        mode_clean = "quick"

    base_cfg = dict(PIVOT_PRESETS[mode_clean])
    if isinstance(custom_config, dict):
        if "max_depth" in custom_config and custom_config["max_depth"] is not None:
            base_cfg["max_depth"] = max(1, min(int(custom_config["max_depth"]), 5))
        if "max_assets" in custom_config and custom_config["max_assets"] is not None:
            base_cfg["max_assets"] = max(5, min(int(custom_config["max_assets"]), 500))
        if "per_pivot_limit" in custom_config and custom_config["per_pivot_limit"] is not None:
            base_cfg["per_pivot_limit"] = max(3, min(int(custom_config["per_pivot_limit"]), 100))
        if "timeout_seconds" in custom_config and custom_config["timeout_seconds"] is not None:
            base_cfg["timeout_seconds"] = max(10, min(int(custom_config["timeout_seconds"]), 600))
        if "api_budget" in custom_config and custom_config["api_budget"] is not None:
            base_cfg["api_budget"] = max(2, min(int(custom_config["api_budget"]), 250))
        if "min_confidence_to_expand" in custom_config and custom_config["min_confidence_to_expand"] is not None:
            base_cfg["min_confidence_to_expand"] = max(10, min(int(custom_config["min_confidence_to_expand"]), 95))
        if "passive_only" in custom_config:
            base_cfg["passive_only"] = bool(custom_config["passive_only"])
        if custom_config.get("enabled_methods"):
            base_cfg["enabled_methods"] = [
                METHOD_ALIASES.get(m, m)
                for m in custom_config["enabled_methods"]
                if METHOD_ALIASES.get(m, m) in PIVOT_METHODS
            ]
        if custom_config.get("providers"):
            base_cfg["providers"] = [p for p in custom_config["providers"] if p in PROVIDER_CAPABILITY_REGISTRY]

    inv_id = f"piv_{uuid.uuid4().hex[:12]}"
    now = _utcnow()
    name = str((custom_config or {}).get("name") or f"Pivot: {seed_info['canonical']} ({mode_clean.upper()})").strip()[:160]

    cancel_event = threading.Event()
    ctx = PivotExecutionContext(inv_id, seed_info, base_cfg, keys or {}, cancel_event)

    # Register root seed asset at depth 0
    ctx.upsert_asset(
        seed_info["type"],
        seed_info["canonical"],
        depth=0,
        provider="seed",
        pivot_method="seed",
        metadata={"subtype": seed_info.get("subtype", "")} if seed_info.get("subtype") else None,
    )

    with _DB_LOCK, _connect() as conn:
        conn.execute(
            """INSERT INTO pivot_investigations
               (id, name, seed_value, seed_type, canonical_seed, mode, status,
                config_json, progress_json, frontier_json, visited_json, stats_json,
                created_at, updated_at, started_at)
               VALUES (?, ?, ?, ?, ?, ?, 'running', ?, '{}', ?, '[]', '{}', ?, ?, ?)""",
            (
                inv_id,
                name,
                seed,
                seed_info["type"],
                seed_info["canonical"],
                mode_clean,
                _json(base_cfg),
                _json(ctx.frontier),
                now,
                now,
                now,
            ),
        )

    with _JOBS_LOCK:
        _ACTIVE_JOBS[inv_id] = cancel_event

    if async_execution:
        t = threading.Thread(target=_execute_traversal_loop, args=(ctx,), daemon=True, name=f"pivot-{inv_id}")
        t.start()
    else:
        _execute_traversal_loop(ctx)

    return get_investigation(inv_id) or {"id": inv_id, "status": "running"}


def cancel_investigation(investigation_id: str) -> Dict[str, Any]:
    """Signals a running investigation to cancel and persists its frontier for later resumption."""
    init_db()
    inv_id = str(investigation_id or "").strip()
    with _JOBS_LOCK:
        ev = _ACTIVE_JOBS.get(inv_id)
        if ev:
            ev.set()

    now = _utcnow()
    with _DB_LOCK, _connect() as conn:
        row = conn.execute("SELECT status, progress_json FROM pivot_investigations WHERE id=?", (inv_id,)).fetchone()
        if not row:
            raise ValueError(f"Investigation '{inv_id}' not found.")
        prog = _loads(row["progress_json"], {})
        prog["status"] = "cancelled"
        conn.execute(
            "UPDATE pivot_investigations SET status='cancelled', progress_json=?, updated_at=?, finished_at=? WHERE id=?",
            (_json(prog), now, now, inv_id),
        )
    return get_investigation(inv_id) or {"id": inv_id, "status": "cancelled"}


def resume_investigation(
    investigation_id: str,
    keys: Optional[Dict[str, str]] = None,
    async_execution: bool = True,
) -> Dict[str, Any]:
    """
    Resumes a cancelled, paused, or interrupted investigation from its persisted
    frontier queue, visited set, and evidence graph in SQLite.
    """
    init_db()
    inv_id = str(investigation_id or "").strip()
    with _JOBS_LOCK:
        if inv_id in _ACTIVE_JOBS:
            return get_investigation(inv_id) or {"id": inv_id, "status": "running"}

    with _connect() as conn:
        inv_row = conn.execute("SELECT * FROM pivot_investigations WHERE id=?", (inv_id,)).fetchone()
        if not inv_row:
            raise ValueError(f"Investigation '{inv_id}' not found.")
        asset_rows = conn.execute("SELECT * FROM pivot_assets WHERE investigation_id=?", (inv_id,)).fetchall()
        rel_rows = conn.execute("SELECT * FROM pivot_relationships WHERE investigation_id=?", (inv_id,)).fetchall()
        obs_rows = conn.execute("SELECT * FROM pivot_observations WHERE investigation_id=?", (inv_id,)).fetchall()
        audit_count = conn.execute("SELECT COUNT(*) AS c FROM pivot_api_audit WHERE investigation_id=?", (inv_id,)).fetchone()["c"]

    config = _loads(inv_row["config_json"], dict(PIVOT_PRESETS["quick"]))
    stats = _loads(inv_row["stats_json"], {})
    config["_elapsed_prior"] = float(stats.get("elapsed", 0.0))

    seed_info = {
        "type": inv_row["seed_type"],
        "value": inv_row["seed_value"],
        "canonical": inv_row["canonical_seed"],
        "asset_id": f"{inv_row['seed_type']}:{inv_row['canonical_seed']}",
    }

    cancel_event = threading.Event()
    ctx = PivotExecutionContext(inv_id, seed_info, config, keys or {}, cancel_event)
    ctx.api_calls_made = int(audit_count or 0)
    ctx.visited_assets = set(_loads(inv_row["visited_json"], []))
    ctx.executed_queries = set(stats.get("executed_queries", []))
    ctx.frontier = _loads(inv_row["frontier_json"], [])

    for r in asset_rows:
        sb = _loads(r["score_breakdown_json"], {})
        ctx.assets[r["asset_id"]] = {
            "asset_id": r["asset_id"],
            "asset_type": r["asset_type"],
            "value": r["value"],
            "canonical_value": r["canonical_value"],
            "depth": r["depth"],
            "relationship_confidence": r["relationship_confidence"],
            "confidence_tier": r["confidence_tier"],
            "score_breakdown": sb,
            "signals": sb.get("signals", []),
            "penalties": _loads(r["penalties_json"], []),
            "shared_infra_flags": _loads(r["shared_infra_flags_json"], []),
            "maliciousness_context": _loads(r["maliciousness_context_json"], {}),
            "providers": _loads(r["providers_json"], []),
            "pivot_methods": _loads(r["pivot_methods_json"], []),
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
            "metadata": _loads(r["metadata_json"], {}),
        }

    for r in rel_rows:
        ctx.relationships[r["edge_id"]] = {
            "edge_id": r["edge_id"],
            "source_asset_id": r["source_asset_id"],
            "target_asset_id": r["target_asset_id"],
            "relationship_type": r["relationship_type"],
            "pivot_method": r["pivot_method"],
            "confidence_score": r["confidence_score"],
            "base_weight": r["base_weight"],
            "penalties": _loads(r["penalties_json"], []),
            "providers": _loads(r["providers_json"], []),
            "explanation": r["explanation"],
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
            "evidence_ids": _loads(r["evidence_ids_json"], []),
        }

    for o in obs_rows:
        ctx.observations[o["observation_id"]] = dict(o)

    # Re-populate frontier for any unvisited assets within depth bounds
    for aid, a in ctx.assets.items():
        if (
            aid not in ctx.visited_assets
            and a["depth"] < ctx.max_depth
            and (a["depth"] == 0 or a["relationship_confidence"] >= ctx.min_confidence_to_expand)
            and not any(f["asset_id"] == aid for f in ctx.frontier)
        ):
            ctx.frontier.append({"asset_id": aid, "depth": a["depth"], "priority": a["relationship_confidence"]})

    with _JOBS_LOCK:
        _ACTIVE_JOBS[inv_id] = cancel_event

    if async_execution:
        t = threading.Thread(target=_execute_traversal_loop, args=(ctx,), daemon=True, name=f"pivot-resume-{inv_id}")
        t.start()
    else:
        _execute_traversal_loop(ctx)

    return get_investigation(inv_id) or {"id": inv_id, "status": "running"}


def get_investigation(investigation_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves full investigation state, assets, relationships, observations, graph, and audit trail."""
    init_db()
    inv_id = str(investigation_id or "").strip()
    with _connect() as conn:
        inv_row = conn.execute("SELECT * FROM pivot_investigations WHERE id=?", (inv_id,)).fetchone()
        if not inv_row:
            return None
        asset_rows = conn.execute(
            "SELECT * FROM pivot_assets WHERE investigation_id=? ORDER BY depth ASC, relationship_confidence DESC",
            (inv_id,),
        ).fetchall()
        rel_rows = conn.execute(
            "SELECT * FROM pivot_relationships WHERE investigation_id=? ORDER BY confidence_score DESC",
            (inv_id,),
        ).fetchall()
        obs_rows = conn.execute(
            "SELECT * FROM pivot_observations WHERE investigation_id=? ORDER BY id DESC LIMIT 400",
            (inv_id,),
        ).fetchall()
        audit_rows = conn.execute(
            "SELECT * FROM pivot_api_audit WHERE investigation_id=? ORDER BY id ASC",
            (inv_id,),
        ).fetchall()

    assets = []
    for r in asset_rows:
        assets.append({
            "asset_id": r["asset_id"],
            "asset_type": r["asset_type"],
            "value": r["value"],
            "canonical_value": r["canonical_value"],
            "depth": r["depth"],
            "relationship_confidence": r["relationship_confidence"],
            "confidence_tier": r["confidence_tier"],
            "score_breakdown": _loads(r["score_breakdown_json"], {}),
            "penalties": _loads(r["penalties_json"], []),
            "shared_infra_flags": _loads(r["shared_infra_flags_json"], []),
            "maliciousness_context": _loads(r["maliciousness_context_json"], {}),
            "providers": _loads(r["providers_json"], []),
            "pivot_methods": _loads(r["pivot_methods_json"], []),
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
            "metadata": _loads(r["metadata_json"], {}),
        })

    relationships = []
    for r in rel_rows:
        relationships.append({
            "edge_id": r["edge_id"],
            "source": r["source_asset_id"],
            "target": r["target_asset_id"],
            "relationship_type": r["relationship_type"],
            "pivot_method": r["pivot_method"],
            "confidence_score": r["confidence_score"],
            "base_weight": r["base_weight"],
            "penalties": _loads(r["penalties_json"], []),
            "providers": _loads(r["providers_json"], []),
            "explanation": r["explanation"],
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
            "evidence_ids": _loads(r["evidence_ids_json"], []),
        })

    observations = [dict(o) for o in obs_rows]
    api_audit = [dict(a) for a in audit_rows]
    frontier = _loads(inv_row["frontier_json"], [])

    # Assess the investigation graph and collected evidence.
    # 1. Node role hypotheses (`c2-candidate`, `payload-host`, `shared-infrastructure`, `fast-flux-dns`, `shared-certificate`)
    # 2. Rarity-weighted APT attribution with commodity-tool caps & multi-dimension guard rails
    # 3. Context-aware defensive playbook & 3-question executive triage summary
    assessment = threat_assessment.build_investigation_assessment(assets, relationships, observations)
    for a in assets:
        a["defanged"] = threat_assessment.defang_ioc(a["value"])

    graph = {
        "nodes": [
            {
                "id": a["asset_id"],
                "label": a["value"],
                "defanged": a.get("defanged", a["value"]),
                "type": a["asset_type"],
                "depth": a["depth"],
                "confidence": a["relationship_confidence"],
                "tier": a["confidence_tier"],
                "providers": a["providers"],
                "shared_flags": a["shared_infra_flags"],
                "maliciousness": a["maliciousness_context"],
                "roles": a.get("roles", []),
            }
            for a in assets
        ],
        "edges": relationships,
    }

    return {
        "id": inv_row["id"],
        "name": inv_row["name"],
        "seed_value": inv_row["seed_value"],
        "seed_type": inv_row["seed_type"],
        "canonical_seed": inv_row["canonical_seed"],
        "defanged_seed": threat_assessment.defang_ioc(inv_row["canonical_seed"]),
        "mode": inv_row["mode"],
        "status": inv_row["status"],
        "can_resume": inv_row["status"] in {"cancelled", "failed"} or (inv_row["status"] != "running" and len(frontier) > 0),
        "config": _loads(inv_row["config_json"], {}),
        "progress": _loads(inv_row["progress_json"], {}),
        "frontier_count": len(frontier),
        "error": inv_row["error"],
        "created_at": inv_row["created_at"],
        "updated_at": inv_row["updated_at"],
        "started_at": inv_row["started_at"],
        "finished_at": inv_row["finished_at"],
        "assets": assets,
        "relationships": relationships,
        "observations": observations,
        "api_audit": api_audit,
        "graph": graph,
        "threat_assessment": assessment,
    }


def get_raw_response(raw_ref_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    with _connect() as conn:
        row = conn.execute("SELECT * FROM pivot_raw_responses WHERE id=?", (str(raw_ref_id or "").strip(),)).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "investigation_id": row["investigation_id"],
            "provider": row["provider"],
            "pivot_method": row["pivot_method"],
            "query": row["query"],
            "status": row["status"],
            "fetched_at": row["fetched_at"],
            "response": _loads(row["response_json"], {}),
        }


def list_investigations(limit: int = 50) -> List[Dict[str, Any]]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM pivot_investigations ORDER BY updated_at DESC, created_at DESC LIMIT ?",
            (max(1, min(int(limit), 200)),),
        ).fetchall()
        out = []
        for r in rows:
            prog = _loads(r["progress_json"], {})
            frontier = _loads(r["frontier_json"], [])
            out.append({
                "id": r["id"],
                "name": r["name"],
                "seed_value": r["seed_value"],
                "seed_type": r["seed_type"],
                "canonical_seed": r["canonical_seed"],
                "mode": r["mode"],
                "status": r["status"],
                "can_resume": r["status"] in {"cancelled", "failed"} or (r["status"] != "running" and len(frontier) > 0),
                "progress": prog,
                "frontier_count": len(frontier),
                "error": r["error"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
                "finished_at": r["finished_at"],
            })
        return out


def delete_investigation(investigation_id: str) -> Dict[str, Any]:
    init_db()
    inv_id = str(investigation_id or "").strip()
    with _JOBS_LOCK:
        ev = _ACTIVE_JOBS.pop(inv_id, None)
        if ev:
            ev.set()
    with _DB_LOCK, _connect() as conn:
        cur = conn.execute("DELETE FROM pivot_investigations WHERE id=?", (inv_id,))
        return {"deleted": cur.rowcount > 0, "id": inv_id}


def export_investigation(investigation_id: str, fmt: str = "json") -> Tuple[str, str, str]:
    """
    Exports an investigation in JSON, CSV, or STIX 2.1 bundle format.
    Returns (content_string, media_type, filename).
    """
    inv = get_investigation(investigation_id)
    if not inv:
        raise ValueError(f"Investigation '{investigation_id}' not found.")
    fmt_low = str(fmt or "json").strip().lower()
    safe_seed = re.sub(r"[^a-zA-Z0-9._-]+", "_", inv["canonical_seed"])[:40]

    if fmt_low == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "asset_id", "asset_type", "value", "depth", "relationship_confidence",
            "confidence_tier", "providers", "pivot_methods", "shared_infra_flags",
            "penalties", "first_seen", "last_seen", "threat_context",
        ])
        for a in inv["assets"]:
            writer.writerow([
                a["asset_id"],
                a["asset_type"],
                a["value"],
                a["depth"],
                a["relationship_confidence"],
                a["confidence_tier"],
                ";".join(a["providers"]),
                ";".join(a["pivot_methods"]),
                ";".join(a["shared_infra_flags"]),
                ";".join(f"{p['type']}(-{p['deduction']})" for p in a["penalties"]),
                a["first_seen"],
                a["last_seen"],
                _json(a["maliciousness_context"]),
            ])
        return buf.getvalue(), "text/csv", f"mantis_pivot_{safe_seed}_{inv['id']}.csv"

    if fmt_low == "stix":
        stix_objects = []
        id_map: Dict[str, str] = {}
        now_stix = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        for a in inv["assets"]:
            s_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"mantis:{inv['id']}:{a['asset_id']}"))
            a_type = a["asset_type"]
            if a_type == "ip":
                s_type = "ipv6-addr" if ":" in a["value"] else "ipv4-addr"
                obj = {"type": s_type, "spec_version": "2.1", "id": f"{s_type}--{s_uuid}", "value": a["value"]}
            elif a_type == "domain":
                obj = {"type": "domain-name", "spec_version": "2.1", "id": f"domain-name--{s_uuid}", "value": a["value"]}
            elif a_type == "url":
                obj = {"type": "url", "spec_version": "2.1", "id": f"url--{s_uuid}", "value": a["value"]}
            elif a_type == "hash":
                algo = "MD5" if len(a["value"]) == 32 else ("SHA-1" if len(a["value"]) == 40 else "SHA-256")
                obj = {"type": "file", "spec_version": "2.1", "id": f"file--{s_uuid}", "hashes": {algo: a["value"]}}
            elif a_type == "asn":
                num = int(re.sub(r"\D", "", a["value"]) or 0)
                obj = {"type": "autonomous-system", "spec_version": "2.1", "id": f"autonomous-system--{s_uuid}", "number": num}
            else:
                obj = {
                    "type": "grouping",
                    "spec_version": "2.1",
                    "id": f"grouping--{s_uuid}",
                    "name": f"{a_type}: {a['value']}",
                    "context": "suspicious-activity",
                    "created": now_stix,
                    "modified": now_stix,
                    "object_refs": [],
                }
            obj["x_mantis_relationship_confidence"] = a["relationship_confidence"]
            obj["x_mantis_depth"] = a["depth"]
            obj["x_mantis_providers"] = a["providers"]
            id_map[a["asset_id"]] = obj["id"]
            stix_objects.append(obj)

        for r in inv["relationships"]:
            src_stix = id_map.get(r["source"])
            tgt_stix = id_map.get(r["target"])
            if src_stix and tgt_stix:
                r_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"mantis:{inv['id']}:{r['edge_id']}"))
                stix_objects.append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{r_uuid}",
                    "created": now_stix,
                    "modified": now_stix,
                    "relationship_type": r["relationship_type"].replace("_", "-"),
                    "source_ref": src_stix,
                    "target_ref": tgt_stix,
                    "confidence": r["confidence_score"],
                    "description": r["explanation"],
                })
        bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": stix_objects}
        return json.dumps(bundle, indent=2), "application/json", f"mantis_pivot_{safe_seed}_{inv['id']}_stix21.json"

    return json.dumps(inv, indent=2, default=str), "application/json", f"mantis_pivot_{safe_seed}_{inv['id']}.json"


init_db()
