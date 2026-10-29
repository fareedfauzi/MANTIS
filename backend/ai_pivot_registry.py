"""
MANTIS AI Pivot Registry.

Maps deterministic, passive pivot types directly to existing provider adapters
and capabilities within MANTIS (intel_query.py).
Enforces:
- 100% passive, read-only lookups
- No fabricated providers
- No simulated intelligence
"""

from typing import Any, Dict, List, Optional


# Registry of verified passive pivots mapped to actual existing provider adapters
PIVOT_REGISTRY: Dict[str, Dict[str, Any]] = {
    # -------------------------------------------------------------
    # 1. HASH PIVOT ARCHETYPES
    # -------------------------------------------------------------
    "hash_to_similar_samples": {
        "pivot_type": "hash_to_similar_samples",
        "input_type": "hash",
        "description": "Query passive repositories for samples sharing code, imphash, visual features, or ssdeep similarity",
        "preferred_sources": ["malwarebazaar", "virustotal", "triage", "hybrid-analysis", "malshare"],
        "is_passive": True,
    },
    "hash_to_network_iocs": {
        "pivot_type": "hash_to_network_iocs",
        "input_type": "hash",
        "description": "Query threat intelligence databases and sandbox detonations for associated C2s and contacted hosts",
        "preferred_sources": ["virustotal", "threatfox", "triage", "hybrid-analysis", "tip", "alienvault", "urlhaus", "threatminer"],
        "is_passive": True,
    },
    "hash_to_yara_matches": {
        "pivot_type": "hash_to_yara_matches",
        "input_type": "hash",
        "description": "Inspect community and provider YARA rule matches for signature corroboration",
        "preferred_sources": ["yaraify", "malwarebazaar", "virustotal", "yara_forge", "rwlive"],
        "is_passive": True,
    },
    "hash_to_family_context": {
        "pivot_type": "hash_to_family_context",
        "input_type": "hash",
        "description": "Retrieve malware family labels, signatures, and tags across threat databases",
        "preferred_sources": ["malwarebazaar", "threatfox", "virustotal", "alienvault", "triage", "hybrid-analysis", "tip", "malware_news"],
        "is_passive": True,
    },
    "hash_to_behavioral_signatures": {
        "pivot_type": "hash_to_behavioral_signatures",
        "input_type": "hash",
        "description": "Extract dynamic detonation behavioral signatures (process hollowing, evasion, persistence, network beacons)",
        "preferred_sources": ["triage", "hybrid-analysis", "virustotal"],
        "is_passive": True,
    },
    "hash_to_execution_parents": {
        "pivot_type": "hash_to_execution_parents",
        "input_type": "hash",
        "description": "Discover dropper documents, archive wrappers, and parent binaries that execute or deploy this sample",
        "preferred_sources": ["virustotal", "triage", "alienvault", "hybrid-analysis"],
        "is_passive": True,
    },

    # -------------------------------------------------------------
    # 2. DOMAIN PIVOT ARCHETYPES
    # -------------------------------------------------------------
    "domain_to_passive_dns": {
        "pivot_type": "domain_to_passive_dns",
        "input_type": "domain",
        "description": "Resolve historical IP resolutions and DNS records through passive telemetry",
        "preferred_sources": ["validin", "virustotal", "silentpush", "dnsdumpster", "driftnet", "alienvault"],
        "is_passive": True,
    },
    "domain_to_ip": {
        "pivot_type": "domain_to_ip",
        "input_type": "domain",
        "description": "Retrieve current and recent IP addresses hosting the domain",
        "preferred_sources": ["virustotal", "dnsdumpster", "driftnet", "shodan", "censys", "validin", "silentpush", "fofa"],
        "is_passive": True,
    },
    "domain_to_certificate": {
        "pivot_type": "domain_to_certificate",
        "input_type": "domain",
        "description": "Query certificate transparency logs and TLS history for the domain",
        "preferred_sources": ["crtsh", "virustotal", "censys", "driftnet", "validin", "shodan", "silentpush"],
        "is_passive": True,
    },
    "domain_to_related_domains": {
        "pivot_type": "domain_to_related_domains",
        "input_type": "domain",
        "description": "Find sibling domains, subdomains, and co-hosted infrastructure",
        "preferred_sources": ["dnsdumpster", "virustotal", "alienvault", "validin", "silentpush", "driftnet", "leakix"],
        "is_passive": True,
    },
    "domain_to_web_reputation": {
        "pivot_type": "domain_to_web_reputation",
        "input_type": "domain",
        "description": "Profile domain web reputation, historical crawl snapshots, phishing telemetry, and blocklist presence",
        "preferred_sources": ["openphish", "phishstats", "reputation_feeds", "urlscan", "archive", "virustotal"],
        "is_passive": True,
    },
    "domain_to_threat_pulses": {
        "pivot_type": "domain_to_threat_pulses",
        "input_type": "domain",
        "description": "Extract threat intelligence community pulses, incident reports, and threat actor associations referencing this domain",
        "preferred_sources": ["alienvault", "orkl", "malware_news", "cti_articles", "tweetfeed"],
        "is_passive": True,
    },

    # -------------------------------------------------------------
    # 3. IP PIVOT ARCHETYPES
    # -------------------------------------------------------------
    "ip_to_domains": {
        "pivot_type": "ip_to_domains",
        "input_type": "ip",
        "description": "Enumerate domains historically or currently resolving to this IP address",
        "preferred_sources": ["virustotal", "shodan", "censys", "validin", "silentpush", "driftnet", "alienvault", "threatbook", "dnsdumpster"],
        "is_passive": True,
    },
    "ip_to_asn": {
        "pivot_type": "ip_to_asn",
        "input_type": "ip",
        "description": "Identify autonomous system (ASN), hosting provider, and BGP routing context",
        "preferred_sources": ["ripe", "driftnet", "abuseipdb", "silentpush", "threatbook", "greynoise", "shodan", "censys", "virustotal"],
        "is_passive": True,
    },
    "ip_to_certificates": {
        "pivot_type": "ip_to_certificates",
        "input_type": "ip",
        "description": "Enumerate TLS/SSL certificates observed on this IP address across scan repositories",
        "preferred_sources": ["censys", "shodan", "driftnet", "fofa", "validin", "virustotal", "threatminer"],
        "is_passive": True,
    },
    "ip_to_services_and_ports": {
        "pivot_type": "ip_to_services_and_ports",
        "input_type": "ip",
        "description": "Discover exposed ports, listening network services, banners, and operating system fingerprints",
        "preferred_sources": ["shodan", "censys", "threatbook", "driftnet", "fofa", "leakix"],
        "is_passive": True,
    },
    "ip_to_abuse_and_noise": {
        "pivot_type": "ip_to_abuse_and_noise",
        "input_type": "ip",
        "description": "Query IP abuse reporting confidence, honeypot attack records, and opportunistic mass-scanning noise classification",
        "preferred_sources": ["abuseipdb", "greynoise", "sans"],
        "is_passive": True,
    },
    "ip_to_threat_pulses": {
        "pivot_type": "ip_to_threat_pulses",
        "input_type": "ip",
        "description": "Extract threat intelligence community pulses, adversary links, and downloaded payload records referencing this IP",
        "preferred_sources": ["tip", "alienvault", "threatbook", "orkl", "malware_news", "cti_articles", "tweetfeed"],
        "is_passive": True,
    },

    # -------------------------------------------------------------
    # 4. URL PIVOT ARCHETYPES
    # -------------------------------------------------------------
    "url_to_telemetry": {
        "pivot_type": "url_to_telemetry",
        "input_type": "url",
        "description": "Query URLhaus, URLscan, and reputation feeds for payload distributions and sandbox captures",
        "preferred_sources": ["urlhaus", "urlscan", "virustotal", "threatfox", "openphish", "phishstats", "alienvault", "triage", "hybrid-analysis", "archive"],
        "is_passive": True,
    },
    "url_to_payload_hash": {
        "pivot_type": "url_to_payload_hash",
        "input_type": "url",
        "description": "Identify malware binary hashes and dropped payloads delivered from this URL endpoint",
        "preferred_sources": ["urlhaus", "urlscan", "virustotal", "triage", "hybrid-analysis"],
        "is_passive": True,
    },
    "url_to_redirect_chain": {
        "pivot_type": "url_to_redirect_chain",
        "input_type": "url",
        "description": "Trace effective URL landing page, redirection hops, server responses, and final payload delivery location",
        "preferred_sources": ["urlscan", "virustotal", "urlhaus"],
        "is_passive": True,
    },

    # -------------------------------------------------------------
    # 5. INFRASTRUCTURE & ROUTING (ASN / CIDR / CERT) PIVOT ARCHETYPES
    # -------------------------------------------------------------
    "asn_to_infrastructure": {
        "pivot_type": "asn_to_infrastructure",
        "input_type": "infra",
        "description": "Enumerate announced BGP routing prefixes, subnets, and host assets under an Autonomous System",
        "preferred_sources": ["ripe", "driftnet", "shodan", "censys", "fofa", "silentpush", "urlscan"],
        "is_passive": True,
    },
    "cidr_to_exposed_hosts": {
        "pivot_type": "cidr_to_exposed_hosts",
        "input_type": "infra",
        "description": "Scan network subnet block for listening services, open ports, and vulnerable edge banners",
        "preferred_sources": ["shodan", "censys", "driftnet", "abuseipdb", "fofa", "dnsdumpster", "validin"],
        "is_passive": True,
    },
    "certificate_to_infrastructure": {
        "pivot_type": "certificate_to_infrastructure",
        "input_type": "infra",
        "description": "Enumerate hostnames, SANs, and infrastructure sharing the same TLS certificate fingerprint or serial",
        "preferred_sources": ["crtsh", "censys", "driftnet", "shodan", "validin", "fofa"],
        "is_passive": True,
    },

    # -------------------------------------------------------------
    # 6. THREAT ACTOR & ADVERSARY CAMPAIGN PIVOT ARCHETYPES
    # -------------------------------------------------------------
    "threat_actor_to_campaign": {
        "pivot_type": "threat_actor_to_campaign",
        "input_type": "keyword",
        "description": "Retrieve adversary profile, known aliases, historical campaigns, and shared TTPs",
        "preferred_sources": ["alienvault", "misp_galaxy", "threat_actor_knowledge", "orkl", "cb", "malware_news", "github", "threatactorusernames"],
        "is_passive": True,
    },
    "threat_actor_to_infrastructure": {
        "pivot_type": "threat_actor_to_infrastructure",
        "input_type": "keyword",
        "description": "Identify known C2 IPs, domains, and registration infrastructure attributed to a threat actor",
        "preferred_sources": ["alienvault", "pulsedive", "threatfox", "silentpush", "orkl"],
        "is_passive": True,
    },
    "ransomware_group_to_victims": {
        "pivot_type": "ransomware_group_to_victims",
        "input_type": "keyword",
        "description": "Enumerate extortion victim disclosures, affected sectors, countries, and ransom leak entries",
        "preferred_sources": ["rwlive", "ransomlook", "malware_news"],
        "is_passive": True,
    },

    # -------------------------------------------------------------
    # 7. VULNERABILITY (CVE) EXPLOIT PIVOT ARCHETYPES
    # -------------------------------------------------------------
    "cve_to_exploits_and_pocs": {
        "pivot_type": "cve_to_exploits_and_pocs",
        "input_type": "keyword",
        "description": "Identify public Proof-of-Concept (PoC) exploit scripts, GitHub repositories, and weaponization context",
        "preferred_sources": ["github", "github_repos", "cb", "orkl", "malware_news", "cti_articles"],
        "is_passive": True,
    },
    "cve_to_wild_exploitation": {
        "pivot_type": "cve_to_wild_exploitation",
        "input_type": "keyword",
        "description": "Correlate in-the-wild exploitation reports, active campaigns, and associated threat groups",
        "preferred_sources": ["orkl", "alienvault", "malware_news", "rss_intel", "tweetfeed"],
        "is_passive": True,
    },

    # -------------------------------------------------------------
    # 8. MALWARE FAMILY & SOCIAL INTELLIGENCE PIVOT ARCHETYPES
    # -------------------------------------------------------------
    "malware_family_to_samples": {
        "pivot_type": "malware_family_to_samples",
        "input_type": "keyword",
        "description": "Retrieve indexed binary hashes, payloads, and delivery signatures for a malware family",
        "preferred_sources": ["malwarebazaar", "threatfox", "hybrid-analysis", "triage", "pulsedive", "malware_tools_knowledge"],
        "is_passive": True,
    },
    "ioc_to_social_mentions": {
        "pivot_type": "ioc_to_social_mentions",
        "input_type": "auto",
        "description": "Monitor real-time infosec community discussions, zero-day chatter, and shared IOC feeds",
        "preferred_sources": ["tweetfeed", "twitter", "x_monitor", "rss_intel", "malware_news"],
        "is_passive": True,
    },
    "ioc_to_threatfox": {
        "pivot_type": "ioc_to_threatfox",
        "input_type": "auto",
        "description": "Check ThreatFox for correlated malware campaign IOCs and threat associations",
        "preferred_sources": ["threatfox", "virustotal", "alienvault"],
        "is_passive": True,
    },
    "ioc_to_malwarebazaar": {
        "pivot_type": "ioc_to_malwarebazaar",
        "input_type": "auto",
        "description": "Query MalwareBazaar database for sample presence and related malware files",
        "preferred_sources": ["malwarebazaar", "virustotal", "triage"],
        "is_passive": True,
    },
}



def get_supported_pivot_types() -> List[str]:
    """Returns a list of all valid passive pivot types."""
    return list(PIVOT_REGISTRY.keys())


def get_pivot_definition(pivot_type: str) -> Optional[Dict[str, Any]]:
    """Returns registration metadata for a specific pivot type."""
    return PIVOT_REGISTRY.get(str(pivot_type).strip().lower())


def is_valid_pivot_type(pivot_type: str) -> bool:
    """Checks whether the given pivot type exists in the deterministic registry."""
    return str(pivot_type).strip().lower() in PIVOT_REGISTRY


def get_pivots_for_type(input_type: str) -> List[Dict[str, Any]]:
    """Returns all pivot archetypes matching the given input indicator type."""
    itype = str(input_type or "").strip().lower()
    return [
        defn for defn in PIVOT_REGISTRY.values()
        if defn.get("input_type") == itype or defn.get("input_type") == "auto"
    ]


def resolve_sources_for_pivot(pivot_type: str, available_sources: Optional[List[str]] = None) -> List[str]:
    """
    Returns the ordered list of provider sources to query for the given pivot type,
    filtered by available or selected sources if specified.
    """
    defn = get_pivot_definition(pivot_type)
    if not defn:
        return []
    preferred = defn.get("preferred_sources", [])
    if not available_sources:
        return list(preferred)
    avail_set = set(str(s).strip().lower() for s in available_sources)
    return [s for s in preferred if s.lower() in avail_set]
