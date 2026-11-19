"""
MANTIS I2A ("IOC -> Infrastructure -> Actor") Assessment, Rarity-Weighted Attribution,
Node Role Hypothesis, and Defensive Playbook Engine.

Inspired by the I2A methodology (LeenAdeeb/IOC-Enricher):
1. Phase 1: Node Role Hypothesis Engine (`c2-candidate`, `payload-host`, `shared-infrastructure`,
   `fast-flux-dns`, `shared-certificate`) + Free-text IOC extraction & defanging/refanging.
2. Phase 2: Explainable Rarity-Weighted APT Attribution Scorer built on MITRE ATT&CK (STIX 2.1)
   and MISP Galaxy (1,100+ groups) with commodity-tool caps, two-dimension guard rails,
   and CERT-EU style hedged analyst attribution statements.
3. Phase 3: Context-Aware Defensive Playbook & 3-Question Executive Triage Generator
   ("1. What is this IOC? 2. What is it connected to? 3. Who might be behind it?").
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import threading
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import intel_query

logger = logging.getLogger("mantis.i2a")

DATA_DIR = Path(__file__).resolve().parent / "data" / "misp"
BUNDLED_KB_PATH = DATA_DIR / "attack_misp_groups_kb.json"
MISP_ACTOR_PATH = DATA_DIR / "threat-actor.json"

# =============================================================================
# 1. FREE-TEXT IOC EXTRACTION, REFANGING & DEFANGING
# =============================================================================

_DEFANG_BRACKETS_RE = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I)
_DEFANG_COLON_RE = re.compile(r"\[:\]|\(:\)", re.I)
_DEFANG_SLASH_RE = re.compile(r"\[/\]|\(/\)", re.I)
_HXXP_RE = re.compile(r"\bhxxps?(?=://)", re.I)

_URL_EXTRACT_RE = re.compile(r"\b(?:https?|hxxps?)://[^\s\"'<>)\]]+", re.I)
_IP4_EXTRACT_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SHA256_EXTRACT_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_EXTRACT_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_EXTRACT_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_JARM_EXTRACT_RE = re.compile(r"\b[a-fA-F0-9]{62}\b")
_TECHNIQUE_EXTRACT_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
_DOMAIN_EXTRACT_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b"
)

COMMON_FILE_EXTENSIONS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "py", "sh", "elf",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "txt", "csv",
    "json", "xml", "yml", "yaml", "html", "htm", "css", "png", "jpg", "jpeg",
    "gif", "svg", "ico", "zip", "rar", "7z", "tar", "gz", "iso", "img", "lnk",
    "msi", "apk", "jar", "war", "php", "asp", "aspx", "jsp", "pdb", "log",
}


def refang_ioc(text: str) -> str:
    """Converts defanged indicators (e.g. hxxp://evil[.]com[:]/path) back to canonical form."""
    s = str(text or "").strip()
    s = re.sub(r"\[:\]\s*//|(?:\(:|\{:)\s*//", "://", s)
    s = re.sub(r"\[:\]\s*/|(?:\(:|\{:)\s*/", "/", s)
    s = _DEFANG_BRACKETS_RE.sub(".", s)
    s = _DEFANG_COLON_RE.sub(":", s)
    s = _DEFANG_SLASH_RE.sub("/", s)
    s = _HXXP_RE.sub(lambda m: "https" if m.group(0).lower().endswith("s") else "http", s)
    return s.strip()


def defang_ioc(value: str) -> str:
    """Safely defangs an IP, domain, or URL for analyst reports and tickets (`evil[.]com`, `hxxps://...`)."""
    s = str(value or "").strip()
    if not s:
        return ""
    if re.fullmatch(r"[a-fA-F0-9]{32,64}", s):
        return s  # Hashes do not need defanging
    s = re.sub(r"(?i)^https://", "hxxps://", s)
    s = re.sub(r"(?i)^http://", "hxxp://", s)
    if "://" in s:
        scheme, rest = s.split("://", 1)
        host, sep, path = rest.partition("/")
        host = host.replace(".", "[.]")
        return f"{scheme}://{host}{sep}{path}"
    if "." in s:
        return s.replace(".", "[.]")
    return s


def extract_iocs_from_text(raw_text: str) -> Dict[str, Any]:
    """
    Extracts and refangs IPs, domains, URLs, file hashes, JARM fingerprints, and MITRE ATT&CK
    technique IDs from unstructured text (threat reports, emails, logs, or defanged snippets).
    """
    refanged = refang_ioc(raw_text or "")
    items: List[Dict[str, str]] = []
    seen: Set[Tuple[str, str]] = set()

    def _add(ioc_type: str, val: str) -> None:
        v = val.strip().rstrip(".,;:'\"!?)")
        if not v:
            return
        key = (ioc_type, v.lower())
        if key not in seen:
            seen.add(key)
            items.append({
                "type": ioc_type,
                "value": v,
                "defanged": defang_ioc(v),
            })

    # 1. URLs
    url_hosts: Set[str] = set()
    for m in _URL_EXTRACT_RE.findall(refanged):
        clean_u = m.rstrip(".,;:'\"!?)")
        if intel_query.is_url(clean_u):
            _add("url", intel_query.normalize_url(clean_u))

    # 2. Hashes & JARM
    for m in _SHA256_EXTRACT_RE.findall(refanged):
        _add("hash", m.lower())
    for m in _JARM_EXTRACT_RE.findall(refanged):
        _add("fingerprint", f"jarm:{m.lower()}")
    for m in _SHA1_EXTRACT_RE.findall(refanged):
        _add("hash", m.lower())
    for m in _MD5_EXTRACT_RE.findall(refanged):
        _add("hash", m.lower())

    # 3. IPv4
    for m in _IP4_EXTRACT_RE.findall(refanged):
        if intel_query.is_ip(m):
            _add("ip", intel_query.normalize_ip(m))

    # 4. Domains (excluding file names like payload.exe or URLs already extracted)
    text_without_urls = _URL_EXTRACT_RE.sub(" ", refanged)
    for m in _DOMAIN_EXTRACT_RE.findall(text_without_urls):
        cand = m.lower().rstrip(".")
        tld = cand.rsplit(".", 1)[-1]
        if tld in COMMON_FILE_EXTENSIONS or tld.isdigit():
            continue
        if intel_query.is_domain(cand):
            _add("domain", cand)

    # 5. ATT&CK Techniques
    techniques = sorted({t.upper() for t in _TECHNIQUE_EXTRACT_RE.findall(refanged)})

    primary = items[0] if items else None
    return {
        "primary": primary,
        "indicators": items,
        "count": len(items),
        "techniques": techniques,
    }


# =============================================================================
# 2. PHASE 1: NODE ROLE HYPOTHESIS ENGINE (What is this node *doing*?)
# =============================================================================

C2_KEYWORDS = {
    "c2", "c&c", "cnc", "botnet_cc", "botnet c2", "beacon", "cobaltstrike",
    "cobalt strike", "sliver", "mythic", "havoc", "brute ratel", "bruteratel",
    "metasploit", "poshc2", "covenant", "deimos", "merlin", "empire", "rat",
    "asyncrat", "njrat", "quasarrat", "remcos", "darkcomet", "nanocore",
    "netwire", "xworm", "plugx", "shadowpad", "gh0st", "viper",
}

PAYLOAD_KEYWORDS = {
    "malware_download", "payload_delivery", "payload", "dropper", "loader",
    "downloader", "staging", "stager", "exploit-kit", "trojanized", "distribution",
    "phishing", "opendir", "open_directory",
}

DYNAMIC_DNS_SUFFIXES = {
    "duckdns.org", "no-ip.com", "no-ip.org", "no-ip.biz", "ddns.net", "hopto.org",
    "zapto.org", "sytes.net", "myftp.org", "myftp.biz", "servebeer.com",
    "serveblog.net", "serveftp.com", "servegame.com", "servehttp.com",
    "servemp3.com", "servepics.com", "servequake.com", "afraid.org", "mooo.com",
    "chickenkiller.com", "crabdance.com", "ignorelist.com", "strangled.net",
    "twilightparadox.com", "us.to", "uk.to", "fr.to", "dynu.com", "dynu.net",
    "freeddns.org", "changeip.com", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
    "workers.dev", "pages.dev",
}

ROTATING_IPS_THRESHOLD = 5
SHARED_HOST_DOMAIN_THRESHOLD = 30
MULTI_TENANT_CERT_THRESHOLD = 25


def is_dynamic_dns_domain(domain: str) -> Optional[str]:
    dom = str(domain or "").strip().lower().rstrip(".")
    for suffix in DYNAMIC_DNS_SUFFIXES:
        if dom == suffix or dom.endswith(f".{suffix}"):
            return suffix
    return None


def assess_asset_roles(
    assets: List[Dict[str, Any]],
    relationships: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Evaluates every asset in the investigation graph and assigns explainable
    functional role hypotheses (`c2-candidate`, `payload-host`, `shared-infrastructure`,
    `fast-flux-dns`, `shared-certificate`).
    Confidence is capped at Moderate because passive pivoting does not inspect live packet payloads.
    """
    asset_map = {a["asset_id"]: a for a in assets}
    out_edges: Dict[str, List[Dict[str, Any]]] = {}
    in_edges: Dict[str, List[Dict[str, Any]]] = {}

    for r in relationships:
        src = r.get("source") or r.get("source_asset_id") or ""
        tgt = r.get("target") or r.get("target_asset_id") or ""
        out_edges.setdefault(src, []).append(r)
        in_edges.setdefault(tgt, []).append(r)

    roles_by_asset: Dict[str, List[Dict[str, Any]]] = {}

    for a in assets:
        aid = a["asset_id"]
        atype = a.get("asset_type", "")
        val = str(a.get("value", "")).lower()
        mal = a.get("maliciousness_context") or {}
        meta = a.get("metadata") or {}
        shared_flags = a.get("shared_infra_flags") or []
        providers = set(a.get("providers") or [])
        methods = set(a.get("pivot_methods") or [])
        a_out = out_edges.get(aid, [])
        a_in = in_edges.get(aid, [])
        all_edges = a_out + a_in

        node_roles: List[Dict[str, Any]] = []

        # 1. Shared Infrastructure / CDN / Cloud Multi-Tenant
        shared_ev: List[str] = []
        if shared_flags:
            shared_ev.append(f"Matched shared/CDN markers: {', '.join(shared_flags[:3])}")
        if mal.get("greynoise_riot"):
            shared_ev.append("Verified benign common business service in GreyNoise RIOT")
        cohosted_domains = [
            e for e in all_edges
            if e.get("relationship_type") in {"resolves_to", "cohosted_on", "hosts"}
        ]
        if atype == "ip" and len(cohosted_domains) >= SHARED_HOST_DOMAIN_THRESHOLD:
            shared_ev.append(f"IP serves {len(cohosted_domains)} domains in graph (shared hosting)")
        if shared_ev:
            node_roles.append({
                "role": "shared-infrastructure",
                "label": "Shared Infra / CDN",
                "badge_class": "shared",
                "confidence": "Moderate",
                "evidence": shared_ev,
            })

        # 2. C2 Candidate vs Payload Host
        c2_ev: List[str] = []
        pay_ev: List[str] = []

        blob_text = json.dumps({"mal": mal, "meta": meta}, default=str).lower()
        matched_c2_kw = sorted({kw for kw in C2_KEYWORDS if kw in blob_text})
        if matched_c2_kw:
            c2_ev.append(f"Tagged with C2/framework indicators: {', '.join(matched_c2_kw[:4])}")

        matched_pay_kw = sorted({kw for kw in PAYLOAD_KEYWORDS if kw in blob_text})
        if matched_pay_kw:
            pay_ev.append(f"Tagged with payload/delivery indicators: {', '.join(matched_pay_kw[:4])}")

        if "threatfox" in providers and atype in {"ip", "domain", "url"}:
            tf_family = mal.get("threatfox_malware") or meta.get("malware") or "known malware"
            c2_ev.append(f"Listed in abuse.ch ThreatFox ({tf_family})")

        if "urlhaus" in providers:
            pay_ev.append("Listed in abuse.ch URLhaus as malware distribution endpoint")

        if "open_dirs" in methods or "etugen" in providers or "index of /" in blob_text:
            pay_ev.append("Exposed open directory (`Index of /`) detected on host")

        # Check communicating vs downloaded malware hash edges
        comm_samples = [
            e for e in all_edges
            if e.get("relationship_type") in {"communicates_with", "contacted_by_malware", "c2_of"}
        ]
        if comm_samples and atype in {"ip", "domain", "url"}:
            c2_ev.append(f"{len(comm_samples)} malware sample(s) communicate with this node")

        dl_samples = [
            e for e in all_edges
            if e.get("relationship_type") in {"distributes_malware", "downloaded_from", "hosts_payload"}
        ]
        if dl_samples and atype in {"ip", "domain", "url"}:
            pay_ev.append(f"Distributes or hosts {len(dl_samples)} malware sample(s)")

        vt_mal = int(mal.get("vt_malicious") or 0)
        if vt_mal >= 5 and atype in {"ip", "domain"} and (mal.get("malware_family") or mal.get("threatfox_malware")):
            c2_ev.append(f"Flagged by {vt_mal} engines with associated malware family")

        if c2_ev:
            node_roles.append({
                "role": "c2-candidate",
                "label": "C2 Candidate",
                "badge_class": "c2",
                "confidence": "Moderate" if len(c2_ev) >= 2 else "Low",
                "evidence": c2_ev,
            })

        if pay_ev:
            node_roles.append({
                "role": "payload-host",
                "label": "Payload Host",
                "badge_class": "payload",
                "confidence": "Moderate" if len(pay_ev) >= 2 else "Low",
                "evidence": pay_ev,
            })

        # 3. Domain DNS Behaviour (Dynamic DNS / Fast-Flux / Rotating IPs)
        if atype == "domain":
            dns_ev: List[str] = []
            ddns_provider = is_dynamic_dns_domain(val)
            if ddns_provider:
                dns_ev.append(f"Hosted under Dynamic DNS / ephemeral provider ({ddns_provider})")
            resolved_ips = {
                (e.get("target") if (e.get("source") == aid) else e.get("source"))
                for e in all_edges
                if e.get("relationship_type") in {"resolves_to", "hosts", "a_record"}
                and ("ip:" in str(e.get("target", "")) or "ip:" in str(e.get("source", "")))
            }
            if len(resolved_ips) >= ROTATING_IPS_THRESHOLD:
                dns_ev.append(f"Resolves across {len(resolved_ips)} distinct IPs (possible IP rotation or fast-flux)")
            if dns_ev:
                node_roles.append({
                    "role": "fast-flux-dns",
                    "label": "Dynamic / Rotating DNS",
                    "badge_class": "dns",
                    "confidence": "Moderate" if len(dns_ev) >= 2 else "Low",
                    "evidence": dns_ev,
                })

        # 4. Shared Certificate Pivot Node
        if atype == "certificate" or (atype == "fingerprint" and "jarm" in aid):
            covered = len(all_edges)
            if covered >= 2:
                is_noisy = covered >= MULTI_TENANT_CERT_THRESHOLD
                node_roles.append({
                    "role": "shared-certificate",
                    "label": "Multi-Tenant Cert" if is_noisy else "Shared Certificate",
                    "badge_class": "shared" if is_noisy else "cert",
                    "confidence": "Moderate" if not is_noisy else "Low",
                    "evidence": [f"Links {covered} infrastructure assets in the pivot graph"],
                })

        roles_by_asset[aid] = node_roles
        a["roles"] = node_roles

    return roles_by_asset


# =============================================================================
# 3. PHASE 2: RARITY-WEIGHTED APT ATTRIBUTION ENGINE WITH GUARD RAILS
# =============================================================================

W_MENTION = 30.0
W_SOFTWARE = 14.0
W_TECHNIQUE = 2.0
TECHNIQUE_CAP = 16.0
SATURATION = 55.0
RARE_THRESHOLD = 0.50       # Rarity score >= 0.50 counts as a distinctive/rare tool
CAP_ONE_RARE = 49           # Single rare family with no direct mention -> capped at Moderate (49%)
CAP_COMMODITY = 20          # Only commodity tools (Cobalt Strike, Mimikatz) / TTPs -> capped at Low (20%)
CAP_SINGLE_DIMENSION = 54   # High confidence (>= 55%) requires at least 2 independent dimensions
MIN_PATH_SCALE = 0.35       # Weakly connected nodes (<35% confidence) cannot lift guard rails

INDEPENDENT_DIMENSIONS = ("infrastructure", "malware", "ttp", "reported")
ALL_DIMENSIONS = ("reported", "infrastructure", "malware", "ttp", "victimology", "operational")
NOT_ASSESSED_DIMENSIONS = ("victimology", "operational")

DIMENSION_PHRASES = {
    "reported": "third-party threat reporting on seed",
    "infrastructure": "linked infrastructure attribution",
    "malware": "rarity-weighted malware/tool overlap",
    "ttp": "MITRE ATT&CK technique overlap",
}

ALIAS_STOPLIST = {
    "snake", "carbon", "dragon", "panda", "bear", "kitten", "tiger", "spider",
    "team", "group", "apt", "unknown", "tonto", "equation", "lead", "gold",
    "wolf", "hawk", "viper", "cobra", "lynx", "jackal", "hydra", "ares",
    "zeus", "atlas", "omega", "alpha", "delta", "nexus", "ghost", "shadow",
    "storm", "temp", "unc", "dev", "uta", "cl", "ta", "fin", "wizard",
}

# Ubiquitous commodity / red-team / dual-use tools that must never trigger high-confidence attribution alone
COMMODITY_SOFTWARE_NORMS = {
    "cobaltstrike", "mimikatz", "metasploit", "powershell", "empire", "ps1",
    "psexec", "impacket", "bloodhound", "sharphound", "rubeus", "certify",
    "adfind", "nltest", "net", "whoami", "cmd", "rundll32", "regsvr32",
    "certutil", "bitsadmin", "mshta", "wmic", "schtasks", "at", "sc",
    "ngrok", "plink", "putty", "winscp", "7zip", "winrar", "curl", "wget",
    "procdump", "processhacker", "anydesk", "teamviewer", "screenconnect",
    "atera", "splashtop", "rustdesk", "chisel", "frp", "ligolo", "sliver",
    "mythic", "havoc", "bruteratel", "covenant", "poshc2", "asyncrat",
    "njrat", "quasarrat", "remcos", "nanocore", "netwire", "darkcomet",
    "redline", "raccoon", "vidar", "lumma", "agenttesla", "formbook",
    "lokibot", "XWorm", "xworm", "qakbot", "emotet", "icedid", "trickbot",
}


def _norm_token(s: str) -> str:
    s = str(s or "").lower().strip()
    s = re.sub(r"^(win|elf|osx|apk|ps1|js|php|py|vbs|win32|win64)[._\-]", "", s)
    return re.sub(r"[^a-z0-9]", "", s)


@dataclass
class AttributionEvidence:
    kind: str               # mention | software | technique
    detail: str
    base_weight: float
    dimension: str          # reported | infrastructure | malware | ttp
    rarity: float = 1.0
    scale: float = 1.0      # strongest node confidence scale (0.0..1.0)
    iocs: List[str] = field(default_factory=list)
    matched_term: str = ""

    @property
    def weight(self) -> float:
        return self.base_weight * self.scale

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "dimension": self.dimension,
            "detail": self.detail,
            "matched_term": self.matched_term,
            "rarity": round(self.rarity, 2),
            "scale": round(self.scale, 2),
            "weight": round(self.weight, 1),
            "iocs": self.iocs[:8],
        }


@dataclass
class AttributionCandidate:
    group: Dict[str, Any]
    raw_score: float = 0.0
    confidence: int = 0
    evidence: List[AttributionEvidence] = field(default_factory=list)
    capped_reason: Optional[str] = None

    @property
    def confidence_label(self) -> str:
        if self.confidence >= 55:
            return "High"
        if self.confidence >= 25:
            return "Moderate"
        return "Low"

    def dimensions(self) -> Dict[str, Optional[int]]:
        out: Dict[str, Optional[int]] = {
            d: (None if d in NOT_ASSESSED_DIMENSIONS else 0)
            for d in ALL_DIMENSIONS
        }
        for e in self.evidence:
            if out.get(e.dimension) is not None:
                out[e.dimension] = int(out[e.dimension] or 0) + 1
        return out

    def active_dimension_count(self) -> int:
        dims = self.dimensions()
        return sum(1 for d in INDEPENDENT_DIMENSIONS if (dims.get(d) or 0) > 0)

    def statement(self, alternatives: Optional[List["AttributionCandidate"]] = None) -> str:
        """Generates a CERT-EU style hedged analyst attribution assessment statement."""
        dims = [
            DIMENSION_PHRASES[d]
            for d, count in self.dimensions().items()
            if count and d in DIMENSION_PHRASES
        ]
        dim_text = (
            dims[0]
            if len(dims) == 1
            else (", ".join(dims[:-1]) + " and " + dims[-1] if dims else "indicators")
        )
        top_ev = sorted(self.evidence, key=lambda e: -e.weight)[:3]
        parts = [
            f"{self.confidence_label}-confidence assessment ({self.confidence}%): "
            f"the observed {dim_text} exhibit similarities to activity previously associated with "
            f"{self.group['name']}."
        ]
        if top_ev:
            parts.append("Supported by: " + "; ".join(e.detail for e in top_ev) + ".")

        lims: List[str] = ["victimology and operational tempo were not assessed"]
        if self.capped_reason:
            lims.insert(0, self.capped_reason)
        if any(e.kind == "software" and e.rarity < RARE_THRESHOLD for e in self.evidence):
            lims.append("part of the tooling overlap involves commodity software shared across multiple threat groups")
        parts.append("Limitations: " + "; ".join(lims) + ".")

        if alternatives:
            alt_str = ", ".join(
                f"{a.group['name']} ({a.confidence_label}, {a.confidence}%)"
                for a in alternatives[:3]
            )
            parts.append(f"Alternative hypotheses: {alt_str}.")
        parts.append("Treat this assessment as an analytical hypothesis rather than definitive attribution.")
        return " ".join(parts)

    def to_dict(self, alternatives: Optional[List["AttributionCandidate"]] = None) -> Dict[str, Any]:
        g = self.group
        return {
            "group_id": g.get("id", ""),
            "name": g.get("name", ""),
            "aliases": (g.get("aliases") or [])[:10],
            "country": g.get("country") or "",
            "description": (g.get("description") or "")[:360],
            "url": g.get("url") or "",
            "source": g.get("source") or "attack+misp",
            "confidence": self.confidence,
            "confidence_label": self.confidence_label,
            "raw_score": round(self.raw_score, 1),
            "capped_reason": self.capped_reason,
            "dimensions": self.dimensions(),
            "active_dimensions": self.active_dimension_count(),
            "statement": self.statement(alternatives),
            "evidence": [e.to_dict() for e in sorted(self.evidence, key=lambda e: -e.weight)],
        }


class RarityWeightedAttributor:
    """
    Singleton-cached MITRE ATT&CK + MISP Galaxy Rarity-Weighted Attribution Scorer.
    """

    def __init__(self, kb: Dict[str, Any]) -> None:
        self.meta = kb.get("meta", {})
        self.groups: List[Dict[str, Any]] = kb.get("groups", [])
        # Denominator N = number of groups with a software profile in ATT&CK
        self._n = max(sum(1 for g in self.groups if g.get("software")), 2)
        self._sw_index: Dict[str, List[int]] = {}
        self._sw_canonical_name: Dict[str, str] = {}
        self._tech_df: Dict[str, int] = {}
        self._patterns: List[Tuple[re.Pattern, int, str]] = []

        for idx, g in enumerate(self.groups):
            seen_sw: Set[str] = set()
            for sw in g.get("software") or []:
                sw_name = sw.get("name", "")
                for nm in [sw_name, *(sw.get("aliases") or [])]:
                    k = _norm_token(nm)
                    if k and len(k) >= 3 and k not in seen_sw:
                        seen_sw.add(k)
                        self._sw_index.setdefault(k, []).append(idx)
                        self._sw_canonical_name.setdefault(k, sw_name)

            for t in g.get("techniques") or []:
                self._tech_df[t] = self._tech_df.get(t, 0) + 1

            for nm in [g.get("name", ""), *(g.get("aliases") or [])]:
                clean_nm = str(nm or "").strip()
                if len(clean_nm) >= 4 and clean_nm.lower() not in ALIAS_STOPLIST:
                    parts = [x for x in re.split(r"[\s\-_./]+", clean_nm.lower()) if x]
                    if not parts:
                        continue
                    flex = r"[\s\-_.]?".join(re.escape(x) for x in parts)
                    pat = re.compile(rf"(?<![a-z0-9]){flex}(?![a-z0-9])", re.I)
                    self._patterns.append((pat, idx, clean_nm))

    def _idf_rarity(self, df: int) -> float:
        df = max(df, 1)
        return math.log(1.0 + self._n / df) / math.log(1.0 + self._n)

    def software_rarity(self, norm_key: str) -> Tuple[float, int]:
        group_list = self._sw_index.get(norm_key, [])
        df = max(len(group_list), 1)
        rar = self._idf_rarity(df)
        if norm_key in COMMODITY_SOFTWARE_NORMS:
            rar = min(rar, 0.28)  # Enforce commodity ceiling
        return rar, df

    def evaluate(
        self,
        items: List[Dict[str, Any]],
        top_n: int = 5,
    ) -> Dict[str, Any]:
        """
        Evaluates a list of enriched IOC items.
        Each item in `items` has:
          - `ioc`: str (e.g. IP, domain, hash)
          - `is_seed`: bool
          - `scale`: float (0.0..1.0, relationship confidence / 100)
          - `actors`: List[str] (explicit actor/adversary fields)
          - `tags`: List[str] (tags, pulse titles, WHOIS orgs, cert subjects, etc.)
          - `malware`: List[str] (malware / tool families)
          - `techniques`: List[str] (MITRE ATT&CK IDs like T1566.001)
        """
        cands: Dict[int, AttributionCandidate] = {}
        mention_seen: Dict[Tuple[int, str, bool], AttributionEvidence] = {}
        sw_seen: Dict[Tuple[int, str], AttributionEvidence] = {}
        tech_hits: Dict[int, Dict[str, AttributionEvidence]] = {}

        def _touch(ev: AttributionEvidence, ioc_val: str, scale_val: float) -> None:
            if ioc_val and ioc_val not in ev.iocs:
                ev.iocs.append(ioc_val)
            ev.scale = max(ev.scale, scale_val)

        for item in items:
            ioc_val = str(item.get("ioc") or "investigation")
            is_seed = bool(item.get("is_seed", True))
            scale = max(0.15, min(1.0, float(item.get("scale", 1.0))))
            actor_set = {str(x).strip() for x in (item.get("actors") or []) if x and len(str(x).strip()) >= 3}
            tag_set = {str(x).strip() for x in (item.get("tags") or []) if x and len(str(x).strip()) >= 3}
            all_texts = actor_set | tag_set

            # 1. Direct Actor / Group Alias Mentions
            for text in all_texts:
                low = text.lower()
                is_direct_actor_field = text in actor_set
                for pat, gi, matched_alias in self._patterns:
                    if pat.search(low):
                        key = (gi, _norm_token(matched_alias), is_seed)
                        ev = mention_seen.get(key)
                        if ev is None:
                            base = W_MENTION * (1.25 if is_direct_actor_field else 1.0)
                            where = "seed indicator intel" if is_seed else f"linked asset ({defang_ioc(ioc_val)})"
                            ev = AttributionEvidence(
                                kind="mention",
                                detail=f'"{matched_alias}" matched in {where}',
                                base_weight=base,
                                dimension="reported" if is_seed else "infrastructure",
                                rarity=1.0,
                                scale=0.0,
                                matched_term=matched_alias,
                            )
                            mention_seen[key] = ev
                            cands.setdefault(gi, AttributionCandidate(self.groups[gi])).evidence.append(ev)
                        _touch(ev, ioc_val, scale)

            # 2. Software / Malware Family Overlap (Rarity-Weighted)
            malware_inputs = list(item.get("malware") or [])
            # Also scan tags for known software names in _sw_index
            for t in tag_set:
                nk = _norm_token(t)
                if nk in self._sw_index:
                    malware_inputs.append(t)

            for fam in malware_inputs:
                k = _norm_token(fam)
                if not k or k not in self._sw_index:
                    continue
                rar, df = self.software_rarity(k)
                canonical_sw = self._sw_canonical_name.get(k, fam)
                for gi in self._sw_index[k]:
                    key = (gi, k)
                    ev = sw_seen.get(key)
                    if ev is None:
                        tier_note = "rare/distinctive" if rar >= RARE_THRESHOLD else "shared/commodity"
                        ev = AttributionEvidence(
                            kind="software",
                            detail=f"{canonical_sw} is used by {self.groups[gi]['name']} ({tier_note}, {df} ATT&CK group(s))",
                            base_weight=W_SOFTWARE * rar * 2.0,
                            dimension="malware",
                            rarity=rar,
                            scale=0.0,
                            matched_term=canonical_sw,
                        )
                        sw_seen[key] = ev
                        cands.setdefault(gi, AttributionCandidate(self.groups[gi])).evidence.append(ev)
                    _touch(ev, ioc_val, scale)

            # 3. MITRE ATT&CK Technique Overlap
            for raw_tid in (item.get("techniques") or []):
                tid = str(raw_tid).strip().upper()
                if not tid:
                    continue
                for gi, g in enumerate(self.groups):
                    if tid in (g.get("techniques") or []):
                        d = tech_hits.setdefault(gi, {})
                        if tid not in d:
                            t_rar = self._idf_rarity(self._tech_df.get(tid, 1))
                            d[tid] = AttributionEvidence(
                                kind="technique",
                                detail=f"{tid} matches {g['name']} ATT&CK profile",
                                base_weight=W_TECHNIQUE * t_rar * 2.0,
                                dimension="ttp",
                                rarity=t_rar,
                                scale=0.0,
                                matched_term=tid,
                            )
                        _touch(d[tid], ioc_val, scale)

        # Attach technique evidence ONLY to candidates that already have a mention or software match
        # (Guard rail: Technique overlap alone can never invent an APT candidate)
        for gi, d in tech_hits.items():
            if gi not in cands:
                continue
            running_t = 0.0
            for ev in sorted(d.values(), key=lambda e: -e.weight):
                if running_t + ev.weight > TECHNIQUE_CAP:
                    break
                running_t += ev.weight
                cands[gi].evidence.append(ev)

        ranked: List[AttributionCandidate] = []
        for gi, c in cands.items():
            c.raw_score = sum(e.weight for e in c.evidence)
            conf = int(round(100.0 * (1.0 - math.exp(-c.raw_score / SATURATION))))

            strong_mention = any(e.kind == "mention" and e.scale >= MIN_PATH_SCALE for e in c.evidence)
            rare_sw_count = sum(
                1 for e in c.evidence
                if e.kind == "software" and e.rarity >= RARE_THRESHOLD and e.scale >= MIN_PATH_SCALE
            )

            if strong_mention or rare_sw_count >= 2:
                c.confidence = conf
            elif rare_sw_count == 1:
                c.confidence = min(conf, CAP_ONE_RARE)
                if conf > CAP_ONE_RARE:
                    c.capped_reason = "capped at Moderate (49%): only one distinctive malware family supports this group without direct mention"
            else:
                c.confidence = min(conf, CAP_COMMODITY)
                if conf > CAP_COMMODITY:
                    c.capped_reason = "capped at Low (20%): evidence is limited to commodity/shared tooling or weak graph hops"

            active_dims = {
                e.dimension for e in c.evidence
                if e.dimension in INDEPENDENT_DIMENSIONS and e.scale >= MIN_PATH_SCALE
            }
            if c.confidence >= 55 and len(active_dims) < 2:
                c.confidence = CAP_SINGLE_DIMENSION
                c.capped_reason = "capped at Moderate (54%): High confidence requires at least 2 independent evidence dimensions"

            ranked.append(c)

        ranked.sort(key=lambda c: (-c.confidence, -c.raw_score, c.group.get("name", "")))
        top_slice = ranked[: max(1, min(top_n, 15))]

        candidates_out = [
            c.to_dict(alternatives=[other for other in top_slice if other is not c])
            for c in top_slice
        ]

        return {
            "kb_meta": self.meta,
            "candidate_count": len(ranked),
            "top_candidate": candidates_out[0] if candidates_out else None,
            "candidates": candidates_out,
            "guard_rails_applied": [
                "Commodity tools (e.g. Cobalt Strike, Mimikatz, AsyncRAT) are rarity-penalized and capped at Low (20%) when seen alone.",
                "MITRE ATT&CK technique overlap is capped at 16 pts and never creates a candidate without malware or direct mention.",
                "High confidence (>=55%) requires corroboration across at least 2 independent dimensions (reported, infrastructure, malware, ttp).",
                "Victimology and operational tempo are explicitly marked as not assessed.",
            ],
            "note": (
                "No threat actor reached the evidence threshold. An indicator can be malicious without being attributable to a named APT group."
                if not candidates_out
                else "Attribution is probabilistic: shared tooling, reused infrastructure, and false flags can mislead. Treat as analyst hypotheses."
            ),
        }


_ATTRIBUTOR_LOCK = threading.Lock()
_ATTRIBUTOR_INSTANCE: Optional[RarityWeightedAttributor] = None


def get_attributor() -> RarityWeightedAttributor:
    global _ATTRIBUTOR_INSTANCE
    with _ATTRIBUTOR_LOCK:
        if _ATTRIBUTOR_INSTANCE is not None:
            return _ATTRIBUTOR_INSTANCE
        if BUNDLED_KB_PATH.exists():
            kb = json.loads(BUNDLED_KB_PATH.read_text(encoding="utf-8"))
        elif MISP_ACTOR_PATH.exists():
            raw_misp = json.loads(MISP_ACTOR_PATH.read_text(encoding="utf-8"))
            groups = []
            for v in raw_misp.get("values", []):
                meta = v.get("meta", {})
                groups.append({
                    "id": f"MISP-{str(v.get('uuid', ''))[:8]}",
                    "name": v.get("value", ""),
                    "aliases": [a for a in meta.get("synonyms", []) if len(a) >= 4],
                    "country": meta.get("country"),
                    "description": (v.get("description") or "")[:360],
                    "url": next(iter(meta.get("refs", [])), ""),
                    "source": "misp",
                    "software": [],
                    "techniques": [],
                })
            kb = {"meta": {"sources": ["MISP Galaxy threat-actor"], "group_count": len(groups)}, "groups": groups}
        else:
            kb = {"meta": {"sources": [], "group_count": 0}, "groups": []}
        _ATTRIBUTOR_INSTANCE = RarityWeightedAttributor(kb)
        return _ATTRIBUTOR_INSTANCE


# =============================================================================
# 4. PHASE 3: CONTEXT-AWARE DEFENSIVE PLAYBOOK & 3-QUESTION TRIAGE GENERATOR
# =============================================================================

def build_defensive_playbook(
    seed_asset: Dict[str, Any],
    assets: List[Dict[str, Any]],
    relationships: List[Dict[str, Any]],
    attribution: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Derives concrete, context-aware SOC defensive recommendations from the pivot graph,
    node roles, and attribution findings. Explicitly warns against blocking shared/CDN IPs.
    """
    actions: List[Dict[str, Any]] = []
    seed_val = seed_asset.get("value", "")
    seed_type = seed_asset.get("asset_type", "")
    seed_mal = seed_asset.get("maliciousness_context") or {}
    seed_roles = {r["role"] for r in (seed_asset.get("roles") or [])}
    seed_shared = "shared-infrastructure" in seed_roles or bool(seed_asset.get("shared_infra_flags"))

    c2_nodes = [
        a for a in assets
        if any(r["role"] == "c2-candidate" for r in (a.get("roles") or []))
    ]
    payload_nodes = [
        a for a in assets
        if any(r["role"] == "payload-host" for r in (a.get("roles") or []))
    ]
    shared_nodes = [
        a for a in assets
        if any(r["role"] == "shared-infrastructure" for r in (a.get("roles") or []))
        or bool(a.get("shared_infra_flags"))
    ]
    dns_nodes = [
        a for a in assets
        if any(r["role"] == "fast-flux-dns" for r in (a.get("roles") or []))
    ]
    cert_nodes = [a for a in assets if a.get("asset_type") == "certificate"]
    hash_nodes = [a for a in assets if a.get("asset_type") == "hash"]
    fp_nodes = [a for a in assets if a.get("asset_type") == "fingerprint"]
    weak_nodes = [
        a for a in assets
        if a.get("depth", 0) > 0
        and a.get("relationship_confidence", 0) < 45
        and a not in shared_nodes
    ]

    # 1. Shared / CDN Infrastructure Guard Rail (CRITICAL Outage Prevention)
    if shared_nodes:
        shared_vals = [defang_ioc(a["value"]) for a in shared_nodes[:5]]
        actions.append({
            "priority": "CRITICAL GUARD RAIL",
            "category": "Do Not Block by IP",
            "color": "amber",
            "icon": "fa-triangle-exclamation",
            "title": "Avoid IP-Level Blocking on Shared / CDN Infrastructure",
            "guidance": (
                f"Do NOT block shared hosting or CDN nodes by IP address ({', '.join(shared_vals)}); "
                "doing so can cause collateral outages across unrelated legitimate services. "
                "Enforce blocks strictly at the FQDN, URL path, or SSL/TLS certificate layer."
            ),
            "indicators": shared_vals,
        })

    # 2. C2 Candidate Blocking & Retro-Hunting
    if c2_nodes:
        c2_vals = [defang_ioc(a["value"]) for a in c2_nodes[:8]]
        actions.append({
            "priority": "HIGH",
            "category": "C2 Containment",
            "color": "red",
            "icon": "fa-Crosshairs",
            "title": f"Contain & Hunt {len(c2_nodes)} Likely C2 Node(s)",
            "guidance": (
                f"Block outbound connections to identified C2 candidate(s) ({', '.join(c2_vals)}) "
                "at perimeter firewalls/SWG (excluding shared CDN IPs) and run a 30-day retro-hunt "
                "across DNS, proxy, and EDR network telemetry for periodic beaconing."
            ),
            "indicators": c2_vals,
        })
    elif not seed_shared and (seed_mal.get("vt_malicious", 0) or 0) > 0:
        actions.append({
            "priority": "HIGH",
            "category": "Seed Triage",
            "color": "red",
            "icon": "fa-shield-halved",
            "title": f"Alert & Retro-Hunt Seed Indicator ({defang_ioc(seed_val)})",
            "guidance": (
                f"Seed indicator {defang_ioc(seed_val)} carries malicious telemetry. "
                "Query SIEM, DNS, proxy, and EDR logs for historical egress or DNS resolution."
            ),
            "indicators": [defang_ioc(seed_val)],
        })

    # 3. Payload Hosts & Open Directories
    if payload_nodes:
        pay_vals = [defang_ioc(a["value"]) for a in payload_nodes[:6]]
        actions.append({
            "priority": "HIGH",
            "category": "Payload Delivery",
            "color": "amber",
            "icon": "fa-file-shield",
            "title": f"Block {len(payload_nodes)} Payload Delivery / Staging Host(s)",
            "guidance": (
                f"Block HTTP/HTTPS downloads from identified payload staging endpoints ({', '.join(pay_vals)}) "
                "and inspect proxy/EDR file-creation events for binaries fetched from these hosts."
            ),
            "indicators": pay_vals,
        })

    # 4. Associated Malware Hashes
    if hash_nodes:
        h_vals = [a["value"] for a in hash_nodes[:6]]
        actions.append({
            "priority": "HIGH",
            "category": "EDR Endpoint Hunt",
            "color": "red",
            "icon": "fa-bug-slash",
            "title": f"Block & Hunt {len(hash_nodes)} Linked Malware Sample Hash(es)",
            "guidance": (
                "Add the associated file hashes to EDR prevention blocklists and hunt endpoint process/file "
                f"telemetry for execution or disk write events: {', '.join(h[:16] + '…' for h in h_vals)}."
            ),
            "indicators": h_vals,
        })

    # 5. TLS Certificates & JARM / JA3 / Favicon Fingerprints
    if cert_nodes or fp_nodes:
        fp_vals = [a["value"] for a in (cert_nodes + fp_nodes)[:5]]
        actions.append({
            "priority": "MEDIUM",
            "category": "Network / TLS Hunting",
            "color": "purple",
            "icon": "fa-certificate",
            "title": f"Hunt TLS / Fingerprint Artifacts ({len(cert_nodes)} Certs, {len(fp_nodes)} Fingerprints)",
            "guidance": (
                "Pivot across Zeek `ssl.log`, Suricata TLS alerts, and Certificate Transparency monitors "
                f"for shared certificates or server fingerprints ({', '.join(fp_vals[:4])}) to uncover "
                "dormant sibling C2 servers before domain rotation."
            ),
            "indicators": fp_vals,
        })

    # 6. Dynamic DNS / Rotating IPs
    if dns_nodes:
        dns_vals = [defang_ioc(a["value"]) for a in dns_nodes[:5]]
        actions.append({
            "priority": "MEDIUM",
            "category": "DNS Monitoring",
            "color": "blue",
            "icon": "fa-globe",
            "title": f"Monitor {len(dns_nodes)} Dynamic / Fast-Flux DNS Domain(s)",
            "guidance": (
                f"Domain(s) {', '.join(dns_vals)} exhibit dynamic DNS or multi-IP rotation behavior. "
                "Alert on DNS queries to the parent FQDN rather than relying on static IP firewall blocks."
            ),
            "indicators": dns_vals,
        })

    # 7. Weakly Linked Nodes Guard Rail
    if weak_nodes:
        w_vals = [defang_ioc(a["value"]) for a in weak_nodes[:5]]
        actions.append({
            "priority": "LOW / GUARD RAIL",
            "category": "Hunting Leads Only",
            "color": "slate",
            "icon": "fa-magnifying-glass",
            "title": f"Treat {len(weak_nodes)} Weakly Linked Node(s) as Hunting Leads Only",
            "guidance": (
                f"Do not auto-block the {len(weak_nodes)} low-confidence node(s) (<45% relationship confidence); "
                "use them only for passive correlation in SIEM searches."
            ),
            "indicators": w_vals,
        })

    # 8. Attributed Actor TTP Coverage
    top_cand = attribution.get("top_candidate")
    if top_cand:
        ev_techs = [
            e["matched_term"] for e in top_cand.get("evidence", [])
            if e.get("kind") == "technique" and e.get("matched_term")
        ]
        actions.append({
            "priority": "MEDIUM",
            "category": "Detection Engineering",
            "color": "yellow",
            "icon": "fa-user-secret",
            "title": f"Validate Detection Coverage for {top_cand['name']} Hypothesis ({top_cand['confidence_label']})",
            "guidance": (
                f"Review Sigma and SIEM detection rules mapped to {top_cand['name']}"
                + (f" techniques ({', '.join(ev_techs[:6])})" if ev_techs else "")
                + ". Keep in mind attribution is an analytical hypothesis."
            ),
            "indicators": [top_cand["name"]] + ev_techs[:5],
        })

    if not actions:
        actions.append({
            "priority": "INFO",
            "category": "Baseline Monitoring",
            "color": "slate",
            "icon": "fa-circle-check",
            "title": f"No High-Risk Infrastructure Links Confirmed for {defang_ioc(seed_val)}",
            "guidance": (
                "No direct C2 candidates or malware distribution links were identified in the current provider set. "
                "Re-run with Deep Pivot or additional API providers if suspicious activity persists."
            ),
            "indicators": [defang_ioc(seed_val)],
        })

    return actions


def build_i2a_investigation_assessment(
    assets: List[Dict[str, Any]],
    relationships: List[Dict[str, Any]],
    observations: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Runs the full 3-phase I2A ("IOC -> Infrastructure -> Actor") pipeline on an investigation:
    1. Assigns node roles to every asset (`assess_asset_roles`).
    2. Extracts signals from assets/observations and runs `RarityWeightedAttributor`.
    3. Builds the 3-Question Executive Triage summary (`what`, `connected`, `who`) and
       the `defensive_playbook`.
    """
    if not assets:
        return {
            "three_questions": {},
            "attribution": {"candidates": [], "top_candidate": None},
            "defensive_playbook": [],
            "role_counts": {},
        }

    # Phase 1: Assess roles on all graph nodes
    assess_asset_roles(assets, relationships)

    seed_asset = next((a for a in assets if a.get("depth") == 0), assets[0])

    # Gather attribution inputs across all nodes in the graph, scaled by relationship_confidence
    attr_inputs: List[Dict[str, Any]] = []
    all_malware: Set[str] = set()
    all_techniques: Set[str] = set()
    earliest_dates: List[Tuple[str, str]] = []

    for a in assets:
        is_seed = a.get("depth", 0) == 0
        scale = 1.0 if is_seed else (float(a.get("relationship_confidence", 50)) / 100.0)
        mal = a.get("maliciousness_context") or {}
        meta = a.get("metadata") or {}

        actors: List[str] = []
        tags: List[str] = []
        malware: List[str] = []
        techniques: List[str] = []

        for k, v in {**meta, **mal}.items():
            if not v:
                continue
            kl = str(k).lower()
            v_str = str(v) if not isinstance(v, list) else ", ".join(str(x) for x in v)
            if any(w in kl for w in ("actor", "adversary", "apt", "group", "intrusion")):
                actors.append(v_str)
            elif any(w in kl for w in ("malware", "family", "tool", "implant", "rat", "ransomware")):
                for part in re.split(r"[,;/|]+", v_str):
                    p = part.strip()
                    if p and p.lower() not in {"none", "unknown", "n/a", "true", "false"}:
                        malware.append(p)
                        all_malware.add(p)
            else:
                tags.append(v_str)

            for tm in _TECHNIQUE_EXTRACT_RE.findall(v_str):
                techniques.append(tm.upper())
                all_techniques.add(tm.upper())

        if a.get("first_seen"):
            prov = (a.get("providers") or ["observed"])[0]
            earliest_dates.append((str(a["first_seen"])[:10], prov))

        attr_inputs.append({
            "ioc": a.get("value", ""),
            "is_seed": is_seed,
            "scale": scale,
            "actors": actors,
            "tags": tags,
            "malware": malware,
            "techniques": techniques,
        })

    # Also scan observation summaries & values for malware/actor/technique mentions
    obs_tags: List[str] = []
    obs_techs: List[str] = []
    for o in observations[:200]:
        for field_key in ("field_value", "summary"):
            txt = str(o.get(field_key) or "").strip()
            if txt:
                obs_tags.append(txt)
                for tm in _TECHNIQUE_EXTRACT_RE.findall(txt):
                    obs_techs.append(tm.upper())
                    all_techniques.add(tm.upper())
        if o.get("first_seen"):
            earliest_dates.append((str(o["first_seen"])[:10], o.get("provider", "intel")))

    if obs_tags or obs_techs:
        attr_inputs.append({
            "ioc": seed_asset.get("value", ""),
            "is_seed": True,
            "scale": 0.85,
            "actors": [],
            "tags": obs_tags[:80],
            "malware": [],
            "techniques": obs_techs,
        })

    # Phase 2: Rarity-weighted attribution
    attributor = get_attributor()
    attribution = attributor.evaluate(attr_inputs, top_n=5)

    # Also record any software matched from tags into all_malware for the summary card
    for cand in attribution.get("candidates", [])[:3]:
        for ev in cand.get("evidence", []):
            if ev.get("kind") == "software" and ev.get("matched_term"):
                all_malware.add(ev["matched_term"])

    # Phase 3: Build Defensive Playbook & 3-Question Summary
    playbook = build_defensive_playbook(seed_asset, assets, relationships, attribution)

    # Count asset types and roles
    type_counts: Dict[str, int] = {}
    role_counts: Dict[str, int] = {}
    for a in assets:
        for r in a.get("roles") or []:
            role_counts[r["role"]] = role_counts.get(r["role"], 0) + 1
        if a.get("depth", 0) > 0:
            t = a.get("asset_type", "other")
            type_counts[t] = type_counts.get(t, 0) + 1

    # Question 1: What is this IOC?
    seed_mal = seed_asset.get("maliciousness_context") or {}
    native_telemetry: List[str] = []
    if "vt_malicious" in seed_mal:
        native_telemetry.append(f"VirusTotal: {seed_mal['vt_malicious']} malicious detections")
    if "greynoise_classification" in seed_mal:
        native_telemetry.append(f"GreyNoise: {seed_mal['greynoise_classification']}")
    if "threatfox_malware" in seed_mal:
        native_telemetry.append(f"ThreatFox: {seed_mal['threatfox_malware']}")
    if "urlhaus_threat" in seed_mal:
        native_telemetry.append(f"URLhaus: {seed_mal['urlhaus_threat']}")
    if "otx_pulse_count" in seed_mal:
        native_telemetry.append(f"AlienVault OTX: {seed_mal['otx_pulse_count']} pulse(s)")

    seed_meta = seed_asset.get("metadata") or {}
    for mk, mlbl in (("asn", "ASN"), ("isp", "ISP"), ("whois_netname", "Netblock"), ("bgp_prefix", "BGP Prefix"), ("country", "Country")):
        if seed_meta.get(mk):
            native_telemetry.append(f"{mlbl}: {seed_meta[mk]}")

    valid_dates = [(d, s) for d, s in earliest_dates if re.match(r"^\d{4}-\d{2}-\d{2}", d)]
    earliest_obs = min(valid_dates, key=lambda x: x[0]) if valid_dates else None

    c2_candidates = [
        defang_ioc(a["value"]) for a in assets
        if any(r["role"] == "c2-candidate" for r in (a.get("roles") or []))
    ]
    payload_hosts = [
        defang_ioc(a["value"]) for a in assets
        if any(r["role"] == "payload-host" for r in (a.get("roles") or []))
    ]
    shared_guards = [
        f"{defang_ioc(a['value'])} ({', '.join(a.get('shared_infra_flags') or ['shared'])})"
        for a in assets
        if any(r["role"] == "shared-infrastructure" for r in (a.get("roles") or []))
    ]

    top_actor = attribution.get("top_candidate")

    three_questions = {
        "what": {
            "ioc": seed_asset.get("value", ""),
            "defanged": defang_ioc(seed_asset.get("value", "")),
            "type": seed_asset.get("asset_type", "").upper(),
            "roles": seed_asset.get("roles") or [],
            "native_telemetry": native_telemetry[:6],
            "first_observed": {"date": earliest_obs[0], "source": earliest_obs[1]} if earliest_obs else None,
            "malware_families": sorted(all_malware)[:8],
        },
        "connected": {
            "total_discovered": max(0, len(assets) - 1),
            "total_relationships": len(relationships),
            "type_counts": type_counts,
            "role_counts": role_counts,
            "c2_candidates": c2_candidates[:6],
            "payload_hosts": payload_hosts[:6],
            "shared_infra_guards": shared_guards[:6],
        },
        "who": {
            "top_candidate": top_actor,
            "candidate_count": attribution.get("candidate_count", 0),
            "statement": top_actor["statement"] if top_actor else attribution.get("note", ""),
            "techniques": sorted(all_techniques)[:10],
        },
    }

    return {
        "three_questions": three_questions,
        "attribution": attribution,
        "defensive_playbook": playbook,
        "role_counts": role_counts,
    }


def enrich_ioc_query(
    indicator: str,
    ioc_type: str = "auto",
    query_results: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Enriches an IOC Search query directly using the LeenAdeeb / IOC-Enricher methodology:
    1. Canonicalizes & refangs defanged inputs (`evil[.]com`, `hxxps://...`, `1[.]1[.]1[.]1`).
    2. Builds seed asset and maps multi-provider signals (VT detections, ThreatFox C2,
       URLhaus threats, Shodan ports/services, GreyNoise RIOT, OTX pulses/actors).
    3. Discovers linked infrastructure (co-hosted domains, resolved IPs, downloaded hashes).
    4. Evaluates functional node role hypotheses (`c2-candidate`, `payload-host`, `shared-infrastructure`,
       `fast-flux-dns`, `shared-certificate`).
    5. Evaluates explainable Rarity-Weighted APT Attribution with commodity caps and guard rails.
    6. Generates Context-Aware Defensive Playbook (e.g. 'Do Not Block by IP' for CDNs/shared infra,
       EDR hunt queries, firewall containment).
    7. Synthesizes Executive 3-Question Triage ('1. What is this IOC? 2. What is it connected to? 3. Who might be behind it?').
    """
    raw_ind = str(indicator or "").strip()
    clean_val = refang_ioc(raw_ind)
    results = query_results or {}

    # Infer IOC type if needed
    t = str(ioc_type or "").strip().lower()
    if t in {"", "auto", "keyword", "infra"}:
        if intel_query.is_ip(clean_val):
            t = "ip"
        elif intel_query.is_url(clean_val):
            t = "url"
        elif intel_query.is_hash(clean_val):
            t = "hash"
        elif intel_query.is_domain(clean_val):
            t = "domain"
        else:
            t = "domain" if "." in clean_val else "keyword"

    seed_id = f"{t}:{clean_val}"
    metadata: Dict[str, Any] = {}
    mal_context: Dict[str, Any] = {}
    shared_flags: List[str] = []
    actors: List[str] = []
    malware: List[str] = []
    techniques: List[str] = []
    tags: List[str] = []
    earliest_dates: List[Tuple[str, str]] = []

    # Providers
    vt = results.get("virustotal") or {}
    tf = results.get("threatfox") or {}
    uh = results.get("urlhaus") or {}
    otx = results.get("otx") or {}
    aip = results.get("abuseipdb") or {}
    gn = results.get("greynoise") or {}
    shodan = results.get("shodan") or {}
    censys = results.get("censys") or {}
    ha = results.get("hybrid-analysis") or results.get("hybrid_analysis") or {}
    triage = results.get("triage") or {}
    misp = results.get("misp") or {}
    dnsdumpster = results.get("dnsdumpster") or {}

    # 1. VirusTotal
    if isinstance(vt, dict) and not vt.get("error"):
        mal_count = vt.get("malicious") or vt.get("positives") or 0
        if isinstance(mal_count, int) and mal_count > 0:
            mal_context["vt_malicious"] = mal_count
            mal_context["vt_total"] = vt.get("total") or 0
        pop = vt.get("popular_threat_classification") or {}
        sugg = pop.get("suggested_threat_label")
        if sugg:
            malware.append(str(sugg))
        for pop_item in pop.get("popular_threat_name") or []:
            if isinstance(pop_item, dict) and pop_item.get("value"):
                malware.append(str(pop_item["value"]))
        for tg in vt.get("tags") or []:
            tags.append(str(tg))
        if vt.get("as_owner"):
            metadata.setdefault("isp", vt.get("as_owner"))
        if vt.get("asn"):
            metadata.setdefault("asn", f"AS{vt.get('asn')}")
        if vt.get("country"):
            metadata.setdefault("country", vt.get("country"))
        if vt.get("first_submission_date"):
            try:
                fs_ts = int(vt["first_submission_date"])
                dt = datetime.fromtimestamp(fs_ts, timezone.utc).strftime("%Y-%m-%d")
                earliest_dates.append((dt, "VirusTotal"))
            except Exception:
                pass

    # 2. ThreatFox
    if isinstance(tf, dict) and not tf.get("error"):
        tf_data = tf.get("data") if isinstance(tf.get("data"), list) else ([tf] if tf.get("malware_printable") or tf.get("malware") else [])
        for entry in tf_data:
            if isinstance(entry, dict):
                mw = entry.get("malware_printable") or entry.get("malware")
                if mw and mw.lower() not in {"none", "unknown"}:
                    mal_context["threatfox_malware"] = mw
                    malware.append(mw)
                ttype = entry.get("threat_type")
                if ttype:
                    mal_context["threatfox_type"] = ttype
                    tags.append(ttype)
                for t_item in entry.get("tags") or []:
                    tags.append(str(t_item))
                if entry.get("first_seen"):
                    earliest_dates.append((str(entry["first_seen"])[:10], "ThreatFox"))

    # 3. URLhaus
    if isinstance(uh, dict) and not uh.get("error"):
        threat = uh.get("threat")
        if threat:
            mal_context["urlhaus_threat"] = threat
            tags.append(threat)
        for tg in uh.get("tags") or []:
            tags.append(str(tg))
        for pl in uh.get("payloads") or []:
            if isinstance(pl, dict) and pl.get("signature"):
                malware.append(pl["signature"])
        if uh.get("date_added"):
            earliest_dates.append((str(uh["date_added"])[:10], "URLhaus"))

    # 4. AlienVault OTX
    if isinstance(otx, dict) and not otx.get("error"):
        pulses = otx.get("pulses") or (otx.get("pulse_info") or {}).get("pulses") or []
        if pulses:
            mal_context["otx_pulse_count"] = len(pulses)
        for p in pulses:
            if not isinstance(p, dict):
                continue
            if p.get("adversary"):
                actors.append(p["adversary"])
            for mf in p.get("malware_families") or []:
                malware.append(str(mf))
            for tg in p.get("tags") or []:
                tags.append(str(tg))
            for att in p.get("attack_ids") or []:
                techniques.append(str(att).upper())
            if p.get("created"):
                earliest_dates.append((str(p["created"])[:10], "AlienVault OTX"))

    # 5. AbuseIPDB
    if isinstance(aip, dict) and not aip.get("error"):
        score = aip.get("abuseConfidenceScore")
        if score is not None:
            mal_context["abuseipdb_score"] = score
        if aip.get("isp"):
            metadata.setdefault("isp", aip["isp"])
        if aip.get("countryCode"):
            metadata.setdefault("country", aip["countryCode"])
        if aip.get("domain"):
            metadata.setdefault("domain", aip["domain"])

    # 6. GreyNoise
    if isinstance(gn, dict) and not gn.get("error"):
        cls = gn.get("classification")
        if cls:
            mal_context["greynoise_classification"] = cls
        if gn.get("riot") is True:
            mal_context["greynoise_riot"] = True
            shared_flags.append("GreyNoise RIOT (Verified Benign Business Service)")
        if gn.get("actor"):
            actors.append(gn["actor"])
        for tg in gn.get("tags") or []:
            tags.append(str(tg))

    # 7. Shodan & Censys
    for s_src in (shodan, censys):
        if isinstance(s_src, dict) and not s_src.get("error"):
            ports = s_src.get("ports") or []
            if isinstance(ports, list) and ports:
                metadata["ports"] = sorted(set(metadata.get("ports", []) + [int(p) for p in ports if str(p).isdigit()]))
            if s_src.get("asn"):
                metadata.setdefault("asn", s_src["asn"])
            if s_src.get("org") or s_src.get("isp"):
                metadata.setdefault("isp", s_src.get("org") or s_src.get("isp"))
            if s_src.get("country") or s_src.get("country_name"):
                metadata.setdefault("country", s_src.get("country") or s_src.get("country_name"))
            if s_src.get("jarm"):
                metadata.setdefault("jarm", s_src["jarm"])

    # 8. Hybrid Analysis & Triage
    if isinstance(ha, dict) and not ha.get("error"):
        vx = ha.get("vx_family")
        if vx:
            malware.append(vx)
        for att in ha.get("mitre_attcks") or []:
            techniques.append(str(att).upper())
        for tg in ha.get("tags") or []:
            tags.append(str(tg))
    if isinstance(triage, dict) and not triage.get("error"):
        fam = triage.get("family")
        if fam:
            malware.append(fam)
        for sig in triage.get("signatures") or []:
            if isinstance(sig, dict) and sig.get("label"):
                tags.append(sig["label"])

    # 9. MISP
    if isinstance(misp, dict) and not misp.get("error"):
        for cluster in misp.get("galaxy") or []:
            if isinstance(cluster, dict) and cluster.get("value"):
                actors.append(cluster["value"])

    # Shared Infrastructure Detection: CDN / Cloudflare / Fastly / Akamai / Dynamic DNS
    isp_text = f"{metadata.get('isp', '')} {metadata.get('asn', '')} {clean_val}".lower()
    for cdn_kw in ("cloudflare", "akamai", "fastly", "cloudfront", "azure front door", "incapsula", "imperva", "sucuri", "google user content"):
        if cdn_kw in isp_text and not any(cdn_kw in f.lower() for f in shared_flags):
            shared_flags.append(f"Shared CDN / Multi-Tenant ({cdn_kw.title()})")

    if t == "domain":
        dyn_suffix = is_dynamic_dns_domain(clean_val)
        if dyn_suffix:
            shared_flags.append(f"Dynamic DNS Provider ({dyn_suffix})")

    # Linked Infrastructure & Relationships Extraction
    linked_assets: List[Dict[str, Any]] = []
    relationships: List[Dict[str, Any]] = []

    # Domains / Hostnames from IP
    if t == "ip":
        hosts_found = set()
        for h in shodan.get("hostnames") or []:
            if isinstance(h, str) and intel_query.is_domain(h):
                hosts_found.add(h.lower())
        for r_entry in vt.get("resolutions") or []:
            if isinstance(r_entry, dict):
                h = r_entry.get("host_name") or r_entry.get("hostname")
                if h and intel_query.is_domain(h):
                    hosts_found.add(h.lower())
        for r_host in (dnsdumpster.get("dns_records") or {}).get("host") or []:
            if isinstance(r_host, dict) and r_host.get("domain") and intel_query.is_domain(r_host["domain"]):
                hosts_found.add(r_host["domain"].lower())

        for idx, dom in enumerate(sorted(hosts_found)[:25]):
            target_id = f"domain:{dom}"
            linked_assets.append({
                "asset_id": target_id,
                "asset_type": "domain",
                "value": dom,
                "depth": 1,
                "relationship_confidence": 80,
                "providers": ["shodan", "virustotal", "dnsdumpster"],
            })
            relationships.append({
                "source": seed_id,
                "target": target_id,
                "relationship_type": "hosts",
                "relationship_confidence": 80,
            })

    # Resolved IPs from Domain
    elif t == "domain":
        ips_found = set()
        for r_entry in vt.get("last_dns_records") or vt.get("resolutions") or []:
            if isinstance(r_entry, dict):
                ip_addr = r_entry.get("ip_address") or r_entry.get("value")
                if ip_addr and intel_query.is_ip(ip_addr):
                    ips_found.add(ip_addr)
        for d_ip in (dnsdumpster.get("dns_records") or {}).get("dns") or []:
            if isinstance(d_ip, dict) and d_ip.get("ip") and intel_query.is_ip(d_ip["ip"]):
                ips_found.add(d_ip["ip"])

        for idx, ip_val in enumerate(sorted(ips_found)[:15]):
            target_id = f"ip:{ip_val}"
            linked_assets.append({
                "asset_id": target_id,
                "asset_type": "ip",
                "value": ip_val,
                "depth": 1,
                "relationship_confidence": 85,
                "providers": ["virustotal", "dnsdumpster"],
            })
            relationships.append({
                "source": seed_id,
                "target": target_id,
                "relationship_type": "resolves_to",
                "relationship_confidence": 85,
            })

    # Communicating / Downloaded Samples (Hashes)
    hashes_found = set()
    for s_list in (vt.get("communicating_samples") or [], vt.get("downloaded_samples") or []):
        for s_item in s_list:
            if isinstance(s_item, dict):
                sh = s_item.get("sha256") or s_item.get("id") or s_item.get("md5")
                if sh and intel_query.is_hash(sh):
                    hashes_found.add(sh.lower())
    for idx, h_val in enumerate(sorted(hashes_found)[:8]):
        target_id = f"hash:{h_val}"
        linked_assets.append({
            "asset_id": target_id,
            "asset_type": "hash",
            "value": h_val,
            "depth": 1,
            "relationship_confidence": 80,
            "providers": ["virustotal"],
        })
        relationships.append({
            "source": seed_id,
            "target": target_id,
            "relationship_type": "delivers",
            "relationship_confidence": 80,
        })

    # Build unique clean actor/malware/technique/tag lists
    mal_context["actors"] = sorted(set(actors))
    mal_context["malware"] = sorted(set(malware))
    mal_context["techniques"] = sorted(set(techniques))
    mal_context["tags"] = sorted(set(tags))

    seed_asset = {
        "asset_id": seed_id,
        "asset_type": t,
        "value": clean_val,
        "depth": 0,
        "providers": list(results.keys()),
        "metadata": metadata,
        "maliciousness_context": mal_context,
        "shared_infra_flags": shared_flags,
    }

    all_assets = [seed_asset] + linked_assets

    # Run full assessment pipeline
    assessment = build_i2a_investigation_assessment(all_assets, relationships, [])
    assessment["indicator"] = clean_val
    assessment["defanged"] = defang_ioc(clean_val)
    assessment["ioc_type"] = t
    return assessment
