"""
SIGMA Repository Manager & Data Provider
Handles rule indexing, full-text & faceted search, CRUD with tombstoning,
statistical analytics, emerging threat classification, and MITRE ATT&CK matrix mapping.
"""

import os
import re
import json
import uuid
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

import threading

import yaml
from sigma_engine import validate_rule_yaml, extract_tags_and_mitre
from sigma_updater import REPOSITORIES, add_tombstone, load_tombstones, seed_all_repositories, sync_repository

logger = logging.getLogger("sigma_repos")
BASE_DIR = Path(__file__).resolve().parent
SIGMA_DATA_DIR = BASE_DIR / "data" / "sigma-rules"

# In-memory rule cache
_RULES_CACHE: List[Dict[str, Any]] = []
_RULES_BY_KEY: Dict[str, Dict[str, Any]] = {}  # key: f"{repo_id}/{filename}"
_LAST_INDEX_TIME: Optional[float] = None

# MITRE ATT&CK Enterprise tactics taxonomy
MITRE_TACTICS = [
    {"id": "TA0043", "short": "reconnaissance", "name": "Reconnaissance"},
    {"id": "TA0042", "short": "resource_development", "name": "Resource Development"},
    {"id": "TA0001", "short": "initial_access", "name": "Initial Access"},
    {"id": "TA0002", "short": "execution", "name": "Execution"},
    {"id": "TA0003", "short": "persistence", "name": "Persistence"},
    {"id": "TA0004", "short": "privilege_escalation", "name": "Privilege Escalation"},
    {"id": "TA0005", "short": "defense_evasion", "name": "Defense Evasion"},
    {"id": "TA0006", "short": "credential_access", "name": "Credential Access"},
    {"id": "TA0007", "short": "discovery", "name": "Discovery"},
    {"id": "TA0008", "short": "lateral_movement", "name": "Lateral Movement"},
    {"id": "TA0009", "short": "collection", "name": "Collection"},
    {"id": "TA0011", "short": "command_and_control", "name": "Command and Control"},
    {"id": "TA0010", "short": "exfiltration", "name": "Exfiltration"},
    {"id": "TA0040", "short": "impact", "name": "Impact"},
]

TECHNIQUE_NAMES = {
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1105": "Ingress Tool Transfer",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1489": "Service Stop",
    "T1190": "Exploit Public-Facing Application",
    "T1027": "Obfuscated Files or Information",
    "T1003": "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1003.002": "Security Account Manager",
    "T1003.006": "DCSync",
    "T1218": "System Binary Proxy Execution",
    "T1218.005": "Mshta",
    "T1218.011": "Rundll32",
    "T1204.002": "Malicious File",
    "T1047": "Windows Management Instrumentation",
    "T1021.001": "Remote Desktop Protocol",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1561.002": "Disk Structure Wipe",
    "T1098": "Account Manipulation",
    "T1558.001": "Golden Ticket",
    "T1210": "Exploitation of Remote Services",
    "T1053.005": "Scheduled Task",
    "T1562.001": "Disable or Modify Tools",
    "T1112": "Modify Registry",
    "T1087.002": "Domain Account",
    "T1069.002": "Domain Groups",
    "T1570": "Lateral Tool Transfer",
    "T1071": "Application Layer Protocol",
    "T1566.001": "Spearphishing Attachment",
    "T1595": "Active Scanning",
}

RANSOMWARE_TAGS = {"ransomware", "lockbit", "akira", "blackcat", "alphv", "conti", "ryuk", "babuk", "clop", "darkside", "medusa", "caddywiper", "wiper"}
APT_TAGS = {"apt28", "apt29", "lazarus", "sandworm", "volt_typhoon", "turla", "muddywater", "noblebaron", "fancybear", "cozybear"}
LOLBAS_TAGS = {"lolbas", "certutil", "mshta", "rundll32", "regsvr32", "powershell", "wmic", "vssadmin", "bcdedit", "schtasks"}


# Reentrant: _build_index() re-enters index_rules(force=True) after seeding.
_INDEX_LOCK = threading.RLock()
_WARM_ACTIVE = False
_WARM_LOCK = threading.Lock()


def warm_index() -> bool:
    """Build the rule index in the background. Returns True when it started.

    Parsing ~9.5k YAML rule files takes ~30s. Doing that inside the first
    request left /api/sigma/repos, /api/sigma/stats and /api/sigma/rules looking
    like they had hung; the UI polled them again and stacked the work.
    """
    global _WARM_ACTIVE
    if os.environ.get("MANTIS_SIGMA_WARM", "1").strip().lower() in ("0", "false", "no"):
        return False
    if _RULES_CACHE:
        return False
    with _WARM_LOCK:
        if _WARM_ACTIVE:
            return False
        _WARM_ACTIVE = True

    def _run() -> None:
        global _WARM_ACTIVE
        try:
            index_rules()
            logger.info("sigma rule index warm: %d rules", len(_RULES_CACHE or []))
        except Exception as e:  # pragma: no cover - defensive
            logger.warning("sigma warm index failed: %s", e)
        finally:
            with _WARM_LOCK:
                _WARM_ACTIVE = False

    threading.Thread(target=_run, name="mantis-sigma-index", daemon=True).start()
    return True


def index_rules(force: bool = False) -> List[Dict[str, Any]]:
    """Scan and index all Sigma rules across all configured repository folders."""
    global _RULES_CACHE, _RULES_BY_KEY, _LAST_INDEX_TIME

    if not force and _RULES_CACHE:
        return _RULES_CACHE
    with _INDEX_LOCK:
        # A concurrent caller may have finished the build while we waited.
        if not force and _RULES_CACHE:
            return _RULES_CACHE
        return _build_index()


def _build_index() -> List[Dict[str, Any]]:
    global _RULES_CACHE, _RULES_BY_KEY, _LAST_INDEX_TIME

    rules = []
    by_key = {}
    tombstones = load_tombstones()

    if not SIGMA_DATA_DIR.exists():
        SIGMA_DATA_DIR.mkdir(parents=True, exist_ok=True)
        seed_all_repositories()

    for repo_id in REPOSITORIES.keys():
        repo_dir = SIGMA_DATA_DIR / repo_id
        if not repo_dir.exists():
            repo_dir.mkdir(parents=True, exist_ok=True)
            continue

        for file_path in repo_dir.rglob("*"):
            if not file_path.is_file() or file_path.suffix.lower() not in (".yml", ".yaml"):
                continue

            rel_file = file_path.relative_to(repo_dir).as_posix()
            base_filename = file_path.name
            rel_path = f"{repo_id}/{rel_file}"

            # Check tombstone
            if base_filename in tombstones or rel_file in tombstones or rel_path in tombstones:
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                try:
                    parsed = yaml.safe_load(content)
                except Exception:
                    try:
                        docs = list(yaml.safe_load_all(content))
                        parsed = next((d for d in docs if isinstance(d, dict) and "title" in d), None)
                    except Exception:
                        parsed = None

                if not isinstance(parsed, dict) or "title" not in parsed:
                    continue

                rule_id = str(parsed.get("id") or base_filename)
                raw_tags = parsed.get("tags") or []
                if isinstance(raw_tags, str):
                    raw_tags = [raw_tags]
                tags = [str(t).strip() for t in raw_tags if t is not None and str(t).strip()]

                parsed_tags = extract_tags_and_mitre(tags)
                logsource = parsed.get("logsource") or {}
                if not isinstance(logsource, dict):
                    logsource = {}

                # Emerging threat classification flags
                cves = parsed_tags.get("cves") or []
                # Also check title/description for CVE-YYYY-NNNN
                raw_author = parsed.get("author")
                author_str = ", ".join(str(a) for a in raw_author) if isinstance(raw_author, (list, tuple)) else str(raw_author or "Unknown")
                raw_desc = parsed.get("description")
                desc_str = " ".join(str(d) for d in raw_desc) if isinstance(raw_desc, (list, tuple)) else str(raw_desc or "")

                text_corpus = f"{parsed.get('title', '')} {desc_str}".upper()
                cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', text_corpus)
                for cve_m in cve_matches:
                    cve_clean = cve_m.lower()
                    if cve_clean not in cves:
                        cves.append(cve_clean)

                tags_clean = [str(t).lower() for t in tags if t]
                is_ransomware = any(t in RANSOMWARE_TAGS for t in tags_clean) or any(t in text_corpus.lower() for t in ("ransomware", "lockbit", "akira", "blackcat", "wiper"))
                is_apt = any(t in APT_TAGS for t in tags_clean) or any(t in text_corpus.lower() for t in ("apt28", "apt29", "lazarus", "sandworm", "volt typhoon"))
                is_lolbas = any(t in LOLBAS_TAGS for t in tags_clean) or ("lolbas" in text_corpus.lower())
                is_emerging = bool(cves) or is_ransomware or is_apt or is_lolbas or ("emerging" in tags_clean)

                item = {
                    "key": rel_path,
                    "repo_id": repo_id,
                    "repo_name": REPOSITORIES.get(repo_id, {}).get("name", repo_id),
                    "filename": rel_file,
                    "file_path": str(file_path),
                    "id": rule_id,
                    "title": str(parsed.get("title") or "Untitled Rule"),
                    "status": str(parsed.get("status") or "stable").lower(),
                    "level": str(parsed.get("level") or "medium").lower(),
                    "description": desc_str.strip(),
                    "author": author_str.strip(),
                    "date": str(parsed.get("date", "")),
                    "modified": str(parsed.get("modified", "")),
                    "references": parsed.get("references") or [],
                    "tags": tags,
                    "mitre_tactics": parsed_tags.get("tactics", []),
                    "mitre_techniques": parsed_tags.get("techniques", []),
                    "cves": cves,
                    "logsource": {
                        "category": str(logsource.get("category") or "general").lower(),
                        "product": str(logsource.get("product") or "generic").lower(),
                        "service": str(logsource.get("service") or "").lower(),
                    },
                    "falsepositives": parsed.get("falsepositives") or [],
                    "is_emerging": is_emerging,
                    "is_ransomware": is_ransomware,
                    "is_apt": is_apt,
                    "is_lolbas": is_lolbas,
                    "is_cve": bool(cves),
                    "size_bytes": len(content),
                    "valid": True
                }

                rules.append(item)
                by_key[rel_path] = item
                by_key[f"{repo_id}/{base_filename}"] = item
                by_key[rule_id] = item
                by_key[base_filename] = item

            except Exception as e:
                logger.warning(f"Error parsing Sigma rule {file_path}: {e}")

        # If zero rules found in all dirs, seed them!
    if not rules:
        seed_all_repositories()
        return index_rules(force=True)

    _RULES_CACHE = sorted(rules, key=lambda x: (x["title"].lower()))
    _RULES_BY_KEY = by_key
    _LAST_INDEX_TIME = datetime.utcnow().timestamp()
    return _RULES_CACHE


def get_repositories() -> List[Dict[str, Any]]:
    """Return all repositories with their active indexed rule count."""
    rules = index_rules()
    counts = {}
    for r in rules:
        rep = r["repo_id"]
        counts[rep] = counts.get(rep, 0) + 1

    repo_list = []
    for rep_id, meta in REPOSITORIES.items():
        repo_list.append({
            "id": rep_id,
            "name": meta["name"],
            "url": meta["url"],
            "description": meta["description"],
            "branch": meta.get("branch", ""),
            "count": counts.get(rep_id, 0)
        })
    return repo_list


def search_rules(
    query: str = "",
    repos: Optional[List[str]] = None,
    level: Optional[str] = None,
    status: Optional[str] = None,
    logsource_product: Optional[str] = None,
    logsource_category: Optional[str] = None,
    author: Optional[str] = None,
    mitre_id: Optional[str] = None,
    tag: Optional[str] = None,
    cve: Optional[str] = None,
    page: int = 1,
    page_size: int = 24
) -> Dict[str, Any]:
    """Search and filter rules with pagination."""
    all_rules = index_rules()
    filtered = []

    q_lower = query.lower().strip() if query else ""
    repos_set = set(repos) if repos else None
    level_lower = level.lower().strip() if level else None
    status_lower = status.lower().strip() if status else None
    prod_lower = logsource_product.lower().strip() if logsource_product else None
    cat_lower = logsource_category.lower().strip() if logsource_category else None
    author_lower = author.lower().strip() if author else None
    mitre_lower = mitre_id.lower().strip() if mitre_id else None
    tag_lower = tag.lower().strip() if tag else None
    cve_lower = cve.lower().strip() if cve else None

    for r in all_rules:
        if repos_set and r.get("repo_id") not in repos_set:
            continue
        if level_lower and str(r.get("level", "")).lower() != level_lower:
            continue
        if status_lower and str(r.get("status", "")).lower() != status_lower:
            continue
        ls = r.get("logsource") or {}
        if prod_lower and str(ls.get("product", "")).lower() != prod_lower:
            continue
        if cat_lower and str(ls.get("category", "")).lower() != cat_lower:
            continue
        if author_lower and author_lower not in str(r.get("author", "")).lower():
            continue
        if mitre_lower:
            mitre_match = False
            for t in (r.get("mitre_techniques") or []) + (r.get("mitre_tactics") or []):
                if t and mitre_lower in str(t).lower():
                    mitre_match = True
                    break
            if not mitre_match:
                continue
        if tag_lower and not any(t and tag_lower in str(t).lower() for t in (r.get("tags") or [])):
            continue
        if cve_lower and not any(c and cve_lower in str(c).lower() for c in (r.get("cves") or [])):
            continue

        if q_lower:
            tags_clean = [str(t).lower() for t in (r.get("tags") or []) if t]
            techs_clean = [str(t).lower() for t in (r.get("mitre_techniques") or []) if t]
            tactics_clean = [str(t).lower() for t in (r.get("mitre_tactics") or []) if t]
            cves_clean = [str(c).lower() for c in (r.get("cves") or []) if c]
            ls_prod = str(ls.get("product", "")).lower()
            ls_cat = str(ls.get("category", "")).lower()
            ls_srv = str(ls.get("service", "")).lower()

            title = str(r.get("title", "")).lower()
            desc = str(r.get("description", "")).lower()
            rid = str(r.get("id", "")).lower()
            author_val = str(r.get("author", "")).lower()
            filename_val = str(r.get("filename", "")).lower()

            haystack = f"{title} {desc} {rid} {' '.join(tags_clean)} {' '.join(techs_clean)} {' '.join(tactics_clean)} {' '.join(cves_clean)} {ls_prod} {ls_cat} {ls_srv} {author_val} {filename_val}"
            
            # Check direct substring
            if q_lower in haystack:
                pass
            # Or if user searched for TTP code like "T1566", match prefix or substring in techniques/tags
            elif any(q_lower in tec or tec in q_lower for tec in techs_clean):
                pass
            elif any(q_lower in t or t in q_lower for t in tags_clean):
                pass
            else:
                continue

        filtered.append(r)

    total_count = len(filtered)
    total_pages = max(1, (total_count + page_size - 1) // page_size)
    page = max(1, min(page, total_pages))
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    items = filtered[start_idx:end_idx]

    return {
        "total_count": total_count,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "rules": items
    }


def get_rule(repo_id: str, filename_or_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full rule definition and YAML source."""
    index_rules()
    key = f"{repo_id}/{filename_or_id}"
    item = _RULES_BY_KEY.get(key) or _RULES_BY_KEY.get(filename_or_id)
    if not item:
        # Fallback search by filename in repo
        target = SIGMA_DATA_DIR / repo_id / filename_or_id
        if not target.exists():
            return None
        content = target.read_text(encoding="utf-8", errors="replace")
    else:
        file_path = Path(item["file_path"])
        if not file_path.exists():
            return None
        content = file_path.read_text(encoding="utf-8", errors="replace")

    return {
        "metadata": item or {},
        "raw_yaml": content
    }


def save_rule(repo_id: str, filename: str, yaml_content: str) -> Dict[str, Any]:
    """Validate and save an existing or updated rule."""
    validation = validate_rule_yaml(yaml_content)
    if not validation["valid"]:
        return {
            "success": False,
            "errors": validation["errors"],
            "message": "Rule validation failed. Fix errors before saving."
        }

    repo_dir = SIGMA_DATA_DIR / repo_id
    repo_dir.mkdir(parents=True, exist_ok=True)
    target = repo_dir / filename

    try:
        target.write_text(yaml_content.strip() + "\n", encoding="utf-8")
        index_rules(force=True)
        return {
            "success": True,
            "key": f"{repo_id}/{filename}",
            "filename": filename,
            "repo_id": repo_id,
            "message": f"Successfully saved rule '{filename}'."
        }
    except Exception as e:
        return {"success": False, "error": str(e), "message": f"Failed to write rule file: {e}"}


def create_rule(yaml_content: str, repo_id: str = "custom", filename: Optional[str] = None) -> Dict[str, Any]:
    """Validate and create a new Sigma rule."""
    validation = validate_rule_yaml(yaml_content)
    if not validation["valid"]:
        return {
            "success": False,
            "errors": validation["errors"],
            "message": "Rule validation failed. Please address errors before creating."
        }

    # Generate filename if not provided
    rule_dict = validation.get("rule_dict") or {}
    title = rule_dict.get("title") or "new_sigma_rule"
    if not filename:
        slug = re.sub(r'[^a-zA-Z0-9_-]', '_', title).lower().strip('_')
        slug = re.sub(r'_+', '_', slug)[:45]
        filename = f"{slug}.yml"
    elif not (filename.endswith(".yml") or filename.endswith(".yaml")):
        filename = f"{filename}.yml"

    return save_rule(repo_id=repo_id, filename=filename, yaml_content=yaml_content)


def delete_rule(repo_id: str, filename: str) -> Dict[str, Any]:
    """Delete a Sigma rule and record it in the tombstone list so it is never re-synced."""
    target = SIGMA_DATA_DIR / repo_id / filename
    rel_path = f"{repo_id}/{filename}"

    # Add to persistent tombstones
    add_tombstone(filename)
    add_tombstone(rel_path)

    deleted = False
    if target.exists():
        try:
            target.unlink()
            deleted = True
        except Exception as e:
            logger.error(f"Error unlinking {target}: {e}")

    index_rules(force=True)
    return {
        "success": True,
        "deleted": deleted,
        "tombstoned": True,
        "key": rel_path,
        "message": f"Rule '{filename}' deleted and permanently registered in tombstones."
    }


def generate_uuid() -> str:
    """Generate a standard lowercase UUIDv4 for new Sigma rule identification."""
    return str(uuid.uuid4())


def get_custom_rules() -> List[Dict[str, Any]]:
    """Return all user-authored custom Sigma rules."""
    rules = index_rules()
    return [r for r in rules if r.get("repo_id") == "custom"]


def get_rule_templates() -> List[Dict[str, Any]]:
    """Return curated starter templates for Sigma rules."""
    now_uuid = generate_uuid()
    today_str = datetime.utcnow().strftime("%Y-%m-%d")

    templates = [
        {
            "id": "proc_creation",
            "title": "Process Creation - Execution / LOLBAS",
            "category": "process_creation",
            "product": "windows",
            "level": "high",
            "description": "Detects execution of a specific suspicious executable, LOLBAS binary, or command line flag sequence.",
            "content": f"""title: Suspicious Process Execution of BinaryName
id: {now_uuid}
status: experimental
description: Detects the execution of BinaryName with suspicious command line parameters indicating evasion or reconnaissance.
references:
    - https://attack.mitre.org/techniques/T1059/
author: Custom Threat Hunter
date: {today_str}
tags:
    - attack.execution
    - attack.t1059
    - attack.defense_evasion
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\binaryname.exe'
        CommandLine|contains:
            - '-suspicious_flag'
            - '/bypass'
    filter:
        CommandLine|contains:
            - 'benign_maintenance_arg'
    condition: selection and not filter
falsepositives:
    - Legitimate administrative maintenance scripts.
level: high
"""
        },
        {
            "id": "powershell_script",
            "title": "PowerShell - Script Block / Encoded Command",
            "category": "ps_script",
            "product": "windows",
            "level": "high",
            "description": "Detects obfuscated, encoded, or in-memory download cradle execution via PowerShell (EID 4104).",
            "content": f"""title: PowerShell Suspicious In-Memory Web Cradle
id: {now_uuid}
status: test
description: Detects PowerShell script block containing web download cradle methods or memory payload invocation.
references:
    - https://attack.mitre.org/techniques/T1059/001/
author: Custom Threat Hunter
date: {today_str}
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
logsource:
    category: ps_script
    product: windows
    definition: 'Requirements: PowerShell Script Block Logging (EventID 4104)'
detection:
    selection:
        ScriptBlockText|contains:
            - 'Net.WebClient'
            - 'DownloadString'
            - 'Invoke-Expression'
            - 'IEX('
            - 'FromBase64String'
    condition: selection
falsepositives:
    - DevOps or deployment scripts.
level: high
"""
        },
        {
            "id": "network_connection",
            "title": "Network Connection - Suspicious Outbound / C2",
            "category": "network_connection",
            "product": "windows",
            "level": "high",
            "description": "Detects network communication to suspicious external destinations or non-standard ports.",
            "content": f"""title: Outbound Connection to Untrusted Port by System Binary
id: {now_uuid}
status: experimental
description: Detects an outbound TCP/UDP connection initiated by a commonly abused LOLBAS binary to suspicious external port.
references:
    - https://attack.mitre.org/techniques/T1071/
author: Custom Threat Hunter
date: {today_str}
tags:
    - attack.command_and_control
    - attack.t1071
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith:
            - '\\rundll32.exe'
            - '\\regsvr32.exe'
            - '\\certutil.exe'
            - '\\mshta.exe'
        DestinationPort:
            - 4444
            - 8080
            - 8888
            - 1337
    condition: selection
falsepositives:
    - Internal developer staging environments.
level: high
"""
        },
        {
            "id": "file_event",
            "title": "File Event - Ransomware / Dropper Artifact",
            "category": "file_event",
            "product": "windows",
            "level": "critical",
            "description": "Detects creation of ransomware ransom note files or suspicious executable drop in temporary folders.",
            "content": f"""title: Ransomware Note or Encrypted File Marker Drop
id: {now_uuid}
status: stable
description: Detects the creation of files with specific extensions or naming patterns indicative of ransomware deployment.
references:
    - https://attack.mitre.org/techniques/T1486/
author: Custom Threat Hunter
date: {today_str}
tags:
    - attack.impact
    - attack.t1486
    - ransomware
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '_README_TO_DECRYPT.txt'
            - '-README.txt'
            - '.locked'
            - '.enc'
    condition: selection
falsepositives:
    - None known.
level: critical
"""
        },
        {
            "id": "registry_persistence",
            "title": "Registry Event - Autostart / Run Key Persistence",
            "category": "registry_set",
            "product": "windows",
            "level": "high",
            "description": "Detects unauthorized modification of Windows Run/RunOnce keys or service configuration.",
            "content": f"""title: Windows Run Key Persistence via Registry
id: {now_uuid}
status: stable
description: Detects addition of an entry to the CurrentVersion\\Run registry key pointing to suspicious user-writable folders.
references:
    - https://attack.mitre.org/techniques/T1547/001/
author: Custom Threat Hunter
date: {today_str}
tags:
    - attack.persistence
    - attack.t1547.001
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains:
            - '\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\'
            - '\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\'
        Details|contains:
            - '\\AppData\\Local\\Temp\\'
            - '\\Users\\Public\\'
            - '\\ProgramData\\'
    condition: selection
falsepositives:
    - Legitimate user software auto-launchers installed in user profiles.
level: high
"""
        },
        {
            "id": "linux_proc",
            "title": "Linux - Interactive Shell / Reverse Shell Execution",
            "category": "process_creation",
            "product": "linux",
            "level": "high",
            "description": "Detects spawned reverse shells using netcat, bash interactive redirections, or python sockets on Linux.",
            "content": f"""title: Linux Interactive Reverse Shell Invocation
id: {now_uuid}
status: stable
description: Detects common Linux reverse shell command strings invoking /bin/sh or /bin/bash redirected across network sockets.
references:
    - https://attack.mitre.org/techniques/T1059/004/
author: Custom Threat Hunter
date: {today_str}
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains:
            - 'bash -i >& /dev/tcp/'
            - 'sh -i >& /dev/tcp/'
            - 'nc -e /bin/sh'
            - 'nc -e /bin/bash'
            - 'ncat -e /bin/bash'
    condition: selection
falsepositives:
    - Authorized penetration testing activities.
level: high
"""
        },
        {
            "id": "minimal",
            "title": "Minimal Starter Template",
            "category": "general",
            "product": "generic",
            "level": "medium",
            "description": "Basic skeleton with all required Sigma fields.",
            "content": f"""title: New Custom Detection Rule
id: {now_uuid}
status: experimental
description: Brief summary of the attack technique or tradecraft being detected.
references:
    - https://attack.mitre.org/
author: Security Analyst
date: {today_str}
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'suspicious_string'
    condition: selection
falsepositives:
    - Unknown
level: medium
"""
        }
    ]
    return templates


def clone_rule(repo_id: str, filename_or_id: str, new_title: Optional[str] = None) -> Dict[str, Any]:
    """Clone an existing Sigma rule into a user-customizable custom rule."""
    rule_info = get_rule(repo_id, filename_or_id)
    if not rule_info or not rule_info.get("raw_yaml"):
        return {"success": False, "error": f"Rule not found: {repo_id}/{filename_or_id}"}

    orig_yaml = rule_info["raw_yaml"]
    meta = rule_info.get("metadata", {})
    orig_title = meta.get("title") or "Cloned Rule"
    clone_title = new_title or f"{orig_title} (Custom Clone)"

    new_id = str(uuid.uuid4())
    today_str = datetime.utcnow().strftime("%Y-%m-%d")

    # Replace id and title in raw yaml
    new_yaml = orig_yaml
    new_yaml = re.sub(r'(?m)^title:\s*.*$', f"title: {clone_title}", new_yaml, count=1)
    if re.search(r'(?m)^id:\s*.*$', new_yaml):
        new_yaml = re.sub(r'(?m)^id:\s*.*$', f"id: {new_id}", new_yaml, count=1)
    else:
        new_yaml = f"id: {new_id}\n" + new_yaml

    # Update author to indicate custom fork
    orig_author = meta.get("author") or "Original Author"
    custom_author = f"Analyst (Forked from {orig_author})"
    if re.search(r'(?m)^author:\s*.*$', new_yaml):
        new_yaml = re.sub(r'(?m)^author:\s*.*$', f"author: {custom_author}", new_yaml, count=1)
    else:
        new_yaml = new_yaml + f"\nauthor: {custom_author}"

    # Update date
    if re.search(r'(?m)^date:\s*.*$', new_yaml):
        new_yaml = re.sub(r'(?m)^date:\s*.*$', f"date: {today_str}", new_yaml, count=1)

    slug = re.sub(r'[^a-zA-Z0-9_-]', '_', clone_title).lower().strip('_')
    slug = re.sub(r'_+', '_', slug)[:45]
    new_filename = f"custom_{slug}_{new_id[:8]}.yml"

    save_res = save_rule(repo_id="custom", filename=new_filename, yaml_content=new_yaml)
    if save_res.get("success"):
        return {
            "success": True,
            "key": f"custom/{new_filename}",
            "filename": new_filename,
            "repo_id": "custom",
            "title": clone_title,
            "raw_yaml": new_yaml,
            "message": f"Successfully cloned rule as '{new_filename}'."
        }
    return save_res


def get_stats() -> Dict[str, Any]:
    """Calculate aggregated stats, distributions, authors, log sources, and MITRE tactics."""
    rules = index_rules()

    repo_counts: Dict[str, int] = {}
    level_counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    status_counts: Dict[str, int] = {"stable": 0, "test": 0, "experimental": 0, "deprecated": 0, "unsupported": 0}
    log_products: Dict[str, int] = {}
    log_categories: Dict[str, int] = {}
    author_counts: Dict[str, int] = {}
    tactic_counts: Dict[str, int] = {}
    technique_counts: Dict[str, int] = {}

    emerging_count = 0
    cve_count = 0
    ransomware_count = 0
    apt_count = 0
    lolbas_count = 0

    for r in rules:
        rep = r["repo_id"]
        repo_counts[rep] = repo_counts.get(rep, 0) + 1

        lvl = r["level"]
        level_counts[lvl] = level_counts.get(lvl, 0) + 1

        st = r["status"]
        status_counts[st] = status_counts.get(st, 0) + 1

        prod = r["logsource"]["product"]
        if prod:
            log_products[prod] = log_products.get(prod, 0) + 1

        cat = r["logsource"]["category"]
        if cat:
            log_categories[cat] = log_categories.get(cat, 0) + 1

        for a in [x.strip() for x in r["author"].split(",")]:
            if a and a != "Unknown":
                author_counts[a] = author_counts.get(a, 0) + 1

        for tac in r["mitre_tactics"]:
            tactic_counts[tac] = tactic_counts.get(tac, 0) + 1

        for tec in r["mitre_techniques"]:
            technique_counts[tec] = technique_counts.get(tec, 0) + 1

        if r["is_emerging"]:
            emerging_count += 1
        if r["is_cve"]:
            cve_count += 1
        if r["is_ransomware"]:
            ransomware_count += 1
        if r["is_apt"]:
            apt_count += 1
        if r["is_lolbas"]:
            lolbas_count += 1

    top_authors = [{"name": k, "count": v} for k, v in sorted(author_counts.items(), key=lambda x: -x[1])[:10]]
    top_products = [{"name": k, "count": v} for k, v in sorted(log_products.items(), key=lambda x: -x[1])[:8]]
    top_categories = [{"name": k, "count": v} for k, v in sorted(log_categories.items(), key=lambda x: -x[1])[:8]]
    top_techniques = [{"id": k, "name": TECHNIQUE_NAMES.get(k.upper(), k), "count": v} for k, v in sorted(technique_counts.items(), key=lambda x: -x[1])[:10]]

    return {
        "total_rules": len(rules),
        "total_valid": len(rules),
        "total_invalid": 0,
        "repo_counts": repo_counts,
        "level_counts": level_counts,
        "status_counts": status_counts,
        "top_authors": top_authors,
        "top_products": top_products,
        "top_categories": top_categories,
        "tactic_counts": tactic_counts,
        "top_techniques": top_techniques,
        "emerging_summary": {
            "total_emerging": emerging_count,
            "cve_count": cve_count,
            "ransomware_count": ransomware_count,
            "apt_count": apt_count,
            "lolbas_count": lolbas_count
        }
    }


def get_emerging_threats(category: str = "all", search: str = "") -> Dict[str, Any]:
    """Retrieve curated emerging threat rules categorized by CVE, Ransomware, APT, LOLBAS."""
    rules = index_rules()
    emerging_all = [r for r in rules if r["is_emerging"]]

    q_lower = search.lower().strip() if search else ""

    counts = {
        "all": len(emerging_all),
        "cve": sum(1 for r in emerging_all if r["is_cve"]),
        "ransomware": sum(1 for r in emerging_all if r["is_ransomware"]),
        "apt": sum(1 for r in emerging_all if r["is_apt"]),
        "lolbas": sum(1 for r in emerging_all if r["is_lolbas"]),
    }

    filtered = []
    cat_lower = category.lower().strip()
    for r in emerging_all:
        if cat_lower == "cve" and not r["is_cve"]:
            continue
        elif cat_lower == "ransomware" and not r["is_ransomware"]:
            continue
        elif cat_lower == "apt" and not r["is_apt"]:
            continue
        elif cat_lower == "lolbas" and not r["is_lolbas"]:
            continue

        if q_lower:
            text = f"{r['title']} {r['description']} {' '.join(r['cves'])} {' '.join(r['tags'])}".lower()
            if q_lower not in text:
                continue

        filtered.append(r)

    return {
        "category": category,
        "counts": counts,
        "total_matched": len(filtered),
        "rules": filtered
    }


def get_mitre_matrix() -> Dict[str, Any]:
    """Build complete 14-tactic Enterprise ATT&CK matrix with mapped techniques and rules."""
    rules = index_rules()

    # Map tactics -> techniques -> rules
    matrix_tactics = []
    total_technique_coverages = 0

    for tac in MITRE_TACTICS:
        tac_short = tac["short"]
        tac_rules = [r for r in rules if tac_short in r["mitre_tactics"]]

        # Group rules by technique
        tech_map: Dict[str, List[Dict[str, Any]]] = {}
        for r in tac_rules:
            for tec in r["mitre_techniques"]:
                tech_upper = tec.upper()
                if tech_upper not in tech_map:
                    tech_map[tech_upper] = []
                tech_map[tech_upper].append({
                    "id": r["id"],
                    "key": r["key"],
                    "title": r["title"],
                    "level": r["level"],
                    "repo_id": r["repo_id"],
                    "filename": r["filename"]
                })

        techniques_list = []
        for tec_id, tec_rule_list in tech_map.items():
            name = TECHNIQUE_NAMES.get(tec_id, tec_id)
            techniques_list.append({
                "id": tec_id,
                "name": name,
                "count": len(tec_rule_list),
                "rules": tec_rule_list
            })
            total_technique_coverages += len(tec_rule_list)

        # Sort by count desc
        techniques_list.sort(key=lambda x: -x["count"])

        matrix_tactics.append({
            "id": tac["id"],
            "short": tac["short"],
            "name": tac["name"],
            "rule_count": len(tac_rules),
            "techniques_count": len(techniques_list),
            "techniques": techniques_list
        })

    return {
        "tactics": matrix_tactics,
        "total_tactics": len(matrix_tactics),
        "total_technique_coverages": total_technique_coverages
    }
