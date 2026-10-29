"""Malpedia taxonomy sync (public endpoints)."""

import json
import logging
import urllib.request
import urllib.error
import time

import cti_db

logger = logging.getLogger("mantis.malpedia")

MALPEDIA_FAMILIES_URL = "https://malpedia.caad.fkie.fraunhofer.de/api/get/families"
MALPEDIA_ACTORS_URL = "https://malpedia.caad.fkie.fraunhofer.de/api/get/actors"

def fetch_json(url: str, retries=3):
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 MANTIS-CTI'})
            with urllib.request.urlopen(req, timeout=30) as response:
                if response.status == 200:
                    return json.loads(response.read().decode('utf-8'))
        except urllib.error.URLError as e:
            logger.warning(f"Error fetching {url}: {e}")
            time.sleep(2)
    return {}

def sync_malpedia():
    logger.info("Starting Malpedia open taxonomy sync...")
    
    # 1. Sync Families
    families = fetch_json(MALPEDIA_FAMILIES_URL)
    family_count = 0
    if families:
        for key, fam_data in families.items():
            fam_data['name'] = key
            cti_db.upsert_malpedia_family(fam_data)
            family_count += 1
        logger.info(f"Synced {family_count} Malpedia families.")
    else:
        logger.error("Failed to fetch Malpedia families.")

    # 2. Sync Actors
    actors = fetch_json(MALPEDIA_ACTORS_URL)
    actor_count = 0
    if actors:
        for key, act_data in actors.items():
            # Key is usually the common name or primary name
            cti_db.upsert_malpedia_actor(act_data)
            actor_count += 1
        logger.info(f"Synced {actor_count} Malpedia actors.")
    else:
        logger.error("Failed to fetch Malpedia actors.")

    generate_misp_galaxy_jsons()

def safe_json_list(val):
    if not val:
        return []
    try:
        res = json.loads(val)
        if isinstance(res, list):
            return res
        return [res]
    except json.JSONDecodeError:
        return [x.strip() for x in str(val).split(',')] if val else []

def generate_misp_galaxy_jsons():
    import sqlite3
    import os
    import uuid
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "cti_articles.db")
    misp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "misp")
    os.makedirs(misp_dir, exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Families
    c.execute("SELECT * FROM malpedia_families")
    db_families = c.fetchall()
    
    grouped_families = {
        'win': [],
        'elf': [],
        'osx': [],
        'apk': [],
        'scripts': [],
        'other': []
    }
    script_prefixes = {'php', 'js', 'py', 'ps1', 'vbs', 'sh', 'pl', 'asp', 'jsp', 'jar'}
    
    for row in db_families:
        val = {
            "value": row['name'],
            "uuid": row['uuid'] or str(uuid.uuid4()),
            "description": row['description'],
            "meta": {
                "synonyms": safe_json_list(row['alt_names']),
                "refs": safe_json_list(row['urls'])
            }
        }
        prefix = row['name'].split('.')[0] if '.' in row['name'] else ''
        if prefix == 'win':
            grouped_families['win'].append(val)
        elif prefix == 'elf':
            grouped_families['elf'].append(val)
        elif prefix == 'osx':
            grouped_families['osx'].append(val)
        elif prefix == 'apk':
            grouped_families['apk'].append(val)
        elif prefix in script_prefixes:
            grouped_families['scripts'].append(val)
        else:
            grouped_families['other'].append(val)
            
    group_labels = {
        'win': 'Windows',
        'elf': 'Linux',
        'osx': 'MacOS',
        'apk': 'Android',
        'scripts': 'Scripts',
        'other': 'Other'
    }
    
    for g_key, g_vals in grouped_families.items():
        if not g_vals:
            continue
        g_name = f"malpedia-{g_key}"
        galaxy = {
            "name": g_name,
            "type": "malware-tools",
            "description": f"Malpedia {group_labels[g_key]}",
            "version": 1,
            "values": g_vals
        }
        with open(os.path.join(misp_dir, f'{g_name}.json'), 'w', encoding='utf-8') as f:
            json.dump(galaxy, f, indent=2)
            
    logger.info("Generated MISP Galaxy JSONs for Malpedia split by OS.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    cti_db.init_db()
    sync_malpedia()
