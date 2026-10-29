"""MANTIS Similarity.

Local-only static feature extraction and entity comparison. Uploaded samples are
copied to a temporary directory by the API layer, processed passively, and never
stored in the database; only derived hashes, fingerprints and selected strings
are persisted.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import math
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "similarity.db")
_INIT_DB_LOCK = threading.Lock()
_INITIALIZED_DB_PATHS: set[str] = set()

DEFAULT_SETTINGS = {
    "weights": {
        "semantic_code": 55,
        "code": 25,
        "strings": 7,
        "tlsh": 4,
        "imports": 3,
        "imphash": 2,
        "icon": 2,
        "rich": 1,
        "ssdeep": 1,
    },
    "code_weights": {
        "functions": 30,
        "blocks": 20,
        "ngrams": 15,
        "api_patterns": 15,
        "cfg": 10,
        "constants": 5,
        "function_strings": 5,
    },
    "stringsifter_threshold": 0.45,
    "minimum_string_length": 4,
    "minimum_match_score": 35,
    "store_comparison_history": True,
    "processing_timeout_seconds": 120,
    "enable_code_similarity": False,
    "enable_semantic_similarity": False,
    "enable_pseudocode_similarity": True,
    "enable_ast_similarity": True,
    "enable_microcode_similarity": True,
    "store_raw_pseudocode": False,
    "store_normalized_tokens": False,
    "ida_path": "",
    "ida_path_32": "",
    "ida_timeout_seconds": 300,
    "hexrays_timeout_seconds": 120,
    "hexrays_function_timeout_seconds": 10,
    "maximum_semantic_functions": 100,
    "minimum_semantic_function_instructions": 10,
    "minimum_semantic_match": 60,
    "semantic_candidate_functions": 20,
    "semantic_ngram_size": 4,
    "ida_max_file_size": 104857600,
    "ida_max_concurrent_jobs": 1,
    "minimum_function_instructions": 5,
    "minimum_block_instructions": 2,
    "minimum_function_match": 55,
    "mnemonic_ngram_size": 4,
    "candidate_functions": 20,
    "exclude_thunks": True,
    "downweight_library_functions": True,
    "normalization_version": 1,
    "feature_schema_version": 2,
    "semantic_schema_version": 1,
    "pseudocode_normalization_version": 1,
    "ast_normalization_version": 1,
    "microcode_normalization_version": 1,
    "api_semantic_map_version": 1,
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'malware',
    description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_similarity_entities_type ON entities(type);

CREATE TABLE IF NOT EXISTS entity_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    sha1 TEXT NOT NULL DEFAULT '',
    md5 TEXT NOT NULL DEFAULT '',
    file_name TEXT NOT NULL DEFAULT '',
    file_size INTEGER NOT NULL DEFAULT 0,
    file_type TEXT NOT NULL DEFAULT '',
    architecture TEXT NOT NULL DEFAULT '',
    processed_at TEXT NOT NULL,
    UNIQUE(entity_id, sha256)
);
CREATE INDEX IF NOT EXISTS idx_similarity_samples_sha256 ON entity_samples(sha256);
CREATE INDEX IF NOT EXISTS idx_similarity_samples_entity ON entity_samples(entity_id);

CREATE TABLE IF NOT EXISTS sample_fuzzy_hashes (
    sample_id INTEGER PRIMARY KEY,
    tlsh TEXT NOT NULL DEFAULT '',
    ssdeep TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS sample_pe_features (
    sample_id INTEGER PRIMARY KEY,
    imphash TEXT NOT NULL DEFAULT '',
    rich_hash TEXT NOT NULL DEFAULT '',
    rich_present INTEGER NOT NULL DEFAULT 0,
    rich_entries_count INTEGER NOT NULL DEFAULT 0,
    icon_sha256 TEXT NOT NULL DEFAULT '',
    icon_phash TEXT NOT NULL DEFAULT '',
    icon_width INTEGER NOT NULL DEFAULT 0,
    icon_height INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sample_imports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id INTEGER NOT NULL,
    dll TEXT NOT NULL DEFAULT '',
    function TEXT NOT NULL DEFAULT '',
    normalized_import TEXT NOT NULL DEFAULT '',
    UNIQUE(sample_id, normalized_import)
);
CREATE INDEX IF NOT EXISTS idx_similarity_sample_imports_sample ON sample_imports(sample_id);

CREATE TABLE IF NOT EXISTS sample_strings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id INTEGER NOT NULL,
    raw_string TEXT NOT NULL DEFAULT '',
    normalized_string TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT 'generic',
    stringsifter_score REAL NOT NULL DEFAULT 0,
    floss_type TEXT NOT NULL DEFAULT '',
    frequency INTEGER NOT NULL DEFAULT 1,
    UNIQUE(sample_id, normalized_string, floss_type)
);
CREATE INDEX IF NOT EXISTS idx_similarity_sample_strings_sample ON sample_strings(sample_id);
CREATE INDEX IF NOT EXISTS idx_similarity_sample_strings_norm ON sample_strings(normalized_string);

CREATE TABLE IF NOT EXISTS sample_extractor_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id INTEGER NOT NULL,
    extractor TEXT NOT NULL,
    status TEXT NOT NULL,
    error TEXT NOT NULL DEFAULT '',
    UNIQUE(sample_id, extractor)
);

CREATE TABLE IF NOT EXISTS entity_string_features (
    entity_id INTEGER NOT NULL,
    normalized_string TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'generic',
    sample_count INTEGER NOT NULL DEFAULT 0,
    prevalence REAL NOT NULL DEFAULT 0,
    global_entity_count INTEGER NOT NULL DEFAULT 0,
    rarity_weight REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(entity_id, normalized_string)
);

CREATE TABLE IF NOT EXISTS entity_import_features (
    entity_id INTEGER NOT NULL,
    normalized_import TEXT NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    prevalence REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(entity_id, normalized_import)
);

CREATE TABLE IF NOT EXISTS entity_imphashes (
    entity_id INTEGER NOT NULL,
    imphash TEXT NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    prevalence REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(entity_id, imphash)
);

CREATE TABLE IF NOT EXISTS entity_rich_hashes (
    entity_id INTEGER NOT NULL,
    rich_hash TEXT NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    prevalence REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(entity_id, rich_hash)
);

CREATE TABLE IF NOT EXISTS entity_icon_hashes (
    entity_id INTEGER NOT NULL,
    icon_phash TEXT NOT NULL DEFAULT '',
    icon_sha256 TEXT NOT NULL DEFAULT '',
    sample_count INTEGER NOT NULL DEFAULT 0,
    prevalence REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(entity_id, icon_phash, icon_sha256)
);

CREATE TABLE IF NOT EXISTS similarity_comparisons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL,
    file_name TEXT NOT NULL DEFAULT '',
    compared_at TEXT NOT NULL,
    best_entity_id INTEGER,
    best_score REAL NOT NULL DEFAULT 0,
    result_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS similarity_settings (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sample_code_profiles (
    sample_id INTEGER PRIMARY KEY,
    status TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    analysis_engine TEXT NOT NULL DEFAULT '',
    analysis_engine_version TEXT NOT NULL DEFAULT '',
    normalization_version INTEGER NOT NULL DEFAULT 1,
    feature_schema_version INTEGER NOT NULL DEFAULT 2,
    ida_analysis_time REAL NOT NULL DEFAULT 0,
    feature_extraction_time REAL NOT NULL DEFAULT 0,
    function_count INTEGER NOT NULL DEFAULT 0,
    meaningful_function_count INTEGER NOT NULL DEFAULT 0,
    block_count INTEGER NOT NULL DEFAULT 0,
    instruction_count INTEGER NOT NULL DEFAULT 0,
    unique_normalized_functions INTEGER NOT NULL DEFAULT 0,
    unique_block_hashes INTEGER NOT NULL DEFAULT 0,
    unique_ngram_hashes INTEGER NOT NULL DEFAULT 0,
    api_pattern_count INTEGER NOT NULL DEFAULT 0,
    constant_count INTEGER NOT NULL DEFAULT 0,
    cfg_hash_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sample_functions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id INTEGER NOT NULL,
    function_index INTEGER NOT NULL,
    ida_address TEXT NOT NULL DEFAULT '',
    size INTEGER NOT NULL DEFAULT 0,
    instruction_count INTEGER NOT NULL DEFAULT 0,
    block_count INTEGER NOT NULL DEFAULT 0,
    cyclomatic_complexity INTEGER NOT NULL DEFAULT 0,
    callers_count INTEGER NOT NULL DEFAULT 0,
    callees_count INTEGER NOT NULL DEFAULT 0,
    referenced_strings_count INTEGER NOT NULL DEFAULT 0,
    imported_api_calls_count INTEGER NOT NULL DEFAULT 0,
    raw_hash TEXT NOT NULL DEFAULT '',
    normalized_hash TEXT NOT NULL DEFAULT '',
    is_library INTEGER NOT NULL DEFAULT 0,
    is_thunk INTEGER NOT NULL DEFAULT 0,
    UNIQUE(sample_id, function_index)
);
CREATE INDEX IF NOT EXISTS idx_similarity_functions_sample ON sample_functions(sample_id);
CREATE INDEX IF NOT EXISTS idx_similarity_functions_norm ON sample_functions(normalized_hash);
CREATE INDEX IF NOT EXISTS idx_similarity_functions_raw ON sample_functions(raw_hash);

CREATE TABLE IF NOT EXISTS function_ngrams (
    function_id INTEGER NOT NULL,
    ngram_hash TEXT NOT NULL,
    ngram_size INTEGER NOT NULL DEFAULT 4,
    UNIQUE(function_id, ngram_hash, ngram_size)
);
CREATE INDEX IF NOT EXISTS idx_similarity_ngrams_function ON function_ngrams(function_id);
CREATE INDEX IF NOT EXISTS idx_similarity_ngrams_hash ON function_ngrams(ngram_hash, ngram_size);

CREATE TABLE IF NOT EXISTS function_blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    function_id INTEGER NOT NULL,
    block_hash TEXT NOT NULL DEFAULT '',
    instruction_count INTEGER NOT NULL DEFAULT 0,
    predecessor_count INTEGER NOT NULL DEFAULT 0,
    successor_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE(function_id, block_hash)
);
CREATE INDEX IF NOT EXISTS idx_similarity_blocks_function ON function_blocks(function_id);
CREATE INDEX IF NOT EXISTS idx_similarity_blocks_hash ON function_blocks(block_hash);

CREATE TABLE IF NOT EXISTS function_apis (
    function_id INTEGER NOT NULL,
    position INTEGER NOT NULL DEFAULT 0,
    api_name TEXT NOT NULL DEFAULT '',
    UNIQUE(function_id, position, api_name)
);
CREATE INDEX IF NOT EXISTS idx_similarity_function_apis_function ON function_apis(function_id);
CREATE INDEX IF NOT EXISTS idx_similarity_function_apis_name ON function_apis(api_name);

CREATE TABLE IF NOT EXISTS function_api_patterns (
    function_id INTEGER NOT NULL,
    pattern_hash TEXT NOT NULL,
    pattern_kind TEXT NOT NULL DEFAULT '',
    UNIQUE(function_id, pattern_hash, pattern_kind)
);
CREATE INDEX IF NOT EXISTS idx_similarity_api_patterns_function ON function_api_patterns(function_id);
CREATE INDEX IF NOT EXISTS idx_similarity_api_patterns_hash ON function_api_patterns(pattern_hash);

CREATE TABLE IF NOT EXISTS function_constants (
    function_id INTEGER NOT NULL,
    constant_value TEXT NOT NULL DEFAULT '',
    UNIQUE(function_id, constant_value)
);
CREATE INDEX IF NOT EXISTS idx_similarity_function_constants_function ON function_constants(function_id);
CREATE INDEX IF NOT EXISTS idx_similarity_function_constants_value ON function_constants(constant_value);

CREATE TABLE IF NOT EXISTS function_strings (
    function_id INTEGER NOT NULL,
    normalized_string TEXT NOT NULL DEFAULT '',
    UNIQUE(function_id, normalized_string)
);
CREATE INDEX IF NOT EXISTS idx_similarity_function_strings_function ON function_strings(function_id);
CREATE INDEX IF NOT EXISTS idx_similarity_function_strings_value ON function_strings(normalized_string);

CREATE TABLE IF NOT EXISTS function_cfg (
    function_id INTEGER PRIMARY KEY,
    cfg_hash TEXT NOT NULL DEFAULT '',
    nodes INTEGER NOT NULL DEFAULT 0,
    edges INTEGER NOT NULL DEFAULT 0,
    complexity INTEGER NOT NULL DEFAULT 0,
    degree_signature TEXT NOT NULL DEFAULT '',
    traversal_hash TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_similarity_cfg_hash ON function_cfg(cfg_hash);

CREATE TABLE IF NOT EXISTS entity_function_features (
    entity_id INTEGER NOT NULL,
    normalized_hash TEXT NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    prevalence REAL NOT NULL DEFAULT 0,
    global_entity_count INTEGER NOT NULL DEFAULT 0,
    rarity_weight REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(entity_id, normalized_hash)
);

CREATE TABLE IF NOT EXISTS entity_block_features (
    entity_id INTEGER NOT NULL,
    block_hash TEXT NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    prevalence REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(entity_id, block_hash)
);

CREATE TABLE IF NOT EXISTS entity_ngram_features (
    entity_id INTEGER NOT NULL,
    ngram_hash TEXT NOT NULL,
    ngram_size INTEGER NOT NULL DEFAULT 4,
    sample_count INTEGER NOT NULL DEFAULT 0,
    prevalence REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(entity_id, ngram_hash, ngram_size)
);

CREATE TABLE IF NOT EXISTS entity_api_patterns (
    entity_id INTEGER NOT NULL,
    pattern_hash TEXT NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    prevalence REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(entity_id, pattern_hash)
);

CREATE TABLE IF NOT EXISTS entity_constant_features (
    entity_id INTEGER NOT NULL,
    constant_value TEXT NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    prevalence REAL NOT NULL DEFAULT 0,
    global_entity_count INTEGER NOT NULL DEFAULT 0,
    rarity_weight REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(entity_id, constant_value)
);

CREATE TABLE IF NOT EXISTS entity_function_string_features (
    entity_id INTEGER NOT NULL,
    normalized_string TEXT NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    prevalence REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(entity_id, normalized_string)
);

CREATE TABLE IF NOT EXISTS entity_cfg_features (
    entity_id INTEGER NOT NULL,
    cfg_hash TEXT NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    prevalence REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(entity_id, cfg_hash)
);

CREATE TABLE IF NOT EXISTS entity_code_summary (
    entity_id INTEGER PRIMARY KEY,
    sample_count INTEGER NOT NULL DEFAULT 0,
    function_count INTEGER NOT NULL DEFAULT 0,
    core_function_count INTEGER NOT NULL DEFAULT 0,
    unique_function_count INTEGER NOT NULL DEFAULT 0,
    unique_block_count INTEGER NOT NULL DEFAULT 0,
    unique_ngram_count INTEGER NOT NULL DEFAULT 0,
    api_pattern_count INTEGER NOT NULL DEFAULT 0,
    constant_count INTEGER NOT NULL DEFAULT 0,
    cfg_hash_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS function_semantic_features (
    function_id INTEGER PRIMARY KEY,
    decompiler_status TEXT NOT NULL DEFAULT '',
    decompiler_error TEXT NOT NULL DEFAULT '',
    pseudocode_hash TEXT NOT NULL DEFAULT '',
    ast_hash TEXT NOT NULL DEFAULT '',
    control_structure_hash TEXT NOT NULL DEFAULT '',
    semantic_api_hash TEXT NOT NULL DEFAULT '',
    microcode_hash TEXT NOT NULL DEFAULT '',
    semantic_version INTEGER NOT NULL DEFAULT 1,
    pseudocode_norm_version INTEGER NOT NULL DEFAULT 1,
    ast_norm_version INTEGER NOT NULL DEFAULT 1,
    microcode_norm_version INTEGER NOT NULL DEFAULT 1,
    api_semantic_map_version INTEGER NOT NULL DEFAULT 1,
    hexrays_version TEXT NOT NULL DEFAULT '',
    token_count INTEGER NOT NULL DEFAULT 0,
    ast_node_count INTEGER NOT NULL DEFAULT 0,
    if_count INTEGER NOT NULL DEFAULT 0,
    loop_count INTEGER NOT NULL DEFAULT 0,
    switch_count INTEGER NOT NULL DEFAULT 0,
    call_count INTEGER NOT NULL DEFAULT 0,
    assignment_count INTEGER NOT NULL DEFAULT 0,
    return_count INTEGER NOT NULL DEFAULT 0,
    pointer_deref_count INTEGER NOT NULL DEFAULT 0,
    arithmetic_count INTEGER NOT NULL DEFAULT 0,
    bitwise_count INTEGER NOT NULL DEFAULT 0,
    comparison_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_similarity_sem_pseudo_hash ON function_semantic_features(pseudocode_hash);
CREATE INDEX IF NOT EXISTS idx_similarity_sem_ast_hash ON function_semantic_features(ast_hash);
CREATE INDEX IF NOT EXISTS idx_similarity_sem_micro_hash ON function_semantic_features(microcode_hash);

CREATE TABLE IF NOT EXISTS function_pseudocode_ngrams (
    function_id INTEGER NOT NULL,
    ngram_hash TEXT NOT NULL,
    ngram_size INTEGER NOT NULL DEFAULT 4,
    UNIQUE(function_id, ngram_hash, ngram_size)
);
CREATE INDEX IF NOT EXISTS idx_similarity_sem_pseudocode_function ON function_pseudocode_ngrams(function_id);
CREATE INDEX IF NOT EXISTS idx_similarity_sem_pseudocode_hash ON function_pseudocode_ngrams(ngram_hash, ngram_size);

CREATE TABLE IF NOT EXISTS function_ast_subtrees (
    function_id INTEGER NOT NULL,
    subtree_hash TEXT NOT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    UNIQUE(function_id, subtree_hash)
);
CREATE INDEX IF NOT EXISTS idx_similarity_sem_ast_subtree_function ON function_ast_subtrees(function_id);
CREATE INDEX IF NOT EXISTS idx_similarity_sem_ast_subtree_hash ON function_ast_subtrees(subtree_hash);

CREATE TABLE IF NOT EXISTS function_semantic_apis (
    function_id INTEGER NOT NULL,
    position INTEGER NOT NULL DEFAULT 0,
    api_category TEXT NOT NULL DEFAULT '',
    api_name TEXT NOT NULL DEFAULT '',
    UNIQUE(function_id, position, api_category, api_name)
);
CREATE INDEX IF NOT EXISTS idx_similarity_sem_api_function ON function_semantic_apis(function_id);
CREATE INDEX IF NOT EXISTS idx_similarity_sem_api_category ON function_semantic_apis(api_category);

CREATE TABLE IF NOT EXISTS function_dataflow_patterns (
    function_id INTEGER NOT NULL,
    pattern_hash TEXT NOT NULL,
    pattern_type TEXT NOT NULL DEFAULT '',
    UNIQUE(function_id, pattern_hash, pattern_type)
);
CREATE INDEX IF NOT EXISTS idx_similarity_sem_dataflow_function ON function_dataflow_patterns(function_id);
CREATE INDEX IF NOT EXISTS idx_similarity_sem_dataflow_hash ON function_dataflow_patterns(pattern_hash);

CREATE TABLE IF NOT EXISTS function_microcode_ngrams (
    function_id INTEGER NOT NULL,
    ngram_hash TEXT NOT NULL,
    ngram_size INTEGER NOT NULL DEFAULT 4,
    UNIQUE(function_id, ngram_hash, ngram_size)
);
CREATE INDEX IF NOT EXISTS idx_similarity_sem_micro_ngram_function ON function_microcode_ngrams(function_id);
CREATE INDEX IF NOT EXISTS idx_similarity_sem_micro_ngram_hash ON function_microcode_ngrams(ngram_hash, ngram_size);

CREATE TABLE IF NOT EXISTS function_micro_blocks (
    function_id INTEGER NOT NULL,
    block_hash TEXT NOT NULL,
    UNIQUE(function_id, block_hash)
);
CREATE INDEX IF NOT EXISTS idx_similarity_sem_micro_block_function ON function_micro_blocks(function_id);
CREATE INDEX IF NOT EXISTS idx_similarity_sem_micro_block_hash ON function_micro_blocks(block_hash);

CREATE TABLE IF NOT EXISTS function_semantic_constants (
    function_id INTEGER NOT NULL,
    constant_value TEXT NOT NULL DEFAULT '',
    semantic_category TEXT NOT NULL DEFAULT '',
    UNIQUE(function_id, constant_value, semantic_category)
);
CREATE INDEX IF NOT EXISTS idx_similarity_sem_constant_function ON function_semantic_constants(function_id);
CREATE INDEX IF NOT EXISTS idx_similarity_sem_constant_value ON function_semantic_constants(constant_value);

CREATE TABLE IF NOT EXISTS entity_semantic_functions (
    entity_id INTEGER NOT NULL,
    semantic_fingerprint TEXT NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    prevalence REAL NOT NULL DEFAULT 0,
    global_entity_count INTEGER NOT NULL DEFAULT 0,
    rarity_weight REAL NOT NULL DEFAULT 0,
    core_semantic INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(entity_id, semantic_fingerprint)
);

CREATE TABLE IF NOT EXISTS entity_ast_features (
    entity_id INTEGER NOT NULL,
    subtree_hash TEXT NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    prevalence REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(entity_id, subtree_hash)
);

CREATE TABLE IF NOT EXISTS entity_microcode_features (
    entity_id INTEGER NOT NULL,
    feature_hash TEXT NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    prevalence REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(entity_id, feature_hash)
);

CREATE TABLE IF NOT EXISTS entity_semantic_api_patterns (
    entity_id INTEGER NOT NULL,
    pattern_hash TEXT NOT NULL,
    api_category TEXT NOT NULL DEFAULT '',
    sample_count INTEGER NOT NULL DEFAULT 0,
    prevalence REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(entity_id, pattern_hash, api_category)
);

CREATE TABLE IF NOT EXISTS entity_dataflow_patterns (
    entity_id INTEGER NOT NULL,
    pattern_hash TEXT NOT NULL,
    pattern_type TEXT NOT NULL DEFAULT '',
    sample_count INTEGER NOT NULL DEFAULT 0,
    prevalence REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(entity_id, pattern_hash, pattern_type)
);

CREATE TABLE IF NOT EXISTS entity_semantic_constants (
    entity_id INTEGER NOT NULL,
    constant_value TEXT NOT NULL,
    sample_count INTEGER NOT NULL DEFAULT 0,
    prevalence REAL NOT NULL DEFAULT 0,
    global_entity_count INTEGER NOT NULL DEFAULT 0,
    rarity_weight REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(entity_id, constant_value)
);

CREATE TABLE IF NOT EXISTS entity_semantic_summary (
    entity_id INTEGER PRIMARY KEY,
    sample_count INTEGER NOT NULL DEFAULT 0,
    function_count INTEGER NOT NULL DEFAULT 0,
    decompiled_function_count INTEGER NOT NULL DEFAULT 0,
    semantic_coverage REAL NOT NULL DEFAULT 0,
    core_semantic_function_count INTEGER NOT NULL DEFAULT 0,
    unique_semantic_function_count INTEGER NOT NULL DEFAULT 0,
    ast_feature_count INTEGER NOT NULL DEFAULT 0,
    microcode_feature_count INTEGER NOT NULL DEFAULT 0,
    semantic_api_pattern_count INTEGER NOT NULL DEFAULT 0,
    dataflow_pattern_count INTEGER NOT NULL DEFAULT 0,
    semantic_constant_count INTEGER NOT NULL DEFAULT 0,
    semantic_schema_version INTEGER NOT NULL DEFAULT 1,
    pseudocode_norm_version INTEGER NOT NULL DEFAULT 1,
    ast_norm_version INTEGER NOT NULL DEFAULT 1,
    microcode_norm_version INTEGER NOT NULL DEFAULT 1,
    api_semantic_map_version INTEGER NOT NULL DEFAULT 1,
    hexrays_version TEXT NOT NULL DEFAULT ''
);
"""


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


def connect(path: str = "") -> sqlite3.Connection:
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(path or DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=120000")
    except sqlite3.Error:
        pass
    return conn


def _schema_ready(db_path: str) -> bool:
    if not os.path.exists(db_path):
        return False
    try:
        conn = sqlite3.connect(db_path)
        try:
            row = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'entities'"
            ).fetchone()
            return bool(row)
        finally:
            conn.close()
    except sqlite3.Error:
        return False


def init_db(path: str = "") -> str:
    db_path = os.path.abspath(path or DB_PATH)
    if db_path in _INITIALIZED_DB_PATHS:
        if _schema_ready(db_path):
            return db_path
        _INITIALIZED_DB_PATHS.discard(db_path)

    with _INIT_DB_LOCK:
        if db_path in _INITIALIZED_DB_PATHS:
            if _schema_ready(db_path):
                return db_path
            _INITIALIZED_DB_PATHS.discard(db_path)

        conn = connect(db_path)
        try:
            conn.executescript(SCHEMA)
            row = conn.execute("SELECT value_json FROM similarity_settings WHERE key = 'settings'").fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO similarity_settings (key, value_json) VALUES ('settings', ?)",
                    (json.dumps(DEFAULT_SETTINGS),),
                )
            conn.commit()
            _INITIALIZED_DB_PATHS.add(db_path)
        finally:
            conn.close()
    return db_path


def _deep_settings_merge(raw: Optional[dict]) -> dict:
    out = json.loads(json.dumps(DEFAULT_SETTINGS))
    if not isinstance(raw, dict):
        return out
    for key, value in raw.items():
        if key in {"weights", "code_weights"} and isinstance(value, dict):
            for wk, wv in value.items():
                try:
                    out[key][wk] = max(0, float(wv))
                except (TypeError, ValueError):
                    pass
        elif key in out:
            out[key] = value
    try:
        out["minimum_string_length"] = max(1, int(out["minimum_string_length"]))
        out["processing_timeout_seconds"] = max(5, int(out["processing_timeout_seconds"]))
        out["ida_timeout_seconds"] = max(30, int(out["ida_timeout_seconds"]))
        out["hexrays_timeout_seconds"] = max(30, int(out["hexrays_timeout_seconds"]))
        out["hexrays_function_timeout_seconds"] = max(1, int(out["hexrays_function_timeout_seconds"]))
        out["maximum_semantic_functions"] = max(1, min(200, int(out["maximum_semantic_functions"])))
        out["minimum_semantic_function_instructions"] = max(1, int(out["minimum_semantic_function_instructions"]))
        out["minimum_semantic_match"] = max(0, min(100, float(out["minimum_semantic_match"])))
        out["semantic_candidate_functions"] = max(1, min(200, int(out["semantic_candidate_functions"])))
        out["semantic_ngram_size"] = max(2, min(8, int(out["semantic_ngram_size"])))
        out["ida_max_file_size"] = max(1024 * 1024, int(out["ida_max_file_size"]))
        out["ida_max_concurrent_jobs"] = max(1, int(out["ida_max_concurrent_jobs"]))
        out["minimum_function_instructions"] = max(1, int(out["minimum_function_instructions"]))
        out["minimum_block_instructions"] = max(1, int(out["minimum_block_instructions"]))
        out["minimum_function_match"] = max(0, min(100, float(out["minimum_function_match"])))
        out["mnemonic_ngram_size"] = max(2, min(8, int(out["mnemonic_ngram_size"])))
        out["candidate_functions"] = max(1, min(200, int(out["candidate_functions"])))
        out["normalization_version"] = max(1, int(out["normalization_version"]))
        out["feature_schema_version"] = max(2, int(out["feature_schema_version"]))
        out["semantic_schema_version"] = max(1, int(out["semantic_schema_version"]))
        out["pseudocode_normalization_version"] = max(1, int(out["pseudocode_normalization_version"]))
        out["ast_normalization_version"] = max(1, int(out["ast_normalization_version"]))
        out["microcode_normalization_version"] = max(1, int(out["microcode_normalization_version"]))
        out["api_semantic_map_version"] = max(1, int(out["api_semantic_map_version"]))
        out["minimum_match_score"] = max(0, min(100, float(out["minimum_match_score"])))
        out["stringsifter_threshold"] = max(0, min(1, float(out["stringsifter_threshold"])))
        out["store_comparison_history"] = bool(out["store_comparison_history"])
        out["enable_code_similarity"] = bool(out["enable_code_similarity"])
        out["enable_semantic_similarity"] = bool(out["enable_semantic_similarity"])
        out["enable_pseudocode_similarity"] = bool(out["enable_pseudocode_similarity"])
        out["enable_ast_similarity"] = bool(out["enable_ast_similarity"])
        out["enable_microcode_similarity"] = bool(out["enable_microcode_similarity"])
        out["store_raw_pseudocode"] = False
        out["store_normalized_tokens"] = bool(out["store_normalized_tokens"])
        out["exclude_thunks"] = bool(out["exclude_thunks"])
        out["downweight_library_functions"] = bool(out["downweight_library_functions"])
        out["ida_path"] = str(out.get("ida_path") or "")
        out["ida_path_32"] = str(out.get("ida_path_32") or "")
    except (TypeError, ValueError):
        pass
    return out


def get_settings() -> dict:
    init_db()
    conn = connect()
    try:
        row = conn.execute("SELECT value_json FROM similarity_settings WHERE key = 'settings'").fetchone()
        raw = json.loads(row["value_json"]) if row else {}
        return _deep_settings_merge(raw)
    finally:
        conn.close()


def save_settings(settings: dict) -> dict:
    init_db()
    current = get_settings()
    if isinstance(settings, dict):
        for key, value in settings.items():
            if key in {"weights", "code_weights"} and isinstance(value, dict):
                current.setdefault(key, {})
                for wk, wv in value.items():
                    current[key][wk] = wv
            elif key in DEFAULT_SETTINGS:
                current[key] = value
    merged = _deep_settings_merge(current)
    conn = connect()
    try:
        conn.execute(
            "INSERT INTO similarity_settings (key, value_json) VALUES ('settings', ?) "
            "ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json",
            (json.dumps(merged),),
        )
        conn.commit()
    finally:
        conn.close()
    return merged


def _status(name: str, status: str, error: str = "") -> dict:
    return {"extractor": name, "status": status, "error": (error or "")[:500]}


ProgressCallback = Optional[Callable[[str, str, str, str, Optional[dict]], None]]


def _progress(progress: ProgressCallback, phase: str, message: str, status: str = "running", sample: str = "", details: Optional[dict] = None) -> None:
    if not progress:
        return
    try:
        progress(phase, message, status, sample, details or {})
    except Exception:
        pass


IDA_TEMP_SUFFIXES = (".id0", ".id1", ".id2", ".idb", ".i64", ".nam", ".til")
COMMON_CODE_CONSTANTS = {-1, 0, 1, 2, 4, 8, 16, 32, 64}
API_PREFIX_RE = re.compile(r"^(?:__imp_|imp_)", re.I)
API_DLL_RE = re.compile(r"^([a-z0-9_.-]+?)(?:\.dll)?[!._]+([a-z_][a-z0-9_@$?]{2,})$", re.I)
SEMANTIC_API_CATEGORY_RULES = [
    ("MEMORY_ALLOC", ("virtualalloc", "virtualallocex", "heapalloc", "malloc", "localalloc", "globalalloc")),
    ("MEMORY_PROTECT", ("virtualprotect", "virtualprotectex", "ntprotectvirtualmemory")),
    ("MEMORY_COPY", ("memcpy", "rtlcopymemory", "copymemory", "movememory", "writeprocessmemory")),
    ("PROCESS_CREATE", ("createprocess", "shellexecute", "winexec")),
    ("PROCESS_ENUM", ("process32first", "process32next", "enumprocesses", "ntquerysysteminformation")),
    ("THREAD_CREATE", ("createthread", "createremotethread", "ntcreatethreadex", "rtlcreatethread")),
    ("FILE_OPEN", ("createfile", "openfile", "ntopenfile")),
    ("FILE_READ", ("readfile", "ntreadfile")),
    ("FILE_WRITE", ("writefile", "ntwritefile")),
    ("FILE_DELETE", ("deletefile", "ntdeletefile")),
    ("REGISTRY_READ", ("regqueryvalue", "regopenkey")),
    ("REGISTRY_WRITE", ("regsetvalue", "regcreatekey")),
    ("SERVICE_CREATE", ("createservice",)),
    ("SERVICE_START", ("startservice",)),
    ("NETWORK_INIT", ("internetopen", "wsastartup", "winhttpopen")),
    ("NETWORK_CONNECT", ("connect", "internetconnect", "winhttpconnect", "internetopenurl")),
    ("NETWORK_SEND", ("send", "httpsendrequest", "winhttpsendrequest")),
    ("NETWORK_RECEIVE", ("recv", "internetreadfile", "winhttpreaddata")),
    ("CRYPTO_HASH", ("crypthashdata", "bcryptcreatehash", "cryptcreatehash")),
    ("CRYPTO_ENCRYPT", ("cryptencrypt", "bcryptencrypt")),
    ("CRYPTO_DECRYPT", ("cryptdecrypt", "bcryptdecrypt")),
    ("COMPRESSION", ("compress", "uncompress", "rtlcompressbuffer", "rtldecompressbuffer")),
    ("MODULE_LOAD", ("loadlibrary", "ldrloaddll")),
    ("API_RESOLVE", ("getprocaddress", "ldrgetprocedureaddress")),
]


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _sha256_text(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8", "ignore")).hexdigest()


def _hash_sequence(values: List[str]) -> str:
    cleaned = [str(v) for v in values if str(v)]
    return _sha256_text("\n".join(cleaned)) if cleaned else ""


def _normalize_api_name(value: str) -> str:
    text = API_PREFIX_RE.sub("", str(value or "").strip())
    text = text.replace("::", "!").replace("/", "!").replace("\\", "!")
    text = re.sub(r"\s+", "", text)
    match = API_DLL_RE.match(text)
    if match:
        module = match.group(1).lower()
        func = match.group(2).lower()
        if not module.endswith(".dll") and "." not in module:
            module = f"{module}.dll"
        return f"{module}!{func}"[:200]
    return text.strip("_").lower()[:200]


def _api_semantic_category(value: str) -> str:
    api = _normalize_api_name(value)
    func = api.split("!")[-1].lower()
    func = re.sub(r"[aw]$", "", func)
    for category, tokens in SEMANTIC_API_CATEGORY_RULES:
        if any(func.startswith(token.lower()) or token.lower() in func for token in tokens):
            return category
    return "API_OTHER" if api else ""


def _semantic_api_pattern_rows(semantic: dict) -> List[dict]:
    rows = []
    categories = [str(a.get("api_category") or "") for a in semantic.get("semantic_apis") or [] if isinstance(a, dict)]
    categories = [c for c in categories if c]
    if categories:
        rows.append({"pattern_hash": _hash_sequence(categories), "api_category": "sequence"})
    for i in range(max(0, len(categories) - 1)):
        rows.append({"pattern_hash": _hash_sequence(categories[i:i + 2]), "api_category": "bigram"})
    seen = set()
    out = []
    for row in rows:
        key = (row["pattern_hash"], row["api_category"])
        if row["pattern_hash"] and key not in seen:
            seen.add(key)
            out.append(row)
    return out


def _semantic_feature_sets(function: dict) -> dict:
    semantic = function.get("semantic") if isinstance(function.get("semantic"), dict) else {}
    apis = []
    for item in semantic.get("semantic_apis") or []:
        if isinstance(item, dict):
            category = str(item.get("api_category") or _api_semantic_category(item.get("api_name", "")))
            if category:
                apis.append(category)
    pseudo_ngrams = {str(n.get("ngram_hash")) for n in semantic.get("pseudocode_ngrams") or [] if isinstance(n, dict) and n.get("ngram_hash")}
    micro_ngrams = {str(n.get("ngram_hash")) for n in semantic.get("microcode_ngrams") or [] if isinstance(n, dict) and n.get("ngram_hash")}
    return {
        "pseudocode_hash": str(semantic.get("pseudocode_hash") or ""),
        "ast_hash": str(semantic.get("ast_hash") or ""),
        "control_structure_hash": str(semantic.get("control_structure_hash") or ""),
        "microcode_hash": str(semantic.get("microcode_hash") or ""),
        "semantic_fingerprint": str(semantic.get("microcode_hash") or semantic.get("ast_hash") or semantic.get("pseudocode_hash") or ""),
        "pseudocode_ngrams": pseudo_ngrams,
        "ast_subtrees": {str(x.get("subtree_hash")) for x in semantic.get("ast_subtrees") or [] if isinstance(x, dict) and x.get("subtree_hash")},
        "semantic_apis": set(apis),
        "semantic_api_patterns": {row["pattern_hash"] for row in _semantic_api_pattern_rows(semantic)},
        "dataflow_patterns": {str(x.get("pattern_hash")) for x in semantic.get("dataflow_patterns") or [] if isinstance(x, dict) and x.get("pattern_hash")},
        "microcode_ngrams": micro_ngrams,
        "micro_blocks": {str(x.get("block_hash")) for x in semantic.get("micro_blocks") or [] if isinstance(x, dict) and x.get("block_hash")},
        "semantic_constants": {str(x.get("constant_value")) for x in semantic.get("semantic_constants") or [] if isinstance(x, dict) and x.get("constant_value")},
    }


def _semantic_versions_match(function: dict, settings: dict) -> bool:
    semantic = function.get("semantic") if isinstance(function.get("semantic"), dict) else {}
    if not semantic:
        return False
    expected = (
        ("semantic_version", "semantic_schema_version"),
        ("pseudocode_norm_version", "pseudocode_normalization_version"),
        ("ast_norm_version", "ast_normalization_version"),
        ("microcode_norm_version", "microcode_normalization_version"),
        ("api_semantic_map_version", "api_semantic_map_version"),
    )
    for feature_key, setting_key in expected:
        if _safe_int(semantic.get(feature_key), 1) != int(settings.get(setting_key) or 1):
            return False
    return True


def _parse_int_constant(value: Any) -> Optional[int]:
    if isinstance(value, int):
        return value
    text = str(value or "").strip().lower()
    if not text:
        return None
    try:
        if text.endswith("h") and not text.startswith("0x"):
            return int(text[:-1], 16)
        return int(text, 0)
    except ValueError:
        return None


def _normalize_constant(value: Any) -> str:
    parsed = _parse_int_constant(value)
    if parsed is None:
        return str(value or "").strip().lower()[:80]
    if parsed in COMMON_CODE_CONSTANTS:
        return ""
    return hex(parsed & 0xffffffffffffffff)


def _function_feature_sets(function: dict) -> dict:
    apis = [_normalize_api_name(a) for a in function.get("apis") or []]
    apis = [a for a in apis if a]
    constants = [_normalize_constant(c) for c in function.get("constants") or []]
    strings = [normalize_string(str(s or "")) for s in function.get("strings") or []]
    cfg = function.get("cfg") if isinstance(function.get("cfg"), dict) else {}
    return {
        "raw_hash": str(function.get("raw_hash") or ""),
        "normalized_hash": str(function.get("normalized_hash") or ""),
        "blocks": {str(b.get("block_hash")) for b in function.get("blocks") or [] if isinstance(b, dict) and b.get("block_hash")},
        "ngrams": {str(n.get("ngram_hash")) for n in function.get("ngrams") or [] if isinstance(n, dict) and n.get("ngram_hash")},
        "apis": apis,
        "api_patterns": {row["pattern_hash"] for row in _api_pattern_rows({"apis": apis})},
        "constants": {c for c in constants if c},
        "strings": {s for s in strings if s},
        "cfg": {str(cfg.get("cfg_hash"))} if cfg.get("cfg_hash") else set(),
    }


def _api_pattern_rows(function: dict) -> List[dict]:
    apis = [_normalize_api_name(str(a)) for a in function.get("apis") or [] if str(a)]
    apis = [a for a in apis if a]
    out: List[dict] = []
    if apis:
        out.append({"pattern_hash": _hash_sequence(apis), "pattern_kind": "sequence"})
    for i in range(max(0, len(apis) - 1)):
        out.append({"pattern_hash": _hash_sequence(apis[i:i + 2]), "pattern_kind": "bigram"})
    seen = set()
    unique = []
    for row in out:
        key = (row["pattern_hash"], row["pattern_kind"])
        if row["pattern_hash"] and key not in seen:
            seen.add(key)
            unique.append(row)
    return unique


def _ida_executable(settings: Optional[dict] = None, path: str = "") -> str:
    settings = settings or get_settings()
    candidates = [path, settings.get("ida_path") or "", settings.get("ida_path_32") or ""]
    for candidate in candidates:
        candidate = str(candidate or "").strip().strip('"')
        if candidate and os.path.exists(candidate):
            return _prefer_headless_ida(candidate)
    return ""


def _prefer_headless_ida(path: str) -> str:
    base = os.path.basename(path).lower()
    if base not in {"ida.exe", "ida64.exe"}:
        return path
    folder = os.path.dirname(path)
    preferred = ["idat.exe", "idat64.exe"] if base == "ida.exe" else ["idat64.exe", "idat.exe"]
    for name in preferred:
        sibling = os.path.join(folder, name)
        if os.path.isfile(sibling):
            return sibling
    return path


def _headless_ida_available() -> bool:
    return importlib.util.find_spec("headless_ida") is not None


def _headless_ida_backend_path(ida_path: str) -> str:
    folder = os.path.dirname(ida_path) if os.path.isfile(ida_path) else ida_path
    for name in ("idalib64.dll", "idalib.dll", "libidalib64.so", "libidalib.so", "libidalib64.dylib", "libidalib.dylib"):
        candidate = os.path.join(folder, name)
        if os.path.isfile(candidate):
            return candidate
    return ida_path


def ida_status(settings: Optional[dict] = None) -> dict:
    settings = settings or get_settings()
    path = _ida_executable(settings)
    enabled = bool(settings.get("enable_code_similarity"))
    out = {
        "enabled": enabled,
        "available": False,
        "configured_path": bool((settings.get("ida_path") or settings.get("ida_path_32") or "").strip()),
        "path": path,
        "version": "",
        "version_probe_status": "not_run",
        "version_probe_error": "",
        "headless": bool(path),
        "python": "idapython",
        "reason": "",
    }
    if not enabled:
        out["reason"] = "Code similarity is disabled."
        return out
    if not path:
        out["reason"] = "IDA executable path is not configured or does not exist."
        return out
    try:
        probe = subprocess.run([path, "-v"], capture_output=True, text=True, timeout=3)
        text = ((probe.stdout or "") + " " + (probe.stderr or "")).strip()
        out["version"] = text[:160]
        out["version_probe_status"] = "success"
    except subprocess.TimeoutExpired as e:
        out["version_probe_status"] = "timeout"
        out["version_probe_error"] = str(e)[:300]
    except Exception as e:
        out["version_probe_status"] = "failed"
        out["version_probe_error"] = str(e)[:300]
    out["available"] = True
    out["reason"] = "IDA executable is configured."
    return out


def hexrays_status(settings: Optional[dict] = None) -> dict:
    settings = settings or get_settings()
    ida = ida_status(settings)
    enabled = bool(settings.get("enable_semantic_similarity"))
    out = {
        "enabled": enabled,
        "available": False,
        "status": "disabled" if not enabled else "unknown",
        "architecture": "",
        "decompiler_version": "",
        "supported": False,
        "reason": "",
        "ida": ida,
    }
    if not enabled:
        out["reason"] = "Semantic similarity is disabled."
        return out
    if not settings.get("enable_code_similarity"):
        out["status"] = "ida_disabled"
        out["reason"] = "IDA code similarity must be enabled before Hex-Rays semantic analysis can run."
        return out
    if not ida.get("available"):
        out["status"] = "ida_unavailable"
        out["reason"] = ida.get("reason") or "IDA is unavailable."
        return out
    out["status"] = "configured"
    out["supported"] = True
    out["reason"] = "Hex-Rays availability is verified during headless sample analysis."
    return out


def _cleanup_ida_artifacts(sample_path: str, *extra_paths: str) -> None:
    base = os.path.splitext(sample_path)[0]
    for suffix in IDA_TEMP_SUFFIXES:
        try:
            os.remove(base + suffix)
        except OSError:
            pass
    for path in extra_paths:
        if not path:
            continue
        try:
            os.remove(path)
        except OSError:
            pass


def extract_code_features(path: str, settings: Optional[dict] = None, progress: ProgressCallback = None, sample: str = "") -> Tuple[dict, dict]:
    settings = settings or get_settings()
    base_profile = {
        "status": "disabled",
        "reason": "",
        "analysis_engine": "ida",
        "analysis_engine_version": "",
        "normalization_version": int(settings.get("normalization_version") or 1),
        "feature_schema_version": int(settings.get("feature_schema_version") or 2),
        "ida_analysis_time": 0,
        "feature_extraction_time": 0,
        "function_count": 0,
        "meaningful_function_count": 0,
        "block_count": 0,
        "instruction_count": 0,
        "unique_normalized_functions": 0,
        "unique_block_hashes": 0,
        "unique_ngram_hashes": 0,
        "api_pattern_count": 0,
        "constant_count": 0,
        "cfg_hash_count": 0,
    }
    if not settings.get("enable_code_similarity"):
        base_profile["reason"] = "Code similarity is disabled."
        _progress(progress, "ida", base_profile["reason"], "skipped", sample)
        return {"status": "disabled", "reason": base_profile["reason"], "profile": base_profile, "functions": []}, _status("ida_code", "disabled", base_profile["reason"])
    max_size = int(settings.get("ida_max_file_size") or DEFAULT_SETTINGS["ida_max_file_size"])
    try:
        size = os.path.getsize(path)
    except OSError as e:
        base_profile.update({"status": "failed", "reason": str(e)})
        _progress(progress, "ida", f"IDA skipped: {e}", "failed", sample)
        return {"status": "failed", "reason": str(e), "profile": base_profile, "functions": []}, _status("ida_code", "failed", str(e))
    if size > max_size:
        reason = f"File exceeds IDA max size ({size} > {max_size})."
        base_profile.update({"status": "too_large", "reason": reason})
        _progress(progress, "ida", f"IDA skipped: {reason}", "skipped", sample, {"file_size": size, "max_size": max_size})
        return {"status": "too_large", "reason": reason, "profile": base_profile, "functions": []}, _status("ida_code", "unsupported", reason)
    ida_path = _ida_executable(settings)
    if not ida_path:
        reason = "IDA executable path is not configured."
        base_profile.update({"status": "unavailable", "reason": reason})
        _progress(progress, "ida", f"IDA unavailable: {reason}", "failed", sample)
        return {"status": "unavailable", "reason": reason, "profile": base_profile, "functions": []}, _status("ida_code", "unsupported", reason)
    script = os.path.join(BASE_DIR, "similarity_ida_extract.py")
    if not os.path.exists(script):
        reason = "IDAPython extractor script is missing."
        base_profile.update({"status": "failed", "reason": reason})
        _progress(progress, "ida", f"IDA failed: {reason}", "failed", sample)
        return {"status": "failed", "reason": reason, "profile": base_profile, "functions": []}, _status("ida_code", "failed", reason)
    headless_runner = os.path.join(BASE_DIR, "similarity_headless_ida_runner.py")
    use_headless_ida = _headless_ida_available() and os.path.exists(headless_runner)
    tmpdir = os.path.dirname(os.path.abspath(path)) or tempfile.gettempdir()
    output_json = os.path.join(tmpdir, f"mantis-ida-{os.getpid()}-{int(time.time() * 1000)}.json")
    config_json = os.path.join(tmpdir, f"mantis-ida-config-{os.getpid()}-{int(time.time() * 1000)}.json")
    config = {
        "minimum_function_instructions": int(settings.get("minimum_function_instructions") or 5),
        "minimum_block_instructions": int(settings.get("minimum_block_instructions") or 2),
        "mnemonic_ngram_size": int(settings.get("mnemonic_ngram_size") or 4),
        "exclude_thunks": bool(settings.get("exclude_thunks")),
        "enable_semantic_similarity": bool(settings.get("enable_semantic_similarity")),
        "enable_pseudocode_similarity": bool(settings.get("enable_pseudocode_similarity")),
        "enable_ast_similarity": bool(settings.get("enable_ast_similarity")),
        "enable_microcode_similarity": bool(settings.get("enable_microcode_similarity")),
        "maximum_semantic_functions": int(settings.get("maximum_semantic_functions") or 100),
        "ida_timeout_seconds": int(settings.get("ida_timeout_seconds") or 300),
        "hexrays_timeout_seconds": int(settings.get("hexrays_timeout_seconds") or 120),
        "hexrays_function_timeout_seconds": int(settings.get("hexrays_function_timeout_seconds") or 10),
        "minimum_semantic_function_instructions": int(settings.get("minimum_semantic_function_instructions") or 10),
        "semantic_ngram_size": int(settings.get("semantic_ngram_size") or 4),
        "semantic_schema_version": int(settings.get("semantic_schema_version") or 1),
        "pseudocode_normalization_version": int(settings.get("pseudocode_normalization_version") or 1),
        "ast_normalization_version": int(settings.get("ast_normalization_version") or 1),
        "microcode_normalization_version": int(settings.get("microcode_normalization_version") or 1),
        "api_semantic_map_version": int(settings.get("api_semantic_map_version") or 1),
        "normalization_version": int(settings.get("normalization_version") or 1),
        "feature_schema_version": int(settings.get("feature_schema_version") or 2),
    }
    try:
        with open(config_json, "w", encoding="utf-8") as f:
            json.dump(config, f)
        timeout = int(settings.get("ida_timeout_seconds") or 300)
        direct_cmd = [ida_path, "-A", f'-S"{script}" "{output_json}" "{config_json}"', path]
        direct_label = f"{os.path.basename(ida_path)} direct IDAPython script"
        if use_headless_ida:
            ida_backend = _headless_ida_backend_path(ida_path)
            cmd = [sys.executable, headless_runner, ida_backend, path, output_json, config_json]
            launch_label = f"headless-ida via {os.path.basename(ida_backend)}"
            runner_name = "headless-ida"
        else:
            ida_backend = ida_path
            cmd = direct_cmd
            launch_label = direct_label
            runner_name = "direct"

        def run_ida_process(run_cmd: List[str], label: str, backend_path: str, runner: str):
            _progress(
                progress,
                "ida",
                f"Launching {label} with {timeout}s timeout.",
                "running",
                sample,
                {"ida_path": ida_path, "backend_path": backend_path, "runner": runner, "timeout_seconds": timeout},
            )
            started = time.monotonic()
            proc = subprocess.Popen(
                run_cmd,
                cwd=tmpdir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            _progress(progress, "ida", f"IDA process started (PID {proc.pid}). Waiting for feature output.", "running", sample, {"pid": proc.pid, "runner": runner})
            stdout = ""
            stderr = ""
            next_heartbeat = started + 10
            while True:
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    proc.kill()
                    stdout, stderr = proc.communicate()
                    raise subprocess.TimeoutExpired(run_cmd, timeout, output=stdout, stderr=stderr)
                try:
                    stdout, stderr = proc.communicate(timeout=min(2.0, remaining))
                    break
                except subprocess.TimeoutExpired:
                    now = time.monotonic()
                    if now >= next_heartbeat:
                        elapsed = int(now - started)
                        _progress(progress, "ida", "IDA still running.", "running", sample, {"pid": proc.pid, "elapsed_seconds": elapsed, "runner": runner})
                        next_heartbeat = now + 10
            return type("CompletedIdaProcess", (), {"returncode": proc.returncode, "stdout": stdout, "stderr": stderr})()

        completed = run_ida_process(cmd, launch_label, ida_backend, runner_name)
        _progress(progress, "ida", f"IDA process exited with code {completed.returncode}. Reading feature output.", "running", sample, {"returncode": completed.returncode})
        if use_headless_ida and not os.path.exists(output_json):
            detail = ((completed.stderr or "") + "\n" + (completed.stdout or "")).strip()[:300]
            _progress(
                progress,
                "ida",
                f"headless-ida did not produce feature output; retrying direct IDAPython extractor.{(' ' + detail) if detail else ''}",
                "running",
                sample,
                {"returncode": completed.returncode, "fallback": "direct"},
            )
            completed = run_ida_process(direct_cmd, direct_label, ida_path, "direct")
            _progress(progress, "ida", f"Direct IDA process exited with code {completed.returncode}. Reading feature output.", "running", sample, {"returncode": completed.returncode})
        if not os.path.exists(output_json):
            detail = ((completed.stderr or "") + "\n" + (completed.stdout or "")).strip()[:300]
            reason = f"IDA did not produce a feature output file (exit {completed.returncode})."
            if detail:
                reason = f"{reason} {detail}"
            base_profile.update({"status": "analysis_failed", "reason": reason})
            _progress(progress, "ida", reason, "failed", sample, {"returncode": completed.returncode})
            return {"status": "analysis_failed", "reason": reason, "profile": base_profile, "functions": []}, _status("ida_code", "failed", reason)
        with open(output_json, "r", encoding="utf-8") as f:
            code = json.load(f)
        if not isinstance(code, dict):
            raise ValueError("IDA output was not a JSON object")
        profile = code.get("profile") if isinstance(code.get("profile"), dict) else {}
        status = str(code.get("status") or profile.get("status") or "success")
        profile = {**base_profile, **profile, "status": status, "reason": str(code.get("reason") or profile.get("reason") or "")}
        functions = code.get("functions") if isinstance(code.get("functions"), list) else []
        profile["function_count"] = int(profile.get("function_count") or len(functions))
        code.update({"status": status, "reason": profile.get("reason", ""), "profile": profile, "functions": functions})
        _progress(
            progress,
            "ida",
            f"IDA extraction {status}: {int(profile.get('meaningful_function_count') or 0)} meaningful / {int(profile.get('function_count') or 0)} total functions.",
            "done" if status in {"success", "partial"} else "failed",
            sample,
            {
                "status": status,
                "function_count": int(profile.get("function_count") or 0),
                "meaningful_function_count": int(profile.get("meaningful_function_count") or 0),
                "reason": profile.get("reason", ""),
            },
        )
        return code, _status("ida_code", "success" if status in {"success", "partial"} else "failed", profile.get("reason", ""))
    except subprocess.TimeoutExpired:
        reason = "IDA analysis timed out."
        base_profile.update({"status": "timeout", "reason": reason})
        _progress(progress, "ida", f"{reason} Increase IDA Timeout Seconds if this sample is large.", "failed", sample)
        return {"status": "timeout", "reason": reason, "profile": base_profile, "functions": []}, _status("ida_code", "timeout", reason)
    except Exception as e:
        reason = str(e)
        base_profile.update({"status": "failed", "reason": reason})
        _progress(progress, "ida", f"IDA extraction failed: {reason}", "failed", sample)
        return {"status": "failed", "reason": reason, "profile": base_profile, "functions": []}, _status("ida_code", "failed", reason)
    finally:
        _cleanup_ida_artifacts(path, output_json, config_json)


def _file_type(path: str, data_head: bytes) -> str:
    if data_head.startswith(b"MZ"):
        return "PE"
    if data_head.startswith(b"\x7fELF"):
        return "ELF"
    return "binary"


def _read_bounded(path: str, max_bytes: int = 128 * 1024 * 1024) -> bytes:
    size = os.path.getsize(path)
    if size > max_bytes:
        with open(path, "rb") as f:
            return f.read(max_bytes)
    with open(path, "rb") as f:
        return f.read()


def calculate_hashes(path: str) -> dict:
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            size += len(chunk)
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
    with open(path, "rb") as f:
        head = f.read(8)
    return {
        "md5": h_md5.hexdigest(),
        "sha1": h_sha1.hexdigest(),
        "sha256": h_sha256.hexdigest(),
        "file_size": size,
        "file_type": _file_type(path, head),
    }


def extract_tlsh(path: str) -> Tuple[str, dict]:
    try:
        import tlsh  # type: ignore
    except Exception:
        return "", _status("tlsh", "unsupported", "python tlsh library is not installed")
    try:
        data = _read_bounded(path)
        value = tlsh.hash(data)
        if not value or value.upper() in {"TNULL", "NULL"}:
            return "", _status("tlsh", "not_present", "TLSH did not produce a hash")
        return value, _status("tlsh", "success")
    except Exception as e:
        return "", _status("tlsh", "failed", str(e))


def extract_ssdeep(path: str) -> Tuple[str, dict]:
    try:
        import ssdeep  # type: ignore
    except Exception:
        return "", _status("ssdeep", "unsupported", "python ssdeep library is not installed")
    try:
        return ssdeep.hash_from_file(path), _status("ssdeep", "success")
    except Exception as e:
        return "", _status("ssdeep", "failed", str(e))


def _machine_arch(machine: int) -> str:
    return {
        0x014C: "x86",
        0x8664: "x64",
        0x01C0: "ARM",
        0x01C4: "ARMv7",
        0xAA64: "ARM64",
    }.get(machine, hex(machine) if machine else "")


def _rich_hash_from_bytes(path: str) -> Tuple[str, bool, int]:
    try:
        data = _read_bounded(path, 8 * 1024 * 1024)
    except OSError:
        return "", False, 0
    rich_at = data.find(b"Rich")
    dans_at = data.find(b"DanS")
    if rich_at < 0 or dans_at < 0 or dans_at >= rich_at:
        return "", False, 0
    start = dans_at
    blob = data[start:rich_at + 8]
    entries = max(0, (rich_at - start) // 8)
    return hashlib.sha256(blob).hexdigest(), True, entries


def _resource_type_id(entry) -> Optional[int]:
    try:
        if entry.id is not None:
            return int(entry.id)
    except Exception:
        pass
    return None


def _resource_data(pe, data_entry) -> bytes:
    offset = int(data_entry.struct.OffsetToData)
    size = int(data_entry.struct.Size)
    return pe.get_memory_mapped_image()[offset:offset + size]


def _ico_bytes_from_group(group: bytes, image: bytes, image_size: int) -> bytes:
    if len(group) < 6:
        return b""
    header = group[:6]
    # GRPICONDIRENTRY is 14 bytes. ICONDIRENTRY replaces the final WORD id
    # with DWORD image offset.
    entry = group[6:20]
    if len(entry) != 14:
        return b""
    return header[:4] + b"\x01\x00" + entry[:12] + (22).to_bytes(4, "little") + image[:image_size]


def _icon_phash(ico_data: bytes) -> Tuple[str, int, int, str]:
    try:
        from PIL import Image  # type: ignore
        import imagehash  # type: ignore
    except Exception:
        return "", 0, 0, "Pillow/imagehash are not installed"
    try:
        with Image.open(io.BytesIO(ico_data)) as img:
            frame_count = getattr(img, "n_frames", 1)
            best = None
            for idx in range(frame_count):
                try:
                    img.seek(idx)
                except EOFError:
                    break
                frame = img.convert("RGBA")
                area = frame.width * frame.height
                if best is None or area > best[0]:
                    best = (area, frame.copy())
            if best is None:
                return "", 0, 0, "icon image could not be decoded"
            frame = best[1]
            return str(imagehash.phash(frame)), int(frame.width), int(frame.height), ""
    except Exception as e:
        return "", 0, 0, str(e)


def _extract_pe_icon(pe) -> Tuple[dict, dict]:
    empty = {"icon_sha256": "", "icon_phash": "", "icon_width": 0, "icon_height": 0}
    try:
        resources = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
        if not resources:
            return empty, _status("icon", "not_present")
        group_entries = []
        icon_blobs = {}
        for type_entry in getattr(resources, "entries", []) or []:
            type_id = _resource_type_id(type_entry)
            directory = getattr(type_entry, "directory", None)
            if not directory:
                continue
            for name_entry in getattr(directory, "entries", []) or []:
                name_id = _resource_type_id(name_entry)
                name_dir = getattr(name_entry, "directory", None)
                if not name_dir:
                    continue
                for lang_entry in getattr(name_dir, "entries", []) or []:
                    data = getattr(lang_entry, "data", None)
                    if not data:
                        continue
                    blob = _resource_data(pe, data)
                    if type_id == 3 and name_id is not None:
                        icon_blobs[int(name_id)] = blob
                    elif type_id == 14:
                        group_entries.append(blob)
        candidates = []
        for group in group_entries:
            if len(group) < 6:
                continue
            count = int.from_bytes(group[4:6], "little")
            for idx in range(count):
                off = 6 + idx * 14
                entry = group[off:off + 14]
                if len(entry) != 14:
                    continue
                width = entry[0] or 256
                height = entry[1] or 256
                bit_count = int.from_bytes(entry[6:8], "little")
                image_size = int.from_bytes(entry[8:12], "little")
                icon_id = int.from_bytes(entry[12:14], "little")
                image = icon_blobs.get(icon_id)
                if not image:
                    continue
                score = (width * height, bit_count, image_size, -icon_id)
                candidates.append((score, group[:6] + entry, image, image_size, width, height))
        if not candidates:
            return empty, _status("icon", "not_present")
        candidates.sort(key=lambda c: c[0], reverse=True)
        _score, group_one, image, image_size, width, height = candidates[0]
        ico_data = _ico_bytes_from_group(group_one, image, image_size)
        sha = hashlib.sha256(image[:image_size] if image_size else image).hexdigest()
        phash, pwidth, pheight, phash_error = _icon_phash(ico_data)
        features = {
            "icon_sha256": sha,
            "icon_phash": phash,
            "icon_width": pwidth or width,
            "icon_height": pheight or height,
        }
        if phash:
            return features, _status("icon", "success")
        return features, _status("icon", "partial", phash_error or "icon SHA256 extracted; pHash unavailable")
    except Exception as e:
        return empty, _status("icon", "failed", str(e))


def extract_pe(path: str) -> Tuple[dict, List[dict], List[dict]]:
    features = {
        "architecture": "",
        "imphash": "",
        "rich_hash": "",
        "rich_present": False,
        "rich_entries_count": 0,
        "icon_sha256": "",
        "icon_phash": "",
        "icon_width": 0,
        "icon_height": 0,
    }
    imports: List[dict] = []
    statuses = []
    rich_hash, rich_present, rich_count = _rich_hash_from_bytes(path)
    features.update({"rich_hash": rich_hash, "rich_present": rich_present, "rich_entries_count": rich_count})
    try:
        import pefile  # type: ignore
    except Exception:
        statuses.append(_status("pe", "unsupported", "python pefile library is not installed"))
        statuses.append(_status("rich", "success" if rich_present else "not_present"))
        statuses.append(_status("icon", "unsupported", "icon extraction requires optional PE resource image support"))
        return features, imports, statuses
    try:
        pe = pefile.PE(path, fast_load=False)
        features["architecture"] = _machine_arch(getattr(pe.FILE_HEADER, "Machine", 0))
        try:
            features["imphash"] = pe.get_imphash() or ""
        except Exception:
            features["imphash"] = ""
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            seen = set()
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = (entry.dll or b"").decode("utf-8", errors="ignore").lower()
                dll_norm = re.sub(r"\.dll$", "", dll)
                for imp in entry.imports:
                    if not imp.name:
                        continue
                    fn = imp.name.decode("utf-8", errors="ignore")
                    norm = f"{dll_norm}!{fn}".lower()
                    if norm in seen:
                        continue
                    seen.add(norm)
                    imports.append({"dll": dll_norm, "function": fn, "normalized_import": norm})
        icon_features, icon_status = _extract_pe_icon(pe)
        features.update(icon_features)
        statuses.append(_status("pe", "success"))
        statuses.append(_status("imports", "success" if imports else "not_present"))
        statuses.append(_status("rich", "success" if rich_present else "not_present"))
        statuses.append(icon_status)
    except Exception as e:
        statuses.append(_status("pe", "failed", str(e)))
        statuses.append(_status("imports", "failed", str(e)))
        statuses.append(_status("rich", "success" if rich_present else "not_present"))
        statuses.append(_status("icon", "failed", str(e)))
    return features, imports, statuses


ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile((rb"(?:[\x20-\x7e]\x00){4,}"))


def _fallback_strings(path: str, minimum: int) -> List[dict]:
    data = _read_bounded(path, 32 * 1024 * 1024)
    out = []
    for m in ASCII_RE.finditer(data):
        s = m.group(0).decode("utf-8", errors="ignore")
        if len(s) >= minimum:
            out.append({"string": s, "type": "static", "encoding": "ascii", "address": m.start()})
    for m in UTF16_RE.finditer(data):
        s = m.group(0).decode("utf-16le", errors="ignore")
        if len(s) >= minimum:
            out.append({"string": s, "type": "static", "encoding": "utf-16le", "address": m.start()})
    return out[:5000]


def _floss_strings(path: str, timeout: int, minimum: int) -> Tuple[List[dict], dict]:
    exe = shutil.which("floss")
    if not exe:
        return _fallback_strings(path, minimum), _status("floss", "unsupported", "FLOSS executable not found; used local strings fallback")
    commands = [
        [exe, "--json", path],
        [exe, "-j", path],
    ]
    last_error = ""
    for cmd in commands:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if proc.returncode != 0:
                last_error = (proc.stderr or proc.stdout or "").strip()[:500]
                continue
            payload = json.loads(proc.stdout or "{}")
            strings = []
            raw_sections = []
            if isinstance(payload, dict):
                if isinstance(payload.get("strings"), dict):
                    raw_sections.extend(payload["strings"].items())
                else:
                    for key in ("static_strings", "stack_strings", "tight_strings", "decoded_strings"):
                        raw_sections.append((key, payload.get(key, [])))
            for floss_type, items in raw_sections:
                if isinstance(items, dict):
                    items = items.get("strings", [])
                for item in items or []:
                    if isinstance(item, str):
                        value = item
                        rec = {"string": value, "type": str(floss_type), "encoding": "", "address": None}
                    elif isinstance(item, dict):
                        value = str(item.get("string") or item.get("value") or "")
                        rec = {
                            "string": value,
                            "type": str(item.get("type") or floss_type),
                            "encoding": str(item.get("encoding") or ""),
                            "address": item.get("address"),
                        }
                    else:
                        continue
                    if len(value) >= minimum:
                        strings.append(rec)
            return strings[:10000], _status("floss", "success")
        except Exception as e:
            last_error = str(e)
    return _fallback_strings(path, minimum), _status("floss", "failed", last_error or "FLOSS failed; used local strings fallback")


CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
WS_RE = re.compile(r"\s+")


def normalize_string(value: str) -> str:
    value = CONTROL_RE.sub("", value or "")
    value = WS_RE.sub(" ", value).strip()
    return value


LOW_VALUE_RE = re.compile(
    r"^(kernel32(?:\.dll)?|user32(?:\.dll)?|advapi32(?:\.dll)?|ntdll(?:\.dll)?|msvcrt(?:\.dll)?|loadlibrarya|getprocaddress|microsoft|windows|\.text|\.data|\.rdata|true|false|null)$",
    re.I,
)

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
FILE_LIKE_RE = re.compile(r"^[\w.-]+\.(?:dll|exe|sys|bin|dat|tmp|pdb|ocx|scr|cpl|drv|mui|manifest)$", re.I)
COMMON_TLDS = {
    "com", "net", "org", "info", "biz", "io", "co", "me", "dev", "app",
    "ru", "cn", "ir", "kp", "uk", "us", "de", "fr", "jp", "kr", "au",
    "br", "in", "id", "my", "sg", "th", "vn", "xyz", "top", "site",
    "online", "tech", "cloud",
}


def _is_domain_string(value: str) -> bool:
    if not DOMAIN_RE.fullmatch(value.strip()):
        return False
    if FILE_LIKE_RE.fullmatch(value.strip()):
        return False
    tld = value.rsplit(".", 1)[-1].lower()
    return tld in COMMON_TLDS or len(tld) > 3


def categorize_string(value: str) -> str:
    low = value.lower()
    if URL_RE.search(value):
        return "url"
    if EMAIL_RE.search(value):
        return "email"
    if IP_RE.search(value):
        return "ip"
    if "\\software\\" in low or low.startswith(("hklm\\", "hkcu\\")):
        return "registry"
    if low.endswith(".pdb") or "\\release\\" in low or "\\debug\\" in low:
        return "pdb"
    if "\\global\\" in low or low.startswith("global\\") or "mutex" in low:
        return "mutex"
    if low.startswith("/") and len(value) > 4:
        return "path"
    if re.search(r"[a-z]:\\", value, re.I) or "\\" in value and "." in value:
        return "path"
    if _is_domain_string(value):
        return "domain"
    if "powershell" in low or "cmd.exe" in low or " /c " in low:
        return "command"
    if "user-agent" in low or "mozilla/" in low:
        return "user_agent"
    if "service" in low:
        return "service"
    if re.search(r"(campaign|bot-[%{]|\b[a-z]+_[0-9]{4}_[a-z0-9]+)", value, re.I):
        return "campaign"
    return "generic"


CATEGORY_WEIGHTS = {
    "pdb": 5.0,
    "path": 5.0,
    "mutex": 5.0,
    "campaign": 5.0,
    "domain": 4.0,
    "url": 4.0,
    "registry": 3.5,
    "command": 3.5,
    "service": 3.5,
    "user_agent": 2.5,
    "ip": 2.5,
    "email": 2.0,
    "generic": 1.0,
}


def _clamp_score(value: Any) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return 0.0
    if math.isnan(score) or math.isinf(score):
        return 0.0
    return max(0.0, min(100.0, score))


def _heuristic_string_score(value: str, category: str) -> float:
    score = 0.15
    if category != "generic":
        score += 0.45
    if len(value) >= 12:
        score += 0.1
    if any(c in value for c in "\\/:_%{}?=&"):
        score += 0.12
    if re.search(r"[A-Z].*[a-z]|[a-z].*[A-Z]|\d", value):
        score += 0.08
    if LOW_VALUE_RE.match(value):
        score = 0.0
    return max(0.0, min(1.0, score))


def _stringsifter_scores(strings: List[str], timeout: int) -> Tuple[dict, dict]:
    exe = shutil.which("rank_strings")
    if not exe:
        return {}, _status("stringsifter", "unsupported", "StringSifter rank_strings executable not found; used heuristic ranking")
    try:
        proc = subprocess.run(
            [exe],
            input="\n".join(strings),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0:
            return {}, _status("stringsifter", "failed", (proc.stderr or proc.stdout or "")[:500])
        scores = {}
        for line in (proc.stdout or "").splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                try:
                    scores[parts[1]] = float(parts[0])
                except ValueError:
                    continue
        return scores, _status("stringsifter", "success")
    except Exception as e:
        return {}, _status("stringsifter", "failed", str(e))


def extract_important_strings(path: str, settings: dict) -> Tuple[List[dict], List[dict]]:
    minimum = int(settings.get("minimum_string_length") or 4)
    timeout = int(settings.get("processing_timeout_seconds") or 120)
    raw_strings, floss_status = _floss_strings(path, timeout, minimum)
    normalized_records = []
    counts = Counter()
    first_seen = {}
    for rec in raw_strings:
        raw = str(rec.get("string") or "")
        norm = normalize_string(raw)
        if len(norm) < minimum or LOW_VALUE_RE.match(norm):
            continue
        counts[norm] += 1
        first_seen.setdefault(norm, rec)
    candidates = list(first_seen.keys())
    sifter_scores, sifter_status = _stringsifter_scores(candidates, min(timeout, 30))
    threshold = float(settings.get("stringsifter_threshold") or 0.45)
    for norm in candidates:
        rec = first_seen[norm]
        category = categorize_string(norm)
        score = sifter_scores.get(norm)
        if score is None:
            score = _heuristic_string_score(norm, category)
        if score < threshold and category == "generic":
            continue
        normalized_records.append({
            "raw_string": str(rec.get("string") or norm)[:2000],
            "normalized_string": norm[:2000],
            "category": category,
            "stringsifter_score": float(score),
            "floss_type": str(rec.get("type") or "")[:40],
            "frequency": counts[norm],
        })
    normalized_records.sort(key=lambda r: (r["category"] == "generic", -r["stringsifter_score"], -r["frequency"], r["normalized_string"]))
    return normalized_records[:300], [floss_status, sifter_status]


def process_sample(path: str, filename: str, settings: Optional[dict] = None, progress: ProgressCallback = None) -> dict:
    settings = settings or get_settings()
    statuses: List[dict] = []
    _progress(progress, "sample", f"Processing sample {filename}.", "running", filename)
    _progress(progress, "hashes", "Calculating MD5, SHA1, and SHA256.", "running", filename)
    hashes = calculate_hashes(path)
    statuses.append(_status("hashes", "success"))
    _progress(progress, "hashes", f"Hashes complete. SHA256 {hashes.get('sha256', '')[:12]}...", "done", filename, {"file_size": hashes.get("file_size")})
    _progress(progress, "fuzzy", "Generating TLSH fuzzy hash.", "running", filename)
    tlsh_hash, tlsh_status = extract_tlsh(path)
    _progress(progress, "fuzzy", f"TLSH {tlsh_status.get('status')}: {tlsh_status.get('error') or (tlsh_hash[:16] + '...' if tlsh_hash else 'no hash')}", "done" if tlsh_status.get("status") in {"success", "not_present", "unsupported"} else "failed", filename)
    _progress(progress, "fuzzy", "Generating ssdeep fuzzy hash.", "running", filename)
    ssdeep_hash, ssdeep_status = extract_ssdeep(path)
    statuses.extend([tlsh_status, ssdeep_status])
    _progress(progress, "fuzzy", f"ssdeep {ssdeep_status.get('status')}: {ssdeep_status.get('error') or ('hash generated' if ssdeep_hash else 'no hash')}", "done" if ssdeep_status.get("status") in {"success", "not_present", "unsupported"} else "failed", filename)
    _progress(progress, "pe", "Parsing PE headers, imports, Rich header, and icon.", "running", filename)
    pe_features, imports, pe_statuses = extract_pe(path)
    statuses.extend(pe_statuses)
    _progress(progress, "pe", f"PE parsing complete: {len(imports)} imports, architecture {pe_features.get('architecture') or 'unknown'}.", "done", filename)
    _progress(progress, "strings", "Extracting and scoring strings.", "running", filename)
    strings, string_statuses = extract_important_strings(path, settings)
    statuses.extend(string_statuses)
    _progress(progress, "strings", f"String extraction complete: {len(strings)} selected strings.", "done", filename)
    _progress(progress, "ida", "Starting IDA code feature stage.", "running", filename)
    if settings.get("enable_semantic_similarity"):
        _progress(progress, "semantic", "Hex-Rays semantic extraction is enabled and runs inside the IDA process.", "running", filename)
    else:
        _progress(progress, "semantic", "Hex-Rays semantic extraction is disabled.", "skipped", filename)
    code, code_status = extract_code_features(path, settings, progress, filename)
    if settings.get("enable_semantic_similarity"):
        semantic_state = "done" if code_status.get("status") == "success" else "failed"
        _progress(progress, "semantic", "Hex-Rays semantic stage finished with the IDA extraction result.", semantic_state, filename)
    statuses.append(code_status)
    _progress(progress, "sample", f"Finished sample {filename}.", "done", filename)
    return {
        **hashes,
        "file_name": filename,
        "architecture": pe_features.pop("architecture", ""),
        "tlsh": tlsh_hash,
        "ssdeep": ssdeep_hash,
        "pe": pe_features,
        "imports": imports,
        "strings": strings,
        "code": code,
        "statuses": statuses,
    }


def _delete_code_features_for_sample(conn: sqlite3.Connection, sample_id: int) -> None:
    function_ids = [int(r[0]) for r in conn.execute("SELECT id FROM sample_functions WHERE sample_id = ?", (sample_id,)).fetchall()]
    for function_id in function_ids:
        for table in (
            "function_ngrams", "function_blocks", "function_apis", "function_api_patterns", "function_constants", "function_strings", "function_cfg",
            "function_semantic_features", "function_pseudocode_ngrams", "function_ast_subtrees", "function_semantic_apis",
            "function_dataflow_patterns", "function_microcode_ngrams", "function_micro_blocks", "function_semantic_constants",
        ):
            conn.execute(f"DELETE FROM {table} WHERE function_id = ?", (function_id,))
    conn.execute("DELETE FROM sample_functions WHERE sample_id = ?", (sample_id,))
    conn.execute("DELETE FROM sample_code_profiles WHERE sample_id = ?", (sample_id,))


def _insert_code_features(conn: sqlite3.Connection, sample_id: int, code: Optional[dict]) -> None:
    if not isinstance(code, dict):
        return
    _delete_code_features_for_sample(conn, sample_id)
    profile = code.get("profile") if isinstance(code.get("profile"), dict) else {}
    status = str(code.get("status") or profile.get("status") or "")
    conn.execute(
        "INSERT OR REPLACE INTO sample_code_profiles (sample_id, status, reason, analysis_engine, analysis_engine_version, "
        "normalization_version, feature_schema_version, ida_analysis_time, feature_extraction_time, function_count, "
        "meaningful_function_count, block_count, instruction_count, unique_normalized_functions, unique_block_hashes, "
        "unique_ngram_hashes, api_pattern_count, constant_count, cfg_hash_count) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            sample_id,
            status[:40],
            str(code.get("reason") or profile.get("reason") or "")[:500],
            str(profile.get("analysis_engine") or code.get("analysis_engine") or "")[:40],
            str(profile.get("analysis_engine_version") or code.get("analysis_engine_version") or "")[:120],
            _safe_int(profile.get("normalization_version") or code.get("normalization_version"), 1),
            _safe_int(profile.get("feature_schema_version") or code.get("feature_schema_version"), 2),
            float(profile.get("ida_analysis_time") or 0),
            float(profile.get("feature_extraction_time") or 0),
            _safe_int(profile.get("function_count"), 0),
            _safe_int(profile.get("meaningful_function_count"), 0),
            _safe_int(profile.get("block_count"), 0),
            _safe_int(profile.get("instruction_count"), 0),
            _safe_int(profile.get("unique_normalized_functions"), 0),
            _safe_int(profile.get("unique_block_hashes"), 0),
            _safe_int(profile.get("unique_ngram_hashes"), 0),
            _safe_int(profile.get("api_pattern_count"), 0),
            _safe_int(profile.get("constant_count"), 0),
            _safe_int(profile.get("cfg_hash_count"), 0),
        ),
    )
    for idx, fn in enumerate(code.get("functions") or []):
        if not isinstance(fn, dict):
            continue
        cur = conn.execute(
            "INSERT OR IGNORE INTO sample_functions (sample_id, function_index, ida_address, size, instruction_count, block_count, "
            "cyclomatic_complexity, callers_count, callees_count, referenced_strings_count, imported_api_calls_count, raw_hash, "
            "normalized_hash, is_library, is_thunk) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                sample_id,
                _safe_int(fn.get("function_index"), idx),
                str(fn.get("ida_address") or "")[:40],
                _safe_int(fn.get("size"), 0),
                _safe_int(fn.get("instruction_count"), 0),
                _safe_int(fn.get("block_count"), 0),
                _safe_int(fn.get("cyclomatic_complexity"), 0),
                _safe_int(fn.get("callers_count"), 0),
                _safe_int(fn.get("callees_count"), 0),
                _safe_int(fn.get("referenced_strings_count"), len(fn.get("strings") or [])),
                _safe_int(fn.get("imported_api_calls_count"), len(fn.get("apis") or [])),
                str(fn.get("raw_hash") or "")[:128],
                str(fn.get("normalized_hash") or "")[:128],
                1 if fn.get("is_library") else 0,
                1 if fn.get("is_thunk") else 0,
            ),
        )
        function_id = int(cur.lastrowid or conn.execute(
            "SELECT id FROM sample_functions WHERE sample_id = ? AND function_index = ?",
            (sample_id, _safe_int(fn.get("function_index"), idx)),
        ).fetchone()["id"])
        for ngram in fn.get("ngrams") or []:
            if isinstance(ngram, dict) and ngram.get("ngram_hash"):
                conn.execute(
                    "INSERT OR IGNORE INTO function_ngrams (function_id, ngram_hash, ngram_size) VALUES (?, ?, ?)",
                    (function_id, str(ngram.get("ngram_hash"))[:128], _safe_int(ngram.get("ngram_size"), 4)),
                )
        for block in fn.get("blocks") or []:
            if isinstance(block, dict) and block.get("block_hash"):
                conn.execute(
                    "INSERT OR IGNORE INTO function_blocks (function_id, block_hash, instruction_count, predecessor_count, successor_count) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        function_id,
                        str(block.get("block_hash"))[:128],
                        _safe_int(block.get("instruction_count"), 0),
                        _safe_int(block.get("predecessor_count"), 0),
                        _safe_int(block.get("successor_count"), 0),
                    ),
                )
        for pos, api in enumerate(fn.get("apis") or []):
            api_name = _normalize_api_name(str(api or ""))
            if api_name:
                conn.execute(
                    "INSERT OR IGNORE INTO function_apis (function_id, position, api_name) VALUES (?, ?, ?)",
                    (function_id, pos, api_name),
                )
        for row in _api_pattern_rows(fn):
            conn.execute(
                "INSERT OR IGNORE INTO function_api_patterns (function_id, pattern_hash, pattern_kind) VALUES (?, ?, ?)",
                (function_id, row["pattern_hash"], row["pattern_kind"]),
            )
        for constant in fn.get("constants") or []:
            value = _normalize_constant(constant)
            if value:
                conn.execute(
                    "INSERT OR IGNORE INTO function_constants (function_id, constant_value) VALUES (?, ?)",
                    (function_id, value),
                )
        for s in fn.get("strings") or []:
            norm = normalize_string(str(s or ""))[:500]
            if norm:
                conn.execute(
                    "INSERT OR IGNORE INTO function_strings (function_id, normalized_string) VALUES (?, ?)",
                    (function_id, norm),
                )
        cfg = fn.get("cfg") if isinstance(fn.get("cfg"), dict) else {}
        if cfg and cfg.get("cfg_hash"):
            conn.execute(
                "INSERT OR REPLACE INTO function_cfg (function_id, cfg_hash, nodes, edges, complexity, degree_signature, traversal_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    function_id,
                    str(cfg.get("cfg_hash"))[:128],
                    _safe_int(cfg.get("nodes"), 0),
                    _safe_int(cfg.get("edges"), 0),
                    _safe_int(cfg.get("complexity"), 0),
                    str(cfg.get("degree_signature") or "")[:1000],
                    str(cfg.get("traversal_hash") or "")[:128],
                ),
            )
        semantic = fn.get("semantic") if isinstance(fn.get("semantic"), dict) else {}
        if semantic:
            counts = semantic.get("ast_counts") if isinstance(semantic.get("ast_counts"), dict) else {}
            conn.execute(
                "INSERT OR REPLACE INTO function_semantic_features (function_id, decompiler_status, decompiler_error, pseudocode_hash, ast_hash, "
                "control_structure_hash, semantic_api_hash, microcode_hash, semantic_version, pseudocode_norm_version, ast_norm_version, "
                "microcode_norm_version, api_semantic_map_version, hexrays_version, token_count, ast_node_count, if_count, loop_count, "
                "switch_count, call_count, assignment_count, return_count, pointer_deref_count, arithmetic_count, bitwise_count, comparison_count) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    function_id,
                    str(semantic.get("decompiler_status") or "")[:40],
                    str(semantic.get("decompiler_error") or "")[:500],
                    str(semantic.get("pseudocode_hash") or "")[:128],
                    str(semantic.get("ast_hash") or "")[:128],
                    str(semantic.get("control_structure_hash") or "")[:128],
                    str(semantic.get("semantic_api_hash") or "")[:128],
                    str(semantic.get("microcode_hash") or "")[:128],
                    _safe_int(semantic.get("semantic_version"), 1),
                    _safe_int(semantic.get("pseudocode_norm_version"), 1),
                    _safe_int(semantic.get("ast_norm_version"), 1),
                    _safe_int(semantic.get("microcode_norm_version"), 1),
                    _safe_int(semantic.get("api_semantic_map_version"), 1),
                    str(semantic.get("hexrays_version") or "")[:120],
                    _safe_int(semantic.get("token_count"), 0),
                    _safe_int(counts.get("ast_node_count"), 0),
                    _safe_int(counts.get("if_count"), 0),
                    _safe_int(counts.get("loop_count"), 0),
                    _safe_int(counts.get("switch_count"), 0),
                    _safe_int(counts.get("call_count"), 0),
                    _safe_int(counts.get("assignment_count"), 0),
                    _safe_int(counts.get("return_count"), 0),
                    _safe_int(counts.get("pointer_deref_count"), 0),
                    _safe_int(counts.get("arithmetic_count"), 0),
                    _safe_int(counts.get("bitwise_count"), 0),
                    _safe_int(counts.get("comparison_count"), 0),
                ),
            )
            for ngram in semantic.get("pseudocode_ngrams") or []:
                if isinstance(ngram, dict) and ngram.get("ngram_hash"):
                    conn.execute(
                        "INSERT OR IGNORE INTO function_pseudocode_ngrams (function_id, ngram_hash, ngram_size) VALUES (?, ?, ?)",
                        (function_id, str(ngram.get("ngram_hash"))[:128], _safe_int(ngram.get("ngram_size"), 4)),
                    )
            for subtree in semantic.get("ast_subtrees") or []:
                if isinstance(subtree, dict) and subtree.get("subtree_hash"):
                    conn.execute(
                        "INSERT OR IGNORE INTO function_ast_subtrees (function_id, subtree_hash, occurrence_count) VALUES (?, ?, ?)",
                        (function_id, str(subtree.get("subtree_hash"))[:128], _safe_int(subtree.get("occurrence_count"), 1)),
                    )
            for pos, api in enumerate(semantic.get("semantic_apis") or []):
                if not isinstance(api, dict):
                    continue
                api_name = _normalize_api_name(str(api.get("api_name") or ""))
                category = str(api.get("api_category") or _api_semantic_category(api_name))[:80]
                if category:
                    conn.execute(
                        "INSERT OR IGNORE INTO function_semantic_apis (function_id, position, api_category, api_name) VALUES (?, ?, ?, ?)",
                        (function_id, pos, category, api_name),
                    )
            for pattern in semantic.get("dataflow_patterns") or []:
                if isinstance(pattern, dict) and pattern.get("pattern_hash"):
                    conn.execute(
                        "INSERT OR IGNORE INTO function_dataflow_patterns (function_id, pattern_hash, pattern_type) VALUES (?, ?, ?)",
                        (function_id, str(pattern.get("pattern_hash"))[:128], str(pattern.get("pattern_type") or "")[:80]),
                    )
            for ngram in semantic.get("microcode_ngrams") or []:
                if isinstance(ngram, dict) and ngram.get("ngram_hash"):
                    conn.execute(
                        "INSERT OR IGNORE INTO function_microcode_ngrams (function_id, ngram_hash, ngram_size) VALUES (?, ?, ?)",
                        (function_id, str(ngram.get("ngram_hash"))[:128], _safe_int(ngram.get("ngram_size"), 4)),
                    )
            for block in semantic.get("micro_blocks") or []:
                if isinstance(block, dict) and block.get("block_hash"):
                    conn.execute(
                        "INSERT OR IGNORE INTO function_micro_blocks (function_id, block_hash) VALUES (?, ?)",
                        (function_id, str(block.get("block_hash"))[:128]),
                    )
            for constant in semantic.get("semantic_constants") or []:
                if isinstance(constant, dict):
                    value = _normalize_constant(constant.get("constant_value"))
                    category = str(constant.get("semantic_category") or "CONST")[:80]
                    if value:
                        conn.execute(
                            "INSERT OR IGNORE INTO function_semantic_constants (function_id, constant_value, semantic_category) VALUES (?, ?, ?)",
                            (function_id, value, category),
                        )


def _insert_sample(conn: sqlite3.Connection, entity_id: int, features: dict) -> Tuple[int, bool]:
    row = conn.execute(
        "SELECT id FROM entity_samples WHERE entity_id = ? AND sha256 = ?",
        (entity_id, features["sha256"]),
    ).fetchone()
    if row:
        sample_id = int(row["id"])
        if isinstance(features.get("code"), dict):
            _insert_code_features(conn, sample_id, features.get("code"))
        return sample_id, False
    cur = conn.execute(
        "INSERT INTO entity_samples (entity_id, sha256, sha1, md5, file_name, file_size, file_type, architecture, processed_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            entity_id,
            features["sha256"],
            features.get("sha1", ""),
            features.get("md5", ""),
            features.get("file_name", ""),
            int(features.get("file_size") or 0),
            features.get("file_type", ""),
            features.get("architecture", ""),
            now_iso(),
        ),
    )
    sample_id = int(cur.lastrowid)
    conn.execute("INSERT INTO sample_fuzzy_hashes (sample_id, tlsh, ssdeep) VALUES (?, ?, ?)",
                 (sample_id, features.get("tlsh", ""), features.get("ssdeep", "")))
    pe = features.get("pe") or {}
    conn.execute(
        "INSERT INTO sample_pe_features (sample_id, imphash, rich_hash, rich_present, rich_entries_count, icon_sha256, icon_phash, icon_width, icon_height) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            sample_id,
            pe.get("imphash", ""),
            pe.get("rich_hash", ""),
            1 if pe.get("rich_present") else 0,
            int(pe.get("rich_entries_count") or 0),
            pe.get("icon_sha256", ""),
            pe.get("icon_phash", ""),
            int(pe.get("icon_width") or 0),
            int(pe.get("icon_height") or 0),
        ),
    )
    for imp in features.get("imports") or []:
        conn.execute(
            "INSERT OR IGNORE INTO sample_imports (sample_id, dll, function, normalized_import) VALUES (?, ?, ?, ?)",
            (sample_id, imp.get("dll", ""), imp.get("function", ""), imp.get("normalized_import", "")),
        )
    for s in features.get("strings") or []:
        conn.execute(
            "INSERT OR IGNORE INTO sample_strings (sample_id, raw_string, normalized_string, category, stringsifter_score, floss_type, frequency) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                sample_id,
                s.get("raw_string", ""),
                s.get("normalized_string", ""),
                s.get("category", "generic"),
                float(s.get("stringsifter_score") or 0),
                s.get("floss_type", ""),
                int(s.get("frequency") or 1),
            ),
        )
    _insert_code_features(conn, sample_id, features.get("code"))
    for st in features.get("statuses") or []:
        conn.execute(
            "INSERT OR REPLACE INTO sample_extractor_status (sample_id, extractor, status, error) VALUES (?, ?, ?, ?)",
            (sample_id, st.get("extractor", ""), st.get("status", ""), st.get("error", "")),
        )
    return sample_id, True


def _sample_count(conn: sqlite3.Connection, entity_id: int) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM entity_samples WHERE entity_id = ?", (entity_id,)).fetchone()[0] or 0)


def rebuild_entity_profile(conn: sqlite3.Connection, entity_id: int) -> None:
    total = _sample_count(conn, entity_id)
    for table in (
        "entity_string_features", "entity_import_features", "entity_imphashes", "entity_rich_hashes", "entity_icon_hashes",
        "entity_function_features", "entity_block_features", "entity_ngram_features", "entity_api_patterns",
        "entity_constant_features", "entity_function_string_features", "entity_cfg_features", "entity_code_summary",
        "entity_semantic_functions", "entity_ast_features", "entity_microcode_features", "entity_semantic_api_patterns",
        "entity_dataflow_patterns", "entity_semantic_constants", "entity_semantic_summary",
    ):
        conn.execute(f"DELETE FROM {table} WHERE entity_id = ?", (entity_id,))
    if total <= 0:
        return
    string_rows = conn.execute(
        "SELECT ss.normalized_string, ss.category, COUNT(DISTINCT ss.sample_id) AS c "
        "FROM sample_strings ss JOIN entity_samples es ON es.id = ss.sample_id "
        "WHERE es.entity_id = ? GROUP BY ss.normalized_string, ss.category",
        (entity_id,),
    ).fetchall()
    total_entities = int(conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0] or 1)
    for r in string_rows:
        global_count = int(conn.execute(
            "SELECT COUNT(DISTINCT es.entity_id) FROM sample_strings ss "
            "JOIN entity_samples es ON es.id = ss.sample_id WHERE ss.normalized_string = ?",
            (r["normalized_string"],),
        ).fetchone()[0] or 1)
        rarity = 1.0 + max(0.0, math.log((total_entities + 1) / (global_count + 0.5)))
        conn.execute(
            "INSERT INTO entity_string_features (entity_id, normalized_string, category, sample_count, prevalence, global_entity_count, rarity_weight) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (entity_id, r["normalized_string"], r["category"], int(r["c"]), int(r["c"]) / total, global_count, rarity),
        )
    import_rows = conn.execute(
        "SELECT si.normalized_import, COUNT(DISTINCT si.sample_id) AS c "
        "FROM sample_imports si JOIN entity_samples es ON es.id = si.sample_id "
        "WHERE es.entity_id = ? GROUP BY si.normalized_import",
        (entity_id,),
    ).fetchall()
    for r in import_rows:
        conn.execute(
            "INSERT INTO entity_import_features (entity_id, normalized_import, sample_count, prevalence) VALUES (?, ?, ?, ?)",
            (entity_id, r["normalized_import"], int(r["c"]), int(r["c"]) / total),
        )
    for table, source_table, col in (
        ("entity_imphashes", "sample_pe_features", "imphash"),
        ("entity_rich_hashes", "sample_pe_features", "rich_hash"),
    ):
        rows = conn.execute(
            f"SELECT sp.{col} AS value, COUNT(DISTINCT sp.sample_id) AS c FROM {source_table} sp "
            "JOIN entity_samples es ON es.id = sp.sample_id WHERE es.entity_id = ? "
            f"AND sp.{col} != '' GROUP BY sp.{col}",
            (entity_id,),
        ).fetchall()
        for r in rows:
            conn.execute(
                f"INSERT INTO {table} (entity_id, {col}, sample_count, prevalence) VALUES (?, ?, ?, ?)",
                (entity_id, r["value"], int(r["c"]), int(r["c"]) / total),
            )
    icon_rows = conn.execute(
        "SELECT sp.icon_phash, sp.icon_sha256, COUNT(DISTINCT sp.sample_id) AS c FROM sample_pe_features sp "
        "JOIN entity_samples es ON es.id = sp.sample_id WHERE es.entity_id = ? "
        "AND (sp.icon_phash != '' OR sp.icon_sha256 != '') GROUP BY sp.icon_phash, sp.icon_sha256",
        (entity_id,),
    ).fetchall()
    for r in icon_rows:
        conn.execute(
            "INSERT INTO entity_icon_hashes (entity_id, icon_phash, icon_sha256, sample_count, prevalence) VALUES (?, ?, ?, ?, ?)",
            (entity_id, r["icon_phash"], r["icon_sha256"], int(r["c"]), int(r["c"]) / total),
        )
    settings = get_settings()
    min_instructions = int(settings.get("minimum_function_instructions") or 5)
    norm_version = int(settings.get("normalization_version") or 1)
    schema_version = int(settings.get("feature_schema_version") or 2)
    total_code = int(conn.execute(
        "SELECT COUNT(DISTINCT scp.sample_id) FROM sample_code_profiles scp "
        "JOIN entity_samples es ON es.id = scp.sample_id WHERE es.entity_id = ? AND scp.status IN ('success', 'partial') "
        "AND scp.normalization_version = ? AND scp.feature_schema_version = ?",
        (entity_id, norm_version, schema_version),
    ).fetchone()[0] or 0)
    if total_code <= 0:
        return
    version_clause = "scp.status IN ('success', 'partial') AND scp.normalization_version = ? AND scp.feature_schema_version = ?"
    function_where = f"es.entity_id = ? AND sf.normalized_hash != '' AND sf.instruction_count >= ? AND {version_clause}"
    function_args: List[Any] = [entity_id, min_instructions, norm_version, schema_version]
    if settings.get("exclude_thunks"):
        function_where += " AND sf.is_thunk = 0"
    function_rows = conn.execute(
        "SELECT sf.normalized_hash, COUNT(DISTINCT sf.sample_id) AS c "
        "FROM sample_functions sf JOIN entity_samples es ON es.id = sf.sample_id "
        "JOIN sample_code_profiles scp ON scp.sample_id = sf.sample_id "
        f"WHERE {function_where} GROUP BY sf.normalized_hash",
        tuple(function_args),
    ).fetchall()
    total_entities = int(conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0] or 1)
    for r in function_rows:
        global_count = int(conn.execute(
            "SELECT COUNT(DISTINCT es.entity_id) FROM sample_functions sf "
            "JOIN entity_samples es ON es.id = sf.sample_id JOIN sample_code_profiles scp ON scp.sample_id = sf.sample_id "
            "WHERE sf.normalized_hash = ? AND scp.normalization_version = ? AND scp.feature_schema_version = ?",
            (r["normalized_hash"], norm_version, schema_version),
        ).fetchone()[0] or 1)
        rarity = 1.0 + max(0.0, math.log((total_entities + 1) / (global_count + 0.5)))
        conn.execute(
            "INSERT INTO entity_function_features (entity_id, normalized_hash, sample_count, prevalence, global_entity_count, rarity_weight) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (entity_id, r["normalized_hash"], int(r["c"]), int(r["c"]) / total_code, global_count, rarity),
        )
    aggregate_specs = [
        ("entity_block_features", "block_hash", "function_blocks fb", "fb.block_hash", "fb.function_id = sf.id", "fb.block_hash != ''"),
        ("entity_api_patterns", "pattern_hash", "function_api_patterns fp", "fp.pattern_hash", "fp.function_id = sf.id", "fp.pattern_hash != ''"),
        ("entity_function_string_features", "normalized_string", "function_strings fs", "fs.normalized_string", "fs.function_id = sf.id", "fs.normalized_string != ''"),
        ("entity_cfg_features", "cfg_hash", "function_cfg fc", "fc.cfg_hash", "fc.function_id = sf.id", "fc.cfg_hash != ''"),
    ]
    for table, col, source, expr, join_clause, value_clause in aggregate_specs:
        rows = conn.execute(
            f"SELECT {expr} AS value, COUNT(DISTINCT sf.sample_id) AS c FROM {source} "
            f"JOIN sample_functions sf ON {join_clause} JOIN entity_samples es ON es.id = sf.sample_id "
            f"JOIN sample_code_profiles scp ON scp.sample_id = sf.sample_id "
            f"WHERE es.entity_id = ? AND sf.instruction_count >= ? AND {version_clause} AND {value_clause} GROUP BY {expr}",
            (entity_id, min_instructions, norm_version, schema_version),
        ).fetchall()
        for r in rows:
            conn.execute(
                f"INSERT INTO {table} (entity_id, {col}, sample_count, prevalence) VALUES (?, ?, ?, ?)",
                (entity_id, r["value"], int(r["c"]), int(r["c"]) / total_code),
            )
    ngram_rows = conn.execute(
        "SELECT fn.ngram_hash, fn.ngram_size, COUNT(DISTINCT sf.sample_id) AS c FROM function_ngrams fn "
        "JOIN sample_functions sf ON sf.id = fn.function_id JOIN entity_samples es ON es.id = sf.sample_id "
        "JOIN sample_code_profiles scp ON scp.sample_id = sf.sample_id "
        f"WHERE es.entity_id = ? AND sf.instruction_count >= ? AND {version_clause} AND fn.ngram_hash != '' GROUP BY fn.ngram_hash, fn.ngram_size",
        (entity_id, min_instructions, norm_version, schema_version),
    ).fetchall()
    for r in ngram_rows:
        conn.execute(
            "INSERT INTO entity_ngram_features (entity_id, ngram_hash, ngram_size, sample_count, prevalence) VALUES (?, ?, ?, ?, ?)",
            (entity_id, r["ngram_hash"], int(r["ngram_size"]), int(r["c"]), int(r["c"]) / total_code),
        )
    constant_rows = conn.execute(
        "SELECT fc.constant_value, COUNT(DISTINCT sf.sample_id) AS c FROM function_constants fc "
        "JOIN sample_functions sf ON sf.id = fc.function_id JOIN entity_samples es ON es.id = sf.sample_id "
        "JOIN sample_code_profiles scp ON scp.sample_id = sf.sample_id "
        f"WHERE es.entity_id = ? AND sf.instruction_count >= ? AND {version_clause} AND fc.constant_value != '' GROUP BY fc.constant_value",
        (entity_id, min_instructions, norm_version, schema_version),
    ).fetchall()
    for r in constant_rows:
        global_count = int(conn.execute(
            "SELECT COUNT(DISTINCT es.entity_id) FROM function_constants fc "
            "JOIN sample_functions sf ON sf.id = fc.function_id JOIN entity_samples es ON es.id = sf.sample_id "
            "JOIN sample_code_profiles scp ON scp.sample_id = sf.sample_id "
            "WHERE fc.constant_value = ? AND scp.normalization_version = ? AND scp.feature_schema_version = ?",
            (r["constant_value"], norm_version, schema_version),
        ).fetchone()[0] or 1)
        rarity = 1.0 + max(0.0, math.log((total_entities + 1) / (global_count + 0.5)))
        conn.execute(
            "INSERT INTO entity_constant_features (entity_id, constant_value, sample_count, prevalence, global_entity_count, rarity_weight) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (entity_id, r["constant_value"], int(r["c"]), int(r["c"]) / total_code, global_count, rarity),
        )
    summary = {
        "sample_count": total_code,
        "function_count": int(conn.execute(
            "SELECT COUNT(*) FROM sample_functions sf JOIN entity_samples es ON es.id = sf.sample_id "
            "JOIN sample_code_profiles scp ON scp.sample_id = sf.sample_id "
            f"WHERE es.entity_id = ? AND {version_clause}",
            (entity_id, norm_version, schema_version),
        ).fetchone()[0] or 0),
        "core_function_count": sum(int(r["c"]) for r in function_rows),
        "unique_function_count": len(function_rows),
        "unique_block_count": int(conn.execute("SELECT COUNT(*) FROM entity_block_features WHERE entity_id = ?", (entity_id,)).fetchone()[0] or 0),
        "unique_ngram_count": int(conn.execute("SELECT COUNT(*) FROM entity_ngram_features WHERE entity_id = ?", (entity_id,)).fetchone()[0] or 0),
        "api_pattern_count": int(conn.execute("SELECT COUNT(*) FROM entity_api_patterns WHERE entity_id = ?", (entity_id,)).fetchone()[0] or 0),
        "constant_count": int(conn.execute("SELECT COUNT(*) FROM entity_constant_features WHERE entity_id = ?", (entity_id,)).fetchone()[0] or 0),
        "cfg_hash_count": int(conn.execute("SELECT COUNT(*) FROM entity_cfg_features WHERE entity_id = ?", (entity_id,)).fetchone()[0] or 0),
    }
    conn.execute(
        "INSERT INTO entity_code_summary (entity_id, sample_count, function_count, core_function_count, unique_function_count, "
        "unique_block_count, unique_ngram_count, api_pattern_count, constant_count, cfg_hash_count) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            entity_id, summary["sample_count"], summary["function_count"], summary["core_function_count"],
            summary["unique_function_count"], summary["unique_block_count"], summary["unique_ngram_count"],
            summary["api_pattern_count"], summary["constant_count"], summary["cfg_hash_count"],
        ),
    )
    sem_version = int(settings.get("semantic_schema_version") or 1)
    pseudo_version = int(settings.get("pseudocode_normalization_version") or 1)
    ast_version = int(settings.get("ast_normalization_version") or 1)
    micro_version = int(settings.get("microcode_normalization_version") or 1)
    api_map_version = int(settings.get("api_semantic_map_version") or 1)
    sem_clause = (
        "fsf.decompiler_status = 'success' AND fsf.semantic_version = ? AND fsf.pseudocode_norm_version = ? "
        "AND fsf.ast_norm_version = ? AND fsf.microcode_norm_version = ? AND fsf.api_semantic_map_version = ?"
    )
    sem_args = (sem_version, pseudo_version, ast_version, micro_version, api_map_version)
    total_semantic = int(conn.execute(
        "SELECT COUNT(DISTINCT sf.sample_id) FROM function_semantic_features fsf "
        "JOIN sample_functions sf ON sf.id = fsf.function_id JOIN entity_samples es ON es.id = sf.sample_id "
        f"WHERE es.entity_id = ? AND sf.instruction_count >= ? AND {sem_clause}",
        (entity_id, int(settings.get("minimum_semantic_function_instructions") or 10), *sem_args),
    ).fetchone()[0] or 0)
    if total_semantic <= 0:
        return
    semantic_fingerprint_expr = "COALESCE(NULLIF(fsf.microcode_hash, ''), NULLIF(fsf.ast_hash, ''), NULLIF(fsf.pseudocode_hash, ''))"
    semantic_rows = conn.execute(
        f"SELECT {semantic_fingerprint_expr} AS value, "
        "COUNT(DISTINCT sf.sample_id) AS c FROM function_semantic_features fsf "
        "JOIN sample_functions sf ON sf.id = fsf.function_id JOIN entity_samples es ON es.id = sf.sample_id "
        f"WHERE es.entity_id = ? AND sf.instruction_count >= ? AND {semantic_fingerprint_expr} IS NOT NULL AND {sem_clause} GROUP BY value",
        (entity_id, int(settings.get("minimum_semantic_function_instructions") or 10), *sem_args),
    ).fetchall()
    for r in semantic_rows:
        global_count = int(conn.execute(
            "SELECT COUNT(DISTINCT es.entity_id) FROM function_semantic_features fsf "
            "JOIN sample_functions sf ON sf.id = fsf.function_id JOIN entity_samples es ON es.id = sf.sample_id "
            f"WHERE {semantic_fingerprint_expr} = ? AND {sem_clause}",
            (r["value"], *sem_args),
        ).fetchone()[0] or 1)
        prevalence = int(r["c"]) / total_semantic
        rarity = 1.0 + max(0.0, math.log((total_entities + 1) / (global_count + 0.5)))
        conn.execute(
            "INSERT INTO entity_semantic_functions (entity_id, semantic_fingerprint, sample_count, prevalence, global_entity_count, rarity_weight, core_semantic) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (entity_id, r["value"], int(r["c"]), prevalence, global_count, rarity, 1 if prevalence >= 0.7 else 0),
        )
    sem_feature_specs = [
        ("entity_ast_features", "subtree_hash", "function_ast_subtrees fas", "fas.subtree_hash", "fas.function_id = sf.id", "fas.subtree_hash != ''"),
        ("entity_microcode_features", "feature_hash", "function_microcode_ngrams fmn", "fmn.ngram_hash", "fmn.function_id = sf.id", "fmn.ngram_hash != ''"),
        ("entity_microcode_features", "feature_hash", "function_micro_blocks fmb", "fmb.block_hash", "fmb.function_id = sf.id", "fmb.block_hash != ''"),
    ]
    for table, col, source, expr, join_clause, value_clause in sem_feature_specs:
        rows = conn.execute(
            f"SELECT {expr} AS value, COUNT(DISTINCT sf.sample_id) AS c FROM {source} "
            f"JOIN sample_functions sf ON {join_clause} JOIN entity_samples es ON es.id = sf.sample_id "
            "JOIN function_semantic_features fsf ON fsf.function_id = sf.id "
            f"WHERE es.entity_id = ? AND sf.instruction_count >= ? AND {sem_clause} AND {value_clause} GROUP BY {expr}",
            (entity_id, int(settings.get("minimum_semantic_function_instructions") or 10), *sem_args),
        ).fetchall()
        for r in rows:
            conn.execute(
                f"INSERT OR IGNORE INTO {table} (entity_id, {col}, sample_count, prevalence) VALUES (?, ?, ?, ?)",
                (entity_id, r["value"], int(r["c"]), int(r["c"]) / total_semantic),
            )
    dataflow_rows = conn.execute(
        "SELECT fdp.pattern_hash, fdp.pattern_type, COUNT(DISTINCT sf.sample_id) AS c FROM function_dataflow_patterns fdp "
        "JOIN sample_functions sf ON sf.id = fdp.function_id JOIN entity_samples es ON es.id = sf.sample_id "
        "JOIN function_semantic_features fsf ON fsf.function_id = sf.id "
        f"WHERE es.entity_id = ? AND sf.instruction_count >= ? AND {sem_clause} AND fdp.pattern_hash != '' "
        "GROUP BY fdp.pattern_hash, fdp.pattern_type",
        (entity_id, int(settings.get("minimum_semantic_function_instructions") or 10), *sem_args),
    ).fetchall()
    for r in dataflow_rows:
        conn.execute(
            "INSERT OR IGNORE INTO entity_dataflow_patterns (entity_id, pattern_hash, pattern_type, sample_count, prevalence) VALUES (?, ?, ?, ?, ?)",
            (entity_id, r["pattern_hash"], r["pattern_type"], int(r["c"]), int(r["c"]) / total_semantic),
        )
    api_rows = conn.execute(
        "SELECT fsa.api_category, COUNT(DISTINCT sf.sample_id) AS c FROM function_semantic_apis fsa "
        "JOIN sample_functions sf ON sf.id = fsa.function_id JOIN entity_samples es ON es.id = sf.sample_id "
        "JOIN function_semantic_features fsf ON fsf.function_id = sf.id "
        f"WHERE es.entity_id = ? AND sf.instruction_count >= ? AND {sem_clause} AND fsa.api_category != '' GROUP BY fsa.api_category",
        (entity_id, int(settings.get("minimum_semantic_function_instructions") or 10), *sem_args),
    ).fetchall()
    for r in api_rows:
        conn.execute(
            "INSERT OR IGNORE INTO entity_semantic_api_patterns (entity_id, pattern_hash, api_category, sample_count, prevalence) VALUES (?, ?, ?, ?, ?)",
            (entity_id, _sha256_text(r["api_category"]), r["api_category"], int(r["c"]), int(r["c"]) / total_semantic),
        )
    semantic_constant_rows = conn.execute(
        "SELECT fsc.constant_value, COUNT(DISTINCT sf.sample_id) AS c FROM function_semantic_constants fsc "
        "JOIN sample_functions sf ON sf.id = fsc.function_id JOIN entity_samples es ON es.id = sf.sample_id "
        "JOIN function_semantic_features fsf ON fsf.function_id = sf.id "
        f"WHERE es.entity_id = ? AND sf.instruction_count >= ? AND {sem_clause} AND fsc.constant_value != '' GROUP BY fsc.constant_value",
        (entity_id, int(settings.get("minimum_semantic_function_instructions") or 10), *sem_args),
    ).fetchall()
    for r in semantic_constant_rows:
        global_count = int(conn.execute(
            "SELECT COUNT(DISTINCT es.entity_id) FROM function_semantic_constants fsc "
            "JOIN sample_functions sf ON sf.id = fsc.function_id JOIN entity_samples es ON es.id = sf.sample_id "
            "JOIN function_semantic_features fsf ON fsf.function_id = sf.id "
            f"WHERE fsc.constant_value = ? AND {sem_clause}",
            (r["constant_value"], *sem_args),
        ).fetchone()[0] or 1)
        rarity = 1.0 + max(0.0, math.log((total_entities + 1) / (global_count + 0.5)))
        conn.execute(
            "INSERT INTO entity_semantic_constants (entity_id, constant_value, sample_count, prevalence, global_entity_count, rarity_weight) VALUES (?, ?, ?, ?, ?, ?)",
            (entity_id, r["constant_value"], int(r["c"]), int(r["c"]) / total_semantic, global_count, rarity),
        )
    function_count = int(conn.execute(
        "SELECT COUNT(*) FROM sample_functions sf JOIN entity_samples es ON es.id = sf.sample_id WHERE es.entity_id = ? AND sf.instruction_count >= ?",
        (entity_id, int(settings.get("minimum_semantic_function_instructions") or 10)),
    ).fetchone()[0] or 0)
    decompiled_count = int(conn.execute(
        "SELECT COUNT(*) FROM function_semantic_features fsf JOIN sample_functions sf ON sf.id = fsf.function_id "
        "JOIN entity_samples es ON es.id = sf.sample_id "
        f"WHERE es.entity_id = ? AND sf.instruction_count >= ? AND {sem_clause}",
        (entity_id, int(settings.get("minimum_semantic_function_instructions") or 10), *sem_args),
    ).fetchone()[0] or 0)
    hexrays_version = conn.execute(
        "SELECT fsf.hexrays_version FROM function_semantic_features fsf JOIN sample_functions sf ON sf.id = fsf.function_id "
        "JOIN entity_samples es ON es.id = sf.sample_id WHERE es.entity_id = ? AND fsf.hexrays_version != '' LIMIT 1",
        (entity_id,),
    ).fetchone()
    conn.execute(
        "INSERT INTO entity_semantic_summary (entity_id, sample_count, function_count, decompiled_function_count, semantic_coverage, "
        "core_semantic_function_count, unique_semantic_function_count, ast_feature_count, microcode_feature_count, semantic_api_pattern_count, "
        "dataflow_pattern_count, semantic_constant_count, semantic_schema_version, pseudocode_norm_version, ast_norm_version, "
        "microcode_norm_version, api_semantic_map_version, hexrays_version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            entity_id, total_semantic, function_count, decompiled_count,
            (decompiled_count / function_count * 100.0) if function_count else 0.0,
            int(conn.execute("SELECT COUNT(*) FROM entity_semantic_functions WHERE entity_id = ? AND core_semantic = 1", (entity_id,)).fetchone()[0] or 0),
            int(conn.execute("SELECT COUNT(*) FROM entity_semantic_functions WHERE entity_id = ?", (entity_id,)).fetchone()[0] or 0),
            int(conn.execute("SELECT COUNT(*) FROM entity_ast_features WHERE entity_id = ?", (entity_id,)).fetchone()[0] or 0),
            int(conn.execute("SELECT COUNT(*) FROM entity_microcode_features WHERE entity_id = ?", (entity_id,)).fetchone()[0] or 0),
            int(conn.execute("SELECT COUNT(*) FROM entity_semantic_api_patterns WHERE entity_id = ?", (entity_id,)).fetchone()[0] or 0),
            int(conn.execute("SELECT COUNT(*) FROM entity_dataflow_patterns WHERE entity_id = ?", (entity_id,)).fetchone()[0] or 0),
            int(conn.execute("SELECT COUNT(*) FROM entity_semantic_constants WHERE entity_id = ?", (entity_id,)).fetchone()[0] or 0),
            sem_version, pseudo_version, ast_version, micro_version, api_map_version,
            hexrays_version["hexrays_version"] if hexrays_version else "",
        ),
    )


def rebuild_all_rarity(conn: sqlite3.Connection) -> None:
    entity_ids = [int(r["id"]) for r in conn.execute("SELECT id FROM entities").fetchall()]
    for eid in entity_ids:
        rebuild_entity_profile(conn, eid)


def create_entity(name: str, entity_type: str, description: str, samples: List[Tuple[str, str]], progress: ProgressCallback = None) -> dict:
    init_db()
    name = (name or "").strip()
    if not name:
        raise ValueError("Entity name is required")
    entity_type = entity_type if entity_type in {"malware", "threat_actor"} else "malware"
    settings = get_settings()
    processed = []
    warnings = []
    conn = connect()
    try:
        ts = now_iso()
        cur = conn.execute(
            "INSERT INTO entities (name, type, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (name[:200], entity_type, (description or "")[:2000], ts, ts),
        )
        entity_id = int(cur.lastrowid)
        _progress(progress, "database", f"Created entity row #{entity_id}.", "done")
        for filename, path in samples:
            features = process_sample(path, filename, settings, progress)
            other = conn.execute(
                "SELECT e.id, e.name FROM entity_samples es JOIN entities e ON e.id = es.entity_id "
                "WHERE es.sha256 = ? AND e.id != ? LIMIT 5",
                (features["sha256"], entity_id),
            ).fetchall()
            if other:
                warnings.append({
                    "file_name": filename,
                    "sha256": features["sha256"],
                    "message": "Sample is already associated with another entity.",
                    "entities": [dict(r) for r in other],
                })
            _progress(progress, "database", f"Saving extracted features for {filename}.", "running", filename)
            sample_id, inserted = _insert_sample(conn, entity_id, features)
            _progress(progress, "database", f"Saved sample #{sample_id} ({'new' if inserted else 'existing'}).", "done", filename)
            processed.append({
                "sample_id": sample_id,
                "file_name": filename,
                "sha256": features["sha256"],
                "inserted": inserted,
                "statuses": features.get("statuses", []),
            })
        _progress(progress, "database", "Rebuilding entity rarity indexes and aggregate profile.", "running")
        rebuild_all_rarity(conn)
        conn.execute("UPDATE entities SET updated_at = ? WHERE id = ?", (now_iso(), entity_id))
        conn.commit()
        _progress(progress, "database", "Entity profile committed.", "done")
        return {"entity_id": entity_id, "status": "processed", "processed": processed, "warnings": warnings}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def update_entity(entity_id: int, name: str, entity_type: str, description: str) -> dict:
    init_db()
    name = (name or "").strip()
    if not name:
        raise ValueError("Entity name is required")
    entity_type = entity_type if entity_type in {"malware", "threat_actor"} else "malware"
    conn = connect()
    try:
        cur = conn.execute(
            "UPDATE entities SET name = ?, type = ?, description = ?, updated_at = ? WHERE id = ?",
            (name[:200], entity_type, (description or "")[:2000], now_iso(), int(entity_id)),
        )
        conn.commit()
        if cur.rowcount <= 0:
            return {}
        return get_entity(int(entity_id))
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def add_entity_samples(entity_id: int, samples: List[Tuple[str, str]], progress: ProgressCallback = None) -> dict:
    init_db()
    settings = get_settings()
    processed = []
    warnings = []
    conn = connect()
    try:
        entity = conn.execute("SELECT * FROM entities WHERE id = ?", (int(entity_id),)).fetchone()
        if not entity:
            return {}
        for filename, path in samples:
            features = process_sample(path, filename, settings, progress)
            other = conn.execute(
                "SELECT e.id, e.name FROM entity_samples es JOIN entities e ON e.id = es.entity_id "
                "WHERE es.sha256 = ? AND e.id != ? LIMIT 5",
                (features["sha256"], int(entity_id)),
            ).fetchall()
            if other:
                warnings.append({
                    "file_name": filename,
                    "sha256": features["sha256"],
                    "message": "Sample is already associated with another entity.",
                    "entities": [dict(r) for r in other],
                })
            _progress(progress, "database", f"Saving extracted features for {filename}.", "running", filename)
            sample_id, inserted = _insert_sample(conn, int(entity_id), features)
            _progress(progress, "database", f"Saved sample #{sample_id} ({'new' if inserted else 'existing'}).", "done", filename)
            processed.append({
                "sample_id": sample_id,
                "file_name": filename,
                "sha256": features["sha256"],
                "inserted": inserted,
                "statuses": features.get("statuses", []),
            })
        _progress(progress, "database", "Rebuilding entity rarity indexes and aggregate profile.", "running")
        rebuild_all_rarity(conn)
        conn.execute("UPDATE entities SET updated_at = ? WHERE id = ?", (now_iso(), int(entity_id)))
        conn.commit()
        _progress(progress, "database", "Entity profile committed.", "done")
        return {"entity_id": int(entity_id), "status": "processed", "processed": processed, "warnings": warnings}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def list_entities() -> dict:
    init_db()
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT e.*, COUNT(es.id) AS sample_count FROM entities e "
            "LEFT JOIN entity_samples es ON es.entity_id = e.id "
            "GROUP BY e.id ORDER BY e.created_at DESC"
        ).fetchall()
        return {"entities": [dict(r) for r in rows]}
    finally:
        conn.close()


def get_entity(entity_id: int) -> dict:
    init_db()
    conn = connect()
    try:
        entity = conn.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()
        if not entity:
            return {}
        samples = [dict(r) for r in conn.execute(
            "SELECT * FROM entity_samples WHERE entity_id = ? ORDER BY processed_at DESC", (entity_id,)
        ).fetchall()]
        strings = [dict(r) for r in conn.execute(
            "SELECT * FROM entity_string_features WHERE entity_id = ? ORDER BY prevalence DESC, rarity_weight DESC LIMIT 200",
            (entity_id,),
        ).fetchall()]
        imports = [dict(r) for r in conn.execute(
            "SELECT * FROM entity_import_features WHERE entity_id = ? ORDER BY prevalence DESC, normalized_import LIMIT 200",
            (entity_id,),
        ).fetchall()]
        imphashes = [dict(r) for r in conn.execute("SELECT * FROM entity_imphashes WHERE entity_id = ? ORDER BY prevalence DESC", (entity_id,)).fetchall()]
        rich = [dict(r) for r in conn.execute("SELECT * FROM entity_rich_hashes WHERE entity_id = ? ORDER BY prevalence DESC", (entity_id,)).fetchall()]
        icons = [dict(r) for r in conn.execute("SELECT * FROM entity_icon_hashes WHERE entity_id = ? ORDER BY prevalence DESC", (entity_id,)).fetchall()]
        code_summary = conn.execute("SELECT * FROM entity_code_summary WHERE entity_id = ?", (entity_id,)).fetchone()
        semantic_summary = conn.execute("SELECT * FROM entity_semantic_summary WHERE entity_id = ?", (entity_id,)).fetchone()
        code_profiles = [dict(r) for r in conn.execute(
            "SELECT es.id AS sample_id, es.file_name, scp.* FROM entity_samples es "
            "LEFT JOIN sample_code_profiles scp ON scp.sample_id = es.id WHERE es.entity_id = ? ORDER BY es.processed_at DESC",
            (entity_id,),
        ).fetchall()]
        fuzzy = [dict(r) for r in conn.execute(
            "SELECT es.id AS sample_id, es.file_name, sf.tlsh, sf.ssdeep, "
            "tl.status AS tlsh_status, tl.error AS tlsh_error, sd.status AS ssdeep_status, sd.error AS ssdeep_error "
            "FROM entity_samples es "
            "LEFT JOIN sample_fuzzy_hashes sf ON sf.sample_id = es.id "
            "LEFT JOIN sample_extractor_status tl ON tl.sample_id = es.id AND tl.extractor = 'tlsh' "
            "LEFT JOIN sample_extractor_status sd ON sd.sample_id = es.id AND sd.extractor = 'ssdeep' "
            "WHERE es.entity_id = ? ORDER BY es.processed_at DESC",
            (entity_id,),
        ).fetchall()]
        return {
            "entity": dict(entity),
            "samples": samples,
            "strings": strings,
            "imports": imports,
            "imphashes": imphashes,
            "rich_hashes": rich,
            "icons": icons,
            "code_summary": dict(code_summary) if code_summary else {},
            "semantic_summary": dict(semantic_summary) if semantic_summary else {},
            "code_profiles": code_profiles,
            "fuzzy_hashes": fuzzy,
        }
    finally:
        conn.close()


def get_entity_code(entity_id: int) -> dict:
    init_db()
    conn = connect()
    try:
        entity = conn.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()
        if not entity:
            return {}
        summary = conn.execute("SELECT * FROM entity_code_summary WHERE entity_id = ?", (entity_id,)).fetchone()
        return {
            "entity": dict(entity),
            "summary": dict(summary) if summary else {},
            "semantic_summary": dict(conn.execute("SELECT * FROM entity_semantic_summary WHERE entity_id = ?", (entity_id,)).fetchone() or {}),
            "functions": [dict(r) for r in conn.execute(
                "SELECT * FROM entity_function_features WHERE entity_id = ? ORDER BY prevalence DESC, rarity_weight DESC LIMIT 200",
                (entity_id,),
            ).fetchall()],
            "blocks": [dict(r) for r in conn.execute(
                "SELECT * FROM entity_block_features WHERE entity_id = ? ORDER BY prevalence DESC LIMIT 200",
                (entity_id,),
            ).fetchall()],
            "ngrams": [dict(r) for r in conn.execute(
                "SELECT * FROM entity_ngram_features WHERE entity_id = ? ORDER BY prevalence DESC LIMIT 200",
                (entity_id,),
            ).fetchall()],
            "api_patterns": [dict(r) for r in conn.execute(
                "SELECT * FROM entity_api_patterns WHERE entity_id = ? ORDER BY prevalence DESC LIMIT 200",
                (entity_id,),
            ).fetchall()],
            "constants": [dict(r) for r in conn.execute(
                "SELECT * FROM entity_constant_features WHERE entity_id = ? ORDER BY prevalence DESC, rarity_weight DESC LIMIT 200",
                (entity_id,),
            ).fetchall()],
            "cfg": [dict(r) for r in conn.execute(
                "SELECT * FROM entity_cfg_features WHERE entity_id = ? ORDER BY prevalence DESC LIMIT 200",
                (entity_id,),
            ).fetchall()],
            "semantic_functions": [dict(r) for r in conn.execute(
                "SELECT * FROM entity_semantic_functions WHERE entity_id = ? ORDER BY core_semantic DESC, prevalence DESC, rarity_weight DESC LIMIT 200",
                (entity_id,),
            ).fetchall()],
            "semantic_apis": [dict(r) for r in conn.execute(
                "SELECT * FROM entity_semantic_api_patterns WHERE entity_id = ? ORDER BY prevalence DESC LIMIT 200",
                (entity_id,),
            ).fetchall()],
            "dataflow": [dict(r) for r in conn.execute(
                "SELECT * FROM entity_dataflow_patterns WHERE entity_id = ? ORDER BY prevalence DESC LIMIT 200",
                (entity_id,),
            ).fetchall()],
        }
    finally:
        conn.close()


def get_entity_functions(entity_id: int, limit: int = 200) -> dict:
    init_db()
    conn = connect()
    try:
        entity = conn.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()
        if not entity:
            return {}
        rows = [dict(r) for r in conn.execute(
            "SELECT sf.*, es.file_name FROM sample_functions sf JOIN entity_samples es ON es.id = sf.sample_id "
            "WHERE es.entity_id = ? ORDER BY sf.instruction_count DESC LIMIT ?",
            (entity_id, max(1, min(1000, int(limit or 200)))),
        ).fetchall()]
        return {"entity": dict(entity), "functions": rows}
    finally:
        conn.close()


def rebuild_entity_code(entity_id: int) -> dict:
    init_db()
    conn = connect()
    try:
        if not conn.execute("SELECT id FROM entities WHERE id = ?", (entity_id,)).fetchone():
            return {}
        rebuild_entity_profile(conn, entity_id)
        conn.execute("UPDATE entities SET updated_at = ? WHERE id = ?", (now_iso(), entity_id))
        conn.commit()
        return get_entity_code(entity_id)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def delete_entity(entity_id: int) -> bool:
    init_db()
    conn = connect()
    try:
        sample_ids = [r[0] for r in conn.execute("SELECT id FROM entity_samples WHERE entity_id = ?", (entity_id,)).fetchall()]
        for sid in sample_ids:
            _delete_code_features_for_sample(conn, int(sid))
            for table in ("sample_fuzzy_hashes", "sample_pe_features", "sample_imports", "sample_strings", "sample_extractor_status"):
                conn.execute(f"DELETE FROM {table} WHERE sample_id = ?", (sid,))
        for table in (
            "entity_samples", "entity_string_features", "entity_import_features", "entity_imphashes", "entity_rich_hashes",
            "entity_icon_hashes", "entity_function_features", "entity_block_features", "entity_ngram_features",
            "entity_api_patterns", "entity_constant_features", "entity_function_string_features", "entity_cfg_features",
            "entity_code_summary",
            "entity_semantic_functions", "entity_ast_features", "entity_microcode_features", "entity_semantic_api_patterns",
            "entity_dataflow_patterns", "entity_semantic_constants", "entity_semantic_summary",
        ):
            conn.execute(f"DELETE FROM {table} WHERE entity_id = ?", (entity_id,))
        cur = conn.execute("DELETE FROM entities WHERE id = ?", (entity_id,))
        rebuild_all_rarity(conn)
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def _weighted_jaccard(a: Dict[str, float], b: Dict[str, float]) -> Tuple[float, List[str]]:
    if not a or not b:
        return 0.0, []
    keys = set(a) | set(b)
    intersection = 0.0
    union = 0.0
    matches = []
    for k in keys:
        av = a.get(k, 0.0)
        bv = b.get(k, 0.0)
        intersection += min(av, bv)
        union += max(av, bv)
        if av > 0 and bv > 0:
            matches.append(k)
    return _clamp_score(intersection / union * 100.0 if union else 0.0), matches


def _tlsh_score(distance: int) -> float:
    if distance <= 0:
        return 100.0
    if distance <= 30:
        return _clamp_score(100.0 - (distance / 30.0) * 10.0)
    if distance <= 70:
        return _clamp_score(89.0 - ((distance - 30) / 40.0) * 19.0)
    if distance <= 120:
        return _clamp_score(69.0 - ((distance - 70) / 50.0) * 29.0)
    return _clamp_score(39.0 - min(distance - 120, 120) / 120.0 * 39.0)


def _phash_score(a: str, b: str) -> Tuple[float, Optional[int]]:
    if not a or not b:
        return 0.0, None
    try:
        ai = int(a, 16)
        bi = int(b, 16)
        dist = (ai ^ bi).bit_count()
    except Exception:
        return (100.0 if a == b else 0.0), 0 if a == b else None
    if dist == 0:
        return 100.0, dist
    if dist <= 5:
        return _clamp_score(95.0 - dist), dist
    if dist <= 10:
        return _clamp_score(80.0 - (dist - 5) * 4), dist
    return _clamp_score(40.0 - (dist - 10) * 4), dist


@dataclass
class FeatureScore:
    feature: str
    score: float = 0.0
    available: bool = False
    evidence: Any = field(default_factory=list)


def _code_status_ok(code: dict) -> bool:
    status = str((code or {}).get("status") or (code or {}).get("profile", {}).get("status") or "")
    return status in {"success", "partial"}


def _meaningful_code_functions(code: dict, settings: dict) -> List[dict]:
    min_instructions = int(settings.get("minimum_function_instructions") or 5)
    out = []
    for fn in (code or {}).get("functions") or []:
        if not isinstance(fn, dict):
            continue
        if settings.get("exclude_thunks") and fn.get("is_thunk"):
            continue
        if _safe_int(fn.get("instruction_count"), 0) < min_instructions:
            continue
        if not fn.get("normalized_hash"):
            continue
        out.append(fn)
    return out


def _code_weight_for_function(fn: dict, settings: dict) -> float:
    weight = 1.0
    if settings.get("downweight_library_functions") and fn.get("is_library"):
        weight *= 0.35
    instructions = _safe_int(fn.get("instruction_count"), 0)
    if instructions >= 100:
        weight *= 1.5
    elif instructions >= 40:
        weight *= 1.2
    return weight


def _feature_map_from_rows(rows: List[sqlite3.Row], key: str, weight_cols: Tuple[str, ...] = ("prevalence",)) -> Dict[str, float]:
    out: Dict[str, float] = {}
    for r in rows:
        value = str(r[key] or "")
        if not value:
            continue
        weight = 1.0
        for col in weight_cols:
            try:
                weight *= float(r[col])
            except Exception:
                pass
        out[value] = max(out.get(value, 0.0), max(0.1, weight))
    return out


def _dict_weight(values: set) -> Dict[str, float]:
    return {str(v): 1.0 for v in values if str(v)}


def _stored_function_features(conn: sqlite3.Connection, function_id: int) -> dict:
    row = conn.execute("SELECT * FROM sample_functions WHERE id = ?", (function_id,)).fetchone()
    if not row:
        return {}
    cfg = conn.execute("SELECT * FROM function_cfg WHERE function_id = ?", (function_id,)).fetchone()
    apis = [r["api_name"] for r in conn.execute(
        "SELECT api_name FROM function_apis WHERE function_id = ? ORDER BY position ASC",
        (function_id,),
    ).fetchall()]
    return {
        "id": function_id,
        "sample_id": int(row["sample_id"]),
        "ida_address": row["ida_address"],
        "raw_hash": row["raw_hash"],
        "normalized_hash": row["normalized_hash"],
        "instruction_count": int(row["instruction_count"] or 0),
        "is_library": bool(row["is_library"]),
        "is_thunk": bool(row["is_thunk"]),
        "blocks": {r["block_hash"] for r in conn.execute("SELECT block_hash FROM function_blocks WHERE function_id = ?", (function_id,)).fetchall()},
        "ngrams": {r["ngram_hash"] for r in conn.execute("SELECT ngram_hash FROM function_ngrams WHERE function_id = ?", (function_id,)).fetchall()},
        "apis": apis,
        "api_patterns": {r["pattern_hash"] for r in conn.execute("SELECT pattern_hash FROM function_api_patterns WHERE function_id = ?", (function_id,)).fetchall()},
        "constants": {r["constant_value"] for r in conn.execute("SELECT constant_value FROM function_constants WHERE function_id = ?", (function_id,)).fetchall()},
        "strings": {r["normalized_string"] for r in conn.execute("SELECT normalized_string FROM function_strings WHERE function_id = ?", (function_id,)).fetchall()},
        "cfg": {cfg["cfg_hash"]} if cfg and cfg["cfg_hash"] else set(),
    }


def _add_candidate_counts(conn: sqlite3.Connection, scores: Dict[int, float], sql: str, values: set, args: Tuple[Any, ...], weight: float) -> None:
    values = sorted({str(v) for v in values if str(v)})[:500]
    if not values:
        return
    placeholders = ",".join("?" for _ in values)
    rows = conn.execute(sql.format(placeholders=placeholders), (*args, *values)).fetchall()
    for r in rows:
        scores[int(r["function_id"])] = scores.get(int(r["function_id"]), 0.0) + weight * float(r["shared"] or 0)


def _function_similarity_score(unknown: dict, stored: dict, settings: dict) -> Tuple[float, dict]:
    if not stored:
        return 0.0, {}
    unknown_sets = _function_feature_sets(unknown)
    raw_exact = bool(unknown_sets["raw_hash"] and unknown_sets["raw_hash"] == stored.get("raw_hash"))
    normalized_exact = bool(unknown_sets["normalized_hash"] and unknown_sets["normalized_hash"] == stored.get("normalized_hash"))
    if raw_exact:
        return 100.0, {"exact_raw_hash": True, "exact_normalized_hash": normalized_exact}
    ngram_score, ngram_matches = _weighted_jaccard(_dict_weight(unknown_sets["ngrams"]), _dict_weight(stored.get("ngrams", set())))
    block_score, block_matches = _weighted_jaccard(_dict_weight(unknown_sets["blocks"]), _dict_weight(stored.get("blocks", set())))
    api_score, api_matches = _weighted_jaccard(_dict_weight(unknown_sets["api_patterns"]), _dict_weight(stored.get("api_patterns", set())))
    const_score, const_matches = _weighted_jaccard(_dict_weight(unknown_sets["constants"]), _dict_weight(stored.get("constants", set())))
    string_score, string_matches = _weighted_jaccard(_dict_weight(unknown_sets["strings"]), _dict_weight(stored.get("strings", set())))
    cfg_score, cfg_matches = _weighted_jaccard(_dict_weight(unknown_sets["cfg"]), _dict_weight(stored.get("cfg", set())))
    component_scores = {
        "normalized": FeatureScore("normalized", 100.0 if normalized_exact else 0.0, bool(unknown_sets["normalized_hash"] and stored.get("normalized_hash")), []),
        "blocks": FeatureScore("blocks", block_score, bool(unknown_sets["blocks"] and stored.get("blocks")), block_matches),
        "ngrams": FeatureScore("ngrams", ngram_score, bool(unknown_sets["ngrams"] and stored.get("ngrams")), ngram_matches),
        "api_patterns": FeatureScore("api_patterns", api_score, bool(unknown_sets["api_patterns"] and stored.get("api_patterns")), api_matches),
        "constants": FeatureScore("constants", const_score, bool(unknown_sets["constants"] and stored.get("constants")), const_matches),
        "function_strings": FeatureScore("function_strings", string_score, bool(unknown_sets["strings"] and stored.get("strings")), string_matches),
        "cfg": FeatureScore("cfg", cfg_score, bool(unknown_sets["cfg"] and stored.get("cfg")), cfg_matches),
    }
    score, active_weights = _overall(component_scores, {
        "normalized": 40,
        "blocks": 15,
        "ngrams": 15,
        "api_patterns": 10,
        "constants": 5,
        "function_strings": 5,
        "cfg": 10,
    })
    if settings.get("downweight_library_functions") and stored.get("is_library"):
        score *= 0.35
    if stored.get("is_thunk"):
        score *= 0.1
    return _clamp_score(score), {
        "exact_raw_hash": False,
        "exact_normalized_hash": normalized_exact,
        "component_scores": {k: round(v.score, 2) for k, v in component_scores.items() if v.available},
        "normalized_weights": active_weights,
    }


def _function_candidates(conn: sqlite3.Connection, unknown: dict, entity_id: int, settings: dict) -> List[dict]:
    features = _function_feature_sets(unknown)
    if not features["normalized_hash"]:
        return []
    min_instructions = int(settings.get("minimum_function_instructions") or 5)
    norm_version = int(settings.get("normalization_version") or 1)
    schema_version = int(settings.get("feature_schema_version") or 2)
    args = (entity_id, min_instructions, norm_version, schema_version)
    base_where = (
        "es.entity_id = ? AND sf.instruction_count >= ? AND scp.status IN ('success', 'partial') "
        "AND scp.normalization_version = ? AND scp.feature_schema_version = ?"
    )
    if settings.get("exclude_thunks"):
        base_where += " AND sf.is_thunk = 0"
    scores: Dict[int, float] = {}
    for col, value, weight in (("raw_hash", features["raw_hash"], 1000.0), ("normalized_hash", features["normalized_hash"], 600.0)):
        if not value:
            continue
        rows = conn.execute(
            f"SELECT sf.id AS function_id, COUNT(*) AS shared FROM sample_functions sf "
            f"JOIN entity_samples es ON es.id = sf.sample_id JOIN sample_code_profiles scp ON scp.sample_id = sf.sample_id "
            f"WHERE {base_where} AND sf.{col} = ? GROUP BY sf.id",
            (*args, value),
        ).fetchall()
        for r in rows:
            scores[int(r["function_id"])] = scores.get(int(r["function_id"]), 0.0) + weight
    _add_candidate_counts(conn, scores,
        "SELECT sf.id AS function_id, COUNT(DISTINCT fb.block_hash) AS shared FROM function_blocks fb "
        "JOIN sample_functions sf ON sf.id = fb.function_id JOIN entity_samples es ON es.id = sf.sample_id "
        "JOIN sample_code_profiles scp ON scp.sample_id = sf.sample_id "
        f"WHERE {base_where} AND fb.block_hash IN ({{placeholders}}) GROUP BY sf.id",
        features["blocks"], args, 8.0)
    _add_candidate_counts(conn, scores,
        "SELECT sf.id AS function_id, COUNT(DISTINCT fn.ngram_hash) AS shared FROM function_ngrams fn "
        "JOIN sample_functions sf ON sf.id = fn.function_id JOIN entity_samples es ON es.id = sf.sample_id "
        "JOIN sample_code_profiles scp ON scp.sample_id = sf.sample_id "
        f"WHERE {base_where} AND fn.ngram_hash IN ({{placeholders}}) GROUP BY sf.id",
        features["ngrams"], args, 3.0)
    _add_candidate_counts(conn, scores,
        "SELECT sf.id AS function_id, COUNT(DISTINCT fp.pattern_hash) AS shared FROM function_api_patterns fp "
        "JOIN sample_functions sf ON sf.id = fp.function_id JOIN entity_samples es ON es.id = sf.sample_id "
        "JOIN sample_code_profiles scp ON scp.sample_id = sf.sample_id "
        f"WHERE {base_where} AND fp.pattern_hash IN ({{placeholders}}) GROUP BY sf.id",
        features["api_patterns"], args, 4.0)
    _add_candidate_counts(conn, scores,
        "SELECT sf.id AS function_id, COUNT(DISTINCT fc.constant_value) AS shared FROM function_constants fc "
        "JOIN sample_functions sf ON sf.id = fc.function_id JOIN entity_samples es ON es.id = sf.sample_id "
        "JOIN sample_code_profiles scp ON scp.sample_id = sf.sample_id "
        f"WHERE {base_where} AND fc.constant_value IN ({{placeholders}}) GROUP BY sf.id",
        features["constants"], args, 1.0)
    _add_candidate_counts(conn, scores,
        "SELECT sf.id AS function_id, COUNT(DISTINCT fs.normalized_string) AS shared FROM function_strings fs "
        "JOIN sample_functions sf ON sf.id = fs.function_id JOIN entity_samples es ON es.id = sf.sample_id "
        "JOIN sample_code_profiles scp ON scp.sample_id = sf.sample_id "
        f"WHERE {base_where} AND fs.normalized_string IN ({{placeholders}}) GROUP BY sf.id",
        features["strings"], args, 4.0)
    _add_candidate_counts(conn, scores,
        "SELECT sf.id AS function_id, COUNT(DISTINCT fc.cfg_hash) AS shared FROM function_cfg fc "
        "JOIN sample_functions sf ON sf.id = fc.function_id JOIN entity_samples es ON es.id = sf.sample_id "
        "JOIN sample_code_profiles scp ON scp.sample_id = sf.sample_id "
        f"WHERE {base_where} AND fc.cfg_hash IN ({{placeholders}}) GROUP BY sf.id",
        features["cfg"], args, 5.0)
    ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))[:int(settings.get("candidate_functions") or 20)]
    out = []
    for function_id, rank_score in ranked:
        stored = _stored_function_features(conn, function_id)
        score, evidence = _function_similarity_score(unknown, stored, settings)
        if score <= 0:
            continue
        out.append({
            "function_id": function_id,
            "sample_id": stored.get("sample_id"),
            "ida_address": unknown.get("ida_address", ""),
            "matched_address": stored.get("ida_address", ""),
            "normalized_hash": features["normalized_hash"],
            "matched_normalized_hash": stored.get("normalized_hash", ""),
            "instruction_count": _safe_int(unknown.get("instruction_count"), 0),
            "score": round(score, 2),
            "rank_score": round(rank_score, 2),
            **evidence,
        })
    out.sort(key=lambda row: (-float(row["score"]), -float(row["rank_score"]), int(row["function_id"])))
    return out


def compare_code_to_entity(conn: sqlite3.Connection, code: dict, entity_id: int, settings: dict) -> FeatureScore:
    evidence = {
        "status": str((code or {}).get("status") or ""),
        "functions_matched": 0,
        "meaningful_functions": 0,
        "coverage": 0.0,
        "candidate_score": 0.0,
        "component_scores": {},
        "matched_functions": [],
    }
    if not isinstance(code, dict) or not _code_status_ok(code):
        return FeatureScore("code", 0.0, False, evidence)
    profile = code.get("profile") if isinstance(code.get("profile"), dict) else {}
    if _safe_int(profile.get("normalization_version") or code.get("normalization_version"), 1) != int(settings.get("normalization_version") or 1):
        evidence["reason"] = "Normalization version mismatch."
        return FeatureScore("code", 0.0, False, evidence)
    if _safe_int(profile.get("feature_schema_version") or code.get("feature_schema_version"), 2) != int(settings.get("feature_schema_version") or 2):
        evidence["reason"] = "Feature schema version mismatch."
        return FeatureScore("code", 0.0, False, evidence)
    summary = conn.execute("SELECT * FROM entity_code_summary WHERE entity_id = ?", (entity_id,)).fetchone()
    if not summary or int(summary["unique_function_count"] or 0) <= 0:
        return FeatureScore("code", 0.0, False, evidence)
    functions = _meaningful_code_functions(code, settings)
    evidence["meaningful_functions"] = len(functions)
    if not functions:
        return FeatureScore("code", 0.0, False, evidence)

    unknown_functions: Dict[str, float] = {}
    unknown_blocks: Dict[str, float] = {}
    unknown_ngrams: Dict[str, float] = {}
    unknown_api_patterns: Dict[str, float] = {}
    unknown_constants: Dict[str, float] = {}
    unknown_strings: Dict[str, float] = {}
    unknown_cfg: Dict[str, float] = {}
    function_weights: Dict[str, float] = {}
    for fn in functions:
        fn_weight = _code_weight_for_function(fn, settings)
        feature_sets = _function_feature_sets(fn)
        norm_hash = feature_sets["normalized_hash"]
        unknown_functions[norm_hash] = max(unknown_functions.get(norm_hash, 0.0), fn_weight)
        function_weights[norm_hash] = max(function_weights.get(norm_hash, 0.0), fn_weight)
        for value in feature_sets["blocks"]:
            unknown_blocks[value] = 1.0
        for value in feature_sets["ngrams"]:
            unknown_ngrams[value] = 1.0
        for value in feature_sets["api_patterns"]:
            unknown_api_patterns[value] = 1.0
        for value in feature_sets["constants"]:
            unknown_constants[value] = 1.0
        for value in feature_sets["strings"]:
            unknown_strings[value] = 1.0
        for value in feature_sets["cfg"]:
            unknown_cfg[value] = 1.0

    entity_functions = _feature_map_from_rows(
        conn.execute("SELECT * FROM entity_function_features WHERE entity_id = ?", (entity_id,)).fetchall(),
        "normalized_hash",
        ("prevalence", "rarity_weight"),
    )
    entity_blocks = _feature_map_from_rows(conn.execute("SELECT * FROM entity_block_features WHERE entity_id = ?", (entity_id,)).fetchall(), "block_hash")
    entity_ngrams = _feature_map_from_rows(conn.execute("SELECT * FROM entity_ngram_features WHERE entity_id = ?", (entity_id,)).fetchall(), "ngram_hash")
    entity_api_patterns = _feature_map_from_rows(conn.execute("SELECT * FROM entity_api_patterns WHERE entity_id = ?", (entity_id,)).fetchall(), "pattern_hash")
    entity_constants = _feature_map_from_rows(
        conn.execute("SELECT * FROM entity_constant_features WHERE entity_id = ?", (entity_id,)).fetchall(),
        "constant_value",
        ("prevalence", "rarity_weight"),
    )
    entity_strings = _feature_map_from_rows(conn.execute("SELECT * FROM entity_function_string_features WHERE entity_id = ?", (entity_id,)).fetchall(), "normalized_string")
    entity_cfg = _feature_map_from_rows(conn.execute("SELECT * FROM entity_cfg_features WHERE entity_id = ?", (entity_id,)).fetchall(), "cfg_hash")

    component_sources = {
        "functions": (unknown_functions, entity_functions),
        "blocks": (unknown_blocks, entity_blocks),
        "ngrams": (unknown_ngrams, entity_ngrams),
        "api_patterns": (unknown_api_patterns, entity_api_patterns),
        "constants": (unknown_constants, entity_constants),
        "function_strings": (unknown_strings, entity_strings),
        "cfg": (unknown_cfg, entity_cfg),
    }
    component_scores: Dict[str, FeatureScore] = {}
    for name, (unknown, entity_map) in component_sources.items():
        score, matches = _weighted_jaccard(unknown, entity_map)
        component_scores[name] = FeatureScore(name, score, bool(unknown and entity_map), matches)
        evidence["component_scores"][name] = round(score, 2) if unknown and entity_map else None
    weights = settings.get("code_weights") or DEFAULT_SETTINGS["code_weights"]
    code_score, normalized_weights = _overall(component_scores, weights)
    threshold = float(settings.get("minimum_function_match") or 55)
    total_function_weight = sum(_code_weight_for_function(fn, settings) for fn in functions) or 1.0
    matched_weight = 0.0
    candidate_weighted_score = 0.0
    best_matches = []
    for fn in functions:
        fn_weight = _code_weight_for_function(fn, settings)
        candidates_for_fn = _function_candidates(conn, fn, entity_id, settings)
        if not candidates_for_fn:
            continue
        best = candidates_for_fn[0]
        if float(best.get("score") or 0) >= threshold:
            matched_weight += fn_weight
            candidate_weighted_score += float(best["score"]) * fn_weight
            best_matches.append(best)
    candidate_sample_score = candidate_weighted_score / total_function_weight if total_function_weight else 0.0
    evidence["functions_matched"] = len(best_matches)
    evidence["coverage"] = round((matched_weight / total_function_weight) * 100.0, 2) if total_function_weight else 0.0
    evidence["candidate_score"] = round(candidate_sample_score, 2)
    evidence["normalized_weights"] = normalized_weights
    code_score = _clamp_score((code_score * 0.45) + (candidate_sample_score * 0.55))
    if evidence["coverage"] < 5 and not any(m.get("exact_raw_hash") for m in best_matches):
        code_score = min(code_score, 35.0)
    best_matches.sort(key=lambda x: (-float(x["score"]), -int(x.get("instruction_count") or 0), int(x["function_id"])))
    evidence["matched_functions"] = best_matches[:int(settings.get("candidate_functions") or 20)]
    return FeatureScore("code", code_score, any(v.available for v in component_scores.values()), evidence)


def compare_semantic_to_entity(conn: sqlite3.Connection, code: dict, entity_id: int, settings: dict) -> FeatureScore:
    evidence = {
        "status": str((code or {}).get("status") or ""),
        "semantic_functions_matched": 0,
        "semantic_functions": 0,
        "semantic_coverage": 0.0,
        "component_scores": {},
        "matched_functions": [],
    }
    if not settings.get("enable_semantic_similarity"):
        evidence["reason"] = "Semantic similarity is disabled."
        return FeatureScore("semantic_code", 0.0, False, evidence)
    if not isinstance(code, dict) or not _code_status_ok(code):
        return FeatureScore("semantic_code", 0.0, False, evidence)
    summary = conn.execute("SELECT * FROM entity_semantic_summary WHERE entity_id = ?", (entity_id,)).fetchone()
    if not summary or int(summary["unique_semantic_function_count"] or 0) <= 0:
        return FeatureScore("semantic_code", 0.0, False, evidence)
    expected_versions = {
        "semantic_schema_version": int(settings.get("semantic_schema_version") or 1),
        "pseudocode_norm_version": int(settings.get("pseudocode_normalization_version") or 1),
        "ast_norm_version": int(settings.get("ast_normalization_version") or 1),
        "microcode_norm_version": int(settings.get("microcode_normalization_version") or 1),
        "api_semantic_map_version": int(settings.get("api_semantic_map_version") or 1),
    }
    for key, expected in expected_versions.items():
        if int(summary[key] or 0) != expected:
            evidence["reason"] = "Semantic version mismatch."
            return FeatureScore("semantic_code", 0.0, False, evidence)
    min_instructions = int(settings.get("minimum_semantic_function_instructions") or 10)
    functions = [
        fn for fn in _meaningful_code_functions(code, {**settings, "minimum_function_instructions": min_instructions})
        if isinstance(fn.get("semantic"), dict) and str(fn.get("semantic", {}).get("decompiler_status") or "") == "success"
    ]
    if functions and not all(_semantic_versions_match(fn, settings) for fn in functions):
        evidence["reason"] = "Semantic version mismatch."
        return FeatureScore("semantic_code", 0.0, False, evidence)
    evidence["semantic_functions"] = len(functions)
    if not functions:
        return FeatureScore("semantic_code", 0.0, False, evidence)

    unknown_functions: Dict[str, float] = {}
    unknown_ast: Dict[str, float] = {}
    unknown_micro: Dict[str, float] = {}
    unknown_apis: Dict[str, float] = {}
    unknown_dataflow: Dict[str, float] = {}
    unknown_constants: Dict[str, float] = {}
    matched = []
    matched_weight = 0.0
    total_weight = 0.0
    for fn in functions:
        weight = _code_weight_for_function(fn, settings)
        total_weight += weight
        sets = _semantic_feature_sets(fn)
        fingerprint = sets["semantic_fingerprint"]
        if fingerprint:
            unknown_functions[fingerprint] = max(unknown_functions.get(fingerprint, 0.0), weight)
        for value in sets["pseudocode_ngrams"] | sets["ast_subtrees"]:
            unknown_ast[value] = 1.0
        for value in sets["microcode_ngrams"] | sets["micro_blocks"]:
            unknown_micro[value] = 1.0
        for value in sets["semantic_api_patterns"] | {_sha256_text(v) for v in sets["semantic_apis"] if v}:
            unknown_apis[value] = 1.0
        for value in sets["dataflow_patterns"]:
            unknown_dataflow[value] = 1.0
        for value in sets["semantic_constants"]:
            unknown_constants[value] = 1.0

    entity_functions = _feature_map_from_rows(
        conn.execute("SELECT * FROM entity_semantic_functions WHERE entity_id = ?", (entity_id,)).fetchall(),
        "semantic_fingerprint",
        ("prevalence", "rarity_weight"),
    )
    entity_ast = _feature_map_from_rows(conn.execute("SELECT * FROM entity_ast_features WHERE entity_id = ?", (entity_id,)).fetchall(), "subtree_hash")
    entity_micro = _feature_map_from_rows(conn.execute("SELECT * FROM entity_microcode_features WHERE entity_id = ?", (entity_id,)).fetchall(), "feature_hash")
    entity_apis = _feature_map_from_rows(conn.execute("SELECT * FROM entity_semantic_api_patterns WHERE entity_id = ?", (entity_id,)).fetchall(), "pattern_hash")
    entity_dataflow = _feature_map_from_rows(conn.execute("SELECT * FROM entity_dataflow_patterns WHERE entity_id = ?", (entity_id,)).fetchall(), "pattern_hash")
    entity_constants = _feature_map_from_rows(
        conn.execute("SELECT * FROM entity_semantic_constants WHERE entity_id = ?", (entity_id,)).fetchall(),
        "constant_value",
        ("prevalence", "rarity_weight"),
    )
    component_sources = {
        "semantic_functions": (unknown_functions, entity_functions),
        "ast": (unknown_ast, entity_ast),
        "microcode": (unknown_micro, entity_micro),
        "semantic_api": (unknown_apis, entity_apis),
        "dataflow": (unknown_dataflow, entity_dataflow),
        "constants": (unknown_constants, entity_constants),
    }
    component_scores: Dict[str, FeatureScore] = {}
    for name, (unknown, entity_map) in component_sources.items():
        score, matches = _weighted_jaccard(unknown, entity_map)
        component_scores[name] = FeatureScore(name, score, bool(unknown and entity_map), matches)
        evidence["component_scores"][name] = round(score, 2) if unknown and entity_map else None
    semantic_score, normalized_weights = _overall(component_scores, {
        "semantic_functions": 30,
        "microcode": 25,
        "ast": 20,
        "semantic_api": 15,
        "dataflow": 7,
        "constants": 3,
    })
    threshold = float(settings.get("minimum_semantic_match") or 60)
    exact_matches = set(component_scores["semantic_functions"].evidence or [])
    for fn in functions:
        sets = _semantic_feature_sets(fn)
        if sets["semantic_fingerprint"] and sets["semantic_fingerprint"] in exact_matches:
            weight = _code_weight_for_function(fn, settings)
            matched_weight += weight
            matched.append({
                "ida_address": fn.get("ida_address", ""),
                "semantic_fingerprint": sets["semantic_fingerprint"],
                "instruction_count": _safe_int(fn.get("instruction_count"), 0),
                "score": 100.0,
                "match_type": "Semantic Exact",
            })
    evidence["semantic_functions_matched"] = len(matched)
    evidence["semantic_coverage"] = round((matched_weight / total_weight) * 100.0, 2) if total_weight else 0.0
    evidence["normalized_weights"] = normalized_weights
    if matched:
        semantic_score = max(semantic_score, evidence["semantic_coverage"])
    if matched and evidence["semantic_coverage"] < 5:
        semantic_score = min(semantic_score, 40.0)
        evidence["shared_component"] = True
    if float(summary["semantic_coverage"] or 0) < 20:
        semantic_score = min(semantic_score, 55.0)
        evidence["low_entity_semantic_coverage"] = True
    matched.sort(key=lambda x: (-x["score"], -x["instruction_count"], x["semantic_fingerprint"]))
    evidence["matched_functions"] = matched[:int(settings.get("semantic_candidate_functions") or 20)]
    return FeatureScore("semantic_code", semantic_score, any(v.available for v in component_scores.values()), evidence)


def compare_features_to_entity(conn: sqlite3.Connection, features: dict, entity: sqlite3.Row) -> Tuple[dict, List[dict]]:
    entity_id = int(entity["id"])
    settings = get_settings()
    unknown_strings = {}
    for s in features.get("strings") or []:
        cat = s.get("category", "generic")
        unknown_strings[s.get("normalized_string", "")] = CATEGORY_WEIGHTS.get(cat, 1.0) * max(0.1, float(s.get("stringsifter_score") or 0.1))
    entity_strings = {}
    for r in conn.execute("SELECT * FROM entity_string_features WHERE entity_id = ?", (entity_id,)).fetchall():
        entity_strings[r["normalized_string"]] = CATEGORY_WEIGHTS.get(r["category"], 1.0) * float(r["prevalence"]) * float(r["rarity_weight"])
    string_score, string_matches = _weighted_jaccard(unknown_strings, entity_strings)

    unknown_imports = {i.get("normalized_import", ""): 1.0 for i in features.get("imports") or []}
    entity_imports = {r["normalized_import"]: max(0.1, float(r["prevalence"])) for r in conn.execute(
        "SELECT * FROM entity_import_features WHERE entity_id = ?", (entity_id,)
    ).fetchall()}
    import_score, import_matches = _weighted_jaccard(unknown_imports, entity_imports)

    pe = features.get("pe") or {}
    imphash = pe.get("imphash") or ""
    imphash_rows = [dict(r) for r in conn.execute("SELECT * FROM entity_imphashes WHERE entity_id = ?", (entity_id,)).fetchall()]
    imphash_match = next((r for r in imphash_rows if r["imphash"] == imphash and imphash), None)
    rich_hash = pe.get("rich_hash") or ""
    rich_rows = [dict(r) for r in conn.execute("SELECT * FROM entity_rich_hashes WHERE entity_id = ?", (entity_id,)).fetchall()]
    rich_match = next((r for r in rich_rows if r["rich_hash"] == rich_hash and rich_hash), None)

    icon_score = 0.0
    icon_evidence = {}
    icon_available = bool(pe.get("icon_phash") or pe.get("icon_sha256"))
    if icon_available:
        for r in conn.execute("SELECT * FROM entity_icon_hashes WHERE entity_id = ?", (entity_id,)).fetchall():
            score = 0.0
            dist = None
            if pe.get("icon_sha256") and pe.get("icon_sha256") == r["icon_sha256"]:
                score = 100.0
                dist = 0
            elif pe.get("icon_phash") and r["icon_phash"]:
                score, dist = _phash_score(pe["icon_phash"], r["icon_phash"])
            if score > icon_score:
                icon_score = score
                icon_evidence = {"icon_phash": r["icon_phash"], "icon_sha256": r["icon_sha256"], "phash_distance": dist}

    tlsh_available = bool(features.get("tlsh"))
    tlsh_score = 0.0
    tlsh_evidence = {}
    if tlsh_available:
        try:
            import tlsh  # type: ignore
            for r in conn.execute(
                "SELECT es.id AS sample_id, es.file_name, sf.tlsh FROM sample_fuzzy_hashes sf "
                "JOIN entity_samples es ON es.id = sf.sample_id WHERE es.entity_id = ? AND sf.tlsh != ''",
                (entity_id,),
            ).fetchall():
                dist = int(tlsh.diff(features["tlsh"], r["tlsh"]))
                score = _tlsh_score(dist)
                if score > tlsh_score:
                    tlsh_score = score
                    tlsh_evidence = {"sample_id": r["sample_id"], "file_name": r["file_name"], "distance": dist}
        except Exception as e:
            tlsh_evidence = {"error": str(e)[:200]}

    ssdeep_available = bool(features.get("ssdeep"))
    ssdeep_score = 0.0
    ssdeep_evidence = {}
    if ssdeep_available:
        try:
            import ssdeep  # type: ignore
            for r in conn.execute(
                "SELECT es.id AS sample_id, es.file_name, sf.ssdeep FROM sample_fuzzy_hashes sf "
                "JOIN entity_samples es ON es.id = sf.sample_id WHERE es.entity_id = ? AND sf.ssdeep != ''",
                (entity_id,),
            ).fetchall():
                score = _clamp_score(ssdeep.compare(features["ssdeep"], r["ssdeep"]))
                if score > ssdeep_score:
                    ssdeep_score = score
                    ssdeep_evidence = {"sample_id": r["sample_id"], "file_name": r["file_name"]}
        except Exception as e:
            ssdeep_evidence = {"error": str(e)[:200]}

    scores = {
        "semantic_code": compare_semantic_to_entity(conn, features.get("code") or {}, entity_id, settings),
        "code": compare_code_to_entity(conn, features.get("code") or {}, entity_id, settings),
        "strings": FeatureScore("strings", string_score, bool(unknown_strings and entity_strings), string_matches[:25]),
        "imports": FeatureScore("imports", import_score, bool(unknown_imports and entity_imports), import_matches[:25]),
        "imphash": FeatureScore("imphash", 100.0 if imphash_match else 0.0, bool(imphash and imphash_rows), imphash_match or {}),
        "rich": FeatureScore("rich", 100.0 if rich_match else 0.0, bool(rich_hash and rich_rows), rich_match or {}),
        "icon": FeatureScore("icon", _clamp_score(icon_score), icon_available and bool(icon_evidence), icon_evidence),
        "tlsh": FeatureScore("tlsh", _clamp_score(tlsh_score), tlsh_available and bool(tlsh_evidence) and "error" not in tlsh_evidence, tlsh_evidence),
        "ssdeep": FeatureScore("ssdeep", _clamp_score(ssdeep_score), ssdeep_available and bool(ssdeep_evidence) and "error" not in ssdeep_evidence, ssdeep_evidence),
    }
    exact = conn.execute(
        "SELECT id, file_name FROM entity_samples WHERE entity_id = ? AND sha256 = ?",
        (entity_id, features["sha256"]),
    ).fetchone()
    sample_matches = []
    if exact:
        for score in scores.values():
            if score.available:
                score.score = 100.0
        sample_matches.append({"sample_id": exact["id"], "file_name": exact["file_name"], "score": 100.0, "reason": "Exact SHA256 match"})
    return scores, sample_matches


def _overall(scores: Dict[str, FeatureScore], weights: dict) -> Tuple[float, dict]:
    active = {k: float(weights.get(k, 0)) for k, v in scores.items() if v.available and float(weights.get(k, 0)) > 0}
    total = sum(active.values())
    if total <= 0:
        return 0.0, {}
    overall = sum(_clamp_score(scores[k].score) * (w / total) for k, w in active.items())
    return _clamp_score(overall), {k: w / total for k, w in active.items()}


def _confidence(overall: float, scores: Dict[str, FeatureScore], entity_type: str) -> Tuple[str, str, str]:
    semantic_code = scores.get("semantic_code", FeatureScore("semantic_code"))
    code = scores.get("code", FeatureScore("code"))
    strings = scores.get("strings", FeatureScore("strings"))
    tlsh = scores.get("tlsh", FeatureScore("tlsh"))
    semantic = max(
        code.score if code.available else 0,
        semantic_code.score if semantic_code.available else 0,
        strings.score if strings.available else 0,
        tlsh.score if tlsh.available else 0,
    )
    metadata = max(
        scores.get("imphash", FeatureScore("imphash")).score,
        scores.get("rich", FeatureScore("rich")).score,
        scores.get("icon", FeatureScore("icon")).score,
    )
    strong_features = sum(1 for score in scores.values() if score.available and score.score >= 70)
    metadata_only = semantic < 35 and metadata >= 70
    if overall >= 90:
        label = "VERY STRONG"
    elif overall >= 75:
        label = "STRONG"
    elif overall >= 55:
        label = "MODERATE"
    elif overall >= 35:
        label = "WEAK"
    else:
        label = "NO MEANINGFUL MATCH"
    if metadata_only:
        evidence = "LOW"
        reason = "Score relies primarily on PE metadata or resource fingerprints."
    elif (
        semantic_code.available
        and semantic_code.score >= 80
        and overall >= 75
        and float((semantic_code.evidence or {}).get("semantic_coverage") or 0) >= 20
        and not (semantic_code.evidence or {}).get("shared_component")
    ):
        evidence = "HIGH"
        reason = "Hex-Rays semantic code features strongly support the match."
    elif code.available and code.score >= 75 and overall >= 75:
        evidence = "HIGH"
        reason = "Normalized code features strongly support the match."
    elif semantic >= 70 and overall >= 75 and strong_features >= 2:
        evidence = "HIGH"
        reason = "High-value strings or fuzzy content similarity support the match."
    elif overall >= 55:
        evidence = "MEDIUM"
        reason = "Multiple static features overlap, but evidence is not attribution-grade."
    else:
        evidence = "LOW"
        reason = "Limited matching evidence."
    if entity_type == "threat_actor":
        reason += " Malware similarity is a potential relationship, not actor attribution."
        if evidence == "HIGH":
            evidence = "MEDIUM"
    return label, evidence, reason


def compare_sample(path: str, filename: str, progress: ProgressCallback = None) -> dict:
    init_db()
    settings = get_settings()
    features = process_sample(path, filename, settings, progress)
    conn = connect()
    try:
        entities = conn.execute("SELECT * FROM entities ORDER BY created_at DESC").fetchall()
        matches = []
        _progress(progress, "scoring", f"Scoring sample against {len(entities)} stored entities.", "running", filename)
        for entity in entities:
            scores, sample_matches = compare_features_to_entity(conn, features, entity)
            overall, normalized_weights = _overall(scores, settings.get("weights", {}))
            label, evidence_conf, reason = _confidence(overall, scores, entity["type"])
            exact = any(m.get("reason") == "Exact SHA256 match" for m in sample_matches)
            if exact:
                overall = 100.0
                label = "EXACT MATCH"
                evidence_conf = "HIGH"
                reason = "SHA256 is identical to a sample already associated with this entity."
            matches.append({
                "entity_id": int(entity["id"]),
                "entity_name": entity["name"],
                "entity_type": entity["type"],
                "score": round(overall, 2),
                "similarity_label": label,
                "confidence": evidence_conf,
                "reason": reason,
                "features": {k: {"score": round(v.score, 2), "available": v.available, "evidence": v.evidence} for k, v in scores.items()},
                "normalized_weights": normalized_weights,
                "sample_matches": sample_matches,
            })
        _progress(progress, "scoring", f"Scoring complete: {len(matches)} candidate matches before threshold.", "done", filename)
        minimum = float(settings.get("minimum_match_score") or 0)
        matches.sort(key=lambda m: m["score"], reverse=True)
        all_matches = matches
        threshold_matches = [m for m in all_matches if m["score"] >= minimum or m["similarity_label"] == "EXACT MATCH"]
        out = {
            "sha256": features["sha256"],
            "sha1": features["sha1"],
            "md5": features["md5"],
            "file_name": filename,
            "file_size": features["file_size"],
            "file_type": features["file_type"],
            "architecture": features.get("architecture", ""),
            "extractor_status": features.get("statuses", []),
            "minimum_match_score": minimum,
            "matches": threshold_matches,
            "candidate_matches": all_matches[:20],
            "below_threshold_count": max(0, len(all_matches) - len(threshold_matches)),
        }
        if settings.get("store_comparison_history"):
            best = all_matches[0] if all_matches else {}
            conn.execute(
                "INSERT INTO similarity_comparisons (sha256, file_name, compared_at, best_entity_id, best_score, result_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (features["sha256"], filename, now_iso(), best.get("entity_id"), float(best.get("score") or 0), json.dumps(out)[:500000]),
            )
            conn.commit()
        return out
    finally:
        conn.close()


def get_comparison(comparison_id: int) -> dict:
    init_db()
    conn = connect()
    try:
        row = conn.execute(
            "SELECT id, sha256, file_name, compared_at, best_entity_id, best_score, result_json "
            "FROM similarity_comparisons WHERE id = ?",
            (int(comparison_id),),
        ).fetchone()
        if not row:
            return {}
        try:
            result = json.loads(row["result_json"] or "{}")
        except Exception:
            result = {}
        if not isinstance(result, dict):
            result = {}
        result.setdefault("sha256", row["sha256"])
        result.setdefault("file_name", row["file_name"])
        result["saved_comparison_id"] = int(row["id"])
        result["compared_at"] = row["compared_at"]
        result["best_entity_id"] = row["best_entity_id"]
        result["best_score"] = float(row["best_score"] or 0)
        return result
    finally:
        conn.close()


def _extractor_health(conn: sqlite3.Connection) -> List[dict]:
    rows = [dict(r) for r in conn.execute(
        "SELECT extractor, status, COALESCE(error, '') AS error, COUNT(*) AS count "
        "FROM sample_extractor_status "
        "GROUP BY extractor, status, COALESCE(error, '') ORDER BY extractor, status, error"
    ).fetchall()]
    grouped: Dict[str, dict] = {}
    for row in rows:
        extractor = row.get("extractor") or "unknown"
        status = row.get("status") or "unknown"
        count = int(row.get("count") or 0)
        error = row.get("error") or ""
        item = grouped.setdefault(extractor, {
            "extractor": extractor,
            "status": "",
            "count": 0,
            "statuses": {},
            "errors": [],
            "detail": "",
        })
        item["count"] += count
        item["statuses"][status] = int(item["statuses"].get(status, 0)) + count
        if error:
            item["errors"].append({"status": status, "error": error, "count": count})

    def overall(statuses: Dict[str, int]) -> str:
        if not statuses:
            return "unknown"
        if statuses.get("failed"):
            return "failed"
        if statuses.get("success") and len(statuses) > 1:
            return "partial"
        if statuses.get("partial"):
            return "partial"
        if statuses.get("success"):
            return "success"
        if statuses.get("unsupported"):
            return "unsupported"
        if statuses.get("not_present"):
            return "not_present"
        return sorted(statuses)[0]

    out = []
    for item in grouped.values():
        statuses = dict(item["statuses"])
        item["status"] = overall(statuses)
        item["detail"] = ", ".join(f"{status}: {count}" for status, count in sorted(statuses.items()))
        out.append(item)
    return sorted(out, key=lambda r: str(r.get("extractor", "")))


def dashboard() -> dict:
    init_db()
    conn = connect()
    try:
        total_entities = int(conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0] or 0)
        total_samples = int(conn.execute("SELECT COUNT(*) FROM entity_samples").fetchone()[0] or 0)
        malware = int(conn.execute("SELECT COUNT(*) FROM entities WHERE type = 'malware'").fetchone()[0] or 0)
        actors = int(conn.execute("SELECT COUNT(*) FROM entities WHERE type = 'threat_actor'").fetchone()[0] or 0)
        latest_entities = [dict(r) for r in conn.execute(
            "SELECT e.*, COUNT(es.id) AS sample_count FROM entities e "
            "LEFT JOIN entity_samples es ON es.entity_id = e.id GROUP BY e.id ORDER BY e.created_at DESC LIMIT 6"
        ).fetchall()]
        latest_comparisons = [dict(r) for r in conn.execute(
            "SELECT id, sha256, file_name, compared_at, best_entity_id, best_score FROM similarity_comparisons "
            "ORDER BY compared_at DESC LIMIT 6"
        ).fetchall()]
        status_rows = _extractor_health(conn)
        return {
            "total_entities": total_entities,
            "total_processed_samples": total_samples,
            "malware_entities": malware,
            "threat_actor_entities": actors,
            "latest_entities": latest_entities,
            "latest_comparisons": latest_comparisons,
            "extractor_health": status_rows,
            "settings": get_settings(),
        }
    finally:
        conn.close()
