"""Scoring rules for sample-to-family comparison.

Design rules (fixed, so the same evidence always gives the same verdict):
  * Weights are fixed and sum to 100. A feature that cannot be computed
    contributes 0 and is reported as "not analysed". Weights are never
    re-scaled over the features that happened to run.
  * A label needs at least two analysed evidence features.
  * Profile maturity caps the label: a single-sample family can never be
    STRONG; a provisional family can never be STRONG.
  * SHA256 identity is reported separately and never changes the score.
"""
from __future__ import annotations

import math
from typing import Dict, Iterable, Optional, Set

try:
    import tlsh as _tlsh
except Exception:  # pragma: no cover
    _tlsh = None

WEIGHTS: Dict[str, int] = {
    "strings": 14,
    "code_functions": 16,
    "code_fuzzy": 15,
    "floss": 6,
    "tlsh": 15,
    "metadata": 17,
    "imports": 10,
    "api_behaviour": 2,
    "vt": 5,
}
# VT is external corroboration: it is scored, but it never counts toward the
# two-feature label gate and never produces exact-match status.
NON_GATE_FEATURES = frozenset({"vt"})
assert sum(WEIGHTS.values()) == 100

FEATURE_LABELS = {
    "strings": "Strings (weighted by rarity)",
    "code_functions": "Exact function matches",
    "code_fuzzy": "Fuzzy code similarity",
    "tlsh": "Fuzzy file similarity (TLSH)",
    "metadata": "Metadata (imphash, rich, PDB, version info)",
    "imports": "Imports",
    "api_behaviour": "APIs reached from code",
    "vt": "VirusTotal labels (external)",
    "floss": "Obfuscation-aware strings (FLOSS)",
}

CORE_SHARE = 0.75
MIN_EVIDENCE_ITEMS = 3   # a family needs at least this many items to judge a feature
VARIABLE_SHARE = 0.25
LIBRARY_FAMILY_SHARE = 0.5   # an item in more than this share of families (min 4) is library code
MIN_FAMILIES_FOR_LIBRARY = 4


def profile_status(n: int) -> str:
    if n <= 0:
        return "EMPTY"
    if n == 1:
        return "SINGLE"
    if n == 2:
        return "PROVISIONAL"
    if n < 10:
        return "DEVELOPING"
    return "ESTABLISHED"


def tier_for(member_count: int, n: int) -> str:
    if n < 3:
        return "UNTIERED"
    if member_count <= 1:
        return "SINGLETON"
    share = member_count / n
    if share >= CORE_SHARE:
        return "CORE"
    if share >= VARIABLE_SHARE:
        return "VARIABLE"
    return "RARE-ONLY"


# Tiers that count as family evidence when matching a new sample.
EVIDENCE_TIERS = ("CORE", "VARIABLE", "UNTIERED")


def tlsh_score(distance: int) -> float:
    """TLSH distance -> 0..100. Bands: 0->100, 30->80, 70->50, 120->0."""
    d = max(0, int(distance))
    if d <= 30:
        return 100.0 - (d / 30.0) * 20.0
    if d <= 70:
        return 80.0 - ((d - 30) / 40.0) * 30.0
    if d <= 120:
        return 50.0 - ((d - 70) / 50.0) * 50.0
    return 0.0


def tlsh_distance(a: str, b: str) -> Optional[int]:
    if not a or not b or _tlsh is None:
        return None
    try:
        return int(_tlsh.diff(a, b))
    except Exception:
        return None


def jaccard(a: Iterable, b: Iterable) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 0.0
    union = len(sa | sb)
    return len(sa & sb) / union if union else 0.0


def weighted_jaccard(sample: Set[str], family: Set[str], idf: Dict[str, float]) -> float:
    num = sum(idf.get(x, 1.0) for x in sample & family)
    den = sum(idf.get(x, 1.0) for x in sample | family)
    return num / den if den else 0.0


def idf(df: int, families: int) -> float:
    """Rarity weight: strings found in few families count more."""
    return 1.0 + max(0.0, math.log((families + 1) / (df + 0.5)))


def is_library(family_count_containing: int, total_families: int) -> bool:
    if total_families < MIN_FAMILIES_FOR_LIBRARY:
        return False
    return family_count_containing / total_families > LIBRARY_FAMILY_SHARE


def evidence_score(features: Dict[str, dict]) -> float:
    """Weighted mean over the features that were analysed (used for label bands only).

    The reported total stays fixed-weight. Labels use this so that a near-exact
    member is not capped at the coverage share; coverage still gates the label.
    """
    num = den = 0.0
    for key, weight in WEIGHTS.items():
        f = features.get(key) or {}
        if f.get("available"):
            num += weight * float(f.get("score", 0.0))
            den += weight
    return round(num / den, 2) if den else 0.0


def label_for(evidence: float, features: Dict[str, dict], status: str, coverage: float) -> str:
    """Map the evidence score to a label, with gates. Returns a label string."""
    overall = evidence
    available = [k for k, v in features.items() if v.get("available") and k not in NON_GATE_FEATURES]
    if len(available) < 2:
        return "INSUFFICIENT EVIDENCE"
    if overall >= 70:
        label = "STRONG"
    elif overall >= 50:
        label = "LIKELY"
    elif overall >= 30:
        label = "WEAK"
    else:
        return "NO MATCH"
    strong_votes = sum(1 for k in available if features[k]["score"] >= 60)
    if label == "STRONG" and (strong_votes < 3 or status not in ("DEVELOPING", "ESTABLISHED")):
        label = "LIKELY"
    if status == "SINGLE":
        label = "WEAK" if label in ("STRONG", "LIKELY") else label
    elif status == "PROVISIONAL" and label == "STRONG":
        label = "LIKELY"
    if coverage < 0.5 and label == "STRONG":
        label = "LIKELY"
    return label


def combine(features: Dict[str, dict]) -> tuple[float, float]:
    """Fixed-weight overall score and coverage. Missing features add 0 (never rescaled)."""
    overall = 0.0
    coverage = 0.0
    for key, weight in WEIGHTS.items():
        f = features.get(key) or {}
        if f.get("available"):
            coverage += weight
            overall += weight * float(f.get("score", 0.0)) / 100.0
    return round(overall, 2), round(coverage / 100.0, 2)
