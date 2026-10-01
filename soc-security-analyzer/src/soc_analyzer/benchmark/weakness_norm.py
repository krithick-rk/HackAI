"""
Weakness-Class Normalization for Benchmark Matching.

Provides a deterministic, explicit normalization table that maps equivalent
weakness-class strings produced by detectors to the canonical benchmark gold
classes used in seeded_cases.py.

Rules:
- Matching is case-insensitive and whitespace-tolerant.
- Normalization is exact-alias lookup, NOT substring inference.
- Unrelated classes are never merged.
- The table is the single source of truth; no fuzzy matching outside it.
"""

from __future__ import annotations
from typing import Optional, Dict

# ---------------------------------------------------------------------------
# Canonical benchmark class names (authoritative set)
# ---------------------------------------------------------------------------

CANONICAL_CLASSES = frozenset({
    "LOCK_ACCESS_CONTROL",
    "RESET_ISSUE",
    "FSM_STRUCTURAL",
    "DEBUG_TEST_GATING",
    "DECODE_ADDRESS",
    "CRYPTO_CONTROL",
    "INFORMATION_FLOW",
    "FAULT_INJECTION",
    "CONSTANT_SECURITY_CONTROL",
    "GENERIC",
})

# ---------------------------------------------------------------------------
# Alias → canonical mapping
#
# Each key is a produced weakness-class string (uppercased, stripped).
# Each value is the canonical class it belongs to.
#
# Only add entries where the alias is genuinely equivalent to the canonical:
#   - Same vulnerability family
#   - Same root cause category
#   - Not merely superficially similar
# ---------------------------------------------------------------------------

_ALIAS_TABLE: Dict[str, str] = {
    # --- ACCESS CONTROL / REGWEN LOCK ---
    "MISSING_REGWEN":           "LOCK_ACCESS_CONTROL",
    "REGWEN_BYPASS":            "LOCK_ACCESS_CONTROL",
    "LOCK_ACCESS_CONTROL":      "LOCK_ACCESS_CONTROL",

    # --- RESET ---
    "MISSING_RESET":            "RESET_ISSUE",
    "UNRESET_STATE":            "RESET_ISSUE",
    "RESET_POLARITY":           "RESET_ISSUE",
    "RESET_ISSUE":              "RESET_ISSUE",

    # --- FSM ---
    "FSM_MISSING_DEFAULT":      "FSM_STRUCTURAL",
    "FSM_STRUCTURAL":           "FSM_STRUCTURAL",
    "FSM":                      "FSM_STRUCTURAL",

    # --- DEBUG / TEST GATING ---
    "MISSING_DEBUG_GATING":     "DEBUG_TEST_GATING",
    "DEBUG_GATING":             "DEBUG_TEST_GATING",
    "DEBUG_TEST_GATING":        "DEBUG_TEST_GATING",
    "UNGATED_DEBUG":            "DEBUG_TEST_GATING",

    # --- DECODE ADDRESS ---
    "DECODE_OVERLAP":           "DECODE_ADDRESS",
    "ADDRESS_COLLISION":        "DECODE_ADDRESS",
    "DECODE_ADDRESS":           "DECODE_ADDRESS",

    # --- CONSTANT SECURITY CONTROL ---
    "CONSTANT_SECURITY_CONTROL": "CONSTANT_SECURITY_CONTROL",
    "HARDCODED_CONSTANT":        "CONSTANT_SECURITY_CONTROL",
    "CONSTANT_CONTROL":          "CONSTANT_SECURITY_CONTROL",

    # --- CRYPTO CONTROL ---
    "CRYPTO_CONTROL":            "CRYPTO_CONTROL",

    # --- INFORMATION FLOW ---
    "INFORMATION_FLOW":          "INFORMATION_FLOW",
    "INFO_FLOW":                 "INFORMATION_FLOW",

    # --- FAULT INJECTION ---
    "FAULT_INJECTION":           "FAULT_INJECTION",

    # --- GENERIC ---
    "GENERIC":                   "GENERIC",
    "GENERIC_SUSPICIOUS_PATTERN": "GENERIC",
}


def normalize_weakness_class(value: Optional[str]) -> Optional[str]:
    """
    Normalize a weakness-class string to its canonical benchmark class.

    Returns the canonical class name, or None if value is empty/unknown.
    Does NOT fall back to substring matching; only explicit alias lookups.
    """
    if not value:
        return None
    key = value.strip().upper()
    return _ALIAS_TABLE.get(key)


def weakness_classes_match(produced: Optional[str], gold: Optional[str]) -> bool:
    """
    Return True if produced and gold weakness classes resolve to the same
    canonical class.

    Rules:
    - Both must normalize to a non-None canonical.
    - They must resolve to the *same* canonical (no cross-class merging).
    - If gold is GENERIC, any produced class is a match.
    - Unknown classes (not in alias table) never match anything.
    """
    if not produced or not gold:
        return False

    gold_upper = gold.strip().upper()
    produced_upper = produced.strip().upper()

    # Fast path: identical strings
    if gold_upper == produced_upper:
        return True

    # GENERIC gold matches any produced class that normalizes to something known
    if gold_upper == "GENERIC":
        return normalize_weakness_class(produced) is not None

    canonical_produced = normalize_weakness_class(produced)
    canonical_gold = normalize_weakness_class(gold)

    if canonical_produced is None or canonical_gold is None:
        return False

    return canonical_produced == canonical_gold


def get_all_aliases() -> Dict[str, str]:
    """Return a copy of the full alias → canonical table (for testing/inspection)."""
    return dict(_ALIAS_TABLE)
