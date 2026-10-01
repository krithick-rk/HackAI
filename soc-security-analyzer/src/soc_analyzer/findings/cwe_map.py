"""
Deterministic CWE Mapping (Stage 6).
Maps normalized hardware weakness classes to authoritative Common Weakness Enumeration (CWE) IDs.
Strictly prohibits free-text AI-generated CWE assignments.
"""

from __future__ import annotations
from typing import Dict, Tuple, Optional

MAPPING_VERSION = "1.0"

# Authoritative hardware weakness taxonomy mapping table
DEFAULT_CWE_MAP: Dict[str, str] = {
    # Access Control / Register Lock Weaknesses
    "ACCESS_CONTROL": "CWE-1234",          # Hardware Internal or Debug Interface Access Control
    "LOCK_ACCESS_CONTROL": "CWE-1234",
    "MISSING_REGWEN": "CWE-1234",
    "UNGUARDED_WRITE": "CWE-1234",

    # Reset Weaknesses
    "RESET": "CWE-1271",                   # Operation of Uninitialized Hardware Logic
    "RESET_ISSUE": "CWE-1271",
    "MISSING_RESET": "CWE-1271",
    "RESET_POLARITY_MISMATCH": "CWE-1271",
    "SUSPICIOUS_RESVAL": "CWE-1272",       # Sensitive Information Uncleared Before Use

    # Constant Security Controls
    "CONSTANT_SECURITY_CONTROL": "CWE-1240", # Use of Hardcoded Security Parameter / Key
    "CONSTANT_ENABLE": "CWE-1240",

    # Debug & Test Gating
    "DEBUG_TEST_GATING": "CWE-1191",       # On-Chip Debug and Test Interface With Improper Access Control
    "DEBUG_GATING": "CWE-1191",
    "UNGATED_DEBUG_PORT": "CWE-1191",

    # FSM State Issues
    "FSM": "CWE-1245",                     # Improper Finite State Machine (FSM) State Transition
    "FSM_STRUCTURAL": "CWE-1245",
    "MISSING_DEFAULT_STATE": "CWE-1245",

    # Dead Checks & Constant Comparisons
    "DEAD_CHECK": "CWE-570",               # Expression is Always False
    "CONSTANT_COMPARISON": "CWE-571",      # Expression is Always True

    # Address Decode & Aliasing
    "DECODE_ADDRESS": "CWE-1256",          # Basics of Physical Memory Protection
    "DECODE_OVERLAP": "CWE-1256",
    "ADDRESS_ALIAS_CONFLICT": "CWE-1256",

    # Sibling Asymmetry
    "SIBLING_GUARD_ASYMMETRY": "CWE-1256",
    "ASYMMETRIC_PROTECTION": "CWE-1256",

    # Information Flow & Side Channels
    "INFORMATION_FLOW": "CWE-1258",        # Exposure of Sensitive Information through Sent Data
    "DATA_LEAKAGE": "CWE-1258",

    # Cryptographic Controls
    "CRYPTO_CONTROL": "CWE-1240",

    # Fault Injection
    "FAULT_INJECTION": "CWE-1332",         # Improper Handling of Faults leading to Fault Injection
}


def map_weakness_to_cwe(
    weakness_class: str,
    custom_map: Optional[Dict[str, str]] = None,
    version: str = MAPPING_VERSION,
) -> Tuple[str, str, str]:
    """
    Deterministically map a weakness class string to an authoritative CWE identifier.
    Returns:
        (cwe_id, cwe_source, mapping_version)
    If unmapped:
        ("CWE_UNMAPPED", "DETERMINISTIC_MAPPING", version)
    """
    lookup_map = custom_map if custom_map is not None else DEFAULT_CWE_MAP
    norm_key = (weakness_class or "").strip().upper()

    cwe_id = lookup_map.get(norm_key)
    if not cwe_id:
        # Check partial/prefix match
        for k, v in lookup_map.items():
            if k in norm_key or norm_key in k:
                cwe_id = v
                break

    if not cwe_id:
        cwe_id = "CWE_UNMAPPED"

    return cwe_id, "DETERMINISTIC_MAPPING", version
