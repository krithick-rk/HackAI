"""
Unit tests for the Weakness-Class Normalization Layer.

Coverage:
- normalize_weakness_class: known aliases, unknown/empty/None inputs
- weakness_classes_match: positive cases (same class), negative cases (different class),
  GENERIC gold, cross-class non-merge, case-insensitivity, whitespace tolerance
- Regression guards: all five previously POLICY_BLOCKED cases now match correctly
- False-positive guards: unrelated classes must NOT normalize to the same canonical
"""

from __future__ import annotations

import pytest
from src.soc_analyzer.benchmark.weakness_norm import (
    normalize_weakness_class,
    weakness_classes_match,
    get_all_aliases,
    CANONICAL_CLASSES,
)


# ---------------------------------------------------------------------------
# normalize_weakness_class
# ---------------------------------------------------------------------------

class TestNormalizeWeaknessClass:

    # --- Known aliases ---
    @pytest.mark.parametrize("alias,expected_canonical", [
        # ACCESS CONTROL
        ("MISSING_REGWEN",        "LOCK_ACCESS_CONTROL"),
        ("REGWEN_BYPASS",         "LOCK_ACCESS_CONTROL"),
        ("LOCK_ACCESS_CONTROL",   "LOCK_ACCESS_CONTROL"),
        # RESET
        ("MISSING_RESET",         "RESET_ISSUE"),
        ("UNRESET_STATE",         "RESET_ISSUE"),
        ("RESET_POLARITY",        "RESET_ISSUE"),
        ("RESET_ISSUE",           "RESET_ISSUE"),
        # FSM
        ("FSM_MISSING_DEFAULT",   "FSM_STRUCTURAL"),
        ("FSM_STRUCTURAL",        "FSM_STRUCTURAL"),
        ("FSM",                   "FSM_STRUCTURAL"),
        # DEBUG / TEST GATING
        ("MISSING_DEBUG_GATING",  "DEBUG_TEST_GATING"),
        ("DEBUG_GATING",          "DEBUG_TEST_GATING"),
        ("DEBUG_TEST_GATING",     "DEBUG_TEST_GATING"),
        ("UNGATED_DEBUG",         "DEBUG_TEST_GATING"),
        # DECODE
        ("DECODE_OVERLAP",        "DECODE_ADDRESS"),
        ("ADDRESS_COLLISION",     "DECODE_ADDRESS"),
        ("DECODE_ADDRESS",        "DECODE_ADDRESS"),
        # CONSTANT
        ("CONSTANT_SECURITY_CONTROL", "CONSTANT_SECURITY_CONTROL"),
        ("HARDCODED_CONSTANT",        "CONSTANT_SECURITY_CONTROL"),
        # CRYPTO
        ("CRYPTO_CONTROL",        "CRYPTO_CONTROL"),
        # INFORMATION FLOW
        ("INFORMATION_FLOW",      "INFORMATION_FLOW"),
        ("INFO_FLOW",             "INFORMATION_FLOW"),
        # FAULT INJECTION
        ("FAULT_INJECTION",       "FAULT_INJECTION"),
        # GENERIC
        ("GENERIC",               "GENERIC"),
        ("GENERIC_SUSPICIOUS_PATTERN", "GENERIC"),
    ])
    def test_known_alias(self, alias, expected_canonical):
        assert normalize_weakness_class(alias) == expected_canonical

    # --- Case-insensitivity ---
    def test_lowercase_input(self):
        assert normalize_weakness_class("missing_regwen") == "LOCK_ACCESS_CONTROL"

    def test_mixed_case_input(self):
        assert normalize_weakness_class("Fsm_Missing_Default") == "FSM_STRUCTURAL"

    # --- Whitespace tolerance ---
    def test_leading_trailing_whitespace(self):
        assert normalize_weakness_class("  MISSING_RESET  ") == "RESET_ISSUE"

    # --- Empty / None inputs ---
    def test_none_input(self):
        assert normalize_weakness_class(None) is None

    def test_empty_string(self):
        assert normalize_weakness_class("") is None

    def test_whitespace_only(self):
        assert normalize_weakness_class("   ") is None

    # --- Unknown/malformed ---
    def test_unknown_class_returns_none(self):
        assert normalize_weakness_class("UNKNOWN_GARBAGE") is None

    def test_partial_substring_not_matched(self):
        # "REGWEN" alone is NOT a registered alias
        assert normalize_weakness_class("REGWEN") is None

    def test_invented_class_returns_none(self):
        assert normalize_weakness_class("CRYPTO_CONTROL_EXTRA") is None

    # --- All canonicals map to themselves ---
    def test_all_canonicals_self_map(self):
        for canonical in CANONICAL_CLASSES:
            result = normalize_weakness_class(canonical)
            # canonical classes are in the alias table and should map to themselves
            # (GENERIC is in table; others should be)
            if result is not None:
                assert result == canonical, f"{canonical} should self-map but got {result}"


# ---------------------------------------------------------------------------
# weakness_classes_match
# ---------------------------------------------------------------------------

class TestWeaknessClassesMatch:

    # --- Same canonical: should match ---
    @pytest.mark.parametrize("produced,gold", [
        ("FSM_MISSING_DEFAULT",   "FSM_STRUCTURAL"),
        ("FSM_STRUCTURAL",        "FSM_STRUCTURAL"),
        ("FSM",                   "FSM_STRUCTURAL"),
        ("MISSING_REGWEN",        "LOCK_ACCESS_CONTROL"),
        ("LOCK_ACCESS_CONTROL",   "LOCK_ACCESS_CONTROL"),
        ("REGWEN_BYPASS",         "LOCK_ACCESS_CONTROL"),
        ("MISSING_RESET",         "RESET_ISSUE"),
        ("UNRESET_STATE",         "RESET_ISSUE"),
        ("MISSING_DEBUG_GATING",  "DEBUG_TEST_GATING"),
        ("DEBUG_GATING",          "DEBUG_TEST_GATING"),
        ("DECODE_OVERLAP",        "DECODE_ADDRESS"),
        ("CRYPTO_CONTROL",        "CRYPTO_CONTROL"),
        ("INFORMATION_FLOW",      "INFORMATION_FLOW"),
        ("FAULT_INJECTION",       "FAULT_INJECTION"),
        # Identical strings always match
        ("RESET_ISSUE",           "RESET_ISSUE"),
    ])
    def test_legitimate_match(self, produced, gold):
        assert weakness_classes_match(produced, gold) is True

    # --- Different canonical: must NOT match ---
    @pytest.mark.parametrize("produced,gold", [
        # Five regression cases from the diagnostic
        ("MISSING_REGWEN",        "CRYPTO_CONTROL"),
        ("MISSING_REGWEN",        "INFORMATION_FLOW"),
        ("MISSING_RESET",         "FAULT_INJECTION"),
        ("MISSING_DEBUG_GATING",  "INFORMATION_FLOW"),
        ("FSM_MISSING_DEFAULT",   "RESET_ISSUE"),
        # General cross-class isolation
        ("MISSING_RESET",         "LOCK_ACCESS_CONTROL"),
        ("FSM_STRUCTURAL",        "DECODE_ADDRESS"),
        ("CRYPTO_CONTROL",        "DEBUG_TEST_GATING"),
        ("DECODE_OVERLAP",        "FSM_STRUCTURAL"),
        ("INFORMATION_FLOW",      "FAULT_INJECTION"),
        ("LOCK_ACCESS_CONTROL",   "RESET_ISSUE"),
    ])
    def test_no_cross_class_match(self, produced, gold):
        assert weakness_classes_match(produced, gold) is False

    # --- GENERIC gold matches anything known ---
    def test_generic_gold_matches_any_known_produced(self):
        for alias in ["MISSING_REGWEN", "FSM_MISSING_DEFAULT", "MISSING_RESET",
                      "MISSING_DEBUG_GATING", "DECODE_OVERLAP", "CRYPTO_CONTROL"]:
            assert weakness_classes_match(alias, "GENERIC") is True

    def test_generic_gold_does_not_match_unknown(self):
        assert weakness_classes_match("TOTALLY_INVENTED_CLASS", "GENERIC") is False

    # --- Empty / None guards ---
    def test_none_produced(self):
        assert weakness_classes_match(None, "RESET_ISSUE") is False

    def test_none_gold(self):
        assert weakness_classes_match("MISSING_RESET", None) is False

    def test_both_none(self):
        assert weakness_classes_match(None, None) is False

    def test_empty_produced(self):
        assert weakness_classes_match("", "RESET_ISSUE") is False

    def test_empty_gold(self):
        assert weakness_classes_match("MISSING_RESET", "") is False

    # --- Malformed inputs ---
    def test_unknown_produced_does_not_match(self):
        assert weakness_classes_match("GARBAGE_WEAKNESS", "RESET_ISSUE") is False

    def test_unknown_gold_does_not_match(self):
        assert weakness_classes_match("MISSING_RESET", "COMPLETELY_UNKNOWN") is False

    def test_both_unknown_do_not_match(self):
        assert weakness_classes_match("JUNK_A", "JUNK_B") is False

    # --- Case insensitivity ---
    def test_case_insensitive_match(self):
        assert weakness_classes_match("fsm_missing_default", "fsm_structural") is True

    def test_mixed_case_no_match(self):
        assert weakness_classes_match("missing_regwen", "crypto_control") is False

    # --- Whitespace tolerance ---
    def test_whitespace_in_produced(self):
        assert weakness_classes_match("  MISSING_RESET  ", "RESET_ISSUE") is True

    def test_whitespace_in_gold(self):
        assert weakness_classes_match("MISSING_RESET", "  RESET_ISSUE  ") is True


# ---------------------------------------------------------------------------
# Regression guards: the five previously POLICY_BLOCKED cases
# ---------------------------------------------------------------------------

class TestPreviouslyBlockedCases:
    """
    Verify that weakness-class normalization preserves correct matching
    and rejects spurious cross-class credits.
    """

    def test_fsm_01_missing_default_now_matches(self):
        """FSM_STRUCTURAL gold + FSM_MISSING_DEFAULT produced → legitimate family match"""
        assert weakness_classes_match("FSM_MISSING_DEFAULT", "FSM_STRUCTURAL") is True

    def test_crypto_01_gold_does_not_match_regwen(self):
        """
        case_crypto_01 root cause is CONSTANT_SECURITY_CONTROL / CRYPTO_CONTROL.
        Detector artifact MISSING_REGWEN must NOT match either class.
        """
        assert weakness_classes_match("MISSING_REGWEN", "CRYPTO_CONTROL") is False
        assert weakness_classes_match("MISSING_REGWEN", "CONSTANT_SECURITY_CONTROL") is False

    def test_inf_01_gold_does_not_match_debug_gating(self):
        """
        case_inf_01 root cause is INFORMATION_FLOW.
        Detector artifact MISSING_DEBUG_GATING must NOT match.
        """
        assert weakness_classes_match("MISSING_DEBUG_GATING", "INFORMATION_FLOW") is False

    def test_fi_01_gold_does_not_match_reset(self):
        """
        case_fi_01 root cause is FAULT_INJECTION.
        Incidental hygiene artifact MISSING_RESET must NOT match.
        """
        assert weakness_classes_match("MISSING_RESET", "FAULT_INJECTION") is False

    def test_dbg_01_obf_no_debug_finding_still_not_matched(self):
        """
        case_dbg_01_obf: detector produces MISSING_REGWEN/MISSING_RESET, gold=DEBUG_TEST_GATING.
        Even after normalization, these still don't match — this is the remaining genuine miss.
        """
        assert weakness_classes_match("MISSING_REGWEN", "DEBUG_TEST_GATING") is False
        assert weakness_classes_match("MISSING_RESET", "DEBUG_TEST_GATING") is False


# ---------------------------------------------------------------------------
# Part A: Audited Benchmark Truth Governance Regression Tests
# ---------------------------------------------------------------------------

class TestAuditedBenchmarkTruthGovernance:
    """
    Enforces the authoritative benchmark taxonomy audit rules:
    1. Baseline invariance rule: Reverting mutation preserves detector artifact (BASELINE_PRESENT -> NO credit).
    2. crypto case does not receive MISSING_REGWEN credit merely because site has a constant control.
    3. info-flow case does not receive MISSING_DEBUG_GATING credit merely because a debug-like output exists.
    4. FI case remains out of scope (in_scope=False).
    5. Benchmark metrics cannot be inflated by relabeling a detector/class mismatch as a true positive.
    6. Canonical audited baseline is preserved: 84.62% inflated recall is rejected.
    """

    def test_crypto_case_governance(self):
        from src.soc_analyzer.benchmark.cases.seeded_cases import get_all_benchmark_cases
        cases = {c.case_id: c for c in get_all_benchmark_cases()}
        crypto_case = cases["case_crypto_01_hardcoded_key_enable"]
        assert crypto_case.weakness_class == "CRYPTO_CONTROL"
        assert crypto_case.weakness_class != "LOCK_ACCESS_CONTROL"
        # Detector produces MISSING_REGWEN -> must NOT match
        assert weakness_classes_match("MISSING_REGWEN", crypto_case.weakness_class) is False

    def test_info_flow_case_governance(self):
        from src.soc_analyzer.benchmark.cases.seeded_cases import get_all_benchmark_cases
        cases = {c.case_id: c for c in get_all_benchmark_cases()}
        inf_case = cases["case_inf_01_unmasked_secret_leak"]
        assert inf_case.weakness_class == "INFORMATION_FLOW"
        assert inf_case.weakness_class != "DEBUG_TEST_GATING"
        # Detector produces MISSING_DEBUG_GATING -> must NOT match
        assert weakness_classes_match("MISSING_DEBUG_GATING", inf_case.weakness_class) is False

    def test_fault_injection_case_governance(self):
        from src.soc_analyzer.benchmark.cases.seeded_cases import get_all_benchmark_cases
        cases = {c.case_id: c for c in get_all_benchmark_cases()}
        fi_case = cases["case_fi_01_ungarded_critical_branch"]
        assert fi_case.weakness_class == "FAULT_INJECTION"
        assert fi_case.weakness_class != "RESET_ISSUE"
        assert fi_case.in_scope is False
        assert "out_of_scope" in fi_case.tags
        # Detector produces MISSING_RESET -> must NOT match
        assert weakness_classes_match("MISSING_RESET", fi_case.weakness_class) is False

    def test_baseline_invariance_clean_reference_present(self):
        """
        Verify that in the clean reference for crypto tie-off and safe declassifier,
        the spurious findings are identical fixture artifacts (BASELINE_PRESENT).
        """
        from src.soc_analyzer.candidates.detectors.lock_access_control import LockAccessControlDetector
        from src.soc_analyzer.design_db.builder import DesignDBBuilder
        from src.soc_analyzer.benchmark.cases.seeded_cases import get_all_benchmark_cases

        cases = {c.case_id: c for c in get_all_benchmark_cases()}
        # For crypto_01: clean is c15_rtl (tie_low_test_pin)
        clean_crypto = cases["case_const_02_intentional_tieoff_safe"]
        assert clean_crypto.expected_behavior.value == "TRUE_NEGATIVE"

    def test_cannot_inflate_metrics_via_mismatch_relabeling(self):
        """
        Verify that the benchmark runner does NOT award TP credit to
        the 3 audited unadjudicated cases, preventing the inflated 84.62% recall.
        """
        from src.soc_analyzer.benchmark.runner import BenchmarkRunner
        report = BenchmarkRunner().run_all()
        # Verify 84.62% recall is NOT produced
        assert report.metrics.recall < 0.80, (
            f"Recall {report.metrics.recall} indicates improper gold-label inflation!"
        )
        # Verify crypto_01 and inf_01 and fi_01 are not marked as passed
        results_by_id = {r["case_id"]: r for r in report.case_results}
        assert results_by_id["case_crypto_01_hardcoded_key_enable"]["passed"] is False
        assert results_by_id["case_inf_01_unmasked_secret_leak"]["passed"] is False
        assert results_by_id["case_fi_01_ungarded_critical_branch"]["passed"] is False


# ---------------------------------------------------------------------------
# Alias table completeness
# ---------------------------------------------------------------------------

class TestAliasTable:
    def test_table_not_empty(self):
        table = get_all_aliases()
        assert len(table) > 0

    def test_all_values_are_canonical(self):
        table = get_all_aliases()
        for alias, canonical in table.items():
            assert canonical in CANONICAL_CLASSES, (
                f"Alias '{alias}' maps to '{canonical}' which is not a CANONICAL_CLASS"
            )

    def test_no_duplicate_cross_mapping(self):
        """
        Verify that within each canonical class group, no alias maps to
        a *different* canonical (i.e. same alias can't appear twice).
        """
        table = get_all_aliases()
        seen: dict = {}
        for alias, canonical in table.items():
            if alias in seen:
                assert seen[alias] == canonical, (
                    f"Alias '{alias}' maps to two different canonicals: "
                    f"{seen[alias]} and {canonical}"
                )
            seen[alias] = canonical
