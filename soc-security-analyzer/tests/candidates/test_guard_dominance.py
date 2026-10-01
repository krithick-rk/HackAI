"""
Unit and Regression Test Suite for Structural Guard-Dominance Analysis.
Verifies:
- AssignmentFact and combinational_defs extraction in DesignDB
- Recursive condition stringification in SlangElaborator
- AC-02 (case_ac_02_subtle_guard_bypass) produces a candidate
- Candidate contains correct source/AST provenance
- Path predicate is inspectable and explainable
- Solver witness is attached to evidence
- Clean reference variant (AC-03 safe) produces no candidate
- Missing lock variant (AC-01) produces MISSING_REGWEN
"""

import os
import tempfile
import pytest

from src.soc_analyzer.design_db.builder import DesignDBBuilder
from src.soc_analyzer.benchmark.cases.seeded_cases import get_all_benchmark_cases
from src.soc_analyzer.benchmark.runner import populate_benchmark_assets, BenchmarkRunner
from src.soc_analyzer.candidates.detectors.lock_access_control import LockAccessControlDetector
from src.soc_analyzer.candidates.schemas import CandidateStatus


@pytest.fixture
def benchmark_cases():
    return {c.case_id: c for c in get_all_benchmark_cases()}


def test_ac_02_candidate_generation_and_provenance(benchmark_cases):
    """
    Verify that case_ac_02_subtle_guard_bypass produces a candidate with:
    - REGWEN_BYPASS weakness class
    - correct source coordinates and AST identity
    - inspectable path predicate
    - solver witness model in metadata
    """
    case = benchmark_cases["case_ac_02_subtle_guard_bypass"]
    with tempfile.NamedTemporaryFile(suffix=".sv", mode="w", delete=False) as f:
        f.write(case.source_fixture)
        path = f.name

    try:
        db = DesignDBBuilder().build_from_files([path], top_module="guarded_cfg")
        populate_benchmark_assets(db, case)

        detector = LockAccessControlDetector()
        candidates = detector.analyze(db)

        # Must produce exactly 1 candidate for the bypass
        assert len(candidates) == 1, f"Expected 1 candidate, got {len(candidates)}"
        cand = candidates[0]

        # Weakness class must be REGWEN_BYPASS (normalizes to LOCK_ACCESS_CONTROL)
        assert cand.weakness_class == "REGWEN_BYPASS"

        # AST and Source coordinates verification
        assert os.path.abspath(cand.source_file) == os.path.abspath(path)
        assert cand.line_range[0] > 0
        assert cand.definition_id == "guarded_cfg"

        # Inspectable path predicate
        assert "path_condition" in cand.metadata
        pc_str = cand.metadata["path_condition"]
        assert "regwen_i" in pc_str
        assert "debug_override" in pc_str

        # Solver witness model verification
        assert "witness" in cand.metadata
        witness = cand.metadata["witness"]
        assert witness.get("regwen_i") == "False"
        assert witness.get("we") == "True"
        assert witness.get("debug_override") == "True"
        assert witness.get("rst_ni") == "True"

        # Evidence references check
        assert len(cand.evidence_refs) >= 2
        ast_ev = [e for e in cand.evidence_refs if e.source == "guarded_cfg.sec_cfg"]
        assert len(ast_ev) == 1
        solver_ev = [e for e in cand.evidence_refs if e.source == "Z3_SMT_SOLVER"]
        assert len(solver_ev) == 1
        assert "SAT witness" in solver_ev[0].description

    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_ac_03_clean_reference_negative_control(benchmark_cases):
    """
    Clean reference variant (case_ac_03_valid_regwen_safe) must NOT produce
    a REGWEN_BYPASS candidate because the guard strictly dominates the update.
    """
    case = benchmark_cases["case_ac_03_valid_regwen_safe"]
    with tempfile.NamedTemporaryFile(suffix=".sv", mode="w", delete=False) as f:
        f.write(case.source_fixture)
        path = f.name

    try:
        db = DesignDBBuilder().build_from_files([path], top_module="safe_regwen_cfg")
        populate_benchmark_assets(db, case)

        detector = LockAccessControlDetector()
        candidates = detector.analyze(db)

        # Must produce 0 candidates
        assert len(candidates) == 0, f"Clean reference produced unexpected candidates: {candidates}"

    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_ac_01_missing_regwen_regression(benchmark_cases):
    """
    Pure missing regwen case (case_ac_01_missing_regwen) must produce
    MISSING_REGWEN candidate without regressions.
    """
    case = benchmark_cases["case_ac_01_missing_regwen"]
    with tempfile.NamedTemporaryFile(suffix=".sv", mode="w", delete=False) as f:
        f.write(case.source_fixture)
        path = f.name

    try:
        db = DesignDBBuilder().build_from_files([path], top_module="sec_ctrl_reg")
        populate_benchmark_assets(db, case)

        detector = LockAccessControlDetector()
        candidates = detector.analyze(db)

        assert len(candidates) == 1
        assert candidates[0].weakness_class == "MISSING_REGWEN"

    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_ac_02_full_pipeline_pass(benchmark_cases):
    """
    Execute AC-02 through the complete BenchmarkRunner pipeline:
    Elaboration -> Detector -> Grounding -> Reachability -> FindingManager.
    Verify that AC-02 passes with status REACHABLE and lane PROBABLE.
    """
    case = benchmark_cases["case_ac_02_subtle_guard_bypass"]
    runner = BenchmarkRunner()
    result = runner.run_case(case)

    assert result.passed is True
    assert result.actual_detected is True
    assert result.actual_weakness == "REGWEN_BYPASS"
    assert result.actual_status == "REACHABLE"
    assert result.actual_lane == "PROBABLE"
    assert result.is_wrong_refutation is False
    assert len(result.notes) == 0
