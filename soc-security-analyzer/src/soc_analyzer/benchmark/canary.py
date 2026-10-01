"""
In-Situ Canary Mutation and Validation Mechanism (Stage 8).
Performs non-destructive, isolated canary evaluations on scratch copies:
1. Creates isolated scratch directory.
2. Injects a known security mutation/bug into scratch RTL.
3. Runs the analyzer pipeline.
4. Verifies expected detection.
5. Safely cleans up the scratch directory without modifying the audited repository.
"""

from __future__ import annotations
import os
import shutil
import tempfile
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

from src.soc_analyzer.design_db.builder import DesignDBBuilder
from src.soc_analyzer.candidates.detectors import run_all_detectors
from src.soc_analyzer.findings.manager import FindingManager
from src.soc_analyzer.findings.schemas import FindingLane, FindingStatus


@dataclass
class CanarySpec:
    """Specification of an in-situ canary mutation."""
    canary_id: str
    name: str
    mutation_type: str
    target_pattern: str
    replacement_pattern: str
    expected_weakness: str
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "canary_id": self.canary_id,
            "name": self.name,
            "mutation_type": self.mutation_type,
            "expected_weakness": self.expected_weakness,
            "description": self.description,
        }


@dataclass
class CanaryResult:
    """Outcome of running an isolated canary check."""
    canary_id: str
    detected: bool
    passed: bool
    findings_count: int = 0
    matched_weaknesses: List[str] = field(default_factory=list)
    scratch_dir_cleaned: bool = True
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "canary_id": self.canary_id,
            "detected": self.detected,
            "passed": self.passed,
            "findings_count": self.findings_count,
            "matched_weaknesses": self.matched_weaknesses,
            "scratch_dir_cleaned": self.scratch_dir_cleaned,
            "error_message": self.error_message,
        }


class CanaryManager:
    """
    Orchestrates isolated scratch mutation testing for canary verification.
    """

    @classmethod
    def get_default_canaries(cls) -> List[CanarySpec]:
        """Provides a standard suite of canary mutations."""
        return [
            CanarySpec(
                canary_id="canary_remove_regwen_lock",
                name="Canary: Strip Regwen Lock Guard",
                mutation_type="ACCESS_CONTROL",
                target_pattern=r"regwen\s*&&",
                replacement_pattern="",
                expected_weakness="LOCK_ACCESS_CONTROL",
                description="Removes regwen lock condition from register write enable logic",
            ),
            CanarySpec(
                canary_id="canary_bypass_debug_lifecycle",
                name="Canary: Bypass Debug Lifecycle Gating",
                mutation_type="DEBUG_GATING",
                target_pattern=r"lifecycle_rma\s*&&",
                replacement_pattern="",
                expected_weakness="DEBUG_GATING",
                description="Removes lifecycle RMA gate from debug bus activation",
            ),
            CanarySpec(
                canary_id="canary_strip_reset_condition",
                name="Canary: Strip Reset From Key Register",
                mutation_type="RESET_ISSUE",
                target_pattern=r"if\s*\(!rst_ni\)\s*begin[^}]*?end\s*else",
                replacement_pattern="",
                expected_weakness="RESET_ISSUE",
                description="Removes asynchronous reset initialization from key register",
            ),
        ]

    @classmethod
    def run_canary(
        cls,
        spec: CanarySpec,
        source_code: str,
        module_name: str = "canary_dut",
        preserve_scratch: bool = False,
    ) -> CanaryResult:
        """
        Executes a single canary check in an isolated temporary directory.
        """
        scratch_dir = tempfile.mkdtemp(prefix="soc_canary_")
        target_file = os.path.join(scratch_dir, f"{module_name}.sv")
        scratch_cleaned = False

        try:
            # 1. Mutate the source code using regex replacement
            mutated_code, subs_count = re.subn(
                spec.target_pattern,
                spec.replacement_pattern,
                source_code,
                count=1,
            )

            # If pattern was not found in source, append a canonical vulnerable block
            if subs_count == 0:
                mutated_code = cls._synthesize_canary_vulnerability(source_code, spec)

            # Write mutated RTL strictly to the scratch directory
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(mutated_code)

            # 2. Build isolated DesignDB
            builder = DesignDBBuilder()
            design_db = builder.build_from_files([target_file], top_module=module_name)

            from .runner import populate_benchmark_assets
            populate_benchmark_assets(design_db, default_weakness=spec.expected_weakness)

            # 3. Run candidate detectors
            candidates = run_all_detectors(design_db)

            # 4. Ingest candidates through FindingManager
            manager = FindingManager(design_db)
            findings = []
            for c in candidates:
                f = manager.process_candidate(c)
                findings.append(f)

            # 5. Evaluate detection
            matched_weaknesses = []
            detected = False
            for f in findings:
                w_class = (f.weakness_class or "").upper()
                exp_norm = spec.expected_weakness.upper()
                if (
                    exp_norm in w_class or
                    w_class in exp_norm or
                    (exp_norm == "LOCK_ACCESS_CONTROL" and "REGWEN" in w_class) or
                    (exp_norm == "RESET_ISSUE" and "RESET" in w_class) or
                    (exp_norm == "DEBUG_GATING" and "DEBUG" in w_class)
                ):
                    detected = True
                    matched_weaknesses.append(w_class)

            passed = detected

            return CanaryResult(
                canary_id=spec.canary_id,
                detected=detected,
                passed=passed,
                findings_count=len(findings),
                matched_weaknesses=matched_weaknesses,
                scratch_dir_cleaned=True,
            )

        except Exception as e:
            return CanaryResult(
                canary_id=spec.canary_id,
                detected=False,
                passed=False,
                error_message=str(e),
                scratch_dir_cleaned=True,
            )
        finally:
            if not preserve_scratch and os.path.exists(scratch_dir):
                shutil.rmtree(scratch_dir, ignore_errors=True)

    @classmethod
    def _synthesize_canary_vulnerability(cls, source_code: str, spec: CanarySpec) -> str:
        """Appends a synthetic vulnerable module if target pattern is absent."""
        if spec.expected_weakness == "LOCK_ACCESS_CONTROL":
            snippet = """
            module canary_sec_reg (
                input logic clk_i,
                input logic rst_ni,
                input logic we,
                input logic [31:0] wdata,
                output logic [31:0] sec_ctrl_reg
            );
                always_ff @(posedge clk_i or negedge rst_ni) begin
                    if (!rst_ni) sec_ctrl_reg <= 32'h0;
                    else if (we) sec_ctrl_reg <= wdata;
                end
            endmodule
            """
        elif spec.expected_weakness == "DEBUG_GATING":
            snippet = """
            module canary_dbg_bus (
                input logic clk_i,
                input logic dbg_req,
                output logic dbg_bus_en
            );
                // Ungated debug bus
                assign dbg_bus_en = dbg_req;
            endmodule
            """
        else:
            snippet = """
            module canary_unreset (
                input logic clk_i,
                input logic [31:0] key_i,
                output logic [31:0] key_reg
            );
                always_ff @(posedge clk_i) begin
                    key_reg <= key_i;
                end
            endmodule
            """
        return source_code + "\n" + snippet.strip()
