"""
Formal Witness and SymbiYosys Integration (Stage 7).
Transforms Stage 5 Z3 SAT models into formal counterexample witnesses.
Provides controlled SymbiYosys (SBY) execution adapters for formal assertion verification.
"""

from __future__ import annotations
import os
import subprocess
import json
from typing import Dict, List, Optional, Any, Tuple

from src.soc_analyzer.reachability.schemas import ReachabilityResult, ReachabilityResultStatus
from .schemas import WitnessResult, WitnessKind, WitnessStatus


class FormalWitnessEngine:
    """
    Constructs and verifies formal counterexample witnesses from Z3 models and SBY runs.
    """

    @classmethod
    def create_formal_witness(
        cls,
        finding_id: str,
        reachability_result: ReachabilityResult,
        instance_path: str = "",
        configuration: str = "default",
    ) -> Optional[WitnessResult]:
        """
        Convert a verified Stage 5 Z3 SAT model into an SMT_EVAL / FORMAL_TRACE witness.
        Only succeeds if reachability is SAT and the model is complete.
        """
        if reachability_result.result != ReachabilityResultStatus.SAT:
            return None

        witness_map = reachability_result.witness_assignment or {}
        if not witness_map:
            return None

        # Format witness stimulus assignments
        stimulus_entries = [
            {"signal": k, "assignment": v, "domain": "formal_smt"}
            for k, v in witness_map.items()
        ]

        # Verification status is VERIFIED if model was complete without unknown reasons
        is_verified = (
            reachability_result.is_model_complete and
            len(reachability_result.unknown_reasons) == 0
        )

        witness = WitnessResult(
            finding_id=finding_id,
            kind=WitnessKind.SMT_EVAL,
            status=WitnessStatus.VERIFIED if is_verified else WitnessStatus.FOUND,
            configuration=configuration,
            instance_path=instance_path,
            stimulus=stimulus_entries,
            assumptions=list(reachability_result.assumptions),
            verification_status="VERIFIED" if is_verified else "UNVERIFIED",
            reason_codes=["formal_z3_sat_model_extracted"],
            tool_versions={"solver": reachability_result.solver, "solver_version": reachability_result.solver_version},
            metadata={"z3_model_hash": reachability_result.model_hash},
        )
        return witness


class SymbiYosysAdapter:
    """
    Controlled adapter generating .sby formal verification task configurations.
    """

    @classmethod
    def generate_sby_config(
        cls,
        top_module: str,
        files: List[str],
        depth: int = 20,
        engine: str = "smtbmc",
    ) -> str:
        """Generate a basic SymbiYosys configuration script."""
        file_lines = "\n".join(f"read -sv {os.path.basename(f)}" for f in files)
        sby_text = f"""[options]
mode bmc
depth {depth}

[engines]
{engine}

[script]
{file_lines}
prep -top {top_module}

[files]
"""
        for f in files:
            sby_text += f"{f}\n"

        return sby_text

    @classmethod
    def run_sby_task(cls, sby_file: str, work_dir: str, timeout_seconds: int = 30) -> Tuple[bool, str]:
        """Run SymbiYosys subprocess in controlled scratch environment."""
        if not os.path.exists(sby_file):
            return False, "sby_file_not_found"
        try:
            res = subprocess.run(
                ["sby", "-f", sby_file],
                cwd=work_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout_seconds,
            )
            passed = res.returncode == 0
            return passed, res.stdout
        except Exception as e:
            return False, str(e)
