"""
Clean Deterministic Replay Engine (Stage 7).
Executes independent re-runs of simulation witnesses to ensure strict reproducibility.
A witness is only promoted to VERIFIED after clean replay succeeds without discrepancies.
"""

from __future__ import annotations
import hashlib
import json
from typing import Dict, Any, Optional, Tuple

from .schemas import Scenario, ReplayResult, SimRunStatus
from .oracle import OracleSpec, OracleEngine
from .sim_runner import SimulationRunner, SimRunResult


class ReplayEngine:
    """
    Executes independent, deterministic replay runs of candidate witnesses.
    """

    @classmethod
    def replay_witness(
        cls,
        witness_id: str,
        scenario: Scenario,
        oracle_spec: OracleSpec,
        dut_file: Optional[str] = None,
        bus_type: Optional[str] = None,
        first_run_observed: Optional[Dict[str, Any]] = None,
        force_emulator: bool = False,
    ) -> ReplayResult:
        """
        Execute an independent replay using identical seed, stimulus, and oracle.
        """
        # Execute replay run
        sim_res: SimRunResult = SimulationRunner.run_simulation(
            scenario=scenario,
            dut_file=dut_file,
            bus_type=bus_type,
            force_emulator=force_emulator,
        )

        if sim_res.status != SimRunStatus.COMPLETED:
            return ReplayResult(
                witness_id=witness_id,
                matched=False,
                harness="verilator" if not force_emulator else "emulator",
                run_status=sim_res.status,
                discrepancy=f"replay_run_failed: {sim_res.stderr or sim_res.status.value}",
                determinism_hash="",
            )

        # Evaluate oracle on replay output
        oracle_res = OracleEngine.evaluate(oracle_spec, sim_res.observed_signals)
        if oracle_res.status.value != "PASSED":
            return ReplayResult(
                witness_id=witness_id,
                matched=False,
                harness="verilator" if not force_emulator else "emulator",
                run_status=sim_res.status,
                discrepancy=f"oracle_failed_on_replay: {oracle_res.details}",
                determinism_hash="",
            )

        # Check observed signal consistency against first run
        discrepancy: Optional[str] = None
        if first_run_observed is not None:
            # Check for signal state match on critical keys
            target = oracle_spec.target_signal
            val1 = first_run_observed.get(target)
            val2 = sim_res.observed_signals.get(target)
            if val1 is not None and val2 is not None and str(val1) != str(val2):
                discrepancy = f"signal_mismatch on {target}: first_run={val1} != replay={val2}"

        matched = discrepancy is None

        # Compute determinism hash
        det_payload = f"{scenario.seed}:{scenario.compute_hash()}:{json.dumps(sim_res.observed_signals, sort_keys=True)}"
        det_hash = hashlib.sha256(det_payload.encode("utf-8")).hexdigest()[:16]

        return ReplayResult(
            witness_id=witness_id,
            matched=matched,
            harness="verilator" if not force_emulator else "emulator",
            run_status=sim_res.status,
            discrepancy=discrepancy,
            determinism_hash=det_hash,
        )
