"""
Witness Engine Orchestrator (Stage 7).
Coordinates harness fit scanning, stimulus validation, simulation execution,
independent oracle evaluations, clean replay verification, and finding status transitions.
"""

from __future__ import annotations
import os
from typing import Dict, List, Optional, Any, Tuple

from src.soc_analyzer.design_db.schemas import DesignDB
from src.soc_analyzer.findings.schemas import (
    Finding,
    FindingStatus,
    FindingLane,
    FindingReason,
    EvidenceItem,
    EvidenceType,
    VerificationStatus,
)
from src.soc_analyzer.findings.state_machine import StateTransitionValidator
from .schemas import (
    WitnessResult,
    WitnessKind,
    WitnessStatus,
    HarnessFitStatus,
    Scenario,
    StimulusOp,
    StimulusOpType,
    OracleType,
    OracleStatus,
    SimRunStatus,
)
from .harness_fit import HarnessFitScanner, HarnessFitResult
from .stimulus import StimulusLegalityValidator
from .dv_inventory import DVInventoryScanner, DVAssetInventory
from .bus_adapter import get_bus_adapter
from .sim_runner import SimulationRunner, SimRunResult
from .oracle import OracleSpec, OracleEngine
from .replay import ReplayEngine, ReplayResult
from .formal_witness import FormalWitnessEngine


class WitnessEngine:
    """
    Central orchestrator for Stage 7 executable witness generation and verification.
    """

    def __init__(self, design_db: DesignDB, work_dir: Optional[str] = None):
        self.db = design_db
        self.work_dir = work_dir or "/tmp/witness_engine"
        os.makedirs(self.work_dir, exist_ok=True)

    def verify(
        self,
        finding: Finding,
        scenario: Optional[Scenario] = None,
        oracle_spec: Optional[OracleSpec] = None,
        context: Optional[Dict[str, Any]] = None,
        force_emulator: bool = False,
    ) -> WitnessResult:
        """
        End-to-end executable witness verification:
        1. Harness fit check
        2. Existing DV inventory check
        3. Stimulus legality validation
        4. Oracle sanity check
        5. Simulation execution
        6. Clean deterministic replay
        7. Finding status promotion to REPRODUCED on verified witness
        """
        ctx = context or {}
        reasons: List[str] = []

        # Step 1: Look up module definition from DesignDB
        def_id = finding.definition_id
        if not def_id and finding.instance_path:
            inst = self.db.instances.get(finding.instance_path)
            if inst:
                def_id = inst.module_name
        module_def = self.db.definitions.get(def_id) if def_id else None

        # Step 2: Harness Fit Scan
        fit_result: Optional[HarnessFitResult] = None
        if module_def:
            fit_result = HarnessFitScanner.scan_module(module_def)
            if fit_result.status == HarnessFitStatus.HARNESS_UNSUPPORTED:
                # Unsupported DUT: Preserve finding, return UNKNOWN witness without rejecting finding
                return WitnessResult(
                    finding_id=finding.finding_id,
                    kind=WitnessKind.BUS_TRACE,
                    status=WitnessStatus.UNKNOWN,
                    configuration=finding.configuration,
                    instance_path=finding.instance_path,
                    verification_status="UNVERIFIED",
                    reason_codes=["harness_unsupported"] + fit_result.unsupported_reasons,
                )

        # Step 3: Check Existing DV Assets
        dv_inventory: Optional[DVAssetInventory] = None
        if module_def:
            dv_inventory = DVInventoryScanner.discover_assets(
                module_name=module_def.name,
                search_roots=[os.path.dirname(module_def.file_path), self.work_dir, "workspace"],
            )

        # Step 4: Scenario and Stimulus Preparation
        active_scenario = scenario
        if not active_scenario:
            # Generate default stimulus scenario targeting finding
            target_addr = int(finding.metadata.get("address_offset", 0x10)) if str(finding.metadata.get("address_offset", "")).startswith("0x") else 0x10
            target_data = int(finding.metadata.get("exploit_data", 0xDEADBEEF))
            active_scenario = Scenario(
                dut_instance=finding.instance_path,
                attacker_id=finding.attacker_id or "ATT_UNPRIV",
                stimulus_sequence=[
                    StimulusOp(cycle=0, operation=StimulusOpType.RESET),
                    StimulusOp(cycle=2, operation=StimulusOpType.IDLE),
                    StimulusOp(cycle=5, operation=StimulusOpType.WRITE, arguments={"addr": target_addr, "data": target_data, "target_signal": finding.metadata.get("target_signal", "sec_reg")}),
                    StimulusOp(cycle=10, operation=StimulusOpType.READ, arguments={"addr": target_addr}),
                ],
                seed=12345,
            )

        # Step 5: Stimulus Legality Validation
        attacker_entry = self.db.get_attacker(active_scenario.attacker_id) if self.db.registries else None
        internal_sigs = set(finding.metadata.get("internal_signals", []))

        is_legal, violations = StimulusLegalityValidator.validate_scenario(
            scenario=active_scenario,
            attacker=attacker_entry,
            internal_signals=internal_sigs,
        )

        if not is_legal:
            return WitnessResult(
                finding_id=finding.finding_id,
                kind=WitnessKind.BUS_TRACE,
                status=WitnessStatus.INVALID,
                configuration=finding.configuration,
                instance_path=finding.instance_path,
                verification_status="INVALID",
                reason_codes=violations,
                stimulus=[s.to_dict() for s in active_scenario.stimulus_sequence],
            )

        # Step 6: Oracle Formulation and Sanity Control
        target_sig = finding.metadata.get("target_signal", "last_write_data")
        expected_val = finding.metadata.get("exploit_data", 0xDEADBEEF)

        active_oracle = oracle_spec
        if not active_oracle:
            active_oracle = OracleSpec(
                oracle_id=f"orc_{finding.finding_id}",
                oracle_type=OracleType.REGISTER_VALUE,
                property_name=f"{finding.weakness_class}_oracle",
                target_signal=target_sig,
                expected_value=expected_val,
                expected_violation=True,
            )

        # Sanity check: Ensure oracle does NOT trigger on benign reset/idle
        benign_signals = {target_sig: 0, "last_write_data": 0}
        sane, sanity_res = OracleEngine.run_sanity_check(active_oracle, benign_signals)
        if not sane:
            return WitnessResult(
                finding_id=finding.finding_id,
                kind=WitnessKind.BUS_TRACE,
                status=WitnessStatus.INVALID,
                configuration=finding.configuration,
                instance_path=finding.instance_path,
                verification_status="INVALID",
                reason_codes=[sanity_res.details],
            )

        # Step 7: Simulation Execution
        dut_file = module_def.file_path if module_def else None
        bus_type = fit_result.bus_type if fit_result else "GENERIC_REG"

        sim_res = SimulationRunner.run_simulation(
            scenario=active_scenario,
            dut_file=dut_file,
            bus_type=bus_type,
            force_emulator=force_emulator,
        )

        if sim_res.status != SimRunStatus.COMPLETED:
            return WitnessResult(
                finding_id=finding.finding_id,
                kind=WitnessKind.BUS_TRACE,
                status=WitnessStatus.FAILED,
                configuration=finding.configuration,
                instance_path=finding.instance_path,
                verification_status="UNVERIFIED",
                reason_codes=[f"sim_execution_failed: {sim_res.status.value}"],
                tool_versions=sim_res.tool_versions,
                seed=sim_res.seed,
            )

        # Evaluate oracle on first run
        oracle_eval = OracleEngine.evaluate(active_oracle, sim_res.observed_signals)
        if oracle_eval.status != OracleStatus.PASSED:
            return WitnessResult(
                finding_id=finding.finding_id,
                kind=WitnessKind.BUS_TRACE,
                status=WitnessStatus.FAILED,
                configuration=finding.configuration,
                instance_path=finding.instance_path,
                verification_status="UNVERIFIED",
                reason_codes=[f"oracle_unmet: {oracle_eval.details}"],
                tool_versions=sim_res.tool_versions,
                seed=sim_res.seed,
            )

        # Step 8: Clean Replay Verification
        witness_id = f"wit_{finding.finding_id}"
        replay_res: ReplayResult = ReplayEngine.replay_witness(
            witness_id=witness_id,
            scenario=active_scenario,
            oracle_spec=active_oracle,
            dut_file=dut_file,
            bus_type=bus_type,
            first_run_observed=sim_res.observed_signals,
            force_emulator=force_emulator,
        )

        if not replay_res.matched:
            return WitnessResult(
                witness_id=witness_id,
                finding_id=finding.finding_id,
                kind=WitnessKind.BUS_TRACE,
                status=WitnessStatus.INVALID,
                configuration=finding.configuration,
                instance_path=finding.instance_path,
                verification_status="INVALID",
                reason_codes=[f"replay_mismatch: {replay_res.discrepancy}"],
                tool_versions=sim_res.tool_versions,
                seed=sim_res.seed,
            )

        # Step 9: Replay Succeeded -> Witness is VERIFIED!
        final_witness = WitnessResult(
            witness_id=witness_id,
            finding_id=finding.finding_id,
            kind=WitnessKind.BUS_TRACE,
            status=WitnessStatus.VERIFIED,
            configuration=finding.configuration,
            instance_path=finding.instance_path,
            stimulus_reference=active_scenario.compute_hash(),
            oracle_reference=active_oracle.oracle_id,
            replay_reference=replay_res.replay_id,
            tool_versions=sim_res.tool_versions,
            seed=sim_res.seed,
            verification_status="VERIFIED",
            reason_codes=["reproducible_witness_verified"],
            stimulus=[s.to_dict() for s in active_scenario.stimulus_sequence],
            metadata={
                "determinism_hash": replay_res.determinism_hash,
                "reused_dv": dv_inventory.has_reusable_dv if dv_inventory else False,
            },
        )

        # Step 10: Finding Integration & Transition to REPRODUCED
        self._integrate_verified_witness(finding, final_witness)

        return final_witness

    def _integrate_verified_witness(self, finding: Finding, witness: WitnessResult) -> None:
        """
        Transition finding status to REPRODUCED and attach structured evidence.
        Enforce witness dominance if static reachability conflicted.
        """
        if witness.verification_status != "VERIFIED":
            return

        # Record witness reference on finding
        if witness.witness_id not in finding.witness_refs:
            finding.witness_refs.append(witness.witness_id)

        # Attach formal witness evidence
        ev = EvidenceItem(
            evidence_type=EvidenceType.SIM_TRACE,
            producer="witness_engine",
            artifact_reference=witness.witness_id,
            hash=witness.compute_signature(),
            configuration=finding.configuration,
            instance_path=finding.instance_path,
            description=f"Verified reproducible witness [{witness.kind.value}] seed={witness.seed}",
            verification_status=VerificationStatus.VERIFIED,
        )
        finding.evidence_refs.append(ev)

        # Check for static conflict (Witness Dominance)
        reach = finding.reachability_result or {}
        reach_status = reach.get("result")
        if reach_status == "UNSAT":
            finding.lane = FindingLane.PROBABLE
            finding.parked_reason = FindingReason.CONFLICT
            finding.metadata["witness_static_conflict"] = True

        # Transition status to REPRODUCED
        if finding.status in (FindingStatus.REACHABLE, FindingStatus.GROUNDED, FindingStatus.PARKED):
            finding.status = FindingStatus.REPRODUCED
