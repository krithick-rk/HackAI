"""
Z3 Reachability and SMT Feasibility Engine (Stage 5).
Solves path conditions under approved attacker capabilities, environment assumptions,
and register invariants using Z3.
Enforces conservative over-approximation: opaque logic or unmodeled constructs NEVER produce UNSAT.
"""

from __future__ import annotations
import z3
from typing import Dict, List, Optional, Any, Set, Tuple

from src.soc_analyzer.design_db.schemas import DesignDB, AnalyzabilityLevel
from src.soc_analyzer.candidates.schemas import CandidateClaim
from .schemas import (
    ProvenanceChain,
    ProvenanceNode,
    ProvenanceEdge,
    SourceKind,
    ReachabilityResult,
    ReachabilityResultStatus,
)
from .path_condition import (
    PathCondition,
    UnknownCondition,
    ConstCondition,
    cond_true,
    cond_and,
)
from .z3_translator import Z3Translator, CannotTranslateError


class Z3ReachabilityEngine:
    """
    Formally evaluates feasibility of security-cone path conditions with Z3.
    """

    def __init__(self, design_db: DesignDB):
        self.db = design_db
        self.solver_version = z3.get_version_string()

    def analyze_reachability(
        self,
        candidate: CandidateClaim,
        provenance_chain: ProvenanceChain,
    ) -> ReachabilityResult:
        """
        Build path condition from provenance edges, apply attacker and environment
        constraints, and solve via Z3.
        """
        unknown_reasons: List[str] = []
        assumptions: List[str] = []
        is_model_complete = True

        # 1. Configuration Awareness
        active_cfg = self.db.active_config or "default"
        cand_cfg = candidate.configuration or "default"
        if cand_cfg != "default" and cand_cfg not in self.db.shipped_configs:
            unknown_reasons.append(f"unverified_configuration: {cand_cfg}")
            is_model_complete = False

        # 2. Check Analyzability and Opaque Nodes in Provenance Chain
        for node_id, node in provenance_chain.nodes.items():
            if node.metadata.get("opaque"):
                unknown_reasons.append(f"opaque_node: {node_id}")
                is_model_complete = False
            # Check module analyzability
            if node.definition_id and node.definition_id in self.db.analyzability:
                assessment = self.db.analyzability[node.definition_id]
                if assessment.level == AnalyzabilityLevel.HIGHLY_OBFUSCATED:
                    unknown_reasons.append(f"highly_obfuscated_module: {node.definition_id}")
                    is_model_complete = False

        # 3. Collect Edge Predicates into Combined Path Condition
        path_conditions: List[PathCondition] = []
        for edge in provenance_chain.edges:
            if edge.predicate:
                pred = PathCondition.from_dict(edge.predicate)
                if pred.has_unknown():
                    unknown_reasons.append(f"unmodeled_guard_construct on edge {edge.source_node_id}->{edge.destination_node_id}")
                    is_model_complete = False
                path_conditions.append(pred)

        combined_condition = cond_and(*path_conditions) if path_conditions else cond_true()

        # 4. Translate Path Condition to Z3
        translator = Z3Translator()
        z3_condition: Optional[z3.ExprRef] = None
        try:
            z3_condition = translator.translate(combined_condition)
        except CannotTranslateError as e:
            unknown_reasons.append(f"translation_failure: {str(e)}")
            is_model_complete = False
        except Exception as e:
            unknown_reasons.append(f"translator_exception: {str(e)}")
            is_model_complete = False

        # 5. Extract Attacker and Environment Assumptions
        solver_constraints: List[z3.ExprRef] = []
        self._apply_attacker_constraints(candidate, translator, solver_constraints, assumptions)
        self._apply_register_invariants(candidate, translator, solver_constraints, assumptions)

        # 6. Check Feasibility with Z3 Solver
        z3_summary = str(z3_condition) if z3_condition is not None else "NONE"
        solver = z3.Solver()

        if z3_condition is not None:
            solver.add(z3_condition)
        for c in solver_constraints:
            solver.add(c)

        # If model is incomplete and we don't have a definitive condition, record reason
        if not is_model_complete and z3_condition is None:
            return ReachabilityResult(
                candidate_id=candidate.candidate_id,
                result=ReachabilityResultStatus.UNKNOWN,
                solver="z3",
                solver_version=self.solver_version,
                path_condition=combined_condition.to_dict(),
                z3_expression_summary=z3_summary,
                assumptions=assumptions,
                provenance_chain=provenance_chain,
                unknown_reasons=unknown_reasons,
                is_model_complete=False,
                configuration=cand_cfg,
            )

        # Run Z3 solver
        try:
            check_res = solver.check()
        except Exception as e:
            unknown_reasons.append(f"solver_execution_error: {str(e)}")
            check_res = z3.unknown

        final_status: ReachabilityResultStatus
        witness_assignment: Optional[Dict[str, Any]] = None

        if check_res == z3.sat:
            try:
                m = solver.model()
                witness_assignment = {str(d): str(m[d]) for d in m.decls()}
            except Exception:
                witness_assignment = {}

            if not is_model_complete or len(unknown_reasons) > 0:
                final_status = ReachabilityResultStatus.UNKNOWN
            else:
                final_status = ReachabilityResultStatus.SAT
        elif check_res == z3.unsat:
            # Conservative Over-Approximation Rule:
            # An UNSAT result can ONLY be trusted if all logic along the path is fully modeled.
            if not is_model_complete or len(unknown_reasons) > 0:
                final_status = ReachabilityResultStatus.UNKNOWN
                if not any("incomplete_model" in r for r in unknown_reasons):
                    unknown_reasons.append("unsat_rejected_due_to_incomplete_modeling")
            else:
                final_status = ReachabilityResultStatus.UNSAT
        else:
            final_status = ReachabilityResultStatus.UNKNOWN
            unknown_reasons.append(f"z3_unknown_reason: {solver.reason_unknown()}")

        result_obj = ReachabilityResult(
            candidate_id=candidate.candidate_id,
            result=final_status,
            solver="z3",
            solver_version=self.solver_version,
            path_condition=combined_condition.to_dict(),
            z3_expression_summary=z3_summary,
            assumptions=assumptions,
            provenance_chain=provenance_chain,
            unknown_reasons=unknown_reasons,
            witness_assignment=witness_assignment,
            is_model_complete=is_model_complete and (len(unknown_reasons) == 0),
            configuration=cand_cfg,
        )
        result_obj.model_hash = result_obj.compute_model_hash()
        return result_obj

    def _apply_attacker_constraints(
        self,
        candidate: CandidateClaim,
        translator: Z3Translator,
        constraints: List[z3.ExprRef],
        assumptions: List[str],
    ) -> None:
        """
        Translate approved attacker capabilities into solver environment assumptions.
        Never assume an attacker has capabilities not explicitly approved in the registry.
        """
        attackers = self.db.get_attackers(only_approved=True, only_enabled=True)
        # Find active attacker (e.g. from candidate metadata or default unprivileged SW attacker)
        active_att_id = candidate.metadata.get("attacker_id")
        active_att = None
        if active_att_id:
            active_att = self.db.get_attacker(active_att_id)
        if not active_att and attackers:
            # Default to first approved unprivileged attacker if none specified
            for att in attackers:
                if att.privilege_level in ("UNPRIVILEGED", "SW_UNPRIV"):
                    active_att = att
                    break
            if not active_att:
                active_att = attackers[0]

        if not active_att or not active_att.is_authoritative:
            assumptions.append("no_authoritative_attacker_assumptions")
            return

        assumptions.append(f"attacker_model:{active_att.id}:{active_att.privilege_level}")

        # If attacker privilege is UNPRIVILEGED, enforce that privileged signals cannot be asserted
        if active_att.privilege_level in ("UNPRIVILEGED", "SW_UNPRIV"):
            for sym_name in list(translator.symbols.keys()):
                if any(k in sym_name.lower() for k in ("priv_mode", "debug_auth", "security_auth", "otp_en")):
                    sym = translator.symbols[sym_name]
                    if z3.is_bool(sym):
                        constraints.append(sym == False)
                        assumptions.append(f"constrained_unprivileged_signal:{sym_name}=0")

        # If attacker boundary does not include DEBUG / JTAG, unauthenticated debug is 0
        b_type = (active_att.boundary.boundary_type or "").upper()
        if b_type not in ("DEBUG", "JTAG"):
            for sym_name in list(translator.symbols.keys()):
                if any(k in sym_name.lower() for k in ("debug_enable", "debug_auth", "jtag_en", "dmi_en")):
                    sym = translator.symbols[sym_name]
                    if z3.is_bool(sym):
                        constraints.append(sym == False)
                        assumptions.append(f"constrained_debug_signal:{sym_name}=0")

    def _apply_register_invariants(
        self,
        candidate: CandidateClaim,
        translator: Z3Translator,
        constraints: List[z3.ExprRef],
        assumptions: List[str],
    ) -> None:
        """
        Apply register reset invariants and regwen access locks from AssetRegistry.
        """
        assets = self.db.get_assets(only_approved=True, only_enabled=True)
        for asset in assets:
            if not asset.is_authoritative:
                continue

            reg_meta = asset.register_metadata
            if not reg_meta:
                continue

            # Regwen invariant: if regwen is ro or fixed 0
            if reg_meta.regwen:
                regwen_sym_name = reg_meta.regwen.lower()
                for sym_name in list(translator.symbols.keys()):
                    if regwen_sym_name in sym_name.lower():
                        sym = translator.symbols[sym_name]
                        # If candidate claims write to locked register without capability to unlock
                        if candidate.metadata.get("regwen_locked", False):
                            if z3.is_bool(sym):
                                constraints.append(sym == False)
                                assumptions.append(f"locked_regwen:{sym_name}=0")

            # Reset value invariant: if verified reset value is known
            if reg_meta.resval is not None:
                try:
                    res_int = int(reg_meta.resval, 0)
                    for sym_name in list(translator.symbols.keys()):
                        if reg_meta.reg_name.lower() in sym_name.lower() and "reset" in sym_name.lower():
                            sym = translator.symbols[sym_name]
                            if z3.is_int(sym):
                                constraints.append(sym == res_int)
                                assumptions.append(f"resval_invariant:{sym_name}={hex(res_int)}")
                            elif z3.is_bool(sym):
                                constraints.append(sym == (res_int != 0))
                                assumptions.append(f"resval_invariant:{sym_name}={res_int != 0}")
                except (ValueError, TypeError):
                    pass
