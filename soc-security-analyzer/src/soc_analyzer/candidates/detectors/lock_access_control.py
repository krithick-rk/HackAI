"""
Lock and Access Control Pattern Detector.
Detects writable security-sensitive registers or controls lacking expected regwen guards,
or containing subtle guard dominance bypasses (e.g. OR/disjunction bypasses, weak guards).
"""

from __future__ import annotations
import re
from typing import List, Dict, Any, Optional, Set
import z3

from src.soc_analyzer.design_db.schemas import DesignDB, ModuleDefinition, AssignmentFact
from src.soc_analyzer.reachability.guard_extractor import GuardTokenizer, GuardParser
from src.soc_analyzer.reachability.z3_translator import Z3Translator
from .base import BaseDetector
from ..schemas import CandidateClaim, SourceChannel, CandidateStatus, EvidenceRef, EvidenceType


class LockAccessControlDetector(BaseDetector):
    """
    Detects security registers lacking regwen write-enable protections
    or displaying subtle guard dominance bypasses (formal SMT SAT proof of bypass).
    """

    def __init__(self):
        super().__init__(
            name="lock_access_control",
            weakness_classes=["MISSING_REGWEN", "REGWEN_BYPASS", "UNPROTECTED_SECURITY_REGISTER"],
        )

    def analyze(
        self,
        design_db: DesignDB,
        context: Optional[Dict[str, Any]] = None
    ) -> List[CandidateClaim]:
        candidates: List[CandidateClaim] = []
        assets = design_db.get_assets(only_approved=False, only_enabled=True)

        for asset in assets:
            reg_meta = asset.register_metadata
            if not reg_meta:
                continue

            # Only inspect writable registers / controls
            swaccess = (reg_meta.swaccess or "rw").lower()
            is_writable = any(w in swaccess for w in ["rw", "wo", "w1c", "w0c"])

            # Check if classified as high/critical sensitivity or security config
            is_sec_sensitive = (
                asset.sensitivity in ("CRITICAL", "HIGH")
                or asset.asset_type in ("SECURITY_CONFIG_REG", "KEY", "DEBUG_CONTROL")
            )

            # Avoid flagging the regwen lock register itself
            is_lock_reg = (
                asset.name.upper().endswith("_REGWEN")
                or "REGWEN" in asset.id.upper()
                or (reg_meta.reg_name and reg_meta.reg_name.upper().endswith("_REGWEN"))
            )

            if not (is_writable and is_sec_sensitive and not is_lock_reg):
                continue

            # Resolve associated module definition
            mod_name = asset.name.split(".")[0] if "." in asset.name else ""
            sig_name = asset.name.split(".")[-1] if "." in asset.name else asset.name
            if mod_name not in design_db.definitions and asset.source_path:
                cand_mod = asset.source_path.split(".")[0]
                if cand_mod in design_db.definitions:
                    mod_name = cand_mod
            if mod_name not in design_db.definitions and len(design_db.definitions) == 1:
                mod_name = list(design_db.definitions.keys())[0]

            m_def = design_db.definitions.get(mod_name)

            target_names = {sig_name}
            if reg_meta.reg_name:
                target_names.add(reg_meta.reg_name)

            # Check explicit guard reference
            guard_ref = reg_meta.guard_ref or reg_meta.regwen

            if not guard_ref:
                # Attempt constrained inference of an authorization / lock signal from module ports if m_def exists
                inferred_guard = None
                if m_def:
                    for p in m_def.ports:
                        if "regwen" in p.lower() or "lock" in p.lower():
                            inferred_guard = p
                            break

                if not inferred_guard:
                    # Purely missing lock guard: emit standard MISSING_REGWEN candidate
                    source_file = m_def.file_path if m_def else ""
                    line_range = (m_def.location.line, m_def.location.end_line or m_def.location.line) if m_def else (1, 1)
                    cand = CandidateClaim(
                        source_channel=SourceChannel.DETERMINISTIC,
                        weakness_class="MISSING_REGWEN",
                        title=f"Security register '{asset.name}' lacks hardware regwen write lock",
                        description=(
                            f"Register '{asset.name}' has swaccess='{swaccess}' with {asset.sensitivity} "
                            f"sensitivity and asset_type='{asset.asset_type}', but specifies no regwen lock signal."
                        ),
                        source_file=source_file,
                        line_range=line_range,
                        instance_path=asset.source_path,
                        definition_id=mod_name or None,
                        claim=(
                            f"Writable security register '{asset.name}' lacks hardware regwen write protection, "
                            f"allowing software with bus write capability to modify sensitive state directly."
                        ),
                        evidence_refs=[
                            EvidenceRef(
                                evidence_type=EvidenceType.REGISTRY,
                                source=asset.id,
                                hash_or_reference=asset.source_path,
                                description=f"Asset swaccess='{swaccess}', sensitivity='{asset.sensitivity}', regwen=None",
                            )
                        ],
                        configuration=design_db.active_config,
                        status=CandidateStatus.CANDIDATE,
                        metadata={"asset_id": asset.id, "swaccess": swaccess},
                    )
                    candidates.append(cand)
                    continue
                else:
                    guard_ref = inferred_guard

            if not m_def:
                continue

            # Structural Guard Dominance and Bypass Analysis (SMT-grounded)
            self._analyze_guard_dominance(
                asset=asset,
                m_def=m_def,
                target_names=target_names,
                guard_ref=guard_ref,
                design_db=design_db,
                candidates=candidates,
            )

        return candidates

    def _analyze_guard_dominance(
        self,
        asset: Any,
        m_def: ModuleDefinition,
        target_names: Set[str],
        guard_ref: str,
        design_db: DesignDB,
        candidates: List[CandidateClaim],
    ) -> None:
        # Resolve effective guard signal in module
        effective_guard_sig = None
        if guard_ref in m_def.ports or guard_ref in m_def.combinational_defs:
            effective_guard_sig = guard_ref
        else:
            for p in m_def.ports:
                if guard_ref.lower() in p.lower():
                    effective_guard_sig = p
                    break

        if not effective_guard_sig:
            return

        # Find candidate assignments to this register/sink
        relevant_assignments = [
            a for a in m_def.assignments
            if (a.target_signal in target_names
                or any(t in a.target_signal for t in target_names)
                or any(t in a.rhs_signals for t in target_names))
        ]

        if not relevant_assignments:
            return

        # Determine reset inactive condition (¬reset_active)
        reset_inactive_parts = []
        for r in m_def.resets:
            if r.active_level == "low":
                reset_inactive_parts.append(r.signal_name)
            else:
                reset_inactive_parts.append(f"!({r.signal_name})")

        reset_inactive_str = " && ".join(reset_inactive_parts) if reset_inactive_parts else "true"

        for u in relevant_assignments:
            # False-positive control 1: Skip explicit reset branches
            if u.is_reset_branch:
                continue

            # False-positive control 2: Skip constant hardware clears / tieoffs with no attacker input
            is_const_clear = (
                u.source_expr in ("0", "1'b0", "32'h0", "32'd0", "0x0", "'0", "1'0")
                and not any(sig in m_def.ports and m_def.ports[sig].direction == "input" for sig in u.rhs_signals)
            )
            if is_const_clear:
                continue

            # False-positive control 3: Require attacker data provenance or input write influence
            has_attacker_input = any(
                sig in m_def.ports and m_def.ports[sig].direction == "input"
                for sig in u.rhs_signals
            )
            is_driven_by_target = any(t in u.rhs_signals for t in target_names)
            if not has_attacker_input and not is_driven_by_target:
                continue

            # Path predicate Φ(U)
            phi_u_str = u.path_condition or "true"

            # Combinational guard inlining
            for _ in range(3):
                modified = False
                for comb_wire, comb_expr in m_def.combinational_defs.items():
                    if comb_wire != effective_guard_sig and re.search(rf"\b{re.escape(comb_wire)}\b", phi_u_str):
                        phi_u_str = re.sub(rf"\b{re.escape(comb_wire)}\b", f"({comb_expr})", phi_u_str)
                        modified = True
                if not modified:
                    break

            guard_cond_str = effective_guard_sig
            if effective_guard_sig in m_def.combinational_defs:
                guard_cond_str = f"({m_def.combinational_defs[effective_guard_sig]})"

            # Identify write request condition (write_request(U))
            write_req_sig = None
            for p, p_fact in m_def.ports.items():
                if p_fact.direction == "input":
                    if p in ("we", "write", "wr_en", "req", "cs", "valid") or any(k in p.lower() for k in ["we", "write", "wr_en"]):
                        if re.search(rf"\b{re.escape(p)}\b", phi_u_str):
                            write_req_sig = p
                            break

            if not write_req_sig:
                for p, p_fact in m_def.ports.items():
                    if p_fact.direction == "input" and p != effective_guard_sig and p not in [r.signal_name for r in m_def.resets]:
                        if re.search(rf"\b{re.escape(p)}\b", phi_u_str):
                            write_req_sig = p
                            break

            if not write_req_sig:
                continue

            # Core formal SMT query:
            # SAT( Φ(U) ∧ ¬L ∧ ¬reset_active ∧ write_request(U) )
            query_str = f"({phi_u_str}) && (!({guard_cond_str})) && ({reset_inactive_str}) && ({write_req_sig})"

            try:
                tokens = GuardTokenizer.tokenize(query_str)
                pc = GuardParser(tokens).parse()
                translator = Z3Translator()
                z3_query = translator.translate(pc)

                solver = z3.Solver()
                solver.set("timeout", 2000)
                solver.add(z3_query)
                res = solver.check()

                if res == z3.sat:
                    model = solver.model()
                    witness_dict = {str(d): str(model[d]) for d in model.decls()}
                    witness_summary = ", ".join(f"{k}={v}" for k, v in witness_dict.items())

                    loc = u.location or m_def.location
                    line_start = loc.line if loc else 1
                    line_end = loc.end_line or line_start

                    cand = CandidateClaim(
                        source_channel=SourceChannel.DETERMINISTIC,
                        weakness_class="REGWEN_BYPASS",
                        title=f"Security register '{asset.name}' has subtle access control guard bypass",
                        description=(
                            f"Update to register '{u.target_signal}' at line {line_start} is reachable when authorization "
                            f"guard '{effective_guard_sig}' is deasserted. "
                            f"Effective path condition '{u.path_condition}' is satisfiable with witness: [{witness_summary}]."
                        ),
                        source_file=loc.file if loc else m_def.file_path,
                        line_range=(line_start, line_end),
                        instance_path=asset.source_path,
                        definition_id=m_def.name,
                        claim=(
                            f"Assignment to security register '{u.target_signal}' allows unauthorized modification "
                            f"when intended lock '{effective_guard_sig}' is inactive. Formal SMT solver found satisfying "
                            f"bypass path with witness: {witness_summary}."
                        ),
                        evidence_refs=[
                            EvidenceRef(
                                evidence_type=EvidenceType.AST,
                                source=f"{m_def.name}.{u.target_signal}",
                                hash_or_reference=u.ast_id or f"{m_def.name}_{u.target_signal}_{line_start}",
                                description=f"Update assignment {u.target_signal} <= {u.source_expr} with path condition: {u.path_condition}",
                            ),
                            EvidenceRef(
                                evidence_type=EvidenceType.DESIGN_DB,
                                source="Z3_SMT_SOLVER",
                                hash_or_reference=str(u.ast_id),
                                description=f"SAT witness: {witness_summary}",
                            ),
                        ],
                        configuration=design_db.active_config,
                        status=CandidateStatus.CANDIDATE,
                        metadata={
                            "asset_id": asset.id,
                            "intended_guard": effective_guard_sig,
                            "path_condition": u.path_condition,
                            "witness": witness_dict,
                            "ast_id": u.ast_id,
                        },
                    )
                    candidates.append(cand)

            except Exception:
                continue
