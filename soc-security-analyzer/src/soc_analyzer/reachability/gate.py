"""
Candidate Reachability Gate (Stage 5).
Applies backward provenance traversal and formal Z3 feasibility analysis to GROUNDED candidates.
Transitions candidate status to REACHABLE, UNREACHABLE, or UNKNOWN_REACHABILITY,
and attaches structured formal evidence references to the candidate.
"""

from __future__ import annotations
from typing import Tuple, Optional, Any, Dict

from src.soc_analyzer.design_db.schemas import DesignDB
from src.soc_analyzer.candidates.schemas import (
    CandidateClaim,
    CandidateStatus,
    EvidenceRef,
    EvidenceType,
)
from .schemas import (
    ReachabilityResult,
    ReachabilityResultStatus,
    ProvenanceChain,
)
from .provenance_engine import ProvenanceEngine
from .z3_engine import Z3ReachabilityEngine


class ReachabilityGate:
    """
    Python Reachability Gate for the Candidate lifecycle.
    Evaluates grounded candidates through provenance traversal and Z3 path condition analysis.
    """

    def __init__(self, design_db: DesignDB):
        self.db = design_db
        self.provenance_engine = ProvenanceEngine(design_db)
        self.z3_engine = Z3ReachabilityEngine(design_db)

    def evaluate(self, candidate: CandidateClaim) -> Tuple[CandidateClaim, ReachabilityResult]:
        """
        Evaluate candidate reachability:
        1. Traverse backward provenance from sink.
        2. Construct and solve guarded path conditions under environment/attacker assumptions.
        3. Transition candidate status:
           SAT   -> REACHABLE
           UNSAT -> UNREACHABLE (only if model is complete)
           UNKNOWN (or incomplete UNSAT) -> UNKNOWN_REACHABILITY
        4. Attach structured formal EvidenceRef to candidate.
        """
        # 1. Build Provenance Chain
        chain = self.provenance_engine.build_provenance_chain(candidate)

        # 2. Analyze Reachability with Z3
        res = self.z3_engine.analyze_reachability(candidate, chain)

        # 3. Transition Lifecycle Status
        if res.result == ReachabilityResultStatus.SAT:
            candidate.status = CandidateStatus.REACHABLE
        elif res.result == ReachabilityResultStatus.UNSAT and res.is_model_complete:
            candidate.status = CandidateStatus.UNREACHABLE
        else:
            candidate.status = CandidateStatus.UNKNOWN_REACHABILITY

        # 4. Attach Structured Evidence
        assump_summary = ", ".join(res.assumptions) if res.assumptions else "none"
        unk_summary = ", ".join(res.unknown_reasons) if res.unknown_reasons else "none"

        evidence = EvidenceRef(
            evidence_type=EvidenceType.DESIGN_DB,
            source=f"reachability.{res.solver}",
            hash_or_reference=res.model_hash,
            description=(
                f"Formal Z3 Reachability: {res.result.value} "
                f"[complete={res.is_model_complete}, config={res.configuration}]. "
                f"Assumptions: [{assump_summary}]. "
                f"Unknowns: [{unk_summary}]."
            ),
        )
        candidate.evidence_refs.append(evidence)

        # Store full result metadata for later stages
        candidate.metadata["reachability"] = res.to_dict()

        return candidate, res
