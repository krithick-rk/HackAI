"""
Class-Specific Confirmation and Adjudication Policy (Stage 6).
Evaluates finding evidence against class-specific requirements.
Assigns authoritative finding lanes (CONFIRMED, PROBABLE, LEAD, WEAKNESS_ONLY, UNREACHABLE),
enforces witness dominance, and ensures missing simulation/witness artifacts park findings
in PROBABLE / LEAD rather than falsely confirming or refuting them.
"""

from __future__ import annotations
from typing import Dict, List, Optional, Any, Tuple

from src.soc_analyzer.design_db.schemas import DesignDB
from .schemas import (
    Finding,
    FindingStatus,
    FindingLane,
    FindingReason,
    VerificationStatus,
    EvidenceType,
)
from .evidence_policy import EvidencePolicyEngine, EvidenceClass


class ClassConfirmationPolicy:
    """
    Evaluates evidence sufficiency per vulnerability class.
    """

    SUPPORTED_CLASSES = {
        "ACCESS_CONTROL",
        "RESET",
        "FSM",
        "INFORMATION_FLOW",
        "DEBUG_TEST_GATING",
        "DECODE_ADDRESS",
        "CRYPTO_CONTROL",
        "FAULT_INJECTION",
    }

    @classmethod
    def evaluate_adjudication(
        cls,
        finding: Finding,
        design_db: Optional[DesignDB] = None,
    ) -> Tuple[FindingLane, FindingReason]:
        """
        Determine the appropriate decision lane and reason for a finding.
        Returns:
            (lane, reason)
        """
        # 1. Check Witness Dominance
        # If static gate contradicts a verified witness, preserve both and park in PROBABLE with CONFLICT.
        has_witness = (
            bool(finding.witness_refs) or
            EvidencePolicyEngine.has_reproducible_witness(finding.evidence_refs)
        )
        reach_data = finding.reachability_result or {}
        reach_status = reach_data.get("result", "UNKNOWN")

        if reach_status == "UNSAT" and has_witness:
            return FindingLane.PROBABLE, FindingReason.CONFLICT

        # 2. Check Sound Unreachability (from Stage 5)
        if reach_status == "UNSAT":
            is_complete = reach_data.get("is_model_complete", False)
            if is_complete and not has_witness:
                return FindingLane.UNREACHABLE, FindingReason.VERIFIED_UNREACHABLE
            else:
                # Incomplete UNSAT must NOT refute
                return FindingLane.PROBABLE, FindingReason.UNKNOWN_REACHABILITY

        # 3. Check UNKNOWN Reachability
        if reach_status == "UNKNOWN":
            return FindingLane.PROBABLE, FindingReason.UNKNOWN_REACHABILITY

        # 4. Filter verified evidence
        verified_evidence = [
            e for e in finding.evidence_refs
            if e.verification_status == VerificationStatus.VERIFIED
        ]
        evidence_classes = EvidencePolicyEngine.get_verified_evidence_classes(verified_evidence)

        # 5. Check Class-Specific Confirmation Requirements
        weakness_norm = (finding.weakness_class or "").upper()
        norm_class = cls._normalize_class(weakness_norm)

        # In Stage 6, full formal/simulation witnesses (Stage 7) do not exist yet.
        # If a verified reproducible witness exists (e.g. from tests/benchmarks), we can evaluate CONFIRMED.
        # Otherwise, findings with sound reachability and authoritative anchors become PROBABLE or LEAD.

        if norm_class == "ACCESS_CONTROL":
            # Requires: grounded + reachability SAT + attacker legality + authoritative asset + independent evidence/witness
            has_auth_asset = False
            if design_db and finding.asset_id:
                has_auth_asset = design_db.is_asset_authoritative(finding.asset_id)
            elif finding.asset_id:
                has_auth_asset = True

            if has_witness and has_auth_asset:
                return FindingLane.CONFIRMED, FindingReason.NONE
            if reach_status == "SAT" and has_auth_asset:
                return FindingLane.PROBABLE, FindingReason.NO_WITNESS
            elif reach_status == "SAT":
                return FindingLane.LEAD, FindingReason.MISSING_ASSET_ANCHOR
            else:
                return FindingLane.LEAD, FindingReason.INSUFFICIENT_EVIDENCE

        elif norm_class == "RESET":
            if has_witness:
                return FindingLane.CONFIRMED, FindingReason.NONE
            if reach_status == "SAT":
                return FindingLane.PROBABLE, FindingReason.NO_WITNESS
            return FindingLane.LEAD, FindingReason.INSUFFICIENT_EVIDENCE

        elif norm_class == "DEBUG_TEST_GATING":
            if has_witness:
                return FindingLane.CONFIRMED, FindingReason.NONE
            if reach_status == "SAT":
                return FindingLane.PROBABLE, FindingReason.NO_WITNESS
            return FindingLane.LEAD, FindingReason.INSUFFICIENT_EVIDENCE

        elif norm_class == "DECODE_ADDRESS":
            if has_witness:
                return FindingLane.CONFIRMED, FindingReason.NONE
            # Decode overlap can be structural or proven via SAT
            if reach_status == "SAT" or EvidenceClass.DETERMINISTIC_STRUCTURAL in evidence_classes:
                return FindingLane.PROBABLE, FindingReason.NO_WITNESS
            return FindingLane.LEAD, FindingReason.INSUFFICIENT_EVIDENCE

        elif norm_class == "FSM":
            if has_witness:
                return FindingLane.CONFIRMED, FindingReason.NONE
            if reach_status == "SAT":
                return FindingLane.PROBABLE, FindingReason.NO_WITNESS
            return FindingLane.WEAKNESS_ONLY, FindingReason.NO_WITNESS

        elif norm_class in ("INFORMATION_FLOW", "CRYPTO_CONTROL", "FAULT_INJECTION"):
            if has_witness:
                return FindingLane.CONFIRMED, FindingReason.NONE
            if reach_status == "SAT":
                return FindingLane.PROBABLE, FindingReason.NO_WITNESS
            return FindingLane.LEAD, FindingReason.INSUFFICIENT_EVIDENCE

        # Generic fallback
        if has_witness:
            return FindingLane.CONFIRMED, FindingReason.NONE
        if reach_status == "SAT":
            return FindingLane.PROBABLE, FindingReason.NO_WITNESS
        return FindingLane.LEAD, FindingReason.INSUFFICIENT_EVIDENCE

    @classmethod
    def _normalize_class(cls, weakness_class: str) -> str:
        for c in cls.SUPPORTED_CLASSES:
            if c in weakness_class:
                return c
        return "ACCESS_CONTROL"
