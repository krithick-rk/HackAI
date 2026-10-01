"""
Evidence Policy and Classification Layer (Stage 6).
Evaluates the validity and strength of structured evidence items.
Enforces the rule that AI-origin evidence cannot alone produce confirmation,
and that only verified Python/tool/formal artifacts contribute to finding confirmation.
"""

from __future__ import annotations
from enum import Enum
from typing import List, Dict, Any, Set

from .schemas import (
    EvidenceItem,
    EvidenceType,
    VerificationStatus,
)


class EvidenceClass(str, Enum):
    """
    Evidence strength tier according to the V2 architecture.
    """
    DETERMINISTIC_STRUCTURAL = "DETERMINISTIC_STRUCTURAL"
    TOOL_NATIVE = "TOOL_NATIVE"
    REPRODUCIBLE_WITNESS = "REPRODUCIBLE_WITNESS"
    AI_ORIGIN = "AI_ORIGIN"


class EvidencePolicyEngine:
    """
    Evaluates evidence validity, categorizes items into strength classes,
    and checks confirmation eligibility.
    """

    @classmethod
    def classify_evidence(cls, item: EvidenceItem) -> EvidenceClass:
        """Classify an evidence item into its strength tier."""
        e_type = item.evidence_type
        if e_type in (EvidenceType.AI_PROPOSAL, EvidenceType.AI_EXPLANATION) or "ai" in item.producer.lower():
            return EvidenceClass.AI_ORIGIN

        if e_type in (EvidenceType.SIM_TRACE, EvidenceType.FORMAL_TRACE, EvidenceType.ORACLE):
            return EvidenceClass.REPRODUCIBLE_WITNESS

        if e_type in (EvidenceType.TOOL, EvidenceType.DV):
            return EvidenceClass.TOOL_NATIVE

        # Default to deterministic structural
        return EvidenceClass.DETERMINISTIC_STRUCTURAL

    @classmethod
    def can_contribute_to_confirmation(cls, item: EvidenceItem) -> bool:
        """
        Only VERIFIED, non-AI evidence can contribute to finding confirmation.
        """
        if item.verification_status != VerificationStatus.VERIFIED:
            return False

        tier = cls.classify_evidence(item)
        if tier == EvidenceClass.AI_ORIGIN:
            # AI evidence may support investigation but cannot alone produce CONFIRMED
            return False

        return True

    @classmethod
    def has_reproducible_witness(cls, evidence_items: List[EvidenceItem]) -> bool:
        """Check if any verified reproducible witness exists."""
        for item in evidence_items:
            if item.verification_status == VerificationStatus.VERIFIED:
                if cls.classify_evidence(item) == EvidenceClass.REPRODUCIBLE_WITNESS:
                    return True
        return False

    @classmethod
    def get_verified_evidence_classes(cls, evidence_items: List[EvidenceItem]) -> Set[EvidenceClass]:
        """Collect set of distinct verified evidence classes present."""
        classes = set()
        for item in evidence_items:
            if item.verification_status == VerificationStatus.VERIFIED:
                classes.add(cls.classify_evidence(item))
        return classes
