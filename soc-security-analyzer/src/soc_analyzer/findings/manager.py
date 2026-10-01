"""
Finding Manager and Pipeline Integrator (Stage 6).
Coordinates candidate ingestion from GroundingEngine and ReachabilityGate,
evaluates evidence and confirmation policies, performs definition-space deduplication,
maps CWEs, and persists findings to the durable SQLite store.
"""

from __future__ import annotations
from typing import Dict, List, Optional, Any, Tuple

from src.soc_analyzer.design_db.schemas import DesignDB
from src.soc_analyzer.candidates.schemas import (
    CandidateClaim,
    CandidateStatus,
    SourceChannel,
    EvidenceRef,
)
from src.soc_analyzer.candidates.grounding import GroundingEngine
from src.soc_analyzer.reachability.gate import ReachabilityGate
from .schemas import (
    Finding,
    FindingStatus,
    FindingLane,
    FindingReason,
    Severity,
    EvidenceItem,
    EvidenceType,
    VerificationStatus,
    InstanceManifestation,
)
from .cwe_map import map_weakness_to_cwe
from .dedup import compute_dedup_signature
from .confirmation_policy import ClassConfirmationPolicy
from .store import SQLiteFindingStore


class FindingManager:
    """
    Authoritative manager for finding lifecycles, adjudication, deduplication, and persistence.
    """

    def __init__(
        self,
        design_db: DesignDB,
        store: Optional[SQLiteFindingStore] = None,
    ):
        self.db = design_db
        self.store = store or SQLiteFindingStore(":memory:")
        self.grounding_engine = GroundingEngine()
        self.reachability_gate = ReachabilityGate(design_db)

    def process_candidate(self, candidate: CandidateClaim) -> Finding:
        """
        Execute full deterministic finding ingestion:
        CandidateClaim -> GroundingEngine -> ReachabilityGate -> FindingManager.
        """
        # 1. Ground candidate if not already grounded
        if candidate.status in (CandidateStatus.CANDIDATE, CandidateStatus.NEEDS_REANCHOR):
            candidate = self.grounding_engine.ground_candidate(candidate, self.db)

        # 2. Evaluate reachability if grounded or reanchored
        reach_dict = None
        if candidate.status in (CandidateStatus.GROUNDED, CandidateStatus.REANCHORED):
            candidate, reach_res = self.reachability_gate.evaluate(candidate)
            reach_dict = reach_res.to_dict()

        # 3. Convert candidate evidence references to EvidenceItem models
        evidence_items: List[EvidenceItem] = []
        for ev in candidate.evidence_refs:
            # Map evidence type
            raw_et = ev.evidence_type.value if hasattr(ev.evidence_type, "value") else str(ev.evidence_type)
            try:
                et = EvidenceType(raw_et)
            except ValueError:
                et = EvidenceType.DESIGN_DB

            # Assign verification status based on producer/channel
            is_ai = ("ai" in ev.source.lower() or
                     candidate.source_channel == SourceChannel.AI_HYPOTHESIS and et == EvidenceType.AI)
            v_status = VerificationStatus.UNVERIFIED if is_ai else VerificationStatus.VERIFIED

            evidence_items.append(EvidenceItem(
                evidence_id=ev.evidence_id,
                evidence_type=et,
                producer=ev.source,
                artifact_reference=ev.hash_or_reference,
                hash=ev.hash_or_reference,
                configuration=candidate.configuration,
                instance_path=candidate.instance_path,
                description=ev.description,
                verification_status=v_status,
            ))

        # 4. Map CWE deterministically
        cwe_id, cwe_src, _ = map_weakness_to_cwe(candidate.weakness_class)

        # 5. Compute L0 Definition-Space Dedup Signature
        dedup_sig = compute_dedup_signature(
            weakness_class=candidate.weakness_class,
            definition_id=candidate.definition_id,
            source_file=candidate.source_file,
            line_range=candidate.line_range,
            ast_id=candidate.ast_id,
        )

        # 6. Map Severity
        severity = Severity.MEDIUM
        asset_id = candidate.metadata.get("target_asset_id") or candidate.metadata.get("asset_id")
        if asset_id and self.db.registries:
            asset = self.db.registries.assets.get(asset_id)
            if asset:
                sens = (asset.sensitivity or "").upper()
                if sens == "CRITICAL":
                    severity = Severity.CRITICAL
                elif sens == "HIGH":
                    severity = Severity.HIGH
                elif sens == "LOW":
                    severity = Severity.LOW

        # 7. Map Initial Pipeline Status
        fnd_status = FindingStatus.CANDIDATE
        if candidate.status == CandidateStatus.REACHABLE:
            fnd_status = FindingStatus.REACHABLE
        elif candidate.status == CandidateStatus.UNREACHABLE:
            fnd_status = FindingStatus.UNREACHABLE
        elif candidate.status in (CandidateStatus.GROUNDED, CandidateStatus.REANCHORED):
            fnd_status = FindingStatus.GROUNDED
        elif candidate.status == CandidateStatus.UNKNOWN_REACHABILITY:
            fnd_status = FindingStatus.PARKED

        # Manifestation
        initial_manifestation = InstanceManifestation(
            instance_path=candidate.instance_path,
            configuration=candidate.configuration,
            line_range=candidate.line_range,
            file_path=candidate.source_file,
            deviating_attributes=candidate.metadata.get("deviating_attributes", {}),
        )

        finding = Finding(
            title=candidate.title or f"{candidate.weakness_class} in {candidate.instance_path}",
            weakness_class=candidate.weakness_class,
            severity=severity,
            source=candidate.claim,
            source_channel=candidate.source_channel.value if hasattr(candidate.source_channel, "value") else str(candidate.source_channel),
            file=candidate.source_file,
            line_range=candidate.line_range,
            definition_id=candidate.definition_id,
            instance_path=candidate.instance_path,
            configuration=candidate.configuration,
            asset_id=asset_id,
            attacker_id=candidate.metadata.get("attacker_id"),
            status=fnd_status,
            evidence_refs=evidence_items,
            reachability_result=reach_dict,
            cwe=cwe_id,
            cwe_source=cwe_src,
            dedup_signature=dedup_sig,
            manifestations=[initial_manifestation],
            metadata=dict(candidate.metadata),
        )

        # 8. Evaluate Class Confirmation Policy (Lane and Reason)
        lane, reason = ClassConfirmationPolicy.evaluate_adjudication(finding, self.db)
        finding.lane = lane
        finding.parked_reason = reason

        # 9. Deduplication check in store
        existing = self.store.get_by_dedup_signature(dedup_sig)
        if existing:
            # Merge duplicate into primary finding
            merged = self.store.merge_duplicate(existing.finding_id, finding)
            return merged

        # Create new authoritative finding
        return self.store.create_finding(finding)
