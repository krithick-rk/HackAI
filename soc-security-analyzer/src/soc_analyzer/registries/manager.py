"""
Security Registries Manager.
Coordinates AttackerRegistry, AssetRegistry, DeclassifierRegistry,
YAML/JSON serialization, cross-registry validation, and proposal workflows.
"""

from __future__ import annotations
import os
import json
from typing import Dict, List, Optional, Any, Tuple
import yaml

from .schemas import (
    ProvenanceType,
    ApprovalStatus,
    RegistryType,
    ProvenanceInfo,
    AttackerEntry,
    AssetEntry,
    DeclassifierEntry,
    RegistryProposal,
)
from .attacker_registry import AttackerRegistry
from .asset_registry import AssetRegistry
from .declassifier_registry import DeclassifierRegistry


class SecurityRegistries:
    """
    Central manager for all security registries and proposals.
    Provides deterministic serialization, cross-registry validation,
    and human approval workflows.
    """

    def __init__(self):
        self.attackers = AttackerRegistry()
        self.assets = AssetRegistry()
        self.declassifiers = DeclassifierRegistry()
        self.proposals: Dict[str, RegistryProposal] = {}

    def validate_all(self) -> List[str]:
        """
        Validates all registries and cross-references.
        Returns a list of actionable error descriptions.
        """
        errors: List[str] = []

        # 1. Validate declassifier references to assets
        declass_errors = self.declassifiers.validate_references(self.assets)
        errors.extend(declass_errors)

        # 2. Validate asset allowed observers/writers against attacker registry
        known_attacker_ids = {a.id for a in self.attackers.list(only_approved=False, only_enabled=False)}

        for asset in self.assets.list(only_approved=False, only_enabled=False):
            for obs in asset.allowed_observers:
                if obs.startswith("SW_") or obs.startswith("EXT_") or obs.startswith("DEBUG_"):
                    if obs not in known_attacker_ids:
                        errors.append(f"Asset '{asset.id}' references unknown attacker '{obs}' in allowed_observers")
            for wr in asset.allowed_writers:
                if wr.startswith("SW_") or wr.startswith("EXT_") or wr.startswith("DEBUG_"):
                    if wr not in known_attacker_ids:
                        errors.append(f"Asset '{asset.id}' references unknown attacker '{wr}' in allowed_writers")

        # 3. Check for any AI_PROPOSAL marked as APPROVED without human approver
        for asset in self.assets.list(only_approved=True, only_enabled=False):
            if asset.provenance.provenance_type == ProvenanceType.AI_PROPOSAL and not asset.provenance.author:
                errors.append(f"Asset '{asset.id}' has AI_PROPOSAL provenance without human approver verification.")

        return errors

    def propose(
        self,
        registry_type: RegistryType,
        proposed_entry: Dict[str, Any],
        reason: str,
        evidence_references: Optional[List[str]] = None,
        confidence: float = 0.5,
        proposal_id: Optional[str] = None,
    ) -> RegistryProposal:
        """
        Creates a new registry proposal in UNAPPROVED / PROPOSED status.
        AI proposals are NEVER automatically approved.
        """
        pid = proposal_id or f"prop_{registry_type.value.lower()}_{len(self.proposals) + 1}"
        if pid in self.proposals:
            raise ValueError(f"Duplicate proposal ID '{pid}' already exists.")

        proposal = RegistryProposal(
            proposal_id=pid,
            registry_type=registry_type,
            proposed_entry=proposed_entry,
            reason=reason,
            evidence_references=evidence_references or [],
            confidence=confidence,
            status=ApprovalStatus.PROPOSED,
        )
        self.proposals[pid] = proposal
        return proposal

    def approve_proposal(
        self,
        proposal_id: str,
        approver: str = "human",
        notes: Optional[str] = None
    ) -> Any:
        """
        Explicitly approves a proposal by a human reviewer.
        Transitions proposal to APPROVED and registers the entry in the target registry.
        """
        if proposal_id not in self.proposals:
            raise KeyError(f"Proposal '{proposal_id}' not found.")

        prop = self.proposals[proposal_id]
        if prop.status == ApprovalStatus.REJECTED:
            raise ValueError(f"Cannot approve proposal '{proposal_id}' which was previously REJECTED.")

        prop.status = ApprovalStatus.APPROVED
        prop.reviewer_notes = notes

        entry_data = dict(prop.proposed_entry)
        entry_data["approval_status"] = "APPROVED"

        # Update provenance to record human approval
        prov_dict = entry_data.get("provenance", {})
        prov_dict["author"] = approver
        prov_dict["description"] = f"Approved proposal {proposal_id} by {approver}: {notes or ''}".strip()
        prov_dict["provenance_type"] = "HUMAN_APPROVED"
        entry_data["provenance"] = prov_dict

        # Insert into target registry
        if prop.registry_type == RegistryType.ATTACKER:
            entry = AttackerEntry.from_dict(entry_data)
            if self.attackers.get(entry.id):
                self.attackers.update(entry)
            else:
                self.attackers.add(entry)
            return entry

        elif prop.registry_type == RegistryType.ASSET:
            entry = AssetEntry.from_dict(entry_data)
            if self.assets.get(entry.id):
                self.assets.update(entry)
            else:
                self.assets.add(entry)
            return entry

        elif prop.registry_type == RegistryType.DECLASSIFIER:
            entry = DeclassifierEntry.from_dict(entry_data)
            if self.declassifiers.get(entry.id):
                self.declassifiers.update(entry)
            else:
                self.declassifiers.add(entry)
            return entry
        else:
            raise ValueError(f"Unknown registry type '{prop.registry_type}'")

    def reject_proposal(self, proposal_id: str, reason: str = "") -> None:
        """Rejects a registry proposal."""
        if proposal_id not in self.proposals:
            raise KeyError(f"Proposal '{proposal_id}' not found.")
        prop = self.proposals[proposal_id]
        prop.status = ApprovalStatus.REJECTED
        prop.reviewer_notes = reason

    def is_authoritative(self, entry: Any) -> bool:
        """Determines if an entry can be used as an authoritative security anchor."""
        if hasattr(entry, "is_authoritative"):
            return bool(entry.is_authoritative)
        return False

    def ingest_hjson(
        self,
        file_path: str,
        module_name: Optional[str] = None,
        auto_approve: bool = False
    ) -> List[AssetEntry]:
        """
        Deterministically extracts registers and fields from an HJSON specification
        and ingests them into the AssetRegistry.
        By default, extracted entries have PROPOSED status (candidate metadata).
        """
        from .hjson_parser import HjsonRegisterExtractor
        extractor = HjsonRegisterExtractor(auto_approve=auto_approve)
        extracted_assets = extractor.parse_hjson_file(file_path, module_name=module_name)
        for asset in extracted_assets:
            if self.assets.get(asset.id):
                self.assets.update(asset)
            else:
                self.assets.add(asset)
        return extracted_assets

    def ingest_hjson_text(
        self,
        content: str,
        source_file: Optional[str] = None,
        module_name: Optional[str] = None,
        auto_approve: bool = False
    ) -> List[AssetEntry]:
        """
        Deterministically extracts registers and fields from HJSON text
        and ingests them into the AssetRegistry.
        """
        from .hjson_parser import HjsonRegisterExtractor
        extractor = HjsonRegisterExtractor(auto_approve=auto_approve)
        extracted_assets = extractor.parse_hjson_text(content, source_file=source_file, module_name=module_name)
        for asset in extracted_assets:
            if self.assets.get(asset.id):
                self.assets.update(asset)
            else:
                self.assets.add(asset)
        return extracted_assets

    def load_from_directory(self, dir_path: str) -> None:
        """
        Loads registries from a directory containing YAML or JSON files:
        attackers.yaml/.json, assets.yaml/.json, declassifiers.yaml/.json, proposals.yaml/.json.
        """
        abs_dir = os.path.abspath(dir_path)
        if not os.path.exists(abs_dir):
            raise FileNotFoundError(f"Registry directory not found: {abs_dir}")

        for base_name, reg_obj, parse_fn in [
            ("attackers", self.attackers, AttackerRegistry.from_dict),
            ("assets", self.assets, AssetRegistry.from_dict),
            ("declassifiers", self.declassifiers, DeclassifierRegistry.from_dict),
        ]:
            data = self._read_file_data(abs_dir, base_name)
            if data is not None:
                new_reg = parse_fn(data)
                # Merge into current registry
                for item in new_reg.list(only_approved=False, only_enabled=False):
                    if reg_obj.get(item.id):
                        reg_obj.update(item)
                    else:
                        reg_obj.add(item)

        # Load proposals if available
        prop_data = self._read_file_data(abs_dir, "proposals")
        if prop_data:
            props = prop_data.get("proposals", prop_data)
            if isinstance(props, list):
                for p in props:
                    prop_entry = RegistryProposal.from_dict(p)
                    self.proposals[prop_entry.proposal_id] = prop_entry

    def save_to_directory(self, dir_path: str, fmt: str = "yaml") -> None:
        """Saves all registries and proposals to a directory in YAML or JSON."""
        abs_dir = os.path.abspath(dir_path)
        os.makedirs(abs_dir, exist_ok=True)

        for base_name, reg_dict in [
            ("attackers", self.attackers.to_dict()),
            ("assets", self.assets.to_dict()),
            ("declassifiers", self.declassifiers.to_dict()),
            ("proposals", {"proposals": [p.to_dict() for p in self.proposals.values()]}),
        ]:
            if fmt.lower() in ("yaml", "yml"):
                f_path = os.path.join(abs_dir, f"{base_name}.yaml")
                with open(f_path, "w", encoding="utf-8") as f:
                    yaml.dump(reg_dict, f, default_flow_style=False, sort_keys=False)
            else:
                f_path = os.path.join(abs_dir, f"{base_name}.json")
                with open(f_path, "w", encoding="utf-8") as f:
                    json.dump(reg_dict, f, indent=2)

    def _read_file_data(self, dir_path: str, base_name: str) -> Optional[Dict[str, Any]]:
        # Try YAML first
        for ext in (".yaml", ".yml"):
            f_path = os.path.join(dir_path, f"{base_name}{ext}")
            if os.path.exists(f_path):
                with open(f_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if isinstance(data, dict):
                        return data
        # Try JSON
        f_path = os.path.join(dir_path, f"{base_name}.json")
        if os.path.exists(f_path):
            with open(f_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attackers": self.attackers.to_dict()["attackers"],
            "assets": self.assets.to_dict()["assets"],
            "declassifiers": self.declassifiers.to_dict()["declassifiers"],
            "proposals": [p.to_dict() for p in self.proposals.values()],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SecurityRegistries:
        mgr = cls()
        if "attackers" in data:
            mgr.attackers = AttackerRegistry.from_dict({"attackers": data["attackers"]})
        if "assets" in data:
            mgr.assets = AssetRegistry.from_dict({"assets": data["assets"]})
        if "declassifiers" in data:
            mgr.declassifiers = DeclassifierRegistry.from_dict({"declassifiers": data["declassifiers"]})
        if "proposals" in data:
            for p in data["proposals"]:
                prop = RegistryProposal.from_dict(p)
                mgr.proposals[prop.proposal_id] = prop
        return mgr
