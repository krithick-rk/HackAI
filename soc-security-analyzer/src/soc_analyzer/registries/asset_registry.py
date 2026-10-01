"""
Asset Registry.
Maintains typed, validated protected assets (keys, registers, state) with provenance.
"""

from __future__ import annotations
from typing import Dict, List, Optional, Any
from .schemas import AssetEntry, ApprovalStatus, ProvenanceType


class AssetRegistry:
    """
    Registry for protected hardware assets.
    Enforces provenance rules: AI proposals and name-derived candidates
    never become approved automatically.
    """

    def __init__(self):
        self._entries: Dict[str, AssetEntry] = {}

    def add(self, entry: AssetEntry) -> None:
        """Adds a protected asset entry, rejecting duplicates and validating required fields."""
        self._validate_entry(entry)
        if entry.id in self._entries:
            raise ValueError(f"Duplicate Asset ID '{entry.id}' already exists in AssetRegistry.")

        # Guard: AI_PROPOSAL must never be added in APPROVED state directly
        if entry.provenance.provenance_type == ProvenanceType.AI_PROPOSAL and entry.approval_status == ApprovalStatus.APPROVED:
            raise ValueError(f"Asset '{entry.id}' has AI_PROPOSAL provenance and cannot be registered directly as APPROVED.")

        self._entries[entry.id] = entry

    def update(self, entry: AssetEntry) -> None:
        """Updates an existing asset entry, validating required fields."""
        self._validate_entry(entry)
        self._entries[entry.id] = entry

    def get(self, asset_id: str) -> Optional[AssetEntry]:
        return self._entries.get(asset_id)

    def list(self, only_approved: bool = False, only_enabled: bool = True) -> List[AssetEntry]:
        results = []
        for entry in self._entries.values():
            if only_enabled and not entry.enabled:
                continue
            if only_approved and entry.approval_status != ApprovalStatus.APPROVED:
                continue
            results.append(entry)
        return results

    def remove(self, asset_id: str) -> bool:
        if asset_id in self._entries:
            del self._entries[asset_id]
            return True
        return False

    def _validate_entry(self, entry: AssetEntry) -> None:
        if not entry.id or not isinstance(entry.id, str) or not entry.id.strip():
            raise ValueError("Asset entry must have a valid non-empty 'id'.")
        if not entry.name or not isinstance(entry.name, str) or not entry.name.strip():
            raise ValueError(f"Asset entry '{entry.id}' must have a valid non-empty 'name'.")
        if not entry.asset_type:
            raise ValueError(f"Asset entry '{entry.id}' must specify an asset_type.")
        if not entry.source_path or not entry.source_path.strip():
            raise ValueError(f"Asset entry '{entry.id}' must specify a source_path (signal or register path).")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assets": [e.to_dict() for e in self._entries.values()]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AssetRegistry:
        reg = cls()
        items = data.get("assets", data.get("entries", []))
        if isinstance(items, dict):
            items = list(items.values())
        for item in items:
            entry = AssetEntry.from_dict(item)
            reg.add(entry)
        return reg
