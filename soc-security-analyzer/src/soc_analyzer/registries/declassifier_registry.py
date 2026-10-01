"""
Declassifier Registry.
Maintains approved declassification transformations from protected assets to public sinks.
"""

from __future__ import annotations
from typing import Dict, List, Optional, Any
from .schemas import DeclassifierEntry, ApprovalStatus, ProvenanceType
from .asset_registry import AssetRegistry


class DeclassifierRegistry:
    """
    Registry for approved declassification paths (e.g. key -> aes_cipher -> ciphertext).
    Enforces reference integrity with AssetRegistry.
    """

    def __init__(self):
        self._entries: Dict[str, DeclassifierEntry] = {}

    def add(self, entry: DeclassifierEntry) -> None:
        """Adds a declassifier entry, rejecting duplicates and validating required fields."""
        self._validate_entry(entry)
        if entry.id in self._entries:
            raise ValueError(f"Duplicate Declassifier ID '{entry.id}' already exists in DeclassifierRegistry.")

        # Guard: AI_PROPOSAL cannot be registered directly as APPROVED
        if entry.provenance.provenance_type == ProvenanceType.AI_PROPOSAL and entry.approval_status == ApprovalStatus.APPROVED:
            raise ValueError(f"Declassifier '{entry.id}' has AI_PROPOSAL provenance and cannot be registered directly as APPROVED.")

        self._entries[entry.id] = entry

    def update(self, entry: DeclassifierEntry) -> None:
        """Updates an existing entry, validating required fields."""
        self._validate_entry(entry)
        self._entries[entry.id] = entry

    def get(self, declassifier_id: str) -> Optional[DeclassifierEntry]:
        return self._entries.get(declassifier_id)

    def list(self, only_approved: bool = False, only_enabled: bool = True) -> List[DeclassifierEntry]:
        results = []
        for entry in self._entries.values():
            if only_enabled and not entry.enabled:
                continue
            if only_approved and entry.approval_status != ApprovalStatus.APPROVED:
                continue
            results.append(entry)
        return results

    def remove(self, declassifier_id: str) -> bool:
        if declassifier_id in self._entries:
            del self._entries[declassifier_id]
            return True
        return False

    def validate_references(self, asset_registry: AssetRegistry) -> List[str]:
        """
        Validates that every declassifier references an existing, valid asset in asset_registry.
        Returns a list of actionable error strings for any broken references.
        """
        errors = []
        for entry in self._entries.values():
            if not asset_registry.get(entry.source_asset_id):
                errors.append(
                    f"Declassifier '{entry.id}' references unknown source_asset_id '{entry.source_asset_id}'"
                )
        return errors

    def _validate_entry(self, entry: DeclassifierEntry) -> None:
        if not entry.id or not isinstance(entry.id, str) or not entry.id.strip():
            raise ValueError("Declassifier entry must have a valid non-empty 'id'.")
        if not entry.source_asset_id or not entry.source_asset_id.strip():
            raise ValueError(f"Declassifier entry '{entry.id}' must specify a source_asset_id.")
        if not entry.sink_target or not entry.sink_target.strip():
            raise ValueError(f"Declassifier entry '{entry.id}' must specify a sink_target.")
        if not entry.allowed_transformation or not entry.allowed_transformation.strip():
            raise ValueError(f"Declassifier entry '{entry.id}' must specify an allowed_transformation.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "declassifiers": [e.to_dict() for e in self._entries.values()]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DeclassifierRegistry:
        reg = cls()
        items = data.get("declassifiers", data.get("entries", []))
        if isinstance(items, dict):
            items = list(items.values())
        for item in items:
            entry = DeclassifierEntry.from_dict(item)
            reg.add(entry)
        return reg
