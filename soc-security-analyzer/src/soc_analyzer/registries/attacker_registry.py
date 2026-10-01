"""
Attacker Registry.
Maintains typed, validated attacker classes and boundaries with provenance.
"""

from __future__ import annotations
from typing import Dict, List, Optional, Any
from .schemas import AttackerEntry, ApprovalStatus


class AttackerRegistry:
    """
    Registry for threat actors and attacker entry boundaries.
    """

    def __init__(self):
        self._entries: Dict[str, AttackerEntry] = {}

    def add(self, entry: AttackerEntry) -> None:
        """Adds an attacker entry, rejecting duplicates and validating required fields."""
        self._validate_entry(entry)
        if entry.id in self._entries:
            raise ValueError(f"Duplicate Attacker ID '{entry.id}' already exists in AttackerRegistry.")
        self._entries[entry.id] = entry

    def update(self, entry: AttackerEntry) -> None:
        """Updates an existing entry, validating required fields."""
        self._validate_entry(entry)
        self._entries[entry.id] = entry

    def get(self, attacker_id: str) -> Optional[AttackerEntry]:
        return self._entries.get(attacker_id)

    def list(self, only_approved: bool = False, only_enabled: bool = True) -> List[AttackerEntry]:
        results = []
        for entry in self._entries.values():
            if only_enabled and not entry.enabled:
                continue
            if only_approved and entry.approval_status != ApprovalStatus.APPROVED:
                continue
            results.append(entry)
        return results

    def remove(self, attacker_id: str) -> bool:
        if attacker_id in self._entries:
            del self._entries[attacker_id]
            return True
        return False

    def _validate_entry(self, entry: AttackerEntry) -> None:
        if not entry.id or not isinstance(entry.id, str) or not entry.id.strip():
            raise ValueError("Attacker entry must have a valid non-empty 'id'.")
        if not entry.name or not isinstance(entry.name, str) or not entry.name.strip():
            raise ValueError(f"Attacker entry '{entry.id}' must have a valid non-empty 'name'.")
        if not isinstance(entry.capabilities, list):
            raise ValueError(f"Attacker entry '{entry.id}' capabilities must be a list.")
        if not entry.boundary or not entry.boundary.boundary_type:
            raise ValueError(f"Attacker entry '{entry.id}' must specify a valid boundary type.")
        if not entry.privilege_level:
            raise ValueError(f"Attacker entry '{entry.id}' must specify a privilege_level.")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attackers": [e.to_dict() for e in self._entries.values()]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AttackerRegistry:
        reg = cls()
        items = data.get("attackers", data.get("entries", []))
        if isinstance(items, dict):
            items = list(items.values())
        for item in items:
            entry = AttackerEntry.from_dict(item)
            reg.add(entry)
        return reg
