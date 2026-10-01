"""
Deterministic HJSON Register Metadata Extractor.
Parses hardware IP HJSON specifications (e.g. OpenTitan register files)
and extracts register/field metadata into AssetRegistry entries.
"""

from __future__ import annotations
import os
import json
from typing import Dict, List, Optional, Any
from .schemas import (
    AssetEntry,
    RegisterMetadata,
    FieldMetadata,
    ProvenanceInfo,
    ProvenanceType,
    ApprovalStatus,
)

try:
    import hjson
except ImportError:
    hjson = None


class HjsonRegisterExtractor:
    """
    Extracts register specifications, access permissions, lock bits (regwen),
    and reset values deterministically from HJSON files.
    """

    def __init__(self, auto_approve: bool = False):
        self.auto_approve = auto_approve

    def parse_hjson_file(self, file_path: str, module_name: Optional[str] = None) -> List[AssetEntry]:
        """Parses an HJSON file and returns extracted AssetEntry objects."""
        abs_path = os.path.abspath(file_path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"HJSON file not found: {abs_path}")

        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        return self.parse_hjson_text(content, source_file=abs_path, module_name=module_name)

    def parse_hjson_text(
        self,
        content: str,
        source_file: Optional[str] = None,
        module_name: Optional[str] = None
    ) -> List[AssetEntry]:
        """Parses HJSON text into AssetEntry objects."""
        data = None
        if hjson is not None:
            try:
                data = hjson.loads(content)
            except Exception:
                pass

        if data is None:
            # Fallback to standard json
            try:
                data = json.loads(content)
            except Exception as e:
                raise ValueError(f"Failed to parse HJSON content: {e}")

        if not isinstance(data, dict):
            return []

        mod_name = module_name or data.get("name", "ip")
        registers = data.get("registers", [])
        assets: List[AssetEntry] = []

        for item in registers:
            if not isinstance(item, dict):
                continue

            # Check if this is a multireg or a regular register
            if "multireg" in item and isinstance(item["multireg"], dict):
                reg_def = item["multireg"]
                count = reg_def.get("count", 1)
                # If count is numeric string or int
                try:
                    num_regs = int(count)
                except Exception:
                    num_regs = 1  # Parameterized count, default to representative asset

                base_name = reg_def.get("name", "MULTIREG")
                for i in range(num_regs):
                    suffix = f"_{i}" if num_regs > 1 else ""
                    r_name = f"{base_name}{suffix}"
                    asset = self._create_asset_from_reg(mod_name, r_name, reg_def, source_file)
                    assets.append(asset)
            else:
                r_name = item.get("name", "")
                if r_name:
                    asset = self._create_asset_from_reg(mod_name, r_name, item, source_file)
                    assets.append(asset)

        return assets

    def _create_asset_from_reg(
        self,
        mod_name: str,
        reg_name: str,
        reg_dict: Dict[str, Any],
        source_file: Optional[str]
    ) -> AssetEntry:
        swaccess = reg_dict.get("swaccess", "rw")
        hwaccess = reg_dict.get("hwaccess", "hro")
        regwen = reg_dict.get("regwen")
        resval = str(reg_dict.get("resval", "0"))
        shadowed = bool(reg_dict.get("shadowed", False))
        desc = reg_dict.get("desc", "").strip()

        # Parse bit fields
        fields: List[FieldMetadata] = []
        for f in reg_dict.get("fields", []):
            if isinstance(f, dict):
                fields.append(FieldMetadata(
                    bits=str(f.get("bits", "0")),
                    name=str(f.get("name", "")),
                    desc=f.get("desc"),
                    swaccess=f.get("swaccess", swaccess),
                    resval=str(f.get("resval")) if f.get("resval") is not None else None,
                ))

        address_offset = str(reg_dict.get("offset") or reg_dict.get("address_offset") or "") or None

        reg_meta = RegisterMetadata(
            reg_name=reg_name,
            address_offset=address_offset,
            swaccess=swaccess,
            hwaccess=hwaccess,
            regwen=regwen,
            resval=resval,
            shadowed=shadowed,
            fields=fields,
        )

        # Categorize asset type and sensitivity deterministically based on HJSON properties
        asset_type = "SECURITY_CONFIG_REG"
        sensitivity = "MEDIUM"
        r_upper = reg_name.upper()

        if regwen or r_upper.endswith("_REGWEN") or "LOCK" in r_upper:
            asset_type = "SECURITY_CONFIG_REG"
            sensitivity = "HIGH"
        elif any(k in r_upper for k in ["KEY", "SECRET", "SEED", "SALT"]):
            asset_type = "KEY"
            sensitivity = "CRITICAL"
        elif any(k in r_upper for k in ["LIFECYCLE", "LC_STATE", "OTP"]):
            asset_type = "LIFECYCLE_STATE"
            sensitivity = "CRITICAL"
        elif any(k in r_upper for k in ["DEBUG", "DBG", "DMI", "JTAG"]):
            asset_type = "DEBUG_CONTROL"
            sensitivity = "HIGH"
        elif shadowed:
            asset_type = "SECURITY_CONFIG_REG"
            sensitivity = "HIGH"

        asset_id = f"{mod_name.upper()}_{reg_name.upper()}"
        status = ApprovalStatus.APPROVED if self.auto_approve else ApprovalStatus.PROPOSED

        prov = ProvenanceInfo(
            provenance_type=ProvenanceType.HJSON,
            source_file=source_file,
            description=f"Extracted from {mod_name} HJSON specification",
        )

        return AssetEntry(
            id=asset_id,
            name=f"{mod_name}.{reg_name}",
            asset_type=asset_type,
            sensitivity=sensitivity,
            source_path=f"reg:{mod_name}.{reg_name}",
            safe_default_value=resval,
            register_metadata=reg_meta,
            provenance=prov,
            approval_status=status,
            enabled=True,
            metadata={"description": desc},
        )
