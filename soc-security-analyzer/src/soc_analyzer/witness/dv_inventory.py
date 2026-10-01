"""
Existing Verification Asset Discovery and Inventory (Stage 7).
Scans design directories for existing testbenches, SVA assertions,
scoreboards, and dv/ environments to reuse rather than generating duplicate harnesses.
"""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set


@dataclass
class DVAssetInventory:
    """Discovered verification assets for a target module."""
    target_module: str
    dv_dirs: List[str] = field(default_factory=list)
    testbenches: List[str] = field(default_factory=list)
    assertions: List[str] = field(default_factory=list)
    scoreboards: List[str] = field(default_factory=list)
    has_reusable_dv: bool = False
    primary_tb_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_module": self.target_module,
            "dv_dirs": self.dv_dirs,
            "testbenches": self.testbenches,
            "assertions": self.assertions,
            "scoreboards": self.scoreboards,
            "has_reusable_dv": self.has_reusable_dv,
            "primary_tb_path": self.primary_tb_path,
        }


class DVInventoryScanner:
    """
    Deterministic discovery of existing DV, TB, and SVA assets.
    """

    DV_DIR_NAMES = {"dv", "pre_dv", "tb", "model", "sva", "scoreboard", "test", "tests"}

    @classmethod
    def discover_assets(cls, module_name: str, search_roots: List[str]) -> DVAssetInventory:
        """
        Scan directory trees for verification assets related to module_name.
        """
        dv_dirs: Set[str] = set()
        testbenches: List[str] = []
        assertions: List[str] = []
        scoreboards: List[str] = []

        mod_lower = module_name.lower()

        for root_path in search_roots:
            if not root_path or not os.path.exists(root_path):
                continue

            for dirpath, dirnames, filenames in os.walk(root_path):
                # Check directory name matches
                base_dir = os.path.basename(dirpath).lower()
                if base_dir in cls.DV_DIR_NAMES or any(k in base_dir for k in ("_dv", "_tb")):
                    dv_dirs.add(dirpath)

                for fname in filenames:
                    f_lower = fname.lower()
                    full_p = os.path.join(dirpath, fname)

                    # Testbench files
                    if f_lower.endswith((".sv", ".v", ".cpp", ".py")):
                        if "tb_" in f_lower or "_tb" in f_lower or "test" in f_lower:
                            if mod_lower in f_lower or base_dir in cls.DV_DIR_NAMES:
                                testbenches.append(full_p)

                    # SVA assertion files
                    if f_lower.endswith(".sv") and ("sva" in f_lower or "assert" in f_lower):
                        assertions.append(full_p)

                    # Scoreboards
                    if "scoreboard" in f_lower or "scb" in f_lower:
                        scoreboards.append(full_p)

        # Select primary testbench if any matches module specifically
        primary_tb = None
        for tb in testbenches:
            if mod_lower in os.path.basename(tb).lower():
                primary_tb = tb
                break
        if not primary_tb and testbenches:
            primary_tb = testbenches[0]

        has_reusable = len(testbenches) > 0 or len(assertions) > 0

        return DVAssetInventory(
            target_module=module_name,
            dv_dirs=sorted(list(dv_dirs)),
            testbenches=sorted(testbenches),
            assertions=sorted(assertions),
            scoreboards=sorted(scoreboards),
            has_reusable_dv=has_reusable,
            primary_tb_path=primary_tb,
        )
