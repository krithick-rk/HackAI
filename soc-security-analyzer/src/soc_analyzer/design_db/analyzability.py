"""
Deterministic Analyzability Assessment for design_db.
Evaluates RTL modules and security cones for NORMAL, DEGRADED, or HIGHLY_OBFUSCATED status.
Thresholds are externalized in configuration rather than hardcoded logic.
"""

from __future__ import annotations
import re
import math
from typing import Dict, List, Optional, Any
from .schemas import AnalyzabilityLevel, AnalyzabilityAssessment, ModuleDefinition, InstanceNode


DEFAULT_ANALYZABILITY_CONFIG = {
    "min_informativeness_ratio": 0.40,
    "max_black_box_ratio": 0.25,
    "degraded_score_threshold": 0.70,
    "obfuscated_score_threshold": 0.45,
    "weights": {
        "elaboration": 0.35,
        "identifier_informativeness": 0.35,
        "hierarchy_preservation": 0.15,
        "black_box_freedom": 0.15,
    }
}


class AnalyzabilityClassifier:
    """
    Computes deterministic analyzability metrics and classifies modules
    into NORMAL, DEGRADED, or HIGHLY_OBFUSCATED.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = dict(DEFAULT_ANALYZABILITY_CONFIG)
        if config:
            self.config.update(config)

    def assess_module(
        self,
        module_def: ModuleDefinition,
        instances: List[InstanceNode],
        elaboration_status: str = "SUCCESS",
        unresolved_instances: int = 0
    ) -> AnalyzabilityAssessment:
        """
        Assesses a single module definition and its instances.
        """
        metrics: Dict[str, float] = {}
        details: List[str] = []

        # 1. Elaboration Metric
        if elaboration_status == "SUCCESS":
            elaboration_score = 1.0
        elif elaboration_status == "WARNINGS":
            elaboration_score = 0.75
            details.append("Elaboration succeeded with warnings")
        elif elaboration_status == "TOOL_UNAVAILABLE":
            elaboration_score = 0.60
            details.append("Slang compiler was unavailable; assessed using fallback AST parser")
        else:
            elaboration_score = 0.20
            details.append("Elaboration errors detected")
        metrics["elaboration_score"] = elaboration_score

        # 2. Identifier Informativeness Metric
        ident_ratio = self._calculate_identifier_informativeness(module_def)
        metrics["identifier_informativeness"] = ident_ratio
        if ident_ratio < self.config["min_informativeness_ratio"]:
            details.append(f"Low identifier informativeness ({ident_ratio:.2f} < {self.config['min_informativeness_ratio']:.2f})")

        # 3. Hierarchy Preservation Metric
        total_subinsts = len(module_def.instantiated_modules)
        # Ratio indicates whether hierarchy was preserved or if it was entirely flattened
        flattening_score = 1.0 if total_subinsts > 0 or len(module_def.ports) <= 8 else 0.8
        metrics["hierarchy_preservation"] = flattening_score

        # 4. Black Box / Opacity Metric
        if total_subinsts > 0:
            black_box_ratio = unresolved_instances / total_subinsts
        else:
            black_box_ratio = 0.0
        black_box_freedom = max(0.0, 1.0 - black_box_ratio)
        metrics["black_box_freedom"] = black_box_freedom
        if black_box_ratio > self.config["max_black_box_ratio"]:
            details.append(f"High black-box/opaque ratio ({black_box_ratio:.2f})")

        # Compute weighted overall score
        w = self.config["weights"]
        overall_score = (
            w.get("elaboration", 0.35) * elaboration_score +
            w.get("identifier_informativeness", 0.35) * ident_ratio +
            w.get("hierarchy_preservation", 0.15) * flattening_score +
            w.get("black_box_freedom", 0.15) * black_box_freedom
        )

        # Classify based on thresholds
        if overall_score < self.config["obfuscated_score_threshold"]:
            level = AnalyzabilityLevel.HIGHLY_OBFUSCATED
            details.append(f"Classified as HIGHLY_OBFUSCATED (score {overall_score:.2f} < {self.config['obfuscated_score_threshold']:.2f})")
        elif overall_score < self.config["degraded_score_threshold"]:
            level = AnalyzabilityLevel.DEGRADED
            details.append(f"Classified as DEGRADED (score {overall_score:.2f} < {self.config['degraded_score_threshold']:.2f})")
        else:
            level = AnalyzabilityLevel.NORMAL
            details.append(f"Classified as NORMAL (score {overall_score:.2f})")

        return AnalyzabilityAssessment(
            level=level,
            overall_score=overall_score,
            metrics=metrics,
            details=details,
        )

    def _calculate_identifier_informativeness(self, module_def: ModuleDefinition) -> float:
        """
        Analyzes names of ports, parameters, and signals.
        Returns the proportion of informative names vs obfuscated/minified names.
        """
        names = list(module_def.ports.keys()) + list(module_def.parameters.keys())
        if not names:
            return 1.0

        informative_count = 0
        minified_pattern = re.compile(r"^(?:[a-zA-Z]|_[0-9]+_|x[0-9a-fA-F]+|[0-9a-fA-F]{6,})$")

        for name in names:
            if len(name) <= 2:
                # Single or double character name (e.g. 'a', 'd', 'q')
                continue
            if minified_pattern.match(name):
                # Minified or synthetic tool name
                continue
            # Check for vowel or common hardware abbreviation
            has_word_structure = any(c in "aeiouAEIOU_" for c in name) or any(
                hw in name.lower() for hw in ["clk", "rst", "ack", "req", "val", "cmd", "addr", "data", "en", "cfg"]
            )
            if has_word_structure:
                informative_count += 1

        return informative_count / len(names)
