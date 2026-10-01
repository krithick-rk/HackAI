"""
Centralized Configuration and Exit Code Definitions (Stage 9).
Defines deterministic CLI exit codes, scan options, and configuration validation.
"""

from __future__ import annotations
import os
import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
import yaml

# Centralized Deterministic Exit Codes
EXIT_SUCCESS = 0             # Scan/command completed successfully, no blocking issues
EXIT_FATAL_ERROR = 1         # Fatal execution or configuration error
EXIT_PARTIAL_ANALYSIS = 2    # Partial or incomplete analysis (e.g., unsupported top, missing tool)
EXIT_FINDINGS_PRESENT = 3     # Actionable security findings present (when requested)
EXIT_BENCHMARK_FAILURE = 4   # Benchmark regression or failure detected

EXIT_CODE_DESCRIPTIONS = {
    EXIT_SUCCESS: "Scan completed successfully",
    EXIT_FATAL_ERROR: "Fatal execution or configuration error",
    EXIT_PARTIAL_ANALYSIS: "Partial or incomplete analysis",
    EXIT_FINDINGS_PRESENT: "Security findings detected",
    EXIT_BENCHMARK_FAILURE: "Benchmark regression or failure detected",
}


@dataclass
class AnalyzerConfig:
    """
    Top-level configuration model for the SoC Security Analyzer pipeline.
    """
    repository: str
    config_name: str = "default"
    top_module: Optional[str] = None
    module: Optional[str] = None
    output_dir: str = "reports"
    budget: float = 0.0
    mode: str = "fast"  # "fast" | "deep"
    backend: str = "agy"
    no_ai: bool = True
    no_dynamic: bool = False
    verbose: bool = False
    registry_dir: Optional[str] = None
    exit_on_findings: bool = False
    extra_options: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> List[str]:
        """Validates configuration parameters, returning list of errors."""
        errors = []
        if not self.repository:
            errors.append("Repository path must be specified")
        elif not os.path.exists(self.repository):
            errors.append(f"Repository path does not exist: {self.repository}")

        if self.mode not in ("fast", "deep"):
            errors.append(f"Unknown mode '{self.mode}'; choose 'fast' or 'deep'")

        if self.budget < 0.0:
            errors.append("Budget cannot be negative")

        return errors

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AnalyzerConfig:
        return cls(
            repository=data.get("repository", ""),
            config_name=data.get("config_name", "default"),
            top_module=data.get("top_module"),
            module=data.get("module"),
            output_dir=data.get("output_dir", "reports"),
            budget=float(data.get("budget", 0.0)),
            mode=data.get("mode", "fast"),
            backend=data.get("backend", "agy"),
            no_ai=bool(data.get("no_ai", True)),
            no_dynamic=bool(data.get("no_dynamic", False)),
            verbose=bool(data.get("verbose", False)),
            registry_dir=data.get("registry_dir"),
            exit_on_findings=bool(data.get("exit_on_findings", False)),
            extra_options=data.get("extra_options", {}),
        )

    @classmethod
    def from_file(cls, file_path: str) -> AnalyzerConfig:
        """Loads configuration from a YAML or JSON file."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Configuration file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        if file_path.endswith(".json"):
            data = json.loads(content)
        else:
            data = yaml.safe_load(content) or {}

        return cls.from_dict(data)
