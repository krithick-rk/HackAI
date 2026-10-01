"""
Shipped configuration discovery and representation for design_db.
Enables project-specific top configurations (e.g. Earl Grey ASIC, Darjeeling, etc.)
to be enumerated externally rather than hardcoded.
"""

from __future__ import annotations
import os
import json
from typing import Dict, List, Optional, Any
from .schemas import ShippedConfig


class ShippedConfigDiscovery:
    """
    Discovers and manages shipped configurations for a target hardware repository.
    Configurations are externalized and can be loaded from JSON/YAML or auto-discovered.
    """

    def __init__(self, project_root: Optional[str] = None):
        self.project_root = os.path.abspath(project_root) if project_root else os.getcwd()
        self._configs: Dict[str, ShippedConfig] = {}

    def add_config(self, config: ShippedConfig) -> None:
        self._configs[config.config_name] = config

    def load_from_dict(self, data: Dict[str, Any]) -> None:
        """Loads configurations from a dictionary structure."""
        configs_data = data.get("configurations", data)
        for name, spec in configs_data.items():
            if isinstance(spec, dict):
                cfg = ShippedConfig(
                    config_name=name,
                    top_module=spec.get("top_module", name),
                    source_files=[os.path.abspath(f) if not os.path.isabs(f) else f for f in spec.get("source_files", [])],
                    include_dirs=[os.path.abspath(d) if not os.path.isabs(d) else d for d in spec.get("include_dirs", [])],
                    defines=spec.get("defines", {}),
                    description=spec.get("description", ""),
                )
                self.add_config(cfg)

    def load_from_file(self, config_path: str) -> None:
        """Loads configuration from a JSON file."""
        abs_path = os.path.abspath(config_path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"Configuration file not found: {abs_path}")
        with open(abs_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.load_from_dict(data)

    def discover_default_config(self, top_module: str, source_files: List[str], include_dirs: Optional[List[str]] = None) -> ShippedConfig:
        """Creates and registers a default single-top configuration."""
        cfg = ShippedConfig(
            config_name="default",
            top_module=top_module,
            source_files=[os.path.abspath(f) for f in source_files],
            include_dirs=[os.path.abspath(d) for d in (include_dirs or [])],
            defines={},
            description="Default single-top configuration",
        )
        self.add_config(cfg)
        return cfg

    @property
    def configs(self) -> Dict[str, ShippedConfig]:
        return dict(self._configs)

    def get_config(self, name: str) -> Optional[ShippedConfig]:
        return self._configs.get(name)
