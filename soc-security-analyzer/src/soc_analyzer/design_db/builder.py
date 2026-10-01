"""
DesignDB Builder.
Orchestrates source snapshots, Slang elaboration, fact extraction,
connectivity graphing, and analyzability assessment into a validated DesignDB.
"""

from __future__ import annotations
import os
from typing import Dict, List, Optional, Any

from .schemas import DesignDB, ShippedConfig
from .source_snapshot import SourceManager
from .config_discovery import ShippedConfigDiscovery
from .slang_elaborator import SlangElaborator
from .analyzability import AnalyzabilityClassifier


class DesignDBBuilder:
    """
    Constructs a deterministic DesignDB from source files or a ShippedConfig.
    """

    def __init__(
        self,
        slang_binary: str = "slang",
        analyzability_config: Optional[Dict[str, Any]] = None,
    ):
        self.source_manager = SourceManager()
        self.elaborator = SlangElaborator(slang_binary=slang_binary, source_manager=self.source_manager)
        self.classifier = AnalyzabilityClassifier(config=analyzability_config)
        self.config_discovery = ShippedConfigDiscovery()

    def build_from_config(self, config: ShippedConfig, design_name: str = "design") -> DesignDB:
        """Builds DesignDB for a specific ShippedConfig."""
        # 1. Capture source snapshots
        for sf in config.source_files:
            if os.path.exists(sf):
                self.source_manager.capture_file(sf)

        # 2. Elaborate with Slang
        elaboration_res = self.elaborator.elaborate(
            source_files=config.source_files,
            include_dirs=config.include_dirs,
            defines=config.defines,
            top_module=config.top_module,
        )

        # 3. Parse AST facts
        definitions, instances, connectivity = self.elaborator.parse_facts(
            ast_dict=elaboration_res.get("ast"),
            source_files=config.source_files,
        )

        # 4. Assess Analyzability per definition
        analyzability = {}
        elab_status = elaboration_res.get("status", "SUCCESS")
        for def_name, def_obj in definitions.items():
            mod_insts = [instances[ip] for ip in def_obj.instances if ip in instances]
            unresolved = 0
            for child_name in def_obj.instantiated_modules:
                if child_name not in definitions:
                    unresolved += 1
            assessment = self.classifier.assess_module(
                module_def=def_obj,
                instances=mod_insts,
                elaboration_status=elab_status,
                unresolved_instances=unresolved,
            )
            analyzability[def_name] = assessment

        # 5. Build final DesignDB
        shipped_configs = {config.config_name: config}
        db = DesignDB(
            design_name=design_name,
            shipped_configs=shipped_configs,
            active_config=config.config_name,
            source_snapshots=self.source_manager.snapshots,
            definitions=definitions,
            instances=instances,
            connectivity=connectivity,
            analyzability=analyzability,
        )
        return db

    def build_from_files(
        self,
        source_files: List[str],
        top_module: Optional[str] = None,
        include_dirs: Optional[List[str]] = None,
        design_name: str = "design",
        config_name: str = "default",
    ) -> DesignDB:
        """Convenience method to build DesignDB directly from a list of files."""
        # If top_module not provided, use basename of first file or deduce from filename
        if not top_module and source_files:
            base = os.path.basename(source_files[0])
            top_module = os.path.splitext(base)[0]

        cfg = self.config_discovery.discover_default_config(
            top_module=top_module or "top",
            source_files=source_files,
            include_dirs=include_dirs,
        )
        cfg.config_name = config_name
        return self.build_from_config(cfg, design_name=design_name)
