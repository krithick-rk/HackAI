"""
Provenance Traversal and Security Boundary Engine (Stage 5).
Performs deterministic backward traversal from candidate security sinks to upstream drivers.
Resolves cross-module instance boundaries, checks approved attacker/asset registries,
preserves instance identity, and tracks complete provenance chains with guarded path predicates.
"""

from __future__ import annotations
from typing import Dict, List, Optional, Any, Set, Tuple

from src.soc_analyzer.design_db.schemas import (
    DesignDB,
    ModuleDefinition,
    InstanceNode,
    GuardedEdge,
    AnalyzabilityLevel,
)
from src.soc_analyzer.registries.schemas import ApprovalStatus, AttackerEntry, AssetEntry
from src.soc_analyzer.candidates.schemas import CandidateClaim, SecurityCone
from .schemas import (
    ProvenanceNode,
    ProvenanceEdge,
    ProvenanceChain,
    SourceKind,
)
from .path_condition import (
    PathCondition,
    UnknownCondition,
    cond_true,
    cond_unknown,
)
from .guard_extractor import parse_guard_expression


class ProvenanceEngine:
    """
    Deterministic backward provenance traversal engine across DesignDB facts and registries.
    """

    def __init__(self, design_db: DesignDB, max_depth: int = 25):
        self.db = design_db
        self.max_depth = max_depth

    def build_provenance_chain(
        self,
        candidate: CandidateClaim,
        sink_signal: Optional[str] = None,
        instance_path: Optional[str] = None,
    ) -> ProvenanceChain:
        """
        Traverse backward from the security sink to identify all upstream drivers,
        intermediate guards, and root source classifications.
        """
        target_inst = instance_path if instance_path is not None else (candidate.instance_path or "")
        target_sink = sink_signal

        # Determine target sink if not provided
        if not target_sink:
            if candidate.security_cone and candidate.security_cone.root_signal:
                target_sink = candidate.security_cone.root_signal
            elif candidate.metadata.get("target_register"):
                target_sink = str(candidate.metadata["target_register"])
            elif candidate.metadata.get("target_signal"):
                target_sink = str(candidate.metadata["target_signal"])
            elif candidate.claim and ":" in candidate.claim:
                # E.g. "reg:CTRL_AUX_REGWEN"
                target_sink = candidate.claim.split(":")[-1].strip()
            else:
                target_sink = "security_sink"

        sink_node_id = self._make_node_id(target_inst, target_sink)

        nodes: Dict[str, ProvenanceNode] = {}
        edges: List[ProvenanceEdge] = []
        root_sources: List[str] = []
        visited: Set[str] = set()

        # Initialize sink node
        sink_node = self._create_provenance_node(target_inst, target_sink, security_role="sink")
        nodes[sink_node_id] = sink_node

        # Run backward traversal
        self._traverse_backward(
            curr_inst=target_inst,
            curr_sig=target_sink,
            nodes=nodes,
            edges=edges,
            root_sources=root_sources,
            visited=visited,
            depth=0,
            candidate=candidate,
        )

        # If no root sources were identified, mark sink as root
        if not root_sources:
            root_sources.append(sink_node_id)

        return ProvenanceChain(
            sink_node_id=sink_node_id,
            nodes=nodes,
            edges=edges,
            root_sources=sorted(list(set(root_sources))),
        )

    def _make_node_id(self, instance_path: str, signal_name: str) -> str:
        clean_inst = instance_path.strip(".")
        clean_sig = signal_name.strip()
        return f"{clean_inst}:{clean_sig}" if clean_inst else clean_sig

    def _create_provenance_node(
        self,
        instance_path: str,
        signal_name: str,
        security_role: Optional[str] = None,
    ) -> ProvenanceNode:
        node_id = self._make_node_id(instance_path, signal_name)

        # Lookup instance and definition
        inst_node = self.db.instances.get(instance_path)
        def_id = inst_node.module_name if inst_node else None
        module_def = self.db.definitions.get(def_id) if def_id else None

        direction = "internal"
        if module_def and signal_name in module_def.ports:
            direction = module_def.ports[signal_name].direction

        source_kind = SourceKind.UNKNOWN
        source_ref: Optional[str] = None
        role = security_role

        # 1. Check if constant tie-off
        const_lower = signal_name.strip().lower()
        if const_lower in ("1'b0", "0", "1'b1", "1", "'0", "'1", "ground", "tie_low", "tie_high"):
            source_kind = SourceKind.CONSTANT
            source_ref = f"const:{signal_name}"
            return ProvenanceNode(
                node_id=node_id,
                instance_path=instance_path,
                definition_id=def_id,
                signal_name=signal_name,
                direction=direction,
                source_kind=source_kind,
                source_reference=source_ref,
                security_role=role,
            )

        # 2. Check approved attacker registry mapping
        attacker_match = self._match_approved_attacker(instance_path, signal_name, direction)
        if attacker_match:
            source_kind = SourceKind.ATTACKER
            source_ref = f"attacker:{attacker_match.id}"
            role = role or "attacker_interface"
            return ProvenanceNode(
                node_id=node_id,
                instance_path=instance_path,
                definition_id=def_id,
                signal_name=signal_name,
                direction=direction,
                source_kind=source_kind,
                source_reference=source_ref,
                security_role=role,
            )

        # 3. Check approved asset registry mapping
        asset_match = self._match_approved_asset(instance_path, signal_name)
        if asset_match:
            source_kind = SourceKind.REGISTER
            source_ref = f"asset:{asset_match.id}"
            role = role or "asset"
            return ProvenanceNode(
                node_id=node_id,
                instance_path=instance_path,
                definition_id=def_id,
                signal_name=signal_name,
                direction=direction,
                source_kind=source_kind,
                source_reference=source_ref,
                security_role=role,
            )

        # 4. Check if registered sequential state
        if module_def:
            # Check if signal is in resets/clocks or marked as register
            for r in module_def.resets:
                if r.signal_name == signal_name:
                    source_kind = SourceKind.DOCUMENTED_INVARIANT
                    source_ref = f"reset:{r.signal_name}"
                    break

        return ProvenanceNode(
            node_id=node_id,
            instance_path=instance_path,
            definition_id=def_id,
            signal_name=signal_name,
            direction=direction,
            source_kind=source_kind,
            source_reference=source_ref,
            security_role=role,
        )

    def _match_approved_attacker(
        self,
        instance_path: str,
        signal_name: str,
        direction: str
    ) -> Optional[AttackerEntry]:
        """
        Check if signal represents an approved attacker interface (e.g. TL-UL bus or external pin).
        Only APPROVED, AUTHORITATIVE entries count.
        Never infer attacker control for internal signals or without approved registry anchor.
        """
        attackers = self.db.get_attackers(only_approved=True, only_enabled=True)
        sig_lower = signal_name.lower()
        inst_lower = instance_path.lower()

        for att in attackers:
            if not att.is_authoritative:
                continue

            b = att.boundary
            b_type = (b.boundary_type or "").upper()

            # PIN boundary match: must be top-level or external pin
            if b_type == "PIN" and (not instance_path or instance_path in ("top", "chip")):
                if direction in ("input", "inout") and ("pin" in sig_lower or "pad" in sig_lower or "io_" in sig_lower):
                    return att

            # BUS boundary match: bus write or request nets
            if b_type == "BUS":
                if any(x in sig_lower for x in ("tl_i", "tl_d", "bus_i", "bus_req", "wdata", "addr", "a_valid", "req")):
                    return att

            # DEBUG boundary: only if attacker has debug boundary explicitly approved
            if b_type in ("DEBUG", "JTAG"):
                if any(x in sig_lower for x in ("jtag", "dmi", "tck", "tms", "tdi")):
                    return att

        return None

    def _match_approved_asset(
        self,
        instance_path: str,
        signal_name: str
    ) -> Optional[AssetEntry]:
        """
        Check if signal matches an approved, authoritative asset entry in the registry.
        """
        assets = self.db.get_assets(only_approved=True, only_enabled=True)
        full_name = f"{instance_path}.{signal_name}" if instance_path else signal_name

        for asset in assets:
            if not asset.is_authoritative:
                continue
            if asset.name == full_name or asset.name == signal_name:
                return asset
            if asset.source_path and (asset.source_path == full_name or asset.source_path.endswith(f":{signal_name}")):
                return asset
        return None

    def _traverse_backward(
        self,
        curr_inst: str,
        curr_sig: str,
        nodes: Dict[str, ProvenanceNode],
        edges: List[ProvenanceEdge],
        root_sources: List[str],
        visited: Set[str],
        depth: int,
        candidate: CandidateClaim,
    ) -> None:
        curr_node_id = self._make_node_id(curr_inst, curr_sig)
        if curr_node_id in visited or depth >= self.max_depth:
            return
        visited.add(curr_node_id)

        curr_node = nodes.get(curr_node_id)
        if not curr_node:
            curr_node = self._create_provenance_node(curr_inst, curr_sig)
            nodes[curr_node_id] = curr_node

        # If this node is already a root source (ATTACKER, CONSTANT, or REGISTER asset), stop traversal
        if curr_node.source_kind in (SourceKind.ATTACKER, SourceKind.CONSTANT, SourceKind.DOCUMENTED_INVARIANT):
            root_sources.append(curr_node_id)
            return

        # Check analyzability of current module definition
        inst_node = self.db.instances.get(curr_inst)
        def_id = inst_node.module_name if inst_node else None
        assessment = self.db.analyzability.get(def_id) if def_id else None
        if assessment and assessment.level == AnalyzabilityLevel.HIGHLY_OBFUSCATED:
            curr_node.metadata["opaque"] = True
            curr_node.metadata["unknown_reason"] = "highly_obfuscated_module"
            root_sources.append(curr_node_id)
            return

        drivers_found = False

        # 1. Search connectivity graph in DesignDB for the current module definition
        if def_id and def_id in self.db.connectivity:
            graph = self.db.connectivity[def_id]
            for edge in graph.edges:
                if edge.target_signal == curr_sig:
                    drivers_found = True
                    src_sig = edge.source_signal
                    src_node_id = self._make_node_id(curr_inst, src_sig)

                    # Extract guard condition
                    pred: Optional[PathCondition] = None
                    if edge.guard_condition:
                        pred = parse_guard_expression(edge.guard_condition, curr_inst)
                    else:
                        pred = cond_true()

                    # Add source node
                    if src_node_id not in nodes:
                        nodes[src_node_id] = self._create_provenance_node(curr_inst, src_sig)

                    # Add edge
                    provenance_edge = ProvenanceEdge(
                        source_node_id=src_node_id,
                        destination_node_id=curr_node_id,
                        instance_context=curr_inst,
                        source_location=edge.location.to_dict() if edge.location else None,
                        predicate=pred.to_dict() if pred else None,
                        condition_source=edge.guard_condition,
                    )
                    edges.append(provenance_edge)

                    # Recurse
                    self._traverse_backward(
                        curr_inst=curr_inst,
                        curr_sig=src_sig,
                        nodes=nodes,
                        edges=edges,
                        root_sources=root_sources,
                        visited=visited,
                        depth=depth + 1,
                        candidate=candidate,
                    )

        # 2. Cross-module traversal:
        # If curr_sig is an input port of child instance, traverse up to parent instance
        if inst_node and inst_node.parent_path is not None and curr_node.direction == "input":
            parent_inst_node = self.db.instances.get(inst_node.parent_path)
            # Find what parent net drives this input port
            conn_net = inst_node.port_connections.get(curr_sig)
            if conn_net:
                drivers_found = True
                parent_node_id = self._make_node_id(inst_node.parent_path, conn_net)
                if parent_node_id not in nodes:
                    nodes[parent_node_id] = self._create_provenance_node(inst_node.parent_path, conn_net)

                edges.append(ProvenanceEdge(
                    source_node_id=parent_node_id,
                    destination_node_id=curr_node_id,
                    instance_context=inst_node.parent_path,
                    predicate=cond_true().to_dict(),
                    condition_source="port_binding",
                ))

                self._traverse_backward(
                    curr_inst=inst_node.parent_path,
                    curr_sig=conn_net,
                    nodes=nodes,
                    edges=edges,
                    root_sources=root_sources,
                    visited=visited,
                    depth=depth + 1,
                    candidate=candidate,
                )

        # 3. Fallback: Security cone edges attached to candidate claim
        if not drivers_found and candidate.security_cone and candidate.security_cone.edges:
            for c_edge in candidate.security_cone.edges:
                dst = c_edge.get("destination") or c_edge.get("target") or c_edge.get("to")
                src = c_edge.get("source") or c_edge.get("from")
                if dst == curr_sig and src:
                    drivers_found = True
                    src_node_id = self._make_node_id(curr_inst, src)
                    if src_node_id not in nodes:
                        nodes[src_node_id] = self._create_provenance_node(curr_inst, src)

                    cond_str = c_edge.get("predicate") or c_edge.get("guard")
                    pred = parse_guard_expression(cond_str, curr_inst) if cond_str else cond_true()

                    edges.append(ProvenanceEdge(
                        source_node_id=src_node_id,
                        destination_node_id=curr_node_id,
                        instance_context=curr_inst,
                        predicate=pred.to_dict() if pred else None,
                        condition_source=cond_str,
                    ))

                    self._traverse_backward(
                        curr_inst=curr_inst,
                        curr_sig=src,
                        nodes=nodes,
                        edges=edges,
                        root_sources=root_sources,
                        visited=visited,
                        depth=depth + 1,
                        candidate=candidate,
                    )

        # If no drivers found at all, curr_node is a root source (UNKNOWN or registered)
        if not drivers_found:
            root_sources.append(curr_node_id)
