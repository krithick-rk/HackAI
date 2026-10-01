"""
Slang Elaboration Integration for design_db.
Executes slang to elaborate the design AST and extracts deterministic design facts:
definitions, instances, ports, parameters, clocks, resets, and assignments.
"""

from __future__ import annotations
import os
import re
import json
import shutil
import tempfile
import subprocess
from typing import Dict, List, Optional, Tuple, Any, Set

from .schemas import (
    SourceLocation,
    ModuleDefinition,
    InstanceNode,
    PortFact,
    ParameterFact,
    ClockFact,
    ResetFact,
    GuardedEdge,
    ConnectivityGraph,
    AssignmentFact,
)
from .source_snapshot import SourceManager


class SlangElaborator:
    """
    Executes slang compiler to elaborate SystemVerilog AST with source coordinates.
    Extracts structural facts into typed design_db models.
    """

    def __init__(self, slang_binary: str = "slang", source_manager: Optional[SourceManager] = None):
        self.slang_binary = slang_binary
        self.source_manager = source_manager or SourceManager()

    def check_available(self) -> bool:
        return shutil.which(self.slang_binary) is not None

    def elaborate(
        self,
        source_files: List[str],
        include_dirs: Optional[List[str]] = None,
        defines: Optional[Dict[str, str]] = None,
        top_module: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Runs slang and generates the elaborated AST and diagnostics in JSON format.
        """
        if not self.check_available():
            return {
                "status": "TOOL_UNAVAILABLE",
                "diagnostics": [{"message": f"Slang binary '{self.slang_binary}' not found in PATH", "severity": "error"}],
                "ast": None,
                "raw_stdout": "",
                "raw_stderr": "",
            }

        include_dirs = include_dirs or []
        defines = defines or {}

        with tempfile.TemporaryDirectory() as tmp_dir:
            ast_path = os.path.join(tmp_dir, "ast.json")
            diag_path = os.path.join(tmp_dir, "diag.json")

            cmd = [
                self.slang_binary,
                "--ast-json", ast_path,
                "--ast-json-source-info",
                "--ast-json-detailed-types",
                "--diag-json", diag_path,
                "--allow-use-before-declare",
                "--error-limit", "0",
            ]

            for inc in include_dirs:
                if os.path.exists(inc):
                    cmd.extend(["-I", os.path.abspath(inc)])

            for k, v in defines.items():
                cmd.append(f"-D{k}={v}" if v else f"-D{k}")

            if top_module:
                cmd.extend(["--top", top_module])

            for sf in source_files:
                cmd.append(os.path.abspath(sf))

            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                stdout = proc.stdout
                stderr = proc.stderr
            except Exception as e:
                return {
                    "status": "ERROR",
                    "diagnostics": [{"message": str(e), "severity": "error"}],
                    "ast": None,
                    "raw_stdout": "",
                    "raw_stderr": str(e),
                }

            ast_data = None
            if os.path.exists(ast_path):
                try:
                    with open(ast_path, "r", encoding="utf-8") as f:
                        ast_data = json.load(f)
                except Exception:
                    pass

            diagnostics = []
            if os.path.exists(diag_path):
                try:
                    with open(diag_path, "r", encoding="utf-8") as f:
                        diagnostics = json.load(f)
                except Exception:
                    pass

            status = "SUCCESS" if proc.returncode == 0 else "FAILED"
            if status == "SUCCESS" and diagnostics:
                status = "WARNINGS"

            return {
                "status": status,
                "diagnostics": diagnostics,
                "ast": ast_data,
                "raw_stdout": stdout,
                "raw_stderr": stderr,
            }

    def parse_facts(
        self,
        ast_dict: Optional[Dict[str, Any]],
        source_files: List[str]
    ) -> Tuple[Dict[str, ModuleDefinition], Dict[str, InstanceNode], Dict[str, ConnectivityGraph]]:
        """
        Parses Slang AST into:
          - definitions: Dict[module_name, ModuleDefinition]
          - instances: Dict[instance_path, InstanceNode]
          - connectivity: Dict[module_name, ConnectivityGraph]
        """
        definitions: Dict[str, ModuleDefinition] = {}
        instances: Dict[str, InstanceNode] = {}
        connectivity: Dict[str, ConnectivityGraph] = {}

        # Capture snapshots for all source files
        for sf in source_files:
            if os.path.exists(sf):
                self.source_manager.capture_file(sf)

        if not ast_dict or "design" not in ast_dict:
            # Fallback to deterministic regex-based AST parser
            return self._fallback_deterministic_parse(source_files)

        root = ast_dict["design"]
        members = root.get("members", [])

        # Slang top-level design members
        for member in members:
            kind = member.get("kind")
            if kind == "Instance":
                self._process_instance_tree(
                    instance_ast=member,
                    parent_path="",
                    definitions=definitions,
                    instances=instances,
                    connectivity=connectivity,
                )

        # Ensure all captured source files have at least a fallback definition if slang didn't elaborate them as tops
        for sf in source_files:
            abs_sf = os.path.abspath(sf)
            snap = self.source_manager.get_snapshot(abs_sf)
            if not snap:
                continue
            # Check if any definition lives in this file
            file_defs = [d for d in definitions.values() if os.path.abspath(d.file_path) == abs_sf or (d.file_path and os.path.basename(d.file_path) == os.path.basename(abs_sf))]
            if not file_defs:
                fallback_defs, fallback_insts, fallback_conn = self._fallback_deterministic_parse([abs_sf])
                for fd_name, fd_val in fallback_defs.items():
                    if fd_name not in definitions:
                        definitions[fd_name] = fd_val
                for fi_name, fi_val in fallback_insts.items():
                    if fi_name not in instances:
                        instances[fi_name] = fi_val
                for fc_name, fc_val in fallback_conn.items():
                    if fc_name not in connectivity:
                        connectivity[fc_name] = fc_val

        return definitions, instances, connectivity

    def _process_instance_tree(
        self,
        instance_ast: Dict[str, Any],
        parent_path: str,
        definitions: Dict[str, ModuleDefinition],
        instances: Dict[str, InstanceNode],
        connectivity: Dict[str, ConnectivityGraph],
    ) -> str:
        inst_name = instance_ast.get("name", "")
        current_path = f"{parent_path}.{inst_name}" if parent_path else inst_name
        body = instance_ast.get("body", {})
        def_name = body.get("name", inst_name)

        # Definition file and location
        def_file = body.get("source_file") or instance_ast.get("source_file", "")
        def_line = body.get("source_line") or instance_ast.get("source_line", 1)
        def_col = body.get("source_column") or instance_ast.get("source_column", 1)
        def_loc = SourceLocation(file=def_file, line=def_line, column=def_col)
        src_file = def_file

        # Instance location
        inst_file = instance_ast.get("source_file") or def_file
        inst_line = instance_ast.get("source_line") or def_line
        inst_col = instance_ast.get("source_column") or def_col
        inst_loc = SourceLocation(file=inst_file, line=inst_line, column=inst_col)

        # Get or create source hash
        abs_src = os.path.abspath(def_file) if def_file else ""
        src_hash = ""
        if abs_src and os.path.exists(abs_src):
            snap = self.source_manager.get_snapshot(abs_src)
            if snap:
                src_hash = snap.source_hash

        # Extract members from instance body
        members = body.get("members", [])
        ports: Dict[str, PortFact] = {}
        parameters: Dict[str, Any] = {}
        clocks: List[ClockFact] = []
        resets: List[ResetFact] = []
        edges: List[GuardedEdge] = []
        nodes: Set[str] = set()
        sub_instances: List[str] = []
        assignments: List[AssignmentFact] = []
        combinational_defs: Dict[str, str] = {}

        # Parse ports, parameters, sub-instances, and procedural blocks
        for m in members:
            m_kind = m.get("kind")
            m_name = m.get("name", "")
            m_loc = SourceLocation(
                file=m.get("source_file", src_file),
                line=m.get("source_line", 1),
                column=m.get("source_column", 1),
            )

            if m_kind == "Port":
                p_dir = m.get("direction", "In").lower()
                dir_map = {"in": "input", "out": "output", "inout": "inout"}
                ports[m_name] = PortFact(
                    name=m_name,
                    direction=dir_map.get(p_dir, p_dir),
                    width=m.get("type", "logic"),
                    port_type=m.get("type", "logic"),
                    location=m_loc,
                )
                nodes.add(m_name)

            elif m_kind == "Parameter":
                parameters[m_name] = m.get("value", "")

            elif m_kind == "Instance":
                sub_path = self._process_instance_tree(
                    instance_ast=m,
                    parent_path=current_path,
                    definitions=definitions,
                    instances=instances,
                    connectivity=connectivity,
                )
                sub_instances.append(sub_path)

            elif m_kind == "ContinuousAssign":
                self._extract_continuous_assign(m, src_file, edges, nodes, assignments, combinational_defs, def_name)

            elif m_kind == "ProceduralBlock":
                self._extract_procedural_block(m, src_file, clocks, resets, edges, nodes, assignments, combinational_defs, def_name)

        # Port connections for this instance
        port_conns: Dict[str, str] = {}
        for conn in instance_ast.get("connections", []):
            p_obj = conn.get("port", {})
            p_name = p_obj.get("name")
            expr_obj = conn.get("expr", {})
            conn_sig = self._extract_signal_name_from_expr(expr_obj)
            if p_name and conn_sig:
                port_conns[p_name] = conn_sig

        # Register instance node
        inst_node = InstanceNode(
            instance_path=current_path,
            module_name=def_name,
            parent_path=parent_path if parent_path else None,
            children=sub_instances,
            parameter_overrides={},
            resolved_parameters=parameters,
            port_connections=port_conns,
            location=inst_loc,
        )
        instances[current_path] = inst_node

        # Register or update module definition
        if def_name not in definitions:
            definitions[def_name] = ModuleDefinition(
                name=def_name,
                file_path=def_file,
                source_hash=src_hash,
                location=def_loc,
                parameters=parameters,
                ports=ports,
                clocks=clocks,
                resets=resets,
                instantiated_modules=[instances[ch].module_name for ch in sub_instances if ch in instances],
                instances=[current_path],
                assignments=assignments,
                combinational_defs=combinational_defs,
            )
        else:
            if current_path not in definitions[def_name].instances:
                definitions[def_name].instances.append(current_path)
            definitions[def_name].assignments.extend(assignments)
            definitions[def_name].combinational_defs.update(combinational_defs)

        # Register connectivity graph
        if def_name not in connectivity:
            connectivity[def_name] = ConnectivityGraph(nodes=nodes, edges=edges)
        else:
            connectivity[def_name].nodes.update(nodes)
            connectivity[def_name].edges.extend(edges)

        return current_path

    def _extract_continuous_assign(
        self,
        assign_ast: Dict[str, Any],
        src_file: str,
        edges: List[GuardedEdge],
        nodes: Set[str],
        assignments: List[AssignmentFact],
        combinational_defs: Dict[str, str],
        def_name: str,
    ) -> None:
        assign_obj = assign_ast.get("assignment", {})
        lhs = self._extract_signal_name_from_expr(assign_obj.get("left"))
        rhs_str = self._stringify_expr(assign_obj.get("right"))
        rhs_signals = self._collect_signals_from_expr(assign_obj.get("right"))
        loc = SourceLocation(
            file=assign_ast.get("source_file", src_file),
            line=assign_ast.get("source_line", 1),
            column=assign_ast.get("source_column", 1),
        )
        if lhs:
            nodes.add(lhs)
            for rhs in rhs_signals:
                nodes.add(rhs)
                edges.append(GuardedEdge(
                    source_signal=rhs,
                    target_signal=lhs,
                    guard_condition=None,
                    guard_type="direct",
                    location=loc,
                ))
            if rhs_str:
                combinational_defs[lhs] = rhs_str
            assignments.append(AssignmentFact(
                target_signal=lhs,
                source_expr=rhs_str,
                rhs_signals=rhs_signals,
                path_condition="true",
                is_reset_branch=False,
                location=loc,
                block_kind="assign",
                ast_id=f"{def_name}_{lhs}_{loc.line}_{loc.column}",
            ))

    def _extract_procedural_block(
        self,
        pb_ast: Dict[str, Any],
        src_file: str,
        clocks: List[ClockFact],
        resets: List[ResetFact],
        edges: List[GuardedEdge],
        nodes: Set[str],
        assignments: List[AssignmentFact],
        combinational_defs: Dict[str, str],
        def_name: str,
    ) -> None:
        body = pb_ast.get("body", {})
        raw_kind = pb_ast.get("procedureKind", "AlwaysFF")
        proc_kind = "always_comb" if "comb" in raw_kind.lower() else ("always_latch" if "latch" in raw_kind.lower() else "always_ff")
        loc = SourceLocation(
            file=pb_ast.get("source_file", src_file),
            line=pb_ast.get("source_line", 1),
            column=pb_ast.get("source_column", 1),
        )

        # Inspect sensitivity list events if present (Timed / EventControl)
        def inspect_events(obj: Any):
            if not isinstance(obj, dict):
                return
            if obj.get("kind") == "SignalEvent":
                edge = obj.get("edge", "None").lower()
                sig = self._extract_signal_name_from_expr(obj.get("expr"))
                if sig:
                    nodes.add(sig)
                    if "rst" in sig.lower() or "reset" in sig.lower():
                        active_lvl = "low" if "neg" in edge or sig.lower().endswith(("_n", "_ni")) else "high"
                        resets.append(ResetFact(signal_name=sig, active_level=active_lvl, is_async=True, location=loc))
                    else:
                        clocks.append(ClockFact(signal_name=sig, edge="posedge" if "pos" in edge else "negedge", location=loc))
            for v in obj.values():
                if isinstance(v, dict):
                    inspect_events(v)
                elif isinstance(v, list):
                    for it in v:
                        inspect_events(it)

        inspect_events(body)

        # Walk procedural assignments and guards
        def walk_statements(stmt: Any, current_guard: Optional[str] = None, is_reset_branch: bool = False):
            if not isinstance(stmt, dict):
                return
            kind = stmt.get("kind")
            stmt_loc = SourceLocation(
                file=stmt.get("source_file_start", src_file),
                line=stmt.get("source_line_start", 1),
                column=stmt.get("source_column_start", 1),
            )

            if kind == "Conditional":
                cond_expr = self._stringify_condition(stmt.get("conditions", []))
                cond_sigs = self._collect_signals_from_conditions(stmt.get("conditions", []))
                is_reset_cond = False
                for rf in resets:
                    if rf.signal_name in cond_sigs:
                        if rf.active_level == "low":
                            if f"!{rf.signal_name}" in cond_expr or f"!({rf.signal_name})" in cond_expr or f"{rf.signal_name} == 0" in cond_expr:
                                is_reset_cond = True
                                break
                        else:
                            if rf.signal_name in cond_expr and f"!{rf.signal_name}" not in cond_expr:
                                is_reset_cond = True
                                break

                # True branch
                t_guard = f"({current_guard}) && ({cond_expr})" if current_guard else cond_expr
                t_reset = is_reset_branch or is_reset_cond
                walk_statements(stmt.get("ifTrue"), t_guard, t_reset)
                # False branch
                if stmt.get("ifFalse"):
                    f_guard = f"({current_guard}) && !({cond_expr})" if current_guard else f"!({cond_expr})"
                    walk_statements(stmt.get("ifFalse"), f_guard, False)

            elif kind == "Assignment":
                lhs = self._extract_signal_name_from_expr(stmt.get("left"))
                rhs_str = self._stringify_expr(stmt.get("right"))
                rhs_signals = self._collect_signals_from_expr(stmt.get("right"))
                if lhs:
                    nodes.add(lhs)
                    for rhs in rhs_signals:
                        nodes.add(rhs)
                        edges.append(GuardedEdge(
                            source_signal=rhs,
                            target_signal=lhs,
                            guard_condition=current_guard,
                            guard_type="if" if current_guard else "direct",
                            location=stmt_loc,
                        ))
                    ast_id = f"{def_name}_{lhs}_{stmt_loc.line}_{stmt_loc.column}"
                    assignments.append(AssignmentFact(
                        target_signal=lhs,
                        source_expr=rhs_str,
                        rhs_signals=rhs_signals,
                        path_condition=current_guard or "true",
                        is_reset_branch=is_reset_branch,
                        location=stmt_loc,
                        block_kind=proc_kind,
                        ast_id=ast_id,
                    ))
                    if proc_kind == "always_comb" and not current_guard and rhs_str:
                        combinational_defs[lhs] = rhs_str

            # Recurse children
            for k, v in stmt.items():
                if k not in ("conditions", "ifTrue", "ifFalse", "left", "right"):
                    if isinstance(v, dict):
                        walk_statements(v, current_guard, is_reset_branch)
                    elif isinstance(v, list):
                        for el in v:
                            walk_statements(el, current_guard, is_reset_branch)

        walk_statements(body)

    def _extract_signal_name_from_expr(self, expr_obj: Any) -> Optional[str]:
        if not isinstance(expr_obj, dict):
            return None
        kind = expr_obj.get("kind")
        if kind == "NamedValue":
            sym = expr_obj.get("symbol", "")
            parts = sym.split()
            return parts[-1] if parts else None
        elif kind == "Conversion":
            return self._extract_signal_name_from_expr(expr_obj.get("operand"))
        elif kind == "Assignment":
            return self._extract_signal_name_from_expr(expr_obj.get("left"))
        elif kind == "ElementSelect":
            return self._extract_signal_name_from_expr(expr_obj.get("value"))
        elif kind == "RangeSelect":
            return self._extract_signal_name_from_expr(expr_obj.get("value"))
        return None

    def _collect_signals_from_expr(self, expr_obj: Any) -> List[str]:
        signals = []
        if not isinstance(expr_obj, dict):
            return signals
        kind = expr_obj.get("kind")
        if kind == "NamedValue":
            sig = self._extract_signal_name_from_expr(expr_obj)
            if sig:
                signals.append(sig)
        for v in expr_obj.values():
            if isinstance(v, dict):
                signals.extend(self._collect_signals_from_expr(v))
            elif isinstance(v, list):
                for item in v:
                    signals.extend(self._collect_signals_from_expr(item))
        return list(set(signals))

    def _collect_signals_from_conditions(self, conditions: List[Dict[str, Any]]) -> List[str]:
        sigs = []
        for c in conditions:
            sigs.extend(self._collect_signals_from_expr(c.get("expr", {})))
        return list(set(sigs))

    def _stringify_expr(self, expr_obj: Any) -> str:
        if not isinstance(expr_obj, dict):
            return ""
        kind = expr_obj.get("kind")
        if kind == "NamedValue":
            sig = self._extract_signal_name_from_expr(expr_obj)
            return sig or ""
        elif kind == "IntegerLiteral":
            val = expr_obj.get("value")
            return str(val) if val is not None else ""
        elif kind == "Conversion":
            return self._stringify_expr(expr_obj.get("operand"))
        elif kind == "UnaryOp":
            op = expr_obj.get("op")
            op_sym = "!" if op == "LogicalNot" else ("~" if op == "BitwiseNot" else "")
            inner = self._stringify_expr(expr_obj.get("operand"))
            return f"{op_sym}({inner})" if op_sym else inner
        elif kind == "BinaryOp":
            op = expr_obj.get("op", "")
            op_map = {
                "LogicalAnd": "&&",
                "LogicalOr": "||",
                "BitwiseAnd": "&",
                "BitwiseOr": "|",
                "BitwiseXor": "^",
                "Equality": "==",
                "Inequality": "!=",
                "CaseEquality": "===",
                "CaseInequality": "!==",
                "LessThan": "<",
                "LessThanEqual": "<=",
                "GreaterThan": ">",
                "GreaterThanEqual": ">=",
            }
            op_str = op_map.get(op, "==")
            l_str = self._stringify_expr(expr_obj.get("left"))
            r_str = self._stringify_expr(expr_obj.get("right"))
            if l_str and r_str:
                return f"({l_str} {op_str} {r_str})"
            return l_str or r_str or ""
        elif kind == "Assignment":
            return self._stringify_expr(expr_obj.get("left"))
        elif kind == "ElementSelect":
            val_s = self._stringify_expr(expr_obj.get("value"))
            sel_s = self._stringify_expr(expr_obj.get("selector"))
            return f"{val_s}[{sel_s}]" if val_s else ""
        elif kind == "RangeSelect":
            val_s = self._stringify_expr(expr_obj.get("value"))
            l_s = self._stringify_expr(expr_obj.get("left"))
            r_s = self._stringify_expr(expr_obj.get("right"))
            return f"{val_s}[{l_s}:{r_s}]" if val_s else ""
        return ""

    def _stringify_condition(self, conditions: List[Dict[str, Any]]) -> str:
        if not conditions:
            return "true"
        cond_strs = []
        for c in conditions:
            expr = c.get("expr", {})
            s = self._stringify_expr(expr)
            cond_strs.append(s if s else "cond")
        return " && ".join(cond_strs)

    def _fallback_deterministic_parse(
        self,
        source_files: List[str]
    ) -> Tuple[Dict[str, ModuleDefinition], Dict[str, InstanceNode], Dict[str, ConnectivityGraph]]:
        """
        Pure Python regex-based parser used when Slang is unavailable or when
        an unelaborated file needs baseline structural extraction.
        """
        definitions: Dict[str, ModuleDefinition] = {}
        instances: Dict[str, InstanceNode] = {}
        connectivity: Dict[str, ConnectivityGraph] = {}

        for sf in source_files:
            abs_sf = os.path.abspath(sf)
            if not os.path.exists(abs_sf):
                continue

            snap = self.source_manager.capture_file(abs_sf)
            with open(abs_sf, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()

            # Find module declarations
            mod_pattern = re.compile(
                r"\bmodule\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:#\s*\((.*?)\))?\s*\((.*?)\);(.*?)endmodule",
                re.DOTALL
            )

            for match in mod_pattern.finditer(content):
                mod_name = match.group(1)
                params_str = match.group(2) or ""
                ports_str = match.group(3) or ""
                body_str = match.group(4) or ""

                start_char = match.start(1)
                line_num, col_num = self.source_manager.get_line_location_by_char_offset(abs_sf, start_char)
                loc = SourceLocation(file=abs_sf, line=line_num, column=col_num)

                # Extract parameters
                params = {}
                for p_match in re.finditer(r"\bparameter\s+(?:[a-zA-Z_][a-zA-Z0-9_]*\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^,;)]+)", params_str):
                    params[p_match.group(1)] = p_match.group(2).strip()

                # Extract ports
                ports = {}
                nodes = set()
                for port_match in re.finditer(r"\b(input|output|inout)\s+(?:reg|wire|logic)?\s*(?:\[[^\]]+\])?\s*([a-zA-Z_][a-zA-Z0-9_]*)", ports_str):
                    p_dir = port_match.group(1)
                    p_name = port_match.group(2)
                    ports[p_name] = PortFact(name=p_name, direction=p_dir, location=loc)
                    nodes.add(p_name)

                # Extract clocks and resets
                clocks = []
                resets = []
                for clk_match in re.finditer(r"@\s*\(\s*(posedge|negedge)\s+([a-zA-Z_][a-zA-Z0-9_]*)", body_str):
                    edge = clk_match.group(1)
                    sig = clk_match.group(2)
                    nodes.add(sig)
                    if "rst" in sig.lower() or "reset" in sig.lower():
                        resets.append(ResetFact(signal_name=sig, active_level="low" if "neg" in edge or sig.endswith(("_n", "_ni")) else "high", location=loc))
                    else:
                        clocks.append(ClockFact(signal_name=sig, edge=edge, location=loc))

                # Extract assignments
                edges = []
                assignments: List[AssignmentFact] = []
                combinational_defs: Dict[str, str] = {}
                for assign_match in re.finditer(r"\bassign\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([^;]+);", body_str):
                    lhs = assign_match.group(1)
                    rhs_expr = assign_match.group(2).strip()
                    nodes.add(lhs)
                    rhs_tokens = re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", rhs_expr)
                    for rhs_token in rhs_tokens:
                        if rhs_token in nodes:
                            edges.append(GuardedEdge(source_signal=rhs_token, target_signal=lhs, guard_type="direct", location=loc))
                    combinational_defs[lhs] = rhs_expr
                    assignments.append(AssignmentFact(
                        target_signal=lhs,
                        source_expr=rhs_expr,
                        rhs_signals=[t for t in rhs_tokens if t in nodes or t in ports],
                        path_condition="true",
                        is_reset_branch=False,
                        location=loc,
                        block_kind="assign",
                        ast_id=f"{mod_name}_{lhs}_{line_num}",
                    ))

                # Procedural if/else if assignments in fallback
                if_blocks = re.findall(r"if\s*\((.*?)\)\s*(?:begin\s*)?([a-zA-Z_][a-zA-Z0-9_]*)\s*<=\s*([^;]+);(?:\s*end)?", body_str, re.DOTALL)
                for cond_text, lhs_text, rhs_text in if_blocks:
                    cond_clean = cond_text.strip()
                    lhs_clean = lhs_text.strip()
                    rhs_clean = rhs_text.strip()
                    is_rst = any(rf.signal_name in cond_clean for rf in resets)
                    rhs_sigs = [t for t in re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", rhs_clean) if t in nodes or t in ports]
                    assignments.append(AssignmentFact(
                        target_signal=lhs_clean,
                        source_expr=rhs_clean,
                        rhs_signals=rhs_sigs,
                        path_condition=cond_clean,
                        is_reset_branch=is_rst,
                        location=loc,
                        block_kind="always_ff",
                        ast_id=f"{mod_name}_{lhs_clean}_{line_num}",
                    ))
                elif_blocks = re.findall(r"else\s+if\s*\((.*?)\)\s*(?:begin\s*)?([a-zA-Z_][a-zA-Z0-9_]*)\s*<=\s*([^;]+);(?:\s*end)?", body_str, re.DOTALL)
                for cond_text, lhs_text, rhs_text in elif_blocks:
                    cond_clean = cond_text.strip()
                    lhs_clean = lhs_text.strip()
                    rhs_clean = rhs_text.strip()
                    rst_prefix = ""
                    if resets:
                        r0 = resets[0].signal_name
                        rst_prefix = f"(!(!{r0})) && " if resets[0].active_level == "low" else f"(!{r0}) && "
                    full_cond = f"{rst_prefix}({cond_clean})"
                    rhs_sigs = [t for t in re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", rhs_clean) if t in nodes or t in ports]
                    assignments.append(AssignmentFact(
                        target_signal=lhs_clean,
                        source_expr=rhs_clean,
                        rhs_signals=rhs_sigs,
                        path_condition=full_cond,
                        is_reset_branch=False,
                        location=loc,
                        block_kind="always_ff",
                        ast_id=f"{mod_name}_{lhs_clean}_{line_num}",
                    ))

                # Extract child instantiations
                inst_pattern = re.compile(
                    r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s+(?:#\s*\(.*?\)\s*)?([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",
                    re.DOTALL
                )
                inst_modules = []
                sub_inst_names = []
                for im in inst_pattern.finditer(body_str):
                    target_mod = im.group(1)
                    inst_ident = im.group(2)
                    if target_mod not in ("always", "always_ff", "always_comb", "initial", "assign", "if", "for", "case"):
                        inst_modules.append(target_mod)
                        sub_path = f"{mod_name}.{inst_ident}"
                        sub_inst_names.append(sub_path)
                        instances[sub_path] = InstanceNode(
                            instance_path=sub_path,
                            module_name=target_mod,
                            parent_path=mod_name,
                            location=loc,
                        )

                # Register top definition
                definitions[mod_name] = ModuleDefinition(
                    name=mod_name,
                    file_path=abs_sf,
                    source_hash=snap.source_hash,
                    location=loc,
                    parameters=params,
                    ports=ports,
                    clocks=clocks,
                    resets=resets,
                    instantiated_modules=inst_modules,
                    instances=[mod_name],
                    assignments=assignments,
                    combinational_defs=combinational_defs,
                )

                instances[mod_name] = InstanceNode(
                    instance_path=mod_name,
                    module_name=mod_name,
                    children=sub_inst_names,
                    location=loc,
                )

                connectivity[mod_name] = ConnectivityGraph(nodes=nodes, edges=edges)

        return definitions, instances, connectivity
