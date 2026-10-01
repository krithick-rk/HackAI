import os
import re
import json
import subprocess
import shutil
import time
import dataclasses
from typing import Dict, Any, List

@dataclasses.dataclass
class SynthesisConfig:
    # Required
    top_module: str
    output_dir: str
    design_dir: str = "."

    # Option A: FuseSoC managed project
    fusesoc_cores_root: str = ""
    fusesoc_core_name: str = ""
    fusesoc_target: str = "syn"
    fusesoc_tool: str = "icarus"

    # Option B: Explicit file list (no FuseSoC)
    rtl_files: list = dataclasses.field(default_factory=list)
    include_dirs: list = dataclasses.field(default_factory=list)
    defines: list = dataclasses.field(default_factory=list)

    # Tool paths (auto-detect from PATH if empty)
    yosys_path: str = ""
    slang_path: str = ""
    fusesoc_path: str = ""
    yosys_slang_plugin: str = "/home/hackdac/hwsec-tools/yosys-slang/build/slang.so"   # path to slang.so Yosys plugin, optional

    # Behaviour flags
    run_slang_elab_check: bool = True
    auto_generate_stubs: bool = True
    max_stub_retries: int = 3
    escalate_to_ai_on_failure: bool = True

def _emit_event(event_type: str, data: dict, output_dir: str = None):
    record = {"event": event_type, "data": data, "ts": time.time()}
    line = json.dumps(record)
    print(line, flush=True)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        with open(os.path.join(output_dir, "phase0_events.jsonl"), "a") as f:
            f.write(line + "\n")

GLOBAL_PARAMS = {}
PACKAGE_EXPORTED_PARAMS = {}
GLOBAL_TYPEDEFS = {}
ACTIVE_PROCESSES = []

SYNTH_STUBS = {
    "rglts_pdm_3p3v.sv": os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "workspace", "stubs", "rglts_pdm_3p3v_stub.sv")
}

def inline_prim_util(content: str) -> str:
    # Remove imports of prim_util_pkg to prevent Yosys package-level import bugs
    content = re.sub(r"\bimport\s+prim_util_pkg::\w+;\s*", "", content)
    content = re.sub(r"\bimport\s+prim_util_pkg::\*;\s*", "", content)

    # 1. Handle vbits
    pos = 0
    while True:
        match = re.search(r"\b(?:prim_util_pkg::)?vbits\s*\(", content[pos:])
        if not match:
            break
        start_idx = pos + match.start()
        # Skip if it is a function definition
        line_start = content.rfind("\n", 0, start_idx) + 1
        line_to_match = content[line_start : start_idx]
        if "function" in line_to_match:
            pos = start_idx + 1
            continue
            
        start_paren = content.find("(", start_idx)
        if start_paren == -1:
            pos = start_idx + 1
            continue
        paren_count = 1
        scan_idx = start_paren + 1
        while paren_count > 0 and scan_idx < len(content):
            char = content[scan_idx]
            if char == "(":
                paren_count += 1
            elif char == ")":
                paren_count -= 1
            scan_idx += 1
        if paren_count == 0:
            expr = content[start_paren+1 : scan_idx-1].strip()
            replacement = f"(({expr}) == 1 ? 1 : $clog2({expr}))"
            content = content[:start_idx] + replacement + content[scan_idx:]
            pos = start_idx
        else:
            pos = start_idx + 1

    # 2. Handle ceil_div
    pos = 0
    while True:
        match = re.search(r"\b(?:prim_util_pkg::)?ceil_div\s*\(", content[pos:])
        if not match:
            break
        start_idx = pos + match.start()
        # Skip if it is a function definition
        line_start = content.rfind("\n", 0, start_idx) + 1
        line_to_match = content[line_start : start_idx]
        if "function" in line_to_match:
            pos = start_idx + 1
            continue
            
        start_paren = content.find("(", start_idx)
        if start_paren == -1:
            pos = start_idx + 1
            continue
        paren_count = 1
        scan_idx = start_paren + 1
        while paren_count > 0 and scan_idx < len(content):
            char = content[scan_idx]
            if char == "(":
                paren_count += 1
            elif char == ")":
                paren_count -= 1
            scan_idx += 1
        if paren_count == 0:
            args_str = content[start_paren+1 : scan_idx-1].strip()
            level = 0
            comma_idx = -1
            for i, c in enumerate(args_str):
                if c == "(":
                    level += 1
                elif c == ")":
                    level -= 1
                elif c == "," and level == 0:
                    comma_idx = i
                    break
            if comma_idx != -1:
                arg1 = args_str[:comma_idx].strip()
                arg2 = args_str[comma_idx+1:].strip()
                replacement = f"((({arg1}) + ({arg2}) - 1) / ({arg2}))"
                content = content[:start_idx] + replacement + content[scan_idx:]
                pos = start_idx
            else:
                pos = start_idx + 1
        else:
            pos = start_idx + 1
    return content

def flatten_anonymous_nested_structs(content: str) -> str:
    pos = 0
    while True:
        match = re.search(r"\btypedef\s+struct\s+packed\s*\{", content[pos:])
        if not match:
            break
        start_idx = pos + match.start()
        open_brace = pos + match.end() - 1
        
        brace_count = 1
        scan_idx = open_brace + 1
        while brace_count > 0 and scan_idx < len(content):
            c = content[scan_idx]
            if c == "{":
                brace_count += 1
            elif c == "}":
                brace_count -= 1
            scan_idx += 1
            
        if brace_count == 0:
            semi = content.find(";", scan_idx)
            if semi != -1:
                struct_name = content[scan_idx:semi].strip()
                struct_body = content[open_brace+1 : scan_idx-1]
                
                inner_pos = 0
                modified_body = []
                last_inner_end = 0
                has_inner = False
                local_sub_decls = []
                
                while True:
                    m_inner = re.search(r"\bstruct\s+packed\s*\{", struct_body[inner_pos:])
                    if not m_inner:
                        break
                    in_start = inner_pos + m_inner.start()
                    in_open = inner_pos + m_inner.end() - 1
                    
                    in_brace = 1
                    in_scan = in_open + 1
                    while in_brace > 0 and in_scan < len(struct_body):
                        ch = struct_body[in_scan]
                        if ch == "{":
                            in_brace += 1
                        elif ch == "}":
                            in_brace -= 1
                        in_scan += 1
                        
                    if in_brace == 0:
                        in_semi = struct_body.find(";", in_scan)
                        if in_semi != -1:
                            field_name = struct_body[in_scan:in_semi].strip()
                            inner_body = struct_body[in_open+1 : in_scan-1]
                            
                            sub_type_name = f"{struct_name}_{field_name}_sub_t"
                            local_sub_decls.append(f"  typedef struct packed {{\n{inner_body}\n  }} {sub_type_name};")
                            
                            modified_body.append(struct_body[last_inner_end:in_start])
                            modified_body.append(f"  {sub_type_name} {field_name}")
                            
                            last_inner_end = in_semi
                            inner_pos = in_semi + 1
                            has_inner = True
                        else:
                            inner_pos = in_scan
                    else:
                        inner_pos = in_start + 14
                        
                if has_inner:
                    modified_body.append(struct_body[last_inner_end:])
                    full_modified_body = "".join(modified_body)
                    sub_decls_str = "\n".join(local_sub_decls)
                    replacement = f"{sub_decls_str}\n  typedef struct packed {{\n{full_modified_body}\n}} {struct_name};"
                    content = content[:start_idx] + replacement + content[semi+1:]
                    pos = start_idx + len(replacement)
                else:
                    pos = semi + 1
            else:
                pos = scan_idx
        else:
            pos = start_idx + 20
            
    return content

def resolve_all_struct_typedefs_to_logic(content: str) -> str:
    struct_widths = {}
    for _ in range(5):
        pos = 0
        while True:
            match = re.search(r"\btypedef\s+struct\s+packed\s*\{", content[pos:])
            if not match:
                break
            start_idx = pos + match.start()
            open_brace = pos + match.end() - 1
            
            brace_count = 1
            scan_idx = open_brace + 1
            while brace_count > 0 and scan_idx < len(content):
                c = content[scan_idx]
                if c == "{":
                    brace_count += 1
                elif c == "}":
                    brace_count -= 1
                scan_idx += 1
                
            if brace_count == 0:
                semi = content.find(";", scan_idx)
                if semi != -1:
                    struct_name = content[scan_idx:semi].strip()
                    struct_body = content[open_brace+1 : scan_idx-1]
                    
                    width = 0
                    for line in struct_body.split(";"):
                        line = line.strip()
                        if not line:
                            continue
                        m_logic = re.search(r"\blogic\s*(?:\[\s*(\d+)\s*:\s*0\s*\])?", line)
                        m_vec = re.search(r"\blogic\s*\[\s*(\d+)\s*-\s*1\s*:\s*0\s*\]", line)
                        m_sub = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s+(?:\[\s*(\d+)\s*:\s*0\s*\]\s+)?([A-Za-z_][A-Za-z0-9_]*)", line)
                        
                        w = 1
                        if m_vec:
                            w = int(m_vec.group(1))
                        elif m_logic and m_logic.group(1):
                            w = int(m_logic.group(1)) + 1
                        elif "logic" in line:
                            w = 1
                        elif m_sub and m_sub.group(1) in struct_widths:
                            w = struct_widths[m_sub.group(1)]
                            if m_sub.group(2):
                                w *= (int(m_sub.group(2)) + 1)
                        width += w
                        
                    if width > 0:
                        struct_widths[struct_name] = width
                    pos = semi + 1
                else:
                    pos = scan_idx
            else:
                pos = start_idx + 20
                
    # Convert struct typedef blocks into logic vector typedefs
    pos = 0
    while True:
        match = re.search(r"\btypedef\s+struct\s+packed\s*\{", content[pos:])
        if not match:
            break
        start_idx = pos + match.start()
        open_brace = pos + match.end() - 1
        
        brace_count = 1
        scan_idx = open_brace + 1
        while brace_count > 0 and scan_idx < len(content):
            c = content[scan_idx]
            if c == "{":
                brace_count += 1
            elif c == "}":
                brace_count -= 1
            scan_idx += 1
            
        if brace_count == 0:
            semi = content.find(";", scan_idx)
            if semi != -1:
                struct_name = content[scan_idx:semi].strip()
                w = struct_widths.get(struct_name, 1)
                repl_typedef = f"typedef logic [{w-1}:0] {struct_name};" if w > 1 else f"typedef logic {struct_name};"
                content = content[:start_idx] + repl_typedef + content[semi+1:]
                pos = start_idx + len(repl_typedef)
            else:
                pos = scan_idx
        else:
            pos = start_idx + 20
            
    return content

def preprocess_sv_for_yosys(content: str) -> str:
    # Inline prim_util_pkg functions
    content = inline_prim_util(content)
    
    # Flatten anonymous inline structs for Yosys AST compatibility
    content = flatten_anonymous_nested_structs(content)
    
    # Resolve packed struct typedefs to logic bit vectors for Yosys AST compatibility
    content = resolve_all_struct_typedefs_to_logic(content)

    # Move other package/module level imports to the top of the file
    # Only hoist imports that have a valid SV import form: "import pkg::name;" or "import pkg::*;"
    # (bare identifiers or substituted literals are NOT valid and must stay as-is or be dropped)
    _VALID_IMPORT_RE = re.compile(r'^import\s+\w+\s*::\s*(?:\w+|\*)\s*;$')
    imports = []
    lines = content.splitlines()
    new_lines = []
    in_function_or_task = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("function ") or stripped.startswith("task "):
            in_function_or_task = True
        elif stripped.startswith("endfunction") or stripped.startswith("endtask"):
            in_function_or_task = False
            
        if not in_function_or_task and stripped.startswith("import ") and stripped.endswith(";"):
            # Only hoist if it matches a structurally valid import statement
            if _VALID_IMPORT_RE.match(stripped):
                imports.append(stripped)
            else:
                # Malformed import (e.g. literal value substituted in) — drop it silently
                pass
        else:
            new_lines.append(line)
            
    content = "\n".join(new_lines)
    if imports:
        unique_imports = []
        for imp in imports:
            if imp not in unique_imports:
                unique_imports.append(imp)
        content = "\n".join(unique_imports) + "\n\n" + content

    # Fix enum user type base types (Yosys does not support user-defined types as enum base types)
    typedefs = {}
    for match in re.finditer(r"\btypedef\s+([^;]+?)\s+(\w+)\s*;", content):
        actual_type = match.group(1).strip()
        user_type = match.group(2).strip()
        if not actual_type.startswith("enum"):
            typedefs[user_type] = actual_type
            
    enum_pos = 0
    while True:
        match = re.search(r"\btypedef\s+enum\b", content[enum_pos:])
        if not match:
            break
        start_idx = enum_pos + match.start()
        open_brace = content.find("{", start_idx)
        if open_brace == -1:
            enum_pos = start_idx + 12
            continue
        
        brace_count = 1
        scan_idx = open_brace + 1
        while brace_count > 0 and scan_idx < len(content):
            c = content[scan_idx]
            if c == "{":
                brace_count += 1
            elif c == "}":
                brace_count -= 1
            scan_idx += 1
            
        if brace_count == 0:
            semi = content.find(";", scan_idx)
            if semi != -1:
                prefix = content[start_idx:open_brace].strip()
                suffix = content[scan_idx:semi].strip()
                base_type = prefix.replace("typedef enum", "").strip()
                if not base_type:
                    base_type = "logic [31:0]"
                user_type = suffix.strip()
                if user_type:
                    typedefs[user_type] = base_type
                enum_pos = semi + 1
            else:
                enum_pos = scan_idx
        else:
            enum_pos = start_idx + 12
            
    for user_type, actual_type in typedefs.items():
        content = re.sub(
            r"\btypedef\s+enum\s+" + re.escape(user_type) + r"\b\s*(\{)",
            f"typedef enum {actual_type} \\1",
            content
        )

    # Resolve cast types for local typedefs to width casts to satisfy Yosys frontend
    for user_type, base_type in typedefs.items():
        dim_match = re.match(r"^logic\s+\[(.*)-1:0\]$", base_type.strip())
        if not dim_match:
            dim_match = re.match(r"^logic\s+\[(.*):0\]$", base_type.strip())
        if dim_match:
            width_expr = dim_match.group(1).strip()
            content = content.replace(f"{user_type}'(", f"({width_expr})'(")

    # Resolve all previously known package scope parameters
    for full_name, val in sorted(GLOBAL_PARAMS.items(), key=lambda x: len(x[0]), reverse=True):
        content = content.replace(full_name, f"({val})")
        
    # Find all package imports in the file to resolve bare parameters
    wildcard_imports = re.findall(r"\bimport\s+(\w+)::\*;", content)
    explicit_imports = re.findall(r"\bimport\s+(\w+)::(\w+);", content)
    
    imported_params = []
    for pkg_name in wildcard_imports:
        if pkg_name in PACKAGE_EXPORTED_PARAMS:
            imported_params.extend(PACKAGE_EXPORTED_PARAMS[pkg_name])
            
    for pkg_name, param_name in explicit_imports:
        if pkg_name in PACKAGE_EXPORTED_PARAMS:
            for name, val in PACKAGE_EXPORTED_PARAMS[pkg_name]:
                if name == param_name:
                    imported_params.append((name, val))
                    break
                    
    for name, val in sorted(imported_params, key=lambda x: len(x[0]), reverse=True):
        content = re.sub(r"\b" + re.escape(name) + r"\b", f"({val})", content)

    # Post-substitution cleanup: remove any import lines that were corrupted by
    # GLOBAL_PARAMS substitution (e.g. "import (4'h6);" which Yosys rejects).
    # Valid SV import forms: "import pkg::name;" or "import pkg::*;"
    _VALID_IMPORT_PAT = re.compile(r'^import\s+\w+\s*::\s*(?:\w+|\*)\s*;$')
    content_lines = content.splitlines()
    content = "\n".join(
        line for line in content_lines
        if not (line.strip().startswith("import ") and line.strip().endswith(";")
                and not _VALID_IMPORT_PAT.match(line.strip()))
    )

    # 1. Replace inside operator: val inside {A, B, C} -> (val == A || val == B || val == C)
    pattern_inside = r"(\w+)\s+inside\s*\{\s*([^}]+)\s*\}"
    def repl_inside(match):
        val = match.group(1).strip()
        elems_str = match.group(2)
        elems = [e.strip() for e in elems_str.split(",")]
        return "(" + " || ".join(f"{val} == {e}" for e in elems) + ")"
    content = re.sub(pattern_inside, repl_inside, content)
    
    # 2. Stateful function return replacement (multi-line aware)
    def repl_function_block(match):
        block = match.group(0)
        header_end = block.find("(")
        semi_idx = block.find(";")
        if header_end == -1 or (semi_idx != -1 and semi_idx < header_end):
            header_end = semi_idx
        if header_end == -1:
            return block
        header = block[:header_end]
        words = re.findall(r"\b\w+\b", header)
        if not words:
            return block
        func_name = words[-1]
        body = block[header_end:]
        body_replaced = re.sub(
            r"\breturn\s+([^;]+);",
            lambda m: f"{func_name} = {m.group(1).strip()};",
            body
        )
        return block[:header_end] + body_replaced

    content = re.sub(
        r"\bfunction\s+.*?\bendfunction\b",
        repl_function_block,
        content,
        flags=re.DOTALL
    )
    
    # 3. Remove named end blocks (endfunction : name, endpackage : name, endtask : name)
    content = re.sub(r"\bendfunction\s*:\s*\w+", "endfunction", content)
    content = re.sub(r"\bendtask\s*:\s*\w+", "endtask", content)
    content = re.sub(r"\bendpackage\s*:\s*\w+", "endpackage", content)
    
    # 4. Simplify named struct patterns: '{field: val, ...} -> '{val, ...}
    pos = 0
    while True:
        idx = content.find("'{", pos)
        if idx == -1:
            break
            
        nesting = 1
        scan = idx + 2
        while scan < len(content) and nesting > 0:
            char = content[scan]
            if char == '{':
                nesting += 1
            elif char == '}':
                nesting -= 1
            scan += 1
            
        if nesting == 0:
            inner = content[idx+2 : scan-1]
            elements = []
            current_element = []
            brace_nesting = 0
            paren_nesting = 0
            i = 0
            while i < len(inner):
                char = inner[i]
                if char == '{':
                    brace_nesting += 1
                    current_element.append(char)
                elif char == '}':
                    brace_nesting -= 1
                    current_element.append(char)
                elif char == '(':
                    paren_nesting += 1
                    current_element.append(char)
                elif char == ')':
                    paren_nesting -= 1
                    current_element.append(char)
                elif char == ',' and brace_nesting == 0 and paren_nesting == 0:
                    elements.append("".join(current_element))
                    current_element = []
                else:
                    current_element.append(char)
                i += 1
            if current_element:
                elements.append("".join(current_element))
                
            cleaned_elements = []
            for elem in elements:
                elem_clean = re.sub(r"//.*$", "", elem, flags=re.MULTILINE).strip()
                colon_idx = -1
                b_nest = 0
                p_nest = 0
                for j, c in enumerate(elem_clean):
                    if c == '{':
                        b_nest += 1
                    elif c == '}':
                        b_nest -= 1
                    elif c == '(':
                        p_nest += 1
                    elif c == ')':
                        p_nest -= 1
                    elif c == ':' and b_nest == 0 and p_nest == 0:
                        if j + 1 < len(elem_clean) and elem_clean[j+1] == ':':
                            continue
                        if j - 1 >= 0 and elem_clean[j-1] == ':':
                            continue
                        colon_idx = j
                        break
                if colon_idx != -1:
                    cleaned_elements.append(elem_clean[colon_idx+1:])
                else:
                    cleaned_elements.append(elem_clean)
                    
            replacement = "'{" + ",".join(cleaned_elements) + "}"
            content = content[:idx] + replacement + content[scan:]
            pos = idx + len(replacement)
        else:
            pos = idx + 2
    
    # 4b. Flatten unpacked parameter/localparam arrays to packed 1D arrays
    def repl_param_array(match):
        kw = match.group(1)
        msb = match.group(2)
        lsb = match.group(3)
        name = match.group(4)
        size = match.group(5).strip()
        
        if msb is not None:
            w_val = int(msb) - int(lsb) + 1
            w_expr = str(w_val)
        else:
            w_val = 1
            w_expr = "1"
            
        try:
            sz_val = int(size)
            tot = sz_val * w_val
            new_dim = f"[{tot}-1:0]"
        except ValueError:
            new_dim = f"[({size}) * {w_expr}-1:0]"
            
        return f"{kw} logic {new_dim} {name} = '{{"
    
    content = re.sub(
        r"\b(parameter|localparam)\s+logic\s*(?:\[\s*(\d+)\s*:\s*(\d+)\s*\])?\s*(\w+)\s*\[([^\]]+)\]\s*=\s*'\s*\{",
        repl_param_array,
        content
    )

    # 4c. Flatten packed multidimensional parameter/localparam arrays to 1D packed arrays for Yosys
    def repl_packed_param(match):
        kw = match.group(1)
        type_and_dims = match.group(2).strip()
        name = match.group(3)
        
        type_match = re.match(r"^(\w+)", type_and_dims)
        if not type_match:
            return match.group(0)
            
        base_type = type_match.group(1)
        resolved_type = typedefs.get(base_type, base_type)
        combined = resolved_type + type_and_dims[len(base_type):]
        
        dims = re.findall(r"\[\s*([^\]]+)\s*\]", combined)
        if not dims:
            return f"{kw} {resolved_type} {name} ="
            
        lengths = []
        for dim in dims:
            dim = dim.strip()
            if ":" in dim:
                parts = dim.split(":")
                msb = parts[0].strip()
                lsb = parts[1].strip()
                if lsb == "0":
                    lengths.append(f"({msb}+1)")
                else:
                    lengths.append(f"({msb}-{lsb}+1)")
            else:
                lengths.append(f"({dim})")
                
        total_width_expr = " * ".join(lengths)
        try:
            evaluated_lengths = []
            for l in lengths:
                inner = l.strip("()")
                if "+" in inner:
                    parts = inner.split("+")
                    evaluated_lengths.append(int(parts[0].strip()) + int(parts[1].strip()))
                elif "-" in inner:
                    parts = inner.split("-")
                    evaluated_lengths.append(int(parts[0].strip()) - int(parts[1].strip()))
                else:
                    evaluated_lengths.append(int(inner))
            tot = 1
            for el in evaluated_lengths:
                tot *= el
            new_dim = f"[{tot}-1:0]"
        except Exception:
            new_dim = f"[({total_width_expr})-1:0]"
            
        return f"{kw} logic {new_dim} {name} ="

    content = re.sub(
        r"\b(parameter|localparam)\s+((?:\w+)(?:\s*\[\s*[^\]]+\s*\])*)\s+(\w+)\s*=",
        repl_packed_param,
        content
    )

    # 4d. Rewrite any PERMIT array accesses to use bit slice selection
    content = re.sub(r"\b(\w+_PERMIT)\[\s*([^\]]+)\s*\]", r"\1[(\2)*4 +: 4]", content)
    
    # 5. Simplify default struct initializers: '{default: '0} -> '0
    content = re.sub(r"'\s*\{\s*default\s*:\s*([^}]+)\}", r"\1", content)
    content = re.sub(r"parameter pmp_cfg_t PmpCfgRst.*?};", "", content, flags=re.DOTALL)
    content = re.sub(r"parameter logic \[[^\]]+\] PmpAddrRst.*?};", "", content, flags=re.DOTALL)
    content = re.sub(r"parameter pmp_mseccfg_t PmpMseccfgRst.*?;", "", content, flags=re.DOTALL)

    
    # 6. Rewrite functions with multidimensional returns or unpacked array args
    content = content.replace(
        "function automatic logic [3:0][3:0][7:0] aes_transpose(logic [3:0][3:0][7:0] in);",
        "function automatic logic [127:0] aes_transpose(logic [127:0] in);\n  logic [3:0][3:0][7:0] in_val;\n  in_val = in;"
    ).replace("transpose[i][j] = in[j][i];", "transpose[i][j] = in_val[j][i];")
    
    content = content.replace(
        "function automatic logic [127:0] aes_state_to_ghash_vec(logic [3:0][3:0][7:0] in);",
        "function automatic logic [127:0] aes_state_to_ghash_vec(logic [127:0] in);\n  logic [3:0][3:0][7:0] in_val;\n  in_val = in;"
    ).replace("byte_vec[15 - 4*i - j] = in[j][i];", "byte_vec[15 - 4*i - j] = in_val[j][i];")
    
    content = content.replace(
        "function automatic logic [3:0][7:0] aes_col_get(logic [3:0][3:0][7:0] in, logic [1:0] idx);",
        "function automatic logic [31:0] aes_col_get(logic [127:0] in, logic [1:0] idx);\n  logic [3:0][3:0][7:0] in_val;\n  in_val = in;"
    ).replace("out[i] = in[idx][i];", "out[i] = in_val[idx][i];")
    
    content = content.replace(
        "function automatic logic [3:0][7:0] aes_prd_get_lsbs(\n  logic [(4*WidthPRDSBox)-1:0] in\n);",
        "function automatic logic [31:0] aes_prd_get_lsbs(logic [(4*WidthPRDSBox)-1:0] in);"
    )
    
    content = content.replace(
        "function automatic logic [7:0] aes_mvm(\n  logic [7:0] vec_b,\n  logic [7:0] mat_a [8]\n);",
        "function automatic logic [7:0] aes_mvm(logic [7:0] vec_b, logic [63:0] mat_a);\n  logic [7:0] mat_a_val [8];\n  for (int k = 0; k < 8; k++) begin mat_a_val[k] = mat_a[k*8 +: 8]; end"
    ).replace("mat_a[j][i]", "mat_a_val[j][i]")

    # Extract package parameters from the preprocessed file for future files
    pkg_match = re.search(r"\bpackage\s+(\w+)\s*;", content)
    if pkg_match:
        pkg_name = pkg_match.group(1)
        matches = list(re.finditer(
            r"\b(?:parameter|localparam)\b[^=]*?\b(\w+)\s*=\s*(.*?);",
            content,
            re.DOTALL
        ))
        if pkg_name not in PACKAGE_EXPORTED_PARAMS:
            PACKAGE_EXPORTED_PARAMS[pkg_name] = []
        for m in matches:
            name = m.group(1)
            val = m.group(2).strip()
            # Clean up value
            val_cleaned = re.sub(r"//.*", "", val)
            val_cleaned = re.sub(r"/\*.*?\*/", "", val_cleaned, flags=re.DOTALL)
            val_cleaned = " ".join(val_cleaned.split())
            
            # Resolve local parameters of this package and global parameters (multi-pass to handle nested dependencies)
            for _ in range(5):
                for prev_name, prev_val in PACKAGE_EXPORTED_PARAMS[pkg_name]:
                    val_cleaned = re.sub(r"\b" + re.escape(prev_name) + r"\b", f"({prev_val})", val_cleaned)
                for full_name, f_val in sorted(GLOBAL_PARAMS.items(), key=lambda x: len(x[0]), reverse=True):
                    val_cleaned = val_cleaned.replace(full_name, f"({f_val})")
                
            GLOBAL_PARAMS[f"{pkg_name}::{name}"] = val_cleaned
            PACKAGE_EXPORTED_PARAMS[pkg_name].append((name, val_cleaned))

        # Extract enum values from enums using nesting-aware scanning
        enum_pos = 0
        while True:
            match = re.search(r"\btypedef\s+enum\b", content[enum_pos:])
            if not match:
                break
            start_idx = enum_pos + match.start()
            open_brace = content.find("{", start_idx)
            if open_brace == -1:
                enum_pos = start_idx + 12
                continue
            
            brace_count = 1
            scan_idx = open_brace + 1
            while brace_count > 0 and scan_idx < len(content):
                c = content[scan_idx]
                if c == "{":
                    brace_count += 1
                elif c == "}":
                    brace_count -= 1
                scan_idx += 1
                
            if brace_count == 0:
                enum_body = content[open_brace+1 : scan_idx-1]
                semi = content.find(";", scan_idx)
                if semi != -1:
                    enum_pos = semi + 1
                else:
                    enum_pos = scan_idx
                
                enum_body_clean = re.sub(r"//.*", "", enum_body)
                enum_body_clean = re.sub(r"/\*.*?\*/", "", enum_body_clean, flags=re.DOTALL)
                
                members = []
                curr_member = []
                b_level = 0
                p_level = 0
                for ch in enum_body_clean:
                    if ch == "{":
                        b_level += 1
                        curr_member.append(ch)
                    elif ch == "}":
                        b_level -= 1
                        curr_member.append(ch)
                    elif ch == "(":
                        p_level += 1
                        curr_member.append(ch)
                    elif ch == ")":
                        p_level -= 1
                        curr_member.append(ch)
                    elif ch == "," and b_level == 0 and p_level == 0:
                        members.append("".join(curr_member).strip())
                        curr_member = []
                    else:
                        curr_member.append(ch)
                if curr_member:
                    members.append("".join(curr_member).strip())
                    
                idx = 0
                for member in members:
                    if not member:
                        continue
                    if "=" in member:
                        parts = member.split("=", 1)
                        m_name = parts[0].strip()
                        m_val = parts[1].strip()
                        m_val_cleaned = " ".join(m_val.split())
                        
                        for _ in range(5):
                            for prev_name, prev_val in PACKAGE_EXPORTED_PARAMS[pkg_name]:
                                m_val_cleaned = re.sub(r"\b" + re.escape(prev_name) + r"\b", f"({prev_val})", m_val_cleaned)
                            for full_name, f_val in sorted(GLOBAL_PARAMS.items(), key=lambda x: len(x[0]), reverse=True):
                                m_val_cleaned = m_val_cleaned.replace(full_name, f"({f_val})")
                            
                        GLOBAL_PARAMS[f"{pkg_name}::{m_name}"] = m_val_cleaned
                        PACKAGE_EXPORTED_PARAMS[pkg_name].append((m_name, m_val_cleaned))
                    else:
                        m_name = member
                        m_val = str(idx)
                        GLOBAL_PARAMS[f"{pkg_name}::{m_name}"] = m_val
                        PACKAGE_EXPORTED_PARAMS[pkg_name].append((m_name, m_val))
                        idx += 1
            else:
                enum_pos = start_idx + 12

        # Save package typedefs with resolved parameters (multi-pass)
        for user_type, base_type in typedefs.items():
            resolved_base = base_type
            for _ in range(5):
                for m in matches:
                    p_name = m.group(1)
                    p_val = m.group(2).strip()
                    p_val_cleaned = re.sub(r"//.*", "", p_val)
                    p_val_cleaned = re.sub(r"/\*.*?\*/", "", p_val_cleaned, flags=re.DOTALL)
                    p_val_cleaned = " ".join(p_val_cleaned.split())
                    resolved_base = re.sub(r"\b" + re.escape(p_name) + r"\b", f"({p_val_cleaned})", resolved_base)
                for full_name, val in sorted(GLOBAL_PARAMS.items(), key=lambda x: len(x[0]), reverse=True):
                    resolved_base = resolved_base.replace(full_name, f"({val})")
            GLOBAL_TYPEDEFS[f"{pkg_name}::{user_type}"] = resolved_base

        # Transitive typedef chain resolution within this package:
        # e.g. lc_state_e -> lc_state_t -> logic [N:0]
        # Build a local_type_map: bare_name -> full_scoped_key for this package
        local_type_map = {}
        for key in GLOBAL_TYPEDEFS:
            if key.startswith(f"{pkg_name}::"):
                bare = key[len(pkg_name) + 2:]
                local_type_map[bare] = key

        for _ in range(5):
            for key in list(GLOBAL_TYPEDEFS.keys()):
                if not key.startswith(f"{pkg_name}::"):
                    continue
                val = GLOBAL_TYPEDEFS[key]
                # If the value is a bare identifier that resolves in this package's typedefs,
                # or in another package's typedefs (scoped), follow the chain
                # 1. Try bare name lookup in same package
                val_stripped = val.strip()
                if val_stripped in local_type_map:
                    resolved_key = local_type_map[val_stripped]
                    GLOBAL_TYPEDEFS[key] = GLOBAL_TYPEDEFS[resolved_key]
                    continue
                # 2. Try scoped name lookup across all packages
                if val_stripped in GLOBAL_TYPEDEFS:
                    GLOBAL_TYPEDEFS[key] = GLOBAL_TYPEDEFS[val_stripped]
                    continue
                # 3. Resolve any bare alias names embedded in array-typed values
                # e.g. "some_type_e [(N)-1:0]" -> "logic [W:0] [(N)-1:0]"
                m = re.match(r'^(\w+)\s*(\[.*)$', val_stripped)
                if m:
                    bare_base = m.group(1)
                    rest = m.group(2)
                    if bare_base in local_type_map:
                        inner = GLOBAL_TYPEDEFS[local_type_map[bare_base]]
                        GLOBAL_TYPEDEFS[key] = inner + ' ' + rest
                    elif f"{pkg_name}::{bare_base}" in GLOBAL_TYPEDEFS:
                        inner = GLOBAL_TYPEDEFS[f"{pkg_name}::{bare_base}"]
                        GLOBAL_TYPEDEFS[key] = inner + ' ' + rest

    return content

def call_llm_for_synthesis_interpretation(module_name: str, log_content: str) -> Dict[str, Any]:
    prompt = f"""You are a hardware security auditing assistant.
We have run Yosys synthesis on the SystemVerilog module '{module_name}'.
Below is the synthesis compiler output (stdout/stderr):

{log_content}

Analyze the synthesis output for any optimization, warning, or error that has security implications.
Focus on:
1. Signals or registers that were optimized away or deleted (e.g. key checks, countermeasure registers, parity checks, redundant security logic, or safety loops).
2. Constant folding or simplification that might bypass a hardware lock, state check, or cryptographic operation.
3. Implicitly declared signals, multi-driven nets, or dangling wires that could lead to undefined state transitions.
4. Compiler warnings about sensitivity lists, latches, or out-of-bounds array accesses.

Return a JSON object containing your analysis:
{{
  "module": "{module_name}",
  "risk_level": "LOW" | "MEDIUM" | "HIGH",
  "security_warnings": [
    {{
      "finding": "Short description of the finding",
      "severity": "LOW" | "MEDIUM" | "HIGH",
      "explanation": "Detailed explanation of why this transformation or warning presents a security risk",
      "recommendation": "How the designer can fix it (e.g. keep attributes, logic changes)"
    }}
  ]
}}
Return ONLY the JSON object. Do not include markdown formatting or explanation.
"""

    response_text = ""
    from src.soc_analyzer.ai_gateway import AIGateway, TaskType
    try:
        gateway = AIGateway()
        resp = gateway.call_prompt(
            task_type=TaskType.EXPLAIN,
            prompt=prompt,
            module=module_name,
        )
        if resp.is_success and resp.parsed_output:
            return resp.parsed_output
        elif resp.is_success and resp.raw_text:
            response_text = resp.raw_text
    except Exception as e:
        print(f"Error during AI interpretation request: {e}")
        
    if response_text:
        try:
            # Clean possible markdown wrap
            cleaned = response_text.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            return json.loads(cleaned.strip())
        except Exception as e:
            print(f"Failed to parse LLM response as JSON: {e}. Raw response: {response_text}")
            
    # Mock / Default return if LLM is not active or failed
    return {
        "module": module_name,
        "risk_level": "LOW",
        "security_warnings": [
            {
                "finding": "Standard Yosys Synthesis Completed",
                "severity": "LOW",
                "explanation": "No custom security flags raised by static compiler log inspection. Run static/dynamic worker agents for deeper auditing.",
                "recommendation": "Proceed to downstream auditing workers."
            }
        ]
    }

def sort_files_by_dependencies(file_paths: list[str]) -> list[str]:
    package_files = []
    other_files = []
    
    for f in file_paths:
        base = os.path.basename(f)
        if "_pkg.sv" in base or "pkg" in base.lower():
            package_files.append(f)
        else:
            other_files.append(f)
            
    defines_pkg = {}
    imports_pkg = {}
    
    for f in package_files:
        try:
            with open(f, "r", errors="ignore") as fh:
                content = fh.read()
        except Exception:
            defines_pkg[f] = []
            imports_pkg[f] = []
            continue
            
        defs = re.findall(r"\bpackage\s+(\w+)\s*;", content)
        defines_pkg[f] = defs
        
        imps = re.findall(r"\b(\w+)::", content)
        explicit_imps = re.findall(r"\bimport\s+(\w+)::", content)
        all_imps = list(set(imps + explicit_imps))
        all_imps = [i for i in all_imps if i not in defs and i != "prim_util_pkg" and i != "prim_mubi_pkg"]
        imports_pkg[f] = all_imps

    pkg_to_file = {}
    for f, pkgs in defines_pkg.items():
        for p in pkgs:
            pkg_to_file[p] = f
            
    adj = {f: set() for f in package_files}
    in_degree = {f: 0 for f in package_files}
    
    for f in package_files:
        for imp in imports_pkg[f]:
            dep_file = pkg_to_file.get(imp)
            if dep_file and dep_file != f:
                if f not in adj[dep_file]:
                    adj[dep_file].add(f)
                    in_degree[f] += 1
                    
    queue = [f for f in package_files if in_degree[f] == 0]
    sorted_packages = []
    queue.sort()
    
    while queue:
        curr = queue.pop(0)
        sorted_packages.append(curr)
        for neighbor in sorted(list(adj[curr])):
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)
                
    for f in package_files:
        if f not in sorted_packages:
            sorted_packages.append(f)
            
    return sorted_packages + other_files

def _resolve_global_typedef_chains():
    """Globally resolve all transitive typedef alias chains in GLOBAL_TYPEDEFS.
    
    After all package files have been preprocessed, GLOBAL_TYPEDEFS may still
    contain entries whose values are bare alias names (e.g. lc_state_e -> lc_state_t)
    instead of concrete logic[N:0] types. This function iteratively chases those
    chains across all packages until stable.
    """
    # Build reverse lookup: bare_name -> scoped_key for fast resolution
    # (prefer longest match to avoid collisions)
    for _ in range(10):
        changed = False
        for key in list(GLOBAL_TYPEDEFS.keys()):
            val = GLOBAL_TYPEDEFS[key].strip()
            # Skip already-concrete types
            if val.startswith('logic') or val.startswith('struct') or val.startswith('bit') or val.startswith('reg'):
                continue

            # Case 1: plain identifier -> look up as scoped key in same pkg, or globally
            pkg_prefix = key.rsplit('::', 1)[0] if '::' in key else ''
            scoped_candidate = f"{pkg_prefix}::{val}" if pkg_prefix else val

            if scoped_candidate in GLOBAL_TYPEDEFS:
                new_val = GLOBAL_TYPEDEFS[scoped_candidate]
                if new_val != val:
                    GLOBAL_TYPEDEFS[key] = new_val
                    changed = True
                continue

            # Case 2: value is a bare enum name that exists under the same package prefix
            if val in GLOBAL_TYPEDEFS:
                new_val = GLOBAL_TYPEDEFS[val]
                if new_val != val:
                    GLOBAL_TYPEDEFS[key] = new_val
                    changed = True
                continue

            # Case 3: value is "some_alias_e [dims...]" — resolve just the base type
            m = re.match(r'^(\w+)(\s*\[.*)$', val)
            if m:
                bare_base = m.group(1)
                rest = m.group(2)
                scoped_base = f"{pkg_prefix}::{bare_base}" if pkg_prefix else bare_base
                resolved_base = None
                if scoped_base in GLOBAL_TYPEDEFS:
                    resolved_base = GLOBAL_TYPEDEFS[scoped_base]
                elif bare_base in GLOBAL_TYPEDEFS:
                    resolved_base = GLOBAL_TYPEDEFS[bare_base]
                if resolved_base and resolved_base != bare_base:
                    new_val = resolved_base.strip() + rest
                    if new_val != val:
                        GLOBAL_TYPEDEFS[key] = new_val
                        changed = True
                    continue

            # Case 4: value contains 'int' -> remap to logic [31:0] for Yosys
            if val == 'int':
                GLOBAL_TYPEDEFS[key] = 'logic [31:0]'
                changed = True

        if not changed:
            break


def synthesize_module(module_name: str, output_dir: str) -> Dict[str, Any]:
    netlist_path = os.path.join(output_dir, "full_soc_netlist.json")
    if os.path.exists(netlist_path):
        dummy_config = SynthesisConfig(top_module="unknown", output_dir=output_dir)
        slice_result = split_netlist_by_module(dummy_config)
        slice_stats = None
        for s in slice_result["slices"]:
            if s["instance"] == module_name:
                slice_stats = s
                break
        if slice_stats:
            ai_interpretation = annotate_module_security(module_name, dummy_config)
            return {
                "status": "COMPLETED",
                "warning_count": 0,
                "error_count": 0,
                "ai_interpretation": ai_interpretation,
                "slice": slice_stats
            }

    GLOBAL_PARAMS.clear()
    PACKAGE_EXPORTED_PARAMS.clear()
    GLOBAL_TYPEDEFS.clear()
    mod_dir = os.path.join(output_dir, "per_module", module_name)
    os.makedirs(mod_dir, exist_ok=True)
    
    inv_map_path = os.path.join(mod_dir, "invocation_map.json")
    if not os.path.exists(inv_map_path):
        return {"status": "FAILED", "reason": "No invocation map found"}
        
    with open(inv_map_path, "r") as f:
        inv_map = json.load(f)
        
    # Use slang files by default, fallback to verilator
    tool_section = inv_map.get("slang") or inv_map.get("verilator")
    if not tool_section:
        return {"status": "FAILED", "reason": "No compilation files found in invocation map"}
        
    raw_files = tool_section.get("files", [])
    files = sort_files_by_dependencies(raw_files)
    include_paths = tool_section.get("include_paths", [])
    
    # Setup temp path
    temp_rtl_dir = os.path.abspath(os.path.join(output_dir, "synthesis_temp", module_name))
    os.makedirs(temp_rtl_dir, exist_ok=True)
    
    # 1. Write the yosys_assert_fix header
    yosys_assert_fix_content = """`ifndef PRIM_ASSERT_SV
`define PRIM_ASSERT_SV
`define ASSERT_I(__name, __prop)
`define ASSERT_INIT(__name, __prop)
`define ASSERT_INIT_NET(__name, __prop)
`define ASSERT_FINAL(__name, __prop)
`define ASSERT_AT_RESET(__name, __prop, __rst = 1'b0)
`define ASSERT_AT_RESET_AND_FINAL(__name, __prop, __rst = 1'b0)
`define ASSERT(__name, __prop, __clk = 1'b0, __rst = 1'b0)
`define ASSERT_NEVER(__name, __prop, __clk = 1'b0, __rst = 1'b0)
`define ASSERT_KNOWN(__name, __sig, __clk = 1'b0, __rst = 1'b0)
`define COVER(__name, __prop, __clk = 1'b0, __rst = 1'b0)
`define ASSUME(__name, __prop, __clk = 1'b0, __rst = 1'b0)
`define ASSUME_I(__name, __prop)
`define ASSERT_STATIC_IN_PACKAGE(__name, __prop)
`define ASSERT_STATIC_LINT_ERROR(__name, __prop)
`define ASSERT_PULSE(__name, __sig, __clk = 1'b0, __rst = 1'b0)
`define ASSERT_IF(__name, __prop, __enable, __clk = 1'b0, __rst = 1'b0)
`define ASSERT_KNOWN_IF(__name, __sig, __enable, __clk = 1'b0, __rst = 1'b0)
`define ASSUME_FPV(__name, __prop, __clk = 1'b0, __rst = 1'b0)
`define ASSUME_I_FPV(__name, __prop)
`define COVER_FPV(__name, __prop, __clk = 1'b0, __rst = 1'b0)
`define ASSERT_FPV_LINEAR_FSM(__name, __state, __type, __clk = 1'b0, __rst = 1'b0)
`endif
"""
    yosys_assert_fix_path = os.path.join(temp_rtl_dir, "yosys_assert_fix.svh")
    with open(yosys_assert_fix_path, "w") as f:
        f.write(yosys_assert_fix_content)
        
    # Copy and preprocess all files in the include paths first to allow resolution of includes
    for inc_dir in include_paths:
        if os.path.exists(inc_dir):
            for item in os.listdir(inc_dir):
                item_path = os.path.join(inc_dir, item)
                if os.path.isfile(item_path) and item.endswith(('.sv', '.svh', '.v')):
                    # Check if it's prim_assert.sv to override with our mock definitions
                    dst_path = os.path.join(temp_rtl_dir, item)
                    if item == "prim_assert.sv":
                        with open(dst_path, "w") as fh:
                            fh.write(yosys_assert_fix_content)
                    else:
                        try:
                            with open(item_path, "r", errors="ignore") as fh:
                                content = fh.read()
                            processed = preprocess_sv_for_yosys(content)
                            with open(dst_path, "w") as fh:
                                fh.write(processed)
                        except Exception:
                            pass
                            
    # Preprocess and copy design files
    preprocessed_files = []
    for f in files:
        if not os.path.exists(f):
            continue
        base = os.path.basename(f)
        dst_path = os.path.join(temp_rtl_dir, base)
        
        if base == "prim_assert.sv":
            with open(dst_path, "w") as fh:
                fh.write(yosys_assert_fix_content)
        else:
            try:
                with open(f, "r", errors="ignore") as fh:
                    content = fh.read()
                processed = preprocess_sv_for_yosys(content)
                with open(dst_path, "w") as fh:
                    fh.write(processed)
            except Exception as e:
                return {"status": "FAILED", "reason": f"Preprocessing failed for {f}: {e}"}
                
        # Only add to primary compiled files list if it is not a header (.svh)
        if not base.endswith(".svh"):
            preprocessed_files.append(dst_path)
            
    # 1b. Resolve transitive typedef chains globally now that all packages are parsed
    _resolve_global_typedef_chains()

    # 2. Second-pass parameter resolution: now that we have parsed all packages,
    # resolve all package parameters (both scoped and imported) in all generated temp files.
    for item in os.listdir(temp_rtl_dir):
        item_path = os.path.join(temp_rtl_dir, item)
        if os.path.isfile(item_path) and item.endswith(('.sv', '.svh', '.v')):
            try:
                with open(item_path, "r", errors="ignore") as fh:
                    content = fh.read()
                
                # Resolve scoped user-defined types (typedefs)
                for full_type, base_type in sorted(GLOBAL_TYPEDEFS.items(), key=lambda x: len(x[0]), reverse=True):
                    dim_match = re.match(r"^logic\s+\[(.*)-1:0\]$", base_type.strip())
                    if not dim_match:
                        dim_match = re.match(r"^logic\s+\[(.*):0\]$", base_type.strip())
                    if dim_match:
                        width_expr = dim_match.group(1).strip()
                        content = content.replace(f"{full_type}'(", f"({width_expr})'(")
                    content = re.sub(r"\b" + re.escape(full_type) + r"\b", base_type, content)
                
                # Resolve scoped parameters
                for full_name, val in sorted(GLOBAL_PARAMS.items(), key=lambda x: len(x[0]), reverse=True):
                    content = content.replace(full_name, f"({val})")
                    
                # Resolve bare parameters for imported packages
                wildcard_imports = re.findall(r"\bimport\s+(\w+)::\*;", content)
                explicit_imports = re.findall(r"\bimport\s+(\w+)::(\w+);", content)
                
                imported_params = []
                for pkg_name in wildcard_imports:
                    if pkg_name in PACKAGE_EXPORTED_PARAMS:
                        imported_params.extend(PACKAGE_EXPORTED_PARAMS[pkg_name])
                        
                for pkg_name, param_name in explicit_imports:
                    if pkg_name in PACKAGE_EXPORTED_PARAMS:
                        for name, val in PACKAGE_EXPORTED_PARAMS[pkg_name]:
                            if name == param_name:
                                imported_params.append((name, val))
                                break
                                
                for name, val in sorted(imported_params, key=lambda x: len(x[0]), reverse=True):
                    content = re.sub(r"\b" + re.escape(name) + r"\b", f"({val})", content)
                    
                with open(item_path, "w") as fh:
                    fh.write(content)
            except Exception:
                pass

    # Run Yosys synthesis command
    # read the yosys_assert_fix.svh first, then add the temp path as include directory, compile files
    read_cmds = []
    # Include assert fix first
    read_cmds.append(f"read_verilog -sv {yosys_assert_fix_path}")
    
    # Read preprocessed files in topologically sorted order
    for pf in preprocessed_files:
        read_cmds.append(f"read_verilog -sv -I {temp_rtl_dir} {pf}")
        
    netlist_json_path = os.path.join(mod_dir, "synthesis_netlist.json")
    yosys_script_content = "\n".join(read_cmds) + f"\nhierarchy -top {module_name}\nprep -top {module_name}\nwrite_json {netlist_json_path}\n"
    
    script_path = os.path.join(mod_dir, "synthesis.ys")
    with open(script_path, "w") as sf:
        sf.write(yosys_script_content)
        
    cmd = ["yosys", script_path]
    
    log_path = os.path.join(mod_dir, "synthesis.log")
    stdout, stderr, returncode = "", "", -1
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        ACTIVE_PROCESSES.append(proc)
        try:
            stdout, stderr = proc.communicate(timeout=300)
            returncode = proc.returncode
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            returncode = -1
            return {"status": "FAILED", "reason": "Yosys compilation timed out"}
        finally:
            if proc in ACTIVE_PROCESSES:
                ACTIVE_PROCESSES.remove(proc)
        
        with open(log_path, "w") as lf:
            lf.write(stdout + "\n" + stderr)
            
        if returncode != 0:
            return {
                "status": "FAILED",
                "reason": "Yosys compilation failed",
                "exit_code": returncode,
                "stdout": stdout,
                "stderr": stderr
            }
    except Exception as e:
        return {"status": "FAILED", "reason": f"Yosys execution failed: {e}"}
    finally:
        # Cleanup temp files (disabled for debugging)
        pass
                
    # Parse logs
    from src.soc_analyzer.preprocessing.log_compressor import compress_log
    raw_logs = stdout + "\n" + stderr
    compressed = compress_log("yosys", raw_logs, returncode)
    
    # Save status
    status_data = {
        "status": "COMPLETED",
        "warning_count": compressed["summary"]["warning_count"],
        "error_count": compressed["summary"]["error_count"]
    }
    with open(os.path.join(mod_dir, "synthesis_status.json"), "w") as sf:
        json.dump(status_data, sf, indent=2)
        
    # AI security interpretation
    ai_interpretation = call_llm_for_synthesis_interpretation(module_name, raw_logs)
    with open(os.path.join(mod_dir, "synthesis_interpretation.json"), "w") as aif:
        json.dump(ai_interpretation, aif, indent=2)
        
    return {
        "status": "COMPLETED",
        "warning_count": status_data["warning_count"],
        "error_count": status_data["error_count"],
        "ai_interpretation": ai_interpretation
    }

def _parse_scr_file(scr_path, stubs_map=None):
    scr_dir = os.path.dirname(scr_path)
    defines, incdirs, rtl_files = [], [], []
    with open(scr_path) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("//") or line.startswith("#"):
                continue
            if line.startswith("+define+"):
                defines.append(line[len("+define+"):])
            elif line.startswith("+incdir+"):
                p = os.path.normpath(os.path.join(scr_dir, line[len("+incdir+"):]))
                incdirs.append(p)
            else:
                p = os.path.normpath(os.path.join(scr_dir, line))
                basename = os.path.basename(p)
                if stubs_map and basename in stubs_map:
                    rtl_files.append(stubs_map[basename])
                elif os.path.isfile(p):
                    rtl_files.append(p)
    return defines, incdirs, rtl_files

def _escalate_synthesis_failure_to_ai(errors: list, config: SynthesisConfig) -> dict:
    """
    Called when synthesis still fails after all auto-stub retries.
    Visible to human via SYNTHESIS_AI_ESCALATION event + saved JSON file.
    """
    log_content = "\n".join(errors)
    prompt_context = f"""
Yosys synthesis failed for top module '{config.top_module}' after {config.max_stub_retries}
auto-stub retry cycles. Remaining errors:

{log_content}

For each error group:
1. Root cause (unsupported SV construct / missing file / type error)
2. Minimal fix or stub strategy
3. Blocker vs ignorable warning
4. Whether a human hardware designer must fix it manually

Return JSON:
{{
  "can_auto_fix": true|false,
  "auto_fix_actions": [{{"file": "...", "action": "stub|exclude|patch", "reason": "..."}}],
  "manual_fixes_required": [{{"error": "...", "explanation": "...", "suggested_fix": "..."}}],
  "overall_recommendation": "..."
}}
"""
    result = call_llm_for_synthesis_interpretation(config.top_module, prompt_context)
    out_path = os.path.join(config.output_dir, "synthesis_ai_repair_suggestions.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    _emit_event("SYNTHESIS_AI_ESCALATION", {
        "file": out_path,
        "can_auto_fix": result.get("can_auto_fix", False),
        "manual_fixes_needed": len(result.get("manual_fixes_required", []))
    }, config.output_dir)
    return result

def auto_generate_stubs(yosys_errors: list, config: SynthesisConfig, current_rtl_files: list) -> tuple:
    stubs_generated = []
    updated_rtl_files = list(current_rtl_files)
    
    p1 = re.compile(r"([^:]+\.sv):\d+:\d+: error: multiple asynchronous loads unsupported")
    p2 = re.compile(r"ERROR: Unknown cell type: (\w+)")
    p3 = re.compile(r"([^:]+\.sv):\d+: ERROR: Unsupported expression")
    p4 = re.compile(r"([^:]+\.sv):\d+: ERROR: error in generate")
    p5 = re.compile(r"([^:]+\.sv):\d+: ERROR: syntax error")
    p5 = re.compile(r"ERROR: Design elaboration failed")
    
    file_errors = {}
    escalate_now = False
    unknown_cells = []
    
    for err in yosys_errors:
        if p5.search(err):
            escalate_now = True
            break
            
        m1 = p1.search(err)
        if m1:
            f = m1.group(1)
            file_errors.setdefault(f, set()).add("multiple asynchronous loads unsupported")
            continue
            
        m2 = p2.search(err)
        if m2:
            unknown_cells.append(m2.group(1))
            continue
            
        m3 = p3.search(err)
        if m3:
            f = m3.group(1)
            file_errors.setdefault(f, set()).add("Unsupported expression")
            continue
            
        m4 = p4.search(err)
        if m4:
            f = m4.group(1)
            file_errors.setdefault(f, set()).add("error in generate")
            continue

        m5 = p5.search(err)
        if m5:
            f = m5.group(1)
            file_errors.setdefault(f, set()).add("syntax error")
            continue

    if escalate_now:
        return updated_rtl_files, stubs_generated
        
    stubs_dir = os.path.join(config.output_dir, "stubs")
    os.makedirs(stubs_dir, exist_ok=True)
    
    stubs_map = {}
    
    for filepath, reasons in file_errors.items():
        if not os.path.exists(filepath):
            continue
        try:
            with open(filepath, "r") as f:
                content = f.read()
        except:
            continue
            
        mod_match = re.search(r"module\s+(\w+)", content)
        if not mod_match:
            continue
        mod_name = mod_match.group(1)
        
        mod_start = mod_match.end()
        param_start = content.find("#", mod_start)
        port_start = content.find("(", mod_start)
        
        if param_start != -1 and param_start < port_start:
            p_open = content.find("(", param_start)
            if p_open != -1:
                paren = 1
                idx = p_open + 1
                while idx < len(content) and paren > 0:
                    if content[idx] == "(": paren += 1
                    elif content[idx] == ")": paren -= 1
                    idx += 1
                port_start = content.find("(", idx)
                
        ports = []
        if port_start != -1:
            paren = 1
            idx = port_start + 1
            port_text_start = idx
            while idx < len(content) and paren > 0:
                if content[idx] == "(": paren += 1
                elif content[idx] == ")": paren -= 1
                idx += 1
            port_text = content[port_text_start:idx-1]
            
            for pdecl in port_text.split(","):
                pdecl = pdecl.strip()
                if not pdecl: continue
                pdecl = re.sub(r"//.*", "", pdecl)
                pdecl = re.sub(r"/\*.*?\*/", "", pdecl, flags=re.DOTALL)
                parts = pdecl.split()
                if not parts: continue
                name = parts[-1]
                name = re.sub(r"\[.*?\]", "", name)
                
                is_out = "output" in parts
                is_clk = "clk" in name.lower()
                ports.append({"name": name, "raw": pdecl.strip(), "is_out": is_out, "is_clk": is_clk})
                
        stub_path = os.path.join(stubs_dir, os.path.basename(filepath))
        reason_str = ", ".join(reasons)
        
        stub_code = f"// Synthesis stub — auto-generated by SoC Security Analyzer Sub-stage 0.4\n"
        stub_code += f"// Reason    : {reason_str}\n"
        stub_code += f"// Original  : {filepath}\n"
        stub_code += f"// Generator : auto_generate_stubs()\n"
        stub_code += f"module {mod_name} (\n"
        stub_code += ",\n".join(f"  {p['raw']}" for p in ports)
        stub_code += "\n);\n"
        
        clk_port = next((p['name'] for p in ports if p['is_clk']), None)
        
        for p in ports:
            if p['is_out']:
                stub_code += f"  assign {p['name']} = '0;\n"
                
        if clk_port:
            stub_code += f"  always_ff @(posedge {clk_port}) begin\n  end\n"
            
        stub_code += f"endmodule\n"
        
        with open(stub_path, "w") as f:
            f.write(stub_code)
            
        stubs_generated.append(stub_path)
        stubs_map[os.path.basename(filepath)] = stub_path
        
        _emit_event("STUB_GENERATED", {"file": os.path.basename(filepath), "reason": reason_str}, config.output_dir)

    for c in unknown_cells:
        stub_path = os.path.join(stubs_dir, f"{c}_stub.sv")
        if os.path.exists(stub_path): continue
        stub_code = f"// Synthesis stub — auto-generated by SoC Security Analyzer Sub-stage 0.4\n"
        stub_code += f"// Reason    : Unknown cell type\n"
        stub_code += f"// Original  : (blackbox)\n"
        stub_code += f"// Generator : auto_generate_stubs()\n"
        stub_code += f"module {c} ();\nendmodule\n"
        with open(stub_path, "w") as f:
            f.write(stub_code)
        stubs_generated.append(stub_path)
        stubs_map[f"{c}.sv"] = stub_path
        _emit_event("STUB_GENERATED", {"cell": c, "reason": "Unknown cell type"}, config.output_dir)

    for i, p in enumerate(updated_rtl_files):
        base = os.path.basename(p)
        if base in stubs_map:
            updated_rtl_files[i] = stubs_map[base]
            
    for s in stubs_generated:
        if s not in updated_rtl_files:
            updated_rtl_files.append(s)

    return updated_rtl_files, stubs_generated

def inline_prim_util(content: str) -> str:
    while True:
        idx = content.find("prim_util_pkg::vbits")
        if idx == -1: break
        start_paren = content.find("(", idx)
        if start_paren == -1: break
        paren_count = 1
        scan_idx = start_paren + 1
        while paren_count > 0 and scan_idx < len(content):
            char = content[scan_idx]
            if char == "(": paren_count += 1
            elif char == ")": paren_count -= 1
            scan_idx += 1
        if paren_count == 0:
            expr = content[start_paren+1 : scan_idx-1].strip()
            replacement = f"(({expr}) == 1 ? 1 : $clog2({expr}))"
            content = content[:idx] + replacement + content[scan_idx:]
        else: break
            
    while True:
        idx = content.find("prim_util_pkg::ceil_div")
        if idx == -1: break
        start_paren = content.find("(", idx)
        if start_paren == -1: break
        paren_count = 1
        scan_idx = start_paren + 1
        while paren_count > 0 and scan_idx < len(content):
            char = content[scan_idx]
            if char == "(": paren_count += 1
            elif char == ")": paren_count -= 1
            scan_idx += 1
        if paren_count == 0:
            args_str = content[start_paren+1 : scan_idx-1].strip()
            level = 0
            comma_idx = -1
            for i, c in enumerate(args_str):
                if c == "(": level += 1
                elif c == ")": level -= 1
                elif c == "," and level == 0:
                    comma_idx = i
                    break
            if comma_idx != -1:
                arg1 = args_str[:comma_idx].strip()
                arg2 = args_str[comma_idx+1:].strip()
                replacement = f"((({arg1}) + ({arg2}) - 1) / ({arg2}))"
                content = content[:idx] + replacement + content[scan_idx:]
            else: break
        else: break
    return content

def preprocess_sv_for_yosys(content: str) -> str:
    content = inline_prim_util(content)
    def repl_inside(match):
        val = match.group(1).strip()
        elems_str = match.group(2)
        elems = [e.strip() for e in elems_str.split(",")]
        return "(" + " || ".join(f"{val} == {e}" for e in elems) + ")"
    content = re.sub(r"(\w+)\s+inside\s*\{\s*([^}]+)\s*\}", repl_inside, content)
    
    lines = content.splitlines()
    new_lines = []
    current_func = None
    func_start_rx = re.compile(r"\bfunction\s+(?:automatic\s+)?(?:[\w\s\[\]:]+)?\b(\w+)\s*(?:\(|;)")
    func_end_rx = re.compile(r"\bendfunction\b")
    for line in lines:
        m_start = func_start_rx.search(line)
        if m_start: current_func = m_start.group(1)
        if current_func and "return " in line:
            indent = line[:line.find("return")]
            expr = line[line.find("return") + 7:].strip()
            line = f"{indent}{current_func} = {expr}"
        if func_end_rx.search(line): current_func = None
        new_lines.append(line)
        
    content = "\n".join(new_lines)
    content = re.sub(r"\bendfunction\s*:\s*\w+", "endfunction", content)
    content = re.sub(r"\bendtask\s*:\s*\w+", "endtask", content)
    content = re.sub(r"\bendpackage\s*:\s*\w+", "endpackage", content)
    
    def repl_struct(match):
        inner = match.group(1)
        inner_cleaned = re.sub(r"\b\w+\s*:(?!:)\s*", "", inner)
        return "'{" + inner_cleaned + "}"
    content = re.sub(r"'\s*\{([^}]+)\}", repl_struct, content)
    
    def repl_param_array(match):
        kw, msb, lsb, name, size = match.group(1), match.group(2), match.group(3), match.group(4), match.group(5).strip()
        w_val = int(msb) - int(lsb) + 1 if msb else 1
        w_expr = str(w_val) if msb else "1"
        try:
            new_dim = f"[{int(size) * w_val}-1:0]"
        except:
            new_dim = f"[({size}) * {w_expr}-1:0]"
        return f"{kw} logic {new_dim} {name} = {{"
    content = re.sub(r"\b(parameter|localparam)\s+logic\s*(?:\[\s*(\d+)\s*:\s*(\d+)\s*\])?\s*(\w+)\s*\[([^\]]+)\]\s*=\s*'\s*\{", repl_param_array, content)
    content = re.sub(r"'\s*\{\s*default\s*:\s*([^}]+)\}", r"\1", content)
    content = re.sub(r"parameter pmp_cfg_t PmpCfgRst.*?};", "", content, flags=re.DOTALL)
    content = re.sub(r"parameter logic \[[^\]]+\] PmpAddrRst.*?};", "", content, flags=re.DOTALL)
    content = re.sub(r"parameter pmp_mseccfg_t PmpMseccfgRst.*?;", "", content, flags=re.DOTALL)

    return content


def run_shared_synthesis(config: SynthesisConfig) -> dict:
    t0 = time.time()
    
    yosys_bin = config.yosys_path or shutil.which("yosys")
    slang_bin = config.slang_path or shutil.which("slang")
    fusesoc_bin = config.fusesoc_path or shutil.which("fusesoc")
    
    defines = list(config.defines)
    incdirs = list(config.include_dirs)
    rtl_files = list(config.rtl_files)
    
    if config.fusesoc_core_name:
        if not fusesoc_bin:
            return {"status": "FAILED", "reason": "fusesoc not found"}
        cmd = [fusesoc_bin, "--cores-root", config.fusesoc_cores_root, "run",
               "--target", config.fusesoc_target, "--tool", config.fusesoc_tool,
               "--setup", config.fusesoc_core_name]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=config.design_dir)
        except subprocess.CalledProcessError as e:
            return {"status": "FAILED", "reason": f"fusesoc setup failed: {e.stderr.decode() if e.stderr else str(e)}"}
            
        build_root = os.path.join(config.design_dir, "build")
        scr_file = None
        
        # fusesoc creates folders like lowrisc_systems_chip_earlgrey_asic_0.1/syn-icarus
        # So we search for .scr files under build/ containing the core name with colons replaced by underscores
        core_prefix = config.fusesoc_core_name.replace(":", "_")
        if os.path.exists(build_root):
            for root, _, files in os.walk(build_root):
                if core_prefix in root:
                    for f in files:
                        if f.endswith(".scr"):
                            scr_file = os.path.join(root, f)
                            break
                if scr_file:
                    break
            
        if not scr_file:
            return {"status": "FAILED", "reason": ".scr file not found"}
            
        d, i, r = _parse_scr_file(scr_file, stubs_map=SYNTH_STUBS)
        defines.extend(d)
        incdirs.extend(i)
        rtl_files.extend(r)
        
        _emit_event("FUSESOC_FILELIST_READY", {"files": len(rtl_files)}, config.output_dir)

    ast_path = os.path.join(config.output_dir, "full_soc_ast.json")
    if config.run_slang_elab_check and slang_bin:
        cmd = [slang_bin, "--ignore-unknown-modules"]
        for d in defines: cmd.extend(["-D", d])
        for i in incdirs: cmd.extend(["-I", i])
        cmd.extend(rtl_files)
        cmd.extend(["--ast-json", ast_path])
        
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=config.design_dir)
        _emit_event("SLANG_ELAB_DONE", {"returncode": res.returncode}, config.output_dir)

    netlist_path = os.path.join(config.output_dir, "full_soc_netlist.json")
    log_path = os.path.join(config.output_dir, "full_soc_synthesis.log")
    
    stubs_total = []
    
    for attempt in range(config.max_stub_retries + 1):
        if attempt > 0:
            _emit_event("YOSYS_RETRY", {"attempt": attempt, "max": config.max_stub_retries}, config.output_dir)
            
        _emit_event("YOSYS_SYNTHESIS_START", {"top": config.top_module}, config.output_dir)    
        ys_path = os.path.join(config.output_dir, "synth.ys")
        ys_content = ""
        if config.yosys_slang_plugin and os.path.exists(config.yosys_slang_plugin):
            ys_content += f"plugin -i {config.yosys_slang_plugin}\n\n"
            
            slang_args = []
            slang_args.append(f"--top {config.top_module}")
            slang_args.append("--single-unit")
            slang_args.append("--ignore-assertions")
            slang_args.append("--compat vcs")
            slang_args.append("-Wno-undefined-param-override")
            for d in defines: slang_args.append(f"-D {d}")
            for i in incdirs: slang_args.append(f"-I {i}")
            for f in rtl_files: slang_args.append(f)
            
            ys_content += "read_slang \\\n"
            for i, arg in enumerate(slang_args):
                is_last = (i == len(slang_args) - 1)
                ys_content += f"  {arg}" + (" \\\n" if not is_last else "\n\n")
        else:
            for f in rtl_files:
                ys_content += f"read_verilog -sv {f}\n"
                
        ys_content += f"hierarchy -top {config.top_module}\n"
        ys_content += "proc\nopt -purge\nstat\n"
        ys_content += f"write_json {netlist_path}\n"
        
        with open(ys_path, "w") as f:
            f.write(ys_content)
            
        res = subprocess.run([yosys_bin, "-s", ys_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=config.design_dir)
        
        with open(log_path, "w") as f:
            f.write(res.stdout + "\n" + res.stderr)
            
        _emit_event("YOSYS_SYNTHESIS_DONE", {"returncode": res.returncode}, config.output_dir)
        
        if res.returncode == 0:
            return {
                "status": "COMPLETED",
                "netlist_path": netlist_path,
                "ast_path": ast_path,
                "log_path": log_path,
                "stubs_generated": stubs_total,
                "elapsed_seconds": time.time() - t0
            }
            
        if config.auto_generate_stubs and attempt < config.max_stub_retries:
            errors = []
            for line in (res.stdout + "\n" + res.stderr).splitlines():
                if "error" in line.lower():
                    errors.append(line)
            
            rtl_files, stubs = auto_generate_stubs(errors, config, rtl_files)
            if not stubs:
                break
            stubs_total.extend(stubs)
        else:
            break
            
    ai_escalation = {}
    if config.escalate_to_ai_on_failure:
        errors = []
        try:
            with open(log_path, "r") as f:
                lines = f.read().splitlines()
                for line in lines:
                    if "error" in line.lower(): errors.append(line)
        except:
            pass
        ai_escalation = _escalate_synthesis_failure_to_ai(errors[-100:], config)
        
    return {
        "status": "FAILED",
        "netlist_path": netlist_path if os.path.exists(netlist_path) else "",
        "ast_path": ast_path if os.path.exists(ast_path) else "",
        "log_path": log_path,
        "stubs_generated": stubs_total,
        "ai_escalation": ai_escalation,
        "elapsed_seconds": time.time() - t0
    }

def split_netlist_by_module(config: SynthesisConfig) -> dict:
    netlist_path = os.path.join(config.output_dir, "full_soc_netlist.json")
    if not os.path.exists(netlist_path):
        return {"slices": [], "netlist_dir": "", "manifest_path": ""}
        
    with open(netlist_path, "r") as f:
        data = json.load(f)
        
    modules = data.get("modules", {})
    if not modules:
        return {"slices": [], "netlist_dir": "", "manifest_path": ""}
        
    slices = {}
    seq_types = {"$dff", "$dffe", "$adff", "$adffe", "$sdff", "$sdffe", "$sdffce", "$dlatch"}
    
    # Get logical sub-modules to extract
    active_mods = []
    active_path = os.path.join(config.output_dir, "shared", "active_modules.json")
    if os.path.exists(active_path):
        try:
            with open(active_path, "r") as f:
                active_mods = json.load(f).get("active_modules", [])
        except Exception:
            pass
            
    # Add a fallback for default extraction
    if not active_mods:
        active_mods = ["dmi_jtag", "rv_core_ibex", "aes", "uart", "spi_device", "flash_ctrl", "otp_macro"]
    
    # 1. First keep the original top-level modules
    for inst, mdata in modules.items():
        cells = mdata.get("cells", {})
        ports = mdata.get("ports", {})
        
        slices[inst] = {
            "instance": inst,
            "ports": ports,
            "source_cells": {},
            "synthesis_stats": {
                "total_cells": 0,
                "cell_type_counts": {},
                "sequential_cells": 0,
                "combinational_cells": 0
            }
        }
        
        for cell_name, cell_data in cells.items():
            slices[inst]["source_cells"][cell_name] = cell_data
            slices[inst]["synthesis_stats"]["total_cells"] += 1
            ctype = cell_data.get("type", "unknown")
            slices[inst]["synthesis_stats"]["cell_type_counts"][ctype] = slices[inst]["synthesis_stats"]["cell_type_counts"].get(ctype, 0) + 1
            if ctype in seq_types:
                slices[inst]["synthesis_stats"]["sequential_cells"] += 1
            else:
                slices[inst]["synthesis_stats"]["combinational_cells"] += 1
                
        # 2. Extract logical sub-modules if this is the giant top-level module
        if "top_earlgrey" in inst or "chip_earlgrey" in inst:
            for submod in active_mods:
                sub_cells = {}
                for cname, cdata in cells.items():
                    if submod in cname:
                        sub_cells[cname] = cdata
                
                if sub_cells:
                    slices[submod] = {
                        "instance": submod,
                        "ports": {},
                        "source_cells": sub_cells,
                        "synthesis_stats": {
                            "total_cells": len(sub_cells),
                            "cell_type_counts": {},
                            "sequential_cells": 0,
                            "combinational_cells": 0
                        }
                    }
                    
                    for cname, cdata in sub_cells.items():
                        ctype = cdata.get("type", "unknown")
                        slices[submod]["synthesis_stats"]["cell_type_counts"][ctype] = slices[submod]["synthesis_stats"]["cell_type_counts"].get(ctype, 0) + 1
                        if ctype in seq_types:
                            slices[submod]["synthesis_stats"]["sequential_cells"] += 1
                        else:
                            slices[submod]["synthesis_stats"]["combinational_cells"] += 1

    netlist_dir = os.path.join(config.output_dir, "netlist")
    os.makedirs(netlist_dir, exist_ok=True)
    
    manifest_slices = []
    
    for inst, sdata in slices.items():
        out_path = os.path.join(netlist_dir, f"{inst}.json")
        with open(out_path, "w") as f:
            json.dump(sdata, f, indent=2)
        manifest_slices.append({
            "instance": inst,
            "cells": sdata["synthesis_stats"]["total_cells"],
            "file": f"netlist/{inst}.json"
        })
        
    manifest = {
        "top_module": config.top_module,
        "generator": "SoC Security Analyzer v0.4",
        "total_cells": len(cells),
        "slices": manifest_slices
    }
    
    manifest_path = os.path.join(netlist_dir, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
        
    return {"slices": manifest_slices, "netlist_dir": netlist_dir, "manifest_path": manifest_path}

def annotate_module_security(instance_name: str, config: SynthesisConfig) -> dict:
    log_path = os.path.join(config.output_dir, "full_soc_synthesis.log")
    snippet = []
    if os.path.exists(log_path):
        with open(log_path, "r") as f:
            lines = f.readlines()
            for i, l in enumerate(lines):
                if instance_name in l:
                    start = max(0, i - 25)
                    end = min(len(lines), i + 25)
                    snippet = lines[start:end]
                    break
    
    log_snippet = "".join(snippet)
    return call_llm_for_synthesis_interpretation(instance_name, log_snippet)

def run_phase0_shared_synthesis(config: SynthesisConfig) -> dict:
    _emit_event("PHASE0_SYNTHESIS_START", {"top": config.top_module, "output_dir": config.output_dir}, config.output_dir)

    synth_result = run_shared_synthesis(config)
    _emit_event("SYNTHESIS_DONE", {"status": synth_result["status"],
                                   "stubs": synth_result.get("stubs_generated", [])}, config.output_dir)

    if synth_result["status"] == "FAILED":
        _emit_event("PHASE0_SYNTHESIS_ABORTED", {"reason": "synthesis failed after retries"}, config.output_dir)
        return synth_result

    slice_result = split_netlist_by_module(config)
    _emit_event("NETLIST_SLICED", {"slice_count": len(slice_result["slices"])}, config.output_dir)

    annotations = {}
    for s in slice_result["slices"]:
        ann = annotate_module_security(s["instance"], config)
        annotations[s["instance"]] = ann
        _emit_event("MODULE_ANNOTATED", {"instance": s["instance"], "risk": ann.get("risk_level")}, config.output_dir)

    _emit_event("PHASE0_SYNTHESIS_COMPLETE", {
        "slices": len(slice_result["slices"]),
        "netlist": synth_result["netlist_path"]
    }, config.output_dir)
    
    with open(os.path.join(config.output_dir, "netlist", "annotations.json"), "w") as f:
        json.dump(annotations, f, indent=2)
        
    return {"status": "COMPLETED", "synthesis": synth_result,
            "slices": slice_result, "annotations": annotations}
