import os
import re
import bisect
from typing import Dict, List, Set, Tuple, Any

from soc_analyzer.preprocessing.comment_stripper import strip_comments
from soc_analyzer.common.fs_utils import write_json_artifact

KEYWORDS = {
    "module", "endmodule", "package", "endpackage", "import", "export", "class", "endclass",
    "function", "endfunction", "task", "endtask", "if", "else", "for", "while", "forever",
    "repeat", "case", "endcase", "casex", "casez", "generate", "endgenerate", "initial",
    "always", "always_ff", "always_comb", "always_latch", "assign", "begin", "end", "wire",
    "reg", "logic", "integer", "genvar", "parameter", "localparam", "input", "output", "inout",
    "tri", "supply0", "supply1", "defparam", "specparam", "typedef", "struct", "enum", "union",
    "const", "automatic", "signed", "unsigned", "ref", "assert", "assume", "cover", "property",
    "bit", "int", "void", "string", "real", "shortint", "longint", "byte", "chandle", "event"
}

def strip_strings(text: str) -> str:
    """Replaces characters inside double-quoted string literals with spaces to avoid keyword false positives."""
    n = len(text)
    out = []
    i = 0
    in_str = False
    while i < n:
        char = text[i]
        if in_str:
            if char == '\\':
                out.append(' ')
                if i + 1 < n:
                    out.append(' ' if text[i+1] != '\n' else '\n')
                    i += 2
                else:
                    i += 1
            elif char == '"':
                in_str = False
                out.append(char)
                i += 1
            else:
                out.append(' ' if char != '\n' else '\n')
                i += 1
        else:
            if char == '"':
                in_str = True
                out.append(char)
                i += 1
            else:
                out.append(char)
                i += 1
    return "".join(out)

def make_line_map(text: str) -> List[int]:
    """Returns starting character indices of each line."""
    line_starts = [0]
    for m in re.finditer(r'\n', text):
        line_starts.append(m.end())
    return line_starts

def get_line_num(char_idx: int, line_starts: List[int]) -> int:
    """Binary search to map character index to 1-indexed line number."""
    return bisect.bisect_right(line_starts, char_idx)

def tokenize_with_lines(clean_text: str) -> List[Tuple[str, int]]:
    """Tokenizes SystemVerilog source and tracks the 1-indexed line number of each token."""
    line_starts = make_line_map(clean_text)
    tokens = []
    pattern = re.compile(r'[a-zA-Z_][a-zA-Z0-9_]*|`[a-zA-Z_][a-zA-Z0-9_]*|#[0-9a-zA-Z_]*|//|/\*|"[^"]*"|[^a-zA-Z0-9_\s]')
    for m in pattern.finditer(clean_text):
        tokens.append((m.group(0), get_line_num(m.start(), line_starts)))
    return tokens

def find_block_ranges(lines: List[str]) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]], List[Tuple[int, str]]]:
    """Returns ranges of lines that are inside `ifdef/`ifndef or generate blocks, and list of directives."""
    ifdef_ranges = []
    generate_ranges = []
    directives = []
    
    ifdef_stack = []
    generate_stack = []
    
    for idx, line in enumerate(lines):
        line_num = idx + 1
        stripped = line.strip()
        
        # Check conditional compilation directives
        if stripped.startswith("`ifdef") or stripped.startswith("`ifndef"):
            ifdef_stack.append(line_num)
            directives.append((line_num, stripped.split()[0]))
        elif stripped.startswith("`elsif") or stripped.startswith("`else"):
            if ifdef_stack:
                start = ifdef_stack.pop()
                ifdef_ranges.append((start, line_num - 1))
            ifdef_stack.append(line_num)
            directives.append((line_num, stripped.split()[0]))
        elif stripped.startswith("`endif"):
            if ifdef_stack:
                start = ifdef_stack.pop()
                ifdef_ranges.append((start, line_num))
            directives.append((line_num, "`endif"))
            
        # Check generate blocks
        if re.search(r"\bgenerate\b", line):
            generate_stack.append(line_num)
        if re.search(r"\bendgenerate\b", line):
            if generate_stack:
                start = generate_stack.pop()
                generate_ranges.append((start, line_num))
                
    return ifdef_ranges, generate_ranges, directives

def is_in_ranges(line_num: int, ranges: List[Tuple[int, int]]) -> bool:
    """Checks if a given line number falls within any of the provided ranges."""
    for start, end in ranges:
        if start <= line_num <= end:
            return True
    return False

def scan_dependencies(file_paths: List[str], include_dirs: List[str]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Statically analyzes SystemVerilog files to extract includes, package imports, and module instantiations.
    Identifies compiler compilation and hierarchy ambiguities.
    """
    # Normalize path helpers
    file_paths = [os.path.abspath(p) for p in file_paths]
    include_dirs = [os.path.abspath(d) for d in include_dirs]
    
    files_data = {}
    modules_data = {}
    ambiguities = []
    
    # Keep track of where modules and packages are defined
    known_modules = {}  # module_name -> absolute_filepath
    known_packages = {} # package_name -> absolute_filepath
    
    # Cache processed contents
    processed_contents = {}
    
    # --- Pass 1: Collect definitions, packages, and directives ---
    for path in file_paths:
        if not os.path.exists(path):
            continue
            
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            raw_text = f.read()
            
        comment_stripped = strip_comments(raw_text)
        clean_text_for_tokens = strip_strings(comment_stripped)
        processed_contents[path] = clean_text_for_tokens
        lines = comment_stripped.splitlines()
        
        # Ranges and Directives
        ifdef_ranges, generate_ranges, directives = find_block_ranges(lines)
        
        # Log conditional compilation directives as ambiguities
        for line_num, dir_type in directives:
            ambiguities.append({
                "file": path,
                "line": line_num,
                "type": "CONDITIONAL_COMPILATION",
                "description": f"Conditional compilation directive '{dir_type}' detected"
            })
            
        # Parse Module definitions, Package definitions, Includes, Package imports line-by-line
        defines_modules = []
        defines_packages = []
        raw_includes = []  # List of (filename, line_num)
        package_imports = []
        
        module_def_pattern = re.compile(r"\bmodule\s+([a-zA-Z_][a-zA-Z0-9_]*)\b")
        package_def_pattern = re.compile(r"\bpackage\s+([a-zA-Z_][a-zA-Z0-9_]*)\b")
        include_pattern = re.compile(r"`include\s*[\"<]([^\"<>]+)[\">]")
        import_pattern = re.compile(r"\bimport\s+([a-zA-Z_][a-zA-Z0-9_]*)::")
        
        for idx, line in enumerate(lines):
            line_num = idx + 1
            
            # Module definitions
            for m in module_def_pattern.finditer(line):
                mod_name = m.group(1)
                defines_modules.append(mod_name)
                known_modules[mod_name] = path
                modules_data[mod_name] = {
                    "defined_in": path,
                    "instantiates": [],
                    "instantiated_by": []
                }
                
            # Package definitions
            for m in package_def_pattern.finditer(line):
                pkg_name = m.group(1)
                defines_packages.append(pkg_name)
                known_packages[pkg_name] = path
                
            # Includes
            for m in include_pattern.finditer(line):
                raw_includes.append((m.group(1), line_num))
                
            # Package imports
            for m in import_pattern.finditer(line):
                package_imports.append(m.group(1))
                
        files_data[path] = {
            "defines_modules": defines_modules,
            "defines_packages": defines_packages,
            "includes": [],  # Filled during include resolution
            "raw_includes": raw_includes, # Temp store
            "package_imports": sorted(list(set(package_imports))),
            "instantiations": [],
            "ifdef_ranges": ifdef_ranges,
            "generate_ranges": generate_ranges
        }
        
    # --- Pass 2: Resolve includes and detect ambiguities ---
    for path, fdata in files_data.items():
        file_dir = os.path.dirname(path)
        resolved_includes = []
        
        for inc_name, line_num in fdata["raw_includes"]:
            # Search order:
            # 1. Directory containing the current file
            # 2. Provided include search directories
            candidates = []
            
            local_cand = os.path.abspath(os.path.join(file_dir, inc_name))
            if os.path.exists(local_cand):
                candidates.append(local_cand)
                
            for inc_dir in include_dirs:
                search_cand = os.path.abspath(os.path.join(inc_dir, inc_name))
                if os.path.exists(search_cand) and search_cand not in candidates:
                    candidates.append(search_cand)
                    
            if len(candidates) == 1:
                resolved_includes.append(candidates[0])
                # Check if it was conditionally compiled
                if is_in_ranges(line_num, fdata["ifdef_ranges"]):
                    ambiguities.append({
                        "file": path,
                        "line": line_num,
                        "type": "CONDITIONAL_INCLUDE",
                        "description": f"Include file '{inc_name}' is inside a conditional compilation block"
                    })
            elif len(candidates) > 1:
                ambiguities.append({
                    "file": path,
                    "line": line_num,
                    "type": "AMBIGUOUS_INCLUDE",
                    "description": f"Include '{inc_name}' matches multiple locations: {candidates}"
                })
            else:
                ambiguities.append({
                    "file": path,
                    "line": line_num,
                    "type": "UNRESOLVED_INCLUDE",
                    "description": f"Include '{inc_name}' could not be resolved in search paths"
                })
                
        fdata["includes"] = resolved_includes
        del fdata["raw_includes"]
        
    # --- Pass 3: Token-based instantiation scanning ---
    for path, fdata in files_data.items():
        clean_text = processed_contents.get(path, "")
        tokens = tokenize_with_lines(clean_text)
        n = len(tokens)
        
        current_module = None
        
        idx = 0
        while idx < n:
            tok, line_num = tokens[idx]
            
            # Module boundaries
            if tok == "module":
                if idx + 1 < n and bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', tokens[idx+1][0])):
                    current_module = tokens[idx+1][0]
            elif tok == "endmodule":
                current_module = None
                
            # Detect instantiations
            if bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', tok)) and tok not in KEYWORDS:
                # Exclude if it's the module definition statement itself
                is_def = False
                if idx > 0 and tokens[idx-1][0] in ("module", "package", "task", "function", "class"):
                    is_def = True
                    
                if not is_def:
                    ptr = idx + 1
                    
                    # Parameter list check
                    has_params = False
                    if ptr < n and tokens[ptr][0] == '#':
                        ptr += 1
                        if ptr < n and tokens[ptr][0] == '(':
                            depth = 1
                            ptr += 1
                            while ptr < n and depth > 0:
                                if tokens[ptr][0] == '(':
                                    depth += 1
                                elif tokens[ptr][0] == ')':
                                    depth -= 1
                                ptr += 1
                            has_params = (depth == 0)
                            
                    # Optional array size / ranges
                    if ptr < n and tokens[ptr][0] == '[':
                        depth = 1
                        ptr += 1
                        while ptr < n and depth > 0:
                            if tokens[ptr][0] == '[':
                                depth += 1
                            elif tokens[ptr][0] == ']':
                                depth -= 1
                            ptr += 1
                            
                    # Instance identifier
                    has_instance_name = False
                    if ptr < n and bool(re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', tokens[ptr][0])) and tokens[ptr][0] not in KEYWORDS:
                        ptr += 1
                        has_instance_name = True
                        
                        # Optional array ranges after instance name
                        if ptr < n and tokens[ptr][0] == '[':
                            depth = 1
                            ptr += 1
                            while ptr < n and depth > 0:
                                if tokens[ptr][0] == '[':
                                    depth += 1
                                elif tokens[ptr][0] == ']':
                                    depth -= 1
                                ptr += 1
                                
                    # Check for port list opening
                    is_inst = False
                    if ptr < n and tokens[ptr][0] == '(':
                        if tok in known_modules:
                            is_inst = True
                        elif has_instance_name:
                            is_inst = True
                            
                    if is_inst:
                        # Record instantiation
                        if tok not in fdata["instantiations"]:
                            fdata["instantiations"].append(tok)
                            
                        if current_module and current_module in modules_data:
                            if tok not in modules_data[current_module]["instantiates"]:
                                modules_data[current_module]["instantiates"].append(tok)
                                
                        # Check instantiations ambiguities
                        if has_params:
                            ambiguities.append({
                                "file": path,
                                "line": line_num,
                                "type": "PARAMETERIZED_INSTANTIATION",
                                "description": f"Instantiation of module '{tok}' is parameterized"
                            })
                        if is_in_ranges(line_num, fdata["ifdef_ranges"]):
                            ambiguities.append({
                                "file": path,
                                "line": line_num,
                                "type": "CONDITIONAL_INSTANTIATION",
                                "description": f"Instantiation of module '{tok}' is inside a conditional compilation block"
                            })
                        if is_in_ranges(line_num, fdata["generate_ranges"]):
                            ambiguities.append({
                                "file": path,
                                "line": line_num,
                                "type": "GENERATE_BLOCK_INSTANTIATION",
                                "description": f"Instantiation of module '{tok}' is inside a generate block"
                            })
                            
                        # Skip until semicolon
                        while idx < n and tokens[idx][0] != ';':
                            idx += 1
                        continue
                        
            idx += 1
            
    # Cleanup internal data structure fields not needed in target schema
    for fdata in files_data.values():
        del fdata["ifdef_ranges"]
        del fdata["generate_ranges"]
        
    # --- Pass 4: Compute reverse instantiations mapping ---
    for mod_name, mdata in modules_data.items():
        for child in mdata["instantiates"]:
            if child in modules_data:
                if mod_name not in modules_data[child]["instantiated_by"]:
                    modules_data[child]["instantiated_by"].append(mod_name)
                    
    graph = {
        "files": files_data,
        "modules": modules_data
    }
    
    return graph, ambiguities

def scan_dependencies_and_write(file_paths: List[str], include_dirs: List[str], output_dir: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Runs dependency scanner and writes dependency_graph.json and ambiguities.json."""
    graph, ambiguities = scan_dependencies(file_paths, include_dirs)
    
    write_json_artifact(graph, os.path.join(output_dir, "shared", "dependency_graph.json"))
    write_json_artifact(ambiguities, os.path.join(output_dir, "shared", "ambiguities.json"))
    
    return graph, ambiguities
