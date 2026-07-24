import os
import sys
import json
import re
import argparse
import shutil
from src.soc_analyzer.phase0.dependency_scanner import scan_dependencies, scan_dependencies_and_write
from src.soc_analyzer.phase0.invocation_map_builder import build_invocation_maps, build_and_write_invocation_maps
from src.soc_analyzer.phase0.tool_validator import validate_environment
from src.soc_analyzer.preprocessing.comment_stripper import strip_comments
from src.soc_analyzer.common.fs_utils import write_json_artifact

def detect_top_module_and_name(user_name: str, files: list) -> tuple:
    """
    Heuristic to find the top SV module file and parse the true SV module name.
    1. Basename matches <user_name>.sv or <user_name>.v
    2. File under rtl/ matching <user_name>*.sv
    3. File with most module keyword instantiations
    """
    top_file = None
    
    # 1. Exact match on basename
    for f in files:
        base = os.path.basename(f)
        if base in (f"{user_name}.sv", f"{user_name}.v"):
            top_file = f
            break
            
    # 2. File in rtl/ matching <user_name>*.sv
    if not top_file:
        for f in files:
            parent_dir = os.path.basename(os.path.dirname(f))
            base = os.path.basename(f)
            if parent_dir == "rtl" and base.startswith(user_name) and base.endswith((".sv", ".v")):
                top_file = f
                break
                
    # 3. Fallback: file with most instantiations
    if not top_file and files:
        max_insts = -1
        inst_pattern = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s+(?:#\s*\(.*?\)\s*)?[a-zA-Z_][a-zA-Z0-9_]*\s*\(")
        for f in files:
            try:
                with open(f, 'r', encoding='utf-8', errors='replace') as fh:
                    clean = strip_comments(fh.read())
                    count = len(inst_pattern.findall(clean))
                    if count > max_insts:
                        max_insts = count
                        top_file = f
            except Exception:
                pass
                
    if not top_file and files:
        top_file = files[0]
        
    sv_module_name = user_name
    if top_file and os.path.exists(top_file):
        try:
            with open(top_file, 'r', encoding='utf-8', errors='replace') as fh:
                clean = strip_comments(fh.read())
                match = re.search(r"\bmodule\s+([a-zA-Z_][a-zA-Z0-9_]*)\b", clean)
                if match:
                    sv_module_name = match.group(1)
        except Exception:
            pass
            
    return top_file, sv_module_name

def determine_project_root(design_dir: str | None, modules_spec: list) -> str | None:
    if design_dir and os.path.exists(design_dir):
        return os.path.abspath(design_dir)
    folders = [os.path.abspath(m.get("folder")) for m in modules_spec if m.get("folder") and os.path.exists(m.get("folder"))]
    if not folders:
        return None
    try:
        common = os.path.commonpath(folders)
        parts = common.split(os.sep)
        if "hw" in parts:
            hw_idx = parts.index("hw")
            return os.sep.join(parts[:hw_idx+1])
        elif len(parts) > 2:
            return os.path.dirname(common)
        return common
    except Exception:
        return None

def discover_project_packages_and_includes(root_dir: str) -> tuple:
    """
    Scans root_dir recursively to discover all package-defining SystemVerilog files
    and all directories containing SystemVerilog header/include files (.svh, .h).
    """
    if not root_dir or not os.path.exists(root_dir):
        return [], set()
        
    pkg_pattern = re.compile(r"\bpackage\s+([a-zA-Z_][a-zA-Z0-9_]*)\b")
    comment_pattern = re.compile(r"//.*|/\*.*?\*/", re.DOTALL)
    
    global_package_files = set()
    global_include_dirs = set()
    
    for root, dirs, filenames in os.walk(root_dir):
        # Skip hidden/build/simulation folders
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('build-out', 'build-bin', 'dv', 'sim', 'tb', 'formal')]
        
        has_headers = False
        for fname in filenames:
            fpath = os.path.abspath(os.path.join(root, fname))
            if fname.endswith(('.svh', '.h')):
                has_headers = True
            elif fname.endswith(('.v', '.sv')):
                if fname.endswith('_pkg.sv') or fname.endswith('_pkg.v'):
                    global_package_files.add(fpath)
                else:
                    try:
                        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = comment_pattern.sub('', f.read())
                            if pkg_pattern.search(content):
                                global_package_files.add(fpath)
                    except Exception:
                        pass
        if has_headers or any(fname.endswith(('.v', '.sv')) for fname in filenames):
            global_include_dirs.add(os.path.abspath(root))
            
    return sorted(list(global_package_files)), global_include_dirs

def main():
    parser = argparse.ArgumentParser(description="Generic Phase 0 SoC Analyzer Pipeline Runner")
    parser.add_argument("-d", "--design-dir", type=str, help="Path to the directory containing RTL designs to scan recursively")
    parser.add_argument("-o", "--output-dir", type=str, help="Output directory for generated Phase 0 artifacts")
    parser.add_argument("-i", "--include-dirs", nargs="*", help="Optional additional include directories")
    parser.add_argument("-x", "--exclude", nargs="*", default=["/dv/", "/pre_dv/", "/formal/", "/google_riscv-dv/", "/test/", "/tb/", "/vip/"],
                        help="Path patterns to exclude from recursive scanning (default: simulation/formal paths)")
    parser.add_argument("--modules-json", type=str, help="Path to JSON file containing user-defined IP module registry specs")
    parser.add_argument("--repair-failures", action="store_true", help="Interactively run LLM failure repair on failed modules")
    
    args = parser.parse_args()
    
    output_dir = args.output_dir or "workspace/opentitan_artifacts"
    os.makedirs(output_dir, exist_ok=True)
    maps = {}

    if args.modules_json:
        modules_json_path = os.path.abspath(args.modules_json)
        if not os.path.exists(modules_json_path):
            print(f"Error: Modules JSON file '{modules_json_path}' does not exist.")
            sys.exit(1)
            
        with open(modules_json_path, 'r', encoding='utf-8') as f:
            modules_spec = json.load(f)
            
        merged_files = {}
        merged_modules = {}
        merged_packages = {}
        merged_ambiguities = []
        
        # Discover global packages & include dirs across whole project root
        proj_root = determine_project_root(args.design_dir, modules_spec)
        global_packages, global_inc_dirs = discover_project_packages_and_includes(proj_root)
        print(f"[INFO] Discovered {len(global_packages)} project-wide package files and {len(global_inc_dirs)} include directories from root: '{proj_root}'")
        
        print(f"Processing {len(modules_spec)} user-defined IP modules from registry...")
        
        for mod_entry in modules_spec:
            user_name = mod_entry.get("name")
            folder = os.path.abspath(mod_entry.get("folder", ""))
            excluded_subfolders = set(mod_entry.get("excluded_subfolders", []))
            
            if not os.path.exists(folder):
                print(f"Warning: Folder for module '{user_name}' does not exist: {folder}")
                continue
                
            # Attempt FuseSoC resolution first (authoritative source of truth for OpenTitan cores)
            from src.soc_analyzer.phase0.fusesoc_resolver import resolve_module_file_list_via_fusesoc
            fusesoc_res = resolve_module_file_list_via_fusesoc(user_name, proj_root, output_dir)
            
            if fusesoc_res.get("status") == "SUCCESS":
                ordered_sv = fusesoc_res.get("sv_files", [])
                vlt_files = fusesoc_res.get("vlt_files", [])
                inc_paths = fusesoc_res.get("include_paths", [])
                print(f"[INFO] FuseSoC resolved {len(ordered_sv)} ordered files for module '{user_name}' ({fusesoc_res.get('core_name')})")
                
                top_mod_name = fusesoc_res.get("toplevel") or user_name
                map_entry = {
                    "slang": {
                        "base_command": "slang",
                        "flags": ["--allow-use-before-declare", "--error-limit", "0"],
                        "include_paths": inc_paths,
                        "files": ordered_sv
                    },
                    "verilator": {
                        "base_command": f"verilator --lint-only --top-module {top_mod_name}",
                        "flags": ["-Wno-fatal", "-Wno-style", "-Wno-LATCH", "-Wno-PINMISSING", "-Wno-REDEFMACRO", "-Wno-MULTITOP"],
                        "include_paths": inc_paths,
                        "files": vlt_files + ordered_sv
                    },
                    "verible": {
                        "base_command": "verible-verilog-lint",
                        "flags": [],
                        "include_paths": inc_paths,
                        "files": ordered_sv
                    }
                }
                
                mod_output_dir = os.path.join(output_dir, "per_module", user_name)
                os.makedirs(mod_output_dir, exist_ok=True)
                write_json_artifact(map_entry, os.path.join(mod_output_dir, "invocation_map.json"))
                maps[user_name] = map_entry
                continue
            else:
                print(f"[INFO] FuseSoC core not found or setup skipped for '{user_name}', falling back to directory scanner...")

            # Collect files while skipping excluded subfolders
            mod_files = []
            mod_include_dirs = set(global_inc_dirs)
            if args.include_dirs:
                for d in args.include_dirs:
                    if os.path.exists(d):
                        mod_include_dirs.add(os.path.abspath(d))
            
            for root, dirs, filenames in os.walk(folder):
                rel_root = os.path.relpath(root, folder)
                if rel_root != ".":
                    top_subfolder = rel_root.split(os.sep)[0]
                    if top_subfolder in excluded_subfolders:
                        dirs.clear()
                        continue
                        
                has_rtl = False
                for fname in filenames:
                    fpath = os.path.abspath(os.path.join(root, fname))
                    if fname.endswith(('.v', '.sv')):
                        mod_files.append(fpath)
                        has_rtl = True
                    elif fname.endswith('.svh'):
                        has_rtl = True
                if has_rtl:
                    mod_include_dirs.add(os.path.abspath(root))
                    
            if not mod_files:
                print(f"Warning: No RTL files found for module '{user_name}' in {folder}")
                continue

            # Combine module files with global project package files for full package visibility
            combined_files = list(mod_files)
            mod_files_set = set(mod_files)
            for pkg_file in global_packages:
                if pkg_file not in mod_files_set:
                    # Check if pkg_file is inside module folder and in an excluded subfolder
                    if pkg_file.startswith(folder + os.sep):
                        rel_pkg = os.path.relpath(pkg_file, folder)
                        top_sub = rel_pkg.split(os.sep)[0]
                        if top_sub in excluded_subfolders:
                            continue
                    combined_files.append(pkg_file)
                
            # Top module file detection & SV module keyword parser (Gap 2)
            top_file_path, sv_module_name = detect_top_module_and_name(user_name, mod_files)
            print(f"[INFO] Top module file detected: {top_file_path} (SV module name: {sv_module_name}, registry name: {user_name})")
            
            # Dependency Scanning per module with project-wide package awareness
            mod_graph, mod_ambiguities = scan_dependencies(combined_files, include_dirs=sorted(list(mod_include_dirs)))
            
            # Write per-module dependency graph under per_module/<user_name>/
            mod_output_dir = os.path.join(output_dir, "per_module", user_name)
            os.makedirs(mod_output_dir, exist_ok=True)
            write_json_artifact(mod_graph, os.path.join(mod_output_dir, "dependency_graph.json"))
            
            # Merge into overall graph for Phase 0.3 context generator
            merged_files.update(mod_graph.get("files", {}))
            merged_modules.update(mod_graph.get("modules", {}))
            merged_packages.update(mod_graph.get("packages", {}))
            merged_ambiguities.extend(mod_ambiguities)
            
            # Build Invocation Map for this module
            mod_maps = build_invocation_maps(mod_graph)
            
            map_entry = None
            if sv_module_name in mod_maps:
                map_entry = mod_maps[sv_module_name]
            elif user_name in mod_maps:
                map_entry = mod_maps[user_name]
            elif mod_maps:
                map_entry = list(mod_maps.values())[0]
                
            if map_entry:
                write_json_artifact(map_entry, os.path.join(mod_output_dir, "invocation_map.json"))
                maps[user_name] = map_entry

        # Write merged shared artifacts for Phase 0.3
        shared_dir = os.path.join(output_dir, "shared")
        os.makedirs(shared_dir, exist_ok=True)
        merged_graph = {
            "files": merged_files,
            "modules": merged_modules,
            "packages": merged_packages
        }
        write_json_artifact(merged_graph, os.path.join(shared_dir, "dependency_graph.json"))
        write_json_artifact(merged_ambiguities, os.path.join(shared_dir, "ambiguities.json"))
        
    else:
        # Legacy --design-dir recursive scan fallback
        files = []
        include_dirs = []
        
        if args.design_dir:
            design_dir = os.path.abspath(args.design_dir)
            if not os.path.exists(design_dir):
                print(f"Error: Design directory '{design_dir}' does not exist.")
                sys.exit(1)
                
            print(f"Scanning '{design_dir}' recursively for RTL files...")
            seen_dirs = set()
            exclude_patterns = args.exclude if args.exclude is not None else []
            
            for root, _, filenames in os.walk(design_dir):
                if any(pat in root for pat in exclude_patterns):
                    continue
                    
                has_sv_files = False
                for f in filenames:
                    file_path = os.path.join(root, f)
                    if any(pat in file_path for pat in exclude_patterns):
                        continue
                        
                    if f.endswith(('.v', '.sv')):
                        files.append(os.path.abspath(file_path))
                        has_sv_files = True
                    elif f.endswith('.svh'):
                        has_sv_files = True
                if has_sv_files:
                    seen_dirs.add(os.path.abspath(root))
            
            include_dirs = sorted(list(seen_dirs))
            if args.include_dirs:
                for d in args.include_dirs:
                    abs_d = os.path.abspath(d)
                    if abs_d not in include_dirs:
                        include_dirs.append(abs_d)
        else:
            rtl_dir = os.path.abspath("fixtures/sample_rtl")
            if not os.path.exists(rtl_dir):
                print(f"Error: Default fixtures directory '{rtl_dir}' not found.")
                sys.exit(1)
            files = [os.path.abspath(os.path.join(rtl_dir, f)) for f in os.listdir(rtl_dir) if f.endswith(('.v', '.sv'))]
            include_dirs = [rtl_dir]
            
        if not files:
            print("Error: No Verilog/SystemVerilog (.v or .sv) files found to scan.")
            sys.exit(1)
            
        print(f"Found {len(files)} RTL source files.")
        print("\n1. Running Dependency Scanner...")
        graph, ambiguities = scan_dependencies_and_write(files, include_dirs=include_dirs, output_dir=output_dir)
        
        print("\n2. Running Invocation Map Builder...")
        all_maps = build_and_write_invocation_maps(graph, output_dir=output_dir)
        
        dir_to_modules = {}
        for mod_name, mod_data in graph["modules"].items():
            defining_file = mod_data.get("defined_in", "")
            if not defining_file:
                continue
            parent_dir = os.path.dirname(defining_file)
            if os.path.basename(parent_dir) == "rtl":
                parent_dir = os.path.dirname(parent_dir)
            if parent_dir not in dir_to_modules:
                dir_to_modules[parent_dir] = []
            dir_to_modules[parent_dir].append(mod_name)

        local_roots = set()
        for dir_path, dir_mods in dir_to_modules.items():
            instantiated_in_dir = set()
            for m in dir_mods:
                instantiates = graph["modules"][m].get("instantiates", [])
                for child in instantiates:
                    if child in dir_mods:
                        instantiated_in_dir.add(child)
            roots = [m for m in dir_mods if m not in instantiated_in_dir]
            local_roots.update(roots)

        for mod_name, map_data in all_maps.items():
            defining_file = graph["modules"][mod_name].get("defined_in", "")
            is_prim = mod_name.startswith("prim_") or "hw/ip/prim" in defining_file or "/prim/" in defining_file
            is_root = mod_name in local_roots
            
            if is_prim or not is_root:
                mod_dir = os.path.join(output_dir, "per_module", mod_name)
                if os.path.exists(mod_dir):
                    try:
                        shutil.rmtree(mod_dir)
                    except Exception:
                        pass
            else:
                maps[mod_name] = map_data

    print("\n3. Running Tool Validator (Health Check)...")
    target_mods = [m["name"] for m in modules_spec] if modules_spec else None
    validate_environment(output_dir, target_modules=target_mods)
    print("   Validation completed successfully.")
    
    print("\n4. Running Context Generator...")
    from src.soc_analyzer.phase0.context_generator import generate_context
    generate_context(output_dir)
    
    if args.repair_failures:
        print("\n5. Running Tool Validation Failure Repairer...")
        from src.soc_analyzer.phase0.failure_repairer import repair_failed_modules
        repair_failed_modules(output_dir)
        print("\nRe-running Context Generator...")
        generate_context(output_dir)
    
    validated_count = 0
    missing_stub_count = 0
    failed_count = 0
    
    for mod in maps.keys():
        mod_dir = os.path.join(output_dir, "per_module", mod)
        status_file = os.path.join(mod_dir, "validation_status.json")
        if os.path.exists(status_file):
            with open(status_file, "r") as sf:
                status_data = json.load(sf)
                statuses = [status_data.get(t) for t in ["slang", "verilator", "verible"] if t in status_data]
                if any(s in ("FAILED", "TOOL_UNAVAILABLE") for s in statuses):
                    failed_count += 1
                elif any(s == "NEEDS_STUB" for s in statuses):
                    missing_stub_count += 1
                else:
                    validated_count += 1
                    
    print(f"\nPhase 0 complete. Status summary:")
    print(f"   Total modules processed: {len(maps)}")
    print(f"   Fully Validated:         {validated_count}")
    print(f"   Missing Stub:            {missing_stub_count}")
    print(f"   Failed/Unavailable:      {failed_count}")

if __name__ == "__main__":
    main()
