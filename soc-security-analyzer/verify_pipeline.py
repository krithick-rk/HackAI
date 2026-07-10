import os
import sys
import argparse
from src.soc_analyzer.phase0.dependency_scanner import scan_dependencies_and_write
from src.soc_analyzer.phase0.invocation_map_builder import build_and_write_invocation_maps
from src.soc_analyzer.phase0.tool_validator import validate_environment

def main():
    parser = argparse.ArgumentParser(description="Generic Phase 0 SoC Analyzer Pipeline Runner")
    parser.add_argument("-d", "--design-dir", type=str, help="Path to the directory containing RTL designs to scan recursively")
    parser.add_argument("-o", "--output-dir", type=str, help="Output directory for generated Phase 0 artifacts")
    parser.add_argument("-i", "--include-dirs", nargs="*", help="Optional additional include directories")
    parser.add_argument("-x", "--exclude", nargs="*", default=["/dv/", "/pre_dv/", "/formal/"],
                        help="Path patterns to exclude from recursive scanning (default: simulation/formal paths)")
    
    args = parser.parse_args()
    
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
        if exclude_patterns:
            print(f"   Exclusion patterns: {exclude_patterns}")
            
        for root, _, filenames in os.walk(design_dir):
            # Check if root matches exclusions
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
        
        output_dir = args.output_dir or "workspace/opentitan_full_artifacts"
    else:
        # Default behavior
        rtl_dir = os.path.abspath("fixtures/sample_rtl")
        if not os.path.exists(rtl_dir):
            print(f"Error: Default fixtures directory '{rtl_dir}' not found.")
            sys.exit(1)
        files = [os.path.abspath(os.path.join(rtl_dir, f)) for f in os.listdir(rtl_dir) if f.endswith(('.v', '.sv'))]
        include_dirs = [rtl_dir]
        output_dir = args.output_dir or "workspace/phase0_artifacts"
        
    if not files:
        print("Error: No Verilog/SystemVerilog (.v or .sv) files found to scan.")
        sys.exit(1)
        
    print(f"Found {len(files)} RTL source files.")
    print(f"Found {len(include_dirs)} include directories.")
    print(f"Output directory: {output_dir}")
    
    print("\n1. Running Dependency Scanner...")
    graph, ambiguities = scan_dependencies_and_write(files, include_dirs=include_dirs, output_dir=output_dir)
    print(f"   Generated dependency graph for {len(graph['files'])} files.")
    print(f"   Found {len(ambiguities)} ambiguities.")
    
    print("\n2. Running Invocation Map Builder...")
    all_maps = build_and_write_invocation_maps(graph, output_dir=output_dir)
    
    # Filter maps to exclude primitives or validation-skipped modules from validation folder
    # Strategy B: Only validate "local roots" (modules not instantiated by others in their folder hierarchy)
    import shutil
    
    # Group modules by their directory path to compute local roots
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

    filtered_maps = {}
    skipped_count = 0
    for mod_name, map_data in all_maps.items():
        defining_file = graph["modules"][mod_name].get("defined_in", "")
        # Module is a primitive if it starts with prim_ or lies in any primitive folder
        is_prim = mod_name.startswith("prim_") or "hw/ip/prim" in defining_file or "/prim/" in defining_file
        is_root = mod_name in local_roots
        
        if is_prim or not is_root:
            mod_dir = os.path.join(output_dir, "per_module", mod_name)
            if os.path.exists(mod_dir):
                try:
                    shutil.rmtree(mod_dir)
                except Exception as e:
                    print(f"Failed to remove directory for skipped module {mod_name}: {e}")
            skipped_count += 1
        else:
            filtered_maps[mod_name] = map_data
            
    print(f"   Generated invocation maps for {len(filtered_maps)} target modules (skipped {skipped_count} primitive/child modules).")
    maps = filtered_maps
    
    print("\n3. Running Tool Validator (Health Check)...")
    validate_environment(output_dir)
    print("   Validation completed successfully.")
    
    # Check outputs
    shared_dir = os.path.join(output_dir, "shared")
    print("\nVerifying output artifacts:")
    print(f"   dependency_graph.json exists: {os.path.exists(os.path.join(shared_dir, 'dependency_graph.json'))}")
    print(f"   ambiguities.json exists: {os.path.exists(os.path.join(shared_dir, 'ambiguities.json'))}")
    
    # Print status summary
    validated_count = 0
    partial_count = 0
    failed_count = 0
    
    for mod in maps.keys():
        mod_dir = os.path.join(output_dir, "per_module", mod)
        status_file = os.path.join(mod_dir, "validation_status.json")
        if os.path.exists(status_file):
            import json
            with open(status_file, "r") as sf:
                status_data = json.load(sf)
                # Count based on status values
                statuses = [status_data.get(t) for t in ["slang", "verilator", "verible"] if t in status_data]
                if all(s == "VALIDATED" for s in statuses):
                    validated_count += 1
                elif any(s in ("FAILED", "TOOL_UNAVAILABLE") for s in statuses):
                    failed_count += 1
                else:
                    partial_count += 1
                    
    print(f"\nPhase 0 complete. Status summary:")
    print(f"   Total modules processed: {len(maps)}")
    print(f"   Fully Validated:         {validated_count}")
    print(f"   Partially Validated:     {partial_count}")
    print(f"   Failed/Unavailable:      {failed_count}")

if __name__ == "__main__":
    main()

